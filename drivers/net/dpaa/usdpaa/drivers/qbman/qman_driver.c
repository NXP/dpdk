/* Copyright (c) 2008-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <usdpaa/fsl_usd.h>
#include <internal/process.h>
#include "qman_private.h"
#include <sys/ioctl.h>
#include <rte_branch_prediction.h>

/* Global variable containing revision id (even on non-control plane systems
 * where CCSR isn't available) */
u16 qman_ip_rev;
EXPORT_SYMBOL(qman_ip_rev);
u16 qm_channel_pool1 = QMAN_CHANNEL_POOL1;
EXPORT_SYMBOL(qm_channel_pool1);
u16 qm_channel_caam = QMAN_CHANNEL_CAAM;
EXPORT_SYMBOL(qman_channel_caam);
u16 qm_channel_pme = QMAN_CHANNEL_PME;
EXPORT_SYMBOL(qman_channel_pme);

/* Ccsr map address to access ccsrbased register */
void *qman_ccsr_map;
/* The qman clock frequency */
u32 qman_clk;
/* Two CEETM instances provided by QMan v3.0 */
struct qm_ceetm qman_ceetms[QMAN_CEETM_MAX];
/* the qman ceetm instances on the given SoC */
u8 num_ceetms;

static __thread int fd = -1;
static __thread struct qm_portal_config pcfg;
static __thread struct usdpaa_ioctl_portal_map map = {
	.type = usdpaa_portal_qman
};

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
static COMPAT_LIST_HEAD(master_list);
static pthread_mutex_t master_list_lock = PTHREAD_MUTEX_INITIALIZER;

struct qman_master {
	struct list_head node;
	u32 index;
	struct qman_portal *portal;
	unsigned int slave_refs;
};
#endif /* CONFIG_FSL_DPA_PORTAL_SHARE */

static int __init fsl_qman_portal_init(uint32_t index, int is_shared)
{
	cpu_set_t cpuset;
	struct qman_portal *portal;
	int loop, ret;
	struct usdpaa_ioctl_irq_map irq_map;

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
	struct qman_master *master;
#endif
	/* Verify the thread's cpu-affinity */
	ret = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t),
				     &cpuset);
	if (ret) {
		error(0, ret, "pthread_getaffinity_np()");
		return ret;
	}
	pcfg.public_cfg.cpu = -1;
	for (loop = 0; loop < CPU_SETSIZE; loop++)
		if (CPU_ISSET(loop, &cpuset)) {
			if (pcfg.public_cfg.cpu != -1) {
				pr_err("Thread is not affine to 1 cpu\n");
				return -EINVAL;
			}
			pcfg.public_cfg.cpu = loop;
		}
	if (pcfg.public_cfg.cpu == -1) {
		pr_err("Bug in getaffinity handling!\n");
		return -EINVAL;
	}

	/* Allocate and map a qman portal */
	map.index = index;
	ret = process_portal_map(&map);
	if (ret) {
		error(0, ret, "process_portal_map()");
		return ret;
	}
	pcfg.public_cfg.channel = map.channel;
	pcfg.public_cfg.pools = map.pools;
	pcfg.public_cfg.index = map.index;

	/* Make the portal's cache-[enabled|inhibited] regions */
	pcfg.addr_virt[DPA_PORTAL_CE] = map.addr.cena;
	pcfg.addr_virt[DPA_PORTAL_CI] = map.addr.cinh;

	fd = open("/dev/fsl-usdpaa-irq", O_RDONLY);
	if (fd == -1) {
		pr_err("QMan irq init failed\n");
		process_portal_unmap(&map.addr);
		return -EBUSY;
	}

	pcfg.public_cfg.is_shared = is_shared;
	pcfg.node = NULL;
	pcfg.public_cfg.irq = fd;

	portal = qman_create_affine_portal(&pcfg, NULL);
	if (!portal) {
		pr_err("Qman portal initialisation failed (%d)\n",
		       pcfg.public_cfg.cpu);
		process_portal_unmap(&map.addr);
		return -EBUSY;
	}

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
	master = calloc(1, sizeof(struct qman_master));
	if (!master) {
		pr_err("Memory allocation failed for qman master\n");
		qman_destroy_affine_portal();
		close(fd);
		process_portal_unmap(&map.addr);
		return -ENOMEM;
	}

	master->portal = portal;
	master->index = qman_get_portal_config()->index;
	master->slave_refs = 0;

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);
	list_add(&master->node, &master_list);
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);
#endif

	irq_map.type = usdpaa_portal_qman;
	irq_map.portal_cinh = map.addr.cinh;
	process_portal_irq_map(fd, &irq_map);
	return 0;
}

static int fsl_qman_portal_finish(void)
{
	__maybe_unused const struct qm_portal_config *cfg;
	int ret;

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE
	struct qman_master *master;
	__maybe_unused struct qman_portal *redirect = NULL;
	const struct qman_portal_config *portal_cfg;

	portal_cfg = qman_get_portal_config();

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);

	list_for_each_entry(master, &master_list, node) {
		if (master->index == portal_cfg->index) {
			redirect = master->portal;
			break;
		}
	}

	BUG_ON(!redirect);
	if (master->slave_refs) {
		ret = pthread_mutex_unlock(&master_list_lock);
		assert(!ret);
		return -EBUSY;
	}

	list_del(&master->node);
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);
	free(master);
#endif

	process_portal_irq_unmap(fd);

	cfg = qman_destroy_affine_portal();
	BUG_ON(cfg != &pcfg);
	ret = process_portal_unmap(&map.addr);
	if (ret)
		error(0, ret, "process_portal_unmap()");
	return ret;
}

int qman_thread_init(void)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_qman_portal_init(QBMAN_ANY_PORTAL_IDX, 0);
}

int qman_thread_init_idx(uint32_t idx)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_qman_portal_init(idx, 0);
}

#ifdef CONFIG_FSL_DPA_PORTAL_SHARE

static int fsl_qman_slave_portal_init(const struct qman_portal_config *cfg)
{
	struct qman_portal *redirect = NULL;
	struct qman_master *master;
	struct qman_portal *p;
	int ret;

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);

	list_for_each_entry(master, &master_list, node) {
		if (master->index == cfg->index) {
			redirect = master->portal;
			break;
		}
	}

	if (!redirect) {
		pr_err("Given portal not found in master list: %p\n", cfg);
		ret = pthread_mutex_unlock(&master_list_lock);
		assert(!ret);
		return -ENODEV;
	}

	master->slave_refs++;
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);

	p = qman_create_affine_slave(redirect);
	if (!p) {
		pr_err("Qman slave init failure for portal: %u\n", cfg->index);
		ret = pthread_mutex_lock(&master_list_lock);
		assert(!ret);
		master->slave_refs--;
		ret = pthread_mutex_unlock(&master_list_lock);
		assert(!ret);
		return -ENODEV;
	}

	return 0;
}

int qman_thread_init_shared(void)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_qman_portal_init(QBMAN_ANY_PORTAL_IDX, 1);
}

int qman_thread_init_shared_idx(uint32_t idx)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_qman_portal_init(idx, 1);
}

int qman_thread_init_slave(const struct qman_portal_config *cfg)
{
	/* Convert from contiguous/virtual cpu numbering to real cpu when
	 * calling into the code that is dependent on the device naming */
	return fsl_qman_slave_portal_init(cfg);
}

int qman_thread_finish_slave(void)
{
	struct qman_master *master;
	__maybe_unused struct qman_portal *redirect = NULL;
	u32 index = qman_get_portal_config()->index;
	int ret = 0;

	qman_destroy_affine_portal();

	ret = pthread_mutex_lock(&master_list_lock);
	assert(!ret);

	list_for_each_entry(master, &master_list, node) {
		if (master->index == index) {
			redirect = master->portal;
			break;
		}
	}

	BUG_ON(!redirect);
	master->slave_refs--;
	ret = pthread_mutex_unlock(&master_list_lock);
	assert(!ret);

	return ret;
}
#endif /* CONFIG_FSL_DPA_PORTAL_SHARE */

int qman_thread_finish(void)
{
	return fsl_qman_portal_finish();
}

int qman_thread_fd(void)
{
	return fd;
}

void qman_thread_irq(void)
{
	qbman_invoke_irq(pcfg.public_cfg.irq);

	/* Now we need to uninhibit interrupts. This is the only code outside
	 * the regular portal driver that manipulates any portal register, so
	 * rather than breaking that encapsulation I am simply hard-coding the
	 * offset to the inhibit register here. */
	out_be32(pcfg.addr_virt[DPA_PORTAL_CI] + 0xe0c, 0);
}

static __init int fsl_ceetm_init(const struct device_node *node)
{
	enum qm_dc_portal dcp_portal;
	struct qm_ceetm_sp *sp;
	struct qm_ceetm_lni *lni;
	const u32 *range;
	int i;
	size_t ret;

	/* Find LFQID range */
	range = of_get_property(node, "fsl,ceetm-lfqid-range", &ret);
	if (!range) {
		pr_err("No fsl,ceetm-lfqid-range in node %s\n",
		       node->full_name);
		return -EINVAL;
	}
	if (ret != 8) {
		pr_err("fsl,ceetm-lfqid-range is not a 2-cell range in node"
						" %s\n", node->full_name);
		return -EINVAL;
	}

	dcp_portal = (be32_to_cpu(range[0]) & 0x0F0000) >> 16;
	if (dcp_portal > qm_dc_portal_fman1) {
		pr_err("The DCP portal %d doesn't support CEETM\n", dcp_portal);
		return -EINVAL;
	}

	qman_ceetms[dcp_portal].idx = dcp_portal;
	INIT_LIST_HEAD(&qman_ceetms[dcp_portal].sub_portals);
	INIT_LIST_HEAD(&qman_ceetms[dcp_portal].lnis);

	/* Find Sub-portal range */
	range = of_get_property(node, "fsl,ceetm-sp-range", &ret);
	if (!range) {
		pr_err("No fsl,ceetm-sp-range in node %s\n", node->full_name);
		return -EINVAL;
	}
	if (ret != 8) {
		pr_err("fsl,ceetm-sp-range is not a 2-cell range in node %s\n",
		       node->full_name);
		return -EINVAL;
	}

	for (i = 0; i < be32_to_cpu(range[1]); i++) {
		sp = kzalloc(sizeof(*sp), GFP_KERNEL);
		if (!sp) {
			pr_err("Can't alloc memory for sub-portal %d\n",
			       range[0] + i);
			return -ENOMEM;
		}
		sp->idx = be32_to_cpu(range[0]) + i;
		sp->dcp_idx = dcp_portal;
		sp->is_claimed = 0;
		list_add_tail(&sp->node, &qman_ceetms[dcp_portal].sub_portals);
		sp++;
	}
	pr_debug("Qman: Reserve sub-portal %d:%d for CEETM %d\n",
		 be32_to_cpu(range[0]), be32_to_cpu(range[1]), dcp_portal);
	qman_ceetms[dcp_portal].sp_range[0] = be32_to_cpu(range[0]);
	qman_ceetms[dcp_portal].sp_range[1] = be32_to_cpu(range[1]);

	/* Find LNI range */
	range = of_get_property(node, "fsl,ceetm-lni-range", &ret);
	if (!range) {
		pr_err("No fsl,ceetm-lni-range in node %s\n", node->full_name);
		return -EINVAL;
	}
	if (ret != 8) {
		pr_err("fsl,ceetm-lni-range is not a 2-cell range in node %s\n",
		       node->full_name);
		return -EINVAL;
	}

	for (i = 0; i < be32_to_cpu(range[1]); i++) {
		lni = kzalloc(sizeof(*lni), GFP_KERNEL);
		if (!lni) {
			pr_err("Can't alloc memory for LNI %d\n",
			       range[0] + i);
			return -ENOMEM;
		}
		lni->idx = be32_to_cpu(range[0]) + i;
		lni->dcp_idx = dcp_portal;
		lni->is_claimed = 0;
		INIT_LIST_HEAD(&lni->channels);
		list_add_tail(&lni->node, &qman_ceetms[dcp_portal].lnis);
		lni++;
	}
	pr_debug("Qman: Reserve LNI %d:%d for CEETM %d\n",
		 be32_to_cpu(range[0]), be32_to_cpu(range[1]), dcp_portal);
	qman_ceetms[dcp_portal].lni_range[0] = be32_to_cpu(range[0]);
	qman_ceetms[dcp_portal].lni_range[1] = be32_to_cpu(range[1]);

	return 0;
}

int qman_global_init(void)
{
	const struct device_node *dt_node;
	int ret;
	size_t lenp;
	const u32 *chanid;
	static int ccsr_map_fd;
	const uint32_t *qman_addr;
	uint64_t phys_addr;
	uint64_t regs_size;
	const u32 *clk;

	static int done;

	if (done)
		return -EBUSY;

	/* Use the device-tree to determine IP revision until something better
	 * is devised. */
	dt_node = of_find_compatible_node(NULL, NULL, "fsl,qman-portal");
	if (!dt_node) {
		pr_err("No qman portals available for any CPU\n");
		return -ENODEV;
	}
	if (of_device_is_compatible(dt_node, "fsl,qman-portal-1.0") ||
	    of_device_is_compatible(dt_node, "fsl,qman-portal-1.0.0"))
		pr_err("QMan rev1.0 on P4080 rev1 is not supported!\n");
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-1.1") ||
		 of_device_is_compatible(dt_node, "fsl,qman-portal-1.1.0"))
		qman_ip_rev = QMAN_REV11;
	else if	(of_device_is_compatible(dt_node, "fsl,qman-portal-1.2") ||
		 of_device_is_compatible(dt_node, "fsl,qman-portal-1.2.0"))
		qman_ip_rev = QMAN_REV12;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-2.0") ||
		 of_device_is_compatible(dt_node, "fsl,qman-portal-2.0.0"))
		qman_ip_rev = QMAN_REV20;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-3.0.0") ||
		 of_device_is_compatible(dt_node, "fsl,qman-portal-3.0.1"))
		qman_ip_rev = QMAN_REV30;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-3.1.0") ||
		 of_device_is_compatible(dt_node, "fsl,qman-portal-3.1.1") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-3.1.2") ||
		of_device_is_compatible(dt_node, "fsl,qman-portal-3.1.3"))
		qman_ip_rev = QMAN_REV31;
	else if (of_device_is_compatible(dt_node, "fsl,qman-portal-3.2.0"))
		qman_ip_rev = QMAN_REV32;
	else
		qman_ip_rev = QMAN_REV11;

	if (!qman_ip_rev) {
		pr_err("Unknown qman portal version\n");
		return -ENODEV;
	}
	if ((qman_ip_rev & 0xFF00) >= QMAN_REV30) {
		qm_channel_pool1 = QMAN_CHANNEL_POOL1_REV3;
		qm_channel_caam = QMAN_CHANNEL_CAAM_REV3;
		qm_channel_pme = QMAN_CHANNEL_PME_REV3;
	}

	dt_node = of_find_compatible_node(NULL, NULL, "fsl,pool-channel-range");
	if (!dt_node) {
		pr_err("No qman pool channel range available\n");
		return -ENODEV;
	}
	chanid = of_get_property(dt_node, "fsl,pool-channel-range", &lenp);
	if (!chanid) {
		pr_err("Can not get pool-channel-range property\n");
		return -EINVAL;
	}

	/* Parse CEETM */
	num_ceetms = 0;
	for_each_compatible_node(dt_node, NULL, "fsl,qman-ceetm") {
		ret = fsl_ceetm_init(dt_node);
		num_ceetms++;
		if (ret)
			return ret;
	}

	/* get ccsr base */
	dt_node = of_find_compatible_node(NULL, NULL, "fsl,qman");
	if (!dt_node) {
		pr_err("No qman device node available\n");
		return -ENODEV;
	}
	qman_addr = of_get_address(dt_node, 0, &regs_size, NULL);
	if (!qman_addr) {
		pr_err("of_get_address cannot return qman address\n");
		return -EINVAL;
	}
	phys_addr = of_translate_address(dt_node, qman_addr);
	if (!phys_addr) {
		pr_err("of_translate_address failed\n");
		return -EINVAL;
	}

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		pr_err("Can not open /dev/mem for qman ccsr map\n");
		return ccsr_map_fd;
	}

	qman_ccsr_map = mmap(NULL, regs_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			     ccsr_map_fd, phys_addr);
	if (qman_ccsr_map == MAP_FAILED) {
		pr_err("Can not map qman ccsr base\n");
		return -EINVAL;
	}

	clk = of_get_property(dt_node, "clock-frequency", NULL);
	if (!clk)
		pr_warn("Can't find Qman clock frequency\n");
	else
		qman_clk = be32_to_cpu(*clk);

#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	ret = qman_setup_fq_lookup_table(CONFIG_FSL_QMAN_FQ_LOOKUP_MAX);
	if (ret)
		return ret;
#endif
	return 0;
}

#define CEETM_CFG_PRES     0x904
int qman_ceetm_get_prescaler(u16 *pres)
{
	*pres = (u16)(in_be32(qman_ccsr_map + CEETM_CFG_PRES));
	return 0;
}

#define CEETM_CFG_IDX      0x900
#define DCP_CFG(n)	(0x0300 + ((n) * 0x10))
#define DCP_CFG_CEETME_MASK 0xFFFF0000
#define QM_SP_ENABLE_CEETM(n) (0x80000000 >> (n))
int qman_sp_enable_ceetm_mode(enum qm_dc_portal portal, u16 sub_portal)
{
	u32 dcp_cfg;

	dcp_cfg = in_be32(qman_ccsr_map + DCP_CFG(portal));
	dcp_cfg |= QM_SP_ENABLE_CEETM(sub_portal);
	out_be32(qman_ccsr_map + DCP_CFG(portal), dcp_cfg);
	return 0;
}

int qman_sp_disable_ceetm_mode(enum qm_dc_portal portal, u16 sub_portal)
{
	u32 dcp_cfg;

	dcp_cfg = in_be32(qman_ccsr_map + DCP_CFG(portal));
	dcp_cfg &= ~(QM_SP_ENABLE_CEETM(sub_portal));
	out_be32(qman_ccsr_map + DCP_CFG(portal), dcp_cfg);
	return 0;
}

#define MISC_CFG	0x0be0
#define MISC_CFG_WPM_MASK	0x00000002
int qm_set_wpm(int wpm)
{
	u32 before;
	u32 after;

	if (!qman_ccsr_map)
		return -ENODEV;

	before = in_be32(qman_ccsr_map + MISC_CFG);
	after = (before & (~MISC_CFG_WPM_MASK)) | (wpm << 1);
	out_be32(qman_ccsr_map + MISC_CFG, after);
	return 0;
}

int qm_get_wpm(int *wpm)
{
	u32 before;

	if (!qman_ccsr_map)
		return -ENODEV;

	before = in_be32(qman_ccsr_map + MISC_CFG);
	*wpm = (before & MISC_CFG_WPM_MASK) >> 1;
	return 0;
}
