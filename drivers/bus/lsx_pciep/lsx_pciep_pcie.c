/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_kvargs.h>
#include <dpaa_of.h>
#include <fsl_qbman_portal.h>
#include <linux/pci_regs.h>
#include <compat.h>
#include <fslmc_vfio.h>
#include <rte_pci.h>
#include <linux/virtio_net.h>
#include <linux/virtio_blk.h>
#include <rte_lsx_pciep_bus.h>

#include "lsx_pciep_dev.h"
#include "lsx_pciep_ctrl.h"

#define LSX_PCIE_REG_PHY_START 0x3400000
#define LSX_PCIE_REG_STRIDE 0x100000

#define LSX_PCIE_DT_REG_ADDR_IDX 0
#define LSX_PCIE_DT_OB_ADDR_IDX 1

#define SVR_MAJOR_VER_MASK	0x00F0

#ifndef SVR_MASK
#define SVR_MASK 0xffff0000
#endif

struct lsx_pcie_svr_map {
	uint32_t svr_id;
	uint16_t pci_dev_id;
	uint16_t rsv;
};

static const struct lsx_pcie_svr_map s_lx_rev2_id_map[] = {
	{SVR_LX2160A | 0x0120, 0x8d81, 0},
	{SVR_LX2160A | 0x1020, 0x8d90, 0},
	{SVR_LX2160A | 0x0020, 0x8d80, 0},
	{SVR_LX2160A | 0x1120, 0x8d91, 0},
	{SVR_LX2160A | 0x2120, 0x8da1, 0},
	{SVR_LX2160A | 0x3020, 0x8db0, 0},
	{SVR_LX2160A | 0x2020, 0x8da0, 0},
	{SVR_LX2160A | 0x3120, 0x8db1, 0},
	{SVR_LX2160A | 0x0320, 0x8d83, 0},
	{SVR_LX2160A | 0x1220, 0x8d92, 0},
	{SVR_LX2160A | 0x0220, 0x8d82, 0},
	{SVR_LX2160A | 0x1320, 0x8d93, 0}
};

static struct lsx_pciep_ctl_hw *s_pctl_hw;

static rte_spinlock_t lsx_pciep_shared_data_lock =
	RTE_SPINLOCK_INITIALIZER;

static const struct rte_memzone *primary_shared_mz;

static const char *lsx_pciep_shared_data_nm =
	"lsx_pciep_shared_data";

#define LSX_PCIEP_CTL_HW_TOTAL_SIZE \
	(sizeof(struct lsx_pciep_ctl_hw) * LSX_MAX_PCIE_NB)

static uint32_t s_pciep_init_flag;

#define LSX_PCIEP_DEFAULT_POLICY RTE_DEV_WHITELISTED
#define LSX_PCIEP_DEFAULT_OB_POLICY LSX_PCIEP_OB_FUN_IDX

#define LSX_PCIEP_DEFAULT_PF_ENABLE 1
#define LSX_PCIEP_DEFAULT_VF_ENABLE 0
#define LSX_PCIEP_DEFAULT_RBP_ENABLE 1
#define LSX_PCIEP_DEFAULT_SIM_ENABLE 0
#define LSX_PCIEP_DEFAULT_VIO_ENABLE 0
#define LSX_PCIEP_DEFAULT_OB_FUN_SIZE CFG_8G_SIZE

struct lsx_pciep_env {
	enum rte_dev_policy policy;
	enum lsx_ob_policy ob_policy;
	uint64_t ob_fun_size;
	uint8_t rbp;
	uint8_t sim;

	uint8_t pf_enable[PF_MAX_NB];
	uint8_t vf_enable[PF_MAX_NB][PCIE_MAX_VF_NUM];

	uint8_t pf_virtio[PF_MAX_NB];
};

struct lsx_pciep_env s_pciep_env[LSX_MAX_PCIE_NB];

#define OB_MAP_DUMP_FORMAT(pci_id, size, phy, vir) \
	"PCIe%d map outbound size(0x%lx) from (0x%lx) to %p", \
	(int)pci_id, \
	(unsigned long)size, \
	(unsigned long)phy, \
	(void *)vir

static int
lsx_pciep_ctl_set_ops(void)
{
	enum PEX_TYPE type;
	int i;

	if (!s_pctl_hw)
		return -ENOTSUP;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		type = s_pctl_hw[i].type;
		if (type == PEX_LX2160_REV1) {
			s_pctl_hw[i].ops = lsx_pciep_get_mv_ops();
		} else if (type == PEX_LX2160_REV2) {
			s_pctl_hw[i].ops = lsx_pciep_get_dw_ops();
		} else if (type == PEX_LS208X) {
			s_pctl_hw[i].ops = lsx_pciep_get_dw_ops();
		} else {
			LSX_PCIEP_BUS_ERR("SoC type(%d) not supported",
				type);
			return -ENOTSUP;
		}
	}

	return 0;
}

static int lsx_pciep_ctl_process_map(void)
{
	int i, ep_nb = 0;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		if (ctlhw->sim) {
			if (ctlhw->ep_enable)
				ep_nb += ctlhw->function_num;
			continue;
		}
		if (ctlhw->ep_enable) {
			ctlhw->hw.dbi_vir =
				lsx_pciep_map_region(ctlhw->hw.dbi_phy,
					ctlhw->hw.dbi_size);
			if (!ctlhw->hw.dbi_vir) {
				LSX_PCIEP_BUS_ERR("dbi_vir map failed\n");

				return -ENOMEM;
			}
			ep_nb += ctlhw->function_num;

			if (ctlhw->hw.ob_policy != LSX_PCIEP_OB_SHARE)
				continue;

			ctlhw->out_vir =
				lsx_pciep_map_region(ctlhw->hw.out_base,
					ctlhw->hw.out_size);
			if (!ctlhw->out_vir) {
				LSX_PCIEP_BUS_ERR("Failure of sharing OB");

				return -ENOMEM;
			}
		}
	}

	return ep_nb;
}

int lsx_pciep_share_info_init(void)
{
	const struct rte_memzone *mz;
	int ret = 0;

	rte_spinlock_lock(&lsx_pciep_shared_data_lock);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		mz = rte_memzone_reserve(lsx_pciep_shared_data_nm,
				sizeof(struct lsx_pciep_ctl_hw) *
				LSX_MAX_PCIE_NB,
				rte_socket_id(), 0);
		primary_shared_mz = mz;
	} else {
		mz = rte_memzone_lookup(lsx_pciep_shared_data_nm);
	}
	if (mz == NULL) {
		LSX_PCIEP_BUS_ERR("Shared mz reserve/lookup failed");
		ret = -ENOMEM;
		goto share_info_init_done;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		if (s_pctl_hw) {
			memcpy(mz->addr, s_pctl_hw,
				LSX_PCIEP_CTL_HW_TOTAL_SIZE);
		}
	} else {
		s_pctl_hw = malloc(LSX_PCIEP_CTL_HW_TOTAL_SIZE);
		if (!s_pctl_hw) {
			LSX_PCIEP_BUS_ERR("Secondary private mem alloc failed");
			ret = -ENOMEM;
			goto share_info_init_done;
		}
		memcpy(s_pctl_hw, mz->addr, LSX_PCIEP_CTL_HW_TOTAL_SIZE);
		ret = lsx_pciep_ctl_set_ops();
		if (ret)
			goto share_info_init_done;

		ret = lsx_pciep_ctl_process_map();
		if (ret <= 0) {
			ret = -ENODEV;
			goto share_info_init_done;
		} else {
			ret = 0;
		}
	}
share_info_init_done:

	rte_spinlock_unlock(&lsx_pciep_shared_data_lock);

	return ret;
}

int
lsx_pciep_ctl_rbp_enable(uint8_t pcie_idx)
{
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pcie_idx].rbp;
}

static void
lsx_pciep_env_default_set(void)
{
	int i, j, k;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		s_pciep_env[i].policy = LSX_PCIEP_DEFAULT_POLICY;
		s_pciep_env[i].ob_policy = LSX_PCIEP_DEFAULT_OB_POLICY;
		s_pciep_env[i].ob_fun_size = LSX_PCIEP_DEFAULT_OB_FUN_SIZE;
		s_pciep_env[i].sim = LSX_PCIEP_DEFAULT_SIM_ENABLE;
		s_pciep_env[i].rbp = LSX_PCIEP_DEFAULT_RBP_ENABLE;
		for (j = 0; j < PF_MAX_NB; j++) {
			s_pciep_env[i].pf_enable[j] =
				LSX_PCIEP_DEFAULT_PF_ENABLE;
			s_pciep_env[i].pf_virtio[j] =
				LSX_PCIEP_DEFAULT_VIO_ENABLE;
			for (k = 0; k < PCIE_MAX_VF_NUM; k++) {
				s_pciep_env[i].vf_enable[j][k] =
					LSX_PCIEP_DEFAULT_VF_ENABLE;
			}
		}
	}
}

static void
lsx_pciep_env_adjust(void)
{
	int i, j;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		if (s_pciep_env[i].sim)
			s_pciep_env[i].rbp = 0;
		for (j = 0; j < PF_MAX_NB; j++) {
			if (!s_pciep_env[i].pf_enable[j]) {
				memset(&s_pciep_env[i].vf_enable[j],
					0, PCIE_MAX_VF_NUM);
			}
		}
		if (s_pciep_env[i].rbp)
			s_pciep_env[i].ob_policy = LSX_PCIEP_OB_RBP;
	}
}

static void
lsx_pciep_fun_env_set(int pciep_idx,
	uint8_t pf_idx, int vf_idx, int enable)
{
	RTE_ASSERT(pciep_idx >= 0 && pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);
	RTE_ASSERT(vf_idx < PCIE_MAX_VF_NUM);

	if (vf_idx < 0) {
		s_pciep_env[pciep_idx].pf_enable[pf_idx] =
			enable;
	} else {
		s_pciep_env[pciep_idx].vf_enable[pf_idx][vf_idx] =
			enable;
	}
}

static void
lsx_pciep_rbp_env_set(uint8_t pciep_idx,
	int enable)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].rbp = enable;
}

static void
lsx_pciep_sim_env_set(uint8_t pciep_idx,
	int enable)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].sim = enable;
}

static void
lsx_pciep_vio_env_set(uint8_t pciep_idx,
	uint8_t pf_idx, int enable)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);

	s_pciep_env[pciep_idx].pf_virtio[pf_idx] = enable;
}

static void
lsx_pciep_policy_env_set(uint8_t pciep_idx,
	enum rte_dev_policy policy)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].policy = policy;
}

static void
lsx_pciep_ob_policy_env_set(uint8_t pciep_idx,
	enum lsx_ob_policy policy)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].ob_policy = policy;
}

static void
lsx_pciep_ob_fun_size_env_set(uint8_t pciep_idx,
	uint64_t g_size)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	s_pciep_env[pciep_idx].ob_fun_size = g_size * CFG_1G_SIZE;
}

static int
lsx_pciep_fun_env_get(uint8_t pciep_idx,
	uint8_t pf_idx, int vf_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);
	RTE_ASSERT(vf_idx < PCIE_MAX_VF_NUM);

	if (vf_idx < 0)
		return s_pciep_env[pciep_idx].pf_enable[pf_idx];
	else
		return s_pciep_env[pciep_idx].vf_enable[pf_idx][vf_idx];
}

static int
lsx_pciep_rbp_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].rbp;
}

static int
lsx_pciep_sim_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].sim;
}

static int
lsx_pciep_vio_env_get(uint8_t pciep_idx,
	uint8_t pf_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);

	return s_pciep_env[pciep_idx].pf_virtio[pf_idx];
}

static enum lsx_ob_policy
lsx_pciep_ob_policy_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].ob_policy;
}

static uint64_t
lsx_pciep_ob_fun_size_env_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);

	return s_pciep_env[pciep_idx].ob_fun_size;
}


static int
lsx_pciep_parse_env_variable(void)
{
	char *penv = NULL;
	int i, j, k;
	char env_name[64];

	lsx_pciep_env_default_set();

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		sprintf(env_name, "LSX_PCIE%d_BLACKLISTED", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_policy_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_OB_POLICY", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_ob_policy_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_OB_FUN_GSIZE", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_ob_fun_size_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_RBP", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_rbp_env_set(i, atoi(penv));

		sprintf(env_name, "LSX_PCIE%d_SIM", i);
		penv = getenv(env_name);
		if (penv)
			lsx_pciep_sim_env_set(i, atoi(penv));

		for (j = 0; j < PF_MAX_NB; j++) {
			sprintf(env_name, "LSX_PCIE%d_PF%d", i, j);
			penv = getenv(env_name);
			if (penv)
				lsx_pciep_fun_env_set(i, j, -1, atoi(penv));

			sprintf(env_name, "LSX_PCIE%d_PF%d_VIRTIO", i, j);
			penv = getenv(env_name);
			if (penv)
				lsx_pciep_vio_env_set(i, j, atoi(penv));

			for (k = 0; k < PCIE_MAX_VF_NUM; k++) {
				sprintf(env_name, "LSX_PCIE%d_PF%d_VF%d",
					i, j, k);
				penv = getenv(env_name);
				if (penv) {
					lsx_pciep_fun_env_set(i, j, k,
						atoi(penv));
				}
			}
		}
	}

	lsx_pciep_env_adjust();

	return 0;
}

static int lsx_pciep_ctl_filtered(int pcie_idx)
{
	if (s_pciep_env[pcie_idx].policy == RTE_DEV_BLACKLISTED)
		return true;
	return false;
}

int lsx_pciep_sim_dev_add(void)
{
	struct lsx_pciep_ctl_hw *ctlhw;
	int i, j, dev_nb = 0;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		if (s_pciep_env[i].policy == RTE_DEV_BLACKLISTED)
			continue;
		for (j = 0; j < PF_MAX_NB; j++) {
			if (s_pciep_env[i].pf_enable[j] &&
				s_pciep_env[i].sim) {
				ctlhw = lsx_pciep_get_dev(i);
				ctlhw->hw.index = i;
				ctlhw->rbp = 0;
				ctlhw->sim = 1;
				ctlhw->ep_enable = 1;
				ctlhw->function_num++;
				dev_nb++;
				LSX_PCIEP_BUS_INFO("Simulator PCIe%dPF%d added",
					i, j);
			}
		}
	}

	return dev_nb;
}

int lsx_pciep_ctl_idx_validated(uint8_t pcie_idx)
{
	if (pcie_idx < LSX_MAX_PCIE_NB)
		return 1;

	return 0;
}

enum PEX_TYPE
lsx_pciep_type_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pciep_idx].type;
}

int
lsx_pciep_hw_rbp_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pciep_idx].rbp;
}

int
lsx_pciep_hw_sim_get(uint8_t pciep_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	return s_pctl_hw[pciep_idx].sim;
}

int
lsx_pciep_hw_vio_get(uint8_t pciep_idx,
	uint8_t pf_idx)
{
	RTE_ASSERT(pciep_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx < PF_MAX_NB);
	return s_pctl_hw[pciep_idx].vio_enable[pf_idx];
}


struct lsx_pciep_ctl_hw *
lsx_pciep_get_dev(uint8_t pcie_idx)
{
	if (pcie_idx >= LSX_MAX_PCIE_NB)
		return NULL;

	return &s_pctl_hw[pcie_idx];
}

static bool
lsx_pciep_ctl_is_ep(struct lsx_pciep_ctl_hw *ctlhw)
{
	if (ctlhw->type == PEX_LX2160_REV1 ||
		ctlhw->type == PEX_LX2160_REV2 ||
		ctlhw->type == PEX_LS208X)
		return true;

	return false;
}

static int
lsx_pciep_hw_set_type(void)
{
	FILE *svr_file = NULL;
	uint32_t svr_ver;
	enum PEX_TYPE type;
	int i;

	svr_file = fopen("/sys/devices/soc0/soc_id", "r");
	if (!svr_file) {
		LSX_PCIEP_BUS_ERR("Unable to open SoC device.");
		return -1;
	}
	if (fscanf(svr_file, "svr:%x", &svr_ver) < 0) {
		LSX_PCIEP_BUS_ERR("PCIe EP unable to read SoC device");
		return -1;
	}

	if ((svr_ver & SVR_MASK) == SVR_LX2160A) {
		if ((svr_ver & SVR_MAJOR_VER_MASK) == 0x10) {
			type = PEX_LX2160_REV1;
		} else {
			type = PEX_LX2160_REV2;
		}
	} else if ((svr_ver & SVR_MASK) == SVR_LS2088A) {
		type = PEX_LS208X;
	} else {
		LSX_PCIEP_BUS_ERR("SoC(0x%08x) not supported",
			(svr_ver & SVR_MASK));
		return -ENOTSUP;
	}

	for (i = 0; i < LSX_MAX_PCIE_NB; i++)
		s_pctl_hw[i].type = type;

	return 0;
}

uint16_t lx_rev2_pciep_default_dev_id(void)
{
	FILE *svr_file = NULL;
	uint32_t svr_ver, i, num;

	svr_file = fopen("/sys/devices/soc0/soc_id", "r");
	if (!svr_file) {
		LSX_PCIEP_BUS_ERR("Unable to open SoC device.");
		return 0;
	}
	if (fscanf(svr_file, "svr:%x", &svr_ver) < 0) {
		LSX_PCIEP_BUS_ERR("PCIe EP unable to read SoC device");
		return 0;
	}

	num = sizeof(s_lx_rev2_id_map) / sizeof(struct lsx_pcie_svr_map);

	for (i = 0; i < num; i++) {
		if (s_lx_rev2_id_map[i].svr_id == svr_ver)
			return s_lx_rev2_id_map[i].pci_dev_id;
	}

	return 0;
}

static int
lsx_pciep_hw_enable_clear_inbound(void)
{
	int i, clear_win;
	char *penv;
	char env[64];

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		sprintf(env, "LSX_PCIE%d_CLEAR_WINDOWS", i);
		penv = getenv(env);
		if (penv)
			clear_win = atoi(penv);
		else
			clear_win = 0;
		s_pctl_hw[i].clear_win = clear_win;
	}

	return 0;
}

uint16_t lsx_pciep_ctl_get_device_id(uint8_t pcie_idx,
	enum lsx_pcie_pf_idx pf_idx)
{
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT(pf_idx == PF0_IDX || pf_idx == PF1_IDX);

	return s_pctl_hw[pcie_idx].pf_device_id[pf_idx];
}

static struct lsx_pciep_ctl_hw *
lsx_pciep_node2ctl(const struct device_node *pcie_node)
{
	const uint32_t *addr;
	uint64_t phys_addr, reg_off;
	uint64_t len;
	uint8_t pcie_idx;
	struct lsx_pciep_ctl_hw *ctlhw;

	addr = of_get_address(pcie_node, LSX_PCIE_DT_REG_ADDR_IDX,
			&len, NULL);
	if (!addr) {
		LSX_PCIEP_BUS_ERR("PCIe EP %s of_get_address failed",
			pcie_node->full_name);

		return NULL;
	}

	phys_addr = of_translate_address(pcie_node, addr);
	if (!phys_addr) {
		LSX_PCIEP_BUS_ERR("PCIe EP %s of_translate_address failed",
			pcie_node->full_name);

		return NULL;
	}
	RTE_ASSERT(!(phys_addr & (LSX_PCIE_REG_STRIDE - 1)));
	RTE_ASSERT(phys_addr >= LSX_PCIE_REG_PHY_START);
	RTE_ASSERT(phys_addr < (LSX_PCIE_REG_PHY_START +
			LSX_PCIE_REG_STRIDE * LSX_MAX_PCIE_NB));

	reg_off = phys_addr - LSX_PCIE_REG_PHY_START;

	pcie_idx = reg_off / LSX_PCIE_REG_STRIDE;
	RTE_ASSERT(pcie_idx < LSX_MAX_PCIE_NB);
	RTE_ASSERT((pcie_idx * (uint64_t)LSX_PCIE_REG_STRIDE) == reg_off);

	ctlhw = &s_pctl_hw[pcie_idx];

	ctlhw->hw.dbi_phy = phys_addr;
	ctlhw->hw.dbi_size = (uint32_t)len;
	ctlhw->hw.index = pcie_idx;

	return ctlhw;
}

static int
lsx_pciep_hw_out_base(struct lsx_pciep_ctl_hw *ctlhw,
	const struct device_node *pcie_node)
{
	uint64_t phys_addr;
	const uint32_t *addr;
	uint64_t len;

	addr = of_get_address(pcie_node, LSX_PCIE_DT_OB_ADDR_IDX,
			&len, NULL);
	if (!addr) {
		LSX_PCIEP_BUS_ERR("%s of_get_address failed",
			pcie_node->full_name);

		return -ENODEV;
	}

	phys_addr = of_translate_address(pcie_node, addr);
	if (!phys_addr) {
		LSX_PCIEP_BUS_ERR("%s of_translate_address failed",
			pcie_node->full_name);

		return -ENODEV;
	}

	ctlhw->hw.out_base = phys_addr;

	return 0;
}

static int
lsx_pciep_ctl_ob_win_scheme(struct lsx_pciep_ctl_hw *ctlhw)
{
	if (ctlhw->rbp)
		return 0;

	/** Hardware max window size.*/
	ctlhw->out_win_size = ctlhw->hw.out_win_max_size;
	if (ctlhw->hw.ob_policy == LSX_PCIEP_OB_SHARE) {
		/* All the PF/VFs share global outbound windows,
		 * in case PF/VFs devices are only mapped into
		 * same VM or host.
		 */
		ctlhw->out_size_per_fun = ctlhw->hw.out_size;
	}
	if (ctlhw->out_size_per_fun < ctlhw->out_win_size)
		ctlhw->out_size_per_fun = ctlhw->out_win_size;

	ctlhw->out_win_per_fun =
		ctlhw->out_size_per_fun / ctlhw->out_win_size;
	if (!ctlhw->out_win_per_fun) {
		LSX_PCIEP_BUS_ERR("Error out_win_per_fun");

		return -ENODEV;
	}

	return 0;
}

static int
lsx_pciep_ctl_hw_init(struct lsx_pciep_ctl_hw *ctlhw)
{
	int ret;

	if (ctlhw->ops->pcie_config)
		ctlhw->ops->pcie_config(&ctlhw->hw);
	ret = lsx_pciep_ctl_ob_win_scheme(ctlhw);
	if (ret)
		LSX_PCIEP_BUS_ERR("Invalid OB win");

	return ret;
}

static int
lsx_pciep_find_all(void)
{
	int ret, ep_nb = 0;
	const struct device_node *pcie_node;
	const char *compatible;
	struct lsx_pciep_ctl_hw *ctlhw;

	ep_nb = lsx_pciep_sim_dev_add();
	if (ep_nb > 0) {
		LSX_PCIEP_BUS_INFO("PCIe EP sim finds %d pcie ep(s)", ep_nb);
		/** Simulator support only.*/
		goto pcie_mapping_start;
	}

	if (lsx_pciep_ctl_set_ops())
		return -ENODEV;

	ret = of_init();
	if (ret) {
		LSX_PCIEP_BUS_ERR("of_init failed");

		return -ENODEV;
	}

	/* ctlhw is temporally pointed to the first
	 * PCIe dev to identify the PEX type.
	 */
	ctlhw = &s_pctl_hw[0];
	switch (ctlhw->type) {
	case PEX_UNKNOWN:
		return -ENODEV;

	case PEX_LX2160_REV1:
		compatible = LX2160A_REV1_PCIE_COMPATIBLE;
		break;

	case PEX_LX2160_REV2:
		compatible = LX2160A_REV2_PCIE_COMPATIBLE;
		break;

	case PEX_LS208X:
		compatible = LS2088A_PCIE_COMPATIBLE;
		break;

	default:
		return -ENODEV;
	}

	for_each_compatible_node(pcie_node, NULL, compatible) {
		if (!of_device_is_available(pcie_node))
			continue;
		ctlhw = lsx_pciep_node2ctl(pcie_node);
		if (!ctlhw)
			continue;
		if (lsx_pciep_ctl_filtered(ctlhw->hw.index))
			continue;
		if (lsx_pciep_ctl_is_ep(ctlhw)) {
			ret = lsx_pciep_hw_out_base(ctlhw, pcie_node);
			if (!ret) {
				ret = lsx_pciep_ctl_hw_init(ctlhw);
				if (ret)
					return ret;
				ep_nb += ctlhw->function_num;
				ctlhw->ep_enable = 1;
			}
		}
	}

	LSX_PCIEP_BUS_INFO("PCIe EP finds %d pcie ep(s)", ep_nb);
pcie_mapping_start:
	ep_nb = lsx_pciep_ctl_process_map();

	return ep_nb;
}

int lsx_pciep_ctl_init_win(uint8_t pcie_idx)
{
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_idx];

	if (ctlhw->init)
		return 0;

	if (ctlhw->ep_enable) {
		if (!lsx_pciep_hw_sim_get(pcie_idx) &&
			rte_eal_process_type() == RTE_PROC_PRIMARY) {
			if (!ctlhw->ops)
				return -EINVAL;
			if (ctlhw->clear_win &&
				ctlhw->ops->pcie_disable_ob_win)
				ctlhw->ops->pcie_disable_ob_win(&ctlhw->hw, -1);
			if (ctlhw->clear_win &&
				ctlhw->ops->pcie_disable_ib_win)
				ctlhw->ops->pcie_disable_ib_win(&ctlhw->hw, -1);
		}
		ctlhw->init = 1;
	}

	return 0;
}

#ifndef IORESOURCE_MEM
#define IORESOURCE_MEM        0x00000200
#endif

static int lsx_pciep_sim_rm_dir(const char *dir)
{
	char cur_dir[] = ".";
	char up_dir[] = "..";
	char dir_name[512];
	DIR *dirp;
	struct dirent *dp;
	struct stat dir_stat;
	int ret;

	ret = access(dir, F_OK);
	if (ret) {
		/** Force remove this file
		 */
		ret = remove(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) remove(%s) = %d failed",
				__LINE__, dir, ret);
		}
		return ret;
	}

	ret = stat(dir, &dir_stat);
	if (ret < 0) {
		/** Force remove this file
		 */
		ret = remove(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) remove(%s) = %d failed",
				__LINE__, dir, ret);
		}
		return ret;
	}

	if (S_ISREG(dir_stat.st_mode)) {
		ret = remove(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) remove(%s) = %d failed",
				__LINE__, dir, ret);
		}
	} else if (S_ISDIR(dir_stat.st_mode)) {
		dirp = opendir(dir);
		while ((dp = readdir(dirp)) != NULL) {
			if (strcmp(cur_dir, dp->d_name) == 0 ||
				strcmp(up_dir, dp->d_name) == 0) {
				continue;
			}

			sprintf(dir_name, "%s/%s", dir, dp->d_name);
			lsx_pciep_sim_rm_dir(dir_name);
		}
		closedir(dirp);

		ret = rmdir(dir);
		if (ret) {
			LSX_PCIEP_BUS_ERR("line(%d) rmdir(%s) = %d failed",
				__LINE__, dir, ret);
		}
	} else {
		LSX_PCIEP_BUS_ERR("unknown file(%s) type!",
				dir);
	}

	return 0;
}

int
lsx_pciep_sim_dev_map_inbound(struct rte_lsx_pciep_device *ep_dev)
{
	char dir_name[64];
	char file_name[128];
	char file_link_name[128];
	char buf[1024];
	int status, fd, i, idx = 0, pf = ep_dev->pf;
	uint64_t flag = IORESOURCE_MEM;
	int ret;
	char *penv;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[ep_dev->pcie_id];
	uint16_t vendor_id, device_id, class_id;

	if (!lsx_pciep_hw_sim_get(ep_dev->pcie_id))
		return 0;

	if (ep_dev->is_vf) {
		LSX_PCIEP_BUS_ERR("PCIe EP simulator does not support VF");

		return -ENODEV;
	}

	vendor_id = ctlhw->vendor_id[pf];
	device_id = ctlhw->pf_device_id[pf];
	class_id = ctlhw->class_id[pf];

	penv = getenv("PCIE_EP_SIM_DEV_PATH");
	if (!penv) {
		snprintf(dir_name, sizeof(dir_name),
			LSX_PCIEP_SIM_DEFAULT_PATH PCI_PRI_FMT,
			ep_dev->pcie_id, LSX_PCIEP_SIM_BUS,
			LSX_PCIEP_SIM_PF_DEV,
			pf);
	} else {
		strcpy(dir_name, penv);
		snprintf(dir_name + strlen(penv),
			sizeof(dir_name) - strlen(penv),
			PCI_PRI_FMT, ep_dev->pcie_id,
			LSX_PCIEP_SIM_BUS,
			LSX_PCIEP_SIM_PF_DEV, pf);
	}

	if (!access(dir_name, F_OK)) {
		status = lsx_pciep_sim_rm_dir(dir_name);
		if (status < 0) {
			LSX_PCIEP_BUS_ERR("Remove dir %s failed", dir_name);

			return -ENODEV;
		}
	}

	status = mkdir(dir_name, 0777);
	if (status < 0) {
		LSX_PCIEP_BUS_ERR("Create dir %s failed", dir_name);
		return -ENODEV;
	}

	snprintf(file_name, sizeof(file_name), "%s/vendor", dir_name);
	sprintf(buf, "0x%04x\n", vendor_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);

		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);

		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/device", dir_name);
	sprintf(buf, "0x%04x\n", device_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/subsystem_vendor", dir_name);
	sprintf(buf, "0x%04x\n", vendor_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/subsystem_device", dir_name);
	sprintf(buf, "0x%04x\n", device_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_name, sizeof(file_name), "%s/class", dir_name);
	sprintf(buf, "0x%04x\n", class_id);
	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, 7);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	snprintf(file_link_name, sizeof(file_link_name),
		"%s/igb_uio", dir_name);
	sprintf(buf, "%s", "igb_uio\n");
	fd = open(file_link_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, sizeof("igb_uio\n"));
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);
	snprintf(file_name, sizeof(file_name), "%s/driver", dir_name);
	ret = symlink(file_link_name, file_name);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Symlink file %s failed", file_name);
		return -ENODEV;
	}

	snprintf(file_name, sizeof(file_name), "%s/resource", dir_name);
	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if (ctlhw->ib_mem.pf_ib_bar[pf][i].size) {
			sprintf(&buf[idx], "0x%016lx",
				ctlhw->ib_mem.pf_ib_bar[pf][i].inbound_phy);
			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;

			sprintf(&buf[idx], "0x%016lx",
				ctlhw->ib_mem.pf_ib_bar[pf][i].inbound_phy +
				ctlhw->ib_mem.pf_ib_bar[pf][i].size - 1);

			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;

			sprintf(&buf[idx], "0x%016lx\r\n", flag);
			idx += 20;
		} else {
			sprintf(&buf[idx], "0x%016lx", (dma_addr_t)0);
			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;
			sprintf(&buf[idx], "0x%016lx", (dma_addr_t)0);
			idx += 18;
			sprintf(&buf[idx], " ");
			idx++;
			sprintf(&buf[idx], "0x%016lx\r\n", (dma_addr_t)0);
			idx += 20;
		}
	}

	fd = open(file_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Open file %s failed", file_name);
		return -ENODEV;
	}
	ret = write(fd, buf, idx);
	if (ret < 0) {
		LSX_PCIEP_BUS_ERR("Write file %s failed", file_name);
		close(fd);
		return -ENODEV;
	}
	close(fd);

	LSX_PCIEP_BUS_INFO("PEX%d:pf%d bar info:\r\n%s",
		ep_dev->pcie_id, ep_dev->pf, buf);

	return 0;
}

int
lsx_pciep_fun_set(uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id,
	uint8_t pcie_id, int pf, int is_vf)
{
	struct lsx_pciep_ctl_hw *ctlhw;

	if (pcie_id >= LSX_MAX_PCIE_NB || pf >= PF_MAX_NB) {
		LSX_PCIEP_BUS_ERR("%s Invalid PCIe ID or PF ID",
			__func__);

		return -EINVAL;
	}

	ctlhw = &s_pctl_hw[pcie_id];
	if (!ctlhw->ep_enable) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) is not EP",
			__func__, pcie_id);

		return -ENODEV;
	}
	if (!ctlhw->pf_enable[pf]) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) pf(%d) is not enabled",
			__func__, pcie_id, pf);

		return -ENODEV;
	}

	if (!is_vf) {
		ctlhw->vendor_id[pf] = vendor_id;
		ctlhw->pf_device_id[pf] = device_id;
		ctlhw->class_id[pf] = class_id;
	} else {
		ctlhw->vf_device_id[pf] = device_id;
	}

	if (!lsx_pciep_hw_sim_get(pcie_id)) {
		if (ctlhw->ops && ctlhw->ops->pcie_fun_init) {
			ctlhw->ops->pcie_fun_init(&ctlhw->hw,
				pf, is_vf,
				vendor_id, device_id, class_id);
		}
	}

	return 0;
}

int
lsx_pciep_ctl_dev_set(uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id,
	uint8_t pcie_id, uint8_t pf)
{
	struct lsx_pciep_ctl_hw *ctlhw;

	if (pcie_id >= LSX_MAX_PCIE_NB || pf >= PF_MAX_NB) {
		LSX_PCIEP_BUS_ERR("%s Invalid PCIe ID or PF ID",
			__func__);

		return -EINVAL;
	}

	ctlhw = &s_pctl_hw[pcie_id];
	if (!ctlhw->ep_enable) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) is not EP",
			__func__, pcie_id);

		return -ENODEV;
	}
	if (!ctlhw->pf_enable[pf]) {
		LSX_PCIEP_BUS_ERR("%s PCIe(%d) pf(%d) is not enabled",
			__func__, pcie_id, pf);

		return -ENODEV;
	}

	ctlhw->vendor_id[pf] = vendor_id;
	ctlhw->pf_device_id[pf] = device_id;
	ctlhw->class_id[pf] = class_id;

	if (!lsx_pciep_hw_sim_get(pcie_id)) {
		if (ctlhw->ops && ctlhw->ops->pcie_fun_init) {
			ctlhw->ops->pcie_fun_init(&ctlhw->hw,
				pf, 0, vendor_id, device_id, class_id);
		}
	}

	return 0;
}

static void
lsx_pciep_hw_set_by_env(void)
{
	int i, j, k;
	struct lsx_pciep_ctl_hw *ctlhw;

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		ctlhw = &s_pctl_hw[i];
		ctlhw->rbp = lsx_pciep_rbp_env_get(i);
		ctlhw->sim = lsx_pciep_sim_env_get(i);
		ctlhw->hw.ob_policy = lsx_pciep_ob_policy_env_get(i);
		ctlhw->out_size_per_fun = lsx_pciep_ob_fun_size_env_get(i);
		for (j = 0; j < PF_MAX_NB; j++) {
			ctlhw->pf_enable[j] =
				lsx_pciep_fun_env_get(i, j, -1);
			if (ctlhw->pf_enable[j])
				ctlhw->function_num++;
			ctlhw->vio_enable[j] =
				lsx_pciep_vio_env_get(i, j);
			for (k = 0; k < PCIE_MAX_VF_NUM; k++) {
				ctlhw->vf_enable[j][k] =
					lsx_pciep_fun_env_get(i, j, k);
				if (ctlhw->vf_enable[j][k])
					ctlhw->function_num++;
			}
		}
	}
}

int
lsx_pciep_primary_init(void)
{
	int ret = 0;

	if (s_pciep_init_flag) {
		LSX_PCIEP_BUS_INFO("%s has been executed!", __func__);

		return 0;
	}

	s_pctl_hw = malloc(LSX_PCIEP_CTL_HW_TOTAL_SIZE);
	if (!s_pctl_hw) {
		LSX_PCIEP_BUS_ERR("malloc (%ldBytes) for s_pctl_hw failed",
			LSX_PCIEP_CTL_HW_TOTAL_SIZE);

		ret = -ENOMEM;
		goto init_exit;
	}
	memset(s_pctl_hw, 0, LSX_PCIEP_CTL_HW_TOTAL_SIZE);

	lsx_pciep_parse_env_variable();
	lsx_pciep_hw_set_by_env();
	ret = lsx_pciep_hw_set_type();
	if (ret) {
		ret = -ENODEV;
		goto init_exit;
	}
	lsx_pciep_hw_enable_clear_inbound();

	lsx_pciep_ctl_set_ops();

	ret = lsx_pciep_find_all();
	if (ret <= 0) {
		ret = -ENODEV;
		goto init_exit;
	}
	ret = 0;

init_exit:
	if (ret) {
		if (s_pctl_hw)
			free(s_pctl_hw);

		s_pctl_hw = NULL;
	}
	s_pciep_init_flag = 1;

	return ret;
}

int
lsx_pciep_uninit(void)
{
	int dev_idx;
	struct lsx_pciep_ctl_hw *ctlhw;

	if (!s_pctl_hw) {
		s_pciep_init_flag = 0;
		return 0;
	}

	for (dev_idx = 0; dev_idx < LSX_MAX_PCIE_NB; dev_idx++) {
		ctlhw = &s_pctl_hw[dev_idx];
		if (!ctlhw->ep_enable)
			continue;

		if (ctlhw->hw.dbi_vir)
			munmap(ctlhw->hw.dbi_vir, ctlhw->hw.dbi_size);

		if (ctlhw->out_vir)
			munmap((void *)ctlhw->out_vir, ctlhw->hw.out_size);

		if (ctlhw->ops->pcie_deconfig)
			ctlhw->ops->pcie_deconfig(&ctlhw->hw);
		ctlhw->ops = NULL;
	}

	if (s_pctl_hw)
		free(s_pctl_hw);
	s_pctl_hw = NULL;

	s_pciep_init_flag = 0;

	return 0;
}

int
lsx_pciep_set_ib_win(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, uint64_t size)
{
	int pcie_id = ep_dev->pcie_id;
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	struct lsx_pciep_ib_mem *ib_mem = &ctlhw->ib_mem;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	size_t mz_size;

	if (size < LSX_PCIEP_INBOUND_MIN_BAR_SIZE)
		size = LSX_PCIEP_INBOUND_MIN_BAR_SIZE;
	if (!rte_is_power_of_2(size))
		size = rte_align64pow2(size);

	if (bar_idx >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("%s too large bar number(%d)",
			__func__, bar_idx);

		return -EINVAL;
	}

	bzero(mz_name, RTE_MEMZONE_NAMESIZE);

	if (is_vf) {
		if (ib_mem->vf_mz[pf][vf][bar_idx]) {
			LSX_PCIEP_BUS_INFO("MZ(%s) detected",
				ib_mem->vf_mz[pf][vf][bar_idx]->name);

			ep_dev->virt_addr[bar_idx] =
				ib_mem->vf_ib_bar[pf][vf][bar_idx].inbound_virt;

			return 0;
		}
		snprintf(mz_name, RTE_MEMZONE_NAMESIZE - 1,
			"mz_pciep%d_pf%d_vf%d_bar%d",
			ctlhw->hw.index, pf, vf, bar_idx);
	} else {
		if (ib_mem->pf_mz[pf][bar_idx]) {
			LSX_PCIEP_BUS_INFO("MZ(%s) detected",
				ib_mem->pf_mz[pf][bar_idx]->name);

			ep_dev->virt_addr[bar_idx] =
				ib_mem->pf_ib_bar[pf][bar_idx].inbound_virt;

			return 0;
		}
		snprintf(mz_name, RTE_MEMZONE_NAMESIZE - 1,
			"mz_pciep%d_pf%d_bar%d",
			ctlhw->hw.index, pf, bar_idx);
	}
	mz_size = size * 2;

	mz = rte_memzone_reserve_aligned(mz_name,
			mz_size, 0, RTE_MEMZONE_IOVA_CONTIG,
			mz_size);
	if (!mz || !mz->iova || !mz->addr) {
		LSX_PCIEP_BUS_ERR("Reserve %s memory(%zuB) failed",
			mz_name, mz_size);

		return -ENOMEM;
	}

	return lsx_pciep_set_ib_win_mz(ep_dev, bar_idx, mz, 1);
}

int
lsx_pciep_set_ib_win_mz(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, const struct rte_memzone *mz,
	int vf_isolate __rte_unused)
{
	int pcie_id = ep_dev->pcie_id;
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	struct lsx_pciep_ib_mem *ib_mem = &ctlhw->ib_mem;
	struct lsx_pciep_inbound_bar *ib_bar;
	uint64_t size = mz->len;

	if (size < LSX_PCIEP_INBOUND_MIN_BAR_SIZE)
		size = LSX_PCIEP_INBOUND_MIN_BAR_SIZE;
	if (!rte_is_power_of_2(size))
		size = rte_align64pow2(size);

	if (bar_idx >= PCI_MAX_RESOURCE) {
		LSX_PCIEP_BUS_ERR("%s too large bar number(%d)",
			__func__, bar_idx);

		return -EINVAL;
	}

	if (is_vf) {
		if (ib_mem->vf_mz[pf][vf][bar_idx]) {
			LSX_PCIEP_BUS_INFO("MZ(%s) detected",
				ib_mem->vf_mz[pf][vf][bar_idx]->name);

			ep_dev->virt_addr[bar_idx] =
				ib_mem->vf_ib_bar[pf][vf][bar_idx].inbound_virt;

			return 0;
		}
		ib_mem->vf_mz[pf][vf][bar_idx] = mz;
		ib_bar = &ib_mem->vf_ib_bar[pf][vf][bar_idx];
		snprintf(ib_bar->name,
			RTE_DEV_NAME_MAX_LEN - 1,
			"pciep%d_pf%d_vf%d_bar%d",
			ctlhw->hw.index, pf, vf, bar_idx);
		ib_bar->inbound_virt = (uint8_t *)mz->addr;
		ib_bar->inbound_iova = mz->iova;
		ib_bar->size = size;
	} else {
		if (ib_mem->pf_mz[pf][bar_idx]) {
			LSX_PCIEP_BUS_INFO("MZ(%s) detected",
				ib_mem->pf_mz[pf][bar_idx]->name);

			ep_dev->virt_addr[bar_idx] =
				ib_mem->pf_ib_bar[pf][bar_idx].inbound_virt;

			return 0;
		}
		ib_mem->pf_mz[pf][bar_idx] = mz;
		ib_bar = &ib_mem->pf_ib_bar[pf][bar_idx];
		snprintf(ib_bar->name, RTE_DEV_NAME_MAX_LEN - 1,
			"pciep%d_pf%d_bar%d",
			pcie_id, pf, bar_idx);
		ib_bar->inbound_virt = (uint8_t *)mz->addr;
		ib_bar->inbound_iova = mz->iova;
		ib_bar->size = size;
	}

	if (!lsx_pciep_hw_sim_get(ctlhw->hw.index)) {
		ctlhw->ops->pcie_cfg_ib_win(&ctlhw->hw,
			pf, is_vf, vf,
			bar_idx, mz->iova, size, 1);
	}

	if (!is_vf) {
		ep_dev->virt_addr[bar_idx] =
			ib_mem->pf_ib_bar[pf][bar_idx].inbound_virt;
	} else {
		ep_dev->virt_addr[bar_idx] =
			ib_mem->vf_ib_bar[pf][vf][bar_idx].inbound_virt;
	}

	return 0;
}

#define OB_PF_INFO_DUMP_FORMAT(pci, pf, \
		vir, phy, bus, size) \
		"Outbound PEX%d PF%d:" \
		"  MEM VIRT:%p" PRIx64 \
		"  MEM:0x%" PRIx64 \
		"  PCI:0x%" PRIx64 \
		"  SIZE:0x%" PRIx64, \
		pci, pf, (void *)vir, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size

#define OB_VF_INFO_DUMP_FORMAT(pci, pf, vf, \
		vir, phy, bus, size) \
		"Outbound PEX%d PF%d-VF%d:" \
		"  MEM VIRT:%p" PRIx64 \
		"  MEM:0x%" PRIx64 \
		"  PCI:0x%" PRIx64 \
		"  SIZE:0x%" PRIx64, \
		pci, pf, vf, (void *)vir, \
		(unsigned long)phy, \
		(unsigned long)bus, \
		(unsigned long)size

static uint8_t *
lsx_pciep_set_ob_win_rbp(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size)
{
	int pf = ep_dev->pf;
	int vf = ep_dev->vf;
	int is_vf = ep_dev->is_vf;
	int pcie_id = ep_dev->pcie_id;
	uint64_t mask;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];

	mask = size - 1;

	if (pci_addr & mask) {
		LSX_PCIEP_BUS_ERR("bus(0x%lx) and size(0x%lx) not aligned",
			pci_addr, size);
		return NULL;
	}

	ep_dev->ob_map_bus_base = pci_addr;
	ep_dev->ob_win_size = size;
	ep_dev->ob_win_nb = 1;

	ep_dev->ob_phy_base =
		ctlhw->ops->pcie_map_ob_win(&ctlhw->hw, pf,
				is_vf, vf,
				ep_dev->ob_map_bus_base,
				size);
	ep_dev->ob_virt_base =
		lsx_pciep_map_region(ep_dev->ob_phy_base,
				size);

	if (is_vf)
		LSX_PCIEP_BUS_INFO(OB_VF_INFO_DUMP_FORMAT(pcie_id,
			pf, vf,
			ep_dev->ob_virt_base,
			ep_dev->ob_phy_base,
			ep_dev->ob_map_bus_base,
			ep_dev->ob_win_size));
	else
		LSX_PCIEP_BUS_INFO(OB_PF_INFO_DUMP_FORMAT(pcie_id,
			pf,
			ep_dev->ob_virt_base,
			ep_dev->ob_phy_base,
			ep_dev->ob_map_bus_base,
			ep_dev->ob_win_size));

	return ep_dev->ob_virt_base;
}

static uint8_t *
lsx_pciep_set_ob_win_norbp(struct rte_lsx_pciep_device *ep_dev)
{
	int pf = ep_dev->pf;
	int is_vf = ep_dev->is_vf;
	int vf = ep_dev->vf;
	int pcie_id = ep_dev->pcie_id;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	uint32_t idx, out_win_nb;
	uint64_t pci_addr = 0, out_phy;

	out_win_nb = ctlhw->out_win_per_fun;

	ep_dev->ob_map_bus_base = pci_addr;
	ep_dev->ob_win_size = ctlhw->out_win_size;
	ep_dev->ob_win_nb = out_win_nb;

	if (ctlhw->hw.ob_policy == LSX_PCIEP_OB_SHARE &&
		ctlhw->hw.primary_done) {
		ep_dev->ob_phy_base = ctlhw->hw.out_base;
		ep_dev->ob_virt_base = ctlhw->out_vir;

		return ep_dev->ob_virt_base + pci_addr;
	}

	for (idx = 0; idx < out_win_nb; idx++) {
		out_phy = ctlhw->ops->pcie_map_ob_win(&ctlhw->hw,
					pf, is_vf, vf,
					pci_addr,
					ctlhw->out_win_size);
		pci_addr += ctlhw->out_win_size;
		if (idx == 0) {
			ep_dev->ob_phy_base = out_phy;
			ep_dev->ob_virt_base = ctlhw->out_vir +
				out_phy - ctlhw->hw.out_base;
		}
	}
	ep_dev->ob_virt_base =
		lsx_pciep_map_region(ep_dev->ob_phy_base,
			out_win_nb * ctlhw->out_win_size);

	if (ctlhw->hw.ob_policy == LSX_PCIEP_OB_SHARE)
		ctlhw->hw.primary_done = 1;

	return ep_dev->ob_virt_base;
}

void *
lsx_pciep_set_ob_win(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size)
{
	int pcie_id = ep_dev->pcie_id;
	uint8_t *vaddr;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];

	if (ctlhw->rbp)
		vaddr = lsx_pciep_set_ob_win_rbp(ep_dev, pci_addr, size);
	else
		vaddr = lsx_pciep_set_ob_win_norbp(ep_dev);

	return vaddr;
}

void
lsx_pciep_set_sim_ob_win(struct rte_lsx_pciep_device *ep_dev,
	uint64_t vir_offset)
{
	if (!lsx_pciep_hw_sim_get(ep_dev->pcie_id))
		return;

	ep_dev->ob_map_bus_base = 0;
	ep_dev->ob_phy_base = 0;
	ep_dev->ob_virt_base = (void *)vir_offset;
}

static void
lsx_pciep_misx_ob_vir_map(uint64_t msix_addr[],
	void *msix_vir[], int num)
{
	int i;
	uint8_t *vir;
	uint64_t min = msix_addr[0], max = 0, map_size;

	for (i = 0; i < num; i++) {
		if (msix_addr[i] > max)
			max = msix_addr[i];
		if (msix_addr[i] < min)
			min = msix_addr[i];
	}

	map_size = (max - min) > CFG_MSIX_OB_SIZE ?
		(max - min) : CFG_MSIX_OB_SIZE;
	vir = lsx_pciep_map_region(min, map_size);

	for (i = 0; i < num; i++)
		msix_vir[i] = vir + msix_addr[i] - min;
}

void
lsx_pciep_msix_init(struct rte_lsx_pciep_device *ep_dev __rte_unused)
{
}

void
lsx_pciep_multi_msix_init(struct rte_lsx_pciep_device *ep_dev,
	int vector_total)
{
	int pcie_id = ep_dev->pcie_id, i;
	struct lsx_pciep_ctl_hw *ctlhw = &s_pctl_hw[pcie_id];
	uint64_t msix_phy[vector_total];

	ctlhw->hw.msi_flag = ep_dev->mmsi_flag;

	ep_dev->msix_addr = malloc(sizeof(void *) * vector_total);
	ep_dev->msix_data = malloc(sizeof(uint32_t) * vector_total);

	ctlhw->ops->pcie_msix_cfg(&ctlhw->hw, ep_dev->pf,
			ep_dev->is_vf, ep_dev->vf,
			msix_phy, ep_dev->msix_data,
			vector_total);

	if (ctlhw->hw.msi_flag == LSX_PCIEP_MSIX_INT) {
		for (i = 0; i < vector_total; i++) {
			ep_dev->msix_addr[i] =
				ctlhw->hw.dbi_vir +
				msix_phy[i] - ctlhw->hw.dbi_phy;
		}
	} else if (ctlhw->hw.msi_flag == LSX_PCIEP_MMSI_INT) {
		lsx_pciep_misx_ob_vir_map(msix_phy,
			ep_dev->msix_addr,
			vector_total);
	}
}

uint64_t
lsx_pciep_msix_get_vaddr(struct rte_lsx_pciep_device *ep_dev,
	uint32_t vector)
{
	return (uint64_t)ep_dev->msix_addr[vector];
}

uint32_t
lsx_pciep_msix_get_cmd(struct rte_lsx_pciep_device *ep_dev,
	uint32_t vector)
{
	return ep_dev->msix_data[vector];
}

void
lsx_pciep_start_msix(void *addr, uint32_t cmd)
{
	rte_write32(cmd, addr);
}

void
lsx_pciep_msix_cmd_send(uint64_t addr, uint32_t cmd)
{
	rte_write32(cmd, (void *)addr);
}

int
lsx_pciep_bus_ob_mapped(struct rte_lsx_pciep_device *ep_dev,
	uint64_t bus_addr)
{
	uint64_t offset, range;

	if (lsx_pciep_hw_sim_get(ep_dev->pcie_id))
		return 1;

	offset = bus_addr - ep_dev->ob_map_bus_base;
	range = ep_dev->ob_win_size * ep_dev->ob_win_nb;

	if (offset > range)
		return 0;

	return 1;
}

static void __attribute__((destructor(102))) lsx_pciep_finish(void)
{
	lsx_pciep_uninit();

	if (primary_shared_mz) {
		rte_memzone_free(primary_shared_mz);

		primary_shared_mz = NULL;
	}
}
