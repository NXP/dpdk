/* Copyright (c) 2010-2012 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>

/* This header declares the driver interface we implement */
#include <usdpaa/fman.h>

/* This header declares things about Fman hardware itself (the format of status
 * words and an inline implementation of CRC64). We include it only in order to
 * instantiate the one global variable it depends on. */
#include <fsl_fman.h>

#include <internal/of.h>
#include <usdpaa/of.h>

/* Instantiate the global variable that the inline CRC64 implementation (in
 * <fsl_fman.h>) depends on. */
DECLARE_FMAN_CRC64_TABLE();

/* The exported "struct fman_if" type contains the subset of fields we want
 * exposed. This struct is embedded in a larger "struct __fman_if" which
 * contains the extra bits we *don't* want exposed. */
struct __fman_if {
	struct fman_if __if;
	char node_path[PATH_MAX];
	uint64_t regs_size;
	void *ccsr_map;
	void *bmi_map;
	void *qmi_map;
	struct list_head node;
};

#define FMAN_PORT_MAX_EXT_POOLS_NUM	8
#define FMAN_PORT_OBS_EXT_POOLS_NUM	2
#define FMAN_PORT_CG_MAP_NUM		8
#define FMAN_PORT_PRS_RESULT_WORDS_NUM	8
#define FMAN_PORT_BMI_FIFO_UNITS	0x100
#define FMAN_PORT_IC_OFFSET_UNITS	0x10

#define QMI_PORT_REGS_OFFSET		0x400

struct rx_bmi_regs {
	uint32_t fmbm_rcfg;		/**< Rx Configuration */
	uint32_t fmbm_rst;		/**< Rx Status */
	uint32_t fmbm_rda;		/**< Rx DMA attributes*/
	uint32_t fmbm_rfp;		/**< Rx FIFO Parameters*/
	uint32_t fmbm_rfed;		/**< Rx Frame End Data*/
	uint32_t fmbm_ricp;		/**< Rx Internal Context Parameters*/
	uint32_t fmbm_rim;		/**< Rx Internal Buffer Margins*/
	uint32_t fmbm_rebm;		/**< Rx External Buffer Margins*/
	uint32_t fmbm_rfne;		/**< Rx Frame Next Engine*/
	uint32_t fmbm_rfca;		/**< Rx Frame Command Attributes.*/
	uint32_t fmbm_rfpne;		/**< Rx Frame Parser Next Engine*/
	uint32_t fmbm_rpso;		/**< Rx Parse Start Offset*/
	uint32_t fmbm_rpp;		/**< Rx Policer Profile  */
	uint32_t fmbm_rccb;		/**< Rx Coarse Classification Base */
	uint32_t fmbm_reth;		/**< Rx Excessive Threshold */
	uint32_t reserved003c[1];	/**< (0x03C 0x03F) */
	uint32_t fmbm_rprai[FMAN_PORT_PRS_RESULT_WORDS_NUM];
					/**< Rx Parse Results Array Init*/
	uint32_t fmbm_rfqid;		/**< Rx Frame Queue ID*/
	uint32_t fmbm_refqid;		/**< Rx Error Frame Queue ID*/
	uint32_t fmbm_rfsdm;		/**< Rx Frame Status Discard Mask*/
	uint32_t fmbm_rfsem;		/**< Rx Frame Status Error Mask*/
	uint32_t fmbm_rfene;		/**< Rx Frame Enqueue Next Engine */
	uint32_t reserved0074[0x2];	/**< (0x074-0x07C)  */
	uint32_t fmbm_rcmne;		/**< Rx Frame Continuous Mode Next Engine */
	uint32_t reserved0080[0x20];/**< (0x080 0x0FF)  */
	uint32_t fmbm_ebmpi[FMAN_PORT_MAX_EXT_POOLS_NUM];
					/**< Buffer Manager pool Information-*/
	uint32_t fmbm_acnt[FMAN_PORT_MAX_EXT_POOLS_NUM];
					/**< Allocate Counter-*/
	uint32_t reserved0130[8];
					/**< 0x130/0x140 - 0x15F reserved -*/
	uint32_t fmbm_rcgm[FMAN_PORT_CG_MAP_NUM];
					/**< Congestion Group Map*/
	uint32_t fmbm_mpd;		/**< BM Pool Depletion  */
	uint32_t reserved0184[0x1F];	/**< (0x184 0x1FF) */
	uint32_t fmbm_rstc;		/**< Rx Statistics Counters*/
	uint32_t fmbm_rfrc;		/**< Rx Frame Counter*/
	uint32_t fmbm_rfbc;		/**< Rx Bad Frames Counter*/
	uint32_t fmbm_rlfc;		/**< Rx Large Frames Counter*/
	uint32_t fmbm_rffc;		/**< Rx Filter Frames Counter*/
	uint32_t fmbm_rfdc;		/**< Rx Frame Discard Counter*/
	uint32_t fmbm_rfldec;		/**< Rx Frames List DMA Error Counter*/
	uint32_t fmbm_rodc;		/**< Rx Out of Buffers Discard nntr*/
	uint32_t fmbm_rbdc;		/**< Rx Buffers Deallocate Counter*/
	uint32_t reserved0224[0x17];	/**< (0x224 0x27F) */
	uint32_t fmbm_rpc;		/**< Rx Performance Counters*/
	uint32_t fmbm_rpcp;		/**< Rx Performance Count Parameters*/
	uint32_t fmbm_rccn;		/**< Rx Cycle Counter*/
	uint32_t fmbm_rtuc;		/**< Rx Tasks Utilization Counter*/
	uint32_t fmbm_rrquc;		/**< Rx Receive Queue Utilization cntr*/
	uint32_t fmbm_rduc;		/**< Rx DMA Utilization Counter*/
	uint32_t fmbm_rfuc;		/**< Rx FIFO Utilization Counter*/
	uint32_t fmbm_rpac;		/**< Rx Pause Activation Counter*/
	uint32_t reserved02a0[0x18];	/**< (0x2A0 0x2FF) */
	uint32_t fmbm_rdbg;		/**< Rx Debug-*/
};

struct oh_bmi_regs {
	uint32_t fmbm_ocfg;		/**< O/H Configuration  */
	uint32_t fmbm_ost;		/**< O/H Status */
	uint32_t fmbm_oda;		/**< O/H DMA attributes  */
	uint32_t fmbm_oicp;		/**< O/H Internal Context Parameters */
	uint32_t fmbm_ofdne;		/**< O/H Frame Dequeue Next Engine  */
	uint32_t fmbm_ofne;		/**< O/H Frame Next Engine  */
	uint32_t fmbm_ofca;		/**< O/H Frame Command Attributes.  */
	uint32_t fmbm_ofpne;		/**< O/H Frame Parser Next Engine  */
	uint32_t fmbm_opso;		/**< O/H Parse Start Offset  */
	uint32_t fmbm_opp;		/**< O/H Policer Profile */
	uint32_t fmbm_occb;		/**< O/H Coarse Classification base */
	uint32_t fmbm_oim;		/**< O/H Internal margins*/
	uint32_t fmbm_ofp;		/**< O/H Fifo Parameters*/
	uint32_t fmbm_ofed;		/**< O/H Frame End Data*/
	uint32_t reserved0030[2];	/**< (0x038 - 0x03F) */
	uint32_t fmbm_oprai[FMAN_PORT_PRS_RESULT_WORDS_NUM];
				/**< O/H Parse Results Array Initialization  */
	uint32_t fmbm_ofqid;		/**< O/H Frame Queue ID  */
	uint32_t fmbm_oefqid;		/**< O/H Error Frame Queue ID  */
	uint32_t fmbm_ofsdm;		/**< O/H Frame Status Discard Mask  */
	uint32_t fmbm_ofsem;		/**< O/H Frame Status Error Mask  */
	uint32_t fmbm_ofene;		/**< O/H Frame Enqueue Next Engine  */
	uint32_t fmbm_orlmts;		/**< O/H Rate Limiter Scale  */
	uint32_t fmbm_orlmt;		/**< O/H Rate Limiter  */
	uint32_t fmbm_ocmne;		/**< O/H Continuous Mode Next Engine  */
	uint32_t reserved0080[0x20];	/**< 0x080 - 0x0FF Reserved */
	uint32_t fmbm_oebmpi[2];	/**< Buf Mngr Observed Pool Info */
	uint32_t reserved0108[0x16];	/**< 0x108 - 0x15F Reserved */
	uint32_t fmbm_ocgm;		/**< Observed Congestion Group Map */
	uint32_t reserved0164[0x7];	/**< 0x164 - 0x17F Reserved */
	uint32_t fmbm_ompd;		/**< Observed BMan Pool Depletion */
	uint32_t reserved0184[0x1F];	/**< 0x184 - 0x1FF Reserved */
	uint32_t fmbm_ostc;		/**< O/H Statistics Counters  */
	uint32_t fmbm_ofrc;		/**< O/H Frame Counter  */
	uint32_t fmbm_ofdc;		/**< O/H Frames Discard Counter  */
	uint32_t fmbm_ofledc;		/**< O/H Frames Len Err Discard Cntr */
	uint32_t fmbm_ofufdc;		/**< O/H Frames Unsprtd Discard Cutr  */
	uint32_t fmbm_offc;		/**< O/H Filter Frames Counter  */
	uint32_t fmbm_ofwdc;		/**< Rx Frames WRED Discard Counter  */
	uint32_t fmbm_ofldec;		/**< O/H Frames List DMA Error Cntr */
	uint32_t fmbm_obdc;		/**< O/H Buffers Deallocate Counter */
	uint32_t reserved0218[0x17];	/**< (0x218 - 0x27F) */
	uint32_t fmbm_opc;		/**< O/H Performance Counters  */
	uint32_t fmbm_opcp;		/**< O/H Performance Count Parameters */
	uint32_t fmbm_occn;		/**< O/H Cycle Counter  */
	uint32_t fmbm_otuc;		/**< O/H Tasks Utilization Counter  */
	uint32_t fmbm_oduc;		/**< O/H DMA Utilization Counter */
	uint32_t fmbm_ofuc;		/**< O/H FIFO Utilization Counter */
};

struct fman_port_qmi_regs {
	uint32_t fmqm_pnc;		/**< PortID n Configuration Register */
	uint32_t fmqm_pns;		/**< PortID n Status Register */
	uint32_t fmqm_pnts;		/**< PortID n Task Status Register */
	uint32_t reserved00c[4];	/**< 0xn00C - 0xn01B */
	uint32_t fmqm_pnen;		/**< PortID n Enqueue NIA Register */
	uint32_t fmqm_pnetfc;		/**< PortID n Enq Total Frame Counter */
	uint32_t reserved024[2];	/**< 0xn024 - 0x02B */
	uint32_t fmqm_pndn;		/**< PortID n Dequeue NIA Register */
	uint32_t fmqm_pndc;		/**< PortID n Dequeue Config Register */
	uint32_t fmqm_pndtfc;		/**< PortID n Dequeue tot Frame cntr */
	uint32_t fmqm_pndfdc;		/**< PortID n Dequeue FQID Dflt Cntr */
	uint32_t fmqm_pndcc;		/**< PortID n Dequeue Confirm Counter */
};

/* CCSR map address to access ccsr based register */
void *fman_ccsr_map;
/* fman version info */
u16 fman_ip_rev;
static int get_once;
u32 fman_dealloc_bufs_mask_hi;
u32 fman_dealloc_bufs_mask_lo;

static int ccsr_map_fd = -1;
static COMPAT_LIST_HEAD(__ifs);

/* This is the (const) global variable that callers have read-only access to.
 * Internally, we have read-write access directly to __ifs. */
const struct list_head *fman_if_list = &__ifs;

static int _dtsec_set_stn_mac_addr(struct __fman_if *m, uint8_t *eth)
{
	void *reg = &((struct dtsec_regs *)m->ccsr_map)->maccfg1;
	u32 val = in_be32(reg);

	memcpy(&m->__if.mac_addr, eth, ETHER_ADDR_LEN);
	reg = &((struct dtsec_regs *)m->ccsr_map)->macstnaddr1;
	val = (m->__if.mac_addr.addr_bytes[2] |
	       (m->__if.mac_addr.addr_bytes[3] << 8) |
	       (m->__if.mac_addr.addr_bytes[4] << 16) |
	       (m->__if.mac_addr.addr_bytes[5] << 24));
	out_be32(reg, val);

	reg = &((struct dtsec_regs *)m->ccsr_map)->macstnaddr2;
	val = ((m->__if.mac_addr.addr_bytes[0] << 16) |
	       (m->__if.mac_addr.addr_bytes[1] << 24));
	out_be32(reg, val);

	return 0;
}

static int _dtsec_get_stn_mac_addr(struct __fman_if *m, uint8_t *eth)
{
	void *reg = &((struct dtsec_regs *)m->ccsr_map)->macstnaddr1;
	u32 val = in_be32(reg);

	eth[2] = (val & 0x000000ff) >> 0;
	eth[3] = (val & 0x0000ff00) >> 8;
	eth[4] = (val & 0x00ff0000) >> 16;
	eth[5] = (val & 0xff000000) >> 24;

	reg = &((struct dtsec_regs *)m->ccsr_map)->macstnaddr2;
	val = in_be32(reg);

	eth[0] = (val & 0x00ff0000) >> 16;
	eth[1] = (val & 0xff00ff00) >> 24;

	return 0;
}

static void if_destructor(struct __fman_if *__if)
{
	struct fman_if_bpool *bp, *tmpbp;

	if (__if->__if.mac_type == fman_offline)
		goto cleanup;

	list_for_each_entry_safe(bp, tmpbp, &__if->__if.bpool_list, node) {
		list_del(&bp->node);
		free(bp);
	}
cleanup:
	free(__if);
}

/* These constructs shrink the size of fman_[if_]init() considerably */
#define my_log(err, fmt, args...) \
	fprintf(stderr, "ERR: %s:%hu:%s()\n%s: " fmt, \
		__FILE__, __LINE__, __func__, strerror(err), ##args)
#define my_err(cond, rc, fmt, args...) \
	if (unlikely(cond)) { \
		_errno = (rc); \
		my_log(_errno, fmt, ##args); \
		goto err; \
	}

static int fman_get_ip_rev(const struct device_node *fman_node)
{
	const uint32_t *fman_addr;
	uint64_t phys_addr;
	uint64_t regs_size;
	uint32_t ip_rev_1;
	int _errno;

	fman_addr = of_get_address(fman_node, 0, &regs_size, NULL);
	if (!fman_addr) {
		pr_err("of_get_address cannot return fman address\n");
		return -EINVAL;
	}
	phys_addr = of_translate_address(fman_node, fman_addr);
	if (!phys_addr) {
		pr_err("of_translate_address failed\n");
		return -EINVAL;
	}
	fman_ccsr_map = mmap(NULL, regs_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			     ccsr_map_fd, phys_addr);
	if (fman_ccsr_map == MAP_FAILED) {
		pr_err("Can not map FMan ccsr base\n");
		return -EINVAL;
	}

	ip_rev_1 = in_be32(fman_ccsr_map + FMAN_IP_REV_1);
	fman_ip_rev = (ip_rev_1 & FMAN_IP_REV_1_MAJOR_MASK) >>
			FMAN_IP_REV_1_MAJOR_SHIFT;

	_errno = munmap(fman_ccsr_map, regs_size);
	if (_errno)
		pr_err("munmap() of FMan ccsr failed\n");

	return 0;
}

static int find_mac_name(struct ether_addr *mac_addr, char *name)
{
	int sock, _errno = -1;
	struct ifaddrs *ifa, *inf;
	struct ifreq ifr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == sock) {
		my_log(errno, "socket open failed\n");
		return errno;
	}

	if (getifaddrs(&ifa)) {
		my_log(errno, "Getting list of interfaces failed");
		close(sock);
		return errno;
	}

	for (inf = ifa; inf; inf = inf->ifa_next) {
		if (inf->ifa_flags & IFF_LOOPBACK)
			continue;

		strcpy(&ifr.ifr_name[0], inf->ifa_name);

		_errno = ioctl(sock, SIOCGIFHWADDR, &ifr);
		my_err(_errno, errno, "Retrieving mac failed for: %s\n",
		       inf->ifa_name);

		if (!memcmp(&ifr.ifr_hwaddr.sa_data, mac_addr, ETHER_ADDR_LEN)) {
			strcpy(name, inf->ifa_name);
			_errno = 0;
			break;
		}
	}
err:
	freeifaddrs(ifa);
	close(sock);
	return _errno;
}

static int fman_if_init(const struct device_node *dpa_node, int is_macless)
{
	const char *rprop, *mprop;
	uint64_t phys_addr;
	struct __fman_if *__if;
	struct fman_if_bpool *bpool;

	const phandle *mac_phandle, *ports_phandle, *pools_phandle;
	const phandle *tx_channel_id, *mac_addr, *cell_idx;
	const phandle *rx_phandle, *tx_phandle;
	uint64_t tx_phandle_host[4] = {0};
	uint64_t rx_phandle_host[4] = {0};
	uint64_t regs_addr_host = 0;
	uint64_t cell_idx_host = 0;

	const struct device_node *mac_node = NULL, *tx_node, *pool_node,
			*fman_node, *rx_node;
	const uint32_t *regs_addr = NULL;
	const char *mname, *fname;
	const char *dname = dpa_node->full_name;
	int is_offline = 0, is_shared = 0;
	size_t lenp;
	int _errno;
	const char *char_prop;
	uint32_t na;

	if (of_device_is_available(dpa_node) == false)
		return 0;
	if (of_device_is_compatible(dpa_node, "fsl,dpa-oh"))
		is_offline = 1;
	else if (of_device_is_compatible(dpa_node, "fsl,dpa-ethernet-shared"))
		is_shared = 1;

	rprop = is_offline ? "fsl,qman-frame-queues-oh" :
					 "fsl,qman-frame-queues-rx";
	mprop = is_offline ? "fsl,fman-oh-port" :
					 "fsl,fman-mac";
	/* Allocate an object for this network interface */
	__if = malloc(sizeof(*__if));
	my_err(!__if, -ENOMEM, "malloc(%zu)\n", sizeof(*__if));
	memset(__if, 0, sizeof(*__if));
	INIT_LIST_HEAD(&__if->__if.bpool_list);
	strncpy(__if->node_path, dpa_node->full_name, PATH_MAX - 1);
	__if->node_path[PATH_MAX - 1] = '\0';

	/* Obtain the MAC node used by this interface except macless */
	if (!is_macless) {
		mac_phandle = of_get_property(dpa_node, mprop, &lenp);
		my_err(!mac_phandle, -EINVAL, "%s: no %s\n", dname, mprop);
		assert(lenp == sizeof(phandle));
		mac_node = of_find_node_by_phandle(*mac_phandle);
		my_err(!mac_node, -ENXIO, "%s: bad 'fsl,fman-mac\n", dname);
		mname = mac_node->full_name;
	} else
		mname = "mac-less-node";

	/* Map the CCSR regs for the MAC node */
	if (!(is_macless | is_offline)) {
		regs_addr = of_get_address(mac_node, 0, &__if->regs_size, NULL);
		my_err(!regs_addr, -EINVAL, "of_get_address(%s)\n", mname);
		phys_addr = of_translate_address(mac_node, regs_addr);
		my_err(!phys_addr, -EINVAL, "of_translate_address(%s, %p)\n",
		       mname, regs_addr);
		__if->ccsr_map = mmap(NULL, __if->regs_size,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				ccsr_map_fd, phys_addr);
		my_err(__if->ccsr_map == MAP_FAILED, -errno,
		       "mmap(0x%"PRIx64")\n", phys_addr);
		na = of_n_addr_cells(mac_node);
		/* Get rid of endianness (issues). Convert to host byte order */
		regs_addr_host = of_read_number(regs_addr, na);
	}

	/* Get the index of the Fman this i/f belongs to */
	if (!is_macless) {
		fman_node = of_get_parent(mac_node);
		na = of_n_addr_cells(mac_node);
		my_err(!fman_node, -ENXIO, "of_get_parent(%s)\n", mname);
		fname = fman_node->full_name;
		cell_idx = of_get_property(fman_node, "cell-index", &lenp);
		my_err(!cell_idx, -ENXIO, "%s: no cell-index)\n", fname);
		assert(lenp == sizeof(*cell_idx));
		cell_idx_host = of_read_number(cell_idx, lenp / sizeof(phandle));
		__if->__if.fman_idx = cell_idx_host;
		if (!get_once) {
			_errno = fman_get_ip_rev(fman_node);
			my_err(_errno, -ENXIO, "%s: ip_rev is not available\n",
			       fname);
		}
	} else
		fname = "mac-less-node";

	if (fman_ip_rev >= FMAN_V3) {
		/*
		 * Set A2V, OVOM, EBD bits in contextA to allow external
		 * buffer deallocation by fman.
		 */
		fman_dealloc_bufs_mask_hi = FMAN_V3_CONTEXTA_EN_A2V |
						FMAN_V3_CONTEXTA_EN_OVOM;
		fman_dealloc_bufs_mask_lo = FMAN_V3_CONTEXTA_EN_EBD;
	} else {
		fman_dealloc_bufs_mask_hi = 0;
		fman_dealloc_bufs_mask_lo = 0;
	}
	/* Is the MAC node 1G, 10G, offline or MAC-less? */
	__if->__if.is_memac = 0;

	if (is_offline)
		__if->__if.mac_type = fman_offline;
	else if (is_macless)
		__if->__if.mac_type = fman_mac_less;
	else if (of_device_is_compatible(mac_node, "fsl,fman-1g-mac"))
		__if->__if.mac_type = fman_mac_1g;
	else if (of_device_is_compatible(mac_node, "fsl,fman-10g-mac"))
		__if->__if.mac_type = fman_mac_10g;
	else if (of_device_is_compatible(mac_node, "fsl,fman-memac")) {
		__if->__if.is_memac = 1;
		char_prop = of_get_property(mac_node, "phy-connection-type",
					    NULL);
		if (!char_prop) {
			printf("memac: unknown MII type assuming 1G\n");
			/* Right now forcing memac to 1g in case of error*/
			__if->__if.mac_type = fman_mac_1g;
		} else {
			if (strstr(char_prop, "sgmii"))
				__if->__if.mac_type = fman_mac_1g;
			else if (strstr(char_prop, "rgmii")) {
				__if->__if.mac_type = fman_mac_1g;
				__if->__if.is_rgmii = 1;
			} else if (strstr(char_prop, "xgmii"))
				__if->__if.mac_type = fman_mac_10g;
		}
	} else
		my_err(1, -EINVAL, "%s: unknown MAC type\n", mname);

	if (is_shared)
		__if->__if.shared_mac_info.is_shared_mac = 1;

	/* Extract the index of the MAC */
	if (!is_macless) {
		if (is_offline) {
			cell_idx = of_get_property(mac_node, "cell-index", &lenp);
			my_err(!cell_idx, -ENXIO, "%s: no cell-index\n", mname);
			assert(lenp == sizeof(*cell_idx));
			cell_idx_host = of_read_number(cell_idx, lenp / sizeof(phandle));
			__if->__if.mac_idx = cell_idx_host;
		} else {
			/*
			 * For MAC ports, we cannot rely on cell-index. In
			 * T2080, two of the 10G ports on single FMAN have same
			 * duplicate cell-indexes as the other two 10G ports on
			 * same FMAN. Hence, we now rely upon addresses of the
			 * ports from device tree to deduce the index.
			 */

			/*
			 * MAC1 : E_0000h
			 * MAC2 : E_2000h
			 * MAC3 : E_4000h
			 * MAC4 : E_6000h
			 * MAC5 : E_8000h
			 * MAC6 : E_A000h
			 * MAC7 : E_C000h
			 * MAC8 : E_E000h
			 * MAC9 : F_0000h
			 * MAC10: F_2000h
			 */

			switch (regs_addr_host) {
				case 0xE0000:
					__if->__if.mac_idx = 1;
					break;
				case 0xE2000:
					__if->__if.mac_idx = 2;
					break;
				case 0xE4000:
					__if->__if.mac_idx = 3;
					break;
				case 0xE6000:
					__if->__if.mac_idx = 4;
					break;
				case 0xE8000:
					__if->__if.mac_idx = 5;
					break;
				case 0xEA000:
					__if->__if.mac_idx = 6;
					break;
				case 0xEC000:
					__if->__if.mac_idx = 7;
					break;
				case 0xEE000:
					__if->__if.mac_idx = 8;
					break;
				case 0xF0000:
					__if->__if.mac_idx = 9;
					break;
				case 0xF2000:
					__if->__if.mac_idx = 10;
					break;
				default:
					my_err(1, -EINVAL, "Invalid regs_addr: %#x\n",
					       regs_addr_host);
			}
		}
	}

	if (is_macless) {
		/* Extract the MAC address for MAC-less */
		mac_addr = of_get_property(dpa_node, "local-mac-address",
					   &lenp);
		my_err(!mac_addr, -EINVAL, "%s: no local-mac-address\n",
		       mname);
		memcpy(&__if->__if.macless_info.peer_mac, mac_addr, ETHER_ADDR_LEN);

		_errno = find_mac_name(&__if->__if.macless_info.peer_mac,
				       &__if->__if.macless_info.macless_name[0]);

		my_err(_errno, -EINVAL, "Get device name failed for: %s\n",
		       mname);

	} else if (is_offline) {
		/* Extract the channel ID (from mac) */
		tx_channel_id = of_get_property(mac_node, "fsl,qman-channel-id",
						&lenp);
		my_err(!tx_channel_id, -EINVAL, "%s: no fsl-qman-channel-id\n",
		       mac_node->full_name);
		regs_addr = of_get_address(mac_node, 0, &__if->regs_size, NULL);
		my_err(!regs_addr, -EINVAL, "of_get_address(%s)\n", mname);
		phys_addr = of_translate_address(mac_node, regs_addr);
		my_err(!phys_addr, -EINVAL, "of_translate_address(%s, %p)\n",
		       mname, regs_addr);
		__if->bmi_map = mmap(NULL, __if->regs_size,
				       PROT_READ | PROT_WRITE, MAP_SHARED,
				       ccsr_map_fd, phys_addr);
		my_err(__if->bmi_map == MAP_FAILED, -errno,
		       "mmap(0x%"PRIx64")\n", phys_addr);

		__if->qmi_map = QMI_PORT_REGS_OFFSET + __if->bmi_map;
	} else {
		/* Extract the MAC address for private and shared interfaces */
		mac_addr = of_get_property(mac_node, "local-mac-address",
					   &lenp);
		my_err(!mac_addr, -EINVAL, "%s: no local-mac-address\n",
		       mname);
		memcpy(&__if->__if.mac_addr, mac_addr, ETHER_ADDR_LEN);

		/* Extract the Tx port (it's the second of the two port handles)
		 * and get its channel ID */
		ports_phandle = of_get_property(mac_node, "fsl,port-handles",
						&lenp);
		my_err(!ports_phandle, -EINVAL, "%s: no fsl,port-handles\n",
		       mname);
		assert(lenp == (2 * sizeof(phandle)));
		tx_node = of_find_node_by_phandle(ports_phandle[1]);
		my_err(!tx_node, -ENXIO, "%s: bad fsl,port-handle[1]\n", mname);
		/* Extract the channel ID (from tx-port-handle) */
		tx_channel_id = of_get_property(tx_node, "fsl,qman-channel-id",
						&lenp);
		my_err(!tx_channel_id, -EINVAL, "%s: no fsl-qman-channel-id\n",
		       tx_node->full_name);

		rx_node = of_find_node_by_phandle(ports_phandle[0]);
		my_err(!rx_node, -ENXIO, "%s: bad fsl,port-handle[0]\n", mname);
		regs_addr = of_get_address(rx_node, 0, &__if->regs_size, NULL);
		my_err(!regs_addr, -EINVAL, "of_get_address(%s)\n", mname);
		phys_addr = of_translate_address(rx_node, regs_addr);
		my_err(!phys_addr, -EINVAL, "of_translate_address(%s, %p)\n",
		       mname, regs_addr);
		__if->bmi_map = mmap(NULL, __if->regs_size,
					 PROT_READ | PROT_WRITE, MAP_SHARED,
					 ccsr_map_fd, phys_addr);
		my_err(__if->bmi_map == MAP_FAILED, -errno,
		       "mmap(0x%"PRIx64")\n", phys_addr);
	}

	/* For shared mac case, also fill the shared_mac_name */
	if (is_shared) {
		struct fman_if *fif = &__if->__if;

		_errno = find_mac_name(&fif->mac_addr,
				       &fif->shared_mac_info.shared_mac_name[0]);
		my_err(_errno, -EINVAL, "Get device name failed for: %s\n",
		       mname);
	}

	/* No channel ID for MAC-less */
	if (!is_macless) {
		assert(lenp == sizeof(*tx_channel_id));
		na = of_n_addr_cells(mac_node);
		__if->__if.tx_channel_id = of_read_number(tx_channel_id, na);
	}

	/* Extract the Rx FQIDs. (Note, the device representation is silly,
	 * there are "counts" that must always be 1.) */
	rx_phandle = of_get_property(dpa_node, rprop, &lenp);
	my_err(!rx_phandle, -EINVAL, "%s: no fsl,qman-frame-queues-rx\n",
	       dname);
	if (is_macless) {
		/* For MAC-less, there are only 8 default RX Frame queues */
		assert(lenp == (2 * sizeof(phandle)));
		na = of_n_addr_cells(mac_node);
		rx_phandle_host[0] = of_read_number(&rx_phandle[0], na);
		rx_phandle_host[1] = of_read_number(&rx_phandle[1], na);
		__if->__if.macless_info.rx_start = rx_phandle_host[0];
		__if->__if.macless_info.rx_count = rx_phandle_host[1];
	} else if (is_shared) {
		assert(lenp == (6 * sizeof(phandle)));
		na = of_n_addr_cells(mac_node);
		/* Get rid of endianness (issues). Convert to host byte order */
		rx_phandle_host[0] = of_read_number(&rx_phandle[0], na);
		rx_phandle_host[1] = of_read_number(&rx_phandle[1], na);
		rx_phandle_host[2] = of_read_number(&rx_phandle[2], na);
		rx_phandle_host[3] = of_read_number(&rx_phandle[3], na);
		assert((rx_phandle_host[1] == 1) && (rx_phandle_host[3] == 1));
		__if->__if.fqid_rx_err = rx_phandle_host[0];
		__if->__if.fqid_rx_def = rx_phandle_host[2];
	} else {
	/*TODO: Fix for other cases also */
		assert(lenp == (4 * sizeof(phandle)));

		na = of_n_addr_cells(mac_node);
		/* Get rid of endianness (issues). Convert to host byte order */
		rx_phandle_host[0] = of_read_number(&rx_phandle[0], na);
		rx_phandle_host[1] = of_read_number(&rx_phandle[1], na);
		rx_phandle_host[2] = of_read_number(&rx_phandle[2], na);
		rx_phandle_host[3] = of_read_number(&rx_phandle[3], na);

		assert((rx_phandle_host[1] == 1) && (rx_phandle_host[3] == 1));
		__if->__if.fqid_rx_err = rx_phandle_host[0];
		__if->__if.fqid_rx_def = rx_phandle_host[2];
	}

	/* No special Tx FQs for offline interfaces, nor hard-coded pools */
	if (is_offline)
		goto ok;

	/* Extract the Tx FQIDs */
	tx_phandle = of_get_property(dpa_node,
				     "fsl,qman-frame-queues-tx", &lenp);
	my_err(!tx_phandle, -EINVAL, "%s: no fsl,qman-frame-queues-tx\n",
	       dname);
	if (is_macless) {
		/* For MAC-less, there are only 8 default TX Frame queues */
		assert(lenp == (2 * sizeof(phandle)));
		na = of_n_addr_cells(mac_node);
		tx_phandle_host[0] = of_read_number(&tx_phandle[0], na);
		tx_phandle_host[1] = of_read_number(&tx_phandle[1], na);
		assert((tx_phandle_host[1] == 8));
		__if->__if.macless_info.tx_start = tx_phandle_host[0];
		__if->__if.macless_info.tx_count = tx_phandle_host[1];
	} else if (is_shared) {
		assert(lenp == (6 * sizeof(phandle)));
		na = of_n_addr_cells(mac_node);
		tx_phandle_host[0] = of_read_number(&tx_phandle[0], na);
		tx_phandle_host[1] = of_read_number(&tx_phandle[1], na);
		tx_phandle_host[2] = of_read_number(&tx_phandle[2], na);
		tx_phandle_host[3] = of_read_number(&tx_phandle[3], na);
		assert((tx_phandle_host[1] == 1) && (tx_phandle_host[3] == 1));
		__if->__if.fqid_tx_err = tx_phandle_host[0];
		__if->__if.fqid_tx_confirm = tx_phandle_host[2];

	} else {
		assert(lenp == (4 * sizeof(phandle)));
		/*TODO: Fix for other cases also */
		na = of_n_addr_cells(mac_node);
		/* Get rid of endianness (issues). Convert to host byte order */
		tx_phandle_host[0] = of_read_number(&tx_phandle[0], na);
		tx_phandle_host[1] = of_read_number(&tx_phandle[1], na);
		tx_phandle_host[2] = of_read_number(&tx_phandle[2], na);
		tx_phandle_host[3] = of_read_number(&tx_phandle[3], na);
		assert((tx_phandle_host[1] == 1) && (tx_phandle_host[3] == 1));
		__if->__if.fqid_tx_err = tx_phandle_host[0];
		__if->__if.fqid_tx_confirm = tx_phandle_host[2];
	}

	/* Obtain the buffer pool nodes used by this interface */
	pools_phandle = of_get_property(dpa_node, "fsl,bman-buffer-pools",
					&lenp);
	my_err(!pools_phandle, -EINVAL, "%s: no fsl,bman-buffer-pools\n",
	       dname);
	/* For each pool, parse the corresponding node and add a pool object to
	 * the interface's "bpool_list" */
	assert(lenp && !(lenp % sizeof(phandle)));
	while (lenp) {
		size_t proplen;
		const phandle *prop;
		uint64_t bpid_host = 0;
		uint64_t bpool_host[6] = {0};
		const char *pname;
		/* Allocate an object for the pool */
		bpool = malloc(sizeof(*bpool));
		my_err(!bpool, -ENOMEM, "malloc(%zu)\n", sizeof(*bpool));
		/* Find the pool node */
		pool_node = of_find_node_by_phandle(*pools_phandle);
		my_err(!pool_node, -ENXIO, "%s: bad fsl,bman-buffer-pools\n",
		       dname);
		pname = pool_node->full_name;
		/* Extract the BPID property */
		prop = of_get_property(pool_node, "fsl,bpid", &proplen);
		my_err(!prop, -EINVAL, "%s: no fsl,bpid\n", pname);
		assert(proplen == sizeof(*prop));
		na = of_n_addr_cells(mac_node);
		/* Get rid of endianness (issues). Convert to host byte order */
		bpid_host = of_read_number(prop, na);
		bpool->bpid = bpid_host;
		/* Extract the cfg property (count/size/addr). "fsl,bpool-cfg"
		 * indicates for the Bman driver to seed the pool.
		 * "fsl,bpool-ethernet-cfg" is used by the network driver. The
		 * two are mutually exclusive, so check for either of them. */
		prop = of_get_property(pool_node, "fsl,bpool-cfg",
				       &proplen);
		if (!prop)
			prop = of_get_property(pool_node,
					       "fsl,bpool-ethernet-cfg",
					       &proplen);
		if (!prop) {
			/* It's OK for there to be no bpool-cfg */
			bpool->count = bpool->size = bpool->addr = 0;
		} else {
			assert(proplen == (6 * sizeof(*prop)));
			na = of_n_addr_cells(mac_node);
			/* Get rid of endianness (issues). Convert to host byte order */
			bpool_host[0] = of_read_number(&prop[0], na);
			bpool_host[1] = of_read_number(&prop[1], na);
			bpool_host[2] = of_read_number(&prop[2], na);
			bpool_host[3] = of_read_number(&prop[3], na);
			bpool_host[4] = of_read_number(&prop[4], na);
			bpool_host[5] = of_read_number(&prop[5], na);

			bpool->count = ((uint64_t)bpool_host[0] << 32) |
					bpool_host[1];
			bpool->size = ((uint64_t)bpool_host[2] << 32) |
					bpool_host[3];
			bpool->addr = ((uint64_t)bpool_host[4] << 32) |
					bpool_host[5];
		}
		/* Parsing of the pool is complete, add it to the interface
		 * list. */
		list_add_tail(&bpool->node, &__if->__if.bpool_list);
		lenp -= sizeof(phandle);
		pools_phandle++;
	}

ok:
	/* Parsing of the network interface is complete, add it to the list. */
	if (is_macless)
		printf("Found %s, MAC-LESS node\n", dname);
	else {
		printf("Found %s, Tx Channel = %x, FMAN = %x, Port ID = %x\n",
		       dname, __if->__if.tx_channel_id, __if->__if.fman_idx,
			__if->__if.mac_idx);
	}
	list_add_tail(&__if->__if.node, &__ifs);
	return 0;
err:
	if_destructor(__if);
	return _errno;
}

static int fman_if_init_onic(const struct device_node *dpa_node)
{
	const char *rprop;
	struct __fman_if *__if;
	struct fman_if_bpool *bpool;
	const phandle *pools_phandle;
	const phandle *tx_channel_id, *mac_addr;
	const phandle *rx_phandle, *tx_phandle;
	const struct device_node *pool_node;
	const char *mname;
	const char *dname = dpa_node->full_name;
	size_t lenp;
	int _errno;
	int i;
	const phandle *p_oh_node = NULL;
	const struct device_node *oh_node = NULL;
	const struct device_node *oh_node2 = NULL;
	const phandle *p_fman_oh_node = NULL;
	const struct device_node *fman_oh_node = NULL;

	if (of_device_is_available(dpa_node) == false)
		return 0;

	/* Allocate an object for this network interface */
	__if = malloc(sizeof(*__if));
	my_err(!__if, -ENOMEM, "malloc(%zu)\n", sizeof(*__if));
	memset(__if, 0, sizeof(*__if));
	INIT_LIST_HEAD(&__if->__if.bpool_list);
	strncpy(__if->node_path, dpa_node->full_name, PATH_MAX - 1);
	__if->node_path[PATH_MAX - 1] = '\0';

	if (fman_ip_rev >= FMAN_V3) {
		/*
		 * Set A2V, OVOM, EBD bits in contextA to allow external
		 * buffer deallocation by fman.
		 */
		fman_dealloc_bufs_mask_hi = FMAN_V3_CONTEXTA_EN_A2V |
			FMAN_V3_CONTEXTA_EN_OVOM;
		fman_dealloc_bufs_mask_lo = FMAN_V3_CONTEXTA_EN_EBD;
	} else {
		fman_dealloc_bufs_mask_hi = 0;
		fman_dealloc_bufs_mask_lo = 0;
	}
	/* Is the MAC node 1G, 10G, offline or MAC-less? */
	__if->__if.is_memac = 0;
	__if->__if.mac_type = fman_onic;

	/* Extract the MAC address for linux peer */
	mname = "oNIC-node";

	mac_addr = of_get_property(dpa_node, "local-mac-address",
				   &lenp);
	my_err(!mac_addr, -EINVAL, "%s: no local-mac-address\n",
	       mname);
	memcpy(&__if->__if.onic_info.peer_mac, mac_addr, ETHER_ADDR_LEN);

	_errno = find_mac_name(&__if->__if.onic_info.peer_mac,
			       &__if->__if.onic_info.macless_name[0]);

	my_err(_errno, -EINVAL, "Get device name failed for: %s\n",
	       mname);

	/* Extract the Tx port (it's the first of the two port handles)
	 * and get its channel ID */
	p_oh_node = of_get_property(dpa_node, "fsl,oh-ports", &lenp);
	my_err(!p_oh_node, -EINVAL, "%s: couldn't get p_oh-ports\n",
	       dpa_node->full_name);

	oh_node = of_find_node_by_phandle(p_oh_node[0]);
	my_err(!oh_node, -EINVAL, "%s: couldn't get oh_node\n",
	       dpa_node->full_name);

	p_fman_oh_node = of_get_property(oh_node, "fsl,fman-oh-port", &lenp);
	my_err(!p_fman_oh_node, -EINVAL, "%s: couldn't get p_fman_oh_node\n",
	       dpa_node->full_name);

	fman_oh_node = of_find_node_by_phandle(*p_fman_oh_node);
	my_err(!fman_oh_node, -EINVAL, "%s: couldn't get fman_oh_node\n",
	       dpa_node->full_name);

	assert(lenp == (1 * sizeof(phandle)));
	tx_channel_id = of_get_property(fman_oh_node, "fsl,qman-channel-id", &lenp);
	my_err(!tx_channel_id, -EINVAL, "%s: no fsl-qman-channel-id\n",
	       dpa_node->full_name);

	assert(lenp == sizeof(*tx_channel_id));
	__if->__if.tx_channel_id = *tx_channel_id;

	rprop = "fsl,qman-frame-queues-oh";

	/* Extract the FQs from which oNIC driver in Linux is dequeing */
	rx_phandle = of_get_property(oh_node, rprop, &lenp);
	my_err(!rx_phandle, -EINVAL, "%s: no fsl,qman-frame-queues-oh\n",
	       dname);
	assert(lenp == (4 * sizeof(phandle)));
	__if->__if.onic_info.onic_rx_start = rx_phandle[2];
	__if->__if.onic_info.onic_rx_count = rx_phandle[3];

	/* Extract the Rx FQIDs */
	oh_node2 = of_find_node_by_phandle(p_oh_node[1]);
	my_err(!oh_node2, -EINVAL, "%s: couldn't get oh_node2\n",
	       dpa_node->full_name);
	rx_phandle = of_get_property(oh_node2, rprop, &lenp);
	my_err(!rx_phandle, -EINVAL, "%s: no fsl,qman-frame-queues-oh\n",
	       dname);
	assert(lenp == (4 * sizeof(phandle)));
	assert((rx_phandle[1] == 1) && (rx_phandle[3] == 1));
	__if->__if.fqid_rx_err = rx_phandle[0];
	__if->__if.fqid_rx_def = rx_phandle[2];

	/* Don't Extract the Tx FQIDs */
	__if->__if.fqid_tx_err = 0;
	__if->__if.fqid_tx_confirm = 0;

	/* Obtain the buffer pool nodes used by this interface */
	oh_node = of_find_node_by_phandle(p_oh_node[1]);
	my_err(!oh_node, -EINVAL, "%s: couldn't get oh_node\n",
	       dpa_node->full_name);
	pools_phandle = of_get_property(oh_node, "fsl,bman-buffer-pools",
					&lenp);
	my_err(!pools_phandle, -EINVAL, "%s: no fsl,bman-buffer-pools\n",
	       dname);
	/* For each pool, parse the corresponding node and add a pool object to
	 * the interface's "bpool_list" */
	assert(lenp && !(lenp % sizeof(phandle)));
	while (lenp) {
		size_t proplen;
		const phandle *prop;
		const char *pname;
		/* Allocate an object for the pool */
		bpool = malloc(sizeof(*bpool));
		my_err(!bpool, -ENOMEM, "malloc(%zu)\n", sizeof(*bpool));
		/* Find the pool node */
		pool_node = of_find_node_by_phandle(*pools_phandle);
		my_err(!pool_node, -ENXIO, "%s: bad fsl,bman-buffer-pools\n",
		       dname);
		pname = pool_node->full_name;
		/* Extract the BPID property */
		prop = of_get_property(pool_node, "fsl,bpid", &proplen);
		my_err(!prop, -EINVAL, "%s: no fsl,bpid\n", pname);
		assert(proplen == sizeof(*prop));
		bpool->bpid = *prop;
		/* Extract the cfg property (count/size/addr). "fsl,bpool-cfg"
		 * indicates for the Bman driver to seed the pool.
		 * "fsl,bpool-ethernet-cfg" is used by the network driver. The
		 * two are mutually exclusive, so check for either of them. */
		prop = of_get_property(pool_node, "fsl,bpool-cfg",
				       &proplen);
		if (!prop)
			prop = of_get_property(pool_node,
					       "fsl,bpool-ethernet-cfg",
					&proplen);
		if (!prop) {
			/* It's OK for there to be no bpool-cfg */
			bpool->count = bpool->size = bpool->addr = 0;
		} else {
			assert(proplen == (6 * sizeof(*prop)));
			bpool->count = ((uint64_t)prop[0] << 32) |
				prop[1];
			bpool->size = ((uint64_t)prop[2] << 32) |
				prop[3];
			bpool->addr = ((uint64_t)prop[4] << 32) |
				prop[5];
		}
		/* Parsing of the pool is complete, add it to the interface
		 * list. */
		list_add_tail(&bpool->node, &__if->__if.bpool_list);
		lenp -= sizeof(phandle);
		pools_phandle++;
	}

	/* Parsing of the network interface is complete, add it to the list. */
	printf("Found %s, Tx Channel = %x, FMAN = %x, Port ID = %x\n",
	       dname, __if->__if.tx_channel_id, __if->__if.fman_idx,
			__if->__if.mac_idx);
	list_add_tail(&__if->__if.node, &__ifs);
	return 0;
err:
	if_destructor(__if);
	return _errno;
}

int fman_init(void)
{
	const struct device_node *dpa_node;
	int _errno;
	size_t lenp;
	const char *mprop = "fsl,fman-mac";

	/* If multiple dependencies try to initialise the Fman driver, don't
	 * panic. */
	if (ccsr_map_fd != -1)
		return 0;

	ccsr_map_fd = open("/dev/mem", O_RDWR);
	if (unlikely(ccsr_map_fd < 0)) {
		my_log(-errno, "open(/dev/mem)\n");
		return ccsr_map_fd;
	}

	/* Parse offline ports first, so they initialise first. That way,
	 * initialisation of regular ports can "choose" an offline port to
	 * association with. */
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-oh") {
		_errno = fman_if_init(dpa_node, 0);
		my_err(_errno, _errno, "if_init(%s)\n", dpa_node->full_name);
	}
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-init") {
		_errno = fman_if_init(dpa_node, 0);
		my_err(_errno, _errno, "if_init(%s)\n", dpa_node->full_name);
	}
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-shared") {
		/* it is a shared MAC interface */
		_errno = fman_if_init(dpa_node, 0);
		my_err(_errno, _errno, "if_init(%s)\n",
		       dpa_node->full_name);
	}
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-macless") {
		/* it is a MAC-less interface */
		_errno = fman_if_init(dpa_node, 1);
		my_err(_errno, _errno, "if_init(%s)\n",
		       dpa_node->full_name);
	}
	for_each_compatible_node(dpa_node, NULL, "fsl,dpa-ethernet-generic") {
		/* it is a oNIC interface */
		_errno = fman_if_init_onic(dpa_node);
		my_err(_errno, _errno, "if_init(%s)\n",
		       dpa_node->full_name);
	}
	return 0;
err:
	fman_finish();
	return _errno;
}

void fman_finish(void)
{
	struct __fman_if *__if, *tmpif;

	assert(ccsr_map_fd != -1);

	list_for_each_entry_safe(__if, tmpif, &__ifs, __if.node) {
		int _errno;

		/* No need to disable Offline port or MAC less */
		if ((__if->__if.mac_type == fman_offline) ||
		    (__if->__if.mac_type == fman_mac_less) ||
			(__if->__if.mac_type == fman_onic))
			continue;

		/* disable Rx and Tx */
		if ((__if->__if.mac_type == fman_mac_1g) &&
		    (!__if->__if.is_memac))
			out_be32(__if->ccsr_map + 0x100,
				 in_be32(__if->ccsr_map + 0x100) & ~(u32)0x5);
		else
			out_be32(__if->ccsr_map + 8,
				 in_be32(__if->ccsr_map + 8) & ~(u32)3);
		/* release the mapping */
		_errno = munmap(__if->ccsr_map, __if->regs_size);
		if (unlikely(_errno < 0))
			fprintf(stderr, "%s:%hu:%s(): munmap() = %d (%s)\n",
				__FILE__, __LINE__, __func__,
				-errno, strerror(errno));
		printf("Tearing down %s\n", __if->node_path);
		list_del(&__if->__if.node);
		free(__if);
	}

	close(ccsr_map_fd);
	ccsr_map_fd = -1;
}

int fm_mac_add_exact_match_mac_addr(struct fman_if *p, uint8_t *eth)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline or Macless ports */
	if ((__if->__if.mac_type == fman_offline) ||
	    (__if->__if.mac_type == fman_mac_less)) {
		my_log(EINVAL, "port type (%d)\n", __if->__if.mac_type);
		return EINVAL;
	}

	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac))
		return _dtsec_set_stn_mac_addr(__if, eth);
	else
		return memac_set_station_mac_addr(p, eth);
}

int fm_mac_config(struct fman_if *p,  uint8_t *eth)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline or Macless ports */
	if ((__if->__if.mac_type == fman_offline) ||
	    (__if->__if.mac_type == fman_mac_less)) {
		my_log(EINVAL, "port type (%d)\n", __if->__if.mac_type);
		return EINVAL;
	}

	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac))
		return _dtsec_get_stn_mac_addr(__if, eth);
	else
		return memac_get_station_mac_addr(p, eth);
}

void fm_mac_set_rx_ignore_pause_frames(struct fman_if *p, bool enable)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);
	u32 value = 0;

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline or Macless ports */
	if ((__if->__if.mac_type == fman_offline) ||
	    (__if->__if.mac_type == fman_mac_less)) {
		my_log(EINVAL, "port type (%d)\n", __if->__if.mac_type);
		return;
	}

	/* Set Rx Ignore Pause Frames */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac)) {
		void *rx_control =
				&((struct dtsec_regs *)__if->ccsr_map)->maccfg1;
		if (enable)
			value = in_be32(rx_control) | MACCFG1_RX_FLOW;
		else
			value = in_be32(rx_control) & ~MACCFG1_RX_FLOW;

		out_be32(rx_control, value);
	} else {
		void *cmdcfg =
			 &((struct memac_regs *)__if->ccsr_map)->command_config;
		if (enable)
			value = in_be32(cmdcfg) | CMD_CFG_PAUSE_IGNORE;
		else
			value = in_be32(cmdcfg) & ~CMD_CFG_PAUSE_IGNORE;

		out_be32(cmdcfg, value);
	}
}

void fm_mac_config_loopback(struct fman_if *p, bool enable)
{
	if (enable)
		/* Enable loopback mode */
		fman_if_loopback_enable(p);
	else
		/* Disable loopback mode */
		fman_if_loopback_disable(p);
}

void fm_mac_conf_max_frame_len(struct fman_if *p,
			       unsigned int max_frame_len)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline port */
	if (__if->__if.mac_type == fman_offline ||
	    __if->__if.mac_type == fman_onic)
		return;

	/* Set Max frame length */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac)) {
		unsigned *maxfrm =
				&((struct dtsec_regs *)__if->ccsr_map)->maxfrm;
		out_be32(maxfrm, (MAXFRM_MASK & max_frame_len));
	} else {
		unsigned *maxfrm =
			 &((struct memac_regs *)__if->ccsr_map)->maxfrm;
		out_be32(maxfrm, (MAXFRM_RX_MASK & max_frame_len));
	}
}

void fm_mac_set_promiscuous(struct fman_if *p)
{
	fman_if_promiscuous_enable(p);
}

void fman_if_promiscuous_enable(struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline or Macless ports */
	if ((__if->__if.mac_type == fman_offline) ||
	    (__if->__if.mac_type == fman_mac_less)) {
		my_log(EINVAL, "port type (%d)\n", __if->__if.mac_type);
		return;
	}

	/* Enable Rx promiscuous mode */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac)) {
		void *rx_control =
				&((struct dtsec_regs *)__if->ccsr_map)->rctrl;
		out_be32(rx_control, in_be32(rx_control) | RCTRL_PROM);
	} else {
		void *cmdcfg =
			 &((struct memac_regs *)__if->ccsr_map)->command_config;
		out_be32(cmdcfg, in_be32(cmdcfg) | CMD_CFG_PROMIS_EN);
	}
}

void fman_if_promiscuous_disable(struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline or Macless ports */
	if ((__if->__if.mac_type == fman_offline) ||
	    (__if->__if.mac_type == fman_mac_less)) {
		my_log(EINVAL, "port type (%d)\n", __if->__if.mac_type);
		return;
	}

	/* Disable Rx promiscuous mode */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac)) {
		void *rx_control =
				&((struct dtsec_regs *)__if->ccsr_map)->rctrl;
		out_be32(rx_control, in_be32(rx_control) & (~RCTRL_PROM));
	} else {
		void *cmdcfg =
			 &((struct memac_regs *)__if->ccsr_map)->command_config;
		out_be32(cmdcfg, in_be32(cmdcfg) & (~CMD_CFG_PROMIS_EN));
	}
}

void fman_if_enable_rx(struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* No need to enable Offline port */
	if ((__if->__if.mac_type == fman_offline) || (__if->__if.mac_type == fman_onic))
		return;

	/* enable Rx and Tx */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac))
		out_be32(__if->ccsr_map + 0x100,
			 in_be32(__if->ccsr_map + 0x100) | 0x5);
	else
		out_be32(__if->ccsr_map + 8,
			 in_be32(__if->ccsr_map + 8) | 3);
}

void fman_if_disable_rx(struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* No need to disable Offline port */
	if (__if->__if.mac_type == fman_offline ||
	    __if->__if.mac_type == fman_onic)
		return;

	/* only disable Rx, not Tx */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac))
		out_be32(__if->ccsr_map + 0x100,
			 in_be32(__if->ccsr_map + 0x100) & ~(u32)0x4);
	else
		out_be32(__if->ccsr_map + 8,
			 in_be32(__if->ccsr_map + 8) & ~(u32)2);
}

void fman_if_loopback_enable(struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline port */
	if (__if->__if.mac_type == fman_offline ||
	    __if->__if.mac_type == fman_onic)
		return;

	/* Enable loopback mode */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac)) {
		unsigned *maccfg =
				&((struct dtsec_regs *)__if->ccsr_map)->maccfg1;
		out_be32(maccfg, in_be32(maccfg) | MACCFG1_LOOPBACK);
	} else if ((__if->__if.is_memac) && (__if->__if.is_rgmii)) {
		unsigned *ifmode =
			 &((struct memac_regs *)__if->ccsr_map)->if_mode;
		out_be32(ifmode, in_be32(ifmode) | IF_MODE_RLP);
	} else{
		unsigned *cmdcfg =
			 &((struct memac_regs *)__if->ccsr_map)->command_config;
		out_be32(cmdcfg, in_be32(cmdcfg) | CMD_CFG_LOOPBACK_EN);
	}
}

void fman_if_loopback_disable(struct fman_if *p)
{
	struct __fman_if *__if = container_of(p, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	/* Do nothing for Offline port */
	if (__if->__if.mac_type == fman_offline ||
	    __if->__if.mac_type == fman_onic)
		return;

	/* Disable loopback mode */
	if ((__if->__if.mac_type == fman_mac_1g) && (!__if->__if.is_memac)) {
		unsigned *maccfg =
				&((struct dtsec_regs *)__if->ccsr_map)->maccfg1;
		out_be32(maccfg, in_be32(maccfg) & ~MACCFG1_LOOPBACK);
	} else if ((__if->__if.is_memac) && (__if->__if.is_rgmii)) {
		unsigned *ifmode =
			 &((struct memac_regs *)__if->ccsr_map)->if_mode;
		out_be32(ifmode, in_be32(ifmode) & ~IF_MODE_RLP);
	} else {
		unsigned *cmdcfg =
			 &((struct memac_regs *)__if->ccsr_map)->command_config;
		out_be32(cmdcfg, in_be32(cmdcfg) & ~CMD_CFG_LOOPBACK_EN);
	}
}

void fman_if_set_bp(struct fman_if *fm_if, unsigned num __always_unused,
		    int bpid, size_t bufsize)
{
	u32 fmbm_ebmpi;
	u32 ebmpi_val_ace = 0xc0000000;
	u32 ebmpi_mask = 0xffc00000;

	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_offline ||
	    __if->__if.mac_type == fman_mac_less)
		return;

	fmbm_ebmpi =
	       in_be32(&((struct rx_bmi_regs *)__if->bmi_map)->fmbm_ebmpi[0]);
	fmbm_ebmpi = ebmpi_val_ace | (fmbm_ebmpi & ebmpi_mask) | (bpid << 16) |
		     (bufsize);

	out_be32(&((struct rx_bmi_regs *)__if->bmi_map)->fmbm_ebmpi[0],
		 fmbm_ebmpi);
}

int fman_if_get_fdoff(struct fman_if *fm_if)
{
	u32 fmbm_ricp;
	int fdoff;
	int iceof_mask = 0x001f0000;
	int icsz_mask = 0x0000001f;

	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_offline ||
	    __if->__if.mac_type == fman_mac_less)
		return -1;

	fmbm_ricp =
		   in_be32(&((struct rx_bmi_regs *)__if->bmi_map)->fmbm_ricp);
	/*iceof + icsz*/
	fdoff = ((fmbm_ricp & iceof_mask) >> 16) * 16 +
		(fmbm_ricp & icsz_mask) * 16;

	return fdoff;
}

void fman_if_set_err_fqid(struct fman_if *fm_if, uint32_t err_fqid)
{
	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_mac_less ||
	    __if->__if.mac_type == fman_onic)
		return;

	if (__if->__if.mac_type == fman_offline) {
		unsigned *fmbm_oefqid =
			  &((struct oh_bmi_regs *)__if->bmi_map)->fmbm_oefqid;
		out_be32(fmbm_oefqid, err_fqid);
	} else {
		unsigned *fmbm_refqid =
			  &((struct rx_bmi_regs *)__if->bmi_map)->fmbm_refqid;
		out_be32(fmbm_refqid, err_fqid);
	}
}

int fman_if_get_ic_params(struct fman_if *fm_if, struct fman_if_ic_params *icp)
{
	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);
	int val = 0;
	int iceof_mask = 0x001f0000;
	int icsz_mask = 0x0000001f;
	int iciof_mask = 0x00000f00;

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_mac_less ||
	    __if->__if.mac_type == fman_onic)
		return -1;

	if (__if->__if.mac_type == fman_offline) {
		unsigned *fmbm_oicp =
			  &((struct oh_bmi_regs *)__if->bmi_map)->fmbm_oicp;
		val = in_be32(fmbm_oicp);
	} else {
		unsigned *fmbm_ricp =
			  &((struct rx_bmi_regs *)__if->bmi_map)->fmbm_ricp;
		val = in_be32(fmbm_ricp);
	}
	icp->iceof = (val & iceof_mask) >> 12;
	icp->iciof = (val & iciof_mask) >> 4;
	icp->icsz = (val & icsz_mask) << 4;

	return 0;
}

int fman_if_set_ic_params(struct fman_if *fm_if,
			  const struct fman_if_ic_params *icp)
{
	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);
	int val = 0;
	int iceof_mask = 0x001f0000;
	int icsz_mask = 0x0000001f;
	int iciof_mask = 0x00000f00;

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_mac_less ||
	    __if->__if.mac_type == fman_onic)
		return -1;

	val |= (icp->iceof << 12) & iceof_mask;
	val |= (icp->iciof << 4) & iciof_mask;
	val |= (icp->icsz >> 4) & icsz_mask;

	if (__if->__if.mac_type == fman_offline) {
		unsigned *fmbm_oicp =
			  &((struct oh_bmi_regs *)__if->bmi_map)->fmbm_oicp;
		out_be32(fmbm_oicp, in_be32(fmbm_oicp) | val);
	} else {
		unsigned *fmbm_ricp =
			  &((struct rx_bmi_regs *)__if->bmi_map)->fmbm_ricp;
		out_be32(fmbm_ricp, in_be32(fmbm_ricp) | val);
	}

	return 0;
}

void fman_if_set_fdoff(struct fman_if *fm_if, uint32_t fd_offset)
{
	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);
	unsigned *fmbm_rebm;

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_mac_less ||
	    __if->__if.mac_type == fman_onic ||
	    __if->__if.mac_type == fman_offline)
		return;

	fmbm_rebm = &((struct rx_bmi_regs *)__if->bmi_map)->fmbm_rebm;

	out_be32(fmbm_rebm, in_be32(fmbm_rebm) | (fd_offset << 16));
}

void fman_if_set_dnia(struct fman_if *fm_if, uint32_t nia)
{
	struct __fman_if *__if = container_of(fm_if, struct __fman_if, __if);
	unsigned *fmqm_pndn;

	assert(ccsr_map_fd != -1);

	if (__if->__if.mac_type == fman_mac_less ||
	    __if->__if.mac_type == fman_onic)
		return;

	fmqm_pndn = &((struct fman_port_qmi_regs *)__if->qmi_map)->fmqm_pndn;

	out_be32(fmqm_pndn, nia);
}
