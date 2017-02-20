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

#ifndef __FMAN_H
#define __FMAN_H

#include <net/if.h>
#include <rte_ether.h>
#include <usdpaa/compat.h>
#include <usdpaa/fsl_qman.h>
#include <stdbool.h>
#include <rte_ethdev.h>

#define MEMAC_NUM_OF_PADDRS 7 /* Num of additional exact match MAC adr regs */

/* Control and Configuration Register (COMMAND_CONFIG) for MEMAC */
#define CMD_CFG_LOOPBACK_EN	0x00000400 /* 21 XGMII/GMII loopback enable */
#define CMD_CFG_PROMIS_EN	0x00000010 /* 27 Promiscuous operation enable */
#define CMD_CFG_PAUSE_IGNORE	0x00000100 /* 23 Ignore Pause frame quanta */

/* Statistics Configuration Register (STATN_CONFIG) */
#define STATS_CFG_CLR           0x00000004 /* 29 Reset all counters */
#define STATS_CFG_CLR_ON_RD     0x00000002 /* 30 Clear on read */
#define STATS_CFG_SATURATE      0x00000001 /* 31 Saturate at the maximum val */

/* Max receive frame length mask */
#define MAXFRM_SIZE_MEMAC	0x00007fe0
#define MAXFRM_RX_MASK		0x0000ffff

/* Interface Mode Register Register for MEMAC */
#define IF_MODE_RLP 0x00000820

/* Represents the different flavour of network interface */
enum fman_mac_type {
	fman_offline = 0,
	fman_mac_1g,
	fman_mac_10g,
	fman_mac_less,
	fman_onic
};

struct mac_addr {
	uint32_t   mac_addr_l;	/* Lower 32 bits of 48-bit MAC address */
	uint32_t   mac_addr_u;	/* Upper 16 bits of 48-bit MAC address */
};

struct memac_regs {
	/* General Control and Status */
	uint32_t res0000[2];
	uint32_t command_config;	/* 0x008 Ctrl and cfg */
	struct mac_addr mac_addr0;	/* 0x00C-0x010 MAC_ADDR_0...1 */
	uint32_t maxfrm;		/* 0x014 Max frame length */
	uint32_t res0018[5];
	uint32_t hashtable_ctrl;	/* 0x02C Hash table control */
	uint32_t res0030[4];
	uint32_t ievent;		/* 0x040 Interrupt event */
	uint32_t tx_ipg_length;		/* 0x044 Transmitter inter-packet-gap */
	uint32_t res0048;
	uint32_t imask;			/* 0x04C Interrupt mask */
	uint32_t res0050;
	uint32_t pause_quanta[4];	/* 0x054 Pause quanta */
	uint32_t pause_thresh[4];	/* 0x064 Pause quanta threshold */
	uint32_t rx_pause_status;	/* 0x074 Receive pause status */
	uint32_t res0078[2];
	struct mac_addr mac_addr[MEMAC_NUM_OF_PADDRS]; /* 0x80-0x0B4 mac padr */
	uint32_t lpwake_timer;		/* 0x0B8 Low Power Wakeup Timer */
	uint32_t sleep_timer;		/* 0x0BC Transmit EEE Low Power Timer */
	uint32_t res00c0[8];
	uint32_t statn_config;		/* 0x0E0 Statistics configuration */
	uint32_t res00e4[7];
	/* Rx Statistics Counter */
	uint32_t reoct_l;
	uint32_t reoct_u;
	uint32_t roct_l;
	uint32_t roct_u;
	uint32_t raln_l;
	uint32_t raln_u;
	uint32_t rxpf_l;
	uint32_t rxpf_u;
	uint32_t rfrm_l;
	uint32_t rfrm_u;
	uint32_t rfcs_l;
	uint32_t rfcs_u;
	uint32_t rvlan_l;
	uint32_t rvlan_u;
	uint32_t rerr_l;
	uint32_t rerr_u;
	uint32_t ruca_l;
	uint32_t ruca_u;
	uint32_t rmca_l;
	uint32_t rmca_u;
	uint32_t rbca_l;
	uint32_t rbca_u;
	uint32_t rdrp_l;
	uint32_t rdrp_u;
	uint32_t rpkt_l;
	uint32_t rpkt_u;
	uint32_t rund_l;
	uint32_t rund_u;
	uint32_t r64_l;
	uint32_t r64_u;
	uint32_t r127_l;
	uint32_t r127_u;
	uint32_t r255_l;
	uint32_t r255_u;
	uint32_t r511_l;
	uint32_t r511_u;
	uint32_t r1023_l;
	uint32_t r1023_u;
	uint32_t r1518_l;
	uint32_t r1518_u;
	uint32_t r1519x_l;
	uint32_t r1519x_u;
	uint32_t rovr_l;
	uint32_t rovr_u;
	uint32_t rjbr_l;
	uint32_t rjbr_u;
	uint32_t rfrg_l;
	uint32_t rfrg_u;
	uint32_t rcnp_l;
	uint32_t rcnp_u;
	uint32_t rdrntp_l;
	uint32_t rdrntp_u;
	uint32_t res01d0[12];
	/* Tx Statistics Counter */
	uint32_t teoct_l;
	uint32_t teoct_u;
	uint32_t toct_l;
	uint32_t toct_u;
	uint32_t res0210[2];
	uint32_t txpf_l;
	uint32_t txpf_u;
	uint32_t tfrm_l;
	uint32_t tfrm_u;
	uint32_t tfcs_l;
	uint32_t tfcs_u;
	uint32_t tvlan_l;
	uint32_t tvlan_u;
	uint32_t terr_l;
	uint32_t terr_u;
	uint32_t tuca_l;
	uint32_t tuca_u;
	uint32_t tmca_l;
	uint32_t tmca_u;
	uint32_t tbca_l;
	uint32_t tbca_u;
	uint32_t res0258[2];
	uint32_t tpkt_l;
	uint32_t tpkt_u;
	uint32_t tund_l;
	uint32_t tund_u;
	uint32_t t64_l;
	uint32_t t64_u;
	uint32_t t127_l;
	uint32_t t127_u;
	uint32_t t255_l;
	uint32_t t255_u;
	uint32_t t511_l;
	uint32_t t511_u;
	uint32_t t1023_l;
	uint32_t t1023_u;
	uint32_t t1518_l;
	uint32_t t1518_u;
	uint32_t t1519x_l;
	uint32_t t1519x_u;
	uint32_t res02a8[6];
	uint32_t tcnp_l;
	uint32_t tcnp_u;
	uint32_t res02c8[14];
	/* Line Interface Control */
	uint32_t if_mode;		/* 0x300 Interface Mode Control */
	uint32_t if_status;		/* 0x304 Interface Status */
	uint32_t res0308[14];
	/* HiGig/2 */
	uint32_t hg_config;		/* 0x340 Control and cfg */
	uint32_t res0344[3];
	uint32_t hg_pause_quanta;	/* 0x350 Pause quanta */
	uint32_t res0354[3];
	uint32_t hg_pause_thresh;	/* 0x360 Pause quanta threshold */
	uint32_t res0364[3];
	uint32_t hgrx_pause_status;	/* 0x370 Receive pause status */
	uint32_t hg_fifos_status;	/* 0x374 fifos status */
	uint32_t rhm;			/* 0x378 rx messages counter */
	uint32_t thm;			/* 0x37C tx messages counter */
};

/* information for macless comes from device tree */
struct macless_port_cfg {
	char macless_name[IFNAMSIZ];
	uint32_t rx_start;
	uint32_t rx_count;
	uint32_t tx_start;
	uint32_t tx_count;
	struct ether_addr src_mac;
	struct ether_addr peer_mac;
};

struct onic_port_cfg {
	char macless_name[IFNAMSIZ];
	uint32_t onic_rx_start;		/* Consumed by oNIC drv in linux */
	uint32_t onic_rx_count;
	struct ether_addr src_mac;
	struct ether_addr peer_mac;
};

struct shared_mac_cfg {
	/* is this interface a shared interface or not */
	int is_shared_mac;
	char shared_mac_name[IFNAMSIZ];
};

/* This struct exports parameters about an Fman network interface, determined
 * from the device-tree. */
struct fman_if {
	/* Which Fman this interface belongs to */
	uint8_t fman_idx;
	/* The type/speed of the interface */
	enum fman_mac_type mac_type;
	/* Boolean, set when mac type is memac */
	uint8_t is_memac;
	/* Boolean, set when PHY is RGMII */
	uint8_t is_rgmii;
	/* The index of this MAC (within the Fman it belongs to) */
	uint8_t mac_idx;
	/* The MAC address */
	struct ether_addr mac_addr;
	/* The Qman channel to schedule Tx FQs to */
	u16 tx_channel_id;
	/* The hard-coded FQIDs for this interface. Note: this doesn't cover the
	 * PCD nor the "Rx default" FQIDs, which are configured via FMC and its
	 * XML-based configuration. */
	uint32_t fqid_rx_def;
	uint32_t fqid_rx_err;
	uint32_t fqid_tx_err;
	uint32_t fqid_tx_confirm;
	/* The MAC-less port info */
	struct macless_port_cfg macless_info;
	/* The oNIC port info */
	struct onic_port_cfg onic_info;
	/* The shared MAC info */
	struct shared_mac_cfg shared_mac_info;
	/* The base node for a per-"if" list of "struct fman_if_bpool" items */
	struct list_head bpool_list;
	/* The node for linking this interface into "fman_if_list" */
	struct list_head node;
};

/* This struct exposes parameters for buffer pools, extracted from the network
 * interface settings in the device tree. */
struct fman_if_bpool {
	uint32_t bpid;
	uint64_t count;
	uint64_t size;
	uint64_t addr;
	/* The node for linking this bpool into fman_if::bpool_list */
	struct list_head node;
};

/* Internal Context transfer params - FMBM_RICP*/
struct fman_if_ic_params {
	/*IC offset in the packet buffer */
	uint16_t iceof;
	/*IC internal offset */
	uint16_t iciof;
	/*IC size to copy */
	uint16_t icsz;
};

/* And this is the base list node that the interfaces are added to. (See
 * fman_if_enable_all_rx() below for an example of its use.) */
const struct list_head *fman_if_list;

/* "init" discovers all Fman interfaces. "finish" tears down the driver. */
int fman_init(void);
void fman_finish(void);

/* Set promiscuous mode on an interface */
void fm_mac_set_promiscuous(struct fman_if *p);

/* Get mac config*/
int fm_mac_config(struct fman_if *p, uint8_t *eth);

/* Set MAC address for a particular interface */
int fm_mac_add_exact_match_mac_addr(struct fman_if *p, uint8_t *eth,
					      uint8_t addr_num);

/* Remove a MAC address for a particular interface */
int fm_mac_rem_exact_match_mac_addr(struct fman_if *p, int8_t addr_num);

/* Get the FMAN statistics */
void fman_if_stats_get(struct fman_if *p, struct rte_eth_stats *stats);

/* Reset the FMAN statistics */
void fman_if_stats_reset(struct fman_if *p);

/* Set ignore pause option for a specific interface */
void fm_mac_set_rx_ignore_pause_frames(struct fman_if *p, bool enable);

/* Enable Loopback mode */
void fm_mac_config_loopback(struct fman_if *p, bool enable);

/* Set max frame length */
void fm_mac_conf_max_frame_len(struct fman_if *p,
			       unsigned int max_frame_len);

/* Enable/disable Rx promiscuous mode on specified interface */
void fman_if_promiscuous_enable(struct fman_if *);
void fman_if_promiscuous_disable(struct fman_if *);

/* Enable/disable Rx on specific interfaces */
void fman_if_enable_rx(struct fman_if *);
void fman_if_disable_rx(struct fman_if *);

/* Enable/disable loopback on specific interfaces */
void fman_if_loopback_enable(struct fman_if *);
void fman_if_loopback_disable(struct fman_if *);

/* Set buffer pool on specific interface */
void fman_if_set_bp(struct fman_if *fm_if, unsigned num, int bpid,
		    size_t bufsize);

/* Get Flow Control threshold parameters on specific interface */
int fman_if_get_fc_threshold(struct fman_if *fm_if);

/* Enable and Set Flow Control threshold parameters on specific interface */
int fman_if_set_fc_threshold(struct fman_if *fm_if,
			u32 high_water, u32 low_water, u32 bpid);

/* Get Flow Control pause quanta on specific interface */
int fman_if_get_fc_quanta(struct fman_if *fm_if);

/* Set Flow Control pause quanta on specific interface */
int fman_if_set_fc_quanta(struct fman_if *fm_if, u16 pause_quanta);

/* Set default error fqid on specific interface */
void fman_if_set_err_fqid(struct fman_if *fm_if, uint32_t err_fqid);

/* Get IC transfer params */
int fman_if_get_ic_params(struct fman_if *fm_if, struct fman_if_ic_params *icp);

/* Set IC transfer params */
int fman_if_set_ic_params(struct fman_if *fm_if,
			  const struct fman_if_ic_params *icp);

/* Get interface fd->offset value */
int fman_if_get_fdoff(struct fman_if *fm_if);

/* Set interface fd->offset value */
void fman_if_set_fdoff(struct fman_if *fm_if, uint32_t fd_offset);

/* Get interface Max Frame length (MTU) */
uint16_t fman_if_get_maxfrm(struct fman_if *fm_if);

/* Set interface  Max Frame length (MTU) */
void fman_if_set_maxfrm(struct fman_if *fm_if, uint16_t max_frm);

/* Set interface next invoked action for dequeue operation */
void fman_if_set_dnia(struct fman_if *fm_if, uint32_t nia);

/* discard error packets on rx */
void fman_if_discard_rx_errors(struct fman_if *fm_if);

void fman_if_set_mcast_filter_table(struct fman_if *p);

void fman_if_reset_mcast_filter_table(struct fman_if *p);

int fman_memac_add_hash_mac_addr(struct fman_if *p, uint8_t *eth);

int fman_memac_get_primary_mac_addr(struct fman_if *p, uint8_t *eth);


/* Enable/disable Rx on all interfaces */
static inline void fman_if_enable_all_rx(void)
{
	struct fman_if *__if;

	list_for_each_entry(__if, fman_if_list, node)
		fman_if_enable_rx(__if);
}

static inline void fman_if_disable_all_rx(void)
{
	struct fman_if *__if;

	list_for_each_entry(__if, fman_if_list, node)
		fman_if_disable_rx(__if);
}

/* To display MAC addresses (of type "struct ether_addr") via printf()-style
 * interfaces, these macros may come in handy. Eg;
 *        struct fman_if *p = get_ptr_to_some_interface();
 *        printf("MAC address is " ETH_MAC_PRINTF_FMT "\n",
 *               ETH_MAC_PRINTF_ARGS(&p->mac_addr));
 */
#define ETH_MAC_PRINTF_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_MAC_PRINTF_ARGS(a) \
		(a)->addr_bytes[0], (a)->addr_bytes[1], \
		(a)->addr_bytes[2], (a)->addr_bytes[3], \
		(a)->addr_bytes[4], (a)->addr_bytes[5]

/* To iterate the "bpool_list" for an interface. Eg;
 *        struct fman_if *p = get_ptr_to_some_interface();
 *        struct fman_if_bpool *bp;
 *        printf("Interface uses following BPIDs;\n");
 *        fman_if_for_each_bpool(bp, p) {
 *            printf("    %d\n", bp->bpid);
 *            [...]
 *        }
 */
#define fman_if_for_each_bpool(bp, __if) \
	list_for_each_entry(bp, &(__if)->bpool_list, node)

#define FMAN_IP_REV_1	0xC30C4
#define FMAN_IP_REV_1_MAJOR_MASK 0x0000FF00
#define FMAN_IP_REV_1_MAJOR_SHIFT 8
#define FMAN_V3	0x06
#define FMAN_V3_CONTEXTA_EN_A2V	0x10000000
#define FMAN_V3_CONTEXTA_EN_OVOM	0x02000000
#define FMAN_V3_CONTEXTA_EN_EBD	0x80000000
#define FMAN_CONTEXTA_DIS_CHECKSUM	0x7ull
#define FMAN_CONTEXTA_SET_OPCODE11 0x2000000b00000000
extern u16 fman_ip_rev;
extern u32 fman_dealloc_bufs_mask_hi;
extern u32 fman_dealloc_bufs_mask_lo;
#endif	/* __FMAN_H */
