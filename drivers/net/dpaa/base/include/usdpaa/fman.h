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

#define MEMAC_NUM_OF_PADDRS 7 /* Num of additional exact match MAC adr regs */

/* dTSEC MAC Registers */
#define MACCFG1_LOOPBACK	0x00000100
#define MACCFG1_RX_FLOW		0x00000020

#define MAXFRM_SIZE_DTSEC	0x00002580
#define MAXFRM_MASK		0x00003fff

#define RCTRL_MPROM		0x00000008
#define RCTRL_UPROM		0x00000001
#define RCTRL_PROM		(RCTRL_UPROM | RCTRL_MPROM)

/* Control and Configuration Register (COMMAND_CONFIG) for MEMAC */
#define CMD_CFG_LOOPBACK_EN	0x00000400 /* 21 XGMII/GMII loopback enable */
#define CMD_CFG_PROMIS_EN	0x00000010 /* 27 Promiscuous operation enable */
#define CMD_CFG_PAUSE_IGNORE	0x00000100 /* 23 Ignore Pause frame quanta */

/* Max recieve frame length mask */
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

struct dtsec_regs {
	/* dTSEC General Control and Status Registers */
	uint32_t tsec_id;	/* 0x000 ETSEC_ID register */
	uint32_t tsec_id2;	/* 0x004 ETSEC_ID2 register */
	uint32_t ievent;	/* 0x008 Interrupt event register */
	uint32_t imask;		/* 0x00C Interrupt mask register */
	uint32_t reserved0010[1];
	uint32_t ecntrl;	/* 0x014 E control register */
	uint32_t ptv;		/* 0x018 Pause time value register */
	uint32_t tbipa;		/* 0x01C TBI PHY address register */
	uint32_t tmr_ctrl;	/* 0x020 Time-stamp Control register */
	uint32_t tmr_pevent;	/* 0x024 Time-stamp event register */
	uint32_t tmr_pemask;	/* 0x028 Timer event mask register */
	uint32_t reserved002c[5];
	uint32_t tctrl;		/* 0x040 Transmit control register */
	uint32_t reserved0044[3];
	uint32_t rctrl;		/* 0x050 Receive control register */
	uint32_t reserved0054[11];
	uint32_t igaddr[8];	/* 0x080-0x09C Individual/group address */
	uint32_t gaddr[8];	/* 0x0A0-0x0BC Group address registers 0-7 */
	uint32_t reserved00c0[16];
	uint32_t maccfg1;		/* 0x100 MAC configuration #1 */
	uint32_t maccfg2;		/* 0x104 MAC configuration #2 */
	uint32_t ipgifg;		/* 0x108 IPG/IFG */
	uint32_t hafdup;		/* 0x10C Half-duplex */
	uint32_t maxfrm;		/* 0x110 Maximum frame */
	uint32_t reserved0114[10];
	uint32_t ifstat;		/* 0x13C Interface status */
	uint32_t macstnaddr1;		/* 0x140 Station Address,part 1 */
	uint32_t macstnaddr2;		/* 0x144 Station Address,part 2  */
	struct {
	    uint32_t exact_match1; /* octets 1-4 */
	    uint32_t exact_match2; /* octets 5-6 */
	} macaddr[15];	/* 0x148-0x1BC mac exact match addresses 1-15 */
	uint32_t reserved01c0[16];
	uint32_t tr64;	/* 0x200 transmit and receive 64 byte frame counter */
	uint32_t tr127;	/* 0x204 transmit and receive 65 to 127 byte frame
			 * counter */
	uint32_t tr255;	/* 0x208 transmit and receive 128 to 255 byte frame
			 * counter */
	uint32_t tr511;	/* 0x20C transmit and receive 256 to 511 byte frame
			 * counter */
	uint32_t tr1k;	/* 0x210 transmit and receive 512 to 1023 byte frame
			 * counter */
	uint32_t trmax;	/* 0x214 transmit and receive 1024 to 1518 byte frame
			 * counter */
	uint32_t trmgv;	/* 0x218 transmit and receive 1519 to 1522 byte good
			 * VLAN frame count */
	uint32_t rbyt;	/* 0x21C receive byte counter */
	uint32_t rpkt;	/* 0x220 receive packet counter */
	uint32_t rfcs;	/* 0x224 receive FCS error counter */
	uint32_t rmca;	/* 0x228 RMCA receive multicast packet counter */
	uint32_t rbca;	/* 0x22C receive broadcast packet counter */
	uint32_t rxcf;	/* 0x230 receive control frame packet counter */
	uint32_t rxpf;	/* 0x234 receive pause frame packet counter */
	uint32_t rxuo;	/* 0x238 receive unknown OP code counter */
	uint32_t raln;	/* 0x23C receive alignment error counter */
	uint32_t rflr;	/* 0x240 receive frame length error counter */
	uint32_t rcde;	/* 0x244 receive code error counter */
	uint32_t rcse;	/* 0x248 receive carrier sense error counter */
	uint32_t rund;	/* 0x24C receive undersize packet counter */
	uint32_t rovr;	/* 0x250 receive oversize packet counter */
	uint32_t rfrg;	/* 0x254 receive fragments counter */
	uint32_t rjbr;	/* 0x258 receive jabber counter */
	uint32_t rdrp;	/* 0x25C receive drop */
	uint32_t tbyt;	/* 0x260 transmit byte counter */
	uint32_t tpkt;	/* 0x264 transmit packet counter */
	uint32_t tmca;	/* 0x268 transmit multicast packet counter */
	uint32_t tbca;	/* 0x26C transmit broadcast packet counter */
	uint32_t txpf;	/* 0x270 transmit pause control frame counter */
	uint32_t tdfr;	/* 0x274 transmit deferral packet counter */
	uint32_t tedf;	/* 0x278 transmit excessive deferral packet counter */
	uint32_t tscl;	/* 0x27C transmit single collision packet counter */
	uint32_t tmcl;	/* 0x280 transmit multiple collision packet counter */
	uint32_t tlcl;	/* 0x284 transmit late collision packet counter */
	uint32_t txcl;	/* 0x288 transmit excessive collision packet counter */
	uint32_t tncl;	/* 0x28C transmit total collision counter */
	uint32_t reserved0290[1];
	uint32_t tdrp;	/* 0x294 transmit drop frame counter */
	uint32_t tjbr;	/* 0x298 transmit jabber frame counter */
	uint32_t tfcs;	/* 0x29C transmit FCS error counter */
	uint32_t txcf;	/* 0x2A0 transmit control frame counter */
	uint32_t tovr;	/* 0x2A4 transmit oversize frame counter */
	uint32_t tund;	/* 0x2A8 transmit undersize frame counter */
	uint32_t tfrg;	/* 0x2AC transmit fragments frame counter */
	uint32_t car1;	/* 0x2B0 carry register one register* */
	uint32_t car2;	/* 0x2B4 carry register two register* */
	uint32_t cam1;	/* 0x2B8 carry register one mask register */
	uint32_t cam2;	/* 0x2BC carry register two mask register */
	uint32_t reserved02c0[848];
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

/* Get MAC address for a particular interface */
int fm_mac_add_exact_match_mac_addr(struct fman_if *p, uint8_t *eth);

/* Add station MAC address on MEMAC */
int memac_set_station_mac_addr(struct fman_if *p, uint8_t *eth);
int memac_get_station_mac_addr(struct fman_if *p, uint8_t *eth);

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

/* Add multicast MAC address on MEMAC */
int memac_add_hash_mac_addr(struct fman_if *p, uint8_t *eth);

/* Enable/disable Rx on specific interfaces */
void fman_if_enable_rx(struct fman_if *);
void fman_if_disable_rx(struct fman_if *);

/* Enable/disable loopback on specific interfaces */
void fman_if_loopback_enable(struct fman_if *);
void fman_if_loopback_disable(struct fman_if *);

/* Set buffer pool on specific interface */
void fman_if_set_bp(struct fman_if *fm_if, unsigned num, int bpid,
		    size_t bufsize);
/* Get interface fd->offset value */
int fman_if_get_fdoff(struct fman_if *fm_if);

/* Set default error fqid on specific interface */
void fman_if_set_err_fqid(struct fman_if *fm_if, uint32_t err_fqid);

/* Get IC transfer params */
int fman_if_get_ic_params(struct fman_if *fm_if, struct fman_if_ic_params *icp);

/* Set IC transfer params */
int fman_if_set_ic_params(struct fman_if *fm_if,
			  const struct fman_if_ic_params *icp);

/* Set interface fd->offset value */
void fman_if_set_fdoff(struct fman_if *fm_if, uint32_t fd_offset);

/* Set interface next invoked action for dequeue operation */
void fman_if_set_dnia(struct fman_if *fm_if, uint32_t nia);

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
