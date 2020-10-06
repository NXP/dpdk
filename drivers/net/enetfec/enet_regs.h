/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */
#ifndef __ENET_REGS_H
#define __ENET_REGS_H

/* Ethernet receive use control and status of buffer descriptor
 */
#define RX_BD_TR	((ushort)0x0001) /* Truncated */
#define RX_BD_OV	((ushort)0x0002) /* Over-run */
#define RX_BD_CR	((ushort)0x0004) /* CRC or Frame error */
#define RX_BD_SH	((ushort)0x0008) /* Reserved */
#define RX_BD_NO	((ushort)0x0010) /* Rcvd non-octet aligned frame */
#define RX_BD_LG	((ushort)0x0020) /* Rcvd frame length voilation */
#define RX_BD_MC	((ushort)0x0040) /* Rcvd Multicast */
#define RX_BD_BC	((ushort)0x0080) /* Rcvd Broadcast */
#define RX_BD_MISS	((ushort)0x0100) /* Miss: promisc mode frame */
#define RX_BD_FIRST	((ushort)0x0400) /* Reserved */
#define RX_BD_LAST	((ushort)0x0800) /* Buffer is the last in the frame */
#define RX_BD_INTR	((ushort)0x1000) /* Software specified field */
/*  0 The next BD in consecutive location
 *  1 The next BD in ENETn_RDSR.
 */
#define RX_BD_WRAP	((ushort)0x2000)
#define RX_BD_EMPTY	((ushort)0x8000) /* BD is empty */
#define RX_BD_STATS	((ushort)0x013f) /* All buffer descriptor status bits */

/* Ethernet receive use control and status of enhanced buffer descriptor */
#define BD_ENET_RX_VLAN	0x00000004

/* Ethernet transmit use control and status of buffer descriptor.
 */
#define TX_BD_CSL	((ushort)0x0001)
#define TX_BD_UN	((ushort)0x0002)
#define TX_BD_RCMASK	((ushort)0x003c)
#define TX_BD_RL	((ushort)0x0040)
#define TX_BD_LC	((ushort)0x0080)
#define TX_BD_HB	((ushort)0x0100)
#define TX_BD_DEF	((ushort)0x0200)
#define TX_BD_TC	((ushort)0x0400) /* Transmit CRC */
#define TX_BD_LAST	((ushort)0x0800) /* Last in frame */
#define TX_BD_INTR	((ushort)0x1000)
#define TX_BD_WRAP	((ushort)0x2000)
#define TX_BD_PAD	((ushort)0x4000)
#define TX_BD_READY	((ushort)0x8000) /* Data is ready */

#define TX_BD_STATS	((ushort)0x0fff) /* All buffer descriptor status bits */

/* Ethernet transmit use control and status of enhanced buffer descriptor */
#define TX_BD_IINS		0x08000000
#define TX_BD_PINS		0x10000000
#define TX_BD_TS		0x20000000
#define TX_BD_INT		0x40000000

#define ENET_RD_START(X)	(((X) == 1) ? ENET_RD_START_1 : \
				(((X) == 2) ? \
					ENET_RD_START_2 : ENET_RD_START_0))
#define ENET_TD_START(X)	(((X) == 1) ? ENET_TD_START_1 : \
				(((X) == 2) ? \
					ENET_TD_START_2 : ENET_TD_START_0))
#define ENET_MRB_SIZE(X)	(((X) == 1) ? ENET_MRB_SIZE_1 : \
				(((X) == 2) ? \
					ENET_MRB_SIZE_2 : ENET_MRB_SIZE_0))

#define ENET_DMACFG(X)	(((X) == 2) ? ENET_DMA2CFG : ENET_DMA1CFG)

#define ENABLE_DMA_CLASS	(1 << 16)
#define ENET_RCM(X)	(((X) == 2) ? ENET_RCM2 : ENET_RCM1)
#define SLOPE_IDLE_MASK		0xffff
#define SLOPE_IDLE_1		0x200 /* BW_fraction: 0.5 */
#define SLOPE_IDLE_2		0x200 /* BW_fraction: 0.5 */
#define SLOPE_IDLE(X)		(((X) == 1) ?				\
				(SLOPE_IDLE_1 & SLOPE_IDLE_MASK) :	\
				(SLOPE_IDLE_2 & SLOPE_IDLE_MASK))
#define RCM_MATCHEN		(0x1 << 16)
#define CFG_RCMR_CMP(v, n)	(((v) & 0x7) <<  (n << 2))
#define RCMR_CMP1		(CFG_RCMR_CMP(0, 0) | CFG_RCMR_CMP(1, 1) | \
				CFG_RCMR_CMP(2, 2) | CFG_RCMR_CMP(3, 3))
#define RCMR_CMP2		(CFG_RCMR_CMP(4, 0) | CFG_RCMR_CMP(5, 1) | \
				CFG_RCMR_CMP(6, 2) | CFG_RCMR_CMP(7, 3))
#define RCM_CMP(X)		(((X) == 1) ? RCMR_CMP1 : RCMR_CMP2)
#define BD_TX_FTYPE(X)		(((X) & 0xf) << 20)

#define RX_BD_INT		0x00800000
#define RX_BD_PTP		((ushort)0x0400)
#define RX_BD_ICE		0x00000020
#define RX_BD_PCR		0x00000010
#define RX_FLAG_CSUM_EN		(RX_BD_ICE | RX_BD_PCR)
#define RX_FLAG_CSUM_ERR	(RX_BD_ICE | RX_BD_PCR)
#define ENET_MII		((uint)0x00800000)      /*MII_interrupt*/

#define ENET_ETHEREN		((uint)0x00000002)
#define ENET_TXC_DLY		((uint)0x00010000)
#define ENET_RXC_DLY		((uint)0x00020000)

/* ENET MAC is in controller */
#define QUIRK_HAS_ENET_MAC	(1 << 0)
/* gasket is used in controller */
#define QUIRK_GASKET		(1 << 2)
/* GBIT supported in controller */
#define QUIRK_GBIT		(1 << 3)
/* Controller has extended descriptor buffer */
#define QUIRK_BUFDESC_EX	(1 << 4)
/* Controller support hardware checksum */
#define QUIRK_CSUM		(1 << 5)
/* Controller support hardware vlan*/
#define QUIRK_VLAN		(1 << 6)
/* ENET IP hardware AVB
 * i.MX8MM ENET IP supports the AVB (Audio Video Bridging) feature.
 */
#define QUIRK_AVB		(1 << 8)
#define QUIRK_ERR007885		(1 << 9)
/* RACC register supported by controller */
#define QUIRK_RACC		(1 << 12)
/* interrupt coalesc supported by controller*/
#define QUIRK_COALESCE		(1 << 13)
/* To support IEEE 802.3az EEE std, new feature is added by i.MX8MQ ENET IP
 * version.
 */
#define QUIRK_EEE		(1 << 17)
/* i.MX8QM ENET IP version added the feature to generate the delayed TXC or
 * RXC. For its implementation, ENET uses synchronized clocks (250MHz) for
 * generating delay of 2ns.
 */
#define QUIRK_SUPPORT_DELAYED_CLKS	(1 << 18)

#define ENET_EIR	0x004 /* Interrupt event register */
#define ENET_EIMR	0x008 /* Interrupt mask register */
#define ENET_RDAR_0	0x010 /* Receive descriptor active register ring0 */
#define ENET_TDAR_0	0x014 /* Transmit descriptor active register ring0 */
#define ENET_ECR	0x024 /* Ethernet control register */
#define ENET_MSCR	0x044 /* MII speed control register */
#define ENET_MIBC	0x064 /* MIB control and status register */
#define ENET_RCR	0x084 /* Receive control register */
#define ENET_TCR	0x0c4 /* Transmit Control register */
#define ENET_PALR	0x0e4 /* MAC address low 32 bits */
#define ENET_PAUR	0x0e8 /* MAC address high 16 bits */
#define ENET_OPD	0x0ec /* Opcode/Pause duration register */
#define ENET_IAUR	0x118 /* hash table 32 bits high */
#define ENET_IALR	0x11c /* hash table 32 bits low */
#define ENET_GAUR	0x120 /* grp hash table 32 bits high */
#define ENET_GALR	0x124 /* grp hash table 32 bits low */
#define ENET_TFWR	0x144 /* transmit FIFO water_mark */
#define ENET_RD_START_1	0x160 /* Receive descriptor ring1 start register */
#define ENET_TD_START_1	0x164 /* Transmit descriptor ring1 start register */
#define ENET_MRB_SIZE_1	0x168 /* Maximum receive buffer size register ring1 */
#define ENET_RD_START_2	0x16c /* Receive descriptor ring2 start register */
#define ENET_TD_START_2	0x170 /* Transmit descriptor ring2 start register */
#define ENET_MRB_SIZE_2	0x174 /* Maximum receive buffer size register ring2 */
#define ENET_RD_START_0	0x180 /* Receive descriptor ring0 start reg */
#define ENET_TD_START_0	0x184 /* Transmit buffer descriptor ring0 start reg */
#define ENET_MRB_SIZE_0	0x188 /* Maximum receive buffer size register ring0*/
#define ENET_R_FIFO_SFL	0x190 /* Rx FIFO full threshold */
#define ENET_R_FIFO_SEM	0x194 /* Rx FIFO empty threshold */
#define ENET_R_FIFO_AEM	0x198 /* Rx FIFO almost empty threshold */
#define ENET_R_FIFO_AFL	0x19c /* Rx FIFO almost full threshold */
#define ENET_FRAME_TRL	0x1b0 /* Frame truncation length */
#define ENET_RACC	0x1c4 /* Receive Accelerator function configuration*/
#define ENET_RCM1	0x1c8 /* Receive classification match register ring1 */
#define ENET_RCM2	0x1cc /* Receive classification match register ring2 */
#define ENET_DMA1CFG	0x1d8 /* DMA class based configuration ring1 */
#define ENET_DMA2CFG	0x1dc /* DMA class based Configuration ring2 */
#define ENET_RDAR_1	0x1e0 /* Rx descriptor active register ring1 */
#define ENET_TDAR_1	0x1e4 /* Tx descriptor active register ring1 */
#define ENET_RDAR_2	0x1e8 /* Rx descriptor active register ring2 */
#define ENET_TDAR_2	0x1ec /* Tx descriptor active register ring2 */
#define ENET_MII_GSK_CFGR	0x300 /* MII_GSK Configuration register */
#define ENET_MII_GSK_ENR		0x308 /* MII_GSK Enable register*/

#define BM_MII_GSK_CFGR_MII		0x00
#define BM_MII_GSK_CFGR_RMII		0x01
#define BM_MII_GSK_CFGR_FRCONT_10M	0x40

/* full duplex or half duplex */
#define HALF_DUPLEX             0x00
#define FULL_DUPLEX             0x01
#define UNKNOWN_DUPLEX          0xff

#endif /*__ENET_REGS_H */
