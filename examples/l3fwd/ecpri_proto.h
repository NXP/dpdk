/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 NXP
 */
#ifndef __ECPRI_PROTO_H__
#define __ECPRI_PROTO_H__

/* eCPRI, the transmission byte order follows network byte order
 * or big endian, i.e. the most significant byte 7 is sent first and the
 * least significant byte is sent last
 */

/*
 * evolved Common Public Radio Interface (eCPRI) is a protocol, which will
 * be used in fronthaul transport network.
 *
 * eCPRI over Ethernet
 * -------------------
 * eCPRImessages shall be transmitted in standard Ethernet frames.
 * The Ethernet network shall follow the definitions of IEEE Specification
 * 802.1CM, Time-Sensitive Networks for Fronthaul.
 * The type field of the Ethernet frame shall contain the eCPRIEthertype.
 * The data field of the Ethernet frame shall contain the eCPRIheader at its
 * beginning,followed immediately by the eCPRIdata.
 * The eCPRImessage shall be embedded in the Ethernet frame as a series of
 * octets. As the minimum size of the data field of an Ethernet frame is 46
 * octets, if necessary, the eCPRIdata field should be padded with octets of
 * zero to fill up this minimum size.
 * This padding is not part of the eCPRImessage and so is not to be included in
 * the message size field of the eCPRIheader.
 *
 * An eCPRInode involved in an eCPRIover Ethernet message exchange shall have
 * at least one unique Ethernet MAC address assigned to it.
 * The mapping of eCPRIservices to Ethernet MAC addresses and how this mapping
 * information is exchanged between eCPRInodes are out of scope of the
 * eCPRIspecification.
 * The Ethernet MAC header shall provide enough information about the source
 * and the destination of the eCPRImessage to deliver the message successfully
 * through the Ethernet network, with the required priority.
 *
 * eCPRI over IP
 * -------------
 * eCPRImessages shall be transmitted in UDP/IP packets.
 * The underlying layer 2 network shall follow the definitions of IEEE
 * Specification 802.1CM, Time-Sensitive Networks for Fronthaul.
 * The data field of the UDP datagram contains the eCPRIheader at its
 * beginning, followed immediately by the eCPRIdata.
 * The eCPRImessage shall be embedded in the UDP datagram as a series of
 * octets.
 * The UDP datagram shall encapsulate the eCPRImessage precisely, i.e. without
 * requiring padding octets added to the eCPRImessage.
 * An eCPRInode shall have at least one unique IP address assigned to it.
 * The mapping of eCPRIservices to IP addresses and how this mapping
 * information is exchanged between eCPRInodes are out of scope of the
 * eCPRIspecification.
 * The header fields of the UDP/IP datagram shall provide enough information
 * about the source and the destination of the eCPRImessage to deliver the
 * message successfully through the IP network, with the required priority.
 * Further details of the format and definition of the UDP/IP datagram, and how
 * the IP network is to be maintained are out of the scope of the
 * eCPRIspecification, nevertheless a routing method is recommended to
 * guarantee preservation of the order of the packets of the same priority
 * sent from one node to another.
 * eCPRIdoes not specify any range of UDP port values to identify the several
 * eCPRIstreams.
 */

#ifndef ETHERTYPE_ECPRI
#define ETHERTYPE_ECPRI		0xAEFE /* Ethernet type of eCPRI */
#endif

#define ECPRI_VERSION_1_0 0x01 /*1.0, 1.2, 2.0 */
#define ECPRI_MAX_PAYLOAD_LEN (1<<16 - 1)
#define ECPRI_MAX_MSG_IN_PKT 6


typedef enum{
	MSG_TYPE_IQ_DATA = 0,
	MSG_TYPE_BIT_SEQUENCE = 1,
	MSG_TYPE_REAL_TIME_CTRL_DATA = 2,
	MSG_TYPE_GENERIC_DATA_TRANSFER = 3,
	MSG_TYPE_REMOTE_MEMORY_ACCESS = 4,
	MSG_TYPE_ONE_WAY_DELAY_MEASURE = 5,
	MSG_TYPE_REMOTE_RESET = 6,
	MSG_TYPE_EVENT_INDICATION = 7,
	MSG_TYPE_IWF_STARTUP = 8,
	MSG_TYPE_IWF_OPERATION = 9,
	MSG_TYPE_IWF_MAPPING = 10,
	MSG_TYPE_IWF_DELAY_CTRL = 11,
	// Reserved: 12 - 63
	// Vendor Specific: 64 - 255
} ecpri_msg_type_t;


#define ECPRI_HDR_PROTO_VERSION_MASK 0xF0
#define ECPRI_HDR_PROTO_CONCAT_MASK 0x01
#define ECPRI_HDR_PROTO_CONCAT_SHIFT 0
#define ECPRI_CONCAT_DATA_ALIGN 4
/* eCPRI messages concatenation indicator.
 * C=0 indicates that the eCPRI message is the last one inside the eCPRI PDU.
 * C=1 indicates that another eCPRI msg follows this one within the eCPRI PDU.
 * In this case, 0 to 3 padding byte(s) shall be added to ensure that the
 * following eCPRI message starts 17 at a 4-byte boundary.
 * Padding byte(s) shall be ignored when received.
 */

typedef struct {
	uint8_t proto;	/* eCPRI protocol revision: 4, Reserved: 3 Concat: 1*/
	uint8_t msg_type;/* eCPRI Msg Type - check ecpri_msg_t */
	uint16_t payload;/* eCPRI Payload size - 2 bytes */
} ecpri_header_t;

typedef struct{
	uint16_t pc_rtc_id;
	/* An identifier of a series of IQ Data Transfer messages. */
	uint8_t seq_id; /*Sequence ID is unique per eAxC */
	uint8_t sub_seq_id;
	uint8_t reserve1;
	uint8_t u;
	/* Subcarrier spacing configuration(Ref.: 3GPP TS 39.211, section 4.2 */

	/* 12 Bytes for PUSCH packet header timing information */
	uint16_t reserve2;
	uint16_t maxTransmissionBW;	/* Maixum transmission bandwidth */
	uint8_t numOfAntennaDataBlock;	/* Num of antenna data blocks */
	uint8_t reserve3;
	uint16_t radio_frame_id;
	uint8_t slot_id;	/* Slot index within one radio frame */
	uint8_t symbol_id;	/* Symbol index within one slot */
} ecpri_iq_rtc_control_data_t;

typedef struct{
	uint16_t pc_rtc_id;
	/* An identifier of a series of IQ Data Transfer messages. */
	uint8_t seq_id; /*Sequence ID is unique per eAxC */
	uint8_t sub_seq_id;
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint8_t SymbolIsSync:1;
	uint8_t DLBufferUnderFlow:1;
	uint8_t DLBufferOverFlow:1;
	uint8_t ULBufferOverFlow:1;
	uint8_t DLSymbolBufOverFlowCount:4;
#else
	uint8_t DLSymbolBufOverFlowCount:4;
	uint8_t ULBufferOverFlow:1;
	uint8_t DLBufferOverFlow:1;
	uint8_t DLBufferUnderFlow:1;
	uint8_t SymbolIsSync:1;
#endif
	uint32_t reserve2:24;
	uint32_t u:8;     /* u, subcarrier spacing 0-4*/
	uint16_t radio_frame_id;
	uint16_t slot_id; /* Slot index within one radio frame */
	uint16_t reserve3;
} ecpri_iq_rtc_control_time_data_t;

/* IQ Data: Msg=0 */
#define ECPI_IQ_SUBSEQ_EBIT_MASK 0x80 /*E-bit in sub-seq id */
typedef struct {
	uint16_t pc_rtc_id;
	/* An identifier of a series of IQ Data Transfer messages. */
	uint8_t seq_id; /*Sequence ID is unique per eAxC */
	uint8_t sub_seq_id;
	uint16_t gain; /* Gain factor for signal from an ant */
} ecpri_iq_data_t;

#define ECPRI_RMA_READ_MASK 0
#define ECPRI_RMA_WRITE_MASK	     0x010000
#define ECPRI_RMA_WRITE_NO_RESP_MASK 0x100000

#define ECPRI_RMA_REQ_MASK 0
#define ECPRI_RMA_RESP_MASK    0x01
#define ECPRI_RMA_FAILURE_MASK 0x10

/* Remote Memory Access: Msg=4 */
typedef struct {
	uint8_t ram_id;
	uint8_t rw_req;
	uint16_t elem_id;
	uint64_t addr:48;
	uint16_t length;
	char data[0];
	/* Zero length array for data, app need to allocate space separately*/
} ecpri_rma_t;

typedef enum {
	ECPRI_OWD_ACTION_REQUEST = 0x0,
	ECPRI_OWD_ACTION_REQUEST_FOLLOW,
	ECPRI_OWD_ACTION_RESPONSE,
	ECPRI_OWD_ACTION_REM_REQUEST,
	ECPRI_OWD_ACTION_REM_REQ_FOLLOW,
	ECPRI_OWD_ACTION_FOLLOW,
	ECPRI_OWD_ACTION_RSVD_MIN = 0x06,
	ECPRI_OWD_ACTION_RSVD_MAX = 0xff,
} ecpri_action_type;

/* One Way Delay: Msg=5 */
typedef struct {
	uint8_t m_id;
	uint8_t action_type;
	char ts_sec[6];
	char ts_nanosec[4];
	char comp[10];
	char dummy[0];
	/* The insertion of dummy bytes is only needed when the Action Type
	 * set to 0x00 (Request) or to 0x01  (Request with Follow_Up).
	 */
} ecpri_delay_t;

#define REM_RESET_REQ 0x1
#define REM_RESET_RES 0x2
// 0x2 ... 0xf reserved

/* Remote Reset: Msg=6 */
typedef struct {
	uint8_t reset_id;
	uint8_t reset_op_code;
	char payload_type[0];
	/* Zero length array for data, app need to allocate space separately*/
} ecpri_reset_t;


typedef enum {
	EVENT_TYPE_FAULTS_INDICATION = 0x00,
	EVENT_TYPE_FAULTS_INDICATION_ACK,
	EVENT_TYPE_NOTIF_INDICATION,
	EVENT_TYPE_SYNC_REQ,
	EVENT_TYPE_SYNC_ACK,
	EVENT_TYPE_SYNC_END_INDICATION,
	EVENT_TYPE_RSVD_MIN = 0x06,
	ECPRI_TYPE_RSVD_MAX = 0xff,
} ecpri_event_type;

#define ECPRI_EVENT_FAULTS_MIN	0x000
#define ECPRI_EVENT_FAULTS_MAX	0x3FF
#define ECPRI_EVENT_NOTIF_MIN	0x400
#define ECPRI_EVENT_NOTIF_MAX	0x7FF
#define ECPRI_EVENT_VENDOR_MIN	0x800
#define ECPRI_EVENT_VENDOR_MAX	0xFF

#define ELEMENT_ID_ALL_ELEMENTS 0xFFFF
/* A fault or notification applicable for all Elements i.e. the node */

#define RAISE_A_FAULT 0x0
#define CEASE_A_FAULT 0x1

// Fault/Notification numbers
// eCPRI fauls and notifcations

#define GENERAL_USERPLANE_HW_FAULT 0x000
#define GENERAL_USERPLANE_SW_FAULT  0x001
// 0x002 ... 0x3ff eCPRI reserved  faults
#define UNKNOWN_MSG_TYPE_RECEIVED 0x400
#define USERPLANE_DATA_BUFFER_UNDERFLOW 0x401
#define USERPLANE_DATA_BUFFER_OVERFLOW 0x402
#define USERPLANE_DATA_ARRIVED_TOO_EARLY 0x403
#define USERPLANE_DATA_RECEIVED_TOO_LATE 0x404
// 0x405 ... 0x7ff notify
//0x800- 0xfff - vendor specific fault or notify

typedef struct {
	uint16_t element_id;
	uint8_t raise_cease;
	uint16_t fault_notif;
	uint32_t additional_info;
} fault_notif_t;

/* Event Indication: Msg=7 */
typedef struct {
	uint8_t event_id;
	uint8_t event_type;
	uint8_t seq_num;
	uint8_t num_faults_notif;
	fault_notif_t fn[12];
} ecpri_event_ind_t;

#define IWF_STARTUP_LINK_FEC_ON  0x80
#define IWF_STARTUP_LINK_SCRAMBLING_ON  0x40

typedef enum {
	eCPRI_LINE_BIT_RATE_OPT1  = 0x00001,
	eCPRI_LINE_BIT_RATE_OPT2  = 0x00010,
	eCPRI_LINE_BIT_RATE_OPT3  = 0x00011,
	eCPRI_LINE_BIT_RATE_OPT4  = 0x00100,
	eCPRI_LINE_BIT_RATE_OPT5  = 0x00101,
	eCPRI_LINE_BIT_RATE_OPT6  = 0x00110,
	eCPRI_LINE_BIT_RATE_OPT7  = 0x00111,
	eCPRI_LINE_BIT_RATE_OPT7A = 0x01000,
	eCPRI_LINE_BIT_RATE_OPT8  = 0x01001,
	eCPRI_LINE_BIT_RATE_OPT9  = 0x01010,
	eCPRI_LINE_BIT_RATE_OPT10 = 0x01011,
} ecpri_line_bit_rate;

/* IWF Startup: Msg=8 */
typedef struct {
	uint16_t pc_id;
	uint8_t hyperframe;
	uint8_t basicframe;
	uint32_t timestamp;
	uint8_t link;
	char data[0];
	/* Zero length array for data, app need to allocate space separately*/
} ecpri_iwf_startup_t;

#define ECPRI_IW_OP_CW_MAIN_MASK	0x80
#define ECPRI_IW_OP_CW_EXT_MASK		0x40
#define ECPRI_IW_OP_DB_MASK		0x20
#define ECPRI_IW_OP_E_MASK		0x10
#define ECPRI_IW_OP_M_MASK		0x08
#define ECPRI_IW_OP_N_MASK		0x04
#define ECPRI_IW_OP_BFF_MASK		0x03

typedef struct {
	uint8_t chunk_first_byte;
	/* Rest of the data to be parsed at run-time */
} ecpri_chunk_t;

/* IWF Operation: Msg=9 */
typedef struct {
	uint16_t pc_id;
	uint8_t hyperframe0;
	uint8_t basicframe0;
	ecpri_chunk_t ecpri_chunk0[0];
} ecpri_iwf_op_t;

/*
 * "IQ Data"			Msg Type 0 = ecpri_iq_t
 * "Bit Sequence"		Msg Type 1 = ecpri_iq_t
 * "Real-Time Control Data"	Msg Type 2 = ecpri_iq_t (pc_id/rtc_id)
 * "Generic Data Transfer"	Msg Type 3 = ecpri_iq_t
 * "Remote Memory Access"	Msg Type 4 = ecpri_rma_t
 * "One-Way Delay Measurement"	Msg Type 5 = ecpri_delay_t
 * "Remote Reset"		Msg Type 6 = ecpri_reset_t
 * "Event Indication"		Msg Type 7 = ecpri_event_ind_t
 *				Msg Type 8 = ecpri_iwf_startup_t
 *				Msg Type 9 = ecpri_iwf_op_t
 *				Msg Type 10 =
 *				Msg Type 11 =
 */

typedef struct {
	ecpri_header_t header;
	union {
		ecpri_iq_data_t iq;
		ecpri_iq_rtc_control_time_data_t iq_rtc_time;
		ecpri_iq_rtc_control_data_t iq_rtc;
		ecpri_rma_t rma;
		ecpri_delay_t owd;
		ecpri_reset_t reset;
		ecpri_event_ind_t event;
		ecpri_iwf_startup_t iwf_start;
		ecpri_iwf_op_t iwf_op;
	} payload;
} __attribute__((packed)) ecpri_msg_t;

#define ECPRI_IQ_BUF_INLINE_MBUF  0x01

typedef struct{
	uint16_t pc_rtc_id;

	uint8_t msg_type;/* eCPRI Msg Type - check ecpri_msg_t */
	uint8_t seq_id; /*Sequence ID is unique per eAxC */
	uint8_t sub_seq_id;
	uint8_t symbol_id;	/* Symbol index within one slot */
	uint16_t slot_id; /* Slot index within one radio frame */

	uint16_t radio_frame_id;
	uint16_t gain; /* Gain factor for signal from an ant */
	uint16_t flags;
	uint16_t iqbuflen;
	struct rte_mbuf *m;
	void *iqbuf;
} ecpri_desc_t;

#endif /* __ECPRI_PROTO_H__ */
