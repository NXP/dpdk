/* Copyright 2013-2016 Freescale Semiconductor Inc.
 * Copyright (c) 2016 NXP.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _FSL_DPBP_CMD_H
#define _FSL_DPBP_CMD_H

/* DPBP Version */
#define DPBP_VER_MAJOR				3
#define DPBP_VER_MINOR				2

/* Command IDs */
#define DPBP_CMDID_CLOSE                        0x8001
#define DPBP_CMDID_OPEN                         0x8041
#define DPBP_CMDID_CREATE                       0x9041
#define DPBP_CMDID_DESTROY                      0x9841
#define DPBP_CMDID_GET_API_VERSION              0xa041

#define DPBP_CMDID_ENABLE                       0x0021
#define DPBP_CMDID_DISABLE                      0x0031
#define DPBP_CMDID_GET_ATTR                     0x0041
#define DPBP_CMDID_RESET                        0x0051
#define DPBP_CMDID_IS_ENABLED                   0x0061

#define DPBP_CMDID_SET_IRQ_ENABLE               0x0121
#define DPBP_CMDID_GET_IRQ_ENABLE               0x0131
#define DPBP_CMDID_SET_IRQ_MASK                 0x0141
#define DPBP_CMDID_GET_IRQ_MASK                 0x0151
#define DPBP_CMDID_GET_IRQ_STATUS               0x0161
#define DPBP_CMDID_CLEAR_IRQ_STATUS             0x0171

#define DPBP_CMDID_SET_NOTIFICATIONS            0x1b01
#define DPBP_CMDID_GET_NOTIFICATIONS            0x1b11

#define DPBP_CMDID_GET_FREE_BUFFERS_NUM         0x1b21

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_OPEN(cmd, dpbp_id) \
	MC_CMD_OP(cmd, 0, 0,  32, int,	    dpbp_id)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_RSP_IS_ENABLED(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  1,  int,	    en)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_SET_IRQ_ENABLE(cmd, irq_index, en) \
do { \
	MC_CMD_OP(cmd, 0, 0,  8,  uint8_t,  en); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_GET_IRQ_ENABLE(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_RSP_GET_IRQ_ENABLE(cmd, en) \
	MC_RSP_OP(cmd, 0, 0,  8,  uint8_t,  en)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_SET_IRQ_MASK(cmd, irq_index, mask) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, mask);\
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_GET_IRQ_MASK(cmd, irq_index) \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_RSP_GET_IRQ_MASK(cmd, mask) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, mask)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_GET_IRQ_STATUS(cmd, irq_index, status) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, status);\
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)
/*                cmd, param, offset, width, type, arg_name */
#define DPBP_RSP_GET_IRQ_STATUS(cmd, status) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, status)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_CLEAR_IRQ_STATUS(cmd, irq_index, status) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, status); \
	MC_CMD_OP(cmd, 0, 32, 8,  uint8_t,  irq_index);\
} while (0)

/*                cmd, param, offset, width, type,	arg_name */
#define DPBP_RSP_GET_ATTRIBUTES(cmd, attr) \
do { \
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, (attr)->bpid); \
	MC_RSP_OP(cmd, 0, 32, 32, int,	    (attr)->id);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_SET_NOTIFICATIONS(cmd, cfg) \
do { \
	MC_CMD_OP(cmd, 0, 0,  32, uint32_t, cfg->depletion_entry); \
	MC_CMD_OP(cmd, 0, 32, 32, uint32_t, cfg->depletion_exit);\
	MC_CMD_OP(cmd, 1, 0,  32, uint32_t, cfg->surplus_entry);\
	MC_CMD_OP(cmd, 1, 32, 32, uint32_t, cfg->surplus_exit);\
	MC_CMD_OP(cmd, 2, 0,  16, uint16_t, cfg->options);\
	MC_CMD_OP(cmd, 3, 0,  64, uint64_t, cfg->message_ctx);\
	MC_CMD_OP(cmd, 4, 0,  64, uint64_t, cfg->message_iova);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_CMD_GET_NOTIFICATIONS(cmd, cfg) \
do { \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, cfg->depletion_entry); \
	MC_RSP_OP(cmd, 0, 32, 32, uint32_t, cfg->depletion_exit);\
	MC_RSP_OP(cmd, 1, 0,  32, uint32_t, cfg->surplus_entry);\
	MC_RSP_OP(cmd, 1, 32, 32, uint32_t, cfg->surplus_exit);\
	MC_RSP_OP(cmd, 2, 0,  16, uint16_t, cfg->options);\
	MC_RSP_OP(cmd, 3, 0,  64, uint64_t, cfg->message_ctx);\
	MC_RSP_OP(cmd, 4, 0,  64, uint64_t, cfg->message_iova);\
} while (0)

/*                cmd, param, offset, width, type,      arg_name */
#define DPBP_RSP_GET_API_VERSION(cmd, major, minor) \
do { \
	MC_RSP_OP(cmd, 0, 0,  16, uint16_t, major);\
	MC_RSP_OP(cmd, 0, 16, 16, uint16_t, minor);\
} while (0)

/*                cmd, param, offset, width, type, arg_name */
#define DPBP_RSP_GET_NUM_FREE_BUFS(cmd, num_free_bufs) \
	MC_RSP_OP(cmd, 0, 0,  32, uint32_t, num_free_bufs)

#endif /* _FSL_DPBP_CMD_H */
