/* Copyright 2013-2015 Freescale Semiconductor Inc.
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
#ifndef __FSL_MC_CMD_H
#define __FSL_MC_CMD_H

#define MC_CMD_NUM_OF_PARAMS	7

#define MAKE_UMASK64(_width) \
       ((uint64_t)((_width) < 64 ? ((uint64_t)1 << (_width)) - 1 :\
		       (uint64_t)-1))
static inline uint64_t mc_enc(int lsoffset, int width, uint64_t val)
{
	return (uint64_t)(((uint64_t)val & MAKE_UMASK64(width)) << lsoffset);
}

static inline uint64_t mc_dec(uint64_t val, int lsoffset, int width)
{
	return (uint64_t)((val >> lsoffset) & MAKE_UMASK64(width));
}

struct mc_command {
	uint64_t header;
	uint64_t params[MC_CMD_NUM_OF_PARAMS];
};

/**
 * enum mc_cmd_status - indicates MC status at command response
 * @MC_CMD_STATUS_OK: Completed successfully
 * @MC_CMD_STATUS_READY: Ready to be processed
 * @MC_CMD_STATUS_AUTH_ERR: Authentication error
 * @MC_CMD_STATUS_NO_PRIVILEGE: No privilege
 * @MC_CMD_STATUS_DMA_ERR: DMA or I/O error
 * @MC_CMD_STATUS_CONFIG_ERR: Configuration error
 * @MC_CMD_STATUS_TIMEOUT: Operation timed out
 * @MC_CMD_STATUS_NO_RESOURCE: No resources
 * @MC_CMD_STATUS_NO_MEMORY: No memory available
 * @MC_CMD_STATUS_BUSY: Device is busy
 * @MC_CMD_STATUS_UNSUPPORTED_OP: Unsupported operation
 * @MC_CMD_STATUS_INVALID_STATE: Invalid state
 */
enum mc_cmd_status {
	MC_CMD_STATUS_OK = 0x0,
	MC_CMD_STATUS_READY = 0x1,
	MC_CMD_STATUS_AUTH_ERR = 0x3,
	MC_CMD_STATUS_NO_PRIVILEGE = 0x4,
	MC_CMD_STATUS_DMA_ERR = 0x5,
	MC_CMD_STATUS_CONFIG_ERR = 0x6,
	MC_CMD_STATUS_TIMEOUT = 0x7,
	MC_CMD_STATUS_NO_RESOURCE = 0x8,
	MC_CMD_STATUS_NO_MEMORY = 0x9,
	MC_CMD_STATUS_BUSY = 0xA,
	MC_CMD_STATUS_UNSUPPORTED_OP = 0xB,
	MC_CMD_STATUS_INVALID_STATE = 0xC
};

/*  MC command flags */

/**
 * High priority flag
 */
#define MC_CMD_FLAG_PRI		0x00008000
/**
 * Command completion flag
 */
#define MC_CMD_FLAG_INTR_DIS	0x01000000

/**
 * Command ID field offset
 */
#define MC_CMD_HDR_CMDID_O	52
/**
 * Command ID field size
 */
#define MC_CMD_HDR_CMDID_S	12
/**
 * Token field offset
 */
#define MC_CMD_HDR_TOKEN_O	38
/**
 * Token field size
 */
#define MC_CMD_HDR_TOKEN_S	10
/**
 * Status field offset
 */
#define MC_CMD_HDR_STATUS_O	16
/**
 * Status field size
 */
#define MC_CMD_HDR_STATUS_S	8
/**
 * Flags field offset
 */
#define MC_CMD_HDR_FLAGS_O	0
/**
 * Flags field size
 */
#define MC_CMD_HDR_FLAGS_S	32
/**
 *  Command flags mask
 */
#define MC_CMD_HDR_FLAGS_MASK	0xFF00FF00

#define MC_CMD_HDR_READ_STATUS(_hdr) \
	((enum mc_cmd_status)mc_dec((_hdr), \
		MC_CMD_HDR_STATUS_O, MC_CMD_HDR_STATUS_S))

#define MC_CMD_HDR_READ_TOKEN(_hdr) \
	((uint16_t)mc_dec((_hdr), MC_CMD_HDR_TOKEN_O, MC_CMD_HDR_TOKEN_S))

#define MC_PREP_OP(_ext, _param, _offset, _width, _type, _arg) \
	((_ext)[_param] |= cpu_to_le64(mc_enc((_offset), (_width), _arg)))

#define MC_EXT_OP(_ext, _param, _offset, _width, _type, _arg) \
	(_arg = (_type)mc_dec(cpu_to_le64(_ext[_param]), (_offset), (_width)))

#define MC_CMD_OP(_cmd, _param, _offset, _width, _type, _arg) \
	((_cmd).params[_param] |= mc_enc((_offset), (_width), _arg))

#define MC_RSP_OP(_cmd, _param, _offset, _width, _type, _arg) \
	(_arg = (_type)mc_dec(_cmd.params[_param], (_offset), (_width)))

static inline uint64_t mc_encode_cmd_header(uint16_t cmd_id,
					    uint32_t cmd_flags,
					    uint16_t token)
{
	uint64_t hdr;

	hdr = mc_enc(MC_CMD_HDR_CMDID_O, MC_CMD_HDR_CMDID_S, cmd_id);
	hdr |= mc_enc(MC_CMD_HDR_FLAGS_O, MC_CMD_HDR_FLAGS_S,
		       (cmd_flags & MC_CMD_HDR_FLAGS_MASK));
	hdr |= mc_enc(MC_CMD_HDR_TOKEN_O, MC_CMD_HDR_TOKEN_S, token);
	hdr |= mc_enc(MC_CMD_HDR_STATUS_O, MC_CMD_HDR_STATUS_S,
		       MC_CMD_STATUS_READY);

	return hdr;
}

/**
 * mc_write_command - writes a command to a Management Complex (MC) portal
 *
 * @portal: pointer to an MC portal
 * @cmd: pointer to a filled command
 */
static inline void mc_write_command(struct mc_command __iomem *portal,
				    struct mc_command *cmd)
{
	int i;
	uint32_t word;

	/* copy command parameters into the portal */
	for (i = 0; i < MC_CMD_NUM_OF_PARAMS; i++)
		iowrite64(cmd->params[i], &portal->params[i]);

	/* submit the command by writing the header */
	word = (uint32_t)mc_dec(cmd->header, 32, 32);
	iowrite32(word, (((uint32_t *)&portal->header) + 1));

	word = (uint32_t)mc_dec(cmd->header, 0, 32);
	iowrite32(word, (uint32_t *)&portal->header);
}

/**
 * mc_read_response - reads the response for the last MC command from a
 * Management Complex (MC) portal
 *
 * @portal: pointer to an MC portal
 * @resp: pointer to command response buffer
 *
 * Returns MC_CMD_STATUS_OK on Success; Error code otherwise.
 */
static inline enum mc_cmd_status mc_read_response(
					struct mc_command __iomem *portal,
					struct mc_command *resp)
{
	int i;
	enum mc_cmd_status status;

	/* Copy command response header from MC portal: */
	resp->header = ioread64(&portal->header);
	status = MC_CMD_HDR_READ_STATUS(resp->header);
	if (status != MC_CMD_STATUS_OK)
		return status;

	/* Copy command response data from MC portal: */
	for (i = 0; i < MC_CMD_NUM_OF_PARAMS; i++)
		resp->params[i] = ioread64(&portal->params[i]);

	return status;
}

#endif /* __FSL_MC_CMD_H */
