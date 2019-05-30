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
#include <fsl_mc_sys.h>
#include <fsl_mc_cmd.h>

/* ODP framework using MC poratl in shared mode. Following
   changes to introduce Locks must be maintained while
   merging the FLIB.
*/

/**
* The mc_spinlock_t type.
*/
typedef struct {
	volatile int locked; /**< lock status 0 = unlocked, 1 = locked */
} mc_spinlock_t;

/**
* A static spinlock initializer.
*/
static mc_spinlock_t mc_portal_lock = { 0 };

static inline void mc_pause(void) {}

static inline void mc_spinlock_lock(mc_spinlock_t *sl)
{
	while (__sync_lock_test_and_set(&sl->locked, 1))
		while (sl->locked)
			mc_pause();
}

static inline void mc_spinlock_unlock(mc_spinlock_t *sl)
{
	__sync_lock_release(&sl->locked);
}

static int mc_status_to_error(enum mc_cmd_status status)
{
	switch (status) {
	case MC_CMD_STATUS_OK:
		return 0;
	case MC_CMD_STATUS_AUTH_ERR:
		return -EACCES; /* Token error */
	case MC_CMD_STATUS_NO_PRIVILEGE:
		return -EPERM; /* Permission denied */
	case MC_CMD_STATUS_DMA_ERR:
		return -EIO; /* Input/Output error */
	case MC_CMD_STATUS_CONFIG_ERR:
		return -EINVAL; /* Device not configured */
	case MC_CMD_STATUS_TIMEOUT:
		return -ETIMEDOUT; /* Operation timed out */
	case MC_CMD_STATUS_NO_RESOURCE:
		return -ENAVAIL; /* Resource temporarily unavailable */
	case MC_CMD_STATUS_NO_MEMORY:
		return -ENOMEM; /* Cannot allocate memory */
	case MC_CMD_STATUS_BUSY:
		return -EBUSY; /* Device busy */
	case MC_CMD_STATUS_UNSUPPORTED_OP:
		return -ENOTSUP; /* Operation not supported by device */
	case MC_CMD_STATUS_INVALID_STATE:
		return -ENODEV; /* Invalid device state */
	default:
		break;
	}

	/* Not expected to reach here */
	return -EINVAL;
}

int mc_send_command(struct fsl_mc_io *mc_io, struct mc_command *cmd)
{
	enum mc_cmd_status status;

	if (!mc_io || !mc_io->regs)
		return -EACCES;

	/* --- Call lock function here in case portal is shared --- */
	mc_spinlock_lock(&mc_portal_lock);

	mc_write_command(mc_io->regs, cmd);

	/* Spin until status changes */
	do {
		status = MC_CMD_HDR_READ_STATUS(ioread64(mc_io->regs));

		/* --- Call wait function here to prevent blocking ---
		 * Change the loop condition accordingly to exit on timeout.
		 */
	} while (status == MC_CMD_STATUS_READY);

	/* Read the response back into the command buffer */
	mc_read_response(mc_io->regs, cmd);

	/* --- Call unlock function here in case portal is shared --- */
	mc_spinlock_unlock(&mc_portal_lock);

	return mc_status_to_error(status);
}
