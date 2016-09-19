/*
 *   BSD LICENSE
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Freescale Semiconductor, Inc nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <time.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>
#include <rte_ethdev.h>

/* DPAA2 Global constants */
#include <dpaa2_logs.h>
#include <dpaa2_hw_pvt.h>

/* DPAA2 Base interface files */
#include <dpaa2_hw_dpbp.h>
#include <dpaa2_hw_dpni.h>
#include <dpaa2_hw_dpio.h>

/* DPDP Interfaces */
#include <dpaa2_ethdev.h>

struct swp_active_dqs global_active_dqs_list[NUM_MAX_SWP];

uint16_t
dpaa2_dev_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0;
	uint8_t is_last = 0, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct rte_eth_dev *dev = dpaa2_q->dev;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;
	dq_storage = dpaa2_q->q_storage->dq_storage[0];

	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, nb_pkts);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	/* todo optimization - we can have dq_storage_phys available*/
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);

	/*Issue a volatile dequeue command. */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			PMD_DRV_LOG(ERR, "VDQ command is not issued."
				"QBMAN is busy\n");
			/* Portal was busy, try again */
			continue;
		}
		break;
	};

	/* Receive the packets till Last Dequeue entry is found with
	 * respect to the above issues PULL command.
	 */
	while (!is_last) {
		/*Check if the previous issued command is completed.
		*Also seems like the SWP is shared between the Ethernet Driver
		*and the SEC driver.*/
		while (!qbman_check_command_complete(swp, dq_storage))
			;
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		while (!qbman_result_has_new_result(swp, dq_storage))
			;
		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				PMD_DRV_LOG(DEBUG, "No frame is delivered\n");
				continue;
			}
		}

		fd = qbman_result_DQ_fd(dq_storage);
		bufs[num_rx] = eth_fd_to_mbuf(fd);
		bufs[num_rx]->port = dev->data->port_id;

		num_rx++;
		dq_storage++;
	} /* End of Packet Rx loop */

	dpaa2_q->rx_pkts += num_rx;

	PMD_DRV_LOG(INFO, "Ethernet Received %d Packets\n", num_rx);
	/*Return the total number of packets received to DPAA2 app*/
	return num_rx;
}

uint16_t
dpaa2_dev_prefetch_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_result *dq_storage;
	uint32_t fqid = dpaa2_q->fqid;
	int ret, num_rx = 0;
	uint8_t is_last = 0, status;
	struct qbman_swp *swp;
	const struct qbman_fd *fd[16];
	struct qbman_pull_desc pulldesc;
	struct queue_storage_info_t *q_storage = dpaa2_q->q_storage;
	struct rte_eth_dev *dev = dpaa2_q->dev;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;
	if (!q_storage->active_dqs) {
		q_storage->toggle = 0;
		dq_storage = q_storage->dq_storage[q_storage->toggle];
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc, nb_pkts);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
				    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
		if (check_swp_active_dqs(thread_io_info.dpio_dev->index)) {
			while (!qbman_check_command_complete(swp,
				get_swp_active_dqs(thread_io_info.dpio_dev->index)));
			clear_swp_active_dqs(thread_io_info.dpio_dev->index);
		}
		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				PMD_DRV_LOG(WARNING, "VDQ command is not issued."
					    "QBMAN is busy\n");
				/* Portal was busy, try again */
				continue;
			}
			break;
		}
		q_storage->active_dqs = dq_storage;
		q_storage->active_dpio_id = thread_io_info.dpio_dev->index;
		set_swp_active_dqs(thread_io_info.dpio_dev->index, dq_storage);
	}
	dq_storage = q_storage->active_dqs;
	while (!qbman_check_command_complete(swp, dq_storage))
		;
	if (dq_storage == get_swp_active_dqs(q_storage->active_dpio_id))
		clear_swp_active_dqs(q_storage->active_dpio_id);
	while (!is_last) {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		struct rte_mbuf *mbuf;

		while (!qbman_result_has_new_result(swp, dq_storage))
			;
		rte_prefetch0((void *)((uint64_t)(dq_storage + 1)));
		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				PMD_DRV_LOG2(DEBUG, "No frame is delivered\n");
				continue;
			}
		}
		fd[num_rx] = qbman_result_DQ_fd(dq_storage);
		mbuf = (struct rte_mbuf *)DPAA2_IOVA_TO_VADDR(
				DPAA2_GET_FD_ADDR(fd[num_rx])
				 - bpid_info[DPAA2_GET_FD_BPID(fd[num_rx])].meta_data_size);
		/* Prefeth mbuf */
		rte_prefetch0(mbuf);
		/* Prefetch Annotation address from where we get parse results */
		rte_prefetch0((void *)((uint64_t)DPAA2_GET_FD_ADDR(fd[num_rx])
				+ DPAA2_FD_PTA_SIZE + 16));

		bufs[num_rx] = eth_fd_to_mbuf(fd[num_rx]);
		bufs[num_rx]->port = dev->data->port_id;

		dq_storage++;
		num_rx++;

	} /* End of Packet Rx loop */

	if (check_swp_active_dqs(thread_io_info.dpio_dev->index)) {
		while (!qbman_check_command_complete(swp,
			get_swp_active_dqs(thread_io_info.dpio_dev->index)))
			;
		clear_swp_active_dqs(thread_io_info.dpio_dev->index);
	}
	q_storage->toggle ^= 1;
	dq_storage = q_storage->dq_storage[q_storage->toggle];
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_numframes(&pulldesc, nb_pkts);
	qbman_pull_desc_set_fq(&pulldesc, fqid);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			    (dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), 1);
	/*Issue a volatile dequeue command. */
	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			PMD_DRV_LOG(WARNING, "VDQ command is not issued."
				"QBMAN is busy\n");
			continue;
		}
		break;
	}
	q_storage->active_dqs = dq_storage;
	q_storage->active_dpio_id = thread_io_info.dpio_dev->index;
	set_swp_active_dqs(thread_io_info.dpio_dev->index, dq_storage);

	dpaa2_q->rx_pkts += num_rx;

	PMD_DRV_LOG2(INFO, "Ethernet Received %d Packets\n", num_rx);
	/*Return the total number of packets received to DPAA2 app*/
	return num_rx;
}

/*
 * Callback to handle sending packets through a real NIC.
 */
uint16_t
dpaa2_dev_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	/* Function to transmit the frames to given device and VQ*/
	uint32_t loop;
	int32_t ret;
#ifdef QBMAN_MULTI_TX
	struct qbman_fd fd_arr[MAX_TX_RING_SLOTS];
	uint32_t frames_to_send;
#else
	struct qbman_fd fd;
#endif
	struct rte_mempool *mp;
	struct qbman_eq_desc eqdesc;
	struct dpaa2_queue *dpaa2_q = (struct dpaa2_queue *)queue;
	struct qbman_swp *swp;
	uint16_t num_tx = 0;
	uint16_t bpid;
	struct rte_eth_dev *dev = dpaa2_q->dev;
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (!thread_io_info.dpio_dev) {
		ret = dpaa2_affine_qbman_swp();
		if (ret) {
			PMD_DRV_LOG(ERR, "Failure in affining portal\n");
			return 0;
		}
	}
	swp = thread_io_info.dpio_dev->sw_portal;

	PMD_DRV_LOG(DEBUG, "===> dev =%p, fqid =%d", dev, dpaa2_q->fqid);

	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);
	qbman_eq_desc_set_qd(&eqdesc, priv->qdid,
			     dpaa2_q->flow_id, dpaa2_q->tc_index);

	/*Clear the unused FD fields before sending*/
#ifdef QBMAN_MULTI_TX
	while (nb_pkts) {
#ifdef DPAA2_CGR_SUPPORT
		/*Check if the queue is congested*/
		if (qbman_result_is_CSCN(dpaa2_q->cscn))
			goto skip_tx;
#endif
		frames_to_send = (nb_pkts >> 3) ? MAX_TX_RING_SLOTS : nb_pkts;

		for (loop = 0; loop < frames_to_send; loop++) {
			fd_arr[loop].simple.frc = 0;
			DPAA2_RESET_FD_CTRL((&fd_arr[loop]));
			DPAA2_SET_FD_FLC((&fd_arr[loop]), NULL);
			mp = (*bufs)->pool;
			/* Not a hw_pkt pool allocated frame */
			if (mp && !(mp->flags & MEMPOOL_F_HW_PKT_POOL)) {
				printf("\n non hw offload bufffer ");
				/* alloc should be from the default buffer pool
				attached to this interface */
				if (priv->bp_list) {
					bpid = priv->bp_list->buf_pool.bpid;
				} else {
					printf("\n ??? why no bpool attached");
					num_tx = 0;
					goto skip_tx;
				}
				if (eth_copy_mbuf_to_fd(*bufs,
					&fd_arr[loop], bpid)) {
					bufs++;
					continue;
				}
			} else {
				bpid = mempool_to_bpid(mp);
				eth_mbuf_to_fd(*bufs, &fd_arr[loop], bpid);
			}
			bufs++;
		}
		loop = 0;
		while (loop < frames_to_send) {
			loop += qbman_swp_send_multiple(swp, &eqdesc,
					&fd_arr[loop], frames_to_send - loop);
		}

		num_tx += frames_to_send;
		dpaa2_q->tx_pkts += frames_to_send;
		nb_pkts -= frames_to_send;
	}
#else
#ifdef DPAA2_CGR_SUPPORT
	/*Check if the queue is congested*/
	if (qbman_result_is_CSCN(dpaa2_q->cscn))
		goto skip_tx;
#endif

	fd.simple.frc = 0;
	DPAA2_RESET_FD_CTRL((&fd));
	DPAA2_SET_FD_FLC((&fd), NULL);
	loop = 0;

	while (loop < nb_pkts) {
		/*Prepare each packet which is to be sent*/
		mp = bufs[loop]->pool;
		/* Not a hw_pkt pool allocated frame */
		if (mp && !(mp->flags & MEMPOOL_F_HW_PKT_POOL)) {
			/* alloc should be from the default buffer pool
			attached to this interface */
			if (priv->bp_list) {
				bpid = priv->bp_list->buf_pool.bpid;
			} else {
				/* Buffer not from offloaded area as well as
				* lacks buffer pool identifier. Cannot
				* continue.
				*/
				PMD_DRV_LOG(ERR, "No Buffer pool "
						"attached.\n");
				num_tx = 0;
				goto skip_tx;
			}

			if (eth_copy_mbuf_to_fd(bufs[loop], &fd, bpid)) {
				loop++;
				continue;
			}
		} else {
			RTE_ASSERT(mp);
			bpid = mempool_to_bpid(mp);
			eth_mbuf_to_fd(bufs[loop], &fd, bpid);
		}
		/*Enqueue a single packet to the QBMAN*/
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				PMD_DRV_LOG(DEBUG,
					"Error in transmiting the frame\n");
			}
		} while (ret != 0);

		/* Free the buffer shell */
		/* rte_pktmbuf_free(bufs[loop]); */
		num_tx++; loop++;
	}
	dpaa2_q->tx_pkts += num_tx;
	dpaa2_q->err_pkts += nb_pkts - num_tx;
#endif
skip_tx:
	return num_tx;
}
