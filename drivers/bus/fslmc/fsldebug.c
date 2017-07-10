/* Copyright (c) 2016, Freescale Semiconductor Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * DEBUG FRAMEWORK
 */


/* Linux libc standard headers */
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <rte_ethdev.h>
#include <dpaa2_ethdev.h>
#include <portal/dpaa2_hw_pvt.h>
#include <portal/dpaa2_hw_dpio.h>
#include <rte_cryptodev_pmd.h>
#include <dpaa2_sec_priv.h>
#include <fslmc_vfio.h>
#include <fsl_dpseci.h>
#include <fsl_dpbp.h>

#include <qbman/qbman_debug.h>
#include "debug.h"

#define BUFLEN 64
#define DEFAULT_PLAT_DEBUG_PORT 10000
#define MAXLENGTH 10000
char pr_buf[MAXLENGTH];


struct dpaa2_dpio_dev *debug_dpio;

static inline struct rte_eth_dev *get_dpaa2_ethdev(char *dev_name)
{
	int ret = 0;
	uint8_t port_id = 0;
	int object_id;
	char *temp_obj;
	char name[RTE_ETH_NAME_MAX_LEN];

	temp_obj = strtok(dev_name, ".");
	temp_obj = strtok(NULL, ".");
	sscanf(temp_obj, "%d", &object_id);

	ret = snprintf(name, RTE_ETH_NAME_MAX_LEN, "%d:%d.%d", 0, object_id,
			DPAA2_MC_DPNI_DEVID);
	if (ret < 0) {
		printf("Error:unable to create unique name! %s\n", dev_name);
		return NULL;
	}

	ret = rte_eth_dev_get_port_by_name(name, &port_id);
	if (ret < 0) {
		printf("Error: DPAA2 DEV %s NOT FOUND!\n", name);
		return NULL;
	}
	return &rte_eth_devices[port_id];
}

static inline struct dpaa2_sec_dev_private  *get_dpaa2_secdev_priv(char *dev_name)
{
	struct rte_cryptodev *dev;

	dev = rte_cryptodev_pmd_get_named_dev(dev_name);
	if (!dev) {
		printf("Error: DPAA2 DEV %s NOT FOUND!\n", dev_name);
		return NULL;
	}

	return dev->data->dev_private;
}

static inline struct dpaa2_dev_priv *get_ethdev_priv(char *dev_name)
{
	struct rte_eth_dev *dev;

	dev = get_dpaa2_ethdev(dev_name);
	if (!dev) {
		printf("Error: DPAA2 DEV %s NOT FOUND!\n", dev_name);
		return NULL;
	}

	return dev->data->dev_private;
}

static void get_dpni_stats(char *dev_name)
{
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpni;
	int32_t  retcode = -1;
	int nbytes;
	union dpni_statistics value;
	char *str = pr_buf;
	uint8_t page0 = 0, page1 = 1, page2 = 2;

	memset(&value, 0, sizeof(union dpni_statistics));

	dev_priv = get_ethdev_priv(dev_name);
	if (!dev_priv) {
		printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
		return;
	}

	dpni = (struct fsl_mc_io *)dev_priv->hw;

	if (!dpni) {
		printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
		return;
	}

	/*Get Counters from page_0*/
	retcode = dpni_get_statistics(dpni, CMD_PRI_LOW, dev_priv->token,
				      page0, &value);
	if (retcode)
		goto error;

	/*total pkt/frames received */
	nbytes = sprintf(str, "\nDpni Stats\n%s:"
		"\t\t\tTotal Ingress Frames\t\t\t\t\t: %lu\n",
		dev_name, value.page_0.ingress_all_frames);
	str = str + nbytes;

	/* get ingress bytes */
	nbytes = sprintf(str, "\t\t\tTotal Ingress Bytes\t\t\t\t\t: %lu\n",
			 value.page_0.ingress_all_bytes);
	str = str + nbytes;

	/*Ingress Multicast Frames */
	nbytes = sprintf(str, "\t\t\tTotal Ingress Multicast Frames\t\t\t\t: %lu\n",
			 value.page_0.ingress_multicast_frames);
	str = str + nbytes;

	/* Ingress Broadcase frames*/
	nbytes = sprintf(str, "\t\t\tTotal Ingress Broadcast Frames\t\t\t\t: %lu\n",
			 value.page_0.ingress_multicast_frames);
	str = str + nbytes;
	/*Get Counters from page_1*/
	retcode =  dpni_get_statistics(dpni, CMD_PRI_LOW, dev_priv->token,
				       page1, &value);
	if (retcode)
		goto error;

	/* Egress frames */
	nbytes = sprintf(str, "\t\t\tTotal Egress Frames\t\t\t\t\t: %lu\n",
			 value.page_1.egress_all_frames);
	str = str + nbytes;

	/* Total Egress Bytes */
	nbytes = sprintf(str, "\t\t\tTotal Egress Bytes\t\t\t\t\t: %lu\n",
			 value.page_1.egress_all_bytes);
	str = str + nbytes;

	/*Get Counters from page_2*/
	retcode =  dpni_get_statistics(dpni, CMD_PRI_LOW, dev_priv->token,
				       page2, &value);
	if (retcode)
		goto error;

	/* Ingress frames dropped due to explicit 'drop' setting*/
	nbytes = sprintf(str, "\t\t\tTotal Ingress Frames dropped explicitly\t\t\t: %lu\n",
			 value.page_2.ingress_filtered_frames);
	str = str + nbytes;

	/* Ingress frames discarded due to errors */
	nbytes = sprintf(str, "\t\t\tTotal Ingress Errored Frames discarded\t\t\t: %lu\n",
			 value.page_2.ingress_discarded_frames);
	str = str + nbytes;

	/* Ingress frames discarded due to errors */
	nbytes = sprintf(str, "\t\t\tTotal Ingress No Buffer discarded\t\t\t: %lu\n",
			 value.page_2.ingress_nobuffer_discards);
	str = str + nbytes;
	/* Total Egress frames discarded due to errors */
	nbytes = sprintf(str, "\t\t\tTotal Egress Errored Frames discarded\t\t\t: %lu\n",
			 value.page_2.egress_discarded_frames);
	return;
error:
	printf("DPNI STATS: Error Code = %d\n", retcode);
	return;
}

static void reset_dpni_stats(char *dev_name)
{
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpni;
	int32_t  retcode = -1;

	dev_priv = get_ethdev_priv(dev_name);

	if (!dev_priv) {
		printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
		return;
	}

	dpni = (struct fsl_mc_io *)dev_priv->hw;

	if (!dpni) {
		printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
		return;
	}

	/* Reset ingress packets */
	retcode =  dpni_reset_statistics(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode)
		goto error;

	return;
error:
	printf("RESET PKTIO STATS: Error Code = %d\n", retcode);
	return;
}

static void event_handler(void *msg)
{
	ipc_msg_t *event_msg = (ipc_msg_t *)msg;
	char name[BUFLEN];
	char *str = pr_buf;

	memset(pr_buf, 0, sizeof(pr_buf));
	memset(name, 0, sizeof(name));
	memcpy(name, event_msg->buffer, event_msg->buffer_len);

	switch (event_msg->obj_id) {
	case DPAA2_DEBUG_DPNI_STATS:
		{
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				get_dpni_stats(name);
			} else if ((event_msg->cmd) == DPAA2_DEBUG_CMD_RESET) {
				reset_dpni_stats(name);
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPNI_ATTRIBUTES:
		{
			struct dpaa2_dev_priv *dev_priv;
			struct dpni_attr dpni_attr;
			struct dpni_attr *attr = &dpni_attr;
			struct fsl_mc_io *dpni_dev;
			uint16_t major, minor;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_api_version(dpni_dev, CMD_PRI_LOW,
						     &major, &minor);
				dpni_get_attributes(dpni_dev, CMD_PRI_LOW, dev_priv->token, &dpni_attr);
				sprintf(str, "Dpni_Attributes\n"
						"%s:"
						"\t\t\tDPNI major version \t\t\t\t\t: %hu\n"
						"\t\t\tDPNI minor version \t\t\t\t\t: %hu\n"
						"\t\t\tMaximum number of Rx Queues per TC\t\t\t: %u\n"
						"\t\t\tMaximum number of Tx Queues \t\t\t: %u\n"
						"\t\t\tMaximum number of traffic classes (for both Tx and Rx)  : %u\n"
						"\t\t\tMaximum number of MAC filters \t\t\t: %u\n"
						"\t\t\tMaximum number of VLAN filters	\t\t\t: %u\n"
						"\t\t\tMaximum entries in QoS table \t\t\t\t: %u\n"
						"\t\t\tMaximum key size for the QoS look-up \t\t\t: %u\n"
						"\t\t\tMaximum entries in FS table \t\t\t\t: %u\n"
						"\t\t\tMaximum key size for the distribution look-up \t\t: %u\n",
						name,
						major, minor, attr->num_queues,
						attr->num_queues, attr->num_tcs,
						attr->mac_filter_entries,
						attr->vlan_filter_entries,
						attr->qos_entries,
						attr->qos_key_size,
						attr->fs_entries,
						attr->fs_key_size);
			} else {
				printf("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPNI_LINK_STATE:
		{
			struct dpaa2_dev_priv *dev_priv;
			struct dpni_link_state state;
			struct dpni_link_state *st = &state;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_link_state(dpni_dev, CMD_PRI_LOW, dev_priv->token, &state);
				sprintf(str, "Dpni Link State\n"
						"%s:"
						"\t\t\tlink rate \t\t\t\t\t\t: %u\n"
						"\t\t\tdpni link options\t\t\t\t\t: %lu\n"
						"\t\t\tlink up	\t\t\t\t\t\t: %d\n\n\n",
						name,
						st->rate, st->options, st->up);
			} else {
				printf("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPNI_MAX_FRAME_LENGTH:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint16_t max_frame_length;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_max_frame_length(dpni_dev, CMD_PRI_LOW, dev_priv->token, &max_frame_length);
				sprintf(str, "%s:\t\t\tmax frame length\t\t\t\t\t"
					": %u\n\n\n",
					name, max_frame_length);
			} else {
				printf("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPNI_MTU:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint16_t mtu = 1500;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}
#ifdef ENABLE_SNIC_SUPPORT
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_mtu(dpni_dev, CMD_PRI_LOW, dev_priv->token, &mtu);
				sprintf(str, "%s:\t\t\tmtu\t\t\t\t\t\t\t: %u\n\n\n",
					name, mtu);
			} else {
				printf("Command not supported\n");
				return;
			}
#endif
			sprintf(str, "%s:\t\t\tmtu\t\t\t\t\t\t\t: %u\n\n\n",
				name, mtu);
			break;
		}
	case DPAA2_DEBUG_DPNI_L3_CHKSUM_VALIDATION:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint32_t en;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_offload(dpni_dev, CMD_PRI_LOW,
						 dev_priv->token,
						 DPNI_OFF_RX_L3_CSUM, &en);
				sprintf(str, "L3 Checksum Hardware Offload Enable on %s"
						"\t\t\t\t\t: %d\n\n\n", name, en);
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPNI_L4_CHKSUM_VALIDATION:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint32_t en;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_offload(dpni_dev, CMD_PRI_LOW,
						 dev_priv->token,
						 DPNI_OFF_RX_L4_CSUM, &en);
				sprintf(str, "L4 Checksum Hardware Offload Enable on %s"
						"\t\t\t\t\t: %d\n\n\n", name, en);
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPNI_PRIMARY_MAC_ADDR:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint8_t mac_addr[6];
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_primary_mac_addr(dpni_dev, CMD_PRI_LOW, dev_priv->token, mac_addr);
				sprintf(str, "%s:\t\t\tMac Address\t\t\t\t\t\t:"
						" %u.%u.%u.%u.%u.%u\n\n\n",
						name,
						mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
						mac_addr[4], mac_addr[5]);
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_CGRID:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes = sprintf(str, "%s:", name);

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr a;
				uint32_t cgrid;
				uint32_t fqid;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = (struct qbman_swp *)debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_cgrid(&a, &cgrid);
						nbytes = sprintf(str, "\t\t\tCongestion group ID\t: %u\t"
								"for RX FQID: %u\n", cgrid, fqid);
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_cgrid(&a, &cgrid);
						nbytes = sprintf(str, "\t\t\tCongestion group ID\t: %u\t"
								"for TX FQID: %u\n", cgrid, fqid);
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_DESTWQ:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes = sprintf(str, "%s:", name);

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr a;
				uint32_t destwq;
				uint32_t fqid;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_destwq(&a, &destwq);
						nbytes = sprintf(str, "\t\t\tScheduling Priority\t: %u\t"
								"for RX FQID: %u\n", destwq, fqid);
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_destwq(&a, &destwq);
						nbytes = sprintf(str, "\t\t\tScheduling Priority\t: %u\t"
								"for TX FQID: %u\n", destwq, fqid);
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_TDTHRESH:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes = 0;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}
			nbytes = sprintf(str, "%s: Rx FQs= %d, Tx FQs= %d\n", name, dev_priv->nb_rx_queues, dev_priv->nb_tx_queues);

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr a;
				uint32_t tdthresh;
				uint32_t fqid;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_tdthresh(&a, &tdthresh);
						nbytes = sprintf(str, "\t\t\tTail drop threashold\t: %u\t"
								"for RX FQID: %u\n", tdthresh, fqid);
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_tdthresh(&a, &tdthresh);
						nbytes = sprintf(str, "\t\t\tTail drop threashold\t: %u\t"
								"for TX FQID: %u\n", tdthresh, fqid);
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_CTX:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes = sprintf(str, "%s:", name);

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr a;
				uint32_t hi;
				uint32_t lo;
				uint64_t ctx;
				uint32_t fqid;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_ctx(&a, &hi, &lo);
						ctx = ((uint64_t)hi << 32) | lo;
						nbytes = sprintf(str, "\t\t\tFQ Context\t\t: %lu\t"
								"for RX FQID: %u\n", ctx, fqid);
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_ctx(&a, &hi, &lo);
						ctx = ((uint64_t)hi << 32) | lo;
						nbytes = sprintf(str, "\t\t\tFQ Context\t\t: %lu\t"
								"for TX FQID: %u\n", ctx, fqid);
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_STATE_SCHEDSTATE:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes = sprintf(str, "%s:", name);

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr state;
				uint32_t fqid;
				uint32_t schd_st;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							str = str + nbytes;
							schd_st = qbman_fq_state_schedstate(&state);
							nbytes = sprintf(str, "\t\t\tFQ State\t\t: %u\t"
								"for RX FQID: %u\n", schd_st, fqid);
						}
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							str = str + nbytes;
							schd_st = qbman_fq_state_schedstate(&state);
							nbytes = sprintf(str, "\t\t\tFQ State\t\t: %u\t"
								"for TX FQID: %u\n", schd_st, fqid);
						}
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_STATE_FRAME_COUNT:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}
			nbytes = sprintf(str, "%s: Rx FQs= %d, Tx FQs= %d\n", name, dev_priv->nb_rx_queues, dev_priv->nb_tx_queues);
			str = str + nbytes;

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr state;
				uint32_t fqid;
				uint32_t frame_cnt;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							frame_cnt = qbman_fq_state_frame_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of frames\t\t: %u\t"
								"for RX FQID: %u\n", frame_cnt, fqid);
							str = str + nbytes;
						}
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							frame_cnt = qbman_fq_state_frame_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of frames\t\t: %u\t"
								"for TX FQID: %u\n", frame_cnt, fqid);
							str = str + nbytes;
						}
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_STATE_BYTE_COUNT:
		{
			struct dpaa2_dev_priv *dev_priv;
			int i = 0;
			int nbytes;

			dev_priv = get_ethdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			nbytes = sprintf(str, "%s: Rx FQs= %d, Tx FQs= %d\n", name, dev_priv->nb_rx_queues, dev_priv->nb_tx_queues);
			str = str + nbytes;

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s;
				struct qbman_attr state;
				uint32_t fqid;
				uint32_t byte_cnt;
				struct dpaa2_queue *eth_vq;

				if (!debug_dpio) {
					printf("Error: DEBUG DPIO NOT FOUND!\n");
					return;
				}

				s = debug_dpio->sw_portal;

				for (i = 0; i < dev_priv->nb_rx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							byte_cnt = qbman_fq_state_byte_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of bytes\t\t: %u\t"
								"for RX FQID: %u\n", byte_cnt, fqid);
							str = str + nbytes;
						}
					}
				}

				for (i = 0; i < dev_priv->nb_tx_queues; i++) {
					eth_vq = (struct dpaa2_queue *)(dev_priv->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							byte_cnt = qbman_fq_state_byte_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of bytes\t\t: %u\t"
								"for TX FQID: %u\n", byte_cnt, fqid);
							str = str + nbytes;
						}
					}
				}
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_BP_INFO_HAS_FREE_BUFS:
	case DPAA2_DEBUG_QBMAN_BP_INFO_IS_DEPLETED:
		{
			printf("Not implemented\n");
			break;
		}
	case DPAA2_DEBUG_QBMAN_BP_INFO_NUM_FREE_BUFS:
		{
			int ret = 0;
			struct dpaa2_dpbp_dev *dpbp_dev = NULL;

			dpbp_dev = dpaa2_get_dpbp_dev_from_name(name);
			if (!dpbp_dev) {
				printf("Either invalid DPBP or not enabled\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				uint32_t num_buf;

				ret = dpbp_get_num_free_bufs(&dpbp_dev->dpbp, CMD_PRI_LOW,
					     dpbp_dev->token, &num_buf);
				if (ret) {
					printf("Unable to obtain free buf count (err=%d)",
							ret);
					return;
				}
				sprintf(str, "Number of free QBMAN buffers for"
						" %s\t\t\t\t\t\t: %u\n\n\n", name, num_buf);
			} else {
				printf("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPSECI_ATTRIBUTES:
		{
			struct dpaa2_sec_dev_private *dev_priv;
			struct dpseci_sec_attr sec_attr;
			struct fsl_mc_io *dpseci_dev;

			dev_priv = get_dpaa2_secdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpseci_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpseci_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpseci_get_sec_attr(dpseci_dev, CMD_PRI_LOW, dev_priv->token, &sec_attr);
				sprintf(str, "DPseci_Attributes\n"
						"%s:"
						"\t\tDPseci object id	\t\t\t\t: %u\n"
						"\t\t\tDPseci major version \t\t\t\t\t: %u\n"
						"\t\t\tDPseci minor version \t\t\t\t\t: %u\n"
						"\t\t\tSec Era \t\t\t\t\t\t: %u\n"
						"\t\t\tNumber of DECO copies implemented \t\t\t: %u\n"
						"\t\t\tNumber of ZUCA copies implemented \t\t\t: %u\n"
						"\t\t\tNumber of ZUCE copies implemented \t\t\t: %u\n"
						"\t\t\tNumber of SNOW-f8 module copies \t\t\t: %u\n"
						"\t\t\tNumber of SNOW-f9 module copies	\t\t\t: %u\n"
						"\t\t\tNumber of CRC module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of Public key module copies \t\t\t: %u\n"
						"\t\t\tNumber of Kasumi module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of Random Number Generator copies \t\t: %u\n"
						"\t\t\tNumber of MDHA (Hashing Module) copies \t\t\t: %u\n"
						"\t\t\tNumber of ARC4 module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of DES module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of AES module copies \t\t\t\t: %u\n\n\n",
						name,
						sec_attr.ip_id, sec_attr.major_rev, sec_attr.minor_rev,
						sec_attr.era, sec_attr.deco_num, sec_attr.zuc_auth_acc_num,
						sec_attr.zuc_enc_acc_num, sec_attr.snow_f8_acc_num,
						sec_attr.snow_f9_acc_num, sec_attr.crc_acc_num, sec_attr.pk_acc_num,
						sec_attr.kasumi_acc_num, sec_attr.rng_acc_num,
						sec_attr.md_acc_num, sec_attr.arc4_acc_num,
						sec_attr.des_acc_num, sec_attr.aes_acc_num);
			} else {
				printf("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPSECI_COUNTERS:
		{
			struct dpaa2_sec_dev_private *dev_priv;
			struct dpseci_sec_counters sec_cnt;
			struct fsl_mc_io *dpseci_dev;
			int ret;

			dev_priv = get_dpaa2_secdev_priv(name);

			if (!dev_priv) {
				printf("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpseci_dev = (struct fsl_mc_io *)dev_priv->hw;
			if (!dpseci_dev) {
				printf("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			ret = dpseci_get_sec_counters(dpseci_dev, CMD_PRI_LOW, dev_priv->token, &sec_cnt);
			if (ret) {
				printf("Error while getting counters. Error Code = %d\n", ret);
				return;
			}
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				sprintf(str, "DPSECI_COUNTERS\n"
					"%s:"
					"\t\tNumber of Requests Dequeued \t\t\t\t: %lu\n"
					"\t\t\tNumber of Outbound Encrypt Requests \t\t\t: %lu\n"
					"\t\t\tNumber of Inbound Decrypt Requests \t\t\t: %lu\n"
					"\t\t\tNumber of Outbound Bytes Encrypted \t\t\t: %lu\n"
					"\t\t\tNumber of Outbound Bytes Protected \t\t\t: %lu\n"
					"\t\t\tNumber of Inbound Bytes Decrypted \t\t\t: %lu\n"
					"\t\t\tNumber of Inbound Bytes Validated \t\t\t: %lu\n\n\n",
					name,
					sec_cnt.dequeued_requests,
					sec_cnt.ob_enc_requests,
					sec_cnt.ib_dec_requests,
					sec_cnt.ob_enc_bytes,
					sec_cnt.ob_prot_bytes,
					sec_cnt.ib_dec_bytes,
					sec_cnt.ib_valid_bytes);
			} else {
				printf("Command not supported\n");
				return;
			}

			break;
		}
#if 0
	case DPAA2_DEBUG_PER_SA_STATS:
		{
			/* TODO*/
			printf("Command not supported\n");
			return;
		}
#endif

	}

	/* Print debug data on console */
	str = pr_buf;
	if (str)
	printf("%s\n", str);
}

static void *open_socket(void *arg  __attribute__((__unused__)))
{
	int udp_socket;
	char buffer[BUFLEN];
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_size;
	fd_set readset;

	void *msg;
	char *port;
	uint16_t port_no = DEFAULT_PLAT_DEBUG_PORT;

	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

	if (udp_socket == -1) {
		printf("Platform Debug Server Socket creation FAILED");
		return NULL;
	}

	memset((char *)&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	port = getenv("PLAT_DEBUG_PORT");

	if (port)
		port_no = atoi(port);

	if (port_no < 1024) {
		printf("ERROR: Cannot use priviledged ports,"
				"Please use port number greater than 1023\n");
		goto close_ret;
	}

	server_addr.sin_port = htons(port_no);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((bind(udp_socket, (struct sockaddr *)&server_addr,
		  sizeof(server_addr))) == -1) {
		printf("Platform Debug Server Socket bind FAILED");
		goto close_ret;
	}

	client_addr_size = sizeof(client_addr);

	debug_dpio = dpaa2_get_qbman_swp();

	while (1) {
		/*wait on udpSocket for any msg */
		FD_ZERO(&readset);
		FD_SET(udp_socket, &readset);
		select(udp_socket + 1, &readset, NULL, NULL, NULL);

		if (recvfrom(udp_socket, buffer, BUFLEN, 0,
			     (struct sockaddr *)&client_addr,
					&client_addr_size) == -1) {
			printf("Platform Debug Server recvfrom FAILED");
			return NULL;
		}

		/*event_handler will be called if udpSocket is active*/
		msg = (void *)&buffer;
		event_handler(msg);
	}
close_ret:
	close(udp_socket);
	return NULL;
}

int dpaa2_platform_debug_init(void)
{
	char *plat_debug_thd = NULL;
	int thd_created = 0;
	pthread_attr_t attr;
	pthread_t thread;
	rte_cpuset_t thd_mask;

	plat_debug_thd = getenv("PLAT_DEBUG_THREAD");
	if (plat_debug_thd) {
		CPU_ZERO(&thd_mask);
		/*TODO: */
		CPU_SET(0, &thd_mask);

		pthread_attr_init(&attr);
		pthread_attr_setaffinity_np(&attr,
					    sizeof(cpu_set_t), &thd_mask);

		thd_created = pthread_create(&thread, &attr,
				open_socket,
				NULL);

		if (thd_created != 0) {
			printf("Platform Debug Thread creation failed!");
			return -1;
		}
		printf("Platform Debug Thread is Intialized\n");
	} else {
		printf("PLATFORM DEBUG THREAD not initialized\n");
		return -1;
	}
	return 0;
}
