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

#include <usdpaa/usdpaa_netcfg.h>

#include <inttypes.h>
#include <usdpaa/of.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <error.h>
#include <net/if_arp.h>

#include <assert.h>
#include <unistd.h>

#define MAX_BPOOL_PER_PORT	8

struct interface_info {
	char *name;
	struct ether_addr mac_addr;
	struct ether_addr peer_mac;
	int mac_present;
	int fman_enabled_mac_interface;
};

struct netcfg_interface {
	uint8_t numof_netcfg_interface;
	uint8_t numof_fman_enabled_macless;
	struct interface_info interface_info[0/*numof_netcfg_interface*/];
};

/* Structure contains information about all the interfaces given by user
 * on command line.
 * */
struct netcfg_interface *netcfg_interface;

/* This data structure contaings all configurations information
 * related to usages of DPA devices.
 * */
struct usdpaa_netcfg_info *usdpaa_netcfg;
/* fd to open a socket for making ioctl request to disable/enable shared
 *  interfaces */
static int skfd = -1;

const char *fm_interfaces;

static const struct argp_option argp_opts[] = {
	{"fm-interfaces",	'i',	"FILE",	0,	"FMAN interfaces"},
	{}
};

static error_t netcfg_parser(int key, char *arg, struct argp_state *state __attribute__((unused)))
{
	switch (key) {
	case 'i':
		fm_interfaces = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

const struct argp netcfg_argp = {argp_opts, netcfg_parser, 0, 0};

void dump_usdpaa_netcfg(struct usdpaa_netcfg_info *cfg_ptr)
{
	int i;

	printf("..........  USDPAA Configuration  ..........\n\n");

	/* Network interfaces */
	printf("Network interfaces: %d\n", cfg_ptr->num_ethports);
	for (i = 0; i < cfg_ptr->num_ethports; i++) {
		struct fman_if_bpool *bpool;
		struct fm_eth_port_cfg *p_cfg = &cfg_ptr->port_cfg[i];
		struct fman_if *__if = p_cfg->fman_if;
		struct fm_eth_port_fqrange *fqr;

		if (__if->mac_type == fman_mac_less)
			printf("\n+ MAC-less name: %s\n",
			       __if->macless_info.macless_name);
		else if (__if->mac_type == fman_onic)
			printf("\n+ oNIC name: %s\n",
			       __if->onic_info.macless_name);
		else
			printf("\n+ Fman %d, MAC %d (%s);\n",
			       __if->fman_idx, __if->mac_idx,
				(__if->mac_type == fman_mac_1g) ? "1G" :
				(__if->mac_type == fman_offline) ? "OFFLINE" :
				"10G");
		if (__if->mac_type != fman_offline) {
			printf("\tmac_addr: " ETH_MAC_PRINTF_FMT "\n",
			       ETH_MAC_PRINTF_ARGS(&__if->mac_addr));
		}

		if (__if->mac_type != fman_onic) {
			if (__if->mac_type != fman_mac_less) {
				printf("\ttx_channel_id: 0x%02x\n",
				       __if->tx_channel_id);
				if (list_empty(p_cfg->list)) {
					printf("PCD List not found\n");
				} else {
					printf("\tfqid_rx_hash:\n");
					list_for_each_entry(fqr, p_cfg->list, list) {
						printf("\t\t(PCD: start 0x%x, count %d)\n",
						       fqr->start, fqr->count);
					}
				}
				printf("\tfqid_rx_def: 0x%x\n", p_cfg->rx_def);
				printf("\tfqid_rx_err: 0x%x\n", __if->fqid_rx_err);
			} else
				printf("\tfqid_rx_def start: 0x%x, count: %d\n",
				       __if->macless_info.tx_start,
						__if->macless_info.tx_count);
		} else {
			printf("\ttx_channel_id: 0x%02x\n",
			       __if->tx_channel_id);
			if (list_empty(p_cfg->list)) {
				printf("PCD List not found\n");
			} else {
				printf("\tfqid_rx_hash:\n");
					list_for_each_entry(fqr, p_cfg->list, list) {
					printf("\t\t(PCD: start 0x%x, count %d)\n",
					       fqr->start, fqr->count);
				}
			}
			printf("\tfqid_rx_def: 0x%x\n", __if->fqid_rx_def);
			printf("\tonic_rx_start: %#x\n",
			       __if->onic_info.onic_rx_start);
			printf("\tonic_rx_count: %#x\n",
			       __if->onic_info.onic_rx_count);
			printf("\tfqid_rx_err: 0x%x\n", __if->fqid_rx_err);
		}

		if (__if->mac_type != fman_offline) {
			if (!(__if->mac_type == fman_mac_less || __if->mac_type == fman_onic)) {
				printf("\tfqid_tx_err: 0x%x\n",
				       __if->fqid_tx_err);
				printf("\tfqid_tx_confirm: 0x%x\n",
				       __if->fqid_tx_confirm);
			}
			fman_if_for_each_bpool(bpool, __if)
				printf("\tbuffer pool: (bpid=%d, count=%"PRId64
				       " size=%"PRId64", addr=0x%"PRIx64")\n",
				       bpool->bpid, bpool->count, bpool->size,
				       bpool->addr);
		}
	}
}

static inline int get_num_netcfg_interfaces(char *str)
{
	char *pch;
	uint8_t count = 0;

	if (str == NULL)
		return -EINVAL;
	pch = strtok(str, ",");
	while (pch != NULL) {
		count++;
		pch = strtok(NULL, ",");
	}
	return count;
}

static inline int str2mac(const char *macaddr, struct ether_addr *mac)
{
	if (sscanf(macaddr, "[%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx]",
		   &mac->addr_bytes[0], &mac->addr_bytes[1],
		&mac->addr_bytes[2], &mac->addr_bytes[3],
		&mac->addr_bytes[4], &mac->addr_bytes[5]) != 6) {
		error(0, EINVAL, "%s", __func__);
		return -EINVAL;
	}
	return 0;
}

/* Read mac address of MAC-less interface using ioctl */
int get_mac_addr(const char *vname, struct ether_addr *src_mac)
{
	struct ifreq ifr;
	int ret = -1;

	assert(skfd != -1);

	strncpy(ifr.ifr_name, vname, sizeof(ifr.ifr_name) - 1);
	/*retrieve corresponding MAC*/
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) == -1) {
		error(0, errno, "%s(): SIOCGIFINDEX", __func__);
		return ret;
	}
	memcpy(src_mac, &ifr.ifr_hwaddr.sa_data, sizeof(*src_mac));
	ret = 0;

	return ret;
}

/* Set mac address of MAC-less interface using ioctl */
int set_mac_addr(const char *vname, struct ether_addr *mac)
{
	int ret;
	struct ifreq ifr;

	assert(skfd != -1);
	if (!mac || !vname)
		return -EINVAL;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, vname, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(ifr.ifr_hwaddr.sa_data, mac->addr_bytes, sizeof(*mac));
	ret = ioctl(skfd, SIOCSIFHWADDR, &ifr);

	return ret;
}

static inline enum fman_mac_type get_mac_type(const char *str)
{
	enum fman_mac_type p_type;
	/* Expected interface name format "fm1-gb1" or "fm1-10g" or "fm1-of1" */
	p_type = (strncmp(str + 4, "10", 2) == 0) ? fman_mac_10g :
		 (strncmp(str + 4, "of", 2) == 0) ? fman_offline : fman_mac_1g;
	return p_type;
}

static inline void fman_get_mac_info(const char *str, uint8_t *mac_idx)
{
	if (str[8] >= '0' && str[8] <= '9')
		*mac_idx = (str[7] - '0') * 10 + (str[8] - '0');
	else
		*mac_idx = str[7] - '0';
}

/* This function disables/enables shared interface using ioctl */
void usdpaa_netcfg_enable_disable_shared_rx(const struct fman_if *fif,
					    int flag_up)
{
	struct ifreq ifreq;
	int flags;

	assert(skfd != -1);

	if (fif->mac_type == fman_mac_less) {
		strncpy(ifreq.ifr_name, fif->macless_info.macless_name,
			sizeof(ifreq.ifr_name) - 1);
	} else if (fif->mac_type == fman_onic) {
		strncpy(ifreq.ifr_name, fif->onic_info.macless_name,
			sizeof(ifreq.ifr_name) - 1);
	} else
		strncpy(ifreq.ifr_name, fif->shared_mac_info.shared_mac_name,
			sizeof(ifreq.ifr_name));
	if (ioctl(skfd, SIOCGIFFLAGS, &ifreq) == -1) {
		error(0, errno, "%s(): SIOCGIFFLAGS", __func__);
		return;
	}

	flags = ifreq.ifr_flags;
	if (flag_up == 1)
		flags |= IFF_UP;
	else
		flags &= ~IFF_UP;
	ifreq.ifr_flags = flags;
	if (ioctl(skfd, SIOCSIFFLAGS, &ifreq) == -1) {
		error(0, errno, "%s(): SIOCSIFFLAGS", __func__);
		return;
	}
}

static void check_fman_enabled_interfaces(void)
{
	struct fman_if *__if;
	int idx, i;
	char str[10];
	uint8_t num, num1;
	struct interface_info *cli_info;
	struct list_head *fqlist;
	enum fman_mac_type val;

	/* Fill in configuration info for all command-line ports */
	idx = 0;
	list_for_each_entry(__if, fman_if_list, node) {
		struct fm_eth_port_cfg *cfg = &usdpaa_netcfg->port_cfg[idx];
		/* Hook in the fman driver interface */
		cfg->fman_if = __if;

		for (i = 0; i < netcfg_interface->numof_netcfg_interface; i++) {
			cli_info = &netcfg_interface->interface_info[i];
			if (cli_info->mac_present) {
				/* compare if command line macless interface
				 * matches the one in fman list */
			   if ((memcmp(&__if->macless_info.peer_mac,
				       &cli_info->peer_mac, ETHER_ADDR_LEN) == 0) ||
				(memcmp(&__if->onic_info.peer_mac,
				&cli_info->peer_mac, ETHER_ADDR_LEN) == 0)) {
				fqlist = malloc(sizeof(struct list_head));
				if (!fqlist) {
					fprintf(stderr, "%s: No mem fqlist\n",
						__FILE__);
					return;
				}
				cfg->list = fqlist;
				INIT_LIST_HEAD(cfg->list);
				memcpy(&__if->macless_info.src_mac,
				       &cli_info->mac_addr, ETHER_ADDR_LEN);
				memcpy(&__if->mac_addr,
				       &cli_info->mac_addr, ETHER_ADDR_LEN);
				netcfg_interface->numof_fman_enabled_macless++;
				idx++;
				break;
			   } else
				continue;
			}
			strncpy(str, cli_info->name, sizeof(str) - 1);
			str[sizeof(str) - 1] = '\0';
			num = str[2] - '0';
			if (strncmp((str + 4), "mac", 3) == 0) {
				fman_get_mac_info(str, &num1);
				if ((num - 1) != __if->fman_idx ||
				    num1 != __if->mac_idx)
					continue;
			} else { /* for e.g. fm1-gb4 */
				num1 = str[6] - '0' + 1;
				val = get_mac_type(str);
				if (val == fman_mac_10g) {
					if ((num - 1) != __if->fman_idx ||
					    val != __if->mac_type)
						continue;
				} else {
					if ((num - 1) != __if->fman_idx ||
					    num1 != __if->mac_idx ||
						val != __if->mac_type)
						continue;
				}
			}
			cli_info->fman_enabled_mac_interface = 1;
			break;
		}
	}
}

static int parse_cmd_line_args(const char *str)
{
	int8_t	numof_netcfg_interface = 0;
	struct interface_info *cli_info;
	char endptr[100];
	uint32_t i = 0;
	char *pch;
	uint16_t sz;
	int ret = 1;

	if (str == NULL)
		return 0;
	strncpy(endptr, str, sizeof(endptr) - 1);
	/* in case sizeof str is greater than sizeof endptr */
	endptr[sizeof(endptr) - 1] = '\0';
	numof_netcfg_interface = get_num_netcfg_interfaces(endptr);
	if (numof_netcfg_interface < 0) {
		error(0, errno, "%s", __func__);
		return -EINVAL;
	} else if (numof_netcfg_interface == 0)
		return 0;
	sz = sizeof(struct netcfg_interface) +
		sizeof(struct interface_info) * numof_netcfg_interface;

	netcfg_interface = malloc(sz);
	if (!netcfg_interface) {
		error(0, errno, "%s", __func__);
		return -ENOMEM;
	}
	memset(netcfg_interface, 0, sz);
	netcfg_interface->numof_netcfg_interface = numof_netcfg_interface;
	pch = strtok((char *)(uint64_t)str, ",:");
	while (pch != NULL) {
		if (strncmp(pch, "[", 1) != 0) {
			cli_info = &netcfg_interface->interface_info[i];
			cli_info->name = pch;
			i++;
		} else {
			cli_info = &(netcfg_interface->interface_info[i - 1]);
			cli_info->mac_present = 1;
			ret = get_mac_addr(cli_info->name, &cli_info->peer_mac);
			if (ret != 0)
				goto out;
			ret = str2mac(pch, &cli_info->mac_addr);
			if (ret != 0) {
				error(0, errno, "%s(): Failed to parse mac: %s",
				      __func__, pch);
				goto out;
			}
		}
		pch = strtok(NULL, ",:");
	}
	ret = numof_netcfg_interface;
	return ret;
out:
	free(netcfg_interface);
	return ret;
}

/* Check if FMC extracted configuration matches the one
 * given by user on command line */
static inline int netcfg_interface_match(uint8_t fman,
					 enum fman_mac_type p_type, uint8_t p_num)
{
	char str[10];
	uint8_t num, num1;
	struct interface_info *cli_info;
	enum fman_mac_type val;
	int i;

	for (i = 0; i < netcfg_interface->numof_netcfg_interface;
		i++) {
		cli_info = &netcfg_interface->interface_info[i];
		if (cli_info->fman_enabled_mac_interface == 1) {
			strncpy(str, cli_info->name, sizeof(str) - 1);
			num = str[2] - '0';
			if (strncmp((str + 4), "mac", 3) == 0) {
				fman_get_mac_info(str, &num1);
				if ((num - 1) != fman || num1 != p_num)
					continue;
			} else {/* fmx-gby y starts from 0,
				hardware mac index starts from 1*/
				num1 = str[6] - '0' + 1;
				val = get_mac_type(str);
				if (val == fman_mac_10g) {
					if ((num - 1) != fman ||
					    val != p_type)
						continue;
				} else {
					if ((num - 1) != fman ||
					    num1 != p_num ||
						val != p_type)
						continue;
				}
			}
			return 1;
		}
	}

	return 0;
}

struct usdpaa_netcfg_info *usdpaa_netcfg_acquire(void)
{
	struct fman_if *__if;
	int _errno, idx;
	uint8_t num_ports = 0;
	uint8_t num_cfg_ports = 0;
	size_t size;
	uint8_t use_all_interfaces = 0;

	/* Extract dpa configuration from fman driver and FMC configuration
	   for command-line interfaces */

	if (skfd == -1) {
		/* Open a basic socket to enable/disable shared
		 * interfaces */
		skfd = socket(AF_PACKET, SOCK_RAW, 0);
		if (unlikely(skfd < 0)) {
			error(0, errno, "%s(): open(SOCK_RAW)", __func__);
			return NULL;
		}
	}

	/* parse command line interfaces */
	_errno = parse_cmd_line_args(fm_interfaces);
	if (_errno == 0)
		use_all_interfaces = 1;
	else if (unlikely(_errno < 0)) {
		error(0, -_errno, "%s", __func__);
		return NULL;
	}

	/* Initialise the Fman driver */
	_errno = fman_init();
	if (_errno) {
		fprintf(stderr, "%s:%hu:%s(): fman driver init failed "
			"(ERRNO = %d)\n", __FILE__, __LINE__, __func__, _errno);
		return NULL;
	}

	/* Number of MAC ports */
	list_for_each_entry(__if, fman_if_list, node)
		num_ports++;

	/* Allocate space for all enabled mac ports */
	size = sizeof(*usdpaa_netcfg) +
		(num_ports * sizeof(struct fm_eth_port_cfg));
	usdpaa_netcfg = calloc(size, 1);
	if (unlikely(usdpaa_netcfg == NULL)) {
		fprintf(stderr, "%s:%hu:%s(): calloc failed\n",
			__FILE__, __LINE__, __func__);
		goto error;
	}

	usdpaa_netcfg->num_ethports = num_ports;

	/* mark FMAN enabled interfaces out of all command-line interfaces */
	if (use_all_interfaces == 0)
		check_fman_enabled_interfaces();
	/* Fill in configuration info for all FMAN enabled command-line ports */
	idx = 0;
	if (use_all_interfaces == 0)
		idx += netcfg_interface->numof_fman_enabled_macless;
	list_for_each_entry(__if, fman_if_list, node) {
		bool is_offline;
		struct fm_eth_port_cfg *cfg = &usdpaa_netcfg->port_cfg[idx];
		/* Hook in the fman driver interface */
		cfg->fman_if = __if;
		/* Extract FMC configuration only for
		   command-line interfaces */
		if (__if->mac_type == fman_onic ||
		   (__if->mac_type == fman_offline)) {
			cfg->rx_def = __if->fqid_rx_def;
			continue;
		}

		is_offline = __if->mac_type == fman_offline ? true : false;
		if (use_all_interfaces || netcfg_interface_match(
		   __if->fman_idx, __if->mac_type, __if->mac_idx)) {
			cfg->rx_def = __if->fqid_rx_def;
			num_cfg_ports++;
			idx++;
		}
	}
	if (!use_all_interfaces) {
		if (netcfg_interface->numof_fman_enabled_macless)
			num_cfg_ports +=
				netcfg_interface->numof_fman_enabled_macless;
	}
	if (!num_cfg_ports) {
		fprintf(stderr, "%s:%hu:%s(): fmc_netcfg_get_info()\n",
			__FILE__, __LINE__, __func__);
		goto error;
	} else if (num_ports != num_cfg_ports)
		usdpaa_netcfg->num_ethports = num_cfg_ports;

	return usdpaa_netcfg;

error:
	return NULL;
}

void usdpaa_netcfg_release(struct usdpaa_netcfg_info *cfg_ptr)
{
	free(cfg_ptr);
	/* Close socket for shared interfaces */
	if (skfd >= 0) {
		close(skfd);
		skfd = -1;
	}
}
