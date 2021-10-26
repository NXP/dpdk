/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>

#include "print_buffer.h"

/*
 * Print data buffer in hex and ascii form to the terminal.
 *
 * parameters:
 *    data: pointer to data buffer
 *    len: data length
 *    width: data value width.  May be 1, 2, or 4.
 */
void print_buf(void *data, uint32_t len, uint32_t width)
{
	uint32_t i;
	uint32_t *uip = (uint32_t *)data;
	uint16_t *usp = (uint16_t *)data;
	uint8_t *ucp = (uint8_t *)data;

	pr_info("data = 0x%p, len = %d\n", data, len);
	for (i = 0; i < len/width; i++) {
		if ((i % (16/width)) == 0)
			pr_info("0x%04x:", i * width);

		if (width == 4)
			pr_info(" %08x", uip[i]);
		else if (width == 2)
			pr_info(" %04x", usp[i]);
		else
			pr_info(" %02x", ucp[i]);

		if (((i+1) % (16/width)) == 0)
			pr_info("\n");
	}
	pr_info("\n");
}

void print_eth(const struct sk_buff *skb)
{
	struct ethhdr *eth;
	int i;

	eth = eth_hdr(skb);
	if (eth) {
		pr_info("Ethernet header(0x%p):\n", eth);
		pr_info("-------------------------------------\n");
		pr_info("h_dest         = ");
		for (i = 0; i < ETH_ALEN; i++)
			pr_info("%x:", eth->h_dest[i]);
		pr_info("\n");

		pr_info("h_source       = ");
		for (i = 0; i < ETH_ALEN; i++)
			pr_info("%x:", eth->h_source[i]);
		pr_info("\n");
		pr_info("h_proto        = 0x%x\n", eth->h_proto);
	}
	pr_info("\n");
}

void print_arp(const struct sk_buff *skb)
{
	struct arphdr *arph = arp_hdr(skb);
	unsigned char *src_mac  = (unsigned char *)arph + 8;
	unsigned char *src_ip  = src_mac + 6;
	unsigned char *dst_mac  = src_ip + 4;
	unsigned char *dst_ip  = dst_mac + 6;

	if (arph) {
		pr_info("ARP header (0x%p):\n", arph);
		pr_info("-------------------------------------\n");
		pr_info("ar_hrd         = 0x%x\n", arph->ar_hrd);
		pr_info("ar_pro         = 0x%x\n", arph->ar_pro);
		pr_info("ar_hln         = 0x%x\n", arph->ar_hln);
		pr_info("ar_pln         = 0x%x\n", arph->ar_pln);
		pr_info("ar_op          = 0x%x\n", arph->ar_op);
		pr_info("src mac        = %02x:%02x:%02x:%02x:%02x:%02x\n",
				*src_mac, *(src_mac+1), *(src_mac+2),
				*(src_mac+3), *(src_mac+4), *(src_mac+5));
		pr_info("src ip          = %d:%d:%d:%d\n", *src_ip,
				*(src_ip+1), *(src_ip+2), *(src_ip+3));
		pr_info("dst mac         = %02x:%02x:%02x:%02x:%02x:%02x\n",
				*dst_mac, *(dst_mac+1), *(dst_mac+2),
				*(dst_mac+3), *(dst_mac+4), *(dst_mac+5));
		pr_info("dst ip          = %d:%d:%d:%d\n", *dst_ip,
				*(dst_ip+1), *(dst_ip+2), *(dst_ip+3));
	}
	pr_info("\n");
}

void print_ip(const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;

	iph = ip_hdr(skb);
	if (iph) {
		pr_info("IP header (0x%p):\n", iph);
		pr_info("-------------------------------------\n");
		pr_info("version        = 0x%x\n", iph->version);
		pr_info("ihl            = 0x%x\n", iph->ihl * 4);
		pr_info("tos            = 0x%x\n", iph->tos);
		pr_info("tot_len        = 0x%x(%d)\n", iph->tot_len,
							iph->tot_len);
		pr_info("id             = 0x%x\n", iph->id);
		pr_info("frag_off       = 0x%x\n", iph->frag_off);
		pr_info("ttl            = 0x%x\n", iph->ttl);
		pr_info("protocol       = 0x%x\n", iph->protocol);
		pr_info("check          = 0x%x\n", iph->check);
		pr_info("saddr          = 0x%x\n", iph->saddr);
		pr_info("daddr          = 0x%x\n", iph->daddr);
	}

	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (udph) {
			pr_info("\nUDP header (0x%p):\n", udph);
			pr_info("-------------------------------------\n");
			pr_info("source         = 0x%x\n", udph->source);
			pr_info("dest           = 0x%x\n", udph->dest);
			pr_info("len            = 0x%x(%d)\n", udph->len,
								udph->len);
			pr_info("check          = 0x%x\n", udph->check);
		}
	}
	pr_info("\n");
}

void print_skb(const struct sk_buff *skb, int rx_tx)
{
	pr_info("%s: %p\n", (rx_tx == RX) ? "RX" : "TX", skb);
	pr_info("=====================================\n");
	pr_info("dev->name      = %s\n", skb->dev->name);
	pr_info("head           = 0x%p\n", skb->head);
	pr_info("data           = 0x%p\n", skb->data);
	pr_info("tail           = 0x%x\n", skb->tail);
	pr_info("end            = 0x%x\n", skb->end);
	pr_info("len            = 0x%x(%d)\n", skb->len, skb->len);
	pr_info("data_len       = 0x%x(%d)\n", skb->data_len, skb->data_len);
	pr_info("mac_len        = 0x%x(%d)\n", skb->mac_len, skb->mac_len);
	pr_info("hdr_len        = 0x%x(%d)\n", skb->hdr_len, skb->hdr_len);
	pr_info("truesize       = 0x%x(%d)\n", skb->truesize, skb->truesize);
	pr_info("protocol       = 0x%x\n", skb->protocol);
	pr_info("mac_header     = 0x%x\n", skb->mac_header);
	pr_info("network_header = 0x%x\n", skb->network_header);
	pr_info("transport_hdr  = 0x%x\n", skb->transport_header);
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
	pr_info("vlan_proto     = 0x%x\n", skb->vlan_proto);
#endif
	pr_info("vlan_tci       = 0x%x\n", skb->vlan_tci);
	pr_info("nr_frag        = 0x%x\n", skb_shinfo(skb)->nr_frags);
	pr_info("\n");

	if (skb->network_header) {
		switch (skb->protocol) {
		case ETH_P_ARP:
			print_arp(skb);
			break;
		case ETH_P_IP:
			print_ip(skb);
			break;
		default:
			break;
		}
	}
	print_buf(skb->data, skb_headlen(skb), 4);
}

void print_sg(struct scatterlist *sg)
{
	pr_info("sg [0x%p]:\n", sg);
	pr_info("virt addr = 0x%p\n", sg_virt(sg));
	pr_info("dma  addr = 0x%llx\n", sg->dma_address);
	pr_info("dmalength = 0x%x\n", sg->dma_length);
	pr_info("length    = 0x%x\n", sg->length);
	pr_info("page      = 0x%p\n", sg_page(sg));
	pr_info("offset    = 0x%x\n", sg->offset);
	pr_info("page_link = 0x%lx\n", sg->page_link);
}
