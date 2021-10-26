/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 NXP
 */

#ifndef _PRINT_BUFFER_H_
#define _PRINT_BUFFER_H_

#define RX 0
#define TX 1

#ifndef pr_info
#define pr_info printk
#endif

void print_buf(void *data, uint32_t len, uint32_t width);
void print_eth(const struct sk_buff *skb);
void print_arp(const struct sk_buff *skb);
void print_ip(const struct sk_buff *skb);
void print_skb(const struct sk_buff *skb, int rx_tx);
void print_sg(struct scatterlist *sg);
#endif /* _PRINT_BUFFER_H_ */
