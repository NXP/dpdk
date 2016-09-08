/* Copyright (c) 2011 Freescale Semiconductor, Inc.
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
#ifndef HEADER_USDPAA_COMPAT_LIST_H
#define HEADER_USDPAA_COMPAT_LIST_H

/****************/
/* Linked-lists */
/****************/

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

#define COMPAT_LIST_HEAD(n) \
struct list_head n = { \
	.prev = &n, \
	.next = &n \
}

#define INIT_LIST_HEAD(p) \
do { \
	struct list_head *__p298 = (p); \
	__p298->prev = __p298->next = __p298; \
} while (0)

#undef container_of
#define container_of(ptr, type, member) ({ \
		typeof(((type *)0)->member)(*__mptr) = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); })

#define list_entry(node, type, member) \
		container_of(node, type, member)

#define list_empty(p) \
({ \
	const struct list_head *__p298 = (p); \
	((__p298->next == __p298) && (__p298->prev == __p298)); \
})
#define list_add(p, l) \
do { \
	struct list_head *__p298 = (p); \
	struct list_head *__l298 = (l); \
	__p298->next = __l298->next; \
	__p298->prev = __l298; \
	__l298->next->prev = __p298; \
	__l298->next = __p298; \
} while (0)
#define list_add_tail(p, l) \
do { \
	struct list_head *__p298 = (p); \
	struct list_head *__l298 = (l); \
	__p298->prev = __l298->prev; \
	__p298->next = __l298; \
	__l298->prev->next = __p298; \
	__l298->prev = __p298; \
} while (0)
#define list_for_each(i, l)				\
	for (i = (l)->next; i != (l); i = i->next)
#define list_for_each_safe(i, j, l)			\
	for (i = (l)->next, j = i->next; i != (l);	\
	     i = j, j = i->next)
#define list_for_each_entry(i, l, name) \
	for (i = list_entry((l)->next, typeof(*i), name); &i->name != (l); \
		i = list_entry(i->name.next, typeof(*i), name))
#define list_for_each_entry_safe(i, j, l, name) \
	for (i = list_entry((l)->next, typeof(*i), name), \
		j = list_entry(i->name.next, typeof(*j), name); \
		&i->name != (l); \
		i = j, j = list_entry(j->name.next, typeof(*j), name))
#define list_del(i) \
do { \
	(i)->next->prev = (i)->prev; \
	(i)->prev->next = (i)->next; \
} while (0)

#endif /* HEADER_USDPAA_COMPAT_LIST_H */
