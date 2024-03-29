/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2015-2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016-2023 NXP
 *
 */
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>

#define ECPRI_UDP_DST_PORT_H 0x12
#define ECPRI_UDP_DST_PORT_L 0x34

static unsigned char *sp_orig_blob;
static unsigned long sp_orig_blob_size;

static unsigned char sp_default_blob[] = {
	0x43, 0x42, 0x50, 0x53, 0x00, 0x00, 0x01, 0x00,
	0x02, 0x00, 0x03, 0x00, 0x10, 0x06, 0x00, 0x00,
	0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x4e, 0x65, 0x74, 0x50, 0x44, 0x4c, 0x20, 0x63,
	0x75, 0x73, 0x74, 0x6f, 0x6d, 0x20, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x00, 0x00,
	0x88, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x80, 0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xb7, 0x9e, 0x02, 0x1f, 0xae, 0xfe,
	0x00, 0x78, 0x00, 0x2d, 0x33, 0x21, 0x32, 0x30,
	0x00, 0x4f, 0x00, 0x81, 0x00, 0x44, 0x18, 0x00,
	0x00, 0x2d, 0x32, 0x31, 0x33, 0x20, 0x00, 0x4a,
	0x00, 0x80, 0x00, 0x02, 0x00, 0x00, 0x87, 0x8f,
	0x28, 0x73, 0x00, 0x00, 0x8f, 0x9f, 0x28, 0x41,
	0x03, 0xe7, 0x00, 0x00, 0x9f, 0xbf, 0x2b, 0x7d,
	0x00, 0x00, 0x87, 0x8e, 0x02, 0x1f, 0x00, 0x03,
	0x02, 0x9f, 0x00, 0x02, 0x02, 0x9f, 0x00, 0x01,
	0x02, 0x9f, 0x00, 0x00, 0x00, 0x30, 0x00, 0x5e,
	0x00, 0x66, 0x00, 0x6f, 0x00, 0x78, 0x00, 0x00,
	0x87, 0x8e, 0x02, 0x1f, 0x00, 0x07, 0x02, 0x9f,
	0x00, 0x06, 0x02, 0x9f, 0x00, 0x05, 0x02, 0x9f,
	0x00, 0x04, 0x00, 0x30, 0x00, 0x82, 0x00, 0x91,
	0x00, 0x9b, 0x00, 0xa5, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x00, 0xb0, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x08, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x00, 0xb0, 0x03, 0xe6, 0x33, 0x21,
	0x00, 0x55, 0x00, 0x08, 0x28, 0x65, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x00, 0xb0, 0x03, 0xe5,
	0x33, 0x21, 0x00, 0x55, 0x00, 0x08, 0x28, 0x65,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x00, 0xb0,
	0x03, 0xe5, 0x03, 0xe6, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x0c, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x00, 0xb0, 0x03, 0xe4, 0x00, 0x00,
	0xb7, 0xdf, 0x28, 0x49, 0x00, 0x00, 0xbf, 0x9f,
	0x28, 0x59, 0x33, 0x21, 0x00, 0x55, 0x00, 0x10,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x00, 0xb0, 0x03, 0xe6, 0x03, 0xe4, 0x33, 0x21,
	0x00, 0x55, 0x00, 0x06, 0x28, 0x65, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x00, 0xb0, 0x03, 0xe5,
	0x03, 0xe4, 0x33, 0x21, 0x00, 0x55, 0x00, 0x07,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x00, 0xb0, 0x03, 0xe4, 0x03, 0xe5, 0x03, 0xe6,
	0x33, 0x21, 0x00, 0x55, 0x00, 0x08, 0x28, 0x65,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x00, 0xb0,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x07, 0xff,
	0x00, 0x00, 0x8f, 0x9e, 0x02, 0x1f, 0xae, 0xfe,
	0x00, 0x78, 0x00, 0xc1, 0x33, 0x21, 0x32, 0x60,
	0x00, 0x4f, 0x00, 0x81, 0x00, 0x44, 0x18, 0x00,
	0x00, 0xc1, 0x32, 0x61, 0x33, 0x20, 0x00, 0x4a,
	0x00, 0x80, 0x00, 0x02, 0x00, 0x00, 0x87, 0x8f,
	0x28, 0x73, 0x00, 0x00, 0x8f, 0x9f, 0x28, 0x41,
	0x03, 0xe7, 0x00, 0x00, 0x9f, 0xbf, 0x2b, 0x7d,
	0x00, 0x00, 0x87, 0x8e, 0x02, 0x1f, 0x00, 0x03,
	0x02, 0x9f, 0x00, 0x02, 0x02, 0x9f, 0x00, 0x01,
	0x02, 0x9f, 0x00, 0x00, 0x00, 0x30, 0x00, 0xf2,
	0x00, 0xfa, 0x01, 0x03, 0x01, 0x0c, 0x00, 0x00,
	0x87, 0x8e, 0x02, 0x1f, 0x00, 0x07, 0x02, 0x9f,
	0x00, 0x06, 0x02, 0x9f, 0x00, 0x05, 0x02, 0x9f,
	0x00, 0x04, 0x00, 0x30, 0x01, 0x16, 0x01, 0x25,
	0x01, 0x2f, 0x01, 0x39, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x01, 0x44, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x08, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x01, 0x44, 0x03, 0xe6, 0x33, 0x21,
	0x00, 0x55, 0x00, 0x08, 0x28, 0x65, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x01, 0x44, 0x03, 0xe5,
	0x33, 0x21, 0x00, 0x55, 0x00, 0x08, 0x28, 0x65,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x01, 0x44,
	0x03, 0xe5, 0x03, 0xe6, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x0c, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x01, 0x44, 0x03, 0xe4, 0x00, 0x00,
	0xb7, 0xdf, 0x28, 0x49, 0x00, 0x00, 0xbf, 0x9f,
	0x28, 0x59, 0x33, 0x21, 0x00, 0x55, 0x00, 0x10,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x01, 0x44, 0x03, 0xe6, 0x03, 0xe4, 0x33, 0x21,
	0x00, 0x55, 0x00, 0x06, 0x28, 0x65, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x01, 0x44, 0x03, 0xe5,
	0x03, 0xe4, 0x33, 0x21, 0x00, 0x55, 0x00, 0x07,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x01, 0x44, 0x03, 0xe4, 0x03, 0xe5, 0x03, 0xe6,
	0x33, 0x21, 0x00, 0x55, 0x00, 0x08, 0x28, 0x65,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x01, 0x44,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x07, 0xff,
	0x00, 0x00, 0x8f, 0x9e, 0x02, 0x1f,
	/** User defined UDP dst port followed by eCPRI,
	 * default is ECPRI_UDP_DST_PORT_H/L.
	 */
	ECPRI_UDP_DST_PORT_H, ECPRI_UDP_DST_PORT_L,
	0x00, 0x78, 0x01, 0x5f, 0x00, 0x00, 0x8f, 0x9e,
	0x02, 0x1f, 0x12, 0xb7, 0x00, 0x78, 0x01, 0x5b,
	0x33, 0x21, 0x32, 0xe0, 0x00, 0x4f, 0x00, 0x81,
	0x00, 0x46, 0x18, 0x00, 0x01, 0x5d, 0x08, 0x01,
	0x00, 0x02, 0x18, 0x00, 0x01, 0x61, 0x08, 0x01,
	0x00, 0x01, 0x33, 0x21, 0x32, 0xe0, 0x00, 0x4f,
	0x00, 0x81, 0x00, 0x02, 0x30, 0x10, 0x02, 0x1f,
	0x00, 0x01, 0x00, 0x78, 0x01, 0x7a, 0x03, 0xe5,
	0x00, 0x00, 0x83, 0x8f, 0x28, 0x77, 0x00, 0x00,
	0x9f, 0xaf, 0x2a, 0x7d, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x0c, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x02, 0x03, 0x00, 0x00, 0x87, 0x8f,
	0x28, 0x73, 0x00, 0x00, 0x8f, 0x9f, 0x28, 0x41,
	0x03, 0xe7, 0x00, 0x00, 0x93, 0x8f, 0x28, 0x77,
	0x00, 0x00, 0x9f, 0xaf, 0x2a, 0x7d, 0x00, 0x00,
	0x87, 0x8e, 0x02, 0x1f, 0x00, 0x03, 0x02, 0x9f,
	0x00, 0x02, 0x02, 0x9f, 0x00, 0x01, 0x02, 0x9f,
	0x00, 0x00, 0x00, 0x30, 0x01, 0xa9, 0x01, 0xb1,
	0x01, 0xba, 0x01, 0xc3, 0x00, 0x00, 0x87, 0x8e,
	0x02, 0x1f, 0x00, 0x07, 0x02, 0x9f, 0x00, 0x06,
	0x02, 0x9f, 0x00, 0x05, 0x02, 0x9f, 0x00, 0x04,
	0x00, 0x30, 0x01, 0xcd, 0x01, 0xe2, 0x01, 0xec,
	0x01, 0xf6, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x01, 0x33, 0x21, 0x00, 0x55, 0x00, 0x08,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x01, 0x03, 0xe6, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x08, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x02, 0x01, 0x03, 0xe5, 0x33, 0x21,
	0x00, 0x55, 0x00, 0x08, 0x28, 0x65, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x02, 0x01, 0x03, 0xe5,
	0x03, 0xe6, 0x33, 0x21, 0x00, 0x55, 0x00, 0x0c,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x01, 0x03, 0xe4, 0x00, 0x00, 0xa3, 0x8f,
	0x28, 0x49, 0x00, 0x00, 0xaf, 0xaf, 0x28, 0x4b,
	0x00, 0x00, 0xb7, 0x9f, 0x28, 0x51, 0x00, 0x00,
	0xbf, 0x9f, 0x28, 0x59, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x10, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x02, 0x01, 0x03, 0xe6, 0x03, 0xe4,
	0x33, 0x21, 0x00, 0x55, 0x00, 0x06, 0x28, 0x65,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x02, 0x01,
	0x03, 0xe5, 0x03, 0xe4, 0x33, 0x21, 0x00, 0x55,
	0x00, 0x07, 0x28, 0x65, 0x18, 0x00, 0x07, 0xfe,
	0x18, 0x00, 0x02, 0x01, 0x03, 0xe4, 0x03, 0xe5,
	0x03, 0xe6, 0x33, 0x21, 0x00, 0x55, 0x00, 0x08,
	0x28, 0x65, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x01, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x07, 0xff, 0x00, 0x00, 0x9b, 0xaf, 0x2a, 0x7b,
	0x00, 0x00, 0xa3, 0x8f, 0x28, 0x49, 0x00, 0x00,
	0xa7, 0x8f, 0x28, 0x4d, 0x00, 0x00, 0xab, 0x8f,
	0x28, 0x51, 0x00, 0x00, 0xaf, 0x8f, 0x28, 0x53,
	0x00, 0x00, 0xb3, 0x8f, 0x28, 0x55, 0x00, 0x00,
	0xb7, 0x8f, 0x28, 0x59, 0x00, 0x00, 0xbb, 0x8f,
	0x28, 0x5b, 0x00, 0x00, 0xbf, 0x8f, 0x28, 0x61,
	0x07, 0x01, 0x00, 0x00, 0xbf, 0x8f, 0x06, 0x00,
	0x28, 0x63, 0x07, 0x02, 0x00, 0x00, 0xbf, 0x8f,
	0x06, 0x00, 0x28, 0x67, 0x07, 0x03, 0x00, 0x00,
	0xbf, 0x8f, 0x06, 0x00, 0x28, 0x73, 0x07, 0x04,
	0x00, 0x00, 0xbf, 0x8f, 0x06, 0x00, 0x28, 0x75,
	0x07, 0x06, 0x00, 0x00, 0xbf, 0x9f, 0x06, 0x00,
	0x29, 0x7f, 0x07, 0x06, 0x00, 0x00, 0xbf, 0x9e,
	0x06, 0x00, 0x02, 0x1f, 0x86, 0xdd, 0x02, 0x9f,
	0x08, 0x00, 0x02, 0x9f, 0x81, 0x00, 0x00, 0x18,
	0x02, 0x4b, 0x02, 0x9d, 0x02, 0xb7, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x02, 0xd1, 0x03, 0xe0,
	0x07, 0x07, 0x00, 0x00, 0xbf, 0x8f, 0x06, 0x00,
	0x28, 0x41, 0x07, 0x08, 0x00, 0x00, 0xbf, 0x8f,
	0x06, 0x00, 0x28, 0x43, 0x07, 0x0a, 0x00, 0x00,
	0xbf, 0x9e, 0x06, 0x00, 0x02, 0x1f, 0x86, 0xdd,
	0x02, 0x9f, 0x08, 0x00, 0x00, 0x0c, 0x02, 0x65,
	0x02, 0x7f, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x99, 0x03, 0xe1, 0x07, 0x14, 0x00, 0x00,
	0xbf, 0x8e, 0x06, 0x00, 0x02, 0x1f, 0x00, 0x06,
	0x02, 0x9f, 0x00, 0x11, 0x00, 0x0c, 0x02, 0x75,
	0x02, 0x78, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x7b, 0x03, 0xe3, 0x18, 0x00, 0x02, 0x7b,
	0x03, 0xe4, 0x18, 0x00, 0x02, 0x7b, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x02, 0x99, 0x03, 0xe2,
	0x07, 0x11, 0x00, 0x00, 0xbf, 0x8e, 0x06, 0x00,
	0x02, 0x1f, 0x00, 0x06, 0x02, 0x9f, 0x00, 0x11,
	0x00, 0x0c, 0x02, 0x8f, 0x02, 0x92, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x02, 0x95, 0x03, 0xe3,
	0x18, 0x00, 0x02, 0x95, 0x03, 0xe4, 0x18, 0x00,
	0x02, 0x95, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0x99, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0xd1, 0x03, 0xe1, 0x07, 0x10, 0x00, 0x00,
	0xbf, 0x8e, 0x06, 0x00, 0x02, 0x1f, 0x00, 0x06,
	0x02, 0x9f, 0x00, 0x11, 0x00, 0x0c, 0x02, 0xad,
	0x02, 0xb0, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0xb3, 0x03, 0xe3, 0x18, 0x00, 0x02, 0xb3,
	0x03, 0xe4, 0x18, 0x00, 0x02, 0xb3, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x02, 0xd1, 0x03, 0xe2,
	0x07, 0x0d, 0x00, 0x00, 0xbf, 0x8e, 0x06, 0x00,
	0x02, 0x1f, 0x00, 0x06, 0x02, 0x9f, 0x00, 0x11,
	0x00, 0x0c, 0x02, 0xc7, 0x02, 0xca, 0x18, 0x00,
	0x07, 0xfe, 0x18, 0x00, 0x02, 0xcd, 0x03, 0xe3,
	0x18, 0x00, 0x02, 0xcd, 0x03, 0xe4, 0x18, 0x00,
	0x02, 0xcd, 0x18, 0x00, 0x07, 0xfe, 0x18, 0x00,
	0x02, 0xd1, 0x18, 0x00, 0x07, 0xfe, 0x30, 0x01,
	0x33, 0x20, 0x00, 0x4a, 0x00, 0x80, 0x00, 0x02,
	0x18, 0x00, 0x07, 0xfe, 0x18, 0x00, 0x07, 0xff,
	0x50, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x65, 0x74, 0x68, 0x65, 0x63, 0x70, 0x72, 0x69,
	0x80, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x76, 0x6c, 0x65, 0x63, 0x70, 0x72, 0x69, 0x00,
	0x80, 0x00, 0x68, 0x01, 0x03, 0x00, 0x00, 0x00,
	0x75, 0x64, 0x70, 0x61, 0x66, 0x74, 0x65, 0x72,
	0x80, 0x00, 0x90, 0x02, 0x0e, 0x00, 0x00, 0x00,
	0x69, 0x6e, 0x65, 0x74, 0x68, 0x00, 0x00, 0x00,
	0x80, 0x00, 0x0a, 0x04, 0x15, 0x00, 0x00, 0x00,
};

/* sp_default_blob is SP code to extract recov2, vxlan, ecpri over ethernet
 * and ecpri over udp. According to ecpri specification, for ecpri over udp,
 * eCPRI does not specify any range of UDP port values to identify the various
 * eCPRI streams. Destination port is specified by user to identify
 * the ecpri protocol.
 *
 * Load this code to Parser engine in u-boot:
 * fsl_mc apply spb $spb_address_in_ddr
 */

/* p: dst port of ecpri over udp */
/* o: original spb file */
/* n: new spb file */
const char short_options[] = "h:p:o:n:";

#define LONG_OPT_HELP "help"
#define LONG_OPT_DST_UDP_PORT_ECPRI "ecpri-port"
#define LONG_OPT_ORIGINAL_SPB "orig-spb"
#define LONG_OPT_NEW_SPB "new-spb"

enum {
	/* long options mapped to a short option */
	LONG_OPT_NUM_BASE = 256,
	LONG_OPT_HELP_NUM,
	LONG_OPT_DST_UDP_PORT_ECPRI_NUM,
	LONG_OPT_ORIGINAL_SPB_NUM,
	LONG_OPT_NEW_SPB_NUM,
	LONG_OPT_MAX_NUM
};

const struct option long_opt[] = {
	{
		LONG_OPT_HELP,
		1, NULL, LONG_OPT_HELP_NUM
	},
	{
		LONG_OPT_DST_UDP_PORT_ECPRI,
		1, NULL, LONG_OPT_DST_UDP_PORT_ECPRI_NUM
	},
	{
		LONG_OPT_ORIGINAL_SPB,
		1, NULL, LONG_OPT_ORIGINAL_SPB_NUM
	},
	{
		LONG_OPT_NEW_SPB,
		1, NULL, LONG_OPT_NEW_SPB_NUM
	}
};

static int
modify_orig_ecpri_udp_port(unsigned char port_h,
	unsigned char port_l,
	unsigned char *blob, unsigned long size)
{
	int i;

	if (!blob)
		return -EINVAL;

	for (i = 0; i < size; i++) {
		if (blob[i] == ECPRI_UDP_DST_PORT_H &&
			(i + 1) < size &&
			blob[i + 1] == ECPRI_UDP_DST_PORT_L) {
			printf("UDP port at blob[0x%08x] -> 0x%02x%02x\r\n",
				i, port_h, port_l);
			blob[i] = port_h;
			blob[i + 1] = port_l;
			return i;
		}
	}

	return -EINVAL;
}

static int
read_original_spb(const char *file_name)
{
	int fd, ret;
	unsigned long size, ret_size;
	struct stat statbuf;

	fd = open(file_name, O_RDWR, 0660);
	if (fd < 0) {
		printf("Open file %s failed\r\n", file_name);

		return -ENODEV;
	}

	ret = stat(file_name, &statbuf);
	if (ret < 0) {
		close(fd);
		return ret;
	}
	size = statbuf.st_size;
	sp_orig_blob = malloc(size);
	if (sp_orig_blob) {
		sp_orig_blob_size = size;
		ret_size = read(fd, sp_orig_blob, size);
		if (ret_size != size) {
			printf("Read file %s failed(%ld != %ld)\r\n",
				file_name, ret_size, size);
			ret = -EIO;
		} else {
			ret = 0;
		}
	} else {
		ret = -ENOMEM;
	}

	close(fd);

	return ret;
}

static void help_usage(void)
{
	size_t i;
	char buf[2048];
	int pos = 0, j;

	j = sprintf(&buf[pos], "./gen_blob -option :\n");
	pos += j;
	j = sprintf(&buf[pos], ": -h print usage\n");
	pos += j;
	j = sprintf(&buf[pos], ": -p <hex or dec>\n");
	pos += j;
	j = sprintf(&buf[pos], ": -o original spb file name\n");
	pos += j;
	j = sprintf(&buf[pos], ": -n new spb file name\n");

	printf("%s", buf);
}

int main(int argc, char **argv)
{
	int opt, option_index, fd, ret;
	int ecpri_port_spec = 0;
	unsigned short dst_port = 0;
	const char *output_name = "gen_sp.blob";
	const char *arg_tmp;

	while ((opt = getopt_long(argc, argv,
			short_options, long_opt, &option_index)) != EOF) {
		if (opt == 'p' ||
			opt == LONG_OPT_DST_UDP_PORT_ECPRI_NUM) {
			arg_tmp = optarg;
			if (arg_tmp && strlen(optarg) > 2 &&
				arg_tmp[0] == '0' &&
				(arg_tmp[1] == 'x' || arg_tmp[1] == 'X'))
				dst_port = strtol(arg_tmp, NULL, 16);
			else
				dst_port = atoi(optarg);
			if (dst_port < 0xffff && dst_port > 0)
				ecpri_port_spec = 1;
		} else if (opt == 'o' ||
			opt == LONG_OPT_ORIGINAL_SPB_NUM) {
			arg_tmp = optarg;
			ret = read_original_spb(arg_tmp);
			if (ret)
				return ret;
		} else if (opt == 'n' ||
			opt == LONG_OPT_ORIGINAL_SPB_NUM) {
			output_name = optarg;
		} else if (opt == 'h' ||
			opt == LONG_OPT_HELP_NUM) {
			help_usage();
			return 0;
		}
	}

	if (ecpri_port_spec) {
		if (sp_orig_blob) {
			ret = modify_orig_ecpri_udp_port(dst_port >> 8,
					dst_port & 0xff,
					sp_orig_blob, sp_orig_blob_size);
		} else {
			ret = modify_orig_ecpri_udp_port(dst_port >> 8,
					dst_port & 0xff,
					sp_default_blob,
					sizeof(sp_default_blob));
		}
		if (ret < 0) {
			printf("Modify UDP port failed\r\n");
			return ret;
		}
	}

	if (!access(output_name, F_OK))
		remove(output_name);

	fd = open(output_name, O_RDWR | O_CREAT, 0660);
	if (fd < 0) {
		printf("Open file %s failed\r\n", output_name);

		return -ENODEV;
	}

	if (sp_orig_blob) {
		ret = write(fd, sp_orig_blob, sp_orig_blob_size);
		free(sp_orig_blob);
	} else {
		ret = write(fd, sp_default_blob,
			sizeof(sp_default_blob));
	}
	if (ret < 0) {
		printf("Write file %s failed\r\n", output_name);
		close(fd);

		return -ENODEV;
	}
	close(fd);

	return 0;
}
