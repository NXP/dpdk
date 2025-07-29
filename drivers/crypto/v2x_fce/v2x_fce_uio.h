/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef _V2X_FCE_UIO_H_
#define _V2X_FCE_UIO_H_

#define ARR_LEN	64

struct uio_fce_mu {
	int fd;
	void *base;
	long size;
	long offset;
};

struct uio_fce_mu *
fce_mu_open(void);

int fce_mu_close(int fd);

#endif /* _V2X_FCE_UIO_H_ */
