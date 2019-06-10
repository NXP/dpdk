/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 NXP
 */

#ifndef SECURITY_PDCP_TEST_FUNC_H_
#define SECURITY_PDCP_TEST_FUNC_H_

int test_pdcp_proto_cplane_encap(int i);
int test_pdcp_proto_uplane_encap(int i);
int test_pdcp_proto_uplane_encap_with_int(int i);
int test_pdcp_proto_cplane_decap(int i);
int test_pdcp_proto_uplane_decap(int i);
int test_pdcp_proto_uplane_decap_with_int(int i);

int test_PDCP_PROTO_cplane_encap_all(void);
int test_PDCP_PROTO_cplane_decap_all(void);
int test_PDCP_PROTO_uplane_encap_all(void);
int test_PDCP_PROTO_uplane_decap_all(void);

#endif /* SECURITY_PDCP_TEST_FUNC_H_ */
