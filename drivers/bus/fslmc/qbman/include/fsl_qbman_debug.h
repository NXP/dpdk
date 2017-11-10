/* Copyright (C) 2015 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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
struct qbman_swp;

struct qbman_fq_query_np_rslt {
uint8_t verb;
	uint8_t rslt;
	uint8_t st1;
	uint8_t st2;
	uint8_t reserved[2];
	uint16_t od1_sfdr;
	uint16_t od2_sfdr;
	uint16_t od3_sfdr;
	uint16_t ra1_sfdr;
	uint16_t ra2_sfdr;
	uint32_t pfdr_hptr;
	uint32_t pfdr_tptr;
	uint32_t frm_cnt;
	uint32_t byte_cnt;
	uint16_t ics_surp;
	uint8_t is;
	uint8_t reserved2[29];
};

int qbman_fq_query_state(struct qbman_swp *s, uint32_t fqid,
			 struct qbman_fq_query_np_rslt *r);
uint32_t qbman_fq_state_frame_count(const struct qbman_fq_query_np_rslt *r);
uint32_t qbman_fq_state_byte_count(const struct qbman_fq_query_np_rslt *r);

