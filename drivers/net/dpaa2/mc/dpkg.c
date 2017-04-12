/*-
 * This file is provided under a dual BSD/GPLv2 license. When using or
 * redistributing this file, you may do so under either license.
 *
 *   BSD LICENSE
 *
 * Copyright 2017 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *   GPL LICENSE SUMMARY
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <fsl_mc_sys.h>
#include <fsl_mc_cmd.h>
#include <fsl_dpkg.h>

int dpkg_prepare_key_cfg(const struct dpkg_profile_cfg *cfg,
			 uint8_t *key_cfg_buf)
{
	int i, j;
	int offset = 0;
	int param = 1;
	uint64_t *params = (uint64_t *)key_cfg_buf;

	if (!key_cfg_buf || !cfg)
		return -EINVAL;

	params[0] |= mc_enc(0, 8, cfg->num_extracts);
	params[0] = cpu_to_le64(params[0]);

	if (cfg->num_extracts >= DPKG_MAX_NUM_OF_EXTRACTS)
		return -EINVAL;

	for (i = 0; i < cfg->num_extracts; i++) {
		switch (cfg->extracts[i].type) {
		case DPKG_EXTRACT_FROM_HDR:
			params[param] |= mc_enc(0, 8,
					cfg->extracts[i].extract.from_hdr.prot);
			params[param] |= mc_enc(8, 4,
					cfg->extracts[i].extract.from_hdr.type);
			params[param] |= mc_enc(16, 8,
					cfg->extracts[i].extract.from_hdr.size);
			params[param] |= mc_enc(24, 8,
					cfg->extracts[i].extract.
					from_hdr.offset);
			params[param] |= mc_enc(32, 32,
					cfg->extracts[i].extract.
					from_hdr.field);
			params[param] = cpu_to_le64(params[param]);
			param++;
			params[param] |= mc_enc(0, 8,
					cfg->extracts[i].extract.
					from_hdr.hdr_index);
			break;
		case DPKG_EXTRACT_FROM_DATA:
			params[param] |= mc_enc(16, 8,
					cfg->extracts[i].extract.
					from_data.size);
			params[param] |= mc_enc(24, 8,
					cfg->extracts[i].extract.
					from_data.offset);
			params[param] = cpu_to_le64(params[param]);
			param++;
			break;
		case DPKG_EXTRACT_FROM_PARSE:
			params[param] |= mc_enc(16, 8,
					cfg->extracts[i].extract.
					from_parse.size);
			params[param] |= mc_enc(24, 8,
					cfg->extracts[i].extract.
					from_parse.offset);
			params[param] = cpu_to_le64(params[param]);
			param++;
			break;
		default:
			return -EINVAL;
		}
		params[param] |= mc_enc(
			24, 8, cfg->extracts[i].num_of_byte_masks);
		params[param] |= mc_enc(32, 4, cfg->extracts[i].type);
		params[param] = cpu_to_le64(params[param]);
		param++;
		for (offset = 0, j = 0;
			j < DPKG_NUM_OF_MASKS;
			offset += 16, j++) {
			params[param] |= mc_enc(
				(offset), 8, cfg->extracts[i].masks[j].mask);
			params[param] |= mc_enc(
				(offset + 8), 8,
				cfg->extracts[i].masks[j].offset);
		}
		params[param] = cpu_to_le64(params[param]);
		param++;
	}
	return 0;
}
