/**
 *****************************************************************************
 *
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file cpa_eddsa_sample.h
 *
 * @description
 *     This file contains declarations of functions used in EdDSA sample.
 *
 *****************************************************************************/

#ifndef CPA_EDDSA_SAMPLE_NUM_H
#define CPA_EDDSA_SAMPLE_NUM_H

#include "Osal.h"
#include "cpa_cy_ec.h"
#include "lac/cpa_cy_key.h"
#include "cpa_sample_utils.h"
#include "cpa_big_num.h"
#include "cpa_ed_point_operations.h"

#define DATA_LEN (32)
#define HASH_LEN (64)

#define SET_BIT(byte, bit) ((byte) |= (1 << (bit)))
#define CLR_BIT(byte, bit) ((byte) &= ~((1) << (bit)))
#define CHK_BIT(byte, bit) (!!((byte) & (1 << (bit))))

#if CY_API_VERSION_AT_LEAST(2, 3)

/*****************************************************************************
 * @description
 *     This function copies buffer to destination with reverse order of bytes.
 *
 * @param[in]   src      Pointer to source buffer
 * @param[in]   src_len  Source buffer length
 *
 * @param[out]  dest     Pointer to destination buffer
 *
 *****************************************************************************/
void memcpy_reverse(Cpa8U *dest, Cpa8U *src, Cpa32U src_len);

/*****************************************************************************
 * @description
 *      This function copies content of buffer into flat buffer.
 *
 * @param[in]   input     Pointer to source buffer
 * @param[in]   inputLen  Source buffer length
 *
 * @param[out]  fb        Pointer to flat buffer.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus copyToFlatBuffer(CpaFlatBuffer *fb, Cpa8U *input, Cpa32U inputLen);

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
#endif
