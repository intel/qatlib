/***************************************************************************
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

/***************************************************************************
 * @file cpa_big_num.h
 *
 * @description
 *     This file contains definitions used in big integer operations.
 *
 ***************************************************************************/
#ifndef CPA_BIG_NUM_H
#define CPA_BIG_NUM_H

#include "cpa_eddsa_sample.h"
#include <openssl/bn.h>

#if CY_API_VERSION_AT_LEAST(2, 3)

#define bigNumMod(R, A, M) bigNum(CPA_BIG_NUM_MOD_OP, R, A, NULL, M)
#define bigNumModInv(R, A, M) bigNum(CPA_BIG_NUM_MOD_INV_OP, R, A, NULL, M)
#define bigNumModAdd(R, A, B, M) bigNum(CPA_BIG_NUM_MOD_ADD_OP, R, A, B, M)
#define bigNumModSub(R, A, B, M) bigNum(CPA_BIG_NUM_MOD_SUB_OP, R, A, B, M)
#define bigNumModMul(R, A, B, M) bigNum(CPA_BIG_NUM_MOD_MUL_OP, R, A, B, M)
#define bigNumModSqr(R, A, M) bigNum(CPA_BIG_NUM_MOD_SQR_OP, R, A, NULL, M)
#define bigNumModExp(R, A, B, M) bigNum(CPA_BIG_NUM_MOD_EXP_OP, R, A, B, M)

/* Supported big integer operations */
typedef enum _CpaBigNumOp
{
    CPA_BIG_NUM_MOD_OP = 0,
    CPA_BIG_NUM_MOD_INV_OP,
    CPA_BIG_NUM_MOD_ADD_OP,
    CPA_BIG_NUM_MOD_SUB_OP,
    CPA_BIG_NUM_MOD_MUL_OP,
    CPA_BIG_NUM_MOD_SQR_OP,
    CPA_BIG_NUM_MOD_EXP_OP,
} CpaBigNumOp;

/* Declaration of big integer operation function */
typedef void (
    *CpaBigNumFunc)(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *m, BN_CTX *ctx);

/*****************************************************************************
 * @description
 *     This function performs big integer operations.
 *
 * @param[in]  bigNumOp  Type of big integer operation performed on a_le, b_le,
 *                       m_le, values.
 * @param[in]  a_le      Flatbuffer with little endian integer value
 * @param[in]  b_le      Flatbuffer with little endian integer value
 * @param[in]  m_le      Flatbuffer with little endian integer modulo value
 *
 * @param[out] r_le      Flatbuffer with little endian integer result value
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter in.
 *
 *****************************************************************************/
CpaStatus bigNum(CpaBigNumOp bigNumOp,
                 CpaFlatBuffer *r_le,
                 CpaFlatBuffer *a_le,
                 CpaFlatBuffer *b_le,
                 CpaFlatBuffer *m_le);

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
#endif
