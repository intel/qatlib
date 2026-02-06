/***************************************************************************
 *
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
