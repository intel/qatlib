/****************************************************************************
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

/*****************************************************************************
 * @file cpa_big_num.c
 *
 * @description
 *     This file contains functions used in big integer operations. All input
 *     values are little endian integers.
 *
 *****************************************************************************/

#include "cpa_big_num.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

/*****************************************************************************
 * @description
 *     This function performs modulo operation using OpenSSL BIGNUM.
 *
 *****************************************************************************/
static void bigNumModFunc(BIGNUM *r,
                          BIGNUM *a,
                          BIGNUM *b,
                          BIGNUM *m,
                          BN_CTX *ctx)
{
    BN_mod(r, a, m, ctx);
}

/*****************************************************************************
 * @description
 *     This function performs modular inverse operation using OpenSSL BIGNUM.
 *
 *****************************************************************************/
static void bigNumModInvFunc(BIGNUM *r,
                             BIGNUM *a,
                             BIGNUM *b,
                             BIGNUM *m,
                             BN_CTX *ctx)
{
    BN_mod_inverse(r, a, m, ctx);
}

/*****************************************************************************
 * @description
 *     This function performs modular addition operation using OpenSSL BIGNUM.
 *
 *****************************************************************************/
static void bigNumModAddFunc(BIGNUM *r,
                             BIGNUM *a,
                             BIGNUM *b,
                             BIGNUM *m,
                             BN_CTX *ctx)
{
    BN_mod_add(r, a, b, m, ctx);
}

/******************************************************************************
 * @description
 *     This function performs modular substraction operation using OpenSSL
 *     BIGNUM.
 *
 *****************************************************************************/
static void bigNumModSubFunc(BIGNUM *r,
                             BIGNUM *a,
                             BIGNUM *b,
                             BIGNUM *m,
                             BN_CTX *ctx)
{
    BN_mod_sub(r, a, b, m, ctx);
}

/******************************************************************************
 * @description
 *     This function performs modular multiply operation using OpenSSL BIGNUM.
 *
 *****************************************************************************/
static void bigNumModMulFunc(BIGNUM *r,
                             BIGNUM *a,
                             BIGNUM *b,
                             BIGNUM *m,
                             BN_CTX *ctx)
{
    BN_mod_mul(r, a, b, m, ctx);
}

/*****************************************************************************
 * @description
 *     This function performs modular square power operation using OpenSSL
 *     BIGNUM.
 *
 *****************************************************************************/
static void bigNumModSqrFunc(BIGNUM *r,
                             BIGNUM *a,
                             BIGNUM *b,
                             BIGNUM *m,
                             BN_CTX *ctx)
{
    BN_mod_sqr(r, a, m, ctx);
}

/*****************************************************************************
 * @description
 *     This function performs modular exponentiation operation using
 *     OpenSSL BIGNUM.
 *
 *****************************************************************************/
static void bigNumModExpFunc(BIGNUM *r,
                             BIGNUM *a,
                             BIGNUM *b,
                             BIGNUM *m,
                             BN_CTX *ctx)
{
    BN_mod_exp(r, a, b, m, ctx);
}

/*****************************************************************************
 * @description
 *     Table of function pointers used in bigNum().
 *
 *****************************************************************************/
static CpaBigNumFunc bigNumFunc[] = {bigNumModFunc,
                                     bigNumModInvFunc,
                                     bigNumModAddFunc,
                                     bigNumModSubFunc,
                                     bigNumModMulFunc,
                                     bigNumModSqrFunc,
                                     bigNumModExpFunc};

CpaStatus bigNum(CpaBigNumOp bigNumOp,
                 CpaFlatBuffer *r_le,
                 CpaFlatBuffer *a_le,
                 CpaFlatBuffer *b_le,
                 CpaFlatBuffer *m_le)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *r_be = NULL;      /* Pointer to reslut in big endian */
    Cpa8U *a_be = NULL;      /* Pointer to input in big endian */
    Cpa8U *b_be = NULL;      /* Pointer to input in big endian */
    Cpa8U *m_be = NULL;      /* Pointer to input in big endian */
    BIGNUM *bn_r = BN_new(); /* BIGNUM result */
    BIGNUM *bn_a = BN_new(); /* BIGNUM input a */
    BIGNUM *bn_b = BN_new(); /* BIGNUM input b */
    BIGNUM *bn_m = BN_new(); /* BIGNUM input m */
    Cpa32U bin_r_size = 0;   /* Size of output buffer */
    BN_CTX *bn_ctx = NULL;   /* BIGNUM context pointer */

    /* Check input data */
    if (a_le->pData == NULL || m_le->pData == NULL)
    {
        PRINT_ERR("Input data error %p\n", m_le->pData);
        status = CPA_STATUS_INVALID_PARAM;
        goto exit;
    }

    if (a_le->dataLenInBytes == 0 || m_le->dataLenInBytes == 0)
    {
        PRINT_ERR("Input data length error: a_le->dataLenInBytes: %d, "
                  "b_le->dataLenInBytes: %d\n",
                  a_le->dataLenInBytes,
                  m_le->dataLenInBytes);
        status = CPA_STATUS_INVALID_PARAM;
        goto exit;
    }

    if (b_le != NULL && b_le->dataLenInBytes == 0)
    {
        PRINT_ERR("b_le->dataLenInBytes %d\n", b_le->dataLenInBytes);
        status = CPA_STATUS_INVALID_PARAM;
        goto exit;
    }

    /* Alloc context */
    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
    {
        PRINT_ERR("BN_CTX_new ERROR!\n");
        status = CPA_STATUS_FAIL;
        goto exit;
    }

    /* Alloc buffers for big endian values */
    status = OS_MALLOC(&a_be, a_le->dataLenInBytes);
    if (b_le != NULL)
        status |= OS_MALLOC(&b_be, b_le->dataLenInBytes);
    status |= OS_MALLOC(&m_be, m_le->dataLenInBytes);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Memory alloc error");
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Copy input from little endian to big endian buffers */
        memcpy_reverse(a_be, a_le->pData, a_le->dataLenInBytes);
        if (b_le != NULL)
            memcpy_reverse(b_be, b_le->pData, b_le->dataLenInBytes);
        memcpy_reverse(m_be, m_le->pData, m_le->dataLenInBytes);

        /* Convert from bin to BIGNUM */
        BN_bin2bn(a_be, a_le->dataLenInBytes, bn_a);
        if (b_le != NULL)
            BN_bin2bn(b_be, b_le->dataLenInBytes, bn_b);
        BN_bin2bn(m_be, m_le->dataLenInBytes, bn_m);

        /* Perform big number operation */
        bigNumFunc[bigNumOp](bn_r, bn_a, bn_b, bn_m, bn_ctx);

        /* Get size of output buffer */
        bin_r_size = BN_num_bytes(bn_r);

        /* Alloc buffer for output in big endian format */
        if (bin_r_size == 0)
        {
            /* If result equals 0 alloc 1 byte and set it with zero */
            status = OS_MALLOC(&r_be, 1);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Memory alloc error");
                status = CPA_STATUS_FAIL;
            }
            else
            {
                bin_r_size = 1;
                *r_be = 0;
            }
        }
        else
        {
            status = OS_MALLOC(&r_be, bin_r_size);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Memory alloc error");
                status = CPA_STATUS_FAIL;
            }
            else
                BN_bn2bin(bn_r, r_be);
        }
    }

    /* Alloc output buffer with little endian value and copy data */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (r_le->pData != NULL)
        {
            OS_FREE(r_le->pData);
            r_le->pData = NULL;
        }

        if (r_le->pData == NULL)
        {
            status = OS_MALLOC(&r_le->pData, bin_r_size);
            if (CPA_STATUS_SUCCESS != status)
                PRINT_ERR("r_le->pData ALLOC ERROR!\n");
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            r_le->dataLenInBytes = bin_r_size;
            memcpy_reverse(r_le->pData, r_be, bin_r_size);
        }
    }

    /* Free memory */
    OS_FREE(r_be);
    OS_FREE(a_be);
    if (b_be != NULL)
        OS_FREE(b_be);
    OS_FREE(m_be);
    BN_CTX_free(bn_ctx);
exit:
    BN_free(bn_r);
    BN_free(bn_a);
    BN_free(bn_b);
    BN_free(bn_m);

    return status;
}
#endif
