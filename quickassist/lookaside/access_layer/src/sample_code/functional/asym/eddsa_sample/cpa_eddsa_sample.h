/**
 *****************************************************************************
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
