/*************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/**
 *****************************************************************************
 * @file lac_sym_nrbg_api.c
 *
 * @ingroup LacSym_Nrbg
 *
 * Implementation of the Non-Deterministic Random Bit Generation API
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_cy_nrbg.h"

/**
 * cpaCyNrbgGetEntropy
 */
CpaStatus cpaCyNrbgGetEntropy(const CpaInstanceHandle instanceHandle_in,
                              const CpaCyGenFlatBufCbFunc pCb,
                              void *pCallbackTag,
                              const CpaCyNrbgOpData *pOpData,
                              CpaFlatBuffer *pEntropy)
{
    return CPA_STATUS_UNSUPPORTED;
}
