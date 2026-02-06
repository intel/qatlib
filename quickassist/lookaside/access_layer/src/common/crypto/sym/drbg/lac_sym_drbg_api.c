/******************************************************************************
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
 * @file lac_sym_drbg_api.c
 *
 * @ingroup LacSym_Drbg
 *
 * @description
 *     Implementation of the Deterministic Random Bit Generation API
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_cy_drbg.h"

/**
 * @ingroup cpaCyDrbg
 */
CpaStatus cpaCyDrbgSessionGetSize(const CpaInstanceHandle instanceHandle_in,
                                  const CpaCyDrbgSessionSetupData *pSetupData,
                                  Cpa32U *pSize)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 * @ingroup cpaCyDrbg
 */
CpaStatus cpaCyDrbgInitSession(const CpaInstanceHandle instanceHandle_in,
                               const CpaCyGenFlatBufCbFunc pGenCb,
                               const CpaCyGenericCbFunc pReseedCb,
                               const CpaCyDrbgSessionSetupData *pSetupData,
                               CpaCyDrbgSessionHandle sessionHandle,
                               Cpa32U *pSeedLen)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 * @ingroup cpaCyDrbg
 */
CpaStatus cpaCyDrbgGen(const CpaInstanceHandle instanceHandle_in,
                       void *pCallbackTag,
                       CpaCyDrbgGenOpData *pOpData,
                       CpaFlatBuffer *pPseudoRandomBits)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 * @ingroup cpaCyDrbg
 */
CpaStatus cpaCyDrbgReseed(const CpaInstanceHandle instanceHandle_in,
                          void *pCallbackTag,
                          CpaCyDrbgReseedOpData *pOpData)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 * @ingroup cpaCyDrbg
 */
CpaStatus cpaCyDrbgRemoveSession(const CpaInstanceHandle instanceHandle_in,
                                 CpaCyDrbgSessionHandle sessionHandle)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 * @ingroup cpaCyDrbg
 */
CpaStatus cpaCyDrbgQueryStats64(const CpaInstanceHandle instanceHandle_in,
                                CpaCyDrbgStats64 *pStats)
{
    return CPA_STATUS_UNSUPPORTED;
}
