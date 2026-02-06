/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file lac_kpt_rsa_decrypt.c
 *
 * @ingroup Lac_KptRsa
 *
 * This file implements data decryption function for KPT RSA.
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_kpt.h"

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     This function performs KPT RSA decryption.
 *
 *****************************************************************************/
CpaStatus cpaCyKptRsaDecrypt(const CpaInstanceHandle instanceHandle,
                             const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                             void *pCallbackTag,
                             const CpaCyKptRsaDecryptOpData *pDecryptOpData,
                             CpaFlatBuffer *pOutputData,
                             CpaCyKptUnwrapContext *pKptUnwrapContext)

{
    return CPA_STATUS_UNSUPPORTED;
}
