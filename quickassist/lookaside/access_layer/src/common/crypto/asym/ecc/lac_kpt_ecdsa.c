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
 *
 * @file lac_kpt_ecdsa.c
 *
 * @ingroup Lac_KptEc
 *
 *      This file implements Elliptic Curve Digital Signature Algorithm with
 *      protected private key
 *
 *****************************************************************************/
/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_kpt.h"

/**
 ***************************************************************************
 * @ingroup Lac_KptEc
 *     This function performs KPT ECDSA Sign R & S.
 *
 ***************************************************************************/
CpaStatus cpaCyKptEcdsaSignRS(const CpaInstanceHandle instanceHandle,
                              const CpaCyEcdsaSignRSCbFunc pCb,
                              void *pCallbackTag,
                              const CpaCyKptEcdsaSignRSOpData *pOpData,
                              CpaBoolean *pSignStatus,
                              CpaFlatBuffer *pR,
                              CpaFlatBuffer *pS,
                              CpaCyKptUnwrapContext *pKptUnwrapContext)
{
    return CPA_STATUS_UNSUPPORTED;
}
