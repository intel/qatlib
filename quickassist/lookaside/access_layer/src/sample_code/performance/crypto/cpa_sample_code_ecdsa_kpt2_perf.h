/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef CPA_SAMPLE_CODE_ECDSA_KPT2_PERF_H
#define CPA_SAMPLE_CODE_ECDSA_KPT2_PERF_H

#include "cpa_sample_code_kpt2_common.h"
#if CY_API_VERSION_AT_LEAST(3, 0)
#define KPT2_ECDSA_P521_WPK_SIZE_IN_BYTES (72)

CpaStatus setKPT2EcdsaSignRSOpData(CpaInstanceHandle instanceHandle,
                                   CpaCyKptEcdsaSignRSOpData *pKPTSignRSOpData,
                                   CpaCyEcdsaSignRSOpData *pSignRSOpData,
                                   Cpa8U *pSampleSWK,
                                   Cpa8U *pIv,
                                   Cpa8U *pAad,
                                   Cpa32U aadLenInBytes);
#endif
#endif
