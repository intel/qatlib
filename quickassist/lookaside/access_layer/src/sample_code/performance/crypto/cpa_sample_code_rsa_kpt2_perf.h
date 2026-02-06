/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef CPA_SAMPLE_CODE_RSA_KPT2_PERF_H
#define CPA_SAMPLE_CODE_RSA_KPT2_PERF_H

#include "cpa_sample_code_kpt2_common.h"

#if CY_API_VERSION_AT_LEAST(3, 0)
CpaStatus setKpt2RsaDecryptOpData(CpaInstanceHandle instanceHandle,
                                  CpaCyKptRsaDecryptOpData **pKPTDecryptOpData,
                                  CpaCyRsaDecryptOpData *pDecryptOpData,
                                  CpaCyRsaPublicKey *pRsaPublicKey,
                                  Cpa32U node,
                                  Cpa8U *pSampleSWK,
                                  Cpa8U *pIv,
                                  Cpa8U *pAad,
                                  Cpa32U aadLenInBytes);

#endif
#endif
