/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef CPA_SAMPLE_CODE_KPT2_COMMON_H
#define CPA_SAMPLE_CODE_KPT2_COMMON_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/param_build.h>
#endif
#include "cpa_cy_kpt.h"
#include "cpa_sample_code_crypto_utils.h"

#if CY_API_VERSION_AT_LEAST(3, 0)

#define AUTH_TAG_LEN_IN_BYTES 16
#define IV_LEN_IN_BYTES 12
#define MAX_SWK_PER_PHYSICAL_DEVICE 128
#define SWK_LEN_IN_BYTES 32
#define NUM_OF_SWK_ONLY_ONE 1
#define PER_PART_PKEY_E_SIZE 8
#define NUM_KEY_PAIRS (2)
#define KEY_PROVISION_RETRY_TIMES_LIMIT 20
#define KEY_PROVISION_RETRY_DELAY_MS 300
/* KPT Stolen Key Test */

CpaStatus encryptAndLoadSWK(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle *kptKeyHandle,
                            Cpa8U *sampleSWK);

CpaBoolean encryptPrivateKey(Cpa8U *pPrivateKey,
                             Cpa32U privateKeyLength,
                             Cpa8U *pSWK,
                             Cpa8U *pIv,
                             Cpa32U ivLength,
                             Cpa8U *pWrappedPrivateKey,
                             Cpa32U *pWPKLenth,
                             Cpa8U *pAuthTag,
                             Cpa8U *pAad,
                             Cpa32U aadLenInBytes);

#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
#endif /* CPA_SAMPLE_CODE_KPT2_COMMON_H */
