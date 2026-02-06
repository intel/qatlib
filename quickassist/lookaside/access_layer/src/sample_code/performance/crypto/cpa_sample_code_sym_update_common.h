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
 * @file cpa_sample_code_sym_update.c
 *
 * @defgroup sampleSymmetricPerf  Symmetric Performance code
 *
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      This file contains the main symmetric session update performance
 *      sample code. It is capable of performing all ciphers, all hashes,
 *      authenticated hashes and algorithm chaining with session update
 *      operation.
 *
 *****************************************************************************/
#ifndef CPA_SAMPLE_CODE_SYM_UPDATE_COMMON_H_
#define CPA_SAMPLE_CODE_SYM_UPDATE_COMMON_H_

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_sym_dp.h"
#include "icp_sal_poll.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_cy_common.h"

#define CIPHER_ALG_NUM (15)
#define HASH_ALG_NUM (13)
#define ALGCHAIN_CIPHER_NUM (18)
#define ALGCHAIN_HASH_NUM (17)

#define SIZE_BIT_IN_BYTES(bits) ((bits + 7) / 8)
#define DIGEST_LENGTH_16 (16)
#define DIGEST_LENGTH_4 (4)
#define DIGEST_LENGTH_8 (8)

#if CY_API_VERSION_AT_LEAST(2, 2)
// Test config struct
typedef struct testSetupCipher_s
{
    CpaCySymCipherAlgorithm cipherAlgorithm;
    Cpa32U cipherKeyLen;
} testSetupCipher_t;

typedef struct testSetupHash_s
{
    CpaCySymHashAlgorithm hashAlgorithm;
    Cpa32U authKeyLen;
    Cpa32U digestResultLenInBytes;
} testSetupHash_t;

extern CpaStatus getCryptoInstanceMapping(void);
extern Cpa16U numInstances_g;
extern Cpa32U *cyInstMap_g;
extern Cpa32U *dcInstMap_g;
extern Cpa32U instMap_g;
extern Cpa16U numInst_g;
extern CpaBoolean usePartial_g;

void symUpdateCallback(void *pCallbackTag,
                       CpaStatus status,
                       const CpaCySymOp operationType,
                       void *pOpData,
                       CpaBufferList *pDstBuffer,
                       CpaBoolean verifyResult);

void symDpUpdateCallback(CpaCySymDpOpData *pOpData,
                         CpaStatus status,
                         CpaBoolean verifyResult);

void sessionUpdatePrintStatsDp(thread_creation_data_t *data);

CpaStatus allocAndFillRandom(Cpa8U **pBuff, Cpa32U len, Cpa32U node);

void freeUpdateMem(void **mem);

CpaStatus setupBufferList(Cpa8U **pBuff,
                          Cpa32U numBuff,
                          Cpa32U bufferSize,
                          CpaBufferList **pSrcBuffer,
                          Cpa32U node);

void setupUpdateData(CpaCySymSessionCtx sessionCtx,
                     CpaCySymSessionUpdateData *pUpdateData,
                     Cpa8U **pUpdateCipherKey,
                     Cpa8U **pUpdateHashKey,
                     CpaBoolean updateCipherDirection);

CpaStatus symSetupSessionUpdateTest(CpaCySymOp symOperation,
                                    CpaCySymCipherAlgorithm cipherAlgorithm,
                                    Cpa32U cipherKeyLen,
                                    CpaCySymHashAlgorithm hashAlgorithm,
                                    Cpa32U authKeyLen,
                                    CpaCySymHashMode hashMode,
                                    Cpa32U digestResultLenInBytes,
                                    CpaCySymAlgChainOrder algChainOrder,
                                    CpaCyPriority priority,
                                    sync_mode_t syncMode,
                                    Cpa32U packetSize,
                                    Cpa32U numOfPacketsInBuffer,
                                    Cpa32U numBuffers,
                                    Cpa32U numLoops,
                                    CpaBoolean isDpApi,
                                    void *samplePerformanceFunction);
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */

#endif /* CPA_SAMPLE_CODE_SYM_UPDATE_COMMON_H_ */
