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

#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "icp_sal_poll.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_sym_update_common.h"
#include "cpa.h"
#include "cpa_cy_common.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_sym_dp.h"

#if CY_API_VERSION_AT_LEAST(2, 2)
#ifdef SC_SYM_UPDATE_DISABLED
CpaStatus cpaCySymUpdateSession(
    CpaCySymSessionCtx sessionCtx,
    const CpaCySymSessionUpdateData *pSessionUpdateData)
{
    return CPA_STATUS_UNSUPPORTED;
}
#endif

#ifdef SC_SYM_SESSION_INUSE_DISABLED
CpaStatus cpaCySymSessionInUse(CpaCySymSessionCtx sessionCtx,
                               CpaBoolean *pSessionInUse)
{
    return CPA_STATUS_UNSUPPORTED;
}
#endif
#endif

#if CY_API_VERSION_AT_LEAST(2, 2)
// Init variables

#define CIPHER_ALGORITHM_LIST                                                  \
    { { 0, 0 },                                                                \
      { CPA_CY_SYM_CIPHER_NULL, SIZE_BIT_IN_BYTES(128) },                      \
      { CPA_CY_SYM_CIPHER_ARC4, SIZE_BIT_IN_BYTES(128) },                      \
      { CPA_CY_SYM_CIPHER_AES_ECB, SIZE_BIT_IN_BYTES(192) },                   \
      { CPA_CY_SYM_CIPHER_AES_CBC, SIZE_BIT_IN_BYTES(256) },                   \
      { CPA_CY_SYM_CIPHER_AES_CTR, SIZE_BIT_IN_BYTES(128) },                   \
      { CPA_CY_SYM_CIPHER_AES_CCM, SIZE_BIT_IN_BYTES(128) },                   \
      { CPA_CY_SYM_CIPHER_AES_GCM, SIZE_BIT_IN_BYTES(128) },                   \
      { CPA_CY_SYM_CIPHER_DES_ECB, SIZE_BIT_IN_BYTES(64) },                    \
      { CPA_CY_SYM_CIPHER_DES_CBC, SIZE_BIT_IN_BYTES(64) },                    \
      { CPA_CY_SYM_CIPHER_3DES_ECB, SIZE_BIT_IN_BYTES(192) },                  \
      { CPA_CY_SYM_CIPHER_3DES_CBC, SIZE_BIT_IN_BYTES(192) },                  \
      { CPA_CY_SYM_CIPHER_3DES_CTR, SIZE_BIT_IN_BYTES(192) },                  \
      { CPA_CY_SYM_CIPHER_KASUMI_F8, SIZE_BIT_IN_BYTES(128) },                 \
      { CPA_CY_SYM_CIPHER_SNOW3G_UEA2, SIZE_BIT_IN_BYTES(128) },               \
      { CPA_CY_SYM_CIPHER_AES_F8, SIZE_BIT_IN_BYTES(256) },                    \
      { CPA_CY_SYM_CIPHER_AES_XTS, SIZE_BIT_IN_BYTES(256) },                   \
      { CPA_CY_SYM_CIPHER_ZUC_EEA3, SIZE_BIT_IN_BYTES(128) } };
#define HASH_ALGORITHM_LIST                                                    \
    { { CPA_CY_SYM_HASH_NONE, SIZE_BIT_IN_BYTES(512), DIGEST_LENGTH_16 },      \
      { CPA_CY_SYM_HASH_MD5, SIZE_BIT_IN_BYTES(192), DIGEST_LENGTH_16 },       \
      { CPA_CY_SYM_HASH_SHA1, SIZE_BIT_IN_BYTES(128), DIGEST_LENGTH_16 },      \
      { CPA_CY_SYM_HASH_SHA224, SIZE_BIT_IN_BYTES(224), DIGEST_LENGTH_16 },    \
      { CPA_CY_SYM_HASH_SHA256, SIZE_BIT_IN_BYTES(256), DIGEST_LENGTH_16 },    \
      { CPA_CY_SYM_HASH_SHA384, SIZE_BIT_IN_BYTES(384), DIGEST_LENGTH_16 },    \
      { CPA_CY_SYM_HASH_SHA512, SIZE_BIT_IN_BYTES(512), DIGEST_LENGTH_16 },    \
      { CPA_CY_SYM_HASH_AES_XCBC, SIZE_BIT_IN_BYTES(128), DIGEST_LENGTH_16 },  \
      { CPA_CY_SYM_HASH_AES_CCM, SIZE_BIT_IN_BYTES(512), DIGEST_LENGTH_16 },   \
      { CPA_CY_SYM_HASH_AES_GCM, SIZE_BIT_IN_BYTES(512), DIGEST_LENGTH_16 },   \
      { CPA_CY_SYM_HASH_KASUMI_F9, SIZE_BIT_IN_BYTES(128), DIGEST_LENGTH_4 },  \
      { CPA_CY_SYM_HASH_SNOW3G_UIA2,                                           \
        SIZE_BIT_IN_BYTES(128),                                                \
        DIGEST_LENGTH_4 },                                                     \
      { CPA_CY_SYM_HASH_AES_CMAC, SIZE_BIT_IN_BYTES(128), DIGEST_LENGTH_16 },  \
      { CPA_CY_SYM_HASH_AES_GMAC, SIZE_BIT_IN_BYTES(512), DIGEST_LENGTH_16 },  \
      { CPA_CY_SYM_HASH_AES_CBC_MAC,                                           \
        SIZE_BIT_IN_BYTES(128),                                                \
        DIGEST_LENGTH_16 },                                                    \
      { CPA_CY_SYM_HASH_ZUC_EIA3, SIZE_BIT_IN_BYTES(128), DIGEST_LENGTH_4 },   \
      { CPA_CY_SYM_HASH_SHA3_256,                                              \
        SIZE_BIT_IN_BYTES(128),                                                \
        DIGEST_LENGTH_16 } };
#define ALGORITHM_CHAIN_BIT_MASK                                               \
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 },                   \
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 },                   \
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1 },                   \
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 } };
#define CIPHER_ALGORITHM_NUM                                                   \
    { 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
#define HASH_ALGORITHM_NUM { 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 14, 15, 16 };

const testSetupCipher_t cipherSetup[ALGCHAIN_CIPHER_NUM] =
    CIPHER_ALGORITHM_LIST;
const testSetupHash_t hashSetup[ALGCHAIN_HASH_NUM] = HASH_ALGORITHM_LIST;
const Cpa32U algChainAlgs[][ALGCHAIN_HASH_NUM] = ALGORITHM_CHAIN_BIT_MASK;
const Cpa32U cipherAlgs[CIPHER_ALG_NUM] = CIPHER_ALGORITHM_NUM;
const Cpa32U hashAlgs[HASH_ALG_NUM] = HASH_ALGORITHM_NUM;

extern CpaStatus getCryptoInstanceMapping(void);
extern Cpa16U numInstances_g;
extern Cpa32U *cyInstMap_g;
extern Cpa32U *dcInstMap_g;
extern Cpa32U instMap_g;
extern Cpa16U numInst_g;
extern CpaBoolean usePartial_g;

// Configure session update data
void setupUpdateData(CpaCySymSessionCtx sessionCtx,
                     CpaCySymSessionUpdateData *pUpdateData,
                     Cpa8U **pUpdateCipherKey,
                     Cpa8U **pUpdateHashKey,
                     CpaBoolean updateCipherDirection)
{
    pUpdateData->flags = 0;

    if (pUpdateCipherKey != NULL)
    {
        pUpdateData->flags |= CPA_CY_SYM_SESUPD_CIPHER_KEY;
        pUpdateData->pCipherKey = *pUpdateCipherKey;
    }

    if (pUpdateHashKey != NULL)
    {
        pUpdateData->flags |= CPA_CY_SYM_SESUPD_AUTH_KEY;
        pUpdateData->authKey = *pUpdateHashKey;
    }

    if (updateCipherDirection)
    {
        pUpdateData->flags |= CPA_CY_SYM_SESUPD_CIPHER_DIR;
        if (pUpdateData->cipherDirection != CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT)
        {
            pUpdateData->cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        }
        else
        {
            pUpdateData->cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
        }
    }
}

CpaStatus allocAndFillRandom(Cpa8U **pBuff, Cpa32U len, Cpa32U node)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferTemp = NULL;

    pBufferTemp = qaeMemAllocNUMA(len, node, BYTE_ALIGNMENT_64);
    if (NULL == pBufferTemp)
    {
        PRINT("Error allocating memory\n");
        status = CPA_STATUS_FAIL;
    }
    else
    {
        generateRandomData(pBufferTemp, len);
    }

    *pBuff = pBufferTemp;

    return status;
}

void freeUpdateMem(void **mem)
{
    if (NULL != mem && NULL != *mem)
    {
        qaeMemFreeNUMA(mem);
    }
}

// Setup buffer list function
CpaStatus setupBufferList(Cpa8U **pBuff,
                          Cpa32U numBuff,
                          Cpa32U bufferSize,
                          CpaBufferList **pSrcBuffer,
                          Cpa32U node)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U bufferMetaSize = 0;
    Cpa32U bufferListSize = 0;
    Cpa32U bufferDescTotalSize = 0;
    Cpa8U *pBufferMem = NULL;
    CpaInstanceHandle cyInstHandle = CPA_INSTANCE_HANDLE_SINGLE;
    Cpa32U i = 0;

    status = cpaCyBufferListGetMetaSize(cyInstHandle, 1, &bufferMetaSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        bufferListSize =
            sizeof(CpaBufferList) + (numBuff * sizeof(CpaFlatBuffer));
        bufferDescTotalSize = bufferMetaSize + bufferListSize;
        pBufferMem =
            qaeMemAllocNUMA(bufferDescTotalSize, node, BYTE_ALIGNMENT_64);
        if (NULL == pBufferMem)
        {
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaBufferList *pTmpBufList = (CpaBufferList *)pBufferMem;
        pTmpBufList->numBuffers = numBuff;
        pTmpBufList->pPrivateMetaData = pBufferMem + bufferListSize;
        pTmpBufList->pBuffers =
            (CpaFlatBuffer *)(pBufferMem + sizeof(CpaBufferList));
        for (i = 0; i < numBuff; i++)
        {
            pTmpBufList->pBuffers[i].pData = pBuff[i];
            pTmpBufList->pBuffers[i].dataLenInBytes = bufferSize;
        }
        *pSrcBuffer = pTmpBufList;
    }

    return status;
}

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
                                    void *samplePerformanceFunction)
{
    symmetric_test_params_t *updateSetup = NULL;

    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }
    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Failed to start Crypto services\n");
        return CPA_STATUS_FAIL;
    }

    if (!poll_inline_g && !isDpApi)
    {
        /* start polling threads if polling is enabled in the configuration file
         */
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }

    if ((symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING ||
         symOperation == CPA_CY_SYM_OP_HASH) &&
        hashMode != CPA_CY_SYM_HASH_MODE_AUTH)
    {
        PRINT_ERR("Unsupported hash mode\n");
        return CPA_STATUS_FAIL;
    }

    updateSetup =
        (symmetric_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    memset(updateSetup, 0, sizeof(symmetric_test_params_t));
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)samplePerformanceFunction;

    updateSetup->setupData.sessionPriority = priority;
    updateSetup->setupData.symOperation = symOperation;
    updateSetup->setupData.algChainOrder = algChainOrder;
    updateSetup->setupData.cipherSetupData.cipherAlgorithm = cipherAlgorithm;
    updateSetup->setupData.cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    updateSetup->setupData.cipherSetupData.cipherKeyLenInBytes = cipherKeyLen;
    updateSetup->setupData.hashSetupData.hashAlgorithm = hashAlgorithm;
    updateSetup->setupData.hashSetupData.hashMode = hashMode;
    updateSetup->setupData.hashSetupData.digestResultLenInBytes =
        digestResultLenInBytes;
    updateSetup->setupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
        authKeyLen;
    updateSetup->flatBufferSizeInBytes = packetSize;
    updateSetup->numBuffers = numBuffers;
    updateSetup->numLoops = numLoops;
    updateSetup->syncMode = syncMode;
    updateSetup->isDpApi = isDpApi;
    /* Set partialsNotRequired to TRUE for default case */
    updateSetup->setupData.partialsNotRequired = CPA_TRUE;

    if (cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CTR ||
        cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CBC ||
        cipherAlgorithm == CPA_CY_SYM_CIPHER_SNOW3G_UEA2 ||
        cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_F8 ||
        cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_XTS ||
        cipherAlgorithm == CPA_CY_SYM_CIPHER_ZUC_EEA3)
    {
        updateSetup->ivLength = IV_LEN_FOR_16_BYTE_BLOCK_CIPHER;
    }
    else if (cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CCM ||
             cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_GCM ||
             cipherAlgorithm == CPA_CY_SYM_CIPHER_CHACHA)
    {
        updateSetup->ivLength = IV_LEN_FOR_16_BYTE_GCM;
    }
    else
    {
        updateSetup->ivLength = IV_LEN_FOR_8_BYTE_BLOCK_CIPHER;
    }
    if (hashAlgorithm == CPA_CY_SYM_HASH_ZUC_EIA3 ||
        hashAlgorithm == CPA_CY_SYM_HASH_SNOW3G_UIA2)
    {
        updateSetup->setupData.hashSetupData.authModeSetupData.aadLenInBytes =
            KEY_SIZE_128_IN_BYTES;
    }
    else if (hashAlgorithm == CPA_CY_SYM_HASH_AES_GCM ||
             hashAlgorithm == CPA_CY_SYM_HASH_AES_CCM)
    {
        updateSetup->setupData.hashSetupData.authModeSetupData.aadLenInBytes =
            AES_CCM_MIN_AAD_ALLOC_LENGTH;
    }
    else
    {
        updateSetup->setupData.hashSetupData.authModeSetupData.aadLenInBytes =
            0;
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(symSetupSessionUpdateTest);
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
