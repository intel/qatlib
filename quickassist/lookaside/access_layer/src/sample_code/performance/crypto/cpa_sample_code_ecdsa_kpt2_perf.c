/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 **************************************************************************/

/***************************************************************************
 * @file cpa_sample_code_ecdsa_kpt2_perf.c
 *
 * This file provides some interface for kpt2 ecdsa performance test.
 *
 **************************************************************************/
#include "cpa_sample_code_ecdsa_kpt2_perf.h"
#if CY_API_VERSION_AT_LEAST(3, 0)

void kpt2FreeECDSAOPDataMemory(CpaCyKptEcdsaSignRSOpData *pKPTSignRSOpData,
                               CpaFlatBuffer *pWpkAndAuthTag,
                               CpaFlatBuffer *pPrivateKey)
{
    if (NULL != pKPTSignRSOpData->privateKey.pData)
        qaeMemFreeNUMA((void **)&pKPTSignRSOpData->privateKey.pData);
    if (NULL != pKPTSignRSOpData->m.pData)
        qaeMemFreeNUMA((void **)&pKPTSignRSOpData->m.pData);
    if (NULL != pWpkAndAuthTag)
    {
        if (NULL != pWpkAndAuthTag->pData)
            qaeMemFree((void **)&pWpkAndAuthTag->pData);
        qaeMemFree((void **)&pWpkAndAuthTag);
    }
    if (NULL != pPrivateKey)
    {
        if (NULL != pPrivateKey->pData)
            qaeMemFree((void **)&pPrivateKey->pData);
        qaeMemFree((void **)&pPrivateKey);
    }

    return;
}

/***************************************************************************
 * @description
 *
 * This function is to set Kpt ECDSA SignRSOpData
 *
 * @param[in]  pSignRSOpData          Unwrapped SignRSOpData
 * @param[in]  instanceHandle         InstanceHandle
 * @param[in]  pSampleSWK             SWK
 * @param[in]  pIv                    iv
 * @param[in]  pAad                   Additional Authenticated Data
 * @param[in]  aadLenInBytes          the length of aad
 * @param[out] pKPTSignRSOpData       Kpt ECDSA SignRSOpData
 *
 * @retval CPA_STATUS_SUCCESS    Operation is successful
 * @retval CPA_STATUS_FAIL       Operation is failure
 ***************************************************************************/
CpaStatus setKPT2EcdsaSignRSOpData(CpaInstanceHandle instanceHandle,
                                   CpaCyKptEcdsaSignRSOpData *pKPTSignRSOpData,
                                   CpaCyEcdsaSignRSOpData *pSignRSOpData,
                                   Cpa8U *pSampleSWK,
                                   Cpa8U *pIv,
                                   Cpa8U *pAad,
                                   Cpa32U aadLenInBytes)
{
    CpaStatus retstatus = CPA_STATUS_SUCCESS;
    CpaBoolean status = CPA_TRUE;
    Cpa32U wpkSize = 0;
    Cpa8U pAuthTag[AUTH_TAG_LEN_IN_BYTES] = {0};
    CpaFlatBuffer *pWpkAndAuthTag = NULL;
    CpaFlatBuffer *pPrivateKey = NULL;
    pWpkAndAuthTag = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pWpkAndAuthTag)
    {
        PRINT_ERR("qaeMemAlloc pWpkAndAuthTag error\n");
        return CPA_STATUS_FAIL;
    }
    pPrivateKey = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pPrivateKey)
    {
        PRINT_ERR("qaeMemAlloc pClearKey error\n");
        qaeMemFree((void **)&pWpkAndAuthTag);
        return CPA_STATUS_FAIL;
    }
    if (GFP_P521_SIZE_IN_BYTES == pSignRSOpData->d.dataLenInBytes)
    {
        pWpkAndAuthTag->dataLenInBytes =
            KPT2_ECDSA_P521_WPK_SIZE_IN_BYTES + AUTH_TAG_LEN_IN_BYTES;
        pPrivateKey->dataLenInBytes = KPT2_ECDSA_P521_WPK_SIZE_IN_BYTES;
    }
    else
    {
        pWpkAndAuthTag->dataLenInBytes =
            pSignRSOpData->d.dataLenInBytes + AUTH_TAG_LEN_IN_BYTES;
        pPrivateKey->dataLenInBytes = pSignRSOpData->d.dataLenInBytes;
    }
    pWpkAndAuthTag->pData = qaeMemAlloc(pWpkAndAuthTag->dataLenInBytes);
    if (NULL == pWpkAndAuthTag->pData)
    {
        PRINT_ERR("qaeMemAlloc pWpkAndAuthTag->pData error\n");
        qaeMemFree((void **)&pPrivateKey);
        qaeMemFree((void **)&pWpkAndAuthTag);
        return CPA_STATUS_FAIL;
    }
    pPrivateKey->pData = qaeMemAlloc(pPrivateKey->dataLenInBytes);
    if (NULL == pPrivateKey->pData)
    {
        PRINT_ERR("qaeMemAlloc pClearKey->pData error\n");
        qaeMemFree((void **)&pPrivateKey);
        qaeMemFree((void **)&pWpkAndAuthTag->pData);
        qaeMemFree((void **)&pWpkAndAuthTag);
        return CPA_STATUS_FAIL;
    }
    memset(pPrivateKey->pData, 0, pPrivateKey->dataLenInBytes);
    memcpy(pPrivateKey->pData + pPrivateKey->dataLenInBytes -
               pSignRSOpData->d.dataLenInBytes,
           pSignRSOpData->d.pData,
           pSignRSOpData->d.dataLenInBytes);
    memset(pWpkAndAuthTag->pData, 0, pWpkAndAuthTag->dataLenInBytes);
    status = encryptPrivateKey(pPrivateKey->pData,
                               pPrivateKey->dataLenInBytes,
                               pSampleSWK,
                               pIv,
                               IV_LEN_IN_BYTES,
                               pWpkAndAuthTag->pData,
                               &wpkSize,
                               pAuthTag,
                               pAad,
                               aadLenInBytes);
    if (CPA_FALSE == status)
    {
        kpt2FreeECDSAOPDataMemory(
            pKPTSignRSOpData, pWpkAndAuthTag, pPrivateKey);
        PRINT_ERR("encryptPrivateKey failed!\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS == retstatus)
    {
        /* Concatenated with AuthTag */
        memcpy(
            pWpkAndAuthTag->pData + wpkSize, pAuthTag, AUTH_TAG_LEN_IN_BYTES);

        /* Opdata setup */
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pKPTSignRSOpData->privateKey),
                             pWpkAndAuthTag->dataLenInBytes,
                             pWpkAndAuthTag->pData,
                             pWpkAndAuthTag->dataLenInBytes,
                             kpt2FreeECDSAOPDataMemory(pKPTSignRSOpData,
                                                       pWpkAndAuthTag,
                                                       pPrivateKey));
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pKPTSignRSOpData->m),
                             pSignRSOpData->m.dataLenInBytes,
                             pSignRSOpData->m.pData,
                             pSignRSOpData->m.dataLenInBytes,
                             kpt2FreeECDSAOPDataMemory(pKPTSignRSOpData,
                                                       pWpkAndAuthTag,
                                                       pPrivateKey));
    }

    if (NULL != pWpkAndAuthTag && NULL != pWpkAndAuthTag->pData)
    {
        qaeMemFree((void **)&pWpkAndAuthTag->pData);
    }
    if (NULL != pWpkAndAuthTag)
    {
        qaeMemFree((void **)&pWpkAndAuthTag);
    }
    if (NULL != pPrivateKey && NULL != pPrivateKey->pData)
    {
        qaeMemFree((void **)&pPrivateKey->pData);
    }
    if (NULL != pPrivateKey)
    {
        qaeMemFree((void **)&pPrivateKey);
    }

    return retstatus;
}

/**
 *****************************************************************************
 * @ingroup sampleKPTECDSACode
 *
 * @description
 *      Function for setup KPT ECDSA test before calling framework createThreads
 *      functions
 *
 *****************************************************************************/
CpaStatus setupKpt2EcdsaTest(Cpa32U nLenInBits,
                             CpaCyEcFieldType fieldType,
                             sync_mode_t syncMode,
                             ecdsa_step_t step,
                             Cpa32U numBuffers,
                             Cpa32U numLoops)
{
    ecdsa_test_params_t *ecdsaSetup = NULL;

    ecdsaSetup = (ecdsa_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    ecdsaSetup->enableKPT = CPA_TRUE;

    return setupEcdsaTest(
        nLenInBits, fieldType, syncMode, step, numBuffers, numLoops);
}

/******************************************************************************
 * @ingroup sampleECDSACode
 *
 * @description
 * This function frees all memory related to KPT2 data.
 * ****************************************************************************/
void kpt2EcdsaFreeDataMemory(CpaCyKptEcdsaSignRSOpData *pKPTSignRSOpData,
                             CpaCyKptUnwrapContext *pKptUnwrapCtx)
{
    if (NULL != pKPTSignRSOpData)
    {
        if (NULL != pKPTSignRSOpData->privateKey.pData)
        {
            qaeMemFreeNUMA((void **)&pKPTSignRSOpData->privateKey.pData);
        }
        if (NULL != pKPTSignRSOpData->m.pData)
        {
            qaeMemFreeNUMA((void **)&pKPTSignRSOpData->m.pData);
        }
        qaeMemFreeNUMA((void **)&pKPTSignRSOpData);
    }
    if (NULL != pKptUnwrapCtx)
    {
        qaeMemFreeNUMA((void **)&pKptUnwrapCtx);
    }
    return;
}
EXPORT_SYMBOL(kpt2EcdsaFreeDataMemory);
#endif
