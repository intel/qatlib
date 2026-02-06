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
 * @file cpa_sample_code_rsa_kpt2_perf.c
 *
 * This file provides some interface for kpt2 RSA performance test.
 *
 **************************************************************************/
#include "cpa_sample_code_rsa_kpt2_perf.h"
#if CY_API_VERSION_AT_LEAST(3, 0)
void kptFreeRSAOPDataMemory(CpaCyKptRsaDecryptOpData *pKPTDecryptOpData,
                            CpaFlatBuffer *pWpkAndAuthTag,
                            CpaFlatBuffer *pPrivateKeyOfType1,
                            CpaFlatBuffer *pPrivateKeyOfType2)
{
    if (NULL != pKPTDecryptOpData->inputData.pData)
        qaeMemFreeNUMA((void **)&pKPTDecryptOpData->inputData.pData);
    if (NULL != pKPTDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                    .privateKey.pData)
        qaeMemFreeNUMA((void **)&pKPTDecryptOpData->pRecipientPrivateKey
                           ->privateKeyRep1.privateKey.pData);
    if (NULL != pKPTDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                    .privateKey.pData)
        qaeMemFreeNUMA((void **)&pKPTDecryptOpData->pRecipientPrivateKey
                           ->privateKeyRep2.privateKey.pData);
    qaeMemFreeNUMA((void **)&pKPTDecryptOpData->pRecipientPrivateKey);
    qaeMemFreeNUMA((void **)&pKPTDecryptOpData);
    if (NULL != pWpkAndAuthTag)
    {
        if (NULL != pWpkAndAuthTag->pData)
            qaeMemFreeNUMA((void **)&pWpkAndAuthTag->pData);
        qaeMemFree((void **)&pWpkAndAuthTag);
    }
    if (NULL != pPrivateKeyOfType1)
    {
        if (NULL != pPrivateKeyOfType1->pData)
            qaeMemFreeNUMA((void **)&pPrivateKeyOfType1->pData);
        qaeMemFree((void **)&pPrivateKeyOfType1);
    }
    if (NULL != pPrivateKeyOfType2)
    {
        if (NULL != pPrivateKeyOfType2->pData)
            qaeMemFreeNUMA((void **)&pPrivateKeyOfType2->pData);
        qaeMemFree((void **)&pPrivateKeyOfType2);
    }

    return;
}
EXPORT_SYMBOL(kptFreeRSAOPDataMemory);

/***************************************************************************
 * @description
 *
 * This function is to set Kpt Rsa Decrypt OpData
 *
 * @param[in]  instanceHandle         instanceHandle
 * @param[in]  pDecryptOpData         Unwrapped Decrypt OpData
 * @param[in]  pRsaPublicKey          RSA public key
 * @param[in]  node                   node
 * @param[in]  pSampleSWK             SWK
 * @param[in]  pIv                    iv
 * @param[in]  pAad                   Additional Authenticated Data
 * @param[in]  aadLenInBytes          the length of aad
 * @param[out] pKPTDecryptOpData      Kpt Rsa Decrypt OpData
 *
 * @retval CPA_STATUS_SUCCESS    Operation is successful
 * @retval CPA_STATUS_FAIL       Operation is failure
 ***************************************************************************/
CpaStatus setKpt2RsaDecryptOpData(CpaInstanceHandle instanceHandle,
                                  CpaCyKptRsaDecryptOpData **pKPTDecryptOpData,
                                  CpaCyRsaDecryptOpData *pDecryptOpData,
                                  CpaCyRsaPublicKey *pRsaPublicKey,
                                  Cpa32U node,
                                  Cpa8U *pSampleSWK,
                                  Cpa8U *pIv,
                                  Cpa8U *pAad,
                                  Cpa32U aadLenInBytes)
{
    CpaBoolean status = CPA_TRUE;
    Cpa32U wpkSize = 0;
    Cpa8U pAuthTag[AUTH_TAG_LEN_IN_BYTES] = {0};
    CpaFlatBuffer *pWpkAndAuthTag = NULL;
    CpaFlatBuffer *pPrivateKeyOfType1 = NULL;
    CpaFlatBuffer *pPrivateKeyOfType2 = NULL;
    CpaCyKptRsaDecryptOpData *pKptDecOpdata = NULL;

    pKptDecOpdata = qaeMemAllocNUMA(
        sizeof(CpaCyKptRsaDecryptOpData), node, BYTE_ALIGNMENT_64);
    if (NULL == pKptDecOpdata)
    {
        PRINT_ERR("qaeMemAllocNUMA pKptDecOpdata error\n");
        return CPA_STATUS_FAIL;
    }

    pKptDecOpdata->pRecipientPrivateKey =
        qaeMemAllocNUMA(sizeof(CpaCyKptRsaPrivateKey), node, BYTE_ALIGNMENT_64);
    if (NULL == pKptDecOpdata->pRecipientPrivateKey)
    {
        PRINT_ERR(
            "qaeMemAllocNUMA pKPTDecryptOpData->pRecipientPrivateKey error\n");
        qaeMemFreeNUMA((void **)&pKptDecOpdata);
        return CPA_STATUS_FAIL;
    }
    pPrivateKeyOfType1 = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pPrivateKeyOfType1)
    {
        PRINT_ERR("qaeMemAlloc pPrivateKeyOfType1 error\n");
        qaeMemFreeNUMA((void **)&(pKptDecOpdata->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&pKptDecOpdata);
        return CPA_STATUS_FAIL;
    }
    pPrivateKeyOfType2 = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pPrivateKeyOfType2)
    {
        PRINT_ERR("qaeMemAlloc pPrivateKeyOfType2 error\n");
        qaeMemFree((void **)&pPrivateKeyOfType1);
        qaeMemFreeNUMA((void **)&(pKptDecOpdata->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&pKptDecOpdata);
        return CPA_STATUS_FAIL;
    }
    pWpkAndAuthTag = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pWpkAndAuthTag)
    {
        PRINT_ERR("qaeMemAlloc pWpkAndAuthTag error\n");
        qaeMemFree((void **)&pPrivateKeyOfType1);
        qaeMemFree((void **)&pPrivateKeyOfType2);
        qaeMemFreeNUMA((void **)&(pKptDecOpdata->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&pKptDecOpdata);
        return CPA_STATUS_FAIL;
    }

    if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 ==
        pDecryptOpData->pRecipientPrivateKey->privateKeyRepType)
    {
        pPrivateKeyOfType1->dataLenInBytes =
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                .privateExponentD.dataLenInBytes +
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep1.modulusN
                .dataLenInBytes;

        pPrivateKeyOfType1->pData = qaeMemAllocNUMA(
            pPrivateKeyOfType1->dataLenInBytes, node, BYTE_ALIGNMENT_64);
        if (NULL == pPrivateKeyOfType1->pData)
        {
            PRINT_ERR("qaeMemAlloc pPrivateKeyOfType1->pData error\n");
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2);
            return CPA_STATUS_FAIL;
        }
        memset(
            pPrivateKeyOfType1->pData, 0, pPrivateKeyOfType1->dataLenInBytes);

        memcpy(pPrivateKeyOfType1->pData,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                   .privateExponentD.pData,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                   .privateExponentD.dataLenInBytes);

        memcpy(
            pPrivateKeyOfType1->pData +
                pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                    .privateExponentD.dataLenInBytes,
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep1.modulusN.pData,
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep1.modulusN
                .dataLenInBytes);

        pWpkAndAuthTag->dataLenInBytes =
            pPrivateKeyOfType1->dataLenInBytes + AUTH_TAG_LEN_IN_BYTES;
        pWpkAndAuthTag->pData = qaeMemAllocNUMA(
            pWpkAndAuthTag->dataLenInBytes, node, BYTE_ALIGNMENT_64);
        if (NULL == pWpkAndAuthTag->pData)
        {
            PRINT_ERR("qaeMemAlloc pWpkAndAuthTag->pData error\n");
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2);
            return CPA_STATUS_FAIL;
        }

        status = encryptPrivateKey(pPrivateKeyOfType1->pData,
                                   pPrivateKeyOfType1->dataLenInBytes,
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
            PRINT_ERR("encyPrivateKey failed!\n");
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2);
            return CPA_STATUS_FAIL;
        }
        /* Concatenated with AuthTag */
        memcpy(
            pWpkAndAuthTag->pData + wpkSize, pAuthTag, AUTH_TAG_LEN_IN_BYTES);

        /* Opdata setup */
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pKptDecOpdata->inputData),
                             pDecryptOpData->inputData.dataLenInBytes,
                             pDecryptOpData->inputData.pData,
                             pDecryptOpData->inputData.dataLenInBytes,
                             kptFreeRSAOPDataMemory(pKptDecOpdata,
                                                    pWpkAndAuthTag,
                                                    pPrivateKeyOfType1,
                                                    pPrivateKeyOfType2));

        ALLOC_FLAT_BUFF_DATA(
            instanceHandle,
            &(pKptDecOpdata->pRecipientPrivateKey->privateKeyRep1.privateKey),
            wpkSize + AUTH_TAG_LEN_IN_BYTES,
            pWpkAndAuthTag->pData,
            wpkSize + AUTH_TAG_LEN_IN_BYTES,
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2));

        pKptDecOpdata->pRecipientPrivateKey->version =
            pDecryptOpData->pRecipientPrivateKey->version;

        pKptDecOpdata->pRecipientPrivateKey->privateKeyRepType =
            pDecryptOpData->pRecipientPrivateKey->privateKeyRepType;
    }
    else
    {
        pPrivateKeyOfType2->dataLenInBytes =
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.coefficientQInv
                .dataLenInBytes +
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.exponent1Dp
                .dataLenInBytes +
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.exponent2Dq
                .dataLenInBytes +
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                .dataLenInBytes +
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                .dataLenInBytes +
            /* publicExponentE is only 3bytes, so the value of
               publicExponentE.dataLenInBytes is 3,
               but the length of publicExponentE required by the driver is twice
               that of prime1P,
               so here is twice that of prime1P.dataLenInBytes. */
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                    .dataLenInBytes *
                NUM_KEY_PAIRS;

        pPrivateKeyOfType2->pData = qaeMemAllocNUMA(
            pPrivateKeyOfType2->dataLenInBytes, node, BYTE_ALIGNMENT_64);
        if (NULL == pPrivateKeyOfType2->pData)
        {
            PRINT_ERR("qaeMemAlloc pPrivateKeyOfType2->pData error\n");
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2);
            return CPA_STATUS_FAIL;
        }

        memset(
            pPrivateKeyOfType2->pData, 0, pPrivateKeyOfType2->dataLenInBytes);

        memcpy(
            pPrivateKeyOfType2->pData,
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P.pData,
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                .dataLenInBytes);

        memcpy(
            pPrivateKeyOfType2->pData +
                pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                    .dataLenInBytes,
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q.pData,
            pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                .dataLenInBytes);

        memcpy(pPrivateKeyOfType2->pData +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                       .dataLenInBytes,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.exponent1Dp
                   .pData,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.exponent1Dp
                   .dataLenInBytes);

        memcpy(pPrivateKeyOfType2->pData +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent1Dp.dataLenInBytes,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.exponent2Dq
                   .pData,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.exponent2Dq
                   .dataLenInBytes);

        memcpy(pPrivateKeyOfType2->pData +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent1Dp.dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent2Dq.dataLenInBytes,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                   .coefficientQInv.pData,
               pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                   .coefficientQInv.dataLenInBytes);

        memcpy(pPrivateKeyOfType2->pData +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                       .dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent1Dp.dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent2Dq.dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .coefficientQInv.dataLenInBytes +
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                           .dataLenInBytes *
                       NUM_KEY_PAIRS -
                   pRsaPublicKey->publicExponentE.dataLenInBytes,
               pRsaPublicKey->publicExponentE.pData,
               pRsaPublicKey->publicExponentE.dataLenInBytes);

        pWpkAndAuthTag->dataLenInBytes =
            pPrivateKeyOfType2->dataLenInBytes + AUTH_TAG_LEN_IN_BYTES;
        pWpkAndAuthTag->pData = qaeMemAllocNUMA(
            pWpkAndAuthTag->dataLenInBytes, node, BYTE_ALIGNMENT_64);
        if (NULL == pWpkAndAuthTag->pData)
        {
            PRINT_ERR("qaeMemAlloc pWpkAndAuthTag->pData error\n");
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2);
            return CPA_STATUS_FAIL;
        }

        status = encryptPrivateKey(pPrivateKeyOfType2->pData,
                                   pPrivateKeyOfType2->dataLenInBytes,
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
            PRINT_ERR("encyPrivateKey failed!\n");
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2);
            return CPA_STATUS_FAIL;
        }
        /* Concatenated with AuthTag */
        memcpy(
            pWpkAndAuthTag->pData + wpkSize, pAuthTag, AUTH_TAG_LEN_IN_BYTES);
        /* Opdata setup */
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pKptDecOpdata->inputData),
                             pDecryptOpData->inputData.dataLenInBytes,
                             pDecryptOpData->inputData.pData,
                             pDecryptOpData->inputData.dataLenInBytes,
                             kptFreeRSAOPDataMemory(pKptDecOpdata,
                                                    pWpkAndAuthTag,
                                                    pPrivateKeyOfType1,
                                                    pPrivateKeyOfType2));

        ALLOC_FLAT_BUFF_DATA(
            instanceHandle,
            &(pKptDecOpdata->pRecipientPrivateKey->privateKeyRep2.privateKey),
            wpkSize + AUTH_TAG_LEN_IN_BYTES,
            pWpkAndAuthTag->pData,
            wpkSize + AUTH_TAG_LEN_IN_BYTES,
            kptFreeRSAOPDataMemory(pKptDecOpdata,
                                   pWpkAndAuthTag,
                                   pPrivateKeyOfType1,
                                   pPrivateKeyOfType2));

        pKptDecOpdata->pRecipientPrivateKey->version =
            pDecryptOpData->pRecipientPrivateKey->version;

        pKptDecOpdata->pRecipientPrivateKey->privateKeyRepType =
            pDecryptOpData->pRecipientPrivateKey->privateKeyRepType;
    }

    *pKPTDecryptOpData = pKptDecOpdata;

    if (NULL != pPrivateKeyOfType1)
    {
        if (NULL != pPrivateKeyOfType1->pData)
        {
            qaeMemFreeNUMA((void **)&pPrivateKeyOfType1->pData);
        }
        qaeMemFree((void **)&pPrivateKeyOfType1);
    }
    if (NULL != pPrivateKeyOfType2)
    {
        if (NULL != pPrivateKeyOfType2->pData)
        {
            qaeMemFreeNUMA((void **)&pPrivateKeyOfType2->pData);
        }
        qaeMemFree((void **)&pPrivateKeyOfType2);
    }
    if (NULL != pWpkAndAuthTag)
    {
        if (NULL != pWpkAndAuthTag->pData)
        {
            qaeMemFreeNUMA((void **)&pWpkAndAuthTag->pData);
        }
        qaeMemFree((void **)&pWpkAndAuthTag);
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setKpt2RsaDecryptOpData);

/**
 *****************************************************************************
 * @ingroup sampleKPTRSACode
 *
 * @description
 *      Function for setup KPT RSA test before calling framework createThreads
 *      functions
 *
 *****************************************************************************/
CpaStatus setupKpt2RsaTest(Cpa32U modulusSize,
                           CpaCyRsaPrivateKeyRepType rsaKeyRepType,
                           sync_mode_t syncMode,
                           Cpa32U numBuffs,
                           Cpa32U numLoops)
{
    asym_test_params_t *rsaSetup = NULL;

    rsaSetup = (asym_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    rsaSetup->enableKPT = CPA_TRUE;

    return setupRsaTest(
        modulusSize, rsaKeyRepType, syncMode, numBuffs, numLoops);
}
EXPORT_SYMBOL(setupKpt2RsaTest);

/******************************************************************************
 * @ingroup sampleKPTRSACode
 *
 * @description
 * This function frees all memory related to KPT2 data.
 ******************************************************************************/
void kpt2RsaFreeDataMemory(asym_test_params_t *setup,
                           CpaCyKptUnwrapContext **pKptUnwrapCtx,
                           CpaCyKptRsaDecryptOpData **ppKPTDecryptOpData)
{
    Cpa32U bufferCount = 0;

    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        if (NULL != ppKPTDecryptOpData)
        {
            if (NULL != ppKPTDecryptOpData[bufferCount])
            {
                if (NULL != ppKPTDecryptOpData[bufferCount]->inputData.pData)
                {
                    qaeMemFreeNUMA((void **)&ppKPTDecryptOpData[bufferCount]
                                       ->inputData.pData);
                }
                if (NULL !=
                    ppKPTDecryptOpData[bufferCount]
                        ->pRecipientPrivateKey->privateKeyRep1.privateKey.pData)
                {
                    qaeMemFreeNUMA((void **)&ppKPTDecryptOpData[bufferCount]
                                       ->pRecipientPrivateKey->privateKeyRep1
                                       .privateKey.pData);
                }
                if (NULL !=
                    ppKPTDecryptOpData[bufferCount]
                        ->pRecipientPrivateKey->privateKeyRep2.privateKey.pData)
                {
                    qaeMemFreeNUMA((void **)&ppKPTDecryptOpData[bufferCount]
                                       ->pRecipientPrivateKey->privateKeyRep2
                                       .privateKey.pData);
                }
                qaeMemFreeNUMA((void **)&ppKPTDecryptOpData[bufferCount]
                                   ->pRecipientPrivateKey);
                qaeMemFreeNUMA((void **)&ppKPTDecryptOpData[bufferCount]);
            }
        }
        if (NULL != pKptUnwrapCtx)
        {
            if (NULL != pKptUnwrapCtx[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pKptUnwrapCtx[bufferCount]);
            }
        }
    }
    return;
}
EXPORT_SYMBOL(kpt2RsaFreeDataMemory);
#endif
