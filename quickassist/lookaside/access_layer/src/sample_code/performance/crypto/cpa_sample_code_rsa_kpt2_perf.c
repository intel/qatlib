/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
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
void kptFreeRSAOPDataMemory(CpaCyKptRsaDecryptOpData *pKPTDecryptOpData)
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
    CpaStatus retstatus = CPA_STATUS_SUCCESS;
    CpaBoolean status = CPA_TRUE;
    Cpa32U wpkSize = 0;
    Cpa8U pAuthTag[AUTH_TAG_LEN_IN_BYTES] = {0};
    CpaFlatBuffer *pWpkAndAuthTag = NULL;
    CpaFlatBuffer *pPrivateKeyOfType1 = NULL;
    CpaFlatBuffer *pPrivateKeyOfType2 = NULL;
    *pKPTDecryptOpData = qaeMemAllocNUMA(
        sizeof(CpaCyKptRsaDecryptOpData *), node, BYTE_ALIGNMENT_64);
    if (NULL == *pKPTDecryptOpData)
    {
        PRINT_ERR("qaeMemAllocNUMA pKPTDecryptOpData error\n");
        return CPA_STATUS_FAIL;
    }

    (*pKPTDecryptOpData)->pRecipientPrivateKey = qaeMemAllocNUMA(
        sizeof(CpaCyKptRsaPrivateKey *), node, BYTE_ALIGNMENT_64);
    if (NULL == (*pKPTDecryptOpData)->pRecipientPrivateKey)
    {
        PRINT_ERR(
            "qaeMemAllocNUMA pKPTDecryptOpData->pRecipientPrivateKey error\n");
        qaeMemFreeNUMA((void **)&(*pKPTDecryptOpData));
        return CPA_STATUS_FAIL;
    }
    pPrivateKeyOfType1 = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pPrivateKeyOfType1)
    {
        PRINT_ERR("qaeMemAlloc pPrivateKeyOfType1 error\n");
        qaeMemFreeNUMA((void **)&((*pKPTDecryptOpData)->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&(*pKPTDecryptOpData));
        return CPA_STATUS_FAIL;
    }
    pPrivateKeyOfType2 = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pPrivateKeyOfType2)
    {
        PRINT_ERR("qaeMemAlloc pPrivateKeyOfType2 error\n");
        qaeMemFree((void **)&pPrivateKeyOfType1);
        qaeMemFreeNUMA((void **)&((*pKPTDecryptOpData)->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&(*pKPTDecryptOpData));
        return CPA_STATUS_FAIL;
    }
    pWpkAndAuthTag = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pWpkAndAuthTag)
    {
        PRINT_ERR("qaeMemAlloc pWpkAndAuthTag error\n");
        qaeMemFree((void **)&pPrivateKeyOfType1);
        qaeMemFree((void **)&pPrivateKeyOfType2);
        qaeMemFreeNUMA((void **)&((*pKPTDecryptOpData)->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&(*pKPTDecryptOpData));
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

        pPrivateKeyOfType1->pData =
            qaeMemAlloc(pPrivateKeyOfType1->dataLenInBytes);
        if (NULL == pPrivateKeyOfType1->pData)
        {
            PRINT_ERR("qaeMemAlloc pPrivateKeyOfType1->pData error\n");
            kptFreeRSAOPDataMemory(*pKPTDecryptOpData);
            retstatus = CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_SUCCESS == retstatus)
        {
            memset(pPrivateKeyOfType1->pData,
                   0,
                   pPrivateKeyOfType1->dataLenInBytes);

            memcpy(pPrivateKeyOfType1->pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                       .privateExponentD.pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                       .privateExponentD.dataLenInBytes);

            memcpy(pPrivateKeyOfType1->pData +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep1
                           .privateExponentD.dataLenInBytes,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep1.modulusN
                       .pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep1.modulusN
                       .dataLenInBytes);

            pWpkAndAuthTag->dataLenInBytes =
                pPrivateKeyOfType1->dataLenInBytes + AUTH_TAG_LEN_IN_BYTES;
            pWpkAndAuthTag->pData = qaeMemAlloc(pWpkAndAuthTag->dataLenInBytes);
            if (NULL == pWpkAndAuthTag->pData)
            {
                PRINT_ERR("qaeMemAlloc pWpkAndAuthTag->pData error\n");
                kptFreeRSAOPDataMemory(*pKPTDecryptOpData);
                retstatus = CPA_STATUS_FAIL;
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
                kptFreeRSAOPDataMemory(*pKPTDecryptOpData);
                retstatus = CPA_STATUS_FAIL;
            }
        }
        if (CPA_STATUS_SUCCESS == retstatus)
        {
            /* Concatenated with AuthTag */
            memcpy(pWpkAndAuthTag->pData + wpkSize,
                   pAuthTag,
                   AUTH_TAG_LEN_IN_BYTES);

            /* Opdata setup */
            ALLOC_FLAT_BUFF_DATA(instanceHandle,
                                 &((*pKPTDecryptOpData)->inputData),
                                 pDecryptOpData->inputData.dataLenInBytes,
                                 pDecryptOpData->inputData.pData,
                                 pDecryptOpData->inputData.dataLenInBytes,
                                 kptFreeRSAOPDataMemory(*pKPTDecryptOpData));

            ALLOC_FLAT_BUFF_DATA(
                instanceHandle,
                &((*pKPTDecryptOpData)
                      ->pRecipientPrivateKey->privateKeyRep1.privateKey),
                wpkSize + AUTH_TAG_LEN_IN_BYTES,
                pWpkAndAuthTag->pData,
                wpkSize + AUTH_TAG_LEN_IN_BYTES,
                kptFreeRSAOPDataMemory(*pKPTDecryptOpData));

            (*pKPTDecryptOpData)->pRecipientPrivateKey->version =
                pDecryptOpData->pRecipientPrivateKey->version;

            (*pKPTDecryptOpData)->pRecipientPrivateKey->privateKeyRepType =
                pDecryptOpData->pRecipientPrivateKey->privateKeyRepType;
        }
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

        pPrivateKeyOfType2->pData =
            qaeMemAlloc(pPrivateKeyOfType2->dataLenInBytes);
        if (NULL == pPrivateKeyOfType2->pData)
        {
            PRINT_ERR("qaeMemAlloc pPrivateKeyOfType2->pData error\n");
            kptFreeRSAOPDataMemory(*pKPTDecryptOpData);
            retstatus = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == retstatus)
        {
            memset(pPrivateKeyOfType2->pData,
                   0,
                   pPrivateKeyOfType2->dataLenInBytes);

            memcpy(pPrivateKeyOfType2->pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                       .pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime1P
                       .dataLenInBytes);

            memcpy(pPrivateKeyOfType2->pData +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime1P.dataLenInBytes,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                       .pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2.prime2Q
                       .dataLenInBytes);

            memcpy(pPrivateKeyOfType2->pData +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime1P.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime2Q.dataLenInBytes,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent1Dp.pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent1Dp.dataLenInBytes);

            memcpy(pPrivateKeyOfType2->pData +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime1P.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime2Q.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .exponent1Dp.dataLenInBytes,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent2Dq.pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .exponent2Dq.dataLenInBytes);

            memcpy(pPrivateKeyOfType2->pData +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime1P.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime2Q.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .exponent1Dp.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .exponent2Dq.dataLenInBytes,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .coefficientQInv.pData,
                   pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                       .coefficientQInv.dataLenInBytes);

            memcpy(pPrivateKeyOfType2->pData +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime1P.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .prime2Q.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .exponent1Dp.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .exponent2Dq.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                           .coefficientQInv.dataLenInBytes +
                       pDecryptOpData->pRecipientPrivateKey->privateKeyRep2
                               .prime1P.dataLenInBytes *
                           NUM_KEY_PAIRS -
                       pRsaPublicKey->publicExponentE.dataLenInBytes,
                   pRsaPublicKey->publicExponentE.pData,
                   pRsaPublicKey->publicExponentE.dataLenInBytes);

            pWpkAndAuthTag->dataLenInBytes =
                pPrivateKeyOfType2->dataLenInBytes + AUTH_TAG_LEN_IN_BYTES;
            pWpkAndAuthTag->pData = qaeMemAlloc(pWpkAndAuthTag->dataLenInBytes);
            if (NULL == pWpkAndAuthTag->pData)
            {
                PRINT_ERR("qaeMemAlloc pWpkAndAuthTag->pData error\n");
                kptFreeRSAOPDataMemory(*pKPTDecryptOpData);
                retstatus = CPA_STATUS_FAIL;
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
                kptFreeRSAOPDataMemory(*pKPTDecryptOpData);
                retstatus = CPA_STATUS_FAIL;
            }
        }
        if (CPA_STATUS_SUCCESS == retstatus)
        {
            /* Concatenated with AuthTag */
            memcpy(pWpkAndAuthTag->pData + wpkSize,
                   pAuthTag,
                   AUTH_TAG_LEN_IN_BYTES);
            /* Opdata setup */
            ALLOC_FLAT_BUFF_DATA(instanceHandle,
                                 &((*pKPTDecryptOpData)->inputData),
                                 pDecryptOpData->inputData.dataLenInBytes,
                                 pDecryptOpData->inputData.pData,
                                 pDecryptOpData->inputData.dataLenInBytes,
                                 kptFreeRSAOPDataMemory(*pKPTDecryptOpData));

            ALLOC_FLAT_BUFF_DATA(
                instanceHandle,
                &((*pKPTDecryptOpData)
                      ->pRecipientPrivateKey->privateKeyRep2.privateKey),
                wpkSize + AUTH_TAG_LEN_IN_BYTES,
                pWpkAndAuthTag->pData,
                wpkSize + AUTH_TAG_LEN_IN_BYTES,
                kptFreeRSAOPDataMemory(*pKPTDecryptOpData));

            (*pKPTDecryptOpData)->pRecipientPrivateKey->version =
                pDecryptOpData->pRecipientPrivateKey->version;

            (*pKPTDecryptOpData)->pRecipientPrivateKey->privateKeyRepType =
                pDecryptOpData->pRecipientPrivateKey->privateKeyRepType;
        }
    }

    if (NULL != pPrivateKeyOfType1->pData)
    {
        qaeMemFree((void **)&pPrivateKeyOfType1->pData);
    }
    if (NULL != pPrivateKeyOfType1)
    {
        qaeMemFree((void **)&pPrivateKeyOfType1);
    }

    if (NULL != pPrivateKeyOfType2->pData)
    {
        qaeMemFree((void **)&pPrivateKeyOfType2->pData);
    }
    if (NULL != pPrivateKeyOfType2)
    {
        qaeMemFree((void **)&pPrivateKeyOfType2);
    }
    if (NULL != pWpkAndAuthTag->pData)
    {
        qaeMemFree((void **)&pWpkAndAuthTag->pData);
    }
    if (NULL != pWpkAndAuthTag)
    {
        qaeMemFree((void **)&pWpkAndAuthTag);
    }

    return retstatus;
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
