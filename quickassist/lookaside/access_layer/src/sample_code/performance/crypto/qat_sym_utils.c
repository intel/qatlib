/****************************************************************************
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
 ***************************************************************************/
#include "qat_sym_utils.h"
#include "cpa_dc.h"
#include "../common/qat_perf_buffer_utils.h"
#include "qat_compression_main.h"

#define EVEN_NUMBER (2)

extern CpaBoolean usePartial_g;
extern Cpa32U symPollingInterval_g;

CpaStatus qatFreeSymLists(CpaBufferList **srcBufferListArray,
                          CpaBufferList **copyBufferListArray,
                          CpaCySymOpData **encryptOpData,
                          CpaCySymOpData **decryptOpData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

    status = FreeArrayOfStructures((void **)srcBufferListArray);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free srcBufferListArray");
        retStatus = CPA_STATUS_FAIL;
    }
    status = FreeArrayOfStructures((void **)copyBufferListArray);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free copyBufferListArray");
        retStatus = CPA_STATUS_FAIL;
    }

    status = FreeArrayOfStructures((void **)encryptOpData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free encryptOpData");
        retStatus = CPA_STATUS_FAIL;
    }

    status = FreeArrayOfStructures((void **)decryptOpData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free decryptOpData");
        retStatus = CPA_STATUS_FAIL;
    }
    return retStatus;
}

CpaStatus qatAllocateSymLists(symmetric_test_params_t *setup,
                              CpaBufferList **srcBufferListArray,
                              CpaBufferList **copyBufferListArray,
                              CpaCySymOpData **encryptOpData,
                              CpaCySymOpData **decryptOpData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = AllocArrayOfStructures((void **)srcBufferListArray,
                                    setup->numBuffLists,
                                    sizeof(CpaBufferList));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not allocate memory for srcBufferListArray\n");
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocArrayOfStructures((void **)copyBufferListArray,
                                        setup->numBuffers,
                                        sizeof(CpaBufferList));
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate copyBufferListArray\n");
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocArrayOfStructures((void **)encryptOpData,
                                        setup->numBuffLists,
                                        sizeof(CpaCySymOpData));

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate encryptOpData\n");
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocArrayOfStructures((void **)decryptOpData,
                                        setup->numBuffLists,
                                        sizeof(CpaCySymOpData));

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate decryptOpData\n");
        }
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        /*something went wrong so attempt to free allocated structures
         * Don't capture the status here as we want to return non success anyway
         */
        qatFreeSymLists(srcBufferListArray,
                        copyBufferListArray,
                        encryptOpData,
                        decryptOpData);
    }
    return status;
}

CpaStatus qatFreeSymFlatBuffers(symmetric_test_params_t *setup,
                                CpaBufferList *srcBufferListArray,
                                CpaBufferList *copyBufferListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (CPA_STATUS_SUCCESS !=
        freeBuffersInLists(srcBufferListArray, setup->numBuffLists))
    {
        PRINT_ERR("freeBuffersInLists (src) error\n");
        status = CPA_STATUS_FAIL;
    }
    // keep trying to free destListArray
    if (CPA_STATUS_SUCCESS !=
        freeBuffersInLists(copyBufferListArray, setup->numBuffLists))
    {
        status = CPA_STATUS_FAIL;
        PRINT_ERR("copyBuffersInLists (dest) error\n");
    }

    return status;
}

CpaStatus qatAllocateSymFlatBuffers(
    symmetric_test_params_t *setup,
    CpaBufferList *srcBufferListArray,
    Cpa32U numBuffersInSrcList,     /*affects the metaSize of CpaBufferList*/
    Cpa32U *sizeOfBuffersInSrcList, /*size of CpaFlatBuffers to  allocate*/
    Cpa32U digestSize,
    CpaBufferList *copyBufferListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U metaSize = 0;

    if (CPA_STATUS_SUCCESS == status)
    {
        // getDcMetaSize required for the src list
        status = cpaCyBufferListGetMetaSize(
            setup->cyInstanceHandle, numBuffersInSrcList, &metaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocateBuffersInLists(srcBufferListArray,
                                        setup->numBuffLists,
                                        numBuffersInSrcList,
                                        sizeOfBuffersInSrcList,
                                        digestSize,
                                        metaSize,
                                        setup->node,
                                        BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocateBuffersInLists(copyBufferListArray,
                                        setup->numBuffLists,
                                        numBuffersInSrcList,
                                        sizeOfBuffersInSrcList,
                                        digestSize,
                                        metaSize,
                                        setup->node,
                                        BYTE_ALIGNMENT_64);
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        // an error has occurred allocating memory so we need to free
        qatFreeSymFlatBuffers(setup, srcBufferListArray, copyBufferListArray);
    }
    return status;
}

CpaStatus qatSymSessionInit(symmetric_test_params_t *setup,
                            CpaCySymSessionCtx *encryptSessionCtx,
                            CpaCySymSessionCtx *decryptSessionCtx,
                            CpaCySymCbFunc pSymCb)
{
    Cpa32U sessionCtxSizeInBytes = 0;
#if CPA_CY_API_VERSION_NUM_MINOR >= 8
    Cpa32U sessionCtxDynamicSizeInBytes = 0;
#endif

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymCipherSetupData *cipherSetupData = NULL;
    CpaCySymHashAuthModeSetupData *authModeSetupData = NULL;
    CpaCySymHashAlgorithm hashAlgorithm = CPA_CY_SYM_HASH_NONE;

    /* Shorten dereference path for more code readability */
    cipherSetupData = &(setup->setupData.cipherSetupData);
    authModeSetupData = &(setup->setupData.hashSetupData.authModeSetupData);
    hashAlgorithm = setup->setupData.hashSetupData.hashAlgorithm;

    /*generate a random cipher and authentication key*/
    /*cipher setup only needs to be set for alg chaining, cipher, AES-GCM
     * and AES-CCM*/
    cipherSetupData->pCipherKey =
        (Cpa8U *)qaeMemAlloc(cipherSetupData->cipherKeyLenInBytes);
    if (NULL == cipherSetupData->pCipherKey)
    {
        PRINT_ERR("Could not allocate pCipherKey\n");
        qatSymSessionTeardown(setup, encryptSessionCtx, decryptSessionCtx);
        return status;
    }

    generateRandomData(cipherSetupData->pCipherKey,
                       cipherSetupData->cipherKeyLenInBytes);

    /*hash setup only needs to be set for hash, AES-GCM and AES-CCM*/
    if (CPA_CY_SYM_HASH_AES_GMAC == hashAlgorithm)
    {
        authModeSetupData->authKey = NULL;
        authModeSetupData->authKeyLenInBytes = 0;
    }
    else
    {
        authModeSetupData->authKey =
            (Cpa8U *)qaeMemAlloc(authModeSetupData->authKeyLenInBytes);
        if (NULL == authModeSetupData->authKey)
        {
            PRINT_ERR("Could not allocate authKey\n");
            qatSymSessionTeardown(setup, encryptSessionCtx, decryptSessionCtx);
            return status;
        }

        generateRandomData(authModeSetupData->authKey,
                           authModeSetupData->authKeyLenInBytes);
    }

    if (CPA_CY_SYM_HASH_SNOW3G_UIA2 == hashAlgorithm
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
        || CPA_CY_SYM_HASH_ZUC_EIA3 == hashAlgorithm
#endif
    )
    {
        authModeSetupData->aadLenInBytes = KEY_SIZE_128_IN_BYTES;
    }
    else
    {
        authModeSetupData->aadLenInBytes = 0;
    }
    /* will not verify digest by default*/
    setup->setupData.verifyDigest = CPA_FALSE;

    /*this is the original API to get the required context size, we show the
     * function used here, but we only use the size for the older version of the
     * API get size for memory allocation*/
    status = cpaCySymSessionCtxGetSize(
        setup->cyInstanceHandle, &setup->setupData, &sessionCtxSizeInBytes);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCySymSessionCtxGetSize error, status: %d", status);
        return status;
    }

#if CPA_CY_API_VERSION_NUM_MINOR >= 8
    /*get dynamic context size*/
    status = cpaCySymSessionCtxGetDynamicSize(setup->cyInstanceHandle,
                                              &setup->setupData,
                                              &sessionCtxDynamicSizeInBytes);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCySymSessionCtxGetDynamicSize error, status: %d", status);
        return status;
    }

    /* compare dynamic context size to normal context size*/
    if (sessionCtxDynamicSizeInBytes > sessionCtxSizeInBytes)
    {
        PRINT_ERR("Dynamic size should not be larger than max size\n");
        return CPA_STATUS_FAIL;
    }
    /*
     * allocate session memory using dynamic context size
     */
    sessionCtxSizeInBytes = sessionCtxDynamicSizeInBytes;
#endif

    *encryptSessionCtx =
        qaeMemAllocNUMA(sessionCtxSizeInBytes, setup->node, BYTE_ALIGNMENT_64);
    if (NULL == *encryptSessionCtx)
    {
        PRINT_ERR("Could not allocate pLocalSession memory\n");
        return CPA_STATUS_FAIL;
    }
    /*zero session memory*/
    memset(*encryptSessionCtx, 0, sessionCtxSizeInBytes);
    /*
     * init session with asynchronous callback- pLocalSession will contain
     * the session context
     */
    status = cpaCySymInitSession(
        setup->cyInstanceHandle, pSymCb, &setup->setupData, *encryptSessionCtx);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCySymInitSession error, status: %d\n", status);
        qatSymSessionTeardown(setup, encryptSessionCtx, decryptSessionCtx);
        return status;
    }

    /*init a second session for the decrypt*/
    cipherSetupData->cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
    if (setup->setupData.algChainOrder ==
        CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH)
    {
        setup->setupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
    }
    else
    {
        setup->setupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
    }

    setup->setupData.verifyDigest = CPA_TRUE;

    /*get size for mem allocation*/
    status = cpaCySymSessionCtxGetSize(
        setup->cyInstanceHandle, &setup->setupData, &sessionCtxSizeInBytes);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCySymSessionCtxGetSize error, status: %d", status);
        return status;
    }

#if CPA_CY_API_VERSION_NUM_MINOR >= 8
    /*get dynamic context size*/
    status = cpaCySymSessionCtxGetDynamicSize(setup->cyInstanceHandle,
                                              &setup->setupData,
                                              &sessionCtxDynamicSizeInBytes);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCySymSessionCtxGetDynamicSize error, status: %d", status);
        return status;
    }
    /* compare dynamic context size to normal context size*/
    if (sessionCtxDynamicSizeInBytes > sessionCtxSizeInBytes)
    {
        PRINT_ERR("Dynamic size should not be larger than max size\n");
        return CPA_STATUS_FAIL;
    }
    /*
     * allocate session memory using dynamic context size
     */
    sessionCtxSizeInBytes = sessionCtxDynamicSizeInBytes;
#endif

    *decryptSessionCtx =
        qaeMemAllocNUMA(sessionCtxSizeInBytes, setup->node, BYTE_ALIGNMENT_64);
    if (NULL == *decryptSessionCtx)
    {
        PRINT_ERR("Could not allocate decryptSessionCtx memory\n");
        qatSymSessionTeardown(setup, encryptSessionCtx, decryptSessionCtx);
        return CPA_STATUS_FAIL;
    }
    memset(*decryptSessionCtx, 0, sessionCtxSizeInBytes);

    status = cpaCySymInitSession(
        setup->cyInstanceHandle, pSymCb, &setup->setupData, *decryptSessionCtx);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCySymInitSession error, status: %d\n", status);
        qatSymSessionTeardown(setup, encryptSessionCtx, *decryptSessionCtx);
        return status;
    }

    return status;
}

CpaStatus qatSymSessionTeardown(symmetric_test_params_t *setup,
                                CpaCySymSessionCtx *encryptSessionCtx,
                                CpaCySymSessionCtx *decryptSessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus returnStatus = CPA_STATUS_SUCCESS;

    status = removeSymSession(setup->cyInstanceHandle, *encryptSessionCtx);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not remove encrypt session context");
        returnStatus = CPA_STATUS_FAIL;
    }

    status = removeSymSession(setup->cyInstanceHandle, *decryptSessionCtx);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not remove decrypt session context");
        returnStatus = CPA_STATUS_FAIL;
    }

    qaeMemFree(
        (void **)&(setup->setupData.hashSetupData.authModeSetupData.authKey));
    if (NULL != setup->setupData.hashSetupData.authModeSetupData.authKey)
    {
        PRINT_ERR("could not free authentication key");
        returnStatus = CPA_STATUS_FAIL;
    }

    qaeMemFree((void **)&(setup->setupData.cipherSetupData.pCipherKey));
    if (NULL != setup->setupData.cipherSetupData.pCipherKey)
    {
        PRINT_ERR("could not free cipher key");
        returnStatus = CPA_STATUS_FAIL;
    }

    qaeMemFreeNUMA((void **)encryptSessionCtx);
    if (NULL != *encryptSessionCtx)
    {
        PRINT_ERR("could not free encrypt session context");
        returnStatus = CPA_STATUS_FAIL;
    }

    qaeMemFreeNUMA((void **)decryptSessionCtx);
    if (NULL != *decryptSessionCtx)
    {
        PRINT_ERR("could not free decrypt session context");
        returnStatus = CPA_STATUS_FAIL;
    }

    return returnStatus;
}

CpaStatus qatSymFreeOpData(symmetric_test_params_t *const pSetup,
                           CpaCySymOpData *const pOpdata)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U idx = 0;

    if (NULL == pOpdata)
    {
        PRINT_ERR("pOpdata is NULL\n");
        return CPA_STATUS_FAIL;
    }

    for (idx = 0; idx < pSetup->numBuffLists; idx++)
    {
        if (NULL != pOpdata[idx].pIv)
        {
            qaeMemFreeNUMA((void **)&(pOpdata[idx].pIv));
        }

        if (NULL != pOpdata[idx].pAdditionalAuthData)
        {
            qaeMemFreeNUMA((void **)&(pOpdata[idx].pAdditionalAuthData));
        }

        if ((NULL != pOpdata[idx].pIv) ||
            (NULL != pOpdata[idx].pAdditionalAuthData))
        {
            PRINT_ERR("Failed to free pIv or pAdditionalAuthData\n");
            status = CPA_STATUS_FAIL;
        }
    }

    return status;
}

CpaStatus qatSymOpDataSetup(symmetric_test_params_t *pSetup,
                            CpaCySymSessionCtx sessionCtx,
                            Cpa32U *pPacketSize,
                            CpaCySymOpData *pOpdata,
                            CpaBufferList *pBuffListArray)
{
    CpaCySymCipherAlgorithm cipherAlgorithm = CPA_CY_SYM_CIPHER_NULL;
    CpaCySymHashAlgorithm hashAlgorithm = CPA_CY_SYM_HASH_NONE;
    Cpa32U numOfBuffers = 0;
    Cpa32U idx = 0;

    /* Shortens dereference path for more code readability */
    cipherAlgorithm = pSetup->setupData.cipherSetupData.cipherAlgorithm;
    hashAlgorithm = pSetup->setupData.hashSetupData.hashAlgorithm;

    /* For each bufferList set the symmetric operation data */
    for (idx = 0; idx < pSetup->numBuffLists; idx++)
    {
        memset(&pOpdata[idx], 0, sizeof(CpaCySymOpData));
        pOpdata[idx].sessionCtx = sessionCtx;
        pOpdata[idx].packetType = CPA_CY_SYM_PACKET_TYPE_FULL;

        if (usePartial_g && ((idx % EVEN_NUMBER) == 0))
        {
            pOpdata[idx].packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;
        }
        else if (usePartial_g)
        {
            pOpdata[idx].packetType = CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL;
        }

        /* These only need to be set for cipher and alg chaining */
        pOpdata[idx].cryptoStartSrcOffsetInBytes = pSetup->cryptoSrcOffset;

        /* messageLenToCipherInBytes and messageLenToHashInBytes do not have
         * to be the same. In this code we want to either hash the entire buffer
         * or encrypt the entire buffer, depending on the SymOperation.
         * For Alg Chaining, depending on the chain order, for HashThenCipher,
         * the digest will be the hash of the unencrypted buffer and then we
         * cipher  the buffer. OR for CipherThenHash, we cipher the buffer, then
         * the perform the hash on the encrypted buffer, so that the digest is
         * the digest of the encrypted data */
        pOpdata[idx].messageLenToCipherInBytes =
            pPacketSize[idx] - pSetup->cryptoSrcOffset;

        /* These only need to be set for hash and alg chaining*/
        pOpdata[idx].hashStartSrcOffsetInBytes = HASH_OFFSET_BYTES;
        pOpdata[idx].messageLenToHashInBytes = pPacketSize[idx];
        pOpdata[idx].pAdditionalAuthData = NULL;

        /* In GMAC mode, there is no message to Cipher */
        if (CPA_CY_SYM_HASH_AES_GMAC == hashAlgorithm)
        {
            pOpdata[idx].cryptoStartSrcOffsetInBytes = 0;
            pOpdata[idx].messageLenToCipherInBytes = 0;
        }

        if (CPA_CY_SYM_HASH_SNOW3G_UIA2 == hashAlgorithm
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
            || CPA_CY_SYM_HASH_ZUC_EIA3 == hashAlgorithm
#endif
        )
        {

            pOpdata[idx].pAdditionalAuthData = qaeMemAllocNUMA(
                KEY_SIZE_128_IN_BYTES, pSetup->node, BYTE_ALIGNMENT_64);

            if (NULL == pOpdata[idx].pAdditionalAuthData)
            {
                qatSymFreeOpData(pSetup, pOpdata);
                PRINT_ERR("Could not allocate additional auth data index %u\n",
                          idx);

                return CPA_STATUS_FAIL;
            }

            memset(
                pOpdata[idx].pAdditionalAuthData, 0xAA, KEY_SIZE_128_IN_BYTES);
        }
        else if (((CPA_CY_SYM_CIPHER_AES_CCM == cipherAlgorithm) ||
                  (CPA_CY_SYM_CIPHER_AES_GCM == cipherAlgorithm)) &&
                 (CPA_CY_SYM_HASH_AES_GMAC != hashAlgorithm))
        {
            /* must allocate to the nearest block size required
             * (above 18 bytes) */
            pOpdata[idx].pAdditionalAuthData = qaeMemAllocNUMA(
                AES_CCM_MIN_AAD_ALLOC_LENGTH, pSetup->node, BYTE_ALIGNMENT_64);

            if (NULL == pOpdata[idx].pAdditionalAuthData)
            {
                PRINT_ERR("Could not allocate additional auth data index %u\n",
                          idx);

                qatSymFreeOpData(pSetup, pOpdata);
                return CPA_STATUS_FAIL;
            }

            memset(pOpdata[idx].pAdditionalAuthData,
                   0,
                   AES_CCM_MIN_AAD_ALLOC_LENGTH);
        }

        /* set IV len depending on what we are testing */
        switch (cipherAlgorithm)
        {
            case CPA_CY_SYM_CIPHER_AES_CBC:
            case CPA_CY_SYM_CIPHER_AES_CTR:
            case CPA_CY_SYM_CIPHER_AES_CCM:
            case CPA_CY_SYM_CIPHER_SNOW3G_UEA2:
            case CPA_CY_SYM_CIPHER_AES_F8:
            case CPA_CY_SYM_CIPHER_AES_XTS:
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
            case CPA_CY_SYM_CIPHER_ZUC_EEA3:
#endif
                pOpdata[idx].ivLenInBytes = IV_LEN_FOR_16_BYTE_BLOCK_CIPHER;
                break;
            case CPA_CY_SYM_CIPHER_DES_CBC:
            case CPA_CY_SYM_CIPHER_3DES_CBC:
            case CPA_CY_SYM_CIPHER_3DES_CTR:
            case CPA_CY_SYM_CIPHER_KASUMI_F8:
                pOpdata[idx].ivLenInBytes = IV_LEN_FOR_8_BYTE_BLOCK_CIPHER;
                break;
            case CPA_CY_SYM_CIPHER_AES_GCM:
                pOpdata[idx].ivLenInBytes = IV_LEN_FOR_12_BYTE_GCM;
                break;
            default:
                pOpdata[idx].ivLenInBytes = IV_LEN_FOR_8_BYTE_BLOCK_CIPHER;
                break;
        }

        /*allocate NUMA aware aligned memory for IV*/
        pOpdata[idx].pIv = qaeMemAllocNUMA(
            pOpdata[idx].ivLenInBytes, pSetup->node, BYTE_ALIGNMENT_64);

        if (NULL == pOpdata[idx].pIv)
        {
            qatSymFreeOpData(pSetup, pOpdata);
            PRINT_ERR("IV is null\n");

            return CPA_STATUS_FAIL;
        }

        memset(pOpdata[idx].pIv, 0, pOpdata[idx].ivLenInBytes);

        if (CPA_CY_SYM_CIPHER_AES_CCM == cipherAlgorithm)
        {
            /*Although the IV data length for CCM must be 16 bytes,
              The nonce length must be between 7 and 13 inclusive*/
            pOpdata[idx].ivLenInBytes = AES_CCM_DEFAULT_NONCE_LENGTH;
        }

        /*if we are testing HASH or Alg Chaining, set the location to place
         * the digest result, this space was allocated in sampleSymmetricPerform
         * function*/
        if ((CPA_CY_SYM_OP_HASH == pSetup->setupData.symOperation) ||
            (CPA_CY_SYM_OP_ALGORITHM_CHAINING ==
             pSetup->setupData.symOperation))
        {
            /* calculate digest offset */
            numOfBuffers = pBuffListArray[idx].numBuffers;
            pOpdata[idx].pDigestResult =
                pBuffListArray[idx].pBuffers[numOfBuffers - 1].pData +
                pSetup->packetSizeInBytesArray[idx];
        }

        if (CPA_CY_SYM_CIPHER_AES_CCM == cipherAlgorithm)
        {
            /*generate a random IV*/
            generateRandomData(&(pOpdata[idx].pIv[1]),
                               pOpdata[idx].ivLenInBytes);

            memcpy(&(pOpdata[idx].pAdditionalAuthData[1]),
                   &(pOpdata[idx].pIv[1]),
                   pOpdata[idx].ivLenInBytes);
        }
        else
        {
            /*generate a random IV*/
            generateRandomData(pOpdata[idx].pIv, pOpdata[idx].ivLenInBytes);
        }
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus qatSymPerform(symmetric_test_params_t *setup,
                        CpaCySymOpData *ppOpData,
                        CpaBufferList *ppSrcBuffListArray)
{
    CpaBoolean verifyResult = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U outsideLoopCount = 0;
    Cpa32U insideLoopCount = 0;
    CpaInstanceInfo2 instanceInfo2 = {0};
    Cpa64U numOps = 0;
    Cpa64U nextPoll = symPollingInterval_g;

    perf_data_t *pSymData = setup->performanceStats;

    memset(pSymData, 0, sizeof(perf_data_t));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, &instanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        return CPA_STATUS_FAIL;
    }
    pSymData->packageId = instanceInfo2.physInstId.packageId;

    qatInitLatency(
        setup->performanceStats, setup->numBuffLists, setup->numLoops);

    /*preset the number of ops we plan to submit*/
    pSymData->numOperations = (Cpa64U)setup->numBuffLists * setup->numLoops;

    /* Init the semaphore used in the callback */
    sampleCodeSemaphoreInit(&pSymData->comp, 0);

    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();

    /* Get the time, collect this only for the first
     * request, the callback collects it for the last */
    pSymData->startCyclesTimestamp = sampleCodeTimestamp();

    /* The outside for-loop will loop around the preallocated buffer list
     * array the number of times necessary to satisfy:
     * NUM_OPERATIONS / setup->numBuffLists*/
    for (outsideLoopCount = 0; outsideLoopCount < setup->numLoops;
         outsideLoopCount++)
    {
        checkStopTestExitFlag(pSymData,
                              &(setup->numLoops),
                              &(setup->numBuffLists),
                              outsideLoopCount);

        /* This inner for-loop loops around the number of Buffer Lists
         * that have been preallocated.  Once the array has completed-
         * exit to the outer loop to move on the next iteration of the
         * preallocated loop. */
        for (insideLoopCount = 0; insideLoopCount < setup->numBuffLists;
             insideLoopCount++)
        {
            /* When the callback returns it will increment the responses
             * counter and test if its equal to NUM_OPERATIONS, in that
             * case all responses have been successfully received. */
            do
            {
                qatStartLatencyMeasurement(setup->performanceStats,
                                           setup->submissions);
                status = cpaCySymPerformOp(setup->cyInstanceHandle,
                                           pSymData,
                                           &ppOpData[insideLoopCount],
                                           &ppSrcBuffListArray[insideLoopCount],
                                           &ppSrcBuffListArray[insideLoopCount],
                                           /*in-place operation*/
                                           &verifyResult);

                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;

                    if (poll_inline_g)
                    {
                        if (instanceInfo2.isPolled)
                        {
                            icp_sal_CyPollInstance(setup->cyInstanceHandle, 0);
                            nextPoll = numOps + symPollingInterval_g;
                        }
                    }

                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }
            setup->submissions++;
            qatLatencyPollForResponses(setup->performanceStats,
                                       setup->submissions,
                                       setup->cyInstanceHandle,
                                       CPA_TRUE,
                                       CPA_FALSE);

            if (poll_inline_g)
            {
                if (instanceInfo2.isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        icp_sal_CyPollInstance(setup->cyInstanceHandle, 0);

                        pSymData->pollCount++;

                        nextPoll = numOps + symPollingInterval_g;
                    }
                }
            }

        } /*end of inner loop */

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp Error %d\n", status);
            break;
        }
    } /* end of outer loop */

    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2.isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pSymData, setup->cyInstanceHandle, pSymData->numOperations);
        }
    }

    /* Checking the response count and initiating the sem_wait in
    waitForResponses function to complete the operations */
    if (pSymData->responses != pSymData->numOperations)
    {
        if (CPA_STATUS_SUCCESS == status)
        {
            status = waitForResponses(pSymData,
                                      setup->syncMode,
                                      setup->numBuffLists,
                                      setup->numLoops);
        }
    }

    qatSummariseLatencyMeasurements(setup->performanceStats);

    /*clean up the callback semaphore*/
    sampleCodeSemaphoreDestroy(&pSymData->comp);

    return status;
}
