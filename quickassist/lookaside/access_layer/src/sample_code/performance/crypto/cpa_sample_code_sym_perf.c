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
 ***************************************************************************/

/**
 *****************************************************************************
 * @file cpa_sample_code_sym_perf.c
 *
 * @defgroup sampleSymmetricPerf  Symmetric Performance code
 *
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      This file contains the main symmetric performance sample code. It is
 *      capable of performing all ciphers, all hashes, authenticated hashes
 *      and algorithm chaining. Nested Hashes are not supported
 *
 *      This code pre-allocates a number of bufferLists as defined by
 *      setup->numBuffLists, each bufferlist includes several flat buffers which
 *      its size is equal to buffer size. The pre-allocated buffers are then
 *      continuously looped until the numLoops is met.
 *      Time stamping is started prior to the
 *      Operation and is stopped when all callbacks have returned.
 *      The packet size and algorithm to be tested is setup using the
 *      setupSymmetricTest function. The framework is used to create the threads
 *      which calls functions here to execute symmetric performance
 *
 *****************************************************************************/

#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "icp_sal_poll.h"

#define EVEN_NUMBER (2)

extern int signOfLife;
extern volatile CpaBoolean digestAppended_g;
extern int verboseOutput;
extern Cpa32U symPollingInterval_g;
#include "busy_loop.h"
#include "qat_perf_cycles.h"


#define ADF_MAX_DEVICES 32
Cpa16U busAddressId[ADF_MAX_DEVICES] = {0};
extern Cpa32U packageIdCount_g;

#ifdef LATENCY_CODE
extern int
    latency_single_buffer_mode; /* set to 1 for single buffer processing */
#endif

extern CpaInstanceHandle *cyInstances_g;

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      Callback function for result of perform operation
 *
 *****************************************************************************/
void symPerformCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    /*we declare the callback as per the API requirements, but we only use
     * the pCallbackTag parameter*/
    processCallback(pCallbackTag);
}

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      calculate the pointer of digest result in the buffer list
 *      digest result should be located in the end of Plaintext and
 *      digest result should be align with block size of cipher.
 *      Please see example as the following:
@verbatim
+--------+----------------------------------------------------+--------+----+
|        |                   Ciphertext                       | Digest |Pad +
+--------+----------------------------------------------------+--------+----+
         <-FlatBuffer[0]-><-FlatBuffer[1]-><-FlatBuffer[2]-><-FlatBuffer[3]->
         <-                               Buffer List                      ->
@endverbatim
 * @param[in] packetSize       Data packet size
 * @param[in] blockSizeInBytes block length of the cipher
 * @param[in] bufferSizeInByte buffer size in the flatbuffer of bufferlist
 * @param[in] pBufferList      the pointer of Buffer list which store data and
 *                             comprised of flatbuffers.
 *
 *****************************************************************************/
static Cpa8U *symCalDigestAddress(Cpa32U packetSize,
                                  Cpa32U blockSizeInBytes,
                                  Cpa32U bufferSizeInByte,
                                  CpaBufferList *pBufferList)
{
    Cpa8U *pDigestResult = 0;
    Cpa32U numBuffers = pBufferList->numBuffers;
    Cpa32U packsetSizePad = 0;
    Cpa32U digestOffset = 0;
    Cpa32U indexBuffer = 0;

#ifdef DEBUF_CODE
    PRINT("flatBufferSize %d\n", bufferSizeInByte);
#endif

    /* check if  packetSize is 0  */
    if (bufferSizeInByte == 0)
    {
        pDigestResult = pBufferList->pBuffers[0].pData + packetSize;
    }

    else if (packetSize % bufferSizeInByte == 0)
    {
        pDigestResult =
            pBufferList->pBuffers[numBuffers - 1].pData + bufferSizeInByte;
    }
    else
    {
        /* since Digest address (pDigestResult) need to align with
         * blockSizeInBytes, we will check if packetSize is align with
         * blockSizeInBytes,
         * if not, padding will added after message */
        if (packetSize % blockSizeInBytes != 0)
        {
            packsetSizePad = blockSizeInBytes - (packetSize % blockSizeInBytes);
        }
        /* calculate actual offset of digest result in flatbuffer*/
        digestOffset = (packetSize + packsetSizePad) % bufferSizeInByte;

        /* calculate the which flat buffer store pDigestResult
         * pDigestResult will appended in the end of pData */
        indexBuffer = (packetSize + packsetSizePad) / bufferSizeInByte;
        pDigestResult = pBufferList->pBuffers[indexBuffer].pData + digestOffset;
    }
    return pDigestResult;
}

#ifdef SYM_SET_SETDIGESTBUFFER
/* Not used API sampleSymmetricPerf
 */
/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      initialize the digest within pBufferList by value.
 *
 * @param[in] messageLenToCipherInBytes  Cipher Message Length
 * @param[in] digestLengthInBytes        Digest Length
 * @param[in] value                      Initial value for Digest Buffer
 * @param[in] pBufferList                the pointer of Buffer list which store
 *                                       data and comprised of flatbuffers.
 *****************************************************************************/
static void symSetDigestBuffer(Cpa32U messageLenToCipherInBytes,
                               Cpa32U digestLengthInBytes,
                               Cpa8U value,
                               CpaBufferList *pBufferList)
{
    Cpa8U *pDigestResult = 0;
    Cpa32U indexBuffer = 0;
    Cpa32U i = 0;
    /*  all the rest of data including padding will initialized ,
     * so ivLenInBytes is 1.*/
    pDigestResult = symCalDigestAddress(messageLenToCipherInBytes,
                                        1,
                                        pBufferList->pBuffers[0].dataLenInBytes,
                                        pBufferList);
    indexBuffer =
        messageLenToCipherInBytes / pBufferList->pBuffers[0].dataLenInBytes;
    /* reset the digest memory to 0 */
    memset(
        pDigestResult,
        value,
        (pBufferList->pBuffers[0].dataLenInBytes -
         messageLenToCipherInBytes % pBufferList->pBuffers[0].dataLenInBytes));
    indexBuffer++;
    for (i = indexBuffer; i < pBufferList->numBuffers; i++)
    {
        memset(pBufferList->pBuffers[i].pData,
               value,
               pBufferList->pBuffers[i].dataLenInBytes);
    }
}
#endif
/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * Create a symmetric session
 */
static CpaStatus symmetricSetupSession(CpaCySymCbFunc pSymCb,
                                       Cpa8U *pCipherKey,
                                       Cpa8U *pAuthKey,
                                       CpaCySymSessionCtx *pSession,
                                       symmetric_test_params_t *setup
)
{
    Cpa32U sessionCtxSizeInBytes = 0;
#if CPA_CY_API_VERSION_NUM_MINOR >= 8
    Cpa32U sessionCtxDynamicSizeInBytes = 0;
#endif
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymSessionCtx pLocalSession = NULL;
    Cpa32U cipherKeyLen = 0;
    Cpa32U authKeyLen = 0;
    Cpa32U node = 0;

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }
    /*set the cipher and authentication key len*/
    cipherKeyLen = setup->setupData.cipherSetupData.cipherKeyLenInBytes;
    authKeyLen =
        setup->setupData.hashSetupData.authModeSetupData.authKeyLenInBytes;
    /*generate a random cipher and authentication key*/
    generateRandomData(pCipherKey, cipherKeyLen);
    generateRandomData(pAuthKey, authKeyLen);
    /*cipher setup only needs to be set for alg chaining, cipher, AES-GCM
     * and AES-CCM*/
    setup->setupData.cipherSetupData.pCipherKey = pCipherKey;
    /*hash setup only needs to be set for hash, AES-GCM
     * and AES-CCM*/
    setup->setupData.hashSetupData.authModeSetupData.authKey = pAuthKey;
    if (CPA_CY_SYM_HASH_AES_GMAC ==
        setup->setupData.hashSetupData.hashAlgorithm)
    {
        setup->setupData.hashSetupData.authModeSetupData.authKey = NULL;
        setup->setupData.hashSetupData.authModeSetupData.authKeyLenInBytes = 0;
    }
    else if (CPA_CY_SYM_HASH_SNOW3G_UIA2 ==
                 setup->setupData.hashSetupData.hashAlgorithm
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
             || ((CPA_CY_SYM_HASH_ZUC_EIA3 ==
                  setup->setupData.hashSetupData.hashAlgorithm) &&
                 (KEY_SIZE_128_IN_BYTES ==
                  setup->setupData.hashSetupData.authModeSetupData
                      .authKeyLenInBytes))
#endif
    )
    {
        setup->setupData.hashSetupData.authModeSetupData.aadLenInBytes =
            KEY_SIZE_128_IN_BYTES;
    }
    else
    {
        setup->setupData.hashSetupData.authModeSetupData.aadLenInBytes = 0;
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

    /*
     * allocate session memory using dynamic context size
     */
    sessionCtxSizeInBytes = sessionCtxDynamicSizeInBytes;
#endif

    pLocalSession =
        qaeMemAllocNUMA(sessionCtxSizeInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == pLocalSession)
    {
        PRINT_ERR("Could not allocate pLocalSession memory\n");
        return CPA_STATUS_FAIL;
    }
    /*zero session memory*/
    memset(pLocalSession, 0, sessionCtxSizeInBytes);
/*
 * init session with asynchronous callback- pLocalSession will contain
 * the session context
 */
    status = cpaCySymInitSession(
        setup->cyInstanceHandle, pSymCb, &setup->setupData, pLocalSession);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCySymInitSession error, status: %d\n", status);
        qaeMemFreeNUMA((void **)&pLocalSession);
        return status;
    }
    *pSession = pLocalSession;

#if CPA_CY_API_VERSION_NUM_MINOR >= 8
#endif

    return status;
}

/*****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * Free memory allocated in the symmetricPerformOpDataSetup function
 * ****************************************************************************/
void opDataMemFree(CpaCySymOpData *pOpdata[],
                   Cpa32U numBuffers,
                   CpaBoolean digestAppend)
{
    Cpa32U k = 0;

    for (k = 0; k < numBuffers; k++)
    {
        if (NULL != pOpdata[k])
        {
            qaeMemFreeNUMA((void **)&pOpdata[k]->pIv);
            if (NULL != pOpdata[k]->pAdditionalAuthData)
            {
                qaeMemFreeNUMA((void **)&pOpdata[k]->pAdditionalAuthData);
            }
            qaeMemFree((void **)&pOpdata[k]);
        }
    }
}

/*****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * Setup symmetric operation data
 * ****************************************************************************/
static CpaStatus symmetricPerformOpDataSetup(CpaCySymSessionCtx pSessionCtx,
                                             Cpa32U *pPacketSize,
                                             CpaCySymOpData *pOpdata[],
                                             symmetric_test_params_t *setup,
                                             CpaBufferList *pBuffListArray[])
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U createCount = 0;
    Cpa32U node = 0;

    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }
    /*for each bufferList set the symmetric operation data*/
    for (createCount = 0; createCount < setup->numBuffLists; createCount++)
    {
        pOpdata[createCount] = qaeMemAlloc(sizeof(CpaCySymOpData));
        if (NULL == pOpdata[createCount])
        {
            PRINT_ERR("Could not allocate Opdata memory at index %u\n",
                      createCount);
            opDataMemFree(pOpdata, setup->numBuffLists, CPA_FALSE);
            return CPA_STATUS_FAIL;
        }
        memset(pOpdata[createCount], 0, sizeof(CpaCySymOpData));
        pOpdata[createCount]->sessionCtx = pSessionCtx;
        pOpdata[createCount]->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        /*these only need to be set for cipher and alg chaining */
        pOpdata[createCount]->cryptoStartSrcOffsetInBytes =
            setup->cryptoSrcOffset;
        /* messageLenToCipherInBytes and messageLenToHashInBytes do not have
         * to be the same. In this code we want to either hash the entire buffer
         * or encrypt the entire buffer, depending on the SymOperation.
         * For Alg Chaining, depending on the chain order, for HashThenCipher,
         * the digest will be the hash of the unencrypted buffer and then we
         * cipher  the buffer. OR for CipherThenHash, we cipher the buffer, then
         * the perform the hash on the encrypted buffer, so that the digest is
         * the digest of the encrypted data*/
        pOpdata[createCount]->messageLenToCipherInBytes =
            pPacketSize[createCount] - setup->cryptoSrcOffset;
        /*these only need to be set for hash and alg chaining*/
        pOpdata[createCount]->hashStartSrcOffsetInBytes = HASH_OFFSET_BYTES;
        pOpdata[createCount]->messageLenToHashInBytes =
            pPacketSize[createCount];

        pOpdata[createCount]->pAdditionalAuthData = NULL;

        /* In GMAC mode, there is no message to Cipher */
        if (CPA_CY_SYM_HASH_AES_GMAC ==
            setup->setupData.hashSetupData.hashAlgorithm)
        {
            pOpdata[createCount]->cryptoStartSrcOffsetInBytes = 0;
            pOpdata[createCount]->messageLenToCipherInBytes = 0;
        }

        if (CPA_CY_SYM_HASH_SNOW3G_UIA2 ==
                setup->setupData.hashSetupData.hashAlgorithm
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
            || ((CPA_CY_SYM_HASH_ZUC_EIA3 ==
                 setup->setupData.hashSetupData.hashAlgorithm) &&
                (KEY_SIZE_128_IN_BYTES ==
                 setup->setupData.hashSetupData.authModeSetupData
                     .authKeyLenInBytes))
#endif
        )
        {

            pOpdata[createCount]->pAdditionalAuthData =
                qaeMemAllocNUMA(KEY_SIZE_128_IN_BYTES, node, BYTE_ALIGNMENT_64);
            if (NULL == pOpdata[createCount]->pAdditionalAuthData)
            {
                PRINT_ERR("Could not allocate additional auth data index %u\n",
                          createCount);
                opDataMemFree(pOpdata, setup->numBuffLists, CPA_FALSE);
                return CPA_STATUS_FAIL;
            }
            memset(pOpdata[createCount]->pAdditionalAuthData,
                   0xAA,
                   KEY_SIZE_128_IN_BYTES);
        }
        else if (((setup->setupData.cipherSetupData.cipherAlgorithm ==
                   CPA_CY_SYM_CIPHER_AES_CCM) ||
                  (setup->setupData.cipherSetupData.cipherAlgorithm ==
                   CPA_CY_SYM_CIPHER_AES_GCM)) &&
                 (setup->setupData.hashSetupData.hashAlgorithm !=
                  CPA_CY_SYM_HASH_AES_GMAC))
        {
            /*must allocate to the nearest block size required
              (above 18 bytes)*/
            pOpdata[createCount]->pAdditionalAuthData = qaeMemAllocNUMA(
                AES_CCM_MIN_AAD_ALLOC_LENGTH, node, BYTE_ALIGNMENT_64);
            if (NULL == pOpdata[createCount]->pAdditionalAuthData)
            {
                PRINT_ERR("Could not allocate additional auth data index %u\n",
                          createCount);
                opDataMemFree(pOpdata, setup->numBuffLists, CPA_FALSE);
                return CPA_STATUS_FAIL;
            }
            memset(pOpdata[createCount]->pAdditionalAuthData,
                   0,
                   AES_CCM_MIN_AAD_ALLOC_LENGTH);
        }
        /*set IV len depending on what we are testing*/
        switch (setup->setupData.cipherSetupData.cipherAlgorithm)
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
            case CPA_CY_SYM_CIPHER_SM4_ECB:
            case CPA_CY_SYM_CIPHER_SM4_CBC:
            case CPA_CY_SYM_CIPHER_SM4_CTR:
                pOpdata[createCount]->ivLenInBytes =
                    IV_LEN_FOR_16_BYTE_BLOCK_CIPHER;
                /* If 0 use default else use value passed. */
                if (0 != setup->ivLength)
                {
                    pOpdata[createCount]->ivLenInBytes = setup->ivLength;
                }
                break;
            case CPA_CY_SYM_CIPHER_DES_CBC:
            case CPA_CY_SYM_CIPHER_3DES_CBC:
            case CPA_CY_SYM_CIPHER_3DES_CTR:
            case CPA_CY_SYM_CIPHER_KASUMI_F8:
                pOpdata[createCount]->ivLenInBytes =
                    IV_LEN_FOR_8_BYTE_BLOCK_CIPHER;
                /* If 0 use default else use value passed. */
                if (0 != setup->ivLength)
                {
                    pOpdata[createCount]->ivLenInBytes = setup->ivLength;
                }
                break;
            case CPA_CY_SYM_CIPHER_AES_GCM:
                pOpdata[createCount]->ivLenInBytes = IV_LEN_FOR_16_BYTE_GCM;
                /* If 0 use default else use value passed. */
                if (0 != setup->ivLength)
                {
                    pOpdata[createCount]->ivLenInBytes = setup->ivLength;
                }
                break;
            default:
                pOpdata[createCount]->ivLenInBytes =
                    IV_LEN_FOR_8_BYTE_BLOCK_CIPHER;
                break;
        }

        /*allocate NUMA aware aligned memory for IV*/
        pOpdata[createCount]->pIv = qaeMemAllocNUMA(
            pOpdata[createCount]->ivLenInBytes, node, BYTE_ALIGNMENT_64);
        if (NULL == pOpdata[createCount]->pIv)
        {
            PRINT_ERR("IV is null\n");
            opDataMemFree(pOpdata, setup->numBuffLists, CPA_FALSE);
            return CPA_STATUS_FAIL;
        }
        memset(
            pOpdata[createCount]->pIv, 0, pOpdata[createCount]->ivLenInBytes);
        if (setup->setupData.cipherSetupData.cipherAlgorithm ==
            CPA_CY_SYM_CIPHER_AES_CCM)
        {
            /*Although the IV data length for CCM must be 16 bytes,
              The nonce length must be between 7 and 13 inclusive*/
            pOpdata[createCount]->ivLenInBytes = AES_CCM_DEFAULT_NONCE_LENGTH;
        }

        /*if we are testing HASH or Alg Chaining, set the location to place
         * the digest result, this space was allocated in sampleSymmetricPerform
         * function*/
        if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH ||
            setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
        {
            /* calculate digest offset */
            pOpdata[createCount]->pDigestResult =
                symCalDigestAddress(pPacketSize[createCount],
                                    IV_LEN_FOR_16_BYTE_BLOCK_CIPHER,
                                    setup->flatBufferSizeInBytes,
                                    pBuffListArray[createCount]);
        }

        if (setup->setupData.cipherSetupData.cipherAlgorithm ==
            CPA_CY_SYM_CIPHER_AES_CCM)
        {
            /*generate a random IV*/
            generateRandomData(&(pOpdata[createCount]->pIv[1]),
                               pOpdata[createCount]->ivLenInBytes);

            memcpy(&(pOpdata[createCount]->pAdditionalAuthData[1]),
                   &(pOpdata[createCount]->pIv[1]),
                   pOpdata[createCount]->ivLenInBytes);
        }
        else
        {
            /*generate a random IV*/
            generateRandomData(pOpdata[createCount]->pIv,
                               pOpdata[createCount]->ivLenInBytes);
        }
    }
    return CPA_STATUS_SUCCESS;
}


/*****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * measures the performance of symmetric encryption operations
 * ****************************************************************************/
CpaStatus symPerform(symmetric_test_params_t *setup,
                     perf_data_t *pSymData,
                     Cpa32U numOfLoops,
                     CpaCySymOpData **ppOpData,
                     CpaBufferList **ppSrcBuffListArray,
                     CpaCySymCipherDirection cipherDirection)
{
    CpaBoolean verifyResult = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U outsideLoopCount = 0;
    Cpa32U insideLoopCount = 0;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = symPollingInterval_g;
#endif
#ifdef LATENCY_CODE
    /* Counts the number of buffers submitted for encryption. Only
     * MAX_LATENCY_COUNT of these will be 'latency buffers' whose
     * times are measured */
    Cpa32U submissions = 0;

    /* set when the latency buffer is sent to accelerator */
    perf_cycles_t *request_submit_start = NULL;

    /* set in completion service routine dcPerformCallback() */
    perf_cycles_t *request_respnse_time = NULL;
    const Cpa32U request_mem_sz = sizeof(perf_cycles_t) * MAX_LATENCY_COUNT;
#endif
    /* Capture busy loop before memset of performanceStats */
    Cpa32U busyLoopValue = pSymData->busyLoopValue;
    Cpa32U staticAssign = 0, busyLoopCount = 0, numBusyLoops = 0;
    perf_cycles_t startBusyLoop = 0, endBusyLoop = 0, totalBusyLoopCycles = 0;

    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    saveClearRestorePerfStats(pSymData);

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        qaeMemFree((void **)&instanceInfo2);
        return CPA_STATUS_FAIL;
    }
    pSymData->packageId = instanceInfo2->physInstId.packageId;

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (pSymData->numOperations > LATENCY_SUBMISSION_LIMIT)
        {
            PRINT_ERR("Error max submissions for latency  must be <= %d\n",
                      LATENCY_SUBMISSION_LIMIT);
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
        request_submit_start = qaeMemAlloc(request_mem_sz);
        request_respnse_time = qaeMemAlloc(request_mem_sz);
        if (request_submit_start == NULL || request_respnse_time == NULL)
        {
            PRINT_ERR("Failed to allocate memory for submission and response "
                      "times\n");
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
        memset(request_submit_start, 0, request_mem_sz);
        memset(request_respnse_time, 0, request_mem_sz);
        /* Calculate how many buffer submissions between latency measurements..
         */
        pSymData->nextCount =
            (setup->numBuffLists * setup->numLoops) / MAX_LATENCY_COUNT;

        /* .. and set the next trigger count to this */
        pSymData->countIncrement = pSymData->nextCount;

        /* How many latency measurements of the MAX_LATENCY_COUNT have been
         * taken so far */
        pSymData->latencyCount = 0;

        /* Completion routine sets end times in the array indirectly */
        pSymData->response_times = request_respnse_time;
        pSymData->start_times = request_submit_start;

        if (latency_debug)
            PRINT("%s: LATENCY_CODE: Initial nextCount %u, countIncrement %u\n",
                  __FUNCTION__,
                  pSymData->nextCount,
                  pSymData->countIncrement);
    }
#endif
    /*preset the number of ops we plan to submit*/
    pSymData->numOperations = (Cpa64U)setup->numBuffLists * setup->numLoops;
    coo_init(pSymData, pSymData->numOperations);
    pSymData->retries = 0;

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
    for (outsideLoopCount = 0; outsideLoopCount < numOfLoops;
         outsideLoopCount++)
    {
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
#ifdef LATENCY_CODE
                if (latency_enable)
                {
                    if (pSymData->latencyCount < MAX_LATENCY_COUNT)
                    {
                        if (submissions + 1 == pSymData->nextCount)
                        {
                            request_submit_start[pSymData->latencyCount] =
                                sampleCodeTimestamp();
                        }
                    }
                }
#endif
                coo_req_start(pSymData);
                status = cpaCySymPerformOp(setup->cyInstanceHandle,
                                           pSymData,
                                           ppOpData[insideLoopCount],
                                           ppSrcBuffListArray[insideLoopCount],
                                           ppSrcBuffListArray[insideLoopCount],
                                           /*in-place operation*/
                                           &verifyResult);
                coo_req_stop(pSymData, status);
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo2->isPolled)
                        {
                            sampleCodeSymPollInstance(setup->cyInstanceHandle,
                                                      0);
                            nextPoll = numOps + symPollingInterval_g;
                        }
                    }
#endif
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);
            if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                busyLoop(busyLoopValue, &staticAssign);
                busyLoopCount++;
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }
#ifdef LATENCY_CODE
            if (latency_enable)
            {
                /* Another buffer has been submitted to the accelerator */
                submissions++;

                /* Have we been requested to process one buffer at a time. This
                 * will result in no retries and so the best latency times.
                 */
                if (latency_single_buffer_mode != 0)
                {
                    /* Must now wait until this buffer is processed by the CPM
                     */
                    while (pSymData->responses != submissions)
                    {
                        /* Keep polling until compression of the buffer
                         * completes
                         * and symPerformCallback() increments
                         * pSymData->responses */
                        icp_sal_CyPollInstance(setup->cyInstanceHandle, 0);
                    }
                }
            }
#endif
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo2->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(
                            pSymData, setup->cyInstanceHandle, &pollStatus);
                        nextPoll = numOps + symPollingInterval_g;
                    }
                }
            }
#endif
        } /*end of inner loop */


        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp Error %d\n", status);
            break;
        }
    } /* end of outer loop */
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pSymData, setup->cyInstanceHandle, pSymData->numOperations);
        }
    }
#endif

    /* Checking the response count and initiating the sem_wait in
    waitForResponses function to complete the operations */
    if (pSymData->responses != pSymData->numOperations)
    {
        if (CPA_STATUS_SUCCESS == status)
        {
            status = waitForResponses(
                pSymData, setup->syncMode, setup->numBuffLists, numOfLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Thread %u timeout. ", setup->threadID);
            }
        }
    }

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        int i;

        if (latency_debug)
        {
            PRINT("%s: Calculating min, max and ave latencies...\n",
                  __FUNCTION__);
            sampleCodeSleep(1); /* Let all our debug be printed out */
        }

        pSymData->minLatency = MAX_LATENCY_LIMIT; /* Will be less than this */
        pSymData->maxLatency = 0;                 /* Will be more than this */

        /* Let's accumulate in 'aveLatency' all the individual 'latency'
         * times. Typically, there should be MAX_LATENCY_COUNT of these.
         * We also calculate min/max so we can get a sense of the variance.
         */

        for (i = 0; i < pSymData->latencyCount; i++)
        {
            perf_cycles_t latency =
                pSymData->response_times[i] - request_submit_start[i];
            pSymData->aveLatency += latency;

            if (latency < pSymData->minLatency)
                pSymData->minLatency = latency;
            if (latency > pSymData->maxLatency)
                pSymData->maxLatency = latency;

            if (latency_debug)
                PRINT("%d, end[i]:%llu, start[i]:%llu, min:%llu, ave:%llu, "
                      "max:%llu\n",
                      i,
                      pSymData->response_times[i],
                      request_submit_start[i],
                      pSymData->minLatency,
                      pSymData->aveLatency,
                      pSymData->maxLatency);
        }
        if (pSymData->latencyCount > 0)
        {
            /* Then scale down this accumulated value to get the average.
             * This will be reported by dcPrintStats() at the end of the test */
            do_div(pSymData->aveLatency, pSymData->latencyCount);
        }

        /*we are finished with the response time so set to null before exit*/
        pSymData->response_times = NULL;
        qaeMemFree((void **)&request_respnse_time);
        qaeMemFree((void **)&request_submit_start);
    }
#endif

    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        pSymData->busyLoopValue = busyLoopValue;
        pSymData->busyLoopCount = busyLoopCount;
        pSymData->totalBusyLoopCycles = totalBusyLoopCycles;
        busyLoopTimeStamp();

        startBusyLoop = busyLoopTimeStamp();
        for (numBusyLoops = 0; numBusyLoops < busyLoopCount; numBusyLoops++)
        {
            busyLoop(busyLoopValue, &staticAssign);
        }
        endBusyLoop = busyLoopTimeStamp();

        setup->performanceStats->totalBusyLoopCycles =
            endBusyLoop - startBusyLoop;
        setup->performanceStats->offloadCycles =
            (setup->performanceStats->endCyclesTimestamp -
             setup->performanceStats->startCyclesTimestamp) -
            setup->performanceStats->totalBusyLoopCycles;

        do_div(setup->performanceStats->offloadCycles,
               setup->performanceStats->responses);
    }
    coo_average(pSymData);
    coo_deinit(pSymData);

    /*clean up the callback semaphore*/
    sampleCodeSemaphoreDestroy(&pSymData->comp);
    qaeMemFree((void **)&instanceInfo2);
    return status;
}

/*****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * Free memory allocated in the sampleSymmetricPerform function
 * ****************************************************************************/
void symPerformMemFree(symmetric_test_params_t *setup,
                       CpaFlatBuffer **ppSrcBuffPtrArray,
                       CpaBufferList **ppSrcBuffListArray,
                       CpaCySymOpData **ppOpData,
                       CpaCySymSessionCtx *pSessionCtx)
{
    /*free bufferLists, flatBuffers and data*/
    sampleFreeBuffers(ppSrcBuffPtrArray, ppSrcBuffListArray, setup);
    if (NULL != ppOpData)
    {
        opDataMemFree(ppOpData, setup->numBuffLists, setup->digestAppend);
        qaeMemFree((void **)&ppOpData);
    }
    /* free the session memory - calling code is responsible for
     * removing the session first*/
    if (NULL != *pSessionCtx)
    {
        qaeMemFreeNUMA((void **)pSessionCtx);
    }
    if (NULL != ppSrcBuffPtrArray)
    {
        qaeMemFree((void **)&ppSrcBuffPtrArray);
    }
    if (NULL != ppSrcBuffListArray)
    {
        qaeMemFree((void **)&ppSrcBuffListArray);
    }
}

/*****************************************************************************
 * @ingroup sampleSymmetricDpPerf
 *
 * @description
 *  Used for profiling IA offload cost.
 *
 *  Phase One:Iterates over the main perform function, increasing the number
 *  of busy loop cycles(BUSY_LOOP_INCREMENT) on each iteration until no retries
 *  occur.
 *
 *  Phase Two: Continues to iterate over the main perform function, increasing
 *  the number of busy loop cycles on each iteration until performance is
 *  affected then steps back to the last increment value, i.e. the last
 *  increment step(BUSY_LOOP_INCREMENT) before performance was affected.
 *****************************************************************************/
static CpaStatus performOffloadCalculation(
    symmetric_test_params_t *setup,
    perf_data_t *pSymData,
    Cpa32U numOfLoops,
    CpaCySymOpData **ppOpData,
    CpaBufferList **ppSrcBuffListArray,
    CpaCySymCipherDirection cipherDirection)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32S baseThroughput = 0, currentThroughput = 0;

    Cpa32U packetSize = 0, lowerBound = 0, upperBound = 0;
    perf_data_t *pPerfData = setup->performanceStats;

    pPerfData->busyLoopValue = 1;

    packetSize = setup->packetSizeInBytesArray[0];

    baseThroughput = getThroughput(pPerfData->responses,
                                   packetSize,
                                   pPerfData->endCyclesTimestamp -
                                       pPerfData->startCyclesTimestamp);
    currentThroughput = baseThroughput;

    /* Find the lower bound(retries) and upper bound(no retries) for subsequent
     * binary search.
     */
    while (CPA_STATUS_SUCCESS == status && pPerfData->retries != 0)
    {
        lowerBound = pPerfData->busyLoopValue;

        pPerfData->busyLoopValue = pPerfData->busyLoopValue << 1;

        /* PERFORM OP */
        status = symPerform(setup,
                            pSymData,
                            numOfLoops,
                            ppOpData,
                            ppSrcBuffListArray,
                            cipherDirection);

        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);
    }
    upperBound = pPerfData->busyLoopValue;

    /* Binary Search for no retries while maintaining throughput */
    while (CPA_STATUS_SUCCESS == status && lowerBound <= upperBound)
    {
        pPerfData->busyLoopValue = (upperBound + lowerBound) / 2;

        /* PERFORM OP */
        status = symPerform(setup,
                            pSymData,
                            numOfLoops,
                            ppOpData,
                            ppSrcBuffListArray,
                            cipherDirection);

        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);
        /* If no retries and we're within ERROR_MARGIN (0.1%) of base throughput
         */
        if (pPerfData->retries == 0 &&
            (withinMargin(baseThroughput, currentThroughput, ERROR_MARGIN) ==
             1))
        {
            break;
        }
        /* If we see retries */
        else if (pPerfData->retries != 0)
        {
            lowerBound = pPerfData->busyLoopValue + 1;
        }
        /* Else retries are zero, but throughput has been affected. */
        else
        {
            upperBound = pPerfData->busyLoopValue - 1;
        }
    }
    return status;
}


/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *  Main executing function
 ******************************************************************************/
CpaStatus sampleSymmetricPerform(symmetric_test_params_t *setup)
{
    /* start of local variable declarations */
    CpaCySymSessionCtx pEncryptSessionCtx = NULL;
    CpaCySymOpData **ppOpData = NULL;
    CpaFlatBuffer **ppSrcBuffPtrArray = NULL;
    CpaBufferList **ppSrcBuffListArray = NULL;
    Cpa32U *totalSizeInBytes = NULL;
    perf_data_t *pSymPerfData = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numOfLoops = setup->numLoops;
    Cpa32U insideLoopCount = 0;
    Cpa8U *cipherKey = NULL;
    Cpa8U *authKey = NULL;
    CpaCySymCbFunc pSymCb = NULL;
    Cpa32U node = 0;
    CpaCySymCipherDirection cipherDirection = cipherDirection_g;

    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return CPA_STATUS_FAIL;
    }
    totalSizeInBytes = qaeMemAlloc(setup->numBuffLists * sizeof(Cpa32U));
    if (NULL == totalSizeInBytes)
    {
        PRINT_ERR("sampleCodeCyGetNode memory allocation error\n");
        return CPA_STATUS_FAIL;
    }
    /* Initialize local variables */
    cipherKey = qaeMemAlloc(
        setup->setupData.cipherSetupData.cipherKeyLenInBytes * sizeof(Cpa8U));
    if (NULL == cipherKey)
    {
        PRINT_ERR("cipherKey memory allocation error\n");
        goto exit;
    }
    authKey = qaeMemAlloc(
        setup->setupData.hashSetupData.authModeSetupData.authKeyLenInBytes *
        sizeof(Cpa8U));
    if (NULL == authKey)
    {
        PRINT_ERR("authKey memory allocation error\n");
        goto exit;
    }

    /*allocate memory for an array of bufferList pointers, flatBuffer pointers
     * and operation data, the bufferLists and Flat buffers are created in
     * sampleCreateBuffers of cpa_sample_code_crypto_utils.c*/
    status = allocArrayOfVirtPointers((void **)&ppOpData, setup->numBuffLists);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto exit;
    }

    status = allocArrayOfVirtPointers((void **)&ppSrcBuffPtrArray,
                                      setup->numBuffLists);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto exit;
    }
    status = allocArrayOfVirtPointers((void **)&ppSrcBuffListArray,
                                      setup->numBuffLists);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto exit;
    }

    /*use the preallocated performance stats to store performance data, this
     * points to an element in perfStats array in the framework, each thread
     * points to a unique element of perfStats array*/

    pSymPerfData = setup->performanceStats;
    if (NULL == pSymPerfData)
    {
        PRINT_ERR("perf data pointer is NULL\n");
        status = CPA_STATUS_FAIL;
        goto exit;
    }

    if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH &&
        (setup->setupData.hashSetupData.hashAlgorithm ==
             CPA_CY_SYM_HASH_SNOW3G_UIA2 ||
         setup->setupData.hashSetupData.hashAlgorithm ==
             CPA_CY_SYM_HASH_KASUMI_F9))
    {
        setup->setupData.hashSetupData.digestResultLenInBytes =
            DIGEST_RESULT_4BYTES;
    }

    /*if we are testing hash or alg chain, get the hash size that needs to be
     *  allocated for the digest result. sampleCreateBuffers uses the hash size
     *  to allocate the appropriate memory*/
    for (insideLoopCount = 0; insideLoopCount < setup->numBuffLists;
         insideLoopCount++)
    {
        /* need to be allocate space for the digest result. */
        totalSizeInBytes[insideLoopCount] =
            setup->packetSizeInBytesArray[insideLoopCount] +
            setup->setupData.hashSetupData.digestResultLenInBytes;
    }

    /*init the symmetric session*/
    /*if the mode is asynchronous then set the callback function*/
    if (ASYNC == setup->syncMode)
    {
        pSymCb = symPerformCallback;
    }
    status = symmetricSetupSession(pSymCb,
                                   cipherKey,
                                   authKey,
                                   &pEncryptSessionCtx,
                                   setup
    );

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("symmetricSetupSession error, status %d\n", status);
        goto exit;
    }

    /* we create sample buffers with space for digest result if testing hash or
     * alg chain , otherwise we just create sample buffers
     * based on the bufferSize we are testing*/
    status = sampleCreateBuffers(setup->cyInstanceHandle,
                                 totalSizeInBytes,
                                 ppSrcBuffPtrArray,
                                 ppSrcBuffListArray,
                                 setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCreateBuffers error, status %d\n", status);
        goto exit;
    }


    /*setup the symmetric operation data*/
    status = symmetricPerformOpDataSetup(pEncryptSessionCtx,
                                         setup->packetSizeInBytesArray,
                                         ppOpData,
                                         setup,
                                         ppSrcBuffListArray);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("symmetricPerformOpDataSetup error, status %d\n", status);
        goto exit;
    }

    status = symPerform(setup,
                        pSymPerfData,
                        numOfLoops,
                        ppOpData,
                        ppSrcBuffListArray,
                        cipherDirection);
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        status = performOffloadCalculation(setup,
                                           pSymPerfData,
                                           numOfLoops,
                                           ppOpData,
                                           ppSrcBuffListArray,
                                           cipherDirection);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("symPerform error, status %d\n", status);
        goto exit;
    }

    status = removeSymSession(setup->cyInstanceHandle, pEncryptSessionCtx);


exit:
    symPerformMemFree(setup,
                      ppSrcBuffPtrArray,
                      ppSrcBuffListArray,
                      ppOpData,
                      &pEncryptSessionCtx);
    if (NULL != authKey)
    {
        qaeMemFree((void **)&authKey);
    }
    if (NULL != cipherKey)
    {
        qaeMemFree((void **)&cipherKey);
    }
    if (NULL != totalSizeInBytes)
    {
        qaeMemFree((void **)&totalSizeInBytes);
    }
    if (NULL != setup->performanceStats)
    {
        if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
        {
            status = CPA_STATUS_FAIL;
        }
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *  Setup a symmetric crypto thread for a given packet size or mix
 ******************************************************************************/
void sampleSymmetricPerformance(single_thread_test_data_t *testSetup)
{
    symmetric_test_params_t symTestSetup;
    symmetric_test_params_t *pSetup =
        ((symmetric_test_params_t *)testSetup->setupPtr);
    Cpa32U loopIteration = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    /*define the distribution of the packet mix
     * here we defined 2 lots of 10 sizes
     * later it is replicated into 100 buffers*/
    Cpa32U packetMix[NUM_PACKETS_IMIX] = {
        BUFFER_SIZE_64,   BUFFER_SIZE_752,  BUFFER_SIZE_1504, BUFFER_SIZE_64,
        BUFFER_SIZE_752,  BUFFER_SIZE_1504, BUFFER_SIZE_64,   BUFFER_SIZE_64,
        BUFFER_SIZE_1504, BUFFER_SIZE_1504, BUFFER_SIZE_752,  BUFFER_SIZE_64,
        BUFFER_SIZE_752,  BUFFER_SIZE_64,   BUFFER_SIZE_1504, BUFFER_SIZE_1504,
        BUFFER_SIZE_64,   BUFFER_SIZE_8992, BUFFER_SIZE_64,   BUFFER_SIZE_1504};
    Cpa32U *pPacketSize = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaInstanceInfo2 *instanceInfo = NULL;

    testSetup->passCriteria = getPassCriteria();

    memset(&symTestSetup, 0, sizeof(symmetric_test_params_t));

    /*cast the setup to a known structure so that we can populate our local
     * test setup*/
    symTestSetup.setupData = pSetup->setupData;


    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*give our thread a unique memory location to store performance stats*/
    symTestSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return;
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    /* give our thread a logical crypto instance to use*/
    symTestSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    status = cpaCyInstanceGetInfo2(symTestSetup.cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (instanceInfo->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo->physInstId.packageId;
    }

    pPacketSize = qaeMemAlloc(sizeof(Cpa32U) * pSetup->numBuffLists);
    if (NULL == pPacketSize)
    {
        PRINT_ERR("Could not allocate memory for pPacketSize\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }

    if (testSetup->packetSize == PACKET_IMIX)
    {
        /*we are testing IMIX so we copy buffer sizes from preallocated
         * array into symTestSetup.numBuffLists*/
        Cpa32U indexer = sizeof(packetMix) / sizeof(Cpa32U);
        for (loopIteration = 0; loopIteration < pSetup->numBuffLists;
             loopIteration++)
        {
            pPacketSize[loopIteration] = packetMix[loopIteration % indexer];
        }
    }
    else
    {
        /*we are testing a uniform bufferSize, so we set the bufferSize array
         * accordingly*/
        for (loopIteration = 0; loopIteration < pSetup->numBuffLists;
             loopIteration++)
        {
            pPacketSize[loopIteration] = testSetup->packetSize;
        }
    }
    /*initialize digestIsAppended with input parameter */
    symTestSetup.setupData.digestIsAppended = pSetup->digestAppend;

    symTestSetup.numBuffLists = pSetup->numBuffLists;
    symTestSetup.flatBufferSizeInBytes = pSetup->flatBufferSizeInBytes;
    symTestSetup.enableRoundOffPkt = pSetup->enableRoundOffPkt;
    symTestSetup.numLoops = pSetup->numLoops;
    /*reset the stats print function to NULL, we set it to the proper function
     * if the test passes at the end of this function*/
    testSetup->statsPrintFunc = NULL;
    /*assign the array of buffer sizes we are testing to the symmetric test
     * setup*/
    symTestSetup.packetSizeInBytesArray = pPacketSize;
    /*assign our thread a unique memory location to store performance stats*/
    symTestSetup.performanceStats = testSetup->performanceStats;
    memset(symTestSetup.performanceStats, 0, sizeof(perf_data_t));
    symTestSetup.performanceStats->packageId =
        instanceInfo->physInstId.packageId;
    symTestSetup.performanceStats->averagePacketSizeInBytes =
        testSetup->packetSize == PACKET_IMIX ? BUFFER_SIZE_1152
                                             : testSetup->packetSize;

    /* give our thread a logical crypto instance to use*/
    symTestSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    symTestSetup.syncMode = pSetup->syncMode;
    /*store core affinity, this assumes logical cpu core number is the same
     * logicalQaInstace */
    symTestSetup.performanceStats->logicalCoreAffinity =
        testSetup->logicalQaInstance;
    symTestSetup.threadID = testSetup->threadID;
    symTestSetup.isDpApi = pSetup->isDpApi;
    symTestSetup.cryptoSrcOffset = pSetup->cryptoSrcOffset;
    symTestSetup.digestAppend = pSetup->digestAppend;
    symTestSetup.ivLength = pSetup->ivLength;

    if (CPA_TRUE != checkCapability(cyInstances[testSetup->logicalQaInstance],
                                    &symTestSetup))
    {
        PRINT("\nThread %u Invalid test.Capability check failed for the "
              "requested algorithm on the configured instance\n",
              testSetup->threadID);
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        error_flag_g = CPA_TRUE;
        sampleCodeBarrier();
        goto exit;
    }

    /*launch function that does all the work*/
    status = sampleSymmetricPerform(&symTestSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        printSymTestType(&symTestSetup);
        PRINT("Test %u FAILED\n", testSetup->threadID);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
    }
    if ((CPA_STATUS_SUCCESS != status) ||
        (symTestSetup.performanceStats->threadReturnStatus == CPA_STATUS_FAIL))
    {
        /* Stop Cy Service function should be called after all threads
         * complete their execution. This function will be called from
         * WaitForThreadCompletion().*/
        testSetup->statsPrintFunc =
            (stats_print_func_t)stopCyServicesFromCallback;
    }
exit:
    /*free memory and exit*/
    if (pPacketSize != NULL)
    {
        qaeMemFree((void **)&pPacketSize);
    }
    qaeMemFree((void **)&cyInstances);
    qaeMemFree((void **)&instanceInfo);
    sampleCodeThreadComplete(testSetup->threadID);
    return;
}
EXPORT_SYMBOL(sampleSymmetricPerformance);

/******************************************************************************
 * @ingroup sampleSymmetricTest
 *
 * @description
 * setup a symmetric test
 * This function needs to be called from main to setup a symmetric test.
 * then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupSymmetricTest(CpaCySymOp opType,
                             CpaCySymCipherAlgorithm cipherAlg,
                             Cpa32U cipherKeyLengthInBytes,
                             Cpa32U cipherOffset,
                             CpaCyPriority priority,
                             CpaCySymHashAlgorithm hashAlg,
                             CpaCySymHashMode hashMode,
                             Cpa32U authKeyLengthInBytes,
                             CpaCySymAlgChainOrder chainOrder,
                             sync_mode_t syncMode,
                             nested_hash_test_setup_t *nestedModeSetupDataPtr,
                             Cpa32U packetSize,
                             Cpa32U bufferSizeInBytes,
                             Cpa32U numBuffLists,
                             Cpa32U numLoops,
                             Cpa32U digestAppend)
{
    /*thread_setup_g is a multidimensional global array that stores the setup
     * for all thread variations in an array of characters. We store our test
     * setup at the start of the second array ie index 0. There maybe multiple
     * thread types(setups) running as counted by testTypeCount_g*/
    symmetric_test_params_t *symmetricSetup = NULL;
    Cpa8S name[] = {'S', 'Y', 'M', '\0'};

    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    /* Return an error if the number of packets is not modulus zero of the
     * number of packets to cover IMIX packet mix.
     */
    if (packetSize == PACKET_IMIX && (numBuffLists % NUM_PACKETS_IMIX) != 0)
    {
        PRINT_ERR("To ensure that the weighting of IMIX packets is correct "
                  ", the number of buffers (%d) should be a multiple of %d\n",
                  numBuffLists,
                  NUM_PACKETS_IMIX);
        return CPA_STATUS_FAIL;
    }

    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Failed to start Crypto services\n");
        return CPA_STATUS_FAIL;
    }
    if (iaCycleCount_g)
    {
#ifdef POLL_INLINE
        enablePollInline();
#endif
    }
    if (!poll_inline_g)
    {
        /* start polling threads if polling is enabled in the configuration file
         */
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }
    /*as setup is a multidimensional char array we need to cast it to the
     * symmetric structure*/
    memcpy(&thread_name_g[testTypeCount_g][0], name, THREAD_NAME_LEN);
    symmetricSetup =
        (symmetric_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    memset(symmetricSetup, 0, sizeof(symmetric_test_params_t));
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)sampleSymmetricPerformance;
    {
        testSetupData_g[testTypeCount_g].packetSize = packetSize;
        symmetricSetup->setupData.partialsNotRequired = CPA_TRUE;
    }
    /*then we store the test setup in the above location*/
    // symmetricSetup->setupData.sessionPriority=CPA_CY_PRIORITY_HIGH;
    symmetricSetup->setupData.sessionPriority = priority;
    symmetricSetup->setupData.symOperation = opType;
    symmetricSetup->setupData.cipherSetupData.cipherAlgorithm = cipherAlg;
    symmetricSetup->setupData.cipherSetupData.cipherDirection =
        cipherDirection_g;
    symmetricSetup->setupData.cipherSetupData.cipherKeyLenInBytes =
        cipherKeyLengthInBytes;
    symmetricSetup->setupData.hashSetupData.hashAlgorithm = hashAlg;
    symmetricSetup->setupData.hashSetupData.hashMode = hashMode;
    symmetricSetup->isDpApi = CPA_FALSE;
    symmetricSetup->cryptoSrcOffset = cipherOffset;
    /* in this code we limit the digest result len to be the same as the the
     * authentication key len*/
    symmetricSetup->setupData.hashSetupData.digestResultLenInBytes =
        authKeyLengthInBytes;

    /* GCM hash works only on 8,12 and 16 bytes, default to 16 if others */
    if (CPA_CY_SYM_HASH_AES_GCM == hashAlg &&
        (authKeyLengthInBytes != 8 && authKeyLengthInBytes != 12 &&
         authKeyLengthInBytes != 16))
    {
        PRINT("CPA_CY_SYM_HASH_AES_GCM digest length %u unsupported , "
              "defaulting to 16 \n",
              authKeyLengthInBytes);
        symmetricSetup->setupData.hashSetupData.digestResultLenInBytes = 16;
    }

#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
#endif


    // check which kind of hash mode is selected
    if (CPA_CY_SYM_HASH_MODE_NESTED == hashMode)
    { // nested mode
        if (NULL == nestedModeSetupDataPtr)
        {
            PRINT_ERR("Doesn't support nested mode, "
                      "nestedModeSetupDataPtr is NULL\n");
            return CPA_STATUS_FAIL;
        }

        // set the struct for nested hash mode
        /* If random numbers need to be generated */
        if (CPA_TRUE == nestedModeSetupDataPtr->generateRandom)
        {
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .innerPrefixLenInBytes = SHA512_DIGEST_LENGTH_IN_BYTES;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .pInnerPrefixData = symmetricSetup->nestedHashInnerPrefix;
            generateRandomData(symmetricSetup->setupData.hashSetupData
                                   .nestedModeSetupData.pInnerPrefixData,
                               SHA512_DIGEST_LENGTH_IN_BYTES);
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .outerHashAlgorithm = CPA_CY_SYM_HASH_SHA512;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .pOuterPrefixData = symmetricSetup->nestedHashOuterPrefix;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .outerPrefixLenInBytes = SHA512_DIGEST_LENGTH_IN_BYTES;
            generateRandomData(symmetricSetup->setupData.hashSetupData
                                   .nestedModeSetupData.pOuterPrefixData,
                               SHA512_DIGEST_LENGTH_IN_BYTES);
        }
        /* Support for old code */
        else
        {
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData =
                nestedModeSetupDataPtr->nestedSetupData;
        }
    }
    if ((CPA_CY_SYM_HASH_AES_XCBC == hashAlg) &&
        (AES_XCBC_DIGEST_LENGTH_IN_BYTES != authKeyLengthInBytes))
    {
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = AES_XCBC_DIGEST_LENGTH_IN_BYTES;
    }
    else if ((CPA_CY_SYM_HASH_KASUMI_F9 == hashAlg) ||
             (CPA_CY_SYM_HASH_SNOW3G_UIA2 == hashAlg))
    {
        /*
         * KASUMI_F9 and SNOW3G_UIA2 supports authKeyLen=128bits
         * and digestResultLen=32bits
         */
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = KASUMI_F9_OR_SNOW3G_UIA2_KEY_SIZE_128_IN_BYTES;
        symmetricSetup->setupData.hashSetupData.digestResultLenInBytes =
            setHashDigestLen(hashAlg);
    }

#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
    // ZUC-EIA3 supports authKeyLen=128bits and digestResultLen=32bits
    else if (CPA_CY_SYM_HASH_ZUC_EIA3 == hashAlg &&
             authKeyLengthInBytes < KEY_SIZE_256_IN_BYTES)
    {
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = KEY_SIZE_128_IN_BYTES;
        symmetricSetup->setupData.hashSetupData.digestResultLenInBytes =
            setHashDigestLen(hashAlg);
    }
#endif
    else
    {
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = authKeyLengthInBytes;
    }

    symmetricSetup->setupData.algChainOrder = chainOrder;
    symmetricSetup->syncMode = syncMode;
    symmetricSetup->flatBufferSizeInBytes = bufferSizeInBytes;
    symmetricSetup->numLoops = numLoops;
    symmetricSetup->numBuffLists = numBuffLists;
    if (((bufferSizeInBytes != 0) && (packetSize == PACKET_IMIX)) ||
        (bufferSizeInBytes % IV_LEN_FOR_16_BYTE_BLOCK_CIPHER != 0))
    {
        PRINT_ERR("Doesn't support PACKET_IMIX  "
                  "when the flat buffer size is not 0 or "
                  " it's not align with block size (%d): ",
                  bufferSizeInBytes);
        return CPA_STATUS_FAIL;
    }
    symmetricSetup->digestAppend = digestAppend;

    return CPA_STATUS_SUCCESS;
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a cipher test
 * This function needs to be called from main to setup a cipher test.
 * then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupCipherTest(CpaCySymCipherAlgorithm cipherAlg,
                          Cpa32U cipherKeyLengthInBytes,
                          CpaCyPriority priority,
                          sync_mode_t syncMode,
                          Cpa32U packetSize,
                          Cpa32U bufferSizeInBytes,
                          Cpa32U numLists,
                          Cpa32U numLoops)
{
    return setupSymmetricTest(
        CPA_CY_SYM_OP_CIPHER,
        cipherAlg,
        cipherKeyLengthInBytes,
        NOT_USED,
        priority,
        NOT_USED /* hash alg not needed in cipher test*/,
        NOT_USED /* hash mode not needed in cipher test*/,
        NOT_USED /* auth key len not needed in cipher test*/,
        NOT_USED /* chain mode not needed in cipher test*/,
        syncMode,
        NULL, /* nested hash data not needed in cipher test*/
        packetSize,
        bufferSizeInBytes,
        numLists,
        numLoops,
        digestAppended_g);
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a hash test
 * This function needs to be called from main to setup a hash test.
 * then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupHashTest(CpaCySymHashAlgorithm hashAlg,
                        CpaCySymHashMode hashMode,
                        Cpa32U authKeyLengthInBytes,
                        CpaCyPriority priority,
                        sync_mode_t syncMode,
                        Cpa32U packetSize,
                        Cpa32U numBufferLists,
                        Cpa32U numLoops)
{
    return setupSymmetricTest(
        CPA_CY_SYM_OP_HASH,
        NOT_USED /* cipher alg not needed in cipher test*/,
        NOT_USED /* cipher key len not needed in cipher test*/,
        NOT_USED,
        priority,
        hashAlg,
        hashMode,
        authKeyLengthInBytes,
        NOT_USED /* chain mode not needed in cipher test*/,
        syncMode,
        NULL, /* nested hash data not needed in cipher test*/
        packetSize,
        BUFFER_SIZE_0,
        numBufferLists,
        numLoops,
        digestAppended_g);
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test (default High Priority)
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupAlgChainTest(CpaCySymCipherAlgorithm cipherAlg,
                            Cpa32U cipherKeyLengthInBytes,
                            CpaCySymHashAlgorithm hashAlg,
                            CpaCySymHashMode hashMode,
                            Cpa32U authKeyLengthInBytes,
                            CpaCySymAlgChainOrder chainOrder,
                            CpaCyPriority priority,
                            sync_mode_t syncMode,
                            Cpa32U packetSize,
                            Cpa32U bufferSizeInBytes,
                            Cpa32U numBufferLists,
                            Cpa32U numLoops)
{
    return setupSymmetricTest(CPA_CY_SYM_OP_ALGORITHM_CHAINING,
                              cipherAlg,
                              cipherKeyLengthInBytes,
                              NOT_USED,
                              priority,
                              hashAlg,
                              hashMode,
                              authKeyLengthInBytes,
                              chainOrder,
                              syncMode,
                              NULL,
                              packetSize,
                              bufferSizeInBytes,
                              numBufferLists,
                              numLoops,
                              digestAppended_g);
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup an IPsec scenario where payload = IP packet, the IP header is not
 * encrypted thus requires an offset into the buffer to test.
 *
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupIpSecTest(CpaCySymCipherAlgorithm cipherAlg,
                         Cpa32U cipherKeyLengthInBytes,
                         Cpa32U cipherOffset,
                         CpaCySymHashAlgorithm hashAlg,
                         CpaCySymHashMode hashMode,
                         Cpa32U authKeyLengthInBytes,
                         CpaCySymAlgChainOrder chainOrder,
                         Cpa32U packetSize,
                         Cpa32U numBufferLists,
                         Cpa32U numLoops)
{
    return setupSymmetricTest(CPA_CY_SYM_OP_ALGORITHM_CHAINING,
                              cipherAlg,
                              cipherKeyLengthInBytes,
                              cipherOffset,
                              CPA_CY_PRIORITY_HIGH,
                              hashAlg,
                              hashMode,
                              authKeyLengthInBytes,
                              chainOrder,
                              ASYNC,
                              NULL,
                              packetSize,
                              BUFFER_SIZE_0,
                              numBufferLists,
                              numLoops,
                              digestAppended_g);
}
EXPORT_SYMBOL(setupIpSecTest);

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test with High Priority
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupAlgChainTestHP(CpaCySymCipherAlgorithm cipherAlg,
                              Cpa32U cipherKeyLengthInBytes,
                              CpaCySymHashAlgorithm hashAlg,
                              CpaCySymHashMode hashMode,
                              Cpa32U authKeyLengthInBytes,
                              CpaCySymAlgChainOrder chainOrder,
                              sync_mode_t syncMode,
                              Cpa32U packetSize,
                              Cpa32U numBufferLists,
                              Cpa32U numLoops)
{
    return setupAlgChainTest(cipherAlg,
                             cipherKeyLengthInBytes,
                             hashAlg,
                             hashMode,
                             authKeyLengthInBytes,
                             chainOrder,
                             CPA_CY_PRIORITY_HIGH,
                             syncMode,
                             packetSize,
                             DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                             numBufferLists,
                             numLoops);
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test with Normal Priority
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupAlgChainTestNP(CpaCySymCipherAlgorithm cipherAlg,
                              Cpa32U cipherKeyLengthInBytes,
                              CpaCySymHashAlgorithm hashAlg,
                              CpaCySymHashMode hashMode,
                              Cpa32U authKeyLengthInBytes,
                              CpaCySymAlgChainOrder chainOrder,
                              sync_mode_t syncMode,
                              Cpa32U packetSize,
                              Cpa32U numBufferLists,
                              Cpa32U numLoops)
{
    return setupAlgChainTest(cipherAlg,
                             cipherKeyLengthInBytes,
                             hashAlg,
                             hashMode,
                             authKeyLengthInBytes,
                             chainOrder,
                             CPA_CY_PRIORITY_NORMAL,
                             syncMode,
                             packetSize,
                             DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                             numBufferLists,
                             numLoops);
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test fixing High priority and async mode
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupAlgChainTestHPAsync(CpaCySymCipherAlgorithm cipherAlg,
                                   Cpa32U cipherKeyLengthInBytes,
                                   CpaCySymHashAlgorithm hashAlg,
                                   CpaCySymHashMode hashMode,
                                   Cpa32U authKeyLengthInBytes,
                                   CpaCySymAlgChainOrder chainOrder,
                                   Cpa32U packetSize,
                                   Cpa32U numBufferLists,
                                   Cpa32U numLoops)
{
    return setupAlgChainTest(cipherAlg,
                             cipherKeyLengthInBytes,
                             hashAlg,
                             hashMode,
                             authKeyLengthInBytes,
                             chainOrder,
                             CPA_CY_PRIORITY_HIGH,
                             ASYNC,
                             packetSize,
                             DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                             numBufferLists,
                             numLoops);
}

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupAlgChainTestNestedMode(
    CpaCySymCipherAlgorithm cipherAlg,
    Cpa32U cipherKeyLengthInBytes,
    CpaCySymHashAlgorithm hashAlg,
    Cpa32U authKeyLengthInBytes,
    CpaCySymAlgChainOrder chainOrder,
    CpaCyPriority priority,
    sync_mode_t syncMode,
    nested_hash_test_setup_t *nestedModeSetupData,
    Cpa32U packetSize,
    Cpa32U numBufferLists,
    Cpa32U numLoops)
{
    return setupSymmetricTest(CPA_CY_SYM_OP_ALGORITHM_CHAINING,
                              cipherAlg,
                              cipherKeyLengthInBytes,
                              NOT_USED,
                              priority,
                              hashAlg,
                              CPA_CY_SYM_HASH_MODE_NESTED,
                              authKeyLengthInBytes,
                              chainOrder,
                              syncMode,
                              nestedModeSetupData,
                              packetSize,
                              BUFFER_SIZE_0,
                              numBufferLists,
                              numLoops,
                              digestAppended_g);
}

