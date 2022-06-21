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
 * @file cpa_sample_code_cipher_perf.c
 *
 * @defgroup sampleCiperPerf  Cipher Performance code
 *
 * @ingroup sampleCipherPerf
 *
 * @description
 *      This file contains the main cipher performance sample code. It is
 *      capable of performing all ciphers
 *
 *      This code pre-allocates a number of buffers as defined by
 *      setup->numBuffers. The pre-allocated buffers are then
 *      continuously looped until the numLoops is met.
 *      Time stamping is started prior to the
 *      Operation and is stopped when all callbacks have returned.
 *      The packet size and algorithm to be tested is setup using the
 *      setupCipherTest function. The framework is used to create the threads
 *      which calls functions here to execute cipher performance
 *
 *****************************************************************************/

#include "cpa_sample_code_crypto_utils.h"

extern int signOfLife;

/**
 *****************************************************************************
 * @ingroup sampleCipherPerf
 *
 * @description
 *      Callback function for result of perform operation
 *
 *****************************************************************************/
void cipherPerformCallback(void *pCallbackTag,
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
 * @ingroup sampleCipherPerf
 *
 * @description
 * Create a cipher session
 */
static CpaStatus cipherSetupSession(CpaCySymCbFunc pSymCb,
                                    Cpa8U *pCipherKey,
                                    CpaCySymSessionCtx *pSession,
                                    symmetric_test_params_t *setup)
{
    Cpa32U sessionCtxSizeInBytes = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymSessionCtx pLocalSession = NULL;
    Cpa32U cipherKeyLen = 0;
    Cpa32U node = 0;

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }
    /*set the cipher key len*/
    cipherKeyLen = setup->setupData.cipherSetupData.cipherKeyLenInBytes;
    /*generate a random cipher n key*/
    generateRandomData(pCipherKey, cipherKeyLen);
    setup->setupData.cipherSetupData.pCipherKey = pCipherKey;

    /*get size for mem allocation*/
    status = cpaCySymSessionCtxGetSize(
        setup->cyInstanceHandle, &setup->setupData, &sessionCtxSizeInBytes);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCySymSessionCtxGetSize error, status: %d", status);
        return status;
    }
    /* allocate session memory  */
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
    return status;
}

/*****************************************************************************
 * @ingroup sampleCipherPerf
 *
 * @description
 * Setup cipher operation data
 * ****************************************************************************/
static CpaStatus cipherPerformOpDataSetup(CpaCySymSessionCtx pSessionCtx,
                                          Cpa32U *pPacketSize,
                                          CpaCySymOpData *pOpdata,
                                          symmetric_test_params_t *setup)
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
    pOpdata->sessionCtx = pSessionCtx;
    pOpdata->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    /*these only need to be set for cipher and alg chaining */
    pOpdata->cryptoStartSrcOffsetInBytes = 0;
    pOpdata->messageLenToCipherInBytes = 0;
    for (createCount = 0; createCount < setup->numBuffers; createCount++)
    {
        pOpdata->messageLenToCipherInBytes += pPacketSize[createCount];
    }
    /*these only need to be set for hash and alg chaining*/

    /*set IV len depending on what we are testing*/
    if (setup->setupData.cipherSetupData.cipherAlgorithm ==
            CPA_CY_SYM_CIPHER_AES_CBC ||
        setup->setupData.cipherSetupData.cipherAlgorithm ==
            CPA_CY_SYM_CIPHER_AES_CTR ||
        setup->setupData.cipherSetupData.cipherAlgorithm ==
            CPA_CY_SYM_CIPHER_SNOW3G_UEA2
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
        || setup->setupData.cipherSetupData.cipherAlgorithm ==
               CPA_CY_SYM_CIPHER_ZUC_EEA3
#endif
    )
    {
        pOpdata->ivLenInBytes = IV_LEN_FOR_16_BYTE_BLOCK_CIPHER;
    }
    else
    {
        /* in this code we always allocate the IV, but it is not always used
         * this reduces the if/else logic when trying to cater for as many
         * cipher options as possible*/
        pOpdata->ivLenInBytes = IV_LEN_FOR_8_BYTE_BLOCK_CIPHER;
    }

    /*allocate NUMA aware aligned memory for IV*/
    pOpdata->pIv =
        qaeMemAllocNUMA(pOpdata->ivLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == pOpdata->pIv)
    {
        PRINT_ERR("IV is null\n");
        return CPA_STATUS_FAIL;
    }
    memset(pOpdata->pIv, 0, pOpdata->ivLenInBytes);
    /*generate a random IV*/
    generateRandomData(pOpdata->pIv, pOpdata->ivLenInBytes);

    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 * @ingroup sampleCipherPerf
 *
 * @description
 * measures the performance of cipher encryption operations
 * ****************************************************************************/
CpaStatus cipherPerform(symmetric_test_params_t *setup,
                        perf_data_t *pSymData,
                        Cpa32U numOfLoops,
                        CpaCySymOpData *ppOpData,
                        CpaBufferList *ppSrcBuffListArray,
                        CpaCySymCipherDirection cipherDirection)
{
    CpaBoolean verifyResult = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U loopCount = 0;
#ifdef LATENCY_CODE
    Cpa32U submissions = 0;
    Cpa32U i = 0;
    perf_cycles_t request_submit_start[100] = {0};
    perf_cycles_t request_respnse_time[100] = {0};
#endif

    memset(pSymData, 0, sizeof(perf_data_t));
#ifdef LATENCY_CODE
    if (((setup->numBuffers * setup->numLoops) / ONE_THOUSAND_RESPONSES) > 100)
    {
        PRINT_ERR("Error max submissions for latency  must be <= 1 million\n");
        return CPA_STATUS_FAIL;
    }
    pSymData->response_times = request_respnse_time;
#endif
    /*preset the number of ops we plan to submit*/
    pSymData->numOperations = numOfLoops;
    pSymData->retries = 0;
    /* Init the semaphore used in the callback */
    sampleCodeSemaphoreInit(&pSymData->comp, 0);
    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();
    /* Get the time, collect this only for the first
     * request, the callback collects it for the last */
    pSymData->startCyclesTimestamp = sampleCodeTimestamp();
    /* loop around the preallocated buffer list*/
    for (loopCount = 0; loopCount < numOfLoops; loopCount++)
    {
        /* This inner for-loop loops around the number of Buffer Lists
         * that have been preallocated.  Once the array has completed-
         * exit to the outer loop to move on the next iteration of the
         * preallocated loop. */
        do
        {
#ifdef LATENCY_CODE
            if ((loopCount + 1) % ONE_THOUSAND_RESPONSES == 0)
            {
                request_submit_start[submissions] = sampleCodeTimestamp();
            }
#endif
            status = cpaCySymPerformOp(setup->cyInstanceHandle,
                                       pSymData,
                                       ppOpData,
                                       ppSrcBuffListArray,
                                       ppSrcBuffListArray,
                                       /*in-place operation*/
                                       &verifyResult);
            if (status == CPA_STATUS_RETRY)
            {
                setup->performanceStats->retries++;
                AVOID_SOFTLOCKUP;
            }
        } while (CPA_STATUS_RETRY == status);
#ifdef LATENCY_CODE
        if ((loopCount + 1) % ONE_THOUSAND_RESPONSES == 0)
        {
            submissions++;
        }
#endif
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp Error %d\n", status);
            break;
        }
    } /* end of  loop */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pSymData, setup->syncMode, setup->numBuffers, numOfLoops);
    }

#ifdef LATENCY_CODE
    pSymData->minLatency =
        pSymData->response_times[0] - request_submit_start[0];
    pSymData->maxLatency = pSymData->minLatency;
    pSymData->aveLatency = pSymData->minLatency;
    for (i = 1; i < submissions; i++)
    {
        if ((pSymData->response_times[i] - request_submit_start[i]) <
            pSymData->minLatency)
        {
            pSymData->minLatency =
                pSymData->response_times[i] - request_submit_start[i];
        }
        if ((pSymData->response_times[i] - request_submit_start[i]) >
            pSymData->maxLatency)
        {
            pSymData->maxLatency =
                pSymData->response_times[i] - request_submit_start[i];
        }
        pSymData->aveLatency +=
            pSymData->response_times[i] - request_submit_start[i];
    }
    if (submissions > 0)
    {
        do_div(pSymData->aveLatency, submissions);
    }
#endif
    /*clean up the callback semaphore*/
    sampleCodeSemaphoreDestroy(&pSymData->comp);
    return status;
}

/*****************************************************************************
 * @ingroup sampleCipherPerf
 *
 * @description
 * Free memory allocated in the sampleCipherPerform function
 * ****************************************************************************/
void cipherPerformMemFree(symmetric_test_params_t *setup,
                          CpaBufferList *pSrcBuffListArray,
                          CpaCySymOpData *pOpData,
                          CpaCySymSessionCtx *pSessionCtx)
{
    Cpa32U freeMemCount = 0;
    CpaBufferList *buffList = pSrcBuffListArray;

    /*free bufferLists: pBuffers, metaData & source data*/
    if (NULL == buffList)
    {
        PRINT_ERR("bufferList Ptr is NULL\n");
    }
    else
    {
        /* Loop through and free all buffers that have been
         * pre-allocated.*/
        for (freeMemCount = 0; freeMemCount < setup->numBuffers; freeMemCount++)
        {
            if (NULL != buffList->pBuffers[freeMemCount].pData)
            {
                qaeMemFreeNUMA(
                    (void **)&buffList->pBuffers[freeMemCount].pData);
            }
        }
    }
    qaeMemFreeNUMA((void **)&buffList->pPrivateMetaData);
    qaeMemFreeNUMA((void **)&buffList->pBuffers);
    qaeMemFreeNUMA((void **)&pOpData->pIv);
    /* free the session memory - calling code is responsible for
     * removing the session first*/
    if (NULL != *pSessionCtx)
    {
        qaeMemFreeNUMA((void **)pSessionCtx);
    }
}

/**
 *****************************************************************************
 * @ingroup sampleCipherPerf
 *
 * @description
 *  Main executing function
 ******************************************************************************/
CpaStatus sampleCipherPerform(symmetric_test_params_t *setup)
{
    /* start of local variable declarations */
    CpaCySymSessionCtx sessionCtx = NULL;
    CpaCySymOpData opData;
    CpaBufferList buffList;
    perf_data_t *pSymPerfData = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U cipherKey[setup->setupData.cipherSetupData.cipherKeyLenInBytes];
    CpaCySymCbFunc pSymCb = cipherPerformCallback;
    Cpa32U node = 0;
    Cpa32U bufferMetaSize = 0;
    Cpa32U createCount = 0;
    Cpa8U *pBufferMeta = NULL;
    CpaCySymCipherDirection cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return CPA_STATUS_FAIL;
    }
    /*use the preallocated performance stats to store performance data, this
     * points to an element in perfStats array in the framework, each thread
     * points to a unique element of perfStats array*/
    pSymPerfData = setup->performanceStats;
    if (NULL == pSymPerfData)
    {
        PRINT_ERR("perf data pointer is NULL\n");
        cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
        return CPA_STATUS_FAIL;
    }
    memset(pSymPerfData, 0, sizeof(perf_data_t));

    /*init the cipher session*/
    status = cipherSetupSession(pSymCb, cipherKey, &sessionCtx, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cipherSetupSession error, status %d\n", status);
        cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
        return CPA_STATUS_FAIL;
    }

    /* calculate memory size which is required for pPrivateMetaData
     * member of CpaBufferList */
    status = cpaCyBufferListGetMetaSize(
        setup->cyInstanceHandle, setup->numBuffers, &bufferMetaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyBufferListGetMetaSize Failed with status: %d\n",
                  status);
        return status;
    }

    buffList.pBuffers = qaeMemAllocNUMA(
        (sizeof(CpaFlatBuffer) * setup->numBuffers), node, BYTE_ALIGNMENT_64);
    if (NULL == buffList.pBuffers)
    {
        PRINT_ERR("Failed to allocate pBuffers for bufferlist\n");
        cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
        return CPA_STATUS_FAIL;
    }
    /* Allocate memory for pPrivateMetaData */
    pBufferMeta = qaeMemAllocNUMA(bufferMetaSize, node, BYTE_ALIGNMENT_64);
    if (NULL == pBufferMeta)
    {
        PRINT_ERR("Failed to allocate pBufferMeta memory\n");
        cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
        return CPA_STATUS_FAIL;
    }

    /*allocate memory for bufferLists: pBuffers, meta data  and source Data*/
    for (createCount = 0; createCount < setup->numBuffers; createCount++)
    {

        /* Allocate aligned memory for specified packet size on the node that
         * the thread is running on*/
        buffList.pBuffers[createCount].pData =
            qaeMemAllocNUMA(setup->packetSizeInBytesArray[createCount],
                            node,
                            BYTE_ALIGNMENT_64);
        if (buffList.pBuffers[createCount].pData == NULL)
        {
            PRINT_ERR("Failed to allocate packetSizeData[%u]:(%u) memory\n",
                      createCount,
                      setup->packetSizeInBytesArray[createCount]);
            cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
            return CPA_STATUS_FAIL;
        }

        buffList.pBuffers[createCount].dataLenInBytes =
            setup->packetSizeInBytesArray[createCount];

        /*populate the data source with random data*/
        generateRandomData(buffList.pBuffers[createCount].pData,
                           setup->packetSizeInBytesArray[createCount]);
    } /* end of pre allocated buffer for loop */
      /*
       * Fill in elements of buffer list struct.
       */
    buffList.numBuffers = setup->numBuffers;
    buffList.pPrivateMetaData = pBufferMeta;

    /*setup the cipher operation data*/
    status = cipherPerformOpDataSetup(
        sessionCtx, setup->packetSizeInBytesArray, &opData, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cipherPerformOpDataSetup error, status %d\n", status);
        cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
        return status;
    }

    status = cipherPerform(setup,
                           pSymPerfData,
                           setup->numLoops,
                           &opData,
                           &buffList,
                           cipherDirection);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("symPerform error, status %d\n", status);
        cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);
        return status;
    }

    /* Free up resources allocated */
    if (CPA_STATUS_SUCCESS !=
        removeSymSession(setup->cyInstanceHandle, sessionCtx))
    {
        PRINT_ERR("Deregister session failed\n");
        status = CPA_STATUS_FAIL;
    }
    cipherPerformMemFree(setup, &buffList, &opData, &sessionCtx);

    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleCipherPerf
 *
 * @description
 *  Setup a cipher thread for a given packet size or mix
 ******************************************************************************/
void sampleCipherPerformance(single_thread_test_data_t *testSetup)
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
    Cpa32U *pPacketSize;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;

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
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (cyInstances == NULL)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    /* give our thread a logical crypto instance to use*/
    symTestSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    pPacketSize = qaeMemAlloc(sizeof(Cpa32U) * pSetup->numBuffers);
    if (NULL == pPacketSize)
    {
        PRINT_ERR("Could not allocate memory for pPacketSize\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    if (testSetup->packetSize == PACKET_IMIX)
    {
        /*we are testing IMIX so we copy buffer sizes from preallocated
         * array into symTestSetup.numBuffers*/
        Cpa32U indexer = sizeof(packetMix) / sizeof(Cpa32U);
        for (loopIteration = 0; loopIteration < pSetup->numBuffers;
             loopIteration++)
        {
            pPacketSize[loopIteration] = packetMix[loopIteration % indexer];
        }
    }
    else
    {
        /*we are testing a uniform bufferSize, so we set the bufferSize array
         * accordingly*/
        for (loopIteration = 0; loopIteration < pSetup->numBuffers;
             loopIteration++)
        {
            pPacketSize[loopIteration] = testSetup->packetSize;
        }
    }

    /*cast the setup to a known structure so that we can populate our local
     * test setup*/
    symTestSetup.setupData = pSetup->setupData;
    symTestSetup.numBuffers = pSetup->numBuffers;
    symTestSetup.numLoops = pSetup->numLoops;
    /*reset the stats print function to NULL, we set it to the proper function
     * if the test passes at the end of this function*/
    testSetup->statsPrintFunc = NULL;
    /*assign the array of buffer sizes we are testing to the cipher test
     * setup*/
    symTestSetup.packetSizeInBytesArray = pPacketSize;
    /*assign our thread a unique memory location to store performance stats*/
    symTestSetup.performanceStats = testSetup->performanceStats;
    symTestSetup.performanceStats->averagePacketSizeInBytes =
        testSetup->packetSize;
    /* give our thread a logical crypto instance to use*/
    symTestSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    symTestSetup.syncMode = ASYNC;
    /*store core affinity, this assumes logical cpu core number is the same
     * logicalQaInstace */
    symTestSetup.performanceStats->logicalCoreAffinity =
        testSetup->logicalQaInstance;
    symTestSetup.threadID = testSetup->threadID;
    symTestSetup.isDpApi = pSetup->isDpApi;
    symTestSetup.isMultiSGL = CPA_TRUE;
    symTestSetup.cryptoSrcOffset = pSetup->cryptoSrcOffset;
    /*launch function that does all the work*/
    status = sampleCipherPerform(&symTestSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        printSymTestType(&symTestSetup);
        PRINT("Test %u FAILED\n", testSetup->logicalQaInstance);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
    }
    /*free memory and exit*/
    qaeMemFree((void **)&pPacketSize);
    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}

/******************************************************************************
 * @ingroup sampleCipherTest
 *
 * @description
 * setup a cipher test
 * This function needs to be called from main to setup a cipher test.
 * then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupCipherTest2(CpaCySymCipherAlgorithm cipherAlg,
                           Cpa32U cipherKeyLengthInBytes,
                           Cpa32U packetSize,
                           Cpa32U numBuffers,
                           Cpa32U numLoops)
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
    if (packetSize == PACKET_IMIX && (numBuffers % NUM_PACKETS_IMIX) != 0)
    {
        PRINT_ERR("To ensure that the weighting of IMIX packets is correct "
                  ", the number of buffers (%d) should be a multiple of %d\n",
                  numBuffers,
                  NUM_PACKETS_IMIX);
        return CPA_STATUS_FAIL;
    }

    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Failed to start Crypto services\n");
        return CPA_STATUS_FAIL;
    }
    /* start polling threads if polling is enabled in the configuration file */
    if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
    {
        PRINT_ERR("Error creating polling threads\n");
        return CPA_STATUS_FAIL;
    }
    /*as setup is a multidimensional char array we need to cast it to the
     * symmetric structure*/
    memcpy(&thread_name_g[testTypeCount_g][0], name, THREAD_NAME_LEN);
    symmetricSetup =
        (symmetric_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)sampleCipherPerformance;
    testSetupData_g[testTypeCount_g].packetSize = packetSize;
    /*then we store the test setup in the above location*/
    symmetricSetup->setupData.symOperation = CPA_CY_SYM_OP_CIPHER;
    symmetricSetup->setupData.sessionPriority = CPA_CY_PRIORITY_HIGH;
    symmetricSetup->setupData.cipherSetupData.cipherAlgorithm = cipherAlg;
    symmetricSetup->setupData.cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    symmetricSetup->setupData.cipherSetupData.cipherKeyLenInBytes =
        cipherKeyLengthInBytes;
    symmetricSetup->isDpApi = CPA_FALSE;
    symmetricSetup->isMultiSGL = CPA_TRUE;
    symmetricSetup->numBuffers = numBuffers;
    symmetricSetup->numLoops = numLoops;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupCipherTest2);
