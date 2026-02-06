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
 * @file cpa_sample_code_sm2_perf.c
 *
 * @ingroup cryptoThreads
 *
 * @description
 *      This file contains the sm2 performance code.
 *      Including Key Exchange P1/P2
 *      More details about the algorithm is in
 *      http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *****************************************************************************/

#include "cpa_sample_code_sm2_perf.h"

/**
 ******************************************************************************
 * Callback function
 * Sm2 Key Exchange Phase 1 Callback function
 *    Performance statistic
 *
 ******************************************************************************/
static void sm2KeyexP1Callback(void *pCallbackTag,
                               CpaStatus status,
                               void *pOpData,
                               CpaFlatBuffer *pOut)
{
    processCallback(pCallbackTag);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("sm2KeyexP1Callback error status %d\n", status);
    }
}

/**
 ******************************************************************************
 * SM2 key exchange phase 2 post processing
 * SM2 APIs return the results of the point multiplication
 * In this function, continue to calculate the shared key with KDF && SM3 hash
 * param input  : pIntermediateBuffer,pOut
 * param output : pSecretKeyBuffer
 ******************************************************************************/
static CpaStatus sm2KeyExPostProc(sm2_perf_test_t *perf_test, void *ptr)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2KeyExOutputData *pKeyexPKEOut = NULL;
    pKeyexPKEOut = (CpaCyEcsm2KeyExOutputData *)ptr;
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData,
           pKeyexPKEOut->x.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           pKeyexPKEOut->y.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData +
               2 * GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           ZA,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData +
               3 * GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           ZB,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* KDF(Xu||Yu||ZA||ZB,klen) */
    status = kdf(perf_test->perf_buffer->pIntermediateBuffer,
                 perf_test->perf_buffer->pC1Buffer);
    return status;
}

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 key exchange phase 1 operation
 *
 ******************************************************************************/
void sm2KeyexP1MemFree(sm2_test_params_t *setup,
                       CpaCyEcsm2KeyExPhase1OpData **opData,
                       CpaCyEcsm2KeyExOutputData **outData)
{
    Cpa32U k = 0;
    if (NULL != opData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != opData[k])
            {
                qaeMemFreeNUMA((void **)&opData[k]->r.pData);
                qaeMemFreeNUMA((void **)&opData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&opData);
    }
    if (NULL != outData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != outData[k])
            {
                qaeMemFreeNUMA((void **)&outData[k]->x.pData);
                qaeMemFreeNUMA((void **)&outData[k]->y.pData);
                qaeMemFreeNUMA((void **)&outData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&outData);
    }
}

/**
 ******************************************************************************
 * Callback function
 * Sm2 Key Exchange Phase 2 Callback function
 *    Post processing with KDF && SM3 Hash
 *    Performance statistic
 *
 ******************************************************************************/
static void sm2KeyexP2Callback(void *pCallbackTag,
                               CpaStatus status,
                               void *pOpData,
                               CpaFlatBuffer *pOut)
{
    post_proc_data_t *postProcData = NULL;
    sm2_perf_test_t *pPerfTestData = NULL;
    void *ptr = NULL;
    perf_data_t *pPerfData = NULL;

    postProcData = (post_proc_data_t *)pCallbackTag;
    pPerfTestData = postProcData->sm2_perf_test;
    ptr = postProcData->ptr;
    pPerfData = pPerfTestData->setup->performanceStats;

    sm2KeyExPostProc(pPerfTestData, ptr);
    processCallback(pPerfData);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("sm2KeyexP2Callback error status %d\n", status);
    }
}

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 key exchange phase 2 operation
 *
 ******************************************************************************/
void sm2KeyexP2MemFree(sm2_test_params_t *setup,
                       CpaCyEcsm2KeyExPhase2OpData **opData,
                       CpaCyEcsm2KeyExOutputData **outData,
                       post_proc_data_t **post_proc_data)
{
    Cpa32U k = 0;
    if (NULL != opData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != opData[k])
            {
                qaeMemFreeNUMA((void **)&opData[k]->r.pData);
                qaeMemFreeNUMA((void **)&opData[k]->d.pData);
                qaeMemFreeNUMA((void **)&opData[k]->x1.pData);
                qaeMemFreeNUMA((void **)&opData[k]->x2.pData);
                qaeMemFreeNUMA((void **)&opData[k]->y2.pData);
                qaeMemFreeNUMA((void **)&opData[k]->xP.pData);
                qaeMemFreeNUMA((void **)&opData[k]->yP.pData);
                qaeMemFreeNUMA((void **)&opData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&opData);
    }

    if (NULL != outData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != outData[k])
            {
                qaeMemFreeNUMA((void **)&outData[k]->x.pData);
                qaeMemFreeNUMA((void **)&outData[k]->y.pData);
                qaeMemFreeNUMA((void **)&outData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&outData);
    }

    if (NULL != post_proc_data)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != post_proc_data[k])
            {
                qaeMemFreeNUMA((void **)&post_proc_data[k]);
            }
        }
        qaeMemFreeNUMA((void **)&post_proc_data);
    }
}

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 key exchange phase 2 operation
 *       This function is called for key exchange phase 2 performance test.
 *
 ******************************************************************************/
CpaStatus sm2KeyexP2Perform(sm2_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    CpaCyEcsm2Stats64 sm2Stats = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2KeyExPhase2OpData **opData = NULL;
    CpaCyEcsm2KeyExOutputData **outData = NULL;
    /* allocated for every loop */
    post_proc_data_t **post_proc_data = NULL;
    CpaFlatBuffer *pSecretKey = NULL;
    CpaFlatBuffer *pIntermediateBuffer = NULL;
    Cpa32U klen = SECRET_KEY_LEN_IN_BYTE;
    /*variable to store what cpu thread is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pSm2Data = NULL;
    sm2_perf_test_t *sm2PerfTest = NULL;
    sm2_perf_buf_t *sm2PerfBuffer = NULL;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;

    status = cpaCyEcsm2QueryStats64(setup->cyInstanceHandle, &sm2Stats);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Could not retrieve stats, error status %d\n", status);
        return status;
    }
    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }

    sm2PerfTest =
        qaeMemAllocNUMA(sizeof(sm2_perf_test_t), node, BYTE_ALIGNMENT_64);
    if (NULL == sm2PerfTest)
    {
        PRINT_ERR("Memory allocation failure for sm2PerfTest\n");
        return CPA_STATUS_FAIL;
    }

    sm2PerfBuffer =
        qaeMemAllocNUMA(sizeof(sm2_perf_buf_t), node, BYTE_ALIGNMENT_64);
    if (NULL == sm2PerfBuffer)
    {
        PRINT_ERR("Memory allocation failure for sm2PerfBuffer\n");
        goto cleanup;
    }

    initSemaphoreAndVariables(pSm2Data, setup);

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&opData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("opData mem allocation error\n");
        goto cleanup;
    }
    /* allocate memory according to the setup->numBuffers */
    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&post_proc_data, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("post_proc_data mem allocation error\n");
        goto cleanup;
    }

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&outData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("outData mem allocation error\n");
        goto cleanup;
    }

    /*allocate and populate all the operation data buffers*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        opData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2KeyExPhase2OpData), node, BYTE_ALIGNMENT_64);
        if (NULL == opData[i])
        {
            PRINT_ERR("opData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(opData[i], 0, sizeof(CpaCyEcsm2KeyExPhase2OpData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->r,
                             setup->nLenInBytes,
                             setup->random[setup->numBuffers - i - 1].pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->d,
                             setup->nLenInBytes,
                             setup->d2->pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->x1,
                             setup->nLenInBytes,
                             setup->x2[i].pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->x2,
                             setup->nLenInBytes,
                             setup->x1[i].pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->y2,
                             setup->nLenInBytes,
                             setup->y1[i].pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->xP,
                             setup->nLenInBytes,
                             setup->xP->pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->yP,
                             setup->nLenInBytes,
                             setup->yP->pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        outData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2KeyExOutputData), node, BYTE_ALIGNMENT_64);
        if (NULL == outData[i])
        {
            PRINT_ERR("outData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(outData[i], 0, sizeof(CpaCyEcsm2KeyExOutputData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->x,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->y,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_KEYEX_P2_MEM_FREE());
        post_proc_data[i] =
            qaeMemAllocNUMA(sizeof(post_proc_data_t), node, BYTE_ALIGNMENT_64);
        if (NULL == post_proc_data[i])
        {
            PRINT_ERR("Memory allocation failure for post_proc_data\n");
            goto cleanup;
        }
        memset(post_proc_data[i], 0, sizeof(post_proc_data_t));
    }
    /* Set the callback function if asynchronous mode is set */
    if (ASYNC == setup->syncMode)
    {
        cbFunc = (CpaCyGenFlatBufCbFunc)sm2KeyexP2Callback;
    }

    pSecretKey =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pSecretKey,
                         klen,
                         NULL,
                         0,
                         SM2_KEYEX_MSG_MEM_FREE());

    pIntermediateBuffer =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pIntermediateBuffer,
                         4 * GFP_SM2_SIZE_IN_BYTE + KDF_COUNTER_PADDING,
                         NULL,
                         0,
                         SM2_KEYEX_MSG_MEM_FREE());

    /* Temporary buffers for sm2KeyExPostProc */
    sm2PerfBuffer->pC1Buffer = pSecretKey;
    sm2PerfBuffer->pIntermediateBuffer = pIntermediateBuffer;
    sm2PerfBuffer->pKeyexPKEOut = outData[0];

    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();

    /* Record the start time, the callback measures the end time when the last
     * response is received*/
    pSm2Data->startCyclesTimestamp = sampleCodeTimestamp();

    for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            do
            {
                opData[i]->fieldType = setup->fieldType;

                sm2PerfTest->setup = setup;
                sm2PerfTest->perf_buffer = sm2PerfBuffer;
                post_proc_data[i]->sm2_perf_test = sm2PerfTest;
                post_proc_data[i]->ptr = (void *)outData[i];

                status = cpaCyEcsm2KeyExPhase2(setup->cyInstanceHandle,
                                               (CpaCyGenFlatBufCbFunc)cbFunc,
                                               (void *)post_proc_data[i],
                                               opData[i],
                                               outData[i]);

                waitForAEonRetry(status, pSm2Data);
            } while (CPA_STATUS_RETRY == status);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("SM2 Verify function failed with status:%d\n",
                          status);

                goto cleanup;
            }

        } /*end buffers loop */
    }     /* end of numLoops loop*/
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pSm2Data, setup->syncMode, setup->numBuffers, setup->numLoops);
    }

    sampleCodeSemaphoreDestroy(&pSm2Data->comp);
    /*Free all memory*/
    SM2_KEYEX_MSG_MEM_FREE();
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (pSecretKey != NULL)
        SM2_KEYEX_MSG_MEM_FREE();
    if (sm2PerfBuffer != NULL)
        SM2_PERFORM_KEYEX_P2_MEM_FREE();
    return CPA_STATUS_FAIL;
}

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 key exchange phase 1 operation
 *       This function is called for key exchange phase 1 performance test.
 *
 ******************************************************************************/
CpaStatus sm2KeyexP1Perform(sm2_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    CpaCyEcsm2Stats64 sm2Stats = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2KeyExPhase1OpData **opData = NULL;
    CpaCyEcsm2KeyExOutputData **outData = NULL;
    /*variable to store what CPU Node/socket is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pSm2Data = NULL;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;

    status = cpaCyEcsm2QueryStats64(setup->cyInstanceHandle, &sm2Stats);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Could not retrieve stats, error status %d\n", status);
        return status;
    }
    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }

    initSemaphoreAndVariables(pSm2Data, setup);

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&opData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("opData mem allocation error\n");
        goto cleanup;
    }
    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&outData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("outData mem allocation error\n");
        goto cleanup;
    }

    /*allocate and populate all the Operation Data buffers*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        opData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2KeyExPhase1OpData), node, BYTE_ALIGNMENT_64);
        if (NULL == opData[i])
        {
            PRINT_ERR("opData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(opData[i], 0, sizeof(CpaCyEcsm2KeyExPhase1OpData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->r,
                             setup->nLenInBytes,
                             setup->random[i].pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_KEYEX_P1_MEM_FREE());

        outData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2KeyExOutputData), node, BYTE_ALIGNMENT_64);
        if (NULL == outData[i])
        {
            PRINT_ERR("outData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(outData[i], 0, sizeof(CpaCyEcsm2KeyExOutputData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->x,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_KEYEX_P1_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->y,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_KEYEX_P1_MEM_FREE());
    }
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = (CpaCyGenFlatBufCbFunc)sm2KeyexP1Callback;
    }
    pSm2Data->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;
    pSm2Data->responses = 0;
    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();

    /* Record the start time, the callback measures the end time when the last
     * response is received */
    pSm2Data->startCyclesTimestamp = sampleCodeTimestamp();

    for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            do
            {
                opData[i]->fieldType = setup->fieldType;
                status = cpaCyEcsm2KeyExPhase1(setup->cyInstanceHandle,
                                               (CpaCyGenFlatBufCbFunc)cbFunc,
                                               pSm2Data,
                                               opData[i],
                                               outData[i]);

                waitForAEonRetry(status, pSm2Data);

            } while (CPA_STATUS_RETRY == status);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("SM2 Verify function failed with status:%d\n",
                          status);
                goto cleanup;
            }

        } /*end buffers loop */
    }     /* end of numLoops loop*/
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pSm2Data, setup->syncMode, setup->numBuffers, setup->numLoops);
    }

    sampleCodeSemaphoreDestroy(&pSm2Data->comp);
    /*Free all memory*/
    SM2_PERFORM_KEYEX_P1_MEM_FREE();
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    SM2_PERFORM_KEYEX_P1_MEM_FREE();
    return CPA_STATUS_FAIL;
}

