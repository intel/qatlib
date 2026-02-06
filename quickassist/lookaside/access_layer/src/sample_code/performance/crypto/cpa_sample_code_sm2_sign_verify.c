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
 *      Including Sign, Verify
 *      More details about the algorithm is in
 *      http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *****************************************************************************/

#include "cpa_sample_code_sm2_perf.h"

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 signature operation
 *
 ******************************************************************************/
static void sm2SignMemFree(sm2_test_params_t *setup,
                           CpaCyEcsm2SignOpData **opData,
                           Ecsm2SignOutputData **outData)
{
    Cpa32U k = 0;
    if (NULL != opData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != opData[k])
            {
                qaeMemFreeNUMA((void **)&opData[k]->k.pData);
                qaeMemFreeNUMA((void **)&opData[k]->e.pData);
                qaeMemFreeNUMA((void **)&opData[k]->d.pData);
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
                qaeMemFreeNUMA((void **)&outData[k]->r.pData);
                qaeMemFreeNUMA((void **)&outData[k]->s.pData);
                qaeMemFreeNUMA((void **)&outData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&outData);
    }
}

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 signature verification operation
 *
 ******************************************************************************/
void sm2VerifyMemFree(sm2_test_params_t *setup,
                      CpaCyEcsm2VerifyOpData **vOpData)
{
    Cpa32U k = 0;
    if (NULL != vOpData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != vOpData[k])
            {
                qaeMemFreeNUMA((void **)&vOpData[k]->e.pData);
                qaeMemFreeNUMA((void **)&vOpData[k]->r.pData);
                qaeMemFreeNUMA((void **)&vOpData[k]->s.pData);
                qaeMemFreeNUMA((void **)&vOpData[k]->yP.pData);
                qaeMemFreeNUMA((void **)&vOpData[k]->xP.pData);
                qaeMemFree((void **)&vOpData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&vOpData);
    }
}

/**
 ******************************************************************************
 * Callback function
 * Sm2 Signature Callback function
 *    Performance statistic
 *
 ******************************************************************************/
static void sm2SignCallback(void *pCallbackTag,
                            CpaStatus status,
                            void *pOpData,
                            CpaBoolean pass,
                            CpaFlatBuffer *pR,
                            CpaFlatBuffer *pS)

{
    if (CPA_TRUE != pass)
    {
        PRINT_ERR("SM2 Signature point operation failed!\n");
    }
    processCallback(pCallbackTag);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("sm2SignCallback error status %d\n", status);
    }
}

/**
 ******************************************************************************
 * Callback function
 * Sm2 Signature Verification Callback function
 *    Performance statistic
 *
 ******************************************************************************/
static void sm2VerifyCallback(void *pCallbackTag,
                              CpaStatus status,
                              void *pOpData,
                              CpaBoolean verifyStatus)
{
    if (CPA_TRUE != verifyStatus)
    {
        PRINT_ERR("SM2 Signature Verify failed!\n");
    }
    processCallback(pCallbackTag);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("sm2VerifyCallback error status %d\n", status);
    }
}

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Signature operation
 *       This function is called for signature performance test.
 *
 ******************************************************************************/
CpaStatus sm2SignPerform(sm2_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    CpaCyEcsm2Stats64 sm2Stats = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean pStatus = CPA_FALSE;
    CpaCyEcsm2SignOpData **opData = NULL;
    Ecsm2SignOutputData **outData = NULL;
    /* variable to store what CPU Node/socket the thread is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pSm2Data = NULL;
    CpaCyEcsm2SignCbFunc cbFunc = NULL;

    status = cpaCyEcsm2QueryStats64(setup->cyInstanceHandle, &sm2Stats);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Could not retrieve stats, error status %d\n", status);
        return status;
    }
    /* Get the node we are running on for local memory allocation */
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
    /*allocate and populate all the operation data buffers*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        opData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2SignOpData), node, BYTE_ALIGNMENT_64);
        if (NULL == opData[i])
        {
            PRINT_ERR("opData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(opData[i], 0, sizeof(CpaCyEcsm2SignOpData));
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->e,
                             setup->nLenInBytes,
                             setup->digest[i].pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_SIGN_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->k,
                             setup->nLenInBytes,
                             setup->random[i].pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_SIGN_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->d,
                             setup->nLenInBytes,
                             setup->d->pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_SIGN_MEM_FREE());

        outData[i] = qaeMemAllocNUMA(
            sizeof(Ecsm2SignOutputData), node, BYTE_ALIGNMENT_64);
        if (NULL == outData[i])
        {
            PRINT_ERR("outData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(outData[i], 0, sizeof(Ecsm2SignOutputData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->r,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_SIGN_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->s,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_SIGN_MEM_FREE());
    }
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = (CpaCyEcsm2SignCbFunc)sm2SignCallback;
    }

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
                status = cpaCyEcsm2Sign(setup->cyInstanceHandle,
                                        (CpaCyEcsm2SignCbFunc)cbFunc,
                                        pSm2Data,
                                        opData[i],
                                        &pStatus,
                                        &outData[i]->r,
                                        &outData[i]->s);

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
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    SM2_PERFORM_SIGN_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    SM2_PERFORM_SIGN_MEM_FREE();
    return CPA_STATUS_FAIL;
}

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Signature verify operation
 *       This function is called for signatrue verify performance test.
 *
 ******************************************************************************/
CpaStatus sm2VerifyPerform(sm2_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    CpaBoolean verifyStatus = CPA_FALSE;
    CpaCyEcsm2Stats64 sm2Stats = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2VerifyOpData **vOpData = setup->verifyOp;
    /*variable to store what cpu thread is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pSm2Data = NULL;
    CpaCyEcsm2VerifyCbFunc cbFunc = NULL;

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

    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = (CpaCyEcsm2VerifyCbFunc)sm2VerifyCallback;
    }
    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();

    /*record the start time, the callback measures the end time when the last
     * response is received*/
    pSm2Data->startCyclesTimestamp = sampleCodeTimestamp();
    for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            vOpData[i]->fieldType = setup->fieldType;
            do
            {
                status = cpaCyEcsm2Verify(setup->cyInstanceHandle,
                                          (CpaCyEcsm2VerifyCbFunc)cbFunc,
                                          pSm2Data,
                                          vOpData[i],
                                          &verifyStatus);

                waitForAEonRetry(status, pSm2Data);
            } while (CPA_STATUS_RETRY == status);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("SM2 Verify function failed with status:%d\n",
                          status);
                SM2_PERFORM_VERIFY_MEM_FREE();
                return status;
            }
            if (ASYNC != setup->syncMode)
            {
                if (CPA_TRUE != verifyStatus)
                {
                    PRINT_ERR("SM2 Verify function verification failed "
                              "but status = %d\n",
                              status);
                }
                else
                {
                    PRINT_ERR("SM2 Verify function verification "
                              "succeeded\n");
                }
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
    SM2_PERFORM_VERIFY_MEM_FREE();
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

