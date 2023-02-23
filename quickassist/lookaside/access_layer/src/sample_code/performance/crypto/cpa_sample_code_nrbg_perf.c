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
 * @file cpa_nrbg_sample.c
 *
 * @ingroup sampleNrbgFunctional
 *
 * @description
 *     This is sample code that implements the NRBG-registered functions. This
 *     also implements the GetEntropy and HealthTest functions using NRGB API.
 *
 *****************************************************************************/
#include "cpa_sample_code_nrbg_perf.h"

/**
 *****************************************************************************
 * @ingroup sampleNrbgFunctional
 *      NRBG Internal Callback Function
 *
 * @description
 *      This is an internal callback function that will be used to signal
 *      the caller that the asynchronous operation is completed. The signal
 *      is performed by calling the client-supplied callback function.
 *
 * @see
 *      IcpSalDrbgGetEntropyInputCbFunc
 *
 *****************************************************************************/
void nrbgPerformCallback(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaFlatBuffer *pOut)
{
    processCallback(pCallbackTag);
}
void nrbgMemFree(nrbg_test_params_t *setup,
                 CpaFlatBuffer *pEntropy,
                 CpaCyNrbgOpData **pOpData)
{
    Cpa32U k = 0;

    /*free verify opData*/
    if (NULL != pOpData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != pEntropy && NULL != pEntropy[k].pData)
            {
                qaeMemFreeNUMA((void **)&pEntropy[k].pData);
            }
            if (NULL != pOpData[k])
            {
                qaeMemFree((void **)&pOpData[k]);
            }
        }
    }
    qaeMemFreeNUMA((void **)&pEntropy);
    qaeMemFreeNUMA((void **)&pOpData);
}

/**
 *****************************************************************************
 * @ingroup sampleNrbgFunctional
 *      NRBG Get Entropy Function
 *
 * @description
 *      This function implements the DRBG implementation-specific
 *      'Get Entropy Input' function by calling cpaCyNrbgGetEntropy API.
 *
 * @see
 *     IcpSalDrbgGetEntropyInputFunc
 *
 *****************************************************************************/

CpaStatus nrbgPerform(nrbg_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    /*pointer to Entropy Buffer*/
    CpaFlatBuffer *pEntropy = NULL;
    /*array of pointers to the operation data structure for each
     * operation*/
    CpaCyNrbgOpData **opData = NULL;
    /*variable to store what cpu thread is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pNrbgData = NULL;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;

    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }
    if (0 == setup->nLenInBytes)
    {
        PRINT_ERR("Invalid parameter -- nLenInBytes\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (0 == setup->numLoops)
    {
        PRINT_ERR("Invalid parameter -- numLoops\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (0 == setup->numBuffers)
    {
        PRINT_ERR("Invalid parameter -- numBuffers\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    /*get memory location to write performance stats to*/
    pNrbgData = setup->performanceStats;
    memset(pNrbgData, 0, sizeof(perf_data_t));

    /*get the number of operations to be done in this test*/
    pNrbgData->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;
    pNrbgData->responses = 0;
    /* Initialize semaphore used in callback */
    sampleCodeSemaphoreInit(&pNrbgData->comp, 0);

    /*verify the signatures to the messages*/

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&opData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("opData mem allocation error\n");
        return CPA_STATUS_FAIL;
    }

    pEntropy = qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
    if (NULL == pEntropy)
    {
        PRINT_ERR("pEntropy mem allocation error\n");
        nrbgMemFree(setup, NULL, opData);
        return CPA_STATUS_FAIL;
    }
    memset(pEntropy, 0, sizeof(CpaFlatBuffer) * setup->numBuffers);

    /*allocate and populate all the CpaCyNrbgOpData buffers*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        opData[i] = qaeMemAlloc(sizeof(CpaCyNrbgOpData));
        if (NULL == opData[i])
        {
            PRINT_ERR("opData[%u] memory allocation error\n", i);
            nrbgMemFree(setup, pEntropy, opData);
            return status;
        }
        memset(opData[i], 0, sizeof(CpaCyNrbgOpData));
        pEntropy[i].pData =
            qaeMemAllocNUMA(setup->nLenInBytes, node, BYTE_ALIGNMENT_64);
        if (NULL == pEntropy[i].pData)
        {
            PRINT_ERR("pEntropy.pData memory allocation error\n");
            qaeMemFreeNUMA((void **)&pEntropy[i].pData);
            return CPA_STATUS_FAIL;
        }
        opData[i]->lengthInBytes = setup->nLenInBytes;
        pEntropy[i].dataLenInBytes = setup->nLenInBytes;
    }

    /*this barrier will wait until all threads get to this point*/
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = nrbgPerformCallback;
    }
    sampleCodeBarrier();

    /*record the start time, the callback measures the end time when the last
     * response is received*/
    pNrbgData->startCyclesTimestamp = sampleCodeTimestamp();
    for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
    {

        for (i = 0; i < setup->numBuffers; i++)
        {
            pNrbgData->numOperations = 1;
            pNrbgData->responses = 0;

            do
            {
                status = cpaCyNrbgGetEntropy(setup->cyInstanceHandle,
                                             cbFunc,
                                             pNrbgData,
                                             opData[i],
                                             &pEntropy[i]);
                if (CPA_STATUS_RETRY == status)
                {
                    pNrbgData->retries++;
                    /*if the acceleration engine is busy pause for a
                     * moment by making a context switch*/
                    if (RETRY_LIMIT == (pNrbgData->retries % (RETRY_LIMIT + 1)))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR(" NRBG function failed with status:%d\n", status);
                nrbgMemFree(setup, pEntropy, opData);
                return status;
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                status = waitForResponses(pNrbgData, setup->syncMode, 1, 1);
            }
        } /*end buffers loop */
    }     /* end of numLoops loop*/

    pNrbgData->numOperations = (Cpa64U)setup->numLoops * setup->numBuffers;
    pNrbgData->responses = pNrbgData->numOperations;
    sampleCodeSemaphoreDestroy(&pNrbgData->comp);

    /*Free all memory*/
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Print the performance stats of the elliptic curve dsa operations
 ***************************************************************************/
CpaStatus nrbgPrintStats(thread_creation_data_t *data)
{
    PRINT("NRBG\n");
    PRINT("NRBG Size %23u\n", data->packetSize);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      setup an elliptic curve performance thread
 ***************************************************************************/
void nrbgPerformance(single_thread_test_data_t *testSetup)
{
    nrbg_test_params_t nrbgSetup;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U continousRngTestFailures = 0;
    nrbg_test_params_t *params = (nrbg_test_params_t *)testSetup->setupPtr;

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call
     * startThreads anyway*/
    startBarrier();
    /*give our thread a unique memory location to store performance stats*/
    nrbgSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        nrbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        nrbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        nrbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        nrbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances*/
    nrbgSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];

    nrbgSetup.nLenInBytes = params->nLenInBytes;
    nrbgSetup.numBuffers = params->numBuffers;
    nrbgSetup.numLoops = params->numLoops;
    nrbgSetup.syncMode = params->syncMode;
    /*launch function that does all the work*/
    status = icp_sal_nrbgHealthTest(nrbgSetup.cyInstanceHandle,
                                    &continousRngTestFailures);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("icp_sal_nrbgHealthTest failed. (status = %d)\n", status);
        nrbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    /*
     * In this sample code, continousRngTestFailures is printed for
     * debug purposes only. Refer to icp_sal_nrbgHealthTest API for
     * more details about this counter.
     */
    /*PRINT("continousRngTestFailures = %d\n", continousRngTestFailures);*/

    status = nrbgPerform(&nrbgSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("NRBG Thread %u FAILED\n", testSetup->logicalQaInstance);
        nrbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc = (stats_print_func_t)nrbgPrintStats;
    }
    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      This function is used to set the parameters to be used in the
 *Non-Deterministic
 *      Random Bit Generation Sample Code performance thread. It is called
 *before the
 *      createThreads function of the framework. The framework replicates it
 *across many
 *      cores
 ***************************************************************************/
CpaStatus setupNrbgTest(Cpa32U nLenInBytes,
                        sync_mode_t syncMode,
                        Cpa32U numBuffers,
                        Cpa32U numLoops)
{
    /* testSetupData_g is a multi-dimensional array that stores the setup for
     * all thread variations in an array of characters. we store our test setup
     * at the start of the second array ie index 0. There maybe multi thread
     * types (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure*/
    nrbg_test_params_t *nrbgSetup = NULL;
    Cpa8S name[] = {'N', 'R', 'B', '\0'};

    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }
    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Error starting Crypto Services\n");
        return CPA_STATUS_FAIL;
    }
    /* start polling threads if polling is enabled in the configuration file */
    if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
    {
        PRINT_ERR("Error creating polling threads\n");
        return CPA_STATUS_FAIL;
    }
    memcpy(&thread_name_g[testTypeCount_g][0], name, THREAD_NAME_LEN);

    nrbgSetup = (nrbg_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)nrbgPerformance;
    testSetupData_g[testTypeCount_g].packetSize = nLenInBytes;

    nrbgSetup->nLenInBytes = nLenInBytes;
    nrbgSetup->syncMode = syncMode;
    nrbgSetup->numBuffers = numBuffers;
    nrbgSetup->numLoops = numLoops;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupNrbgTest);
