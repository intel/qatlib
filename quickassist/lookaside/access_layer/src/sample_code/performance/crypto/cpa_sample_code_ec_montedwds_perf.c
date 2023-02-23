/**
 *****************************************************************************
 *
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
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file cpa_sample_code_ec_montedwds_perf.c
 *
 * @defgroup ecMontEdwdsThreads
 *
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This sample code test runs EcMontEdwds point and generator
 *      multiplication in given amount of loops and buffers. Test measures QAT
 *      performance in operations per second and calculates cost of offload of
 *      EcMontEdwds function. Sample code uses generated test vectors based on
 *      Edwards(448, 25519) and Montgomery(448, 25519) curves. Supported
 *      EcMontEdwds operations are: generator multiplication and point
 *      multiplication.
 *
 *****************************************************************************/

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_sample_code_crypto_utils.h"
#include "icp_sal_poll.h"
#include "qat_perf_cycles.h"
#include "cpa_sample_code_ec_montedwds_vectors.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
extern Cpa32U packageIdCount_g;

CpaBoolean isECMontEdwdsSupported(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyCapabilitiesInfo cap = {0};
    CpaBoolean isECMontEdwdsEnabled = CPA_FALSE;

    status = getCryptoInstanceCapabilities(&cap, ASYM);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("getCryptoInstanceCapabilities failed with status: %d\n",
                  status);
        return isECMontEdwdsEnabled;
    }
    isECMontEdwdsEnabled = cap.ecEdMontSupported;
    return isECMontEdwdsEnabled;
}
EXPORT_SYMBOL(isECMontEdwdsSupported);

/*****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      Callback used after ecMontEdwds operation
 *
 *****************************************************************************/
void ecMontEdwdsCallback(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaBoolean multiplyStatus,
                         CpaFlatBuffer *pXk,
                         CpaFlatBuffer *pYk)
{
    processCallback(pCallbackTag);
}

/***************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      Print the performance stats of the ecMontEdwds operations
 *
 ***************************************************************************/
static CpaStatus ecMontEdwdsPrintStats(thread_creation_data_t *data)
{
    ec_montedwds_test_params_t *setup =
        (ec_montedwds_test_params_t *)data->setupPtr;
    char *generatorText = NULL;
    char *curveTypeText = NULL;

    switch (setup->generator)
    {
        case CPA_TRUE:
            generatorText = "Generator multiplication (kG)";
            break;

        case CPA_FALSE:
            generatorText = "Point multiplcation (kP)";
            break;

        default:
            PRINT("Unknown ECED operation %d\n", setup->generator);
            break;
    }

    switch (setup->curveType)
    {
        case CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE:
            curveTypeText = "Montgomery 25519 curve";
            break;

        case CPA_CY_EC_MONTEDWDS_ED25519_TYPE:
            curveTypeText = "Twisted Edwards 25519 curve";
            break;

        case CPA_CY_EC_MONTEDWDS_CURVE448_TYPE:
            curveTypeText = "Montgomery 448 curve";
            break;

        case CPA_CY_EC_MONTEDWDS_ED448_TYPE:
            curveTypeText = "Twisted Edwards 448 curve";
            break;

        default:
            PRINT("Unknown ECED curve type %d\n", setup->curveType);
            break;
    }

    PRINT("ECMONTEDWDS TEST\n");
    if (reliability_g)
    {
        PRINT("Reliability mode enabled\n");
        PRINT("Vector number         %d\n", setup->vector);
    }
    PRINT("Operation             %s\n", generatorText);
    PRINT("Curve type            %s\n", curveTypeText);

    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/***************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This function allocates data used in ecMontEdwds operations
 *
 ***************************************************************************/
static CpaStatus ecMontEdwdsAllocData(
    ec_montedwds_test_params_t *setup,
    sample_ec_montedwds_vectors_t *testVectors,
    CpaCyEcMontEdwdsPointMultiplyOpData **ppReturnOpData,
    CpaFlatBuffer **ppReturnXk,
    CpaFlatBuffer **ppReturnYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U node = 0;
    Cpa32U numBuffers = 0;
    CpaCyEcMontEdwdsPointMultiplyOpData **ppOpData = NULL;
    CpaFlatBuffer **ppXk = NULL;
    CpaFlatBuffer **ppYk = NULL;

    /* get the node we are running on for local memory allocation */
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }

    /* alloc array of pointers to opData */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = allocArrayOfPointers(
            setup->cyInstanceHandle, (void **)&ppOpData, setup->numBuffers);
        if (CPA_STATUS_SUCCESS != status)
            return status;
    }
    memset(ppOpData,
           0,
           (sizeof(CpaCyEcMontEdwdsPointMultiplyOpData *) * setup->numBuffers));
    *ppReturnOpData = (CpaCyEcMontEdwdsPointMultiplyOpData *)ppOpData;

    /* alloc array of pointers to Xk */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = allocArrayOfPointers(
            setup->cyInstanceHandle, (void **)&ppXk, setup->numBuffers);
        if (CPA_STATUS_SUCCESS != status)
            return status;
    }
    memset(ppXk, 0, (sizeof(CpaFlatBuffer *) * setup->numBuffers));
    *ppReturnXk = (CpaFlatBuffer *)ppXk;

    /* alloc array of pointers to Yk */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = allocArrayOfPointers(
            setup->cyInstanceHandle, (void **)&ppYk, setup->numBuffers);
        if (CPA_STATUS_SUCCESS != status)
            return status;
    }
    memset(ppYk, 0, (sizeof(CpaFlatBuffer *) * setup->numBuffers));
    *ppReturnYk = (CpaFlatBuffer *)ppYk;

    if (CPA_STATUS_SUCCESS == status)
    {
        for (numBuffers = 0; numBuffers < setup->numBuffers; numBuffers++)
        {
            /* alloc memory for opData in buffer */
            ppOpData[numBuffers] =
                qaeMemAllocNUMA(sizeof(CpaCyEcMontEdwdsPointMultiplyOpData),
                                node,
                                BYTE_ALIGNMENT_64);
            if (ppOpData[numBuffers] == NULL)
                return CPA_STATUS_FAIL;
            memset(ppOpData[numBuffers],
                   0,
                   sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));

            /* alloc memory for opData.x.pData in buffer */
            if (testVectors->xSize > 0)
            {
                ppOpData[numBuffers]->x.pData = qaeMemAllocNUMA(
                    testVectors->xSize, node, BYTE_ALIGNMENT_64);
                if (ppOpData[numBuffers]->x.pData == NULL)
                    return CPA_STATUS_FAIL;
                memset(ppOpData[numBuffers]->x.pData, 0, testVectors->xSize);
            }

            /* alloc memory for opData.y.pData in buffer */
            if (testVectors->ySize > 0)
            {
                ppOpData[numBuffers]->y.pData = qaeMemAllocNUMA(
                    testVectors->ySize, node, BYTE_ALIGNMENT_64);
                if (ppOpData[numBuffers]->y.pData == NULL)
                    return CPA_STATUS_FAIL;
                memset(ppOpData[numBuffers]->y.pData, 0, testVectors->ySize);
            }

            /* alloc memory for opData.k.pData in buffer */
            ppOpData[numBuffers]->k.pData =
                qaeMemAllocNUMA(testVectors->kSize, node, BYTE_ALIGNMENT_64);
            if (ppOpData[numBuffers]->k.pData == NULL)
                return CPA_STATUS_FAIL;
            memset(ppOpData[numBuffers]->k.pData, 0, testVectors->kSize);

            /* alloc memory for ppXk CpaFlatBuffer */
            ppXk[numBuffers] =
                qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
            if (ppXk[numBuffers] == NULL)
                return CPA_STATUS_FAIL;
            memset(ppXk[numBuffers], 0, sizeof(CpaFlatBuffer));

            /* alloc memory for Data in ppXk CpaFlatBuffer */
            ppXk[numBuffers]->pData =
                qaeMemAllocNUMA(testVectors->uSize, node, BYTE_ALIGNMENT_64);
            if (ppXk[numBuffers]->pData == NULL)
                return CPA_STATUS_FAIL;
            memset(ppXk[numBuffers]->pData, 0, testVectors->uSize);

            /* alloc memory for ppYk CpaFlatBuffer */
            ppYk[numBuffers] =
                qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
            if (ppYk[numBuffers] == NULL)
                return CPA_STATUS_FAIL;
            memset(ppYk[numBuffers], 0, sizeof(CpaFlatBuffer));

            /* alloc memory for Data in ppYk CpaFlatBuffer */
            if (testVectors->vSize > 0)
            {
                ppYk[numBuffers]->pData = qaeMemAllocNUMA(
                    testVectors->vSize, node, BYTE_ALIGNMENT_64);
                if (ppYk[numBuffers]->pData == NULL)
                    return CPA_STATUS_FAIL;
                memset(ppYk[numBuffers]->pData, 0, testVectors->vSize);
            }
        }
    }

    return status;
}

/***************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This function copies test vectors data to opData
 *
 ***************************************************************************/
static CpaStatus ecMontEdwdsSetupData(
    ec_montedwds_test_params_t *setup,
    sample_ec_montedwds_vectors_t *testVectors,
    CpaCyEcMontEdwdsPointMultiplyOpData **ppOpData,
    CpaFlatBuffer **ppXk,
    CpaFlatBuffer **ppYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numBuffers = 0;

    for (numBuffers = 0; numBuffers < setup->numBuffers; numBuffers++)
    {
        ppOpData[numBuffers]->generator = setup->generator;
        ppOpData[numBuffers]->curveType = setup->curveType;
        ppOpData[numBuffers]->x.dataLenInBytes = testVectors->xSize;
        ppOpData[numBuffers]->y.dataLenInBytes = testVectors->ySize;
        ppOpData[numBuffers]->k.dataLenInBytes = testVectors->kSize;
        ppXk[numBuffers]->dataLenInBytes = testVectors->uSize;
        ppYk[numBuffers]->dataLenInBytes = testVectors->vSize;
            if (testVectors->xSize > 0)
            {
                generateRandomData(ppOpData[numBuffers]->x.pData,
                                   testVectors->xSize);
            }
            if (testVectors->ySize > 0)
            {
                generateRandomData(ppOpData[numBuffers]->y.pData,
                                   testVectors->ySize);
            }
            generateRandomData(ppOpData[numBuffers]->k.pData,
                               testVectors->kSize);
    }

    return status;
}


/***************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This function frees allocated data at the end of test
 *
 ***************************************************************************/
static void ecMontEdwdsFreeData(ec_montedwds_test_params_t *setup,
                                CpaCyEcMontEdwdsPointMultiplyOpData **ppOpData,
                                CpaFlatBuffer **ppXk,
                                CpaFlatBuffer **ppYk)
{
    Cpa32U numBuffers = 0;

    if (ppOpData != NULL)
    {
        for (numBuffers = 0; numBuffers < setup->numBuffers; numBuffers++)
        {
            if (ppOpData[numBuffers] != NULL)
            {
                if (ppOpData[numBuffers]->x.pData != NULL)
                {
                    qaeMemFreeNUMA((void **)&ppOpData[numBuffers]->x.pData);
                }
                if (ppOpData[numBuffers]->y.pData != NULL)
                {
                    qaeMemFreeNUMA((void **)&ppOpData[numBuffers]->y.pData);
                }
                if (ppOpData[numBuffers]->k.pData != NULL)
                {
                    qaeMemFreeNUMA((void **)&ppOpData[numBuffers]->k.pData);
                }
                qaeMemFreeNUMA((void **)&ppOpData[numBuffers]);
            }
        }
        qaeMemFreeNUMA((void **)&ppOpData);
    }

    if (ppXk != NULL)
    {
        for (numBuffers = 0; numBuffers < setup->numBuffers; numBuffers++)
        {
            if (ppXk[numBuffers] != NULL)
            {
                if (ppXk[numBuffers]->pData != NULL)
                {
                    qaeMemFreeNUMA((void **)&ppXk[numBuffers]->pData);
                }
                qaeMemFreeNUMA((void **)&ppXk[numBuffers]);
            }
        }
        qaeMemFreeNUMA((void **)&ppXk);
    }

    if (ppYk != NULL)
    {
        for (numBuffers = 0; numBuffers < setup->numBuffers; numBuffers++)
        {
            if (ppYk[numBuffers] != NULL)
            {
                if (ppYk[numBuffers]->pData != NULL)
                {
                    qaeMemFreeNUMA((void **)&ppYk[numBuffers]->pData);
                }
                qaeMemFreeNUMA((void **)&ppYk[numBuffers]);
            }
        }
        qaeMemFreeNUMA((void **)&ppYk);
    }
}

/***************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      Main function that performs ecMontEdwds operation
 *
 ***************************************************************************/
static CpaStatus ecMontEdwdsPerform(ec_montedwds_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean multiplyStatus = CPA_FALSE;
    Cpa32U numLoops = 0;
    Cpa32U numBuffers = 0;
    perf_data_t *pPerfData = NULL;
    void *cbFunc = NULL;
    CpaCyEcMontEdwdsPointMultiplyOpData **ppOpData = NULL;
    CpaFlatBuffer **ppXk = NULL;
    CpaFlatBuffer **ppYk = NULL;
    sample_ec_montedwds_vectors_t testVectors = {0};
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;

    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
    }
#endif

    /* get memory location to write performance stats to */
    pPerfData = setup->performanceStats;

    /* get the number of operations to be done in this test */
    pPerfData->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;
    coo_init(pPerfData, pPerfData->numOperations);

    /* Initilise semaphore used in callback */
    sampleCodeSemaphoreInit(&pPerfData->comp, 0);

    /* set the callback function if asynchronous mode is set */
    if (ASYNC == setup->syncMode)
    {
        cbFunc = ecMontEdwdsCallback;
    }

    /* get test vectors */
    if (status == CPA_STATUS_SUCCESS)
    {
        status = getEcMontEdwdsTestVectors(
            setup->generator, setup->curveType, setup->vector, &testVectors);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Could not allocate Data\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /* alloc opData */
    if (status == CPA_STATUS_SUCCESS)
    {
        status = ecMontEdwdsAllocData(
            setup,
            &testVectors,
            (CpaCyEcMontEdwdsPointMultiplyOpData **)&ppOpData,
            (CpaFlatBuffer **)&ppXk,
            (CpaFlatBuffer **)&ppYk);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Could not allocate Data\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /* setup opData */
    if (status == CPA_STATUS_SUCCESS)
    {
        status =
            ecMontEdwdsSetupData(setup, &testVectors, ppOpData, ppXk, ppYk);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Could not setup Data\n");
            status = CPA_STATUS_FAIL;
        }
    }

    if (status == CPA_STATUS_SUCCESS)
    {
        /*this barrier will wait until all threads get to this point*/
        sampleCodeBarrier();

        /*record the start time, the callback measures the end time when the
         * last response is received*/
        pPerfData->startCyclesTimestamp = sampleCodeTimestamp();

        for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
        {
            for (numBuffers = 0; numBuffers < setup->numBuffers; numBuffers++)
            {
                do
                {
                    coo_req_start(pPerfData);
                    status =
                        cpaCyEcMontEdwdsPointMultiply(setup->cyInstanceHandle,
                                                      cbFunc,
                                                      pPerfData,
                                                      ppOpData[numBuffers],
                                                      &multiplyStatus,
                                                      ppXk[numBuffers],
                                                      ppYk[numBuffers]);
                    coo_req_stop(pPerfData, status);

                    if (CPA_STATUS_RETRY == status)
                    {
#ifdef POLL_INLINE
                        if (poll_inline_g)
                        {
                            if (instanceInfo2->isPolled)
                            {
                                sampleCodeAsymPollInstance(
                                    setup->cyInstanceHandle, 0);
                                nextPoll = numOps + asymPollingInterval_g;
                            }
                        }
#endif
                        pPerfData->retries++;
                        /*if the acceleration engine is busy pause for a
                         * moment by making a context switch*/
                        if (RETRY_LIMIT ==
                            (pPerfData->retries % (RETRY_LIMIT + 1)))
                        {
                            AVOID_SOFTLOCKUP;
                        }
                    }
                } while (CPA_STATUS_RETRY == status);

                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("cpaCyEcMontEdwdsPointMultiply function failed "
                              "with status:%d, loop: %d, buffer: %d\n",
                              status,
                              numLoops,
                              numBuffers);
                    break;
                }

#ifdef POLL_INLINE
                if (poll_inline_g)
                {
                    if (instanceInfo2->isPolled)
                    {
                        ++numOps;
                        if (numOps == nextPoll)
                        {
                            coo_poll_trad_cy(pPerfData,
                                             setup->cyInstanceHandle,
                                             &pollStatus);
                            if (CPA_STATUS_SUCCESS != pollStatus)
                            {
                                PRINT_ERR(
                                    "coo_poll_trad_cy failed with status: %d\n",
                                    pollStatus);
                            }
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
                }
#endif
            } /* End loop - numBuffers */

            if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }
        } /* End loop - numLoops */

#ifdef POLL_INLINE
        if (poll_inline_g)
        {
            if ((instanceInfo2->isPolled))
            {
                /* Now need to wait for all the inflight Requests */
                pollStatus = cyPollNumOperations(pPerfData,
                                                 setup->cyInstanceHandle,
                                                 pPerfData->numOperations);
                if (CPA_STATUS_SUCCESS != pollStatus)
                {
                    PRINT_ERR("cyPollNumOperations failed with status: %d\n",
                              pollStatus);
                    status = CPA_STATUS_FAIL;
                }
            }
        }
#endif

        if (CPA_STATUS_SUCCESS == status)
        {
            status = waitForResponses(
                pPerfData, setup->syncMode, setup->numBuffers, setup->numLoops);

        }
    }

    coo_average(pPerfData);
    coo_deinit(pPerfData);

    sampleCodeSemaphoreDestroy(&pPerfData->comp);
    ecMontEdwdsFreeData(setup, ppOpData, ppXk, ppYk);

#ifdef POLL_INLINE
    qaeMemFree((void **)&instanceInfo2);
#endif

    return status;
}

/*****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This function starts performance test in thread
 *
 *****************************************************************************/
void ecMontEdwdsPerformance(single_thread_test_data_t *testSetup)
{
    ec_montedwds_test_params_t ecMontEdwdsSetup = {0};
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    ec_montedwds_test_params_t *params =
        (ec_montedwds_test_params_t *)testSetup->setupPtr;
    CpaInstanceInfo2 *instanceInfo = NULL;

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space is does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*set the print function that can be used to print stats at the end of the
     * test*/
    testSetup->statsPrintFunc = (stats_print_func_t)ecMontEdwdsPrintStats;
    /*give our thread a unique memory location to store performance stats*/
    ecMontEdwdsSetup.performanceStats = testSetup->performanceStats;
    memset(ecMontEdwdsSetup.performanceStats, 0, sizeof(perf_data_t));
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (cyInstances == NULL)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances*/
    ecMontEdwdsSetup.threadID = testSetup->threadID;
    ecMontEdwdsSetup.cyInstanceHandle =
        cyInstances[testSetup->logicalQaInstance];

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
        return;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status =
        cpaCyInstanceGetInfo2(ecMontEdwdsSetup.cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        qaeMemFree((void **)&cyInstances);
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (instanceInfo->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo->physInstId.packageId;
    }
    ecMontEdwdsSetup.performanceStats->packageId =
        instanceInfo->physInstId.packageId;
    ecMontEdwdsSetup.syncMode = params->syncMode;
    ecMontEdwdsSetup.generator = params->generator;
    ecMontEdwdsSetup.curveType = params->curveType;
    ecMontEdwdsSetup.vector = params->vector;
    ecMontEdwdsSetup.numBuffers = params->numBuffers;
    ecMontEdwdsSetup.numLoops = params->numLoops;

    /*launch function that does all the work*/
    status = ecMontEdwdsPerform(&ecMontEdwdsSetup);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("ECED Thread %u FAILED\n", testSetup->threadID);
        ecMontEdwdsSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        ecMontEdwdsSetup.performanceStats->threadReturnStatus =
            CPA_STATUS_SUCCESS;
    }

    qaeMemFree((void **)&cyInstances);
    qaeMemFree((void **)&instanceInfo);
    sampleCodeThreadExit();
}

/*****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This function configures threads for ecMontEdwds performance test
 *
 *****************************************************************************/
CpaStatus setupEcMontEdwdsTest(sync_mode_t syncMode,
                               CpaBoolean generator,
                               CpaCyEcMontEdwdsCurveType curveType,
                               Cpa32U vector,
                               Cpa32U numBuffers,
                               Cpa32U numLoops)
{
    /* thread_setup_g is a multi-dimensional array that stores the setup for
     * all thread
     * variations in an array of characters. we store our test setup at the
     * start of the second array ie index 0. There maybe multi thread types
     * (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure*/
    ec_montedwds_test_params_t *ecMontEdwdsSetup = NULL;

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
    if (!poll_inline_g)
    {
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }

    ecMontEdwdsSetup =
        (ec_montedwds_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)ecMontEdwdsPerformance;

    ecMontEdwdsSetup->syncMode = syncMode;
    ecMontEdwdsSetup->generator = generator;
    ecMontEdwdsSetup->curveType = curveType;
    ecMontEdwdsSetup->vector = vector;
    ecMontEdwdsSetup->numBuffers = numBuffers;
    ecMontEdwdsSetup->numLoops = numLoops;

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupEcMontEdwdsTest);
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
