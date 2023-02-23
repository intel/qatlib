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
 * @file cpa_sample_code_dc_dp.c
 *
 *
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *    This is a sample code that uses Data Plane - Data Compression(DC)  APIs.

 *    This code preallocates a number of buffers as based on the size of each
 *    file defined in the calgary/canterbury corpus. The preallocated buffers
 *    are then populated with the corpus files as defined in
 *    setup->testBuffersize.
 *    Time stamping is started prior to the first performed DC
 *    Operation and is stopped when all callbacks have returned.
 *
 *****************************************************************************/

#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_dc_utils.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_dc_dp.h"
#include "cpa_sample_code_framework.h"
#include "icp_sal_user.h"

#include "icp_sal_poll.h"
#include "busy_loop.h"
#include "qat_perf_cycles.h"
#include "qat_perf_buffer_utils.h"
#ifdef LATENCY_CODE
extern int
    latency_single_buffer_mode; /* set to 1 for single buffer processing */
extern char *cpaStatusToString(CpaStatus status); /* for more readable debug */
#endif

/* Backoff timer implementation variables*/
extern volatile CpaBoolean backoff_timer_g;
extern volatile CpaBoolean backoff_dynamic_g;
extern Cpa32U backoff_static_timer_g;
static inline void printThreadDetails(single_thread_test_data_t *testSetup)
    __attribute__((unused));

/*****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 * Set the polling interval. The Polling interval is the number of successful
 * submissions before the driver is polled for responses
 * ***************************************************************************/
CpaStatus setDcPollingInterval(Cpa64U pollingInterval)
{
    dcPollingInterval_g = pollingInterval;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDcPollingInterval);

/*****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 * Print the polling interval. The Polling interval is the number
 * of successful submissions before the driver is polled for responses
 * ***************************************************************************/
CpaStatus printDcPollingInterval(void)
{
    PRINT("Compression Polling Interval: %u\n", dcPollingInterval_g);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(printDcPollingInterval);

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Callback function after a call to the DC API
 ******************************************************************************/
void dcDpCallbackFunction(CpaDcDpOpData *pOpData)
{
    CpaDcRqResults *pResults = &(pOpData->results);


    perf_data_t *pPerfData = (perf_data_t *)pOpData->pCallbackTag;

    if (CPA_STATUS_SUCCESS != pOpData->responseStatus)
    {
        PRINT_ERR(
            "%s Failed, status = %d, dcResult = %d, responseCount %llu \n",
            __func__,
            pOpData->responseStatus,
            pOpData->results.status,
            (long long int)pPerfData->responses);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }

    /* increment responses */
    pPerfData->responses++;

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        /* Did the latency function setup the array pointer? */
        if (NULL == pPerfData->response_times)
        {
            if (latency_debug)
                PRINT("%s: Callback for non-latency code\n", __FUNCTION__);
        }
        else
        {
            /* Have we sampled too many buffer operations? */
            if (pPerfData->latencyCount > MAX_LATENCY_COUNT)
            {
                PRINT_ERR("pPerfData latencyCount > MAX_LATENCY_COUNT\n");
                return;
            }

            /* Is this the buffer we calculate latency on?
             * And have we calculated too many for array? */
            if (pPerfData->responses == pPerfData->nextCount)
            {
                int i = pPerfData->latencyCount;

                /* Now get the end timestamp - before any print outs */
                pPerfData->response_times[i] = sampleCodeTimestamp();

                pPerfData->nextCount += pPerfData->countIncrement;

                if (latency_debug)
                    PRINT("%s: responses=%u, latencyCount=%d, end[i]:%llu, "
                          "start[i]:%llu, nextCount=%u\n",
                          __FUNCTION__,
                          (unsigned int)pPerfData->responses,
                          i,
                          pPerfData->response_times[i],
                          pPerfData->start_times[i],
                          pPerfData->nextCount);

                pPerfData->latencyCount++;
            }
        }
    }
#endif // LATENCY_CODE

    if (CPA_DC_WDOG_TIMER_ERR == (Cpa8S)pResults->status)
    {
        PRINT_ERR("Slice hang is detected\n");
        /* fw does not respond for any furthur requests in case of slice hang
         * so, exit the test */
        pPerfData->numOperations = pPerfData->responses;
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }

    /*if we have received the pre-set numOperations, then get the clock cycle
     * as a timestamp and post the Semaphore to release parent thread*/
    if (pPerfData->numOperations == pPerfData->responses)
    {
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
    }
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Allocate memory for PhysFlatBuffers
 ******************************************************************************/
static CpaStatus createBuffersDp(Cpa32U buffSize,
                                 Cpa32U numBuffs,
                                 CpaPhysFlatBuffer **pFlatBuffArray,
                                 Cpa32U nodeId)
{
    Cpa32U i = 0;

    for (i = 0; i < numBuffs; i++)
    {
        pFlatBuffArray[i] = qaeMemAllocNUMA(
            (sizeof(CpaPhysFlatBuffer)), nodeId, BYTE_ALIGNMENT_64);
        if (NULL == pFlatBuffArray[i])
        {
            PRINT_ERR(" Unable to allocate flat buffer\n");
            return CPA_STATUS_FAIL;
        }

        pFlatBuffArray[i]->dataLenInBytes = buffSize;

        /* At this point the bufferPhysAddr is not yet a physical address
         * We convert it to a physical address after we use it as a virtual
         * address
         */
        pFlatBuffArray[i]->bufferPhysAddr = (CpaPhysicalAddr)(
            uintptr_t)qaeMemAllocNUMA(buffSize, nodeId, BYTE_ALIGNMENT_64);

        if (NULL == (void *)(uintptr_t)pFlatBuffArray[i]->bufferPhysAddr)
        {
            PRINT_ERR(" Unable to allocate flat buffer phys addr\n");
            return CPA_STATUS_FAIL;
        }

        memset((SAMPLE_CODE_UINT *)(uintptr_t)pFlatBuffArray[i]->bufferPhysAddr,
               0,
               buffSize);
    }
    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Allocate memory for OpData structures
 ******************************************************************************/
static CpaStatus createOpDataDp(Cpa32U numBuffs,
                                CpaDcDpOpData **pOpDataArray,
                                Cpa32U nodeId)
{
    Cpa32U i = 0;

    for (i = 0; i < numBuffs; i++)
    {
        pOpDataArray[i] =
            qaeMemAllocNUMA((sizeof(CpaDcDpOpData)), nodeId, BYTE_ALIGNMENT_8);
        if (NULL == pOpDataArray[i])
        {
            PRINT_ERR(" Unable to allocate op data\n");
            return CPA_STATUS_FAIL;
        }
        else
        {
            memset(pOpDataArray[i], 0, sizeof(CpaDcDpOpData));
        }
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Free memory for PhysFlatBuffers
 ******************************************************************************/
static void freeBuffersDp(CpaPhysFlatBuffer ***pFlatBuffArray,
                          Cpa32U numberOfFiles,
                          compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;

    if (NULL == pFlatBuffArray)
    {
        /* Return silently */
        return;
    }

    for (i = 0; i < numberOfFiles; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            if (NULL != pFlatBuffArray[i][j])
            {
                if (NULL !=
                    (void *)(uintptr_t)pFlatBuffArray[i][j]->bufferPhysAddr)
                {
                    qaeMemFreeNUMA(
                        (void **)&pFlatBuffArray[i][j]->bufferPhysAddr);
                }
                qaeMemFreeNUMA((void **)&pFlatBuffArray[i][j]);
            }
        }
        if (NULL != pFlatBuffArray[i])
        {
            qaeMemFreeNUMA((void **)&pFlatBuffArray[i]);
        }
    }
    qaeMemFreeNUMA((void **)&pFlatBuffArray);
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Print out details of the current thread
 ******************************************************************************/
static inline void printThreadDetails(single_thread_test_data_t *testSetup)
{
    compression_test_params_t *tmpSetup = NULL;
    PRINT("Thread %u, LI %u, ",
          testSetup->threadID,
          testSetup->logicalQaInstance);
    tmpSetup = (compression_test_params_t *)(testSetup->setupPtr);
    if (tmpSetup->setupData.compType == CPA_DC_DEFLATE)
    {
        if (tmpSetup->setupData.huffType == CPA_DC_HT_STATIC)
        {
            PRINT("DeflateDP Static");
        }
        else
        {
            PRINT("DeflateDP Dynamic");
        }
    }
    if (tmpSetup->dcSessDir == CPA_DC_DIR_DECOMPRESS)
    {
        PRINT(" Decompress");
    }
    else
    {
        PRINT(" Compress");
    }
#ifdef RELIABILITY_MODE
    PRINT(" in Reliability mode");
#endif
    PRINT("\n");
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Free memory for the compression op data structs
 ******************************************************************************/
static void freeOpDataDp(CpaDcDpOpData ***compressionOpData,
                         Cpa32U numberOfFiles,
                         compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;

    if (NULL == compressionOpData)
    {
        /* Return silently */
        return;
    }

    for (i = 0; i < numberOfFiles; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            if (NULL != compressionOpData[i][j])
            {
                qaeMemFreeNUMA((void **)&compressionOpData[i][j]);
            }
        }
        if (NULL != compressionOpData[i])
        {
            qaeMemFreeNUMA((void **)&compressionOpData[i]);
        }
    }

    qaeMemFreeNUMA((void **)&compressionOpData);
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Compress the corpus before we do decompression
 ******************************************************************************/
static CpaStatus compressCorpusPreDecomp(compression_test_params_t *setup,
                                         CpaDcDpOpData ***compressionOpData,
                                         perf_data_t *perfData)
{
    /* Local Variable Declaration */
    Cpa32U i = 0, j = 0, k = 0;
    Cpa32U submittedOps = 0;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    /* Status variable */
    CpaStatus status = CPA_STATUS_FAIL;

    for (i = 0; i < numFiles; i++)
    {
        /* call the compress api */
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            do
            {
                status = cpaDcDpEnqueueOp(compressionOpData[i][j], CPA_TRUE);
                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
                    icp_sal_DcPollDpInstance(setup->dcInstanceHandle, 0);
                    AVOID_SOFTLOCKUP;
                }
                if (perfData->threadReturnStatus == CPA_STATUS_FAIL)
                {
                    PRINT_ERR("%s An error was detected in the callback\n",
                              __func__);
                    for (k = 0; k < j; k++)
                    {
                        if (compressionOpData[i][k]->results.status !=
                            CPA_DC_OK)
                        {
                            PRINT("Response %d, dcResult status %d\n",
                                  (i * j) + k,
                                  compressionOpData[i][k]->results.status);
                        }
                    }
                    status = CPA_STATUS_FAIL;
                    break;
                }
            } while (CPA_STATUS_RETRY == status);
            /* Check Status */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Data Compression Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
                break;
            }
            if (++submittedOps == OPERATIONS_POLLING_INTERVAL)
            {
                icp_sal_DcPollDpInstance(setup->dcInstanceHandle, 0);
            }
        } /* End of number of buffers Loop */
    }     /* End of number of Files Loop*/

    /* While there are pending requests, continue to poll */
    status = dcDpPollNumOperations(setup->performanceStats,
                                   setup->dcInstanceHandle,
                                   setup->performanceStats->numOperations);
    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Perform EnqueueBatchOp compression
 *****************************************************************************/
static CpaStatus performDcDpBatchOp(compression_test_params_t *setup,
                                    CpaDcDpOpData ***compressionOpData,
                                    perf_data_t *perfData,
                                    Cpa32U numOfOpsToBatch)
{
    /* Local Variable Declaration */
    Cpa32U i = 0, j = 0, k = 0, numLoops = 0;
    Cpa32U compressLoops = 0;
    Cpa32U remainingOps = 0;
    Cpa32U submittedOps = 0;
    Cpa32U totalBuffers = 0;
    /* Status variable */
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U staticAssign = 0, busyLoopCount = 0;
    Cpa32U busyLoopValue = setup->performanceStats->busyLoopValue;
    perf_cycles_t startBusyLoop = 0, endBusyLoop = 0, totalBusyLoopCycles = 0;
    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    /* Zero performance stats */
    memset(perfData, 0, sizeof(perf_data_t));

    for (i = 0; i < numFiles; i++)
    {
        totalBuffers += setup->numberOfBuffers[i];
    }
    setup->performanceStats->numOperations =
        (Cpa64U)totalBuffers * (Cpa64U)setup->numLoops;
    compressLoops = setup->numLoops;
    perfData->numLoops = setup->numLoops;
    /* this Barrier will waits until all the threads get to this point */
    sampleCodeBarrier();
    coo_init(perfData, perfData->numOperations);

    /* generate the start time stamp */
    perfData->startCyclesTimestamp = sampleCodeTimestamp();

    for (numLoops = 0; numLoops < compressLoops; numLoops++)
    {
        for (i = 0; i < numFiles; i++)
        {
            /* call the compress api */
            for (j = 0; j < setup->numberOfBuffers[i]; j = j + numOfOpsToBatch)
            {
                do
                {
                    /* Is the next batch size greater than the amount of
                     * buffers that we have left
                     */
                    if (j + numOfOpsToBatch > setup->numberOfBuffers[i])
                    {
                        remainingOps = setup->numberOfBuffers[i] - j;
                    }
                    else
                    {
                        remainingOps = numOfOpsToBatch;
                    }
                    coo_req_start(perfData);
                    status = cpaDcDpEnqueueOpBatch(
                        remainingOps, &compressionOpData[i][j], CPA_TRUE);
                    coo_req_stop(perfData, status);
                    if (CPA_STATUS_RETRY == status)
                    {
                        setup->performanceStats->retries++;
                        icp_sal_DcPollDpInstance(setup->dcInstanceHandle, 0);
                        AVOID_SOFTLOCKUP;
                    }
                    if (perfData->threadReturnStatus == CPA_STATUS_FAIL)
                    {
                        PRINT_ERR("%s An error was detected in the callback\n",
                                  __func__);
                        for (k = 0; k < j; k++)
                        {
                            if (compressionOpData[i][k]->results.status !=
                                CPA_DC_OK)
                            {
                                PRINT("Response %d, dcResult status %d\n",
                                      (i * j) + k,
                                      compressionOpData[i][k]->results.status);
                            }
                        }
                        status = CPA_STATUS_FAIL;
                        break;
                    }
                } while (CPA_STATUS_RETRY == status);

                if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
                {
                    startBusyLoop = busyLoopTimeStamp();
                    busyLoop(busyLoopValue, &staticAssign);
                    busyLoopCount++;
                    endBusyLoop = busyLoopTimeStamp();
                    totalBusyLoopCycles =
                        totalBusyLoopCycles + (endBusyLoop - startBusyLoop);
                }

                /* Check Status */
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Data Compression Failed %d\n\n", status);
                    perfData->threadReturnStatus = CPA_STATUS_FAIL;
                    break;
                }
                if (++submittedOps == OPERATIONS_POLLING_INTERVAL)
                {
                    coo_poll_dp_dc(
                        perfData, setup->dcInstanceHandle, &pollStatus);
                }
            } /* End of number of buffers Loop */
            if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }
        } /* End of number of Files Loop*/
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Data Compression Failed %d\n\n", status);
            perfData->threadReturnStatus = CPA_STATUS_FAIL;
            break;
        }
    } /* End of compression Loops */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* While there are pending requests, continue to poll */
        status = dcDpPollNumOperations(setup->performanceStats,
                                       setup->dcInstanceHandle,
                                       setup->performanceStats->numOperations);
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        setup->performanceStats->totalBusyLoopCycles = totalBusyLoopCycles;
        setup->performanceStats->busyLoopCount = busyLoopCount;
        setup->performanceStats->busyLoopValue = busyLoopValue;
    }
    coo_average(perfData);
    coo_deinit(perfData);

    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Perform EnqueueOp compression
 ******************************************************************************/
static CpaStatus performDcDpEnqueueOp(compression_test_params_t *setup,
                                      CpaDcDpOpData ***compressionOpData,
                                      perf_data_t *perfData)
{
    /* Local Variable Declaration */
    Cpa32U i = 0, j = 0, k = 0, numLoops = 0;
    Cpa32U numOps = 0;
    Cpa32U compressLoops = 0;
    CpaBoolean performOpNowFlag = CPA_FALSE;
    /* Status variable */
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa64U numOps2 = 0;
    Cpa32U totalBuffers = 0;
    Cpa64U nextPoll = dcPollingInterval_g;
    Cpa32U retries = 0;
    /* Capture busy loop before memset of performanceStats */
    Cpa32U busyLoopValue = setup->performanceStats->busyLoopValue;
    Cpa32U staticAssign = 0, busyLoopCount = 0;
    Cpa32U numBusyLoops = 0;
    perf_cycles_t startBusyLoop = 0, endBusyLoop = 0, enqueueBusyLoop = 0;

    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    /* backoff timer parameters initialization */
    Cpa32U backoff = 0;

#ifdef LATENCY_CODE
    /* Counts the number of buffers submitted for compression. Only
     * MAX_LATENCY_COUNT of these will be 'latency buffers' whose
     * times are measured */
    Cpa32U submissions = 0;

    /* set when the latency buffer is sent to accelerator */
    perf_cycles_t *request_submit_start = NULL;

    /* set in completion service routine dcPerformCallback() */
    perf_cycles_t *request_respnse_time = NULL;
    const Cpa32U request_mem_sz = sizeof(perf_cycles_t) * MAX_LATENCY_COUNT;
#endif
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    /* Zero performance stats */
    memset(perfData, 0, sizeof(perf_data_t));

    for (i = 0; i < numFiles; i++)
    {
        totalBuffers += setup->numberOfBuffers[i];
    }
    setup->performanceStats->numOperations =
        (Cpa64U)totalBuffers * (Cpa64U)setup->numLoops;
    compressLoops = setup->numLoops;
    perfData->numLoops = setup->numLoops;
    coo_init(perfData, perfData->numOperations);

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (perfData->numOperations > LATENCY_SUBMISSION_LIMIT)
        {
            PRINT_ERR("Error max submissions for latency  must be <= %d\n",
                      LATENCY_SUBMISSION_LIMIT);
            return CPA_STATUS_FAIL;
        }

        request_submit_start = qaeMemAlloc(request_mem_sz);
        request_respnse_time = qaeMemAlloc(request_mem_sz);
        if (request_submit_start == NULL || request_respnse_time == NULL)
        {
            PRINT_ERR("Failed to allocate memory for submission and response "
                      "times\n");
            return CPA_STATUS_FAIL;
        }
        memset(request_submit_start, 0, request_mem_sz);
        memset(request_respnse_time, 0, request_mem_sz);

        /* Calculate how many buffer submissions between latency measurements..
         */
        perfData->countIncrement =
            (setup->numberOfBuffers[0] * setup->numLoops) / MAX_LATENCY_COUNT;

        /* .. and set the next trigger count to this */
        perfData->nextCount = perfData->countIncrement;

        /* How many latency measurements of the MAX_LATENCY_COUNT have been
         * taken so far */
        perfData->latencyCount = 0;

        /* Completion routine sets end times in the array indirectly */
        perfData->response_times = request_respnse_time;
        perfData->start_times = request_submit_start; /* for debug */

        if (latency_debug)
            PRINT("LATENCY_CODE: Initial nextCount %u, countIncrement %u\n",
                  perfData->nextCount,
                  perfData->countIncrement);
    }
#endif
    /* this Barrier will waits until all the threads get to this point */
    sampleCodeBarrier();

    /* generate the start time stamp */
    perfData->startCyclesTimestamp = sampleCodeTimestamp();

    for (numLoops = 0; numLoops < compressLoops; numLoops++)
    {
        for (i = 0; i < numFiles; i++)
        {
            /* Loop through all our buffers and call EnqueueOp, until we have
             * enqueued numRequests, and when we do, call performOpNow to clear
             * the ring and actually execute the operations */
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                /* if we have reached the enqueue limit or we are about to
                 * submit the last buffer of the current corpus file then
                 * enqueue and perform the enqueued operations now.
                 */
                if (++numOps % setup->numRequests == 0 ||
                    j + 1 == setup->numberOfBuffers[i])
                {
                    performOpNowFlag = CPA_TRUE;
                }
                else
                {
                    performOpNowFlag = CPA_FALSE;
                }

                do
                {
#ifdef LATENCY_CODE
                    if (latency_enable)
                    {
                        if (submissions + 1 == perfData->nextCount)
                        {
                            int i = perfData->latencyCount;

                            /* When this buffer has been processed the
                             * 'submissions'
                             * count will be incremented and checked in the
                             * dcPerformCallback()
                             * routine. So we grab it's start time now.
                             */
                            if (latency_debug)
                                PRINT("%s: status=%s submissions=%u, "
                                      "nextCount=%u, latencyCount=%d\n",
                                      __FUNCTION__,
                                      cpaStatusToString(status),
                                      submissions,
                                      perfData->nextCount,
                                      i);

                            /* Must do this after any print outs */
                            /* NOTE: Will be overwritten if CPA_STATUS_RETRY */
                            request_submit_start[perfData->latencyCount] =
                                sampleCodeTimestamp();
                        }
                    }
#endif
                    coo_req_start(perfData);

                    status = cpaDcDpEnqueueOp(compressionOpData[i][j],
                                              performOpNowFlag);
                    coo_req_stop(perfData, status);
                    if (CPA_STATUS_RETRY == status)
                    {
                        setup->performanceStats->retries++;
                        coo_poll_dp_dc(
                            perfData, setup->dcInstanceHandle, &pollStatus);
                        nextPoll = numOps2 + dcPollingInterval_g;
                        AVOID_SOFTLOCKUP;
                    }
                    if (perfData->threadReturnStatus == CPA_STATUS_FAIL)
                    {
                        PRINT_ERR("%s An error was detected in the callback\n",
                                  __func__);
                        for (k = 0; k < j; k++)
                        {
                            if (compressionOpData[i][k]->results.status !=
                                CPA_DC_OK)
                            {
                                PRINT("Response %d, dcResult status %d\n",
                                      (i * j) + k,
                                      compressionOpData[i][k]->results.status);
                            }
                        }
                        status = CPA_STATUS_FAIL;
                        break;
                    }
                    if (CPA_STATUS_RETRY == status)
                    {
                        if (backoff_timer_g && backoff_dynamic_g)
                        {
                            /*
                             * Backoff a bit if submission was unsuccessful
                             */
                            for (k = 1; k <= backoff; k++)
                            {
                                /*
                                 *  do nothing
                                 */
                                __asm__ volatile("nop");
                            }
                            /*
                             * increase the backoff interval after the
                             * unsuccessful submission.
                             * if the backoff is too big, set it 0 (this is done
                             * for the large packets as they keep device busy
                             * and backoff could became unnecessary long)
                             */
                            if (backoff < DP_BACKOFF_TIMER_MAX)
                            {
                                backoff += DP_BACKOFF_STEP_FORWARD;
                            }
                            else
                            {
                                backoff = 0;
                            }
                        }
                        else
                        {
                            /* if  requested just to wait certain number of busy
                             * loop cycles (static timer) */
                            if (backoff_timer_g)
                            {
                                for (k = 1; k <= backoff_static_timer_g; k++)
                                {
                                    /*
                                     *  do nothing
                                     */
                                    __asm__ volatile("nop");
                                }
                            }
                        }
                    }
                    else
                    {
                        if (backoff_timer_g && backoff_dynamic_g)
                        {
                            /* decrease the backoff  value after the successful
                             * submission */
                            if (backoff > DP_BACKOFF_STEP_BACK)
                            {
                                backoff -= DP_BACKOFF_STEP_BACK;
                            }
                        }
                    }
                } while (CPA_STATUS_RETRY == status);
#ifdef LATENCY_CODE
                if (latency_enable)
                {
                    /* Another buffer has been submitted to the accelerator */
                    submissions++;

                    /* Have we been requested to process one buffer at a time.
                     * This
                     * will result in no retries and so the best latency times.
                     */
                    if (latency_single_buffer_mode != 0)
                    {
                        /* Must now wait until this buffer is processed by the
                         * CPM */
                        while (perfData->responses != submissions)
                        {
                            /* Keep polling until compression of the buffer
                             * completes
                             * and dcPerformCallback() increments
                             * perfData->responses */
                            icp_sal_DcPollDpInstance(setup->dcInstanceHandle,
                                                     0);
                        }
                    }
                }
#endif
                if (CPA_CC_BUSY_LOOPS == iaCycleCount_g && performOpNowFlag)
                {
                    if (busyLoopValue > 0)
                    {
                        startBusyLoop = busyLoopTimeStamp();
                        busyLoop(busyLoopValue, &staticAssign);
                        endBusyLoop = busyLoopTimeStamp();
                        enqueueBusyLoop += endBusyLoop - startBusyLoop;
                        startBusyLoop = 0;
                        endBusyLoop = 0;
                    }
                    busyLoopCount++;
                }
                ++numOps2;
                if ((numOps2 == nextPoll) ||
                    (numOps % OPERATIONS_POLLING_INTERVAL == 0))
                {
                    coo_poll_dp_dc(
                        perfData, setup->dcInstanceHandle, &pollStatus);
                    if (CPA_STATUS_FAIL == pollStatus)

                    {
                        status = CPA_STATUS_FAIL;
                        PRINT_ERR("icp_sal_DcPollDpInstance Failed %d\n\n",
                                  status);
                    }
                    if (numOps2 == nextPoll)
                    {
                        nextPoll = numOps2 + dcPollingInterval_g;
                    }
                }
                /* Check Status */
                if (CPA_STATUS_SUCCESS != status)
                {
                    break;
                }
            } /* End of number of buffers Loop */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Data Compression Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
                break;
            }
        } /* End of number of Files Loop*/
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
    } /* End of compression Loops */
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        if (busyLoopValue > 0 && busyLoopCount > 0)
        {
            busyLoopTimeStamp();
            startBusyLoop = busyLoopTimeStamp();
            for (numBusyLoops = 0; numBusyLoops < busyLoopCount; numBusyLoops++)
            {
                busyLoop(busyLoopValue, &staticAssign);
            }
            endBusyLoop = busyLoopTimeStamp();
        }
    }

    /* While there are pending requests, continue to poll */
    if (CPA_STATUS_SUCCESS !=
        dcDpPollNumOperationsRetries(setup->performanceStats,
                                     setup->dcInstanceHandle,
                                     setup->performanceStats->numOperations,
                                     &retries))
    {
        PRINT_ERR("dcDpPollNumOperationsRetries Failed \n");
        status = CPA_STATUS_FAIL;
    }
    setup->performanceStats->pollRetries += retries;
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        setup->performanceStats->busyLoopValue = busyLoopValue;
        setup->performanceStats->busyLoopCount = busyLoopCount;

        setup->performanceStats->totalBusyLoopCycles = enqueueBusyLoop;

        /* Since all responses could have already been processed before calling
         * dcDpPollNumOperationsRetries, we need to ensure we only count the
         * latest busy loop in case it was actually needed */
        if (setup->performanceStats->endCyclesTimestamp > endBusyLoop)
        {
            setup->performanceStats->totalBusyLoopCycles +=
                endBusyLoop - startBusyLoop;
        }

        setup->performanceStats->offloadCycles =
            (setup->performanceStats->endCyclesTimestamp -
             setup->performanceStats->startCyclesTimestamp) -
            setup->performanceStats->totalBusyLoopCycles;

        do_div(setup->performanceStats->offloadCycles,
               setup->performanceStats->responses);
    }

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (latency_debug)
            PRINT("%s: Calculating min, max and ave latencies...\n",
                  __FUNCTION__);

        perfData->minLatency = MAX_LATENCY_LIMIT; /* Will be less than this */
        perfData->maxLatency = 0;                 /* Will be more than this */
        /* Let's accumulate in 'aveLatency' all the individual 'latency'
         * times. Typically, there should be MAX_LATENCY_COUNT of these.
         * We also calculate min/max so we can get a sense of the variance.
         */

        for (i = 0; i < perfData->latencyCount; i++)
        {
            perf_cycles_t latency =
                perfData->response_times[i] - request_submit_start[i];
            perfData->aveLatency += latency;

            if (latency < perfData->minLatency)
                perfData->minLatency = latency;
            if (latency > perfData->maxLatency)
                perfData->maxLatency = latency;

            if (latency_debug)
                PRINT("%d, end[i]:%llu, start[i]:%llu, min:%llu, ave:%llu, "
                      "max:%llu\n",
                      i,
                      perfData->response_times[i],
                      request_submit_start[i],
                      perfData->minLatency,
                      perfData->aveLatency,
                      perfData->maxLatency);
        }
        if (perfData->latencyCount > 0)
        {
            /* Then scale down this accumulated value to get the average.
             * This will be reported by dcPrintStats() at the end of the test */
            do_div(perfData->aveLatency, perfData->latencyCount);
        }
        qaeMemFree((void **)&request_respnse_time);
        qaeMemFree((void **)&request_submit_start);
    }
#endif
    coo_average(perfData);
    coo_deinit(perfData);

    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Main executing function which selects the operation type to be performed(
 *  Enqueue/Batch) and the direction of the operation(compress/decompress)
 ******************************************************************************/
static CpaStatus PerformOp(compression_test_params_t *setup,
                           CpaDcDpOpData ***compressionOpData,
                           CpaDcDpOpData ***decompressionOpData,
                           perf_data_t *perfData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    switch (setup->dpTestType)
    {
        case DC_DP_ENQUEUEING:
            if (CPA_DC_DIR_COMPRESS == setup->dcSessDir)
            {
                status =
                    performDcDpEnqueueOp(setup, compressionOpData, perfData);
#ifdef LATENCY_CODE
                if ((latency_enable) && (latency_debug))
                {
                    PRINT("%s: performDcDpEnqueueOp() returns=%d\n",
                          __FUNCTION__,
                          (int)status);
                }
#endif
            }
            else
            {
                status =
                    performDcDpEnqueueOp(setup, decompressionOpData, perfData);
            }
            break;
        case DC_DP_BATCHING:
            if (CPA_DC_DIR_COMPRESS == setup->dcSessDir)
            {
                status = performDcDpBatchOp(
                    setup, compressionOpData, perfData, setup->numRequests);
            }
            else
            {
                status = performDcDpBatchOp(
                    setup, decompressionOpData, perfData, setup->numRequests);
            }
            break;
        default:
            PRINT_ERR("Neither enqueueing or batching mode\n");
            return CPA_STATUS_FAIL;
    }
    return status;
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
static CpaStatus performOffloadCalculation(compression_test_params_t *setup,
                                           CpaDcDpOpData ***compressionOpData,
                                           CpaDcDpOpData ***decompressionOpData,
                                           perf_data_t *perfData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32S baseThroughput = 0, currentThroughput = 0;
    Cpa32U packetSize = 0, lowerBound = 0, upperBound = 0;
    perf_data_t *pPerfData = setup->performanceStats;

    pPerfData->busyLoopValue = 1;

    packetSize = setup->bufferSize;

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
        status =
            PerformOp(setup, compressionOpData, decompressionOpData, perfData);
        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);
    }

    upperBound = pPerfData->busyLoopValue;

    /* Binary Search for no retries and maintaining throughput */
    do
    {
        pPerfData->busyLoopValue = (upperBound + lowerBound) / 2;

        /* PERFORM OP */
        status =
            PerformOp(setup, compressionOpData, decompressionOpData, perfData);
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
    } while (CPA_STATUS_SUCCESS == status && pPerfData->retries != 0);

    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Main executing function which allocates/frees memory which is required,
 *  and performs Enqueue/Batch operations as required
 ******************************************************************************/
static CpaStatus dcDpPerform(compression_test_params_t *setup)
{
    /* Looping control variables */
    Cpa32U i = 0, j = 0;

    /* Status variable */
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* NUMA node ID */
    Cpa32U nodeId = 0;

    /* File data pointer */
    Cpa8U *fileDataPtr = NULL;

    /* Performance data Structure */
    perf_data_t *perfData = NULL;

    /* Total num of buffers */
    Cpa32U totalBuffs = 0;

    /* Buffer size */
    Cpa32U bufferSize = 0;

    /* Dest Buffer size */
    Cpa32U destBufferSize = 0;

    /* Session size */
    Cpa32U sessionSize = 0;

    /* Session handle */
    CpaDcSessionHandle *pSessionHandle = NULL;
    Cpa32U removeStatus = 0;
    /* Session direction */
    CpaDcSessionDir dcSessDirReq = CPA_DC_DIR_COMPRESS;

    /* Buffer counters */
    Cpa32U amountOfFullBuffers = 0;

    /* Two dimensional array of CpaDcDpOpData pointers which will be used to
     * reference values from a 2 dimensional array through the corpus file and
     * buffer number
     */
    CpaDcDpOpData ***compressionOpData = NULL;
    CpaDcDpOpData ***decompressionOpData = NULL;

    /* Declare src, dst & comp buffers */
    CpaPhysFlatBuffer ***srcFlatBuffArray = NULL;
    CpaPhysFlatBuffer ***dstFlatBuffArray = NULL;
    CpaPhysFlatBuffer ***cmpFlatBuffArray = NULL;
    Cpa32U numFiles = 0;
    const corpus_file_t *fileArray = NULL;

    if (NULL == setup)
    {
        PRINT_ERR("Test Setup Pointer is NULL\n");
        return CPA_STATUS_FAIL;
    }
    numFiles = getNumFilesInCorpus(setup->corpus);
    fileArray = getFilesInCorpus(setup->corpus);

    dcSessDirReq = setup->dcSessDir;
    perfData = setup->performanceStats;
    bufferSize = setup->bufferSize;

    /* Check what NUMA node we are on in order to allocate memory */
    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return status;
    }

    srcFlatBuffArray = qaeMemAllocNUMA(
        (numFiles * sizeof(CpaPhysFlatBuffer *)), nodeId, BYTE_ALIGNMENT_64);
    /* Check for NULL */
    if (NULL == srcFlatBuffArray)
    {
        PRINT_ERR("unable to allocate srcFlatBuffArray\n");
        return CPA_STATUS_FAIL;
    }

    dstFlatBuffArray = qaeMemAllocNUMA(
        (numFiles * sizeof(CpaPhysFlatBuffer *)), nodeId, BYTE_ALIGNMENT_64);
    /* Check for NULL */
    if (NULL == dstFlatBuffArray)
    {
        qaeMemFreeNUMA((void **)&srcFlatBuffArray);
        PRINT_ERR("unable to allocate dstFlatBuffArray \n");
        return CPA_STATUS_FAIL;
    }

    cmpFlatBuffArray = qaeMemAllocNUMA(
        (numFiles * sizeof(CpaPhysFlatBuffer *)), nodeId, BYTE_ALIGNMENT_64);
    /* Check for NULL */
    if (NULL == cmpFlatBuffArray)
    {
        qaeMemFreeNUMA((void **)&srcFlatBuffArray);
        qaeMemFreeNUMA((void **)&dstFlatBuffArray);
        PRINT_ERR("unable to allocate cmpFlatBuffArray \n");
        return CPA_STATUS_FAIL;
    }

    compressionOpData = qaeMemAllocNUMA(
        (numFiles * sizeof(CpaDcDpOpData *)), nodeId, BYTE_ALIGNMENT_64);
    /* Check for NULL */
    if (NULL == compressionOpData)
    {
        qaeMemFreeNUMA((void **)&srcFlatBuffArray);
        qaeMemFreeNUMA((void **)&dstFlatBuffArray);
        qaeMemFreeNUMA((void **)&cmpFlatBuffArray);
        PRINT_ERR("unable to allocate compressionOpData \n");
        return CPA_STATUS_FAIL;
    }

    decompressionOpData = qaeMemAllocNUMA(
        (numFiles * sizeof(CpaDcDpOpData *)), nodeId, BYTE_ALIGNMENT_64);
    /* Check for NULL */
    if (NULL == decompressionOpData)
    {
        qaeMemFreeNUMA((void **)&srcFlatBuffArray);
        qaeMemFreeNUMA((void **)&dstFlatBuffArray);
        qaeMemFreeNUMA((void **)&cmpFlatBuffArray);
        qaeMemFreeNUMA((void **)&compressionOpData);
        PRINT_ERR("unable to allocate decompressionOpData \n");
        return CPA_STATUS_FAIL;
    }

    /* populate the flat buffer array with number of buffers required
     * for each file and allocate the memory
     */
    for (i = 0; i < numFiles; i++)
    {
        /* add up the number of buffers required for
         * complete corpus, this counter will be used to get the
         * number of call backs invoked
         */
        totalBuffs += setup->numberOfBuffers[i];
        /* allocate the memory for src, destination and compare buffers
         * for each file
         */
        srcFlatBuffArray[i] = qaeMemAllocNUMA(
            (setup->numberOfBuffers[i] * (sizeof(CpaPhysFlatBuffer *))),
            nodeId,
            BYTE_ALIGNMENT_64);
        /* Check for NULL */
        if (NULL == srcFlatBuffArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for srcFlatBuffArray\n ");
            freeBuffersDp(srcFlatBuffArray, i, setup);
            freeBuffersDp(dstFlatBuffArray, i, setup);
            freeBuffersDp(cmpFlatBuffArray, i, setup);
            freeOpDataDp(compressionOpData, i, setup);
            freeOpDataDp(decompressionOpData, i, setup);

            return CPA_STATUS_FAIL;
        }

        dstFlatBuffArray[i] = qaeMemAllocNUMA(
            (setup->numberOfBuffers[i] * (sizeof(CpaPhysFlatBuffer *))),
            nodeId,
            BYTE_ALIGNMENT_64);
        /* Check for NULL */
        if (NULL == dstFlatBuffArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for dstFlatBuffArray\n ");
            freeBuffersDp(srcFlatBuffArray, i, setup);
            freeBuffersDp(dstFlatBuffArray, i, setup);
            freeBuffersDp(cmpFlatBuffArray, i, setup);
            freeOpDataDp(compressionOpData, i, setup);
            freeOpDataDp(decompressionOpData, i, setup);

            return CPA_STATUS_FAIL;
        }

        cmpFlatBuffArray[i] = qaeMemAllocNUMA(
            (setup->numberOfBuffers[i] * (sizeof(CpaPhysFlatBuffer *))),
            nodeId,
            BYTE_ALIGNMENT_64);
        /* Check for NULL */
        if (NULL == cmpFlatBuffArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for cmpFlatBuffArray\n ");
            freeBuffersDp(srcFlatBuffArray, i, setup);
            freeBuffersDp(dstFlatBuffArray, i, setup);
            freeBuffersDp(cmpFlatBuffArray, i, setup);
            freeOpDataDp(compressionOpData, i, setup);
            freeOpDataDp(decompressionOpData, i, setup);

            return CPA_STATUS_FAIL;
        }

        compressionOpData[i] = qaeMemAllocNUMA(
            (setup->numberOfBuffers[i] * (sizeof(CpaDcDpOpData *))),
            nodeId,
            BYTE_ALIGNMENT_64);
        /* Check for NULL */
        if (NULL == compressionOpData[i])
        {
            PRINT_ERR("Unable to allocate Memory for compressionOpData\n ");
            freeBuffersDp(srcFlatBuffArray, i, setup);
            freeBuffersDp(dstFlatBuffArray, i, setup);
            freeBuffersDp(cmpFlatBuffArray, i, setup);
            freeOpDataDp(compressionOpData, i, setup);
            freeOpDataDp(decompressionOpData, i, setup);

            return CPA_STATUS_FAIL;
        }

        decompressionOpData[i] = qaeMemAllocNUMA(
            (setup->numberOfBuffers[i] * (sizeof(CpaDcDpOpData *))),
            nodeId,
            BYTE_ALIGNMENT_64);
        /* Check for NULL */
        if (NULL == decompressionOpData[i])
        {
            PRINT_ERR("Unable to allocate Memory for decompressionOpData\n ");
            freeBuffersDp(srcFlatBuffArray, i, setup);
            freeBuffersDp(dstFlatBuffArray, i, setup);
            freeBuffersDp(cmpFlatBuffArray, i, setup);
            freeOpDataDp(compressionOpData, i, setup);
            freeOpDataDp(decompressionOpData, i, setup);

            return CPA_STATUS_FAIL;
        }
    }

    /* For compression,the destination buffer size is obtained using
     * Compress Bound API.*/
    status = qatGetCompressBoundDestinationBufferSize(
        setup, bufferSize, &destBufferSize);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get the destination buffer size using Compress "
                  "Bound API\n");
        freeBuffersDp(srcFlatBuffArray, numFiles, setup);
        freeBuffersDp(dstFlatBuffArray, numFiles, setup);
        freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
        freeOpDataDp(compressionOpData, numFiles, setup);
        freeOpDataDp(decompressionOpData, numFiles, setup);

        return CPA_STATUS_FAIL;
    }

    /* Allocate flat buffers for each file */
    for (i = 0; i < numFiles; i++)
    {
        status = createBuffersDp(
            bufferSize, setup->numberOfBuffers[i], srcFlatBuffArray[i], nodeId);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to create flat buffers for srcFlatBuffArray\n");
            freeBuffersDp(srcFlatBuffArray, numFiles, setup);
            freeBuffersDp(dstFlatBuffArray, numFiles, setup);
            freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
            freeOpDataDp(compressionOpData, numFiles, setup);
            freeOpDataDp(decompressionOpData, numFiles, setup);

            return CPA_STATUS_FAIL;
        }

        status = createOpDataDp(
            setup->numberOfBuffers[i], compressionOpData[i], nodeId);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to create compression opdata\n");
            freeBuffersDp(srcFlatBuffArray, numFiles, setup);
            freeBuffersDp(dstFlatBuffArray, numFiles, setup);
            freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
            freeOpDataDp(compressionOpData, numFiles, setup);
            freeOpDataDp(decompressionOpData, numFiles, setup);

            return CPA_STATUS_FAIL;
        }

        status = createBuffersDp(destBufferSize,
                                 setup->numberOfBuffers[i],
                                 dstFlatBuffArray[i],
                                 nodeId);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to create buffers for dstFlatBuffArray\n");
            freeBuffersDp(srcFlatBuffArray, numFiles, setup);
            freeBuffersDp(dstFlatBuffArray, numFiles, setup);
            freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
            freeOpDataDp(compressionOpData, numFiles, setup);
            freeOpDataDp(decompressionOpData, numFiles, setup);

            return CPA_STATUS_FAIL;
        }
        if (setup->disableAdditionalCmpbufferSize == CPA_FALSE)
        {

            /* For reliabilty mode we need to allocate double the space to
             * extract the SW compressed data into*/
            status = createBuffersDp((bufferSize * EXTRA_BUFFER),
                                     setup->numberOfBuffers[i],
                                     cmpFlatBuffArray[i],
                                     nodeId);
        }
        else
        {
            /* For performance use cases additonal buffer size  is not required
             * to be added to the cmp buffer, as there is no SW checks*/
            status = createBuffersDp(bufferSize,
                                     setup->numberOfBuffers[i],
                                     cmpFlatBuffArray[i],
                                     nodeId);
        }

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to create buffers for cmpFlatBuffArray\n");
            freeBuffersDp(srcFlatBuffArray, numFiles, setup);
            freeBuffersDp(dstFlatBuffArray, numFiles, setup);
            freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
            freeOpDataDp(compressionOpData, numFiles, setup);
            freeOpDataDp(decompressionOpData, numFiles, setup);

            return CPA_STATUS_FAIL;
        }

        status = createOpDataDp(
            setup->numberOfBuffers[i], decompressionOpData[i], nodeId);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to create decompression opdata\n");
            freeBuffersDp(srcFlatBuffArray, numFiles, setup);
            freeBuffersDp(dstFlatBuffArray, numFiles, setup);
            freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
            freeOpDataDp(compressionOpData, numFiles, setup);
            freeOpDataDp(decompressionOpData, numFiles, setup);

            return CPA_STATUS_FAIL;
        }
    }

    /* Copy data into Flat Buffers from the corpus structure */
    for (i = 0; i < numFiles; i++)
    {
        fileDataPtr = fileArray[i].corpusBinaryData;
        /* get the number of full Buffers */
        amountOfFullBuffers = (fileArray[i].corpusBinaryDataLen) / bufferSize;
        /* Copy the data into Flat buffers */
        for (j = 0; j < amountOfFullBuffers; j++)
        {
            memcpy(((void *)(uintptr_t)srcFlatBuffArray[i][j]->bufferPhysAddr),
                   fileDataPtr,
                   bufferSize);
            fileDataPtr += bufferSize;
        }
        fileDataPtr = NULL;
    }

    setup->setupData.sessDirection = CPA_DC_DIR_COMBINED;

    /* Get Size for DC Session */
    status = cpaDcDpGetSessionSize(
        setup->dcInstanceHandle, &(setup->setupData), &sessionSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetSessionSize() returned %d status.\n", status);
        return CPA_STATUS_FAIL;
    }

    /* Allocate Memory for DC Session */
    pSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
        (sessionSize), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == pSessionHandle)
    {
        PRINT_ERR("Unable to allocate Memory for Session Handle\n");
        freeBuffersDp(srcFlatBuffArray, numFiles, setup);
        freeBuffersDp(dstFlatBuffArray, numFiles, setup);
        freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
        freeOpDataDp(compressionOpData, numFiles, setup);
        freeOpDataDp(decompressionOpData, numFiles, setup);

        return CPA_STATUS_FAIL;
    }
    /* Setup and init Session */
    status = cpaDcDpInitSession(
        setup->dcInstanceHandle, pSessionHandle, &(setup->setupData));
#ifdef LATENCY_CODE
    if ((latency_enable) && (latency_debug))
    {
        PRINT(
            "%s: cpaDcDpInitSession() returns=%d\n", __FUNCTION__, (int)status);
    }
#endif
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Problem in session creation: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        freeBuffersDp(srcFlatBuffArray, numFiles, setup);
        freeBuffersDp(dstFlatBuffArray, numFiles, setup);
        freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
        freeOpDataDp(compressionOpData, numFiles, setup);
        freeOpDataDp(decompressionOpData, numFiles, setup);

        return CPA_STATUS_FAIL;
    }

/*CnV Error Injection */
    /* Register a callback function */
    status = cpaDcDpRegCbFunc(setup->dcInstanceHandle,
                              (CpaDcDpCallbackFn)dcDpCallbackFunction);
#ifdef LATENCY_CODE
    if ((latency_enable) && (latency_debug))
    {
        PRINT("%s: cpaDcDpRegCbFunc() returns=%d\n", __FUNCTION__, (int)status);
    }
#endif
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to register callback fn, status = %d \n", status);
        status = CPA_STATUS_FAIL;
        goto exit;
    }

    /* Populate OpData struct */
    for (i = 0; i < numFiles; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            compressionOpData[i][j]->dcInstance = setup->dcInstanceHandle;

            compressionOpData[i][j]->pSessionHandle = pSessionHandle;

            compressionOpData[i][j]->srcBuffer =
                (CpaPhysicalAddr)virtAddrToDevAddr(
                    (void *)(uintptr_t)srcFlatBuffArray[i][j]->bufferPhysAddr,
                    setup->dcInstanceHandle,
                    CPA_ACC_SVC_TYPE_DATA_COMPRESSION);

            compressionOpData[i][j]->destBuffer =
                (CpaPhysicalAddr)virtAddrToDevAddr(
                    (void *)(uintptr_t)dstFlatBuffArray[i][j]->bufferPhysAddr,
                    setup->dcInstanceHandle,
                    CPA_ACC_SVC_TYPE_DATA_COMPRESSION);

            compressionOpData[i][j]->srcBufferLen =
                srcFlatBuffArray[i][j]->dataLenInBytes;

            compressionOpData[i][j]->destBufferLen =
                dstFlatBuffArray[i][j]->dataLenInBytes;

            /* Even though we are using CpaFlatBuffers we also have to set the
             * bufferLenToCompress and bufferLenForData fields which are used to
             * support CpaBufferList where srcBufferLen/destBufferLen take the
             * value CPA_DP_BUFLIST.
             */
            compressionOpData[i][j]->bufferLenToCompress =
                srcFlatBuffArray[i][j]->dataLenInBytes;

            compressionOpData[i][j]->bufferLenForData =
                dstFlatBuffArray[i][j]->dataLenInBytes;

            compressionOpData[i][j]->pCallbackTag = perfData;

            compressionOpData[i][j]->sessDirection = CPA_DC_DIR_COMPRESS;
            SET_DC_DP_CNV_PARAMS_DEFAULT(compressionOpData[i][j]);

            compressionOpData[i][j]->thisPhys =
                (CpaPhysicalAddr)(SAMPLE_CODE_UINT)virtAddrToDevAddr(
                    compressionOpData[i][j],
                    setup->dcInstanceHandle,
                    CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
        }
    }

    if (CPA_DC_DIR_COMPRESS == dcSessDirReq)
    {
        /* Our compression session is already set up. We need to set our
         * number of operations and then we are ready to batch or enqueue
         */
        perfData->numOperations = (Cpa64U)totalBuffs * (Cpa64U)setup->numLoops;
    }
    else if (CPA_DC_DIR_DECOMPRESS == dcSessDirReq)
    {
        perfData->numOperations = totalBuffs;

        /* Compress the corpus so we can de-compress it */
        status = compressCorpusPreDecomp(setup, compressionOpData, perfData);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Could not compress corpus before Decompression = %d \n",
                      status);
            status = CPA_STATUS_FAIL;
            goto exit;
        }
        /* Swap the data in OpData structs */
        for (i = 0; i < numFiles; i++)
        {
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                /* Update the compressed buffers length */
                dstFlatBuffArray[i][j]->dataLenInBytes =
                    compressionOpData[i][j]->results.produced;

                decompressionOpData[i][j]->dcInstance = setup->dcInstanceHandle;

                decompressionOpData[i][j]->pSessionHandle = pSessionHandle;

                decompressionOpData[i][j]
                    ->srcBuffer = (CpaPhysicalAddr)virtAddrToDevAddr(
                    (void *)(uintptr_t)dstFlatBuffArray[i][j]->bufferPhysAddr,
                    setup->dcInstanceHandle,
                    CPA_ACC_SVC_TYPE_DATA_COMPRESSION);

                decompressionOpData[i][j]
                    ->destBuffer = (CpaPhysicalAddr)virtAddrToDevAddr(
                    (void *)(uintptr_t)cmpFlatBuffArray[i][j]->bufferPhysAddr,
                    setup->dcInstanceHandle,
                    CPA_ACC_SVC_TYPE_DATA_COMPRESSION);

                decompressionOpData[i][j]->srcBufferLen =
                    dstFlatBuffArray[i][j]->dataLenInBytes;

                decompressionOpData[i][j]->destBufferLen =
                    cmpFlatBuffArray[i][j]->dataLenInBytes;

                /* Even though we are using CpaFlatBuffers we also have to set
                 * the bufferLenToCompress and bufferLenForData fields which are
                 * used to support CpaBufferList where
                 * srcBufferLen/destBufferLen take the value CPA_DP_BUFLIST.
                 */
                decompressionOpData[i][j]->bufferLenToCompress =
                    dstFlatBuffArray[i][j]->dataLenInBytes;

                decompressionOpData[i][j]->bufferLenForData =
                    cmpFlatBuffArray[i][j]->dataLenInBytes;

                decompressionOpData[i][j]->sessDirection =
                    CPA_DC_DIR_DECOMPRESS;

                decompressionOpData[i][j]->pCallbackTag = perfData;
                SET_DC_DP_CNV_PARAMS_DEFAULT(decompressionOpData[i][j]);

                decompressionOpData[i][j]->thisPhys =
                    (CpaPhysicalAddr)(SAMPLE_CODE_UINT)virtAddrToDevAddr(
                        decompressionOpData[i][j],
                        setup->dcInstanceHandle,
                        CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
            }
        }

        /* Update the number of operations/responses for the expected for the
         * pre decompression stage */
        perfData->numOperations = (Cpa64U)totalBuffs * (Cpa64U)setup->numLoops;
        perfData->responses = 0;
    }

    status = PerformOp(setup, compressionOpData, decompressionOpData, perfData);
#ifdef LATENCY_CODE
    if ((latency_enable) && (latency_debug))
    {
        PRINT("%s: PerformOp() returns=%d\n", __FUNCTION__, (int)status);
    }
#endif
    if (CPA_STATUS_SUCCESS != status)
    {
        status = CPA_STATUS_FAIL;
        goto exit;
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        status = performOffloadCalculation(
            setup, compressionOpData, decompressionOpData, perfData);
    }


    /* Record the bytes consumed and produced from the compressionOpData
     * structures for later printing.
     */
    dcDpSetBytesProducedAndConsumed(compressionOpData, perfData, setup);

exit:
    if (CPA_STATUS_SUCCESS != status)
    {
        removeStatus =
            sampleRemoveDcDpSession(setup->dcInstanceHandle, pSessionHandle);
    }
    if (CPA_STATUS_SUCCESS != removeStatus)
    {
        PRINT_ERR("Unable to remove compression session\n");
    }
    qaeMemFreeNUMA((void **)&pSessionHandle);

    /* Free allocated src, dst & cmp memory */
    freeBuffersDp(srcFlatBuffArray, numFiles, setup);
    freeBuffersDp(dstFlatBuffArray, numFiles, setup);
    freeBuffersDp(cmpFlatBuffArray, numFiles, setup);
    /* Free OpData structures */
    freeOpDataDp(compressionOpData, numFiles, setup);
    freeOpDataDp(decompressionOpData, numFiles, setup);

    return status;
}

/**
 *****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 *  Setup a compression thread for a given packet size.
 ******************************************************************************/

void dcDpPerformance(single_thread_test_data_t *testSetup)
{
    compression_test_params_t dcSetup = {0};
    compression_test_params_t *tmpSetup = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcInstanceCapabilities capabilities = {0};
    CpaInstanceInfo2 *instanceInfo = NULL;
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
    int fd = -1;
#endif

    /* Get the setup pointer */
    tmpSetup = (compression_test_params_t *)(testSetup->setupPtr);


    /* update the setup structure with setup parameters */
    memcpy(&dcSetup.requestOps, &tmpSetup->requestOps, sizeof(CpaDcOpData));
    dcSetup.bufferSize = tmpSetup->bufferSize;
    dcSetup.corpus = tmpSetup->corpus;
    dcSetup.setupData = tmpSetup->setupData;
    dcSetup.dcSessDir = tmpSetup->dcSessDir;
    dcSetup.syncFlag = tmpSetup->syncFlag;
    dcSetup.dpTestType = tmpSetup->dpTestType;
    dcSetup.numRequests = tmpSetup->numRequests;
    dcSetup.numLoops = tmpSetup->numLoops;
    dcSetup.isDpApi = CPA_TRUE;
    dcSetup.disableAdditionalCmpbufferSize =
        tmpSetup->disableAdditionalCmpbufferSize;
    dcSetup.threadID = testSetup->threadID;
    /*give our thread a unique memory location to store performance stats*/
    dcSetup.performanceStats = testSetup->performanceStats;
    dcSetup.performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
    /*initialize number of buffers with NULL*/
    dcSetup.numberOfBuffers = NULL;
    status = calculateRequireBuffers(&dcSetup);

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space is does
     * nothing, but kernel space threads do not start
     * until we call startThreads anyway
     */
    startBarrier();

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("Error calculating required buffers\n");
        goto exit;
    }

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate Memory for instanceInfo");
        goto exit;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    /*Initialize the statsPrintFunc to NULL, the dcPrintStats function will
     * be assigned if compression completes successfully
     */
    testSetup->statsPrintFunc = NULL;

    /* Get the number of instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR(" Unable to get number of DC instances\n");
        goto exit;
    }
    if (0 == numInstances)
    {
        PRINT_ERR(" DC Instances are not present\n");
        goto exit;
    }
    instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == instances)
    {
        PRINT_ERR("Unable to allocate Memory for Instances\n");
        goto exit;
    }
    /*get the instance handles so that we can start
     * our thread on the selected instance
     */
    status = cpaDcGetInstances(numInstances, instances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get instances failed");
        goto exit;
    }
    /* give our thread a logical quick assist instance to use
     * use % to wrap around the max number of instances*/
    dcSetup.dcInstanceHandle =
        instances[(testSetup->logicalQaInstance) % numInstances];

    /*check if dynamic compression is supported*/
    status = cpaDcQueryCapabilities(dcSetup.dcInstanceHandle, &capabilities);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaDcQueryCapabilities failed", __func__, __LINE__);
        goto exit;
    }
    if (CPA_FALSE == capabilities.dynamicHuffman &&
        tmpSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
    {
        PRINT("Dynamic is not supported on logical instance %d\n",
              (testSetup->logicalQaInstance) % numInstances);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    status = cpaDcInstanceGetInfo2(dcSetup.dcInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaDcInstanceGetInfo2 failed", __func__, __LINE__);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (instanceInfo->isPolled == CPA_FALSE)
    {
        PRINT("Data-Plane operations not supported on non-polled instances\n");
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (CPA_STATUS_SUCCESS !=
        qatDcGetPreTestRecoveryCount(
            &dcSetup, &capabilities, testSetup->performanceStats))
    {
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (CPA_TRUE == dcSetup.useXlt && ASYNC == dcSetup.syncFlag)
    {
        PRINT("Async mode not supported in Xlt[%d]\n", dcSetup.useXlt);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadExit();
    }
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)

    status = icp_sal_DcGetFileDescriptor(dcSetup.dcInstanceHandle, &fd);
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT("Data-Plane operations not supported on Epoll instances\n");
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        qaeMemFree((void **)&instanceInfo);
        icp_sal_DcPutFileDescriptor(dcSetup.dcInstanceHandle, fd);
        testSetup->performanceStats->threadReturnStatus =
            CPA_STATUS_UNSUPPORTED;
        sampleCodeThreadExit();
    }
#endif


    /*launch function that does all the work*/
    status = dcDpPerform(&dcSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        dcPrintTestData(&dcSetup);
        PRINT_ERR("Compression Thread %u FAILED\n", testSetup->threadID);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        qatDcGetPostTestRecoveryCount(&dcSetup, testSetup->performanceStats);
    }
    if ((CPA_STATUS_SUCCESS == status) &&
        (CPA_STATUS_FAIL != testSetup->performanceStats->threadReturnStatus))
    {
        /*set the print function that can be used to print
         * statistics at the end of the test
         * */
        testSetup->statsPrintFunc = (stats_print_func_t)dcPrintStats;
    }

exit:
    if (dcSetup.numberOfBuffers != NULL)
    {
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
    }
    if (instances != NULL)
    {
        qaeMemFree((void **)&instances);
    }
    if (instanceInfo != NULL)
    {
        qaeMemFree((void **)&instanceInfo);
    }

    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(dcDpPerformance);

/**
 *****************************************************************************
 * @ingroup checkDcNonPollingInstance
 *
 * @description
 *  Check for Non Polling DC Instance.
 ******************************************************************************/

CpaStatus checkDcNonPollingInstance(CpaBoolean *polled)
{
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceInfo2 instanceInfo = {0};
    int i = 0;

    /* Get the number of instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get number of DC instances\n");
        return CPA_STATUS_FAIL;
    }
    if (0 == numInstances)
    {
        PRINT_ERR("DC Instances are not present\n");
        return CPA_STATUS_FAIL;
    }
    instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == instances)
    {
        PRINT_ERR("Unable to allocate Memory for Instances\n");
        return CPA_STATUS_FAIL;
    }
    /*get the instance handles
     */
    status = cpaDcGetInstances(numInstances, instances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get instances failed");
        goto exit;
    }
    for (i = 0; i < numInstances; i++)
    {
        status = cpaDcInstanceGetInfo2(instances[i], &instanceInfo);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcInstanceGetInfo2 failed");
            status = CPA_STATUS_FAIL;
            goto exit;
        }
        if (instanceInfo.isPolled == CPA_FALSE)
        {
            *polled = CPA_FALSE;
            status = CPA_STATUS_SUCCESS;
            goto exit;
        }
    }
exit:
    if (instances != NULL)
    {
        qaeMemFree((void **)&instances);
    }
    return status;
}

/**
*****************************************************************************
*
*  External Function Interfaces
*
******************************************************************************/

/**
 ****************************************************************************
 * @ingroup sampleCompressionDpPerf
 *
 * @description
 * setup a Compression Data Plane API test
 * This function needs to be called from main to setup a compression test.
 * The framework createThreads function is then used to propagate this setup
 * across cores using different compression logical instances
 *****************************************************************************/

CpaStatus setupDcDpTest(CpaDcCompType algorithm,
                        CpaDcSessionDir direction,
                        CpaDcCompLvl compLevel,
                        CpaDcHuffType huffmanType,
                        Cpa32U windowSize,
                        Cpa32U testBufferSize,
                        corpus_type_t corpusType,
                        sync_mode_t syncFlag,
                        dp_request_type_t dpTestType,
                        Cpa32U numRequests,
                        Cpa32U numLoops)
{
    compression_test_params_t *dcSetup = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numberOfBuffersPerFile = 0, i = 0;
    Cpa32U numFiles = getNumFilesInCorpus(corpusType);
    const corpus_file_t *const fileArray = getFilesInCorpus(corpusType);
    CpaBoolean polled = CPA_TRUE;

    /* Ensure that the number of threads created do not exceed the amount of
     * threads supported by the sample code framework.
     */
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    status = checkDcNonPollingInstance(&polled);
    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }

    if (polled == CPA_FALSE)
    {
        PRINT("Data-Plane operations not supported on non-polled instances\n");
        return CPA_STATUS_SUCCESS;
    }

    status = populateCorpus(testBufferSize, corpusType);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to Populate corpus file\n");
        return CPA_STATUS_FAIL;
    }
    /*
     * Create DC instances handles, allocate temporary memory for dynamic
     * compression and create polling threads(if enabled in configuration)
     * */
    status = startDcServices(DYNAMIC_BUFFER_AREA, TEMP_NUM_BUFFS);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("Error in Starting Dc Services\n");
        return CPA_STATUS_FAIL;
    }
    /* Get the framework setup pointer */
    /* thread_setup_g is a multi-dimensional array that
     * stores the setup for all thread
     * variations in an array of characters.
     * we store our test setup at the
     * start of the second array ie index 0.
     * There maybe multi thread types
     * (setups) running as counted by testTypeCount_g*/

    /* thread_setup_g is a multi-dimensional char array
     * we need to cast it to the
     * Compression structure
     */
    dcSetup = (compression_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    INIT_OPDATA_DEFAULT(&dcSetup->requestOps);

    /* Set the performance function to the actual performance function
     * that actually does all the performance
     */
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)dcDpPerformance;

    /* update the setup_g with buffersize */
    testSetupData_g[testTypeCount_g].packetSize = testBufferSize;
    /* Data compression setup data */
    dcSetup->setupData.compLevel = compLevel;
    dcSetup->setupData.compType = algorithm;
    dcSetup->setupData.sessDirection = CPA_DC_DIR_COMPRESS;
    dcSetup->setupData.checksum = gChecksum;
#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
    dcSetup->setupData.huffType = huffmanType;
#else
    dcSetup->setupData.huffType = CPA_DC_HT_STATIC;
#endif
    dcSetup->setupData.sessState = CPA_DC_STATELESS;
#if DC_API_VERSION_LESS_THAN(1, 6)
    dcSetup->setupData.deflateWindowSize = DEFAULT_COMPRESSION_WINDOW_SIZE;
#endif
    dcSetup->corpus = corpusType;
    dcSetup->bufferSize = testBufferSize;
    dcSetup->dcSessDir = direction;
    dcSetup->syncFlag = syncFlag;
    dcSetup->dpTestType = dpTestType;
    dcSetup->numRequests = numRequests;
    dcSetup->numLoops = numLoops;
    dcSetup->setupData.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
    dcSetup->isDpApi = CPA_TRUE;
    dcSetup->disableAdditionalCmpbufferSize = disableAdditionalCmpbufferSize_g;


    /* Ensure that the numbers of buffers required for each file is less
     * than or equal to the batch/enqueue amount.
     */
    for (i = 0; i < numFiles; i++)
    {
        numberOfBuffersPerFile =
            fileArray[i].corpusBinaryDataLen / testBufferSize;

        if (fileArray[i].corpusBinaryDataLen % testBufferSize != 0)
        {
            numberOfBuffersPerFile++;
        }
        if (numberOfBuffersPerFile < numRequests)
        {
            PRINT_ERR("The batch/enqueue amount (%d) specified exceeds the"
                      " number of buffers available (%d)\n",
                      numRequests,
                      numberOfBuffersPerFile);

            return CPA_STATUS_FAIL;
        }
        numberOfBuffersPerFile = 0;
    }

    return status;
}

