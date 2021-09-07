/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 * @file cpa_sample_code_dc_stateful.c
 *
 *
 * @ingroup compressionThreads
 *
 * @description
 *    This is a sample code that uses Data Compression(DC)  APIs.

 *    This code preallocates a number of buffers as based on the size of each
 *    file defined in the calgary/canterbury corpus. The preallocated buffers
 *    are then populated with the corpus files as define in
 *    setup->testBuffersize.
 *    Time stamping is started prior to the first performed DC
 *    Operation and is stopped when all callbacks have returned.
 *****************************************************************************/

#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_dc_utils.h"
#include "cpa_sample_code_crypto_utils.h"

#include "icp_sal_poll.h"

#define DOUBLE_SUBMISSIONS (2)
#ifdef LATENCY_CODE
#define NUM_LATENCY_SAMPLES (100)
#endif

CpaDcChecksum checksum_g = CPA_DC_NONE;


extern CpaStatus deflate_init(struct z_stream_s *stream);
extern CpaStatus deflate_compress(struct z_stream_s *stream,
                                  const Cpa8U *src,
                                  Cpa32U slen,
                                  Cpa8U *dst,
                                  Cpa32U dlen,
                                  int zfflag);
extern void deflate_destroy(struct z_stream_s *stream);
extern CpaStatus inflate_init(z_stream *stream, CpaDcSessionState sessState);
extern CpaStatus inflate_decompress(z_stream *stream,
                                    const Cpa8U *src,
                                    Cpa32U slen,
                                    Cpa8U *dst,
                                    Cpa32U dlen,
                                    CpaDcSessionState sessState);

extern void inflate_destroy(struct z_stream_s *stream);
extern Cpa32U packageIdCount_g;

void compressStatefulCallback(void *pCallbackTag, CpaStatus status)
{

    dc_callbacktag_t *cbTag = (dc_callbacktag_t *)pCallbackTag;
    perf_data_t *pPerfData;

    /*check perf_data pointer is valid*/
    if (NULL == cbTag)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    pPerfData = cbTag->perfData;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("Compression failed, status = %d, DC request(%llu) status = %d\n",
              status,
              (unsigned long long)pPerfData->responses,
              cbTag->dcResult->status);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    /* Update the data length with produced */
    cbTag->pBuffList->pBuffers->dataLenInBytes = cbTag->dcResult->produced;
    /* increment the responses */
    pPerfData->responses++;
    /* Release the semaphore */
    sampleCodeSemaphorePost(&pPerfData->comp);

}
void deCompressStatefulCallback(void *pCallbackTag, CpaStatus status)
{

    dc_callbacktag_t *cbTag = (dc_callbacktag_t *)pCallbackTag;
    perf_data_t *pPerfData;

    /*check perf_data pointer is valid*/
    if (NULL == cbTag)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    pPerfData = cbTag->perfData;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT(
            "Decompression failed, status = %d, DC request(%llu) status = %d\n",
            status,
            (unsigned long long)pPerfData->responses,
            cbTag->dcResult->status);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    /* increment the responses */
    pPerfData->responses++;
    if (pPerfData->responses >= pPerfData->numOperations)
    {
        /* generate end of the cycle stamp for Corpus */
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
    }
#ifdef LATENCY_CODE
    if ((0 != pPerfData->responses) && (NULL != pPerfData->response_times))
    {
        if (pPerfData->responses == pPerfData->nextCount)
        {
            pPerfData->response_times[pPerfData->latencyCount++] =
                sampleCodeTimestamp();
            pPerfData->nextCount += pPerfData->countIncrement;
        }
    }
#endif
    /* Release the semaphore */
    sampleCodeSemaphorePost(&pPerfData->comp);

}

/*********** Call Back Function **************/
void dcPerformStatefulCallback(void *pCallbackTag, CpaStatus status)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;


    /*check status */
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Compression failed with status %d after response %llu\n",
                  status,
                  (unsigned long long)pPerfData->responses);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }

    /*check perf_data pointer is valid*/
    if (NULL == pPerfData)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    pPerfData->responses++;
    if (pPerfData->responses >= pPerfData->numOperations)
    {
        /* generate end of the cycle stamp for Corpus */
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
    }
    sampleCodeSemaphorePost(&pPerfData->comp);
}

static void dcSampleFreeStatefulContextBuffer(CpaBufferList *pBuffListArray)
{
    if (NULL == pBuffListArray)
    {
        /* Return Silent */
        return;
    }

    if (NULL != pBuffListArray->pPrivateMetaData)
    {
        qaeMemFreeNUMA((void **)&pBuffListArray->pPrivateMetaData);
    }
    if (NULL != pBuffListArray->pBuffers)
    {
        if (NULL != pBuffListArray->pBuffers->pData)
        {
            qaeMemFreeNUMA((void **)&pBuffListArray->pBuffers->pData);
        }
        qaeMemFreeNUMA((void **)&pBuffListArray->pBuffers);
    }
    if (NULL != pBuffListArray)
    {
        qaeMemFreeNUMA((void **)&pBuffListArray);
    }

    return;
}

static CpaStatus performCompressStateful(compression_test_params_t *setup,
                                         CpaBufferList ***srcBuffListArray,
                                         CpaBufferList ***dstBuffListArray,
                                         CpaDcRqResults ***cmpResult,
                                         CpaDcCallbackFn dcCbFn)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionSize = 0, contextSize = 0;
    /* DC session Handle */
    CpaDcSessionHandle *pSessionHandle = NULL;
    Cpa32U numLoops = 0, i = 0, j = 0;
    Cpa32U compressLoops = setup->numLoops;
    perf_data_t *perfData = NULL;
    Cpa32U nodeId = 0;
    CpaBufferList *pContextBuffer = NULL;
    Cpa32U metaSizeInBytes = 0;
    Cpa32U dataLenInBytes = 0;
    Cpa8U *pData = NULL;
    Cpa32U numFilesInCorpus = getNumFilesInCorpus(setup->corpus);

    perfData = setup->performanceStats;

    /* Get the Node Affinity to allocate memory */
    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return status;
    }

    /* Get Size for DC Session */
    status = cpaDcGetSessionSize(setup->dcInstanceHandle,
                                 &(setup->setupData),
                                 &sessionSize,
                                 &contextSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetSessionSize() returned %d status.\n", status);
        return CPA_STATUS_FAIL;
    }
    /* Allocate Memory for DC Session */
    pSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
        (sessionSize + contextSize), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == pSessionHandle)
    {
        PRINT_ERR("Unable to allocate Memory for Session Handle\n");
        return CPA_STATUS_FAIL;
    }

    if (setup->syncFlag == CPA_SAMPLE_SYNCHRONOUS)
    {
        dcCbFn = NULL;
    }

    status = cpaDcBufferListGetMetaSize(
        setup->dcInstanceHandle, ONE_BUFFER_DC, &metaSizeInBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Meta size: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    status = dcSampleCreateStatefulContextBuffer(
        (contextSize * EXTRA_BUFFER), metaSizeInBytes, &pContextBuffer, nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to allocate context : status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    /* Initialize DC API Session */
    status = cpaDcInitSession(setup->dcInstanceHandle,
                              pSessionHandle,
                              &(setup->setupData),
                              pContextBuffer,
                              dcCbFn);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Problem in session creation: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        dcSampleFreeStatefulContextBuffer(pContextBuffer);
        return CPA_STATUS_FAIL;
    }

    perfData->numLoops = setup->numLoops;
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&perfData->comp, 0);
    /* this Barrier will waits until all the threads get to this point */
    sampleCodeBarrier();
    /* generate the start time stamp */
    perfData->startCyclesTimestamp = sampleCodeTimestamp();
    for (numLoops = 0; numLoops < compressLoops; numLoops++)
    {

        /* compression API will be called for each buffer list
         * in the corpus File
         */
        for (i = 0; i < numFilesInCorpus; i++)
        {
            /* call the compress api */
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {

                if (j == (setup->numberOfBuffers[i] - 1))
                {
                    setup->requestOps.flushFlag = CPA_DC_FLUSH_FINAL;
                }
                else
                {
                    setup->requestOps.flushFlag = CPA_DC_FLUSH_SYNC;
                }
                dataLenInBytes =
                    srcBuffListArray[i][j]->pBuffers->dataLenInBytes;
                pData = srcBuffListArray[i][j]->pBuffers->pData;
                do
                {
                    do
                    {
                        status = cpaDcCompressData2(setup->dcInstanceHandle,
                                                    pSessionHandle,
                                                    srcBuffListArray[i][j],
                                                    dstBuffListArray[i][j],
                                                    &setup->requestOps,
                                                    cmpResult[i][j],
                                                    perfData);

                        if (CPA_STATUS_RETRY == status)
                        {
                            setup->performanceStats->retries++;
                            /*once we get too many retries, perform a
                             * context switch to give the acceleration
                             * engine a small break
                             */
                            if (RETRY_LIMIT == setup->performanceStats->retries)
                            {
                                setup->performanceStats->retries = 0;
                                AVOID_SOFTLOCKUP;
                            }
                        }

                    } while (CPA_STATUS_RETRY == status);
                    /* Check Status */
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT_ERR("Data Compression Failed %d\n\n", status);
                        perfData->threadReturnStatus = CPA_STATUS_FAIL;
                        break;
                    }

                    /* check if synchronous flag is set
                     * if set, invoke the callback API
                     */
                    if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
                    {
                        /* invoke the Compression Callback only */
                        dcPerformStatefulCallback(perfData, status);
                    }

                    /* Stateful compression only supports a single request in
                     * flight
                     * for each session, so wait for the semaphore to post on
                     * the
                     * submitted request
                     */
                    status = waitForSemaphore(perfData);
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT_ERR("Wait for Semaphore Failed %d\n\n", status);
                        perfData->threadReturnStatus = CPA_STATUS_FAIL;
                        break;
                    }
                    if (cmpResult[i][j]->consumed &&
                        cmpResult[i][j]->status == CPA_DC_OVERFLOW &&
                        cmpResult[i][j]->consumed <=
                            srcBuffListArray[i][j]->pBuffers->dataLenInBytes)
                    {
                        srcBuffListArray[i][j]->pBuffers->dataLenInBytes -=
                            cmpResult[i][j]->consumed;
                        srcBuffListArray[i][j]->pBuffers->pData +=
                            cmpResult[i][j]->consumed;
                        PRINT_ERR("Overflow Identified ");
                    }
                    else
                    {
                        srcBuffListArray[i][j]->pBuffers->dataLenInBytes = 0;
                    }
                } while (srcBuffListArray[i][j]->pBuffers->dataLenInBytes != 0);
                srcBuffListArray[i][j]->pBuffers->dataLenInBytes =
                    dataLenInBytes;
                srcBuffListArray[i][j]->pBuffers->pData = pData;

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
            PRINT_ERR("Data Compression Failed %d\n\n", status);
            perfData->threadReturnStatus = CPA_STATUS_FAIL;
            break;
        }
    } /* End of compression Loops */

    /* Close the DC Session */
    status = cpaDcRemoveSession(setup->dcInstanceHandle, pSessionHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to remove session\n");
        perfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    qaeMemFreeNUMA((void **)&pSessionHandle);
    dcSampleFreeStatefulContextBuffer(pContextBuffer);
    return status;
}

static CpaStatus compressCorpusStateful(compression_test_params_t *setup,
                                        CpaBufferList ***srcBuffListArray,
                                        CpaBufferList ***dstBuffListArray,
                                        CpaDcRqResults ***cmpResult,
                                        dc_callbacktag_t ***callbackTag)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionSize = 0, contextSize = 0;
    /* DC session Handle */
    CpaDcSessionHandle *pSessionHandle = NULL;
    perf_data_t *perfData = NULL;
    Cpa32U i = 0, j = 0;
    Cpa32U numBuffs = 0, nodeId = 0;
    CpaBufferList *pContextBuffer = NULL;
    Cpa32U metaSizeInBytes = 0;
    CpaDcCallbackFn dcCbFn = NULL;
    Cpa32U numFilesInCorpus = getNumFilesInCorpus(setup->corpus);
#ifdef LATENCY_CODE
    Cpa32U submissions = 0;
    perf_cycles_t request_submit_start[NUM_LATENCY_SAMPLES] = {0};
    perf_cycles_t request_respnse_time[NUM_LATENCY_SAMPLES] = {0};
#endif

    perfData = setup->performanceStats;

    /* Get the Node Affinity to allocate memory */
    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return status;
    }

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (perfData->numOperations > LATENCY_SUBMISSION_LIMIT)
        {
            PRINT_ERR("Error max submissions for latency  must be <= %d\n",
                      LATENCY_SUBMISSION_LIMIT);
            return CPA_STATUS_FAIL;
        }
        perfData->nextCount =
            (setup->numberOfBuffers[0] * setup->numLoops) / NUM_LATENCY_SAMPLES;
        perfData->countIncrement =
            (setup->numberOfBuffers[0] * setup->numLoops) / NUM_LATENCY_SAMPLES;
        perfData->latencyCount = 0;
        perfData->response_times = request_respnse_time;
    }
#endif

    /* Get Size for DC Session */
    status = cpaDcGetSessionSize(setup->dcInstanceHandle,
                                 &(setup->setupData),
                                 &sessionSize,
                                 &contextSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetSessionSize() returned %d status.\n", status);
        return CPA_STATUS_FAIL;
    }
    /* Allocate Memory for DC Session */
    pSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
        (sessionSize + contextSize), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == pSessionHandle)
    {
        PRINT_ERR("Unable to allocate Memory for Session Handle\n");
        return CPA_STATUS_FAIL;
    }

    status = cpaDcBufferListGetMetaSize(
        setup->dcInstanceHandle, ONE_BUFFER_DC, &metaSizeInBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Meta size: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    status = dcSampleCreateStatefulContextBuffer(
        (contextSize * EXTRA_BUFFER), metaSizeInBytes, &pContextBuffer, nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to allocate context : status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    if (setup->syncFlag == CPA_SAMPLE_SYNCHRONOUS)
    {
        dcCbFn = NULL;
    }
    else
    {
        dcCbFn = compressStatefulCallback;
    }

    /* Initialize DC API Session */
    status = cpaDcInitSession(setup->dcInstanceHandle,
                              pSessionHandle,
                              &(setup->setupData),
                              pContextBuffer,
                              dcCbFn);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Problem in session creation: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        dcSampleFreeStatefulContextBuffer(pContextBuffer);
        return CPA_STATUS_FAIL;
    }
    /* calculate the number of buffers */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        numBuffs += setup->numberOfBuffers[i];
    }
    perfData->numOperations = numBuffs;

    /* Completion used in callback */
    sampleCodeSemaphoreInit(&perfData->comp, 0);
    /* compression API will be called for each buffer list
     * in the corpus File
     */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        /* call the compress api */
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {

            if (j == (setup->numberOfBuffers[i] - 1))
            {
                setup->requestOps.flushFlag = CPA_DC_FLUSH_FINAL;
            }
            else
            {
                setup->requestOps.flushFlag = CPA_DC_FLUSH_SYNC;
            }

            do
            {
#ifdef LATENCY_CODE
                if (latency_enable)
                {
                    if (submissions + 1 == perfData->nextCount)
                    {
                        request_submit_start[perfData->latencyCount] =
                            sampleCodeTimestamp();
                    }
                }
#endif
                status = cpaDcCompressData2(setup->dcInstanceHandle,
                                            pSessionHandle,
                                            srcBuffListArray[i][j],
                                            dstBuffListArray[i][j],
                                            &setup->requestOps,
                                            cmpResult[i][j],
                                            callbackTag[i][j]);

                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
                    /*once we get too many retries, perform a
                     * context switch to give the acceleration
                     * engine a small break
                     */
                    if (RETRY_LIMIT == setup->performanceStats->retries)
                    {
                        setup->performanceStats->retries = 0;
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);
            /* Check Status */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Data Compression Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
                break;
            }
#ifdef LATENCY_CODE
            if (latency_enable)
            {
                perfData->latencyCount++;
                submissions++;
            }
#endif
            if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
            {
                /* invoke the Compression Callback only */
                compressStatefulCallback(callbackTag[i][j], status);
            }

            /* Stateful compression only supports a single request in flight
             * for each session, so wait for the semaphore to post on the
             * submitted request
             */
            status = waitForSemaphore(perfData);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Wait for Semaphore Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
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
    /* Close the DC Session */
    status = cpaDcRemoveSession(setup->dcInstanceHandle, pSessionHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to remove session\n");
        perfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    qaeMemFreeNUMA((void **)&pSessionHandle);
#ifdef LATENCY_CODE
    if (latency_enable)
    {
        for (i = 0; i < perfData->latencyCount; i++)
        {
            perfData->aveLatency +=
                perfData->response_times[i] - request_submit_start[i];
        }
        if (perfData->latencyCount > 0)
        {
            do_div(perfData->aveLatency, perfData->latencyCount);
        }
    }
#endif
    dcSampleFreeStatefulContextBuffer(pContextBuffer);
    return status;
}
static CpaStatus performDeCompressStateful(compression_test_params_t *setup,
                                           CpaBufferList ***srcBuffListArray,
                                           CpaBufferList ***dstBuffListArray,
                                           CpaBufferList ***cmpBuffListArray,
                                           CpaDcRqResults ***cmpResult,
                                           CpaDcRqResults ***dcmpResult,
                                           CpaDcCallbackFn dcCbFn)

{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionSize = 0, contextSize = 0;
    /* DC session Handle */
    CpaDcSessionHandle *pSessionHandle = NULL;
    Cpa32U numLoops = 0, i = 0, j = 0;
    int zlibFlushflag = 0;
    Cpa32U deCompressLoops = setup->numLoops;
    perf_data_t *perfData = NULL;
    dc_callbacktag_t ***dcCallbackTag = NULL;
    Cpa32U numBuffs = 0, nodeId = 0;
    CpaBufferList *pContextBuffer = NULL;
    Cpa32U metaSizeInBytes = 0;
    Cpa32U dataLenInBytes = 0;
    Cpa8U *pData = NULL;
    Cpa32U numFilesInCorpus = getNumFilesInCorpus(setup->corpus);
    Cpa32U totalConsumed = 0, totalProduced = 0;
#ifdef LATENCY_CODE
    Cpa32U submissions = 0;
    perf_cycles_t request_submit_start[NUM_LATENCY_SAMPLES] = {0};
    perf_cycles_t request_respnse_time[NUM_LATENCY_SAMPLES] = {0};
#endif
    struct z_stream_s stream = {0};
    CpaFlatBuffer tempFB;
    Cpa32U remainder = 0;

    /* Get the Node Affinity to allocate memory */
    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return status;
    }

    perfData = setup->performanceStats;

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (perfData->numOperations > LATENCY_SUBMISSION_LIMIT)
        {
            PRINT_ERR("Error max submissions for latency  must be <= %d\n",
                      LATENCY_SUBMISSION_LIMIT);
            return CPA_STATUS_FAIL;
        }
        perfData->nextCount =
            (setup->numberOfBuffers[0] * setup->numLoops) / NUM_LATENCY_SAMPLES;
        perfData->countIncrement =
            (setup->numberOfBuffers[0] * setup->numLoops) / NUM_LATENCY_SAMPLES;
        perfData->latencyCount = 0;
        perfData->response_times = request_respnse_time;
    }
#endif
    tempFB.pData =
        qaeMemAllocNUMA(setup->bufferSize, nodeId, BYTE_ALIGNMENT_64);
    if (NULL == tempFB.pData)
    {
        PRINT("ERROR: Allocating temporary flat buffer data\n");
        return CPA_STATUS_FAIL;
    }
    /* Get Size for DC Session */
    status = cpaDcGetSessionSize(setup->dcInstanceHandle,
                                 &(setup->setupData),
                                 &sessionSize,
                                 &contextSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetSessionSize() returned %d status.\n", status);
        return CPA_STATUS_FAIL;
    }
    /* Allocate Memory for DC Session */
    pSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
        (sessionSize + contextSize), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == pSessionHandle)
    {
        PRINT_ERR("Unable to allocate Memory for Session Handle\n");
        return CPA_STATUS_FAIL;
    }
    /* Setup callback Tags */
    dcCallbackTag =
        qaeMemAllocNUMA(numFilesInCorpus * sizeof(dc_callbacktag_t **),
                        nodeId,
                        BYTE_ALIGNMENT_64);

    if (NULL == dcCallbackTag)
    {
        PRINT("Unable to allocate memory for callback tags\n");
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < numFilesInCorpus; i++)
    {

        dcCallbackTag[i] = qaeMemAllocNUMA(setup->numberOfBuffers[i] *
                                               sizeof(dc_callbacktag_t *),
                                           nodeId,
                                           BYTE_ALIGNMENT_64);
        if (NULL == dcCallbackTag[i])
        {
            PRINT("Unable to allocate memory for callback tags\n");
            freeCbTags(dcCallbackTag, i, setup);
            return CPA_STATUS_FAIL;
        }

    }
    /* Setup callbacktags for each buffer with results structure
     * and performance structure
     * */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            dcCallbackTag[i][j] = qaeMemAllocNUMA(
                sizeof(dc_callbacktag_t), nodeId, BYTE_ALIGNMENT_64);
            if (NULL == dcCallbackTag[i])
            {
                PRINT("Unable to allocate memory for callback tags\n");
                freeCbTags(dcCallbackTag, i, setup);
                return CPA_STATUS_FAIL;
            }
            dcCallbackTag[i][j]->perfData = perfData;
            dcCallbackTag[i][j]->dcResult = dcmpResult[i][j];
            dcCallbackTag[i][j]->pBuffList = dstBuffListArray[i][j];
        }
    }

    /* make sure to compress the corpus before starting
     * de compression
     */
    if (setup->corpus != LUKAS_COMPRESSED_FILES)
    {
        if (!useZlib_g)
        {
            status = compressCorpusStateful(setup,
                                            srcBuffListArray,
                                            dstBuffListArray,
                                            dcmpResult,
                                            dcCallbackTag);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("Compression Failed before decompressing the corpus\n");
                return CPA_STATUS_FAIL;
            }
        }
        else
        {
            deflate_init(&stream);
            for (i = 0; i < numFilesInCorpus; i++)
            {
                /* call the compress api */
                for (j = 0; j < setup->numberOfBuffers[i]; j++)
                {
                    if (j < setup->numberOfBuffers[i] - 1)
                    {
                        zlibFlushflag = Z_SYNC_FLUSH;
                    }
                    else
                    {
                        zlibFlushflag = Z_FINISH;
                    }
                    status = deflate_compress(
                        &stream,
                        srcBuffListArray[i][j]->pBuffers[0].pData,
                        srcBuffListArray[i][j]->pBuffers[0].dataLenInBytes,
                        dstBuffListArray[i][j]->pBuffers[0].pData,
                        dstBuffListArray[i][j]->pBuffers[0].dataLenInBytes,
                        zlibFlushflag);
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT(
                            "i: %d, j: %d, srcLen: %d, destLen: %d \n",
                            i,
                            j,
                            srcBuffListArray[i][j]->pBuffers[0].dataLenInBytes,
                            dstBuffListArray[i][j]->pBuffers[0].dataLenInBytes);
                        perfData->threadReturnStatus = CPA_STATUS_FAIL;
                    }
                    cmpResult[i][j]->consumed = stream.total_in;
                    cmpResult[i][j]->produced = stream.total_out;
                }
            }
            deflate_destroy(&stream);
        }
    }
    dcSetBytesProducedAndConsumed(dcmpResult, setup->performanceStats, setup);

    /* calculate the number of buffers */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        numBuffs += setup->numberOfBuffers[i];
    }
    perfData->numOperations = (Cpa64U)numBuffs * setup->numLoops;
    perfData->responses = 0;

    if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
    {
        dcCbFn = NULL;
    }

    status = cpaDcBufferListGetMetaSize(
        setup->dcInstanceHandle, ONE_BUFFER_DC, &metaSizeInBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Meta size: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    status = dcSampleCreateStatefulContextBuffer(
        (contextSize * EXTRA_BUFFER), metaSizeInBytes, &pContextBuffer, nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to allocate context : status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    /* Initialize DC API Session */
    status = cpaDcInitSession(setup->dcInstanceHandle,
                              pSessionHandle,
                              &(setup->setupData),
                              pContextBuffer,
                              dcCbFn);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Problem in session creation: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    perfData->numLoops = setup->numLoops;
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&perfData->comp, 0);
    /* this Barrier will waits until all the threads get to this point */
    sampleCodeBarrier();
    /* generate the start time stamp */
    perfData->startCyclesTimestamp = sampleCodeTimestamp();
    for (numLoops = 0; numLoops < deCompressLoops; numLoops++)
    {
/* Check if terminated by global flag.
 * If yes, update numOperations, compressLoops,
 *  numLoops: added by waterman */

        /* for each file in corpus */
        for (i = 0; i < numFilesInCorpus; i++)
        {
            totalConsumed = 0;
            totalProduced = 0;

            /* de compress the data */
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (j == (setup->numberOfBuffers[i] - 1))
                {
                    setup->requestOps.flushFlag = CPA_DC_FLUSH_FINAL;
                }
                else
                {
                    setup->requestOps.flushFlag = CPA_DC_FLUSH_SYNC;
                }
                dataLenInBytes =
                    dstBuffListArray[i][j]->pBuffers->dataLenInBytes;
                pData = dstBuffListArray[i][j]->pBuffers->pData;
                do
                {
#ifdef LATENCY_CODE
                    if (latency_enable)
                    {
                        if (submissions + 1 == perfData->nextCount)
                        {
                            request_submit_start[perfData->latencyCount] =
                                sampleCodeTimestamp();
                        }
                    }
#endif
                    status = cpaDcDecompressData2(setup->dcInstanceHandle,
                                                  pSessionHandle,
                                                  dstBuffListArray[i][j],
                                                  cmpBuffListArray[i][j],
                                                  &setup->requestOps,
                                                  dcmpResult[i][j],
                                                  dcCallbackTag[i][j]);
                    if (CPA_STATUS_RETRY == status)
                    {
                        setup->performanceStats->retries++;
                        /*once we get too many retries, perform a
                         * context switch to give the acceleration
                         * engine a small break
                         */
                        if (RETRY_LIMIT == setup->performanceStats->retries)
                        {
                            setup->performanceStats->retries = 0;
                            AVOID_SOFTLOCKUP;
                        }
                    }
                } while (CPA_STATUS_RETRY == status);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR(" Data De-Compression Failed\n");
                    perfData->threadReturnStatus = CPA_STATUS_FAIL;
                    break;
                }

#ifdef LATENCY_CODE
                if (latency_enable)
                {
                    perfData->latencyCount++;
                    submissions++;
                }
#endif
                /* check if synchronous flag is set
                 * if set, invoke the callback API
                 */
                if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
                {
                    /* invoke the decompression Callback only */
                    deCompressStatefulCallback(dcCallbackTag[i][j], status);
                }

                /* Stateful compression only supports a single request
                 * in flight for each session, so wait for the semaphore
                 * to post on the submitted request
                 */
                status = waitForSemaphore(perfData);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Wait for Semaphore Failed %d\n\n", status);
                    perfData->threadReturnStatus = CPA_STATUS_FAIL;

                    break;
                }

                /* Update the result after the request has been processed. */
                totalConsumed += dcmpResult[i][j]->consumed;
                totalProduced += dcmpResult[i][j]->produced;

                cmpBuffListArray[i][j]->pBuffers->dataLenInBytes =
                    dcmpResult[i][j]->produced;
                if (dcmpResult[i][j]->consumed &&
                    dcmpResult[i][j]->consumed <=
                        dstBuffListArray[i][j]->pBuffers->dataLenInBytes)
                {
                    dstBuffListArray[i][j]->pBuffers->dataLenInBytes -=
                        dcmpResult[i][j]->consumed;
                    dstBuffListArray[i][j]->pBuffers->pData +=
                        dcmpResult[i][j]->consumed;
                }
                if (dcmpResult[i][j]->produced >
                    setup->bufferSize * EXTRA_BUFFER * expansionFactor_g)
                {
                    PRINT(
                        "warning HW output is bigger than allocated memory\n");
                }
                /* Stateful decompression requires that the input buffer
                 * contains an even number of bytes for every request except
                 * the last, i.e. the last where CpaDcFlush is
                 * CPA_DC_FLUSH_FINAL. Submitting a request with an odd
                 * number of bytes will result in a partial consumption
                 * of the input data.If partial consumption occurs,
                 * submit the remaining data as part of the next request.
                 */
                remainder = 0;
                if (CPA_DC_FLUSH_FINAL != setup->requestOps.flushFlag &&
                    dstBuffListArray[i][j]->pBuffers->dataLenInBytes)
                {
                    remainder =
                        dstBuffListArray[i][j]->pBuffers->dataLenInBytes;
                    memcpy(
                        tempFB.pData,
                        dstBuffListArray[i][j + 1]->pBuffers->pData,
                        dstBuffListArray[i][j + 1]->pBuffers->dataLenInBytes);
                    tempFB.dataLenInBytes =
                        dstBuffListArray[i][j + 1]->pBuffers->dataLenInBytes;
                    /* Copy the remaining data to the start of the next
                     * request */
                    memcpy(dstBuffListArray[i][j + 1]->pBuffers->pData,
                           (dstBuffListArray[i][j]->pBuffers->pData),
                           remainder);
                    /* Copy the original data of the next request and
                     * append to the remaining data */
                    memcpy((dstBuffListArray[i][j + 1]->pBuffers->pData +
                            remainder),
                           tempFB.pData,
                           tempFB.dataLenInBytes);
                    /* Update the next request with the correct length */
                    dstBuffListArray[i][j + 1]->pBuffers->dataLenInBytes =
                        remainder + tempFB.dataLenInBytes;
                }
                dstBuffListArray[i][j]->pBuffers->dataLenInBytes =
                    (dataLenInBytes - remainder);
                dstBuffListArray[i][j]->pBuffers->pData = pData;
            } /* End of number of buffers Loop */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Data De-Compression Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
                break;
            }

            if (setup->corpus == LUKAS_COMPRESSED_FILES &&
                totalConsumed != fileArray[i].corpusBinaryDataLen)
            {
                PRINT_ERR(
                    "\n\n Input file Size     : %d\n Total bytes consumed: %d \
                         \n Total bytes produced: %d\n Residues            : %d\n",
                    (fileArray[i].corpusBinaryDataLen),
                    totalConsumed,
                    totalProduced,
                    (fileArray[i].corpusBinaryDataLen - totalConsumed));
                status = CPA_STATUS_FAIL;
                break;
            }
        } /* End of number of File Loop */

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Data De-Compression Failed %d\n\n", status);
            perfData->threadReturnStatus = CPA_STATUS_FAIL;
            break;
        }

    } /* End of de-compression Loops*/

    /* Close the DC Session */
    status = cpaDcRemoveSession(setup->dcInstanceHandle, pSessionHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to remove session\n");
        perfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    freeCbTags(dcCallbackTag, numFilesInCorpus, setup);
    qaeMemFreeNUMA((void **)&pSessionHandle);

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        for (i = 0; i < perfData->latencyCount; i++)
        {
            perfData->aveLatency +=
                perfData->response_times[i] - request_submit_start[i];
        }
        if (perfData->latencyCount > 0)
        {
            do_div(perfData->aveLatency, perfData->latencyCount);
        }
    }
#endif

    return status;
}

CpaStatus dcPerformStateful(compression_test_params_t *setup)
{
    /* start of local variable declarations */
    Cpa32U i = 0;
    Cpa32U j = 0;
    Cpa8U *filePtr = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U nodeId = 0;
    /* Initialize to 0 and set later to size as declared in setup */
    Cpa32U totalBuffs = 0;
    Cpa32U bufferSize = 0;
    CpaDcRqResults ***cmpResult = NULL;
    CpaDcRqResults ***dcmpResult = NULL;
    Cpa32U amountOfFullBuffers = 0;
    Cpa32U metaSize = 0;
    /* Performance data Structure */
    perf_data_t *perfData = NULL;
    /* Src Buffer list for data to be compressed */
    CpaBufferList ***srcBuffListArray = NULL;
    /* BufferList for de-compressed Data */
    CpaBufferList ***dstBuffListArray = NULL;
    /* BufferList for compressed data */
    CpaBufferList ***cmpBuffListArray = NULL;
    /* Initialize to compress and set later to direction as declared in setup */
    CpaDcSessionDir dcSessDir = CPA_DC_DIR_COMPRESS;
    Cpa32U numFilesInCorpus = getNumFilesInCorpus(setup->corpus);
    const corpus_file_t *const fileArray = getFilesInCorpus(setup->corpus);

#ifdef ZERO_BYTE_LAST_REQUEST
    Cpa32U lastBufferIndex = 0;
#endif

    if (NULL == setup)
    {
        PRINT_ERR(" Setup Pointer is NULL\n");
        return CPA_STATUS_FAIL;
    }
    bufferSize = setup->bufferSize;
    dcSessDir = setup->dcSessDir;
    bufferSize = setup->bufferSize;
    /* get the performance structure */
    perfData = setup->performanceStats;

    /* Get the Node Affinity to allocate memory */
    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return status;
    }


    /* Allocate buff list list pointers
     * this list array is used as source for compression
     */
    srcBuffListArray = qaeMemAlloc(numFilesInCorpus * sizeof(CpaBufferList *));
    /* Check for NULL */
    if (NULL == srcBuffListArray)
    {
        PRINT_ERR("unable to allocate srcBuffListArray\n");
        return CPA_STATUS_FAIL;
    }

    /* Allocate buff list list pointers
     * This List array will be used as destination buffers
     * to store compressed data
     */
    dstBuffListArray =
        qaeMemAlloc((numFilesInCorpus * sizeof(CpaBufferList *)));
    /* Check for NULL */
    if (NULL == dstBuffListArray)
    {
        qaeMemFree((void **)&srcBuffListArray);
        PRINT_ERR("unable to allocate dstBuffListArray \n");
        return CPA_STATUS_FAIL;
    }

    /* Allocate bufflist list pointers
     * This List array will be used as destination buffers
     * for the decompression
     */
    cmpBuffListArray =
        qaeMemAlloc((numFilesInCorpus * sizeof(CpaBufferList *)));
    /* Check for NULL */
    if (NULL == cmpBuffListArray)
    {
        qaeMemFree((void **)&srcBuffListArray);
        qaeMemFree((void **)&dstBuffListArray);
        PRINT_ERR("unable to allocate cmpBuffListArray \n");
        return CPA_STATUS_FAIL;
    }

    /* populate the bufflist array with number of Buffers required
     * for each file and allocate the memory
     */
    for (i = 0; i < numFilesInCorpus; i++)
    {

#ifdef ZERO_BYTE_LAST_REQUEST
        if (zeroByteLastRequest_g)
        {
            /* To support zero byte requests to indicate
             * a termination of a flow, we increment the number of buffers
             * required for each file by 1, this additional buffer will have
             * dataLenInBytes = 0.
             */
            setup->numberOfBuffers[i] += 1;
        }
#endif
        /* add up the number of buffers required for
         * complete corpus, this counter will be used to get the
         * number of call backs invoked
         */
        totalBuffs += setup->numberOfBuffers[i];

        /* allocate the memory for src, destination and compare buffers
         * for each file
         */
        srcBuffListArray[i] = qaeMemAlloc(
            (setup->numberOfBuffers[i] * (sizeof(CpaBufferList *))));
        /* Check for NULL */
        if (NULL == srcBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for File\n ");
            freeBuffers(srcBuffListArray, i, setup);
            freeBuffers(dstBuffListArray, i, setup);
            freeBuffers(cmpBuffListArray, i, setup);
            return CPA_STATUS_FAIL;
        }
        dstBuffListArray[i] = qaeMemAlloc(
            (setup->numberOfBuffers[i] * (sizeof(CpaBufferList *))));
        /* Check for NULL */
        if (NULL == dstBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for File\n ");
            freeBuffers(srcBuffListArray, i, setup);
            freeBuffers(dstBuffListArray, i, setup);
            freeBuffers(cmpBuffListArray, i, setup);
            return CPA_STATUS_FAIL;
        }
        cmpBuffListArray[i] = qaeMemAlloc(
            (setup->numberOfBuffers[i] * (sizeof(CpaBufferList *))));
        /* Check for NULL */
        if (NULL == cmpBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for File\n ");
            freeBuffers(srcBuffListArray, i, setup);
            freeBuffers(dstBuffListArray, i, setup);
            freeBuffers(cmpBuffListArray, i, setup);
            return CPA_STATUS_FAIL;
        }
    }
    /* update the number of operations to
     * total number of buffers required for
     * complete corpus based on the session direction
     *
     */
    perfData->numOperations = (Cpa64U)totalBuffs * setup->numLoops;

    if (CPA_DC_DIR_COMBINED == dcSessDir)
    {
        perfData->numOperations =
            ((Cpa64U)totalBuffs * setup->numLoops) * DOUBLE_SUBMISSIONS;
    }

    /* Allocate Flat Buffers for each file in buffer List array */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        status = createBuffers(
            bufferSize, setup->numberOfBuffers[i], srcBuffListArray[i], nodeId);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Create Buffers for source List array\n");
            freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
            freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
            freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
            return CPA_STATUS_FAIL;
        }
        /* When compressing,small packet sizes the destination buffer
         * may need to be larger than the source buffer to accommodate
         * huffman data, so allocate double the source buffer size
         */
        if (MIN_DST_BUFFER_SIZE >= bufferSize)
        {
            if (setup->useXlt)
            {
                /*To get xlt overflow minimum destination buffer size
                should be 128Byte.So if this feature is enabled,reduce
                destination buffer size by 0.85% of input buffer size.*/
                status = createBuffers(((bufferSize * 85UL) / 100UL),
                                       setup->numberOfBuffers[i],
                                       dstBuffListArray[i],
                                       nodeId);
            }
            else
            {
                status = createBuffers(bufferSize * EXTRA_BUFFER,
                                       setup->numberOfBuffers[i],
                                       dstBuffListArray[i],
                                       nodeId);
            }
        }
        else
        {
            status = createBuffers(bufferSize,
                                   setup->numberOfBuffers[i],
                                   dstBuffListArray[i],
                                   nodeId);
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Create Buffers for destination List array\n");
            freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
            freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
            freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
            return CPA_STATUS_FAIL;
        }
        /* When Decompression, the FW expects that the Buffer size
         * to be greater than the source buffer, so allocate double the
         * size of the source buffer
         */
        status = createBuffers((bufferSize * EXTRA_BUFFER * expansionFactor_g),
                               setup->numberOfBuffers[i],
                               cmpBuffListArray[i],
                               nodeId);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Create Buffers for compare List array\n");
            freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
            freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
            freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
            return CPA_STATUS_FAIL;
        }
#ifdef ZERO_BYTE_LAST_REQUEST
        if (zeroByteLastRequest_g)
        {
            lastBufferIndex = setup->numberOfBuffers[i] - 1;
            srcBuffListArray[i][lastBufferIndex]->pBuffers->dataLenInBytes = 0;
        }
#endif
    }
    /* Allocate Memory for the results structure */
    cmpResult = qaeMemAlloc((numFilesInCorpus * sizeof(CpaDcRqResults *)));
    if (NULL == cmpResult)
    {
        PRINT_ERR("unable to allocate memory for Results\n");
        freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
        freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
        freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
        return CPA_STATUS_FAIL;
    }
    /* Allocate Memory for the results structure */
    dcmpResult = qaeMemAlloc((numFilesInCorpus * sizeof(CpaDcRqResults *)));
    if (NULL == dcmpResult)
    {
        PRINT_ERR("unable to allocate memory for Results\n");
        qaeMemFree((void **)&cmpResult);
        freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
        freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
        freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
        return CPA_STATUS_FAIL;
    }

    /* Copy data into Flat Buffers from the corpus structure */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        filePtr = fileArray[i].corpusBinaryData;
        /* get the number of full Buffers */
        amountOfFullBuffers = (fileArray[i].corpusBinaryDataLen) / bufferSize;
        /* Copy the data into Flat buffers */
        for (j = 0; j < amountOfFullBuffers; j++)
        {
            memcpy(
                (srcBuffListArray[i][j]->pBuffers->pData), filePtr, bufferSize);
            filePtr += bufferSize;
        }
        filePtr = NULL;
    }

    /* allocate the results structure for each buffer in the
     * corpus file
     */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        dcmpResult[i] =
            qaeMemAlloc(setup->numberOfBuffers[i] * sizeof(CpaDcRqResults *));
        if (NULL == dcmpResult[i])
        {
            PRINT_ERR("unable to allocate memory for"
                      "Results structure for each buffer\n");
            freeResults(dcmpResult, i, setup);
            qaeMemFree((void **)&cmpResult);
            freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
            freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
            freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
            return CPA_STATUS_FAIL;
        }
    }

    for (i = 0; i < numFilesInCorpus; i++)
    {
        cmpResult[i] =
            qaeMemAlloc(setup->numberOfBuffers[i] * sizeof(CpaDcRqResults *));
        if (NULL == cmpResult[i])
        {
            PRINT_ERR("unable to allocate memory for"
                      "Results structure for each buffer\n");
            freeResults(cmpResult, i, setup);
            freeResults(dcmpResult, numFilesInCorpus, setup);
            freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
            freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
            freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
            return CPA_STATUS_FAIL;
        }
    }

    for (i = 0; i < numFilesInCorpus; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            cmpResult[i][j] = qaeMemAlloc(sizeof(CpaDcRqResults));
            if (NULL == cmpResult[i][j])
            {
                freeResults(cmpResult, numFilesInCorpus, setup);
                freeResults(dcmpResult, numFilesInCorpus, setup);
                freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
                freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
                freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
                return CPA_STATUS_FAIL;
            }
            dcmpResult[i][j] = qaeMemAlloc(sizeof(CpaDcRqResults));
            if (NULL == dcmpResult[i][j])
            {
                freeResults(cmpResult, numFilesInCorpus, setup);
                freeResults(dcmpResult, numFilesInCorpus, setup);
                freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
                freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
                freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
                return CPA_STATUS_FAIL;
            }
        }
    }
    /* get the Meta Size for each buffer List and
     * allocate Private Meta Data
     */
    for (i = 0; i < numFilesInCorpus; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            /* Get the Meta size for each file in buffers list */
            status =
                cpaDcBufferListGetMetaSize(setup->dcInstanceHandle,
                                           srcBuffListArray[i][j]->numBuffers,
                                           &metaSize);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to get Meta Size\n");
                freeResults(dcmpResult, numFilesInCorpus, setup);
                freeResults(cmpResult, numFilesInCorpus, setup);
                freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
                freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
                freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
                return CPA_STATUS_FAIL;
            }

            srcBuffListArray[i][j]->pPrivateMetaData =
                qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
            if (NULL == srcBuffListArray[i][j]->pPrivateMetaData)
            {
                PRINT_ERR(" Unable to allocate pPrivateMetaData\n");
                freeResults(dcmpResult, numFilesInCorpus, setup);
                freeResults(cmpResult, numFilesInCorpus, setup);
                freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
                freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
                freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
                return CPA_STATUS_FAIL;
            }
            cmpBuffListArray[i][j]->pPrivateMetaData =
                qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
            if (NULL == cmpBuffListArray[i][j]->pPrivateMetaData)
            {
                PRINT_ERR(" Unable to allocate pPrivateMetaData\n");
                freeResults(dcmpResult, numFilesInCorpus, setup);
                freeResults(cmpResult, numFilesInCorpus, setup);
                freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
                freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
                freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
                return CPA_STATUS_FAIL;
            }
            dstBuffListArray[i][j]->pPrivateMetaData =
                qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
            if (dstBuffListArray[i][j]->pPrivateMetaData == NULL)
            {
                PRINT_ERR(" Unable to allocate pPrivateMetaData\n");
                freeResults(dcmpResult, numFilesInCorpus, setup);
                freeResults(cmpResult, numFilesInCorpus, setup);
                freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
                freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
                freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);
                return CPA_STATUS_FAIL;
            }
        }
    }

#if DC_API_VERSION_LESS_THAN(1, 6)
#endif

    if (CPA_DC_DIR_COMPRESS == dcSessDir)
    {
        status = performCompressStateful(setup,
                                         srcBuffListArray,
                                         dstBuffListArray,
                                         cmpResult,
                                         dcPerformStatefulCallback);
        dcSetBytesProducedAndConsumed(
            cmpResult, setup->performanceStats, setup);
    }
    if (CPA_DC_DIR_DECOMPRESS == dcSessDir)
    {
        status = performDeCompressStateful(setup,
                                           srcBuffListArray,
                                           dstBuffListArray,
                                           cmpBuffListArray,
                                           cmpResult,
                                           dcmpResult,
                                           deCompressStatefulCallback);
        // dcSetBytesProducedAndConsumed(dcmpResult,setup->performanceStats,setup);
    }

    /* Free all the results structures */
    freeResults(cmpResult, numFilesInCorpus, setup);
    freeResults(dcmpResult, numFilesInCorpus, setup);
    /* Free all the Buffer Lists */

    freeBuffers(srcBuffListArray, numFilesInCorpus, setup);
    freeBuffers(dstBuffListArray, numFilesInCorpus, setup);
    freeBuffers(cmpBuffListArray, numFilesInCorpus, setup);

    /*clean up the callback semaphore*/

    sampleCodeSemaphoreDestroy(&perfData->comp);
    return status;
}

/*********** Call Back Function **************/
void dcPerformanceStateful(single_thread_test_data_t *testSetup)
{
    compression_test_params_t dcSetup, *tmpSetup = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcInstanceCapabilities capabilities = {0};


    /* Get the setup pointer */
    tmpSetup = (compression_test_params_t *)(testSetup->setupPtr);
    /* update the setup structure with setup parameters */
    memcpy(&dcSetup.requestOps, &tmpSetup->requestOps, sizeof(CpaDcOpData));
    dcSetup.bufferSize = tmpSetup->bufferSize;
    dcSetup.corpus = tmpSetup->corpus;
    dcSetup.setupData = tmpSetup->setupData;
    dcSetup.dcSessDir = tmpSetup->dcSessDir;
    dcSetup.syncFlag = tmpSetup->syncFlag;
    dcSetup.numLoops = tmpSetup->numLoops;
    /*give our thread a unique memory location to store performance stats*/
    dcSetup.performanceStats = testSetup->performanceStats;
    dcSetup.useXlt = tmpSetup->useXlt;
    dcSetup.useE2E = tmpSetup->useE2E;
    dcSetup.useE2EVerify = tmpSetup->useE2EVerify;
    /* In case of E2E Verify we need to use CRC32 only */
    if (dcSetup.useE2EVerify)
        dcSetup.setupData.checksum = CPA_DC_CRC32;
    testSetup->performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;

    status = calculateRequireBuffers(&dcSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("Error calculating required buffers\n");
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space is does
     * nothing, but kernel space threads do not start
     * until we call startThreads anyway
     */
    startBarrier();

    /*Initialize the statsPrintFunc to NULL, the dcPrintStats function will
     * be assigned if compression completes successfully
     */
    testSetup->statsPrintFunc = NULL;

    /* Get the number of instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR(" Unable to get number of DC instances\n");
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return;
    }
    if (0 == numInstances)
    {
        PRINT_ERR(" DC Instances are not present\n");
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == instances)
    {
        PRINT_ERR("Unable to allocate Memory for Instances\n");
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        sampleCodeThreadExit();
    }

    /*get the instance handles so that we can start
     * our thread on the selected instance
     */
    status = cpaDcGetInstances(numInstances, instances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get instances failed");
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        sampleCodeThreadExit();
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
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (CPA_FALSE == capabilities.dynamicHuffman &&
        tmpSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
    {
        PRINT("Dynamic is not supported on logical instance %d\n",
              (testSetup->logicalQaInstance) % numInstances);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        sampleCodeThreadExit();
    }
    if (CPA_TRUE == dcSetup.useE2E)
    {
            if (CPA_FALSE == capabilities.integrityCrcs)
            {

                PRINT("CRC integrity check is unsupported for this instance. "
                      "%d\n",
                      testSetup->logicalQaInstance);
                testSetup->performanceStats->threadReturnStatus =
                    CPA_STATUS_SUCCESS;
                qaeMemFree((void **)&instances);
                qaeMemFree((void **)&dcSetup.numberOfBuffers);
                sampleCodeThreadExit();
            }
    }

    /*launch function that does all the work*/
    status = dcPerformStateful(&dcSetup);
    if ((CPA_STATUS_SUCCESS != status) ||
        (CPA_STATUS_SUCCESS != testSetup->performanceStats->threadReturnStatus))
    {
        dcPrintTestData(&dcSetup);
        PRINT_ERR("Compression Thread FAILED\n");
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print
         * statistics at the end of the test
         * */
        testSetup->statsPrintFunc = (stats_print_func_t)dcPrintStats;
    }
    qaeMemFree((void **)&dcSetup.numberOfBuffers);
    qaeMemFree((void **)&instances);


    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(dcPerformanceStateful);

CpaStatus setupDcStatefulTest_Depreciated(CpaDcCompType algorithm,
                                          CpaDcSessionDir direction,
                                          CpaDcCompLvl compLevel,
                                          CpaDcHuffType huffmanType,
                                          Cpa32U testBufferSize,
                                          corpus_type_t corpusType,
                                          synchronous_flag_t syncFlag,
                                          Cpa32U numLoops)
{

    compression_test_params_t *dcSetup = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;


    /* Initialize the Performance device */
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }
    /* Populate Corpus */
    status = populateCorpus(testBufferSize, corpusType);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to load one or more corpus files, have they been "
                  "extracted to %s?\n",
                  SAMPLE_CODE_CORPUS_PATH);
        return CPA_STATUS_FAIL;
    }

    /*Start DC Services */
    status =
        startDcServices(testBufferSize /*DYNAMIC_BUFFER_AREA*/, TEMP_NUM_BUFFS);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error in Starting Dc Services\n");
        return CPA_STATUS_FAIL;
    }
    /* start polling threads if polling is enabled in the configuration file */
    if (CPA_STATUS_SUCCESS != dcCreatePollingThreadsIfPollingIsEnabled())
    {
        PRINT_ERR("Error creating polling threads\n");
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
        (performance_func_t)dcPerformanceStateful;

    /* update the setup_g with buffersize */
    testSetupData_g[testTypeCount_g].packetSize = testBufferSize;
    /* Data compression setup data */
    dcSetup->setupData.compLevel = compLevel;
    dcSetup->setupData.compType = algorithm;

    dcSetup->setupData.sessDirection = direction;
    dcSetup->setupData.checksum = checksum_g;
#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
    dcSetup->setupData.huffType = huffmanType;
#else
    dcSetup->setupData.huffType = CPA_DC_HT_STATIC;
#endif
    dcSetup->setupData.sessState = CPA_DC_STATEFUL;
#if DC_API_VERSION_LESS_THAN(1, 6)
    dcSetup->setupData.fileType = CPA_DC_FT_ASCII;
    dcSetup->setupData.deflateWindowSize = DEFAULT_COMPRESSION_WINDOW_SIZE;
#endif
    dcSetup->corpus = corpusType;
    dcSetup->bufferSize = testBufferSize;
    dcSetup->dcSessDir = direction;
    dcSetup->setupData.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;


    dcSetup->syncFlag = syncFlag;
    dcSetup->numLoops = numLoops;

    return status;
}
EXPORT_SYMBOL(setupDcStatefulTest_Depreciated);
