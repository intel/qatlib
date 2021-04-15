/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 * @file cpa_sample_code_dc_2k.c
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

#define ZLIB_OUTPUT_BUFFER_SIZE_MULTIPLIER (20)
//#define DEBUG_STATEFUL2
CpaDcChecksum checksum2_g = CPA_DC_NONE;
extern CpaStatus createStartandWaitForCompletion(Cpa32U instType);
extern CpaStatus getCompressionInstanceMapping(void);
extern CpaStatus printFuzzFile(void);
extern CpaStatus setFuzzFile(const char *fileName);

extern Cpa16U numInst_g;


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

Cpa32U roundUp(Cpa32U a, Cpa32U b)
{
    Cpa32U c = a / b;
    if (a % b)
    {
        c++;
    }
    return c;
}

void printBuffer(CpaFlatBuffer flatBuffer)
{
    Cpa32U i = 0;

    for (i = 0; i < flatBuffer.dataLenInBytes; i++)
    {
        PRINT("%02X ", flatBuffer.pData[i]);
        if (i % 8 == 0 && i != 0 && i != 16)
        {
            PRINT("    ");
        }
        if (i % 16 == 0 && i != 0)
        {
            PRINT("\n");
        }
    }
    PRINT("\n");
}
void printListAddress(CpaBufferList *pList)
{
#ifdef DEBUG_STATEFUL2
    Cpa32U i = 0;

    for (i = 0; i < pList->numBuffers; i++)
    {
        PRINT("pMeta %08x, pBuff %08x, pData[%d] %08x, Len: %d\n",
              pList->pPrivateMetaData,
              pList->pBuffers,
              i,
              pList->pBuffers[i].pData,
              pList->pBuffers[i].dataLenInBytes);
    }
    PRINT("\n");
#endif
}

void deCompressStatefulCallback2(void *pCallbackTag, CpaStatus status)
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
        PRINT("DC Function Failed, status = %d \n", status);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    /* Update the data length with produced */
    cbTag->pBuffList->pBuffers->dataLenInBytes = cbTag->dcResult->produced;
    /* increment the responses */
    pPerfData->responses++;
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
void dcPerformStatefulCallback2(void *pCallbackTag, CpaStatus status)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;


    /*check status */
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DC Function Failed with status %d after response %llu\n",
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

CpaStatus populateRandomCorpus(Cpa32U numLists,
                               CpaBufferList **pBuffListArray,
                               CpaBufferList **cmpBuffListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U j = 0;

    for (i = 0; i < numLists; i++)
    {
        for (j = 0; j < pBuffListArray[i]->numBuffers; j++)
        {
            generateRandomData(pBuffListArray[i]->pBuffers[j].pData,
                               pBuffListArray[i]->pBuffers[j].dataLenInBytes);
            /*memcpy(cmpBuffListArray[i]->pBuffers[j].pData,
                    pBuffListArray[i]->pBuffers[j].pData,
                    pBuffListArray[i]->pBuffers[j].dataLenInBytes);*/
        }
    }

    return status;
}

void freeBuffers2(CpaBufferList ***pBuffListArray,
                  Cpa32U *numListsPerFile,
                  Cpa32U listSize,
                  Cpa32U numberOfFiles,
                  Cpa32U bufferSize)
{
    Cpa32U i = 0, j = 0, k = 0;
    Cpa32U numFlatBuffersPerList = 0;

    if (NULL == pBuffListArray)
    {
        /* Return Silent */
        return;
    }

    numFlatBuffersPerList = listSize / bufferSize;
    if (listSize % bufferSize)
    {
        numFlatBuffersPerList++;
    }
    if (0 != numberOfFiles)
    {
        for (i = 0; i < numberOfFiles; i++)
        {
#ifdef DEBUG_STATEFUL2
            PRINT("%d List %d addr %08x\n", __LINE__, i, pBuffListArray[i]);
#endif
            for (j = 0; j < numListsPerFile[i]; j++)
            {
#ifdef DEBUG_STATEFUL2
                PRINT("File %d, List %d, numFlatBuffers %d, listAddr %08x\n",
                      i,
                      j,
                      numFlatBuffersPerList,
                      pBuffListArray[i][j]);
#endif
                // printListAddress(pBuffListArray[i][j]);
                for (k = 0; k < numFlatBuffersPerList; k++)
                {

                    if (NULL != pBuffListArray[i][j]->pBuffers[k].pData)
                    {
                        qaeMemFreeNUMA(
                            (void **)&pBuffListArray[i][j]->pBuffers[k].pData);
                        if (NULL != pBuffListArray[i][j]->pBuffers[k].pData)
                        {
                            PRINT("Could not free bufferList[%d][%d] pData\n",
                                  i,
                                  j);
                        }
                    }
                }
                if (NULL != pBuffListArray[i][j]->pPrivateMetaData)
                {
                    qaeMemFreeNUMA(
                        (void **)&pBuffListArray[i][j]->pPrivateMetaData);
                    if (NULL != pBuffListArray[i][j]->pPrivateMetaData)
                    {
                        PRINT("Could not free "
                              "bufferList[%d][%d] pPrivateMetaData\n",
                              i,
                              j);
                    }
                }
                if (NULL != pBuffListArray[i][j]->pBuffers)
                {
                    qaeMemFree((void **)&pBuffListArray[i][j]->pBuffers);
                    if (NULL != pBuffListArray[i][j]->pBuffers)
                    {
                        PRINT("Could not free bufferList[%d][%d] pBuffers\n",
                              i,
                              j);
                    }
                }
                if (NULL != pBuffListArray[i][j])
                {
                    qaeMemFree((void **)&pBuffListArray[i][j]);
                    if (NULL != pBuffListArray[i][j])
                    {
                        PRINT("%d:: Could not free bufferList[%d][%d]\n",
                              __LINE__,
                              i,
                              j);
                    }
                }
            }
            if (NULL != pBuffListArray[i])
            {
#ifdef DEBUG_STATEFUL2
                PRINT("List %d addr %08x\n", i, pBuffListArray[i]);
#endif
                qaeMemFree((void **)&pBuffListArray[i]);
                if (NULL != pBuffListArray[i])
                {
                    PRINT("Could not free bufferList[%d]\n", i);
                }
            }
        }
    }
#ifdef DEBUG_STATEFUL2
    PRINT("%d:: List %d addr %08x\n", __LINE__, i, pBuffListArray);
#endif
    qaeMemFree((void **)&pBuffListArray);
    if (NULL != pBuffListArray)
    {
        PRINT("Could not free bufferList\n");
    }
    return;
}

void dcSetBytesProducedAndConsumed2(CpaDcRqResults ***cmpResult,
                                    perf_data_t *perfData,
                                    compression_test_params_t *setup)
{

    Cpa32U i = 0, j = 0;

    for (i = 0; i < setup->sessions; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
#ifdef DEBUG_STATEFUL2
            PRINT("File %d, BuffList%d, Consumed %u, Produced %u\n",
                  i,
                  j,
                  cmpResult[i][j]->consumed,
                  cmpResult[i][j]->produced);
#endif
            perfData->bytesConsumedPerLoop += cmpResult[i][j]->consumed;
            perfData->bytesProducedPerLoop += cmpResult[i][j]->produced;
        }
    }
}

CpaStatus createBuffers2(Cpa32U listSize,
                         Cpa32U flatBuffSize,
                         Cpa32U numListsPerFile,
                         CpaBufferList **pBuffListArray,
                         Cpa32U nodeId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U j = 0;
    Cpa32U numBuffsPerList = 0;


    numBuffsPerList = listSize / flatBuffSize;
    if (listSize % flatBuffSize)
    {
        // if the list does not divide evenly, add another buffer
        numBuffsPerList++;
    }
#ifdef DEBUG_STATEFUL2
    PRINT("Creating %d Lists, ListSize %d, with %d flatBuffSize = %d "
          "flatBuffers\n",
          numListsPerFile,
          listSize,
          flatBuffSize,
          numBuffsPerList);
#endif
    for (i = 0; i < numListsPerFile; i++)
    {
        pBuffListArray[i] = qaeMemAlloc(sizeof(CpaBufferList));
#ifdef DEBUG_STATEFUL2
        PRINT("List %d addr %08x\n", i, pBuffListArray[i]);
#endif
        if (NULL == pBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]\n", i);
            return CPA_STATUS_FAIL;
        }
        pBuffListArray[i]->pBuffers =
            qaeMemAlloc(sizeof(CpaFlatBuffer) * numBuffsPerList);
        if (NULL == pBuffListArray[i]->pBuffers)
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d] pBuffers\n", i);
            return CPA_STATUS_FAIL;
        }
        for (j = 0; j < numBuffsPerList; j++)
        {
            /* Allocate Flat buffer for each buffer List */
            pBuffListArray[i]->pBuffers[j].dataLenInBytes = flatBuffSize;
            pBuffListArray[i]->pBuffers[j].pData =
                qaeMemAllocNUMA(flatBuffSize, nodeId, BYTE_ALIGNMENT_64);

            if (NULL == pBuffListArray[i]->pBuffers[j].pData)
            {
                PRINT_ERR("pBuffListArray[%d] pBuffers[%d].pData\n", i, j);
                return CPA_STATUS_FAIL;
            }
            memset(pBuffListArray[i]->pBuffers[j].pData, 0, flatBuffSize);
        }
        pBuffListArray[i]->numBuffers = numBuffsPerList;
    }

    return status;
}

static CpaStatus dcSampleCreateStatefulContextBuffer2(
    Cpa32U buffSize,
    Cpa32U metaSize,
    CpaBufferList **pBuffListArray,
    Cpa32U nodeId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;


    *pBuffListArray =
        qaeMemAllocNUMA((sizeof(CpaBufferList)), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == (*pBuffListArray))
    {
        PRINT_ERR(" Unable to allocate Buffers List Array\n");
        return CPA_STATUS_FAIL;
    }
    (*pBuffListArray)->numBuffers = ONE_BUFFER_DC;
    (*pBuffListArray)->pBuffers =
        qaeMemAllocNUMA((sizeof(CpaFlatBuffer)), nodeId, BYTE_ALIGNMENT_64);
    if (NULL == (*pBuffListArray)->pBuffers)
    {
        PRINT_ERR(" Unable to allocate Flat Buffers\n");
        qaeMemFreeNUMA((void **)pBuffListArray);
        return CPA_STATUS_FAIL;
    }
    if (metaSize)
    {
        (*pBuffListArray)->pPrivateMetaData =
            (Cpa8U *)qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
        if (NULL == (*pBuffListArray)->pPrivateMetaData)
        {
            PRINT_ERR(" Unable to allocate pPrivateMetaData Buffers\n");
            qaeMemFreeNUMA((void **)&(*pBuffListArray)->pBuffers);
            qaeMemFreeNUMA((void **)pBuffListArray);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        (*pBuffListArray)->pPrivateMetaData = NULL;
    }

    /* Allocate Flat buffer for each buffer List */
    (*pBuffListArray)->pBuffers->dataLenInBytes = buffSize;
    if (0 == buffSize)
    {
        (*pBuffListArray)->pBuffers->pData = NULL;
    }
    else
    {
        (*pBuffListArray)->pBuffers->pData =
            qaeMemAllocNUMA(buffSize, nodeId, BYTE_ALIGNMENT_64);
        if (NULL == (*pBuffListArray)->pBuffers->pData)
        {
            PRINT(" Unable to allocate Flat buffer\n");
            qaeMemFreeNUMA((void **)&(*pBuffListArray)->pPrivateMetaData);
            qaeMemFreeNUMA((void **)&(*pBuffListArray)->pBuffers);
            qaeMemFreeNUMA((void **)pBuffListArray);
            return CPA_STATUS_FAIL;
        }

        memset((*pBuffListArray)->pBuffers->pData, 0, buffSize);
    }

    return status;
}

static void dcSampleFreeStatefulContextBuffer2(CpaBufferList *pBuffListArray)
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

CpaStatus submitList(compression_test_params_t *setup,
                     CpaBufferList *srcBuffListArray,
                     CpaBufferList *dstBuffListArray,
                     CpaBufferList *cmpBuffListArray,
                     CpaDcRqResults *cmpResult,
                     CpaDcSessionHandle *pSessionHandle,
                     CpaDcFlush flushFlag,
                     struct z_stream_s *stream)
{
    CpaStatus status = CPA_STATUS_FAIL;
    /*CpaBufferList cmpResubmitList;*/
    Cpa32U nodeId = 0;
#ifdef USE_ZLIB
    Cpa8U *tempPtr = NULL;
    Cpa32U tempLen = 0;
    /*Cpa8U *cmpTempPtr = NULL;
    Cpa32U cmpTempLen = 0;*/
    Cpa32U srcListLen = 0;
    Cpa32U i = 0;
    Cpa32U amountOfFullBuffersConsumed = 0;
    Cpa32U offsetIntoIncompleteBuffer = 0;
    CpaBufferList resubmitList;
    Cpa32U metaSize = 0;
    CpaDcRqResults result = {0, 0, 0, 0, 0};
    Cpa32U tempSize = 0;
    Cpa32U zlibProduced = 0;
    Cpa32U numFilledBuffers = 0;
    Cpa32U remainder = 0;
#endif

    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return status;
    }

    setup->requestOps.flushFlag = flushFlag;
    do
    {
        status = cpaDcCompressData2(setup->dcInstanceHandle,
                                    pSessionHandle,
                                    srcBuffListArray,
                                    dstBuffListArray,
                                    &setup->requestOps,
                                    cmpResult,
                                    setup->performanceStats);
        if (CPA_STATUS_RETRY == status)
        {
            setup->performanceStats->retries++;
            if (RETRY_LIMIT == setup->performanceStats->retries)
            {
                setup->performanceStats->retries = 0;
                AVOID_SOFTLOCKUP;
            }
        }
    } while (CPA_STATUS_RETRY == status);
#ifdef USE_ZLIB
#ifdef DEBUG_STATEFUL2_SUBLIST
    PRINT("%d:: Consumed %d, Produced %d, Status %d\n",
          __LINE__,
          cmpResult->consumed,
          cmpResult->produced,
          cmpResult->status);
#endif
    /* Check Status */
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Data Compression Failed %d\n\n", status);
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return CPA_STATUS_FAIL;
    }

    /* check if synchronous flag is set
     * if set, invoke the callback API
     */
    if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
    {
        /* invoke the Compression Callback only */
        dcPerformStatefulCallback2(setup->performanceStats, status);
    }

    /* Stateful compression only supports a single request in flight
     * for each session, so wait for the semaphore to post on the
     * submitted request
     */
    status = waitForSemaphore(setup->performanceStats);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Wait for Semaphore Failed %d\n\n", status);
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return CPA_STATUS_FAIL;
    }
    /*check that we can decompress with zlib*/
    numFilledBuffers =
        cmpResult->produced / dstBuffListArray->pBuffers[0].dataLenInBytes;
    remainder =
        cmpResult->produced % dstBuffListArray->pBuffers[0].dataLenInBytes;

#ifdef DEBUG_STATEFUL2_SUBLIST
    PRINT("numBuffers %d, amountFilled %d, amountInLast %d\n",
          dstBuffListArray->numBuffers,
          numFilledBuffers,
          remainder);
#endif
    for (i = 0; i < numFilledBuffers; i++)
    {
        tempSize = cmpBuffListArray->pBuffers[0].dataLenInBytes;

#ifdef DEBUG_STATEFUL2_SUBLIST
        PRINT("inflate buffer[%d] size: %d into buffer of size %d, produced: ",
              i,
              dstBuffListArray->pBuffers[0].dataLenInBytes,
              cmpBuffListArray->pBuffers[0].dataLenInBytes);
#endif
        status =
            inflate_decompress(stream,
                               dstBuffListArray->pBuffers[i].pData,
                               dstBuffListArray->pBuffers[i].dataLenInBytes,
                               cmpBuffListArray->pBuffers[0].pData,
                               cmpBuffListArray->pBuffers[0].dataLenInBytes,
                               setup->setupData.sessState);
        if (CPA_STATUS_SUCCESS != status)
        {
            /*cmpBuffListArray->pBuffers[i].dataLenInBytes =
                                tempSize - (*stream).avail_out;*/
            PRINT("%d:: srcLen: %d, destLen: %d \n",
                  __LINE__,
                  dstBuffListArray->pBuffers[i].dataLenInBytes,
                  tempSize - (Cpa32U)((*stream).avail_out));
            setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
            break;
        }
        zlibProduced += tempSize - (*stream).avail_out;
#ifdef DEBUG_STATEFUL2_SUBLIST
        PRINT(" %d, remaining %d\n",
              tempSize - (*stream).avail_out,
              (*stream).avail_in);
#endif

        /*if( 0 != memcmp(srcBuffListArray->pBuffers[i].pData,
                cmpBuffListArray->pBuffers[i].pData,
                cmpResult->consumed))
        {
            PRINT("%d:: Buffers comparison Failed on buffer %d on a consumed \
                     Length of %d\n", __LINE__,i, cmpResult->consumed);
            PRINT("srcBuffListArray pBuffers[%d]::\n", i);
            printBuffer(srcBuffListArray->pBuffers[i]);
            PRINT("cmpBuffListArray pBuffers[%d]::\n", i);
            printBuffer(cmpBuffListArray->pBuffers[i]);
            return CPA_STATUS_FAIL;
        }*/
    }
    if (remainder)
    {
        tempSize = cmpBuffListArray->pBuffers[0].dataLenInBytes;
#ifdef DEBUG_STATEFUL2_SUBLIST
        PRINT("inflate %d buffer size %d produced: ",
              i,
              cmpBuffListArray->pBuffers[0].dataLenInBytes);
#endif
        status = inflate_decompress(
            stream,
            dstBuffListArray->pBuffers[numFilledBuffers].pData,
            remainder,
            cmpBuffListArray->pBuffers[0].pData,
            cmpBuffListArray->pBuffers[0].dataLenInBytes,
            setup->setupData.sessState);
        if (CPA_STATUS_SUCCESS != status)
        {
            /*cmpBuffListArray->pBuffers[numFilledBuffers].dataLenInBytes =
                                tempSize - (*stream).avail_out;*/
            PRINT("%d:: srcLen: %d, destLen: %d \n",
                  __LINE__,
                  remainder,
                  tempSize - (Cpa32U)((*stream).avail_out));
            setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        }
        zlibProduced += tempSize - (*stream).avail_out;
#ifdef DEBUG_STATEFUL2_SUBLIST
        PRINT(" %d, remaining %d\n",
              tempSize - (*stream).avail_out,
              (*stream).avail_in);
#endif
    }
#ifdef DEBUG_STATEFUL2_SUBLIST
    PRINT("Src Consumed: %d vs Zlib Produced %d\n",
          cmpResult->consumed,
          zlibProduced);
#endif
    /*check the what was produced from zlib matches consumed input*/
    if (zlibProduced != cmpResult->consumed)
    {
        PRINT_ERR(
            "zlib output length %d != consumed input length %d, diff: %d\n",
            zlibProduced,
            cmpResult->consumed,
            cmpResult->consumed - zlibProduced);
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeSleep(10);
    }

    if (cmpResult->status == CPA_DC_OVERFLOW)
    {
        setup->performanceStats->numOperations++;
        // PRINT("%d:: Consumed: %d\n", __LINE__,cmpResult->consumed);
        // PRINT("Src List: ");
        // printListAddress(srcBuffListArray);
        setup->performanceStats->overflow++;
        // need to resubmit from the at the overflow point

        // calculate the total length of the inputList
        for (i = 0; i < srcBuffListArray->numBuffers; i++)
        {
            srcListLen += srcBuffListArray->pBuffers[i].dataLenInBytes;
        }
        // calculate how far the into the list was consumed
        amountOfFullBuffersConsumed = cmpResult->consumed / setup->bufferSize;
        offsetIntoIncompleteBuffer =
            cmpResult->consumed -
            amountOfFullBuffersConsumed * setup->bufferSize;
        // store the existing ptr and update the inputList ptr for re-submission
        tempPtr = srcBuffListArray->pBuffers[amountOfFullBuffersConsumed].pData;
        tempLen = srcBuffListArray->pBuffers[amountOfFullBuffersConsumed]
                      .dataLenInBytes;
        /*cmpTempPtr =
        cmpBuffListArray->pBuffers[amountOfFullBuffersConsumed].pData;
        cmpTempLen =
        cmpBuffListArray->pBuffers[amountOfFullBuffersConsumed].dataLenInBytes;*/
        srcBuffListArray->pBuffers[amountOfFullBuffersConsumed].pData +=
            offsetIntoIncompleteBuffer;
        srcBuffListArray->pBuffers[amountOfFullBuffersConsumed]
            .dataLenInBytes -= offsetIntoIncompleteBuffer;
        /**cmpBuffListArray->pBuffers[amountOfFullBuffersConsumed].pData +=
                    offsetIntoIncompleteBuffer;
        cmpBuffListArray->pBuffers[amountOfFullBuffersConsumed].dataLenInBytes
        -=
                    offsetIntoIncompleteBuffer;*/
        /*setup a resubmit buffer using the existing uncompressed part of the
        srcList*/
        resubmitList.numBuffers =
            srcBuffListArray->numBuffers - amountOfFullBuffersConsumed;
        /*cmpResubmitList.numBuffers = srcBuffListArray->numBuffers -
                    amountOfFullBuffersConsumed;*/
        status = cpaDcBufferListGetMetaSize(
            setup->dcInstanceHandle, resubmitList.numBuffers, &metaSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get Meta Size\n");
            setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
            return CPA_STATUS_FAIL;
        }
        resubmitList.pPrivateMetaData =
            qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
        if (NULL == resubmitList.pPrivateMetaData)
        {
            PRINT_ERR("Could not alloc privateMeta data for re-submit list\n");
            setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
            return CPA_STATUS_FAIL;
        }
        /*cmpResubmitList.pPrivateMetaData =
                                qaeMemAllocNUMA(metaSize, nodeId,
        BYTE_ALIGNMENT_64);
        if( NULL == cmpResubmitList.pPrivateMetaData)
        {
            PRINT_ERR("Could not alloc privateMeta data for re-submit list\n");
            setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
            return CPA_STATUS_FAIL;
        }*/
        // copy the pData to resubmit list
        // PRINT("src pBuffer[offset] %08x\n",
        // srcBuffListArray->pBuffers[amountOfFullBuffersConsumed]);
        resubmitList.pBuffers =
            &srcBuffListArray->pBuffers[amountOfFullBuffersConsumed];
        /*cmpResubmitList.pBuffers =
                    &srcBuffListArray->pBuffers[amountOfFullBuffersConsumed];*/
        status = submitList(setup,
                            &resubmitList,
                            dstBuffListArray,
                            cmpBuffListArray,
                            &result,
                            pSessionHandle,
                            flushFlag,
                            stream);
        /*free privateMetaData regardless of result we are not going to use it
        again*/
        qaeMemFreeNUMA((void **)&resubmitList.pPrivateMetaData);
        /*qaeMemFreeNUMA((void**)&cmpResubmitList.pPrivateMetaData);*/
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to resubmit data\n");
            setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        }
        else
        {
            // update produced and consumed
            cmpResult->consumed += result.consumed;
            cmpResult->produced += result.produced;
        }
        // restore modified pBuffer
        srcBuffListArray->pBuffers[amountOfFullBuffersConsumed].pData = tempPtr;
        srcBuffListArray->pBuffers[amountOfFullBuffersConsumed].dataLenInBytes =
            tempLen;
        /*cmpBuffListArray->pBuffers[amountOfFullBuffersConsumed].pData =
        cmpTempPtr;
        cmpBuffListArray->pBuffers[amountOfFullBuffersConsumed].dataLenInBytes
            = cmpTempLen;*/
    }
#endif // USE_ZLIB
    return status;
}

static CpaStatus performCompressStateful2(compression_test_params_t *setup,
                                          CpaBufferList ***srcBuffListArray,
                                          CpaBufferList ***dstBuffListArray,
                                          CpaBufferList ***cmpBuffListArray,
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
    /*Cpa32U bufferSize = setup->bufferSize;
    Cpa32U numberOfFlatBuffsInLastList = 0;*/
    struct z_stream_s stream = {0};


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
        (sessionSize /*+ contextSize*/), nodeId, BYTE_ALIGNMENT_64);
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
        setup->dcInstanceHandle, setup->numberOfBuffers[0], &metaSizeInBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Meta size: status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }

    status =
        dcSampleCreateStatefulContextBuffer2((contextSize /* *EXTRA_BUFFER*/),
                                             metaSizeInBytes,
                                             &pContextBuffer,
                                             nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to allocate context : status = %d \n", status);
        qaeMemFreeNUMA((void **)&pSessionHandle);
        return CPA_STATUS_FAIL;
    }
    /*PRINT("%d:: pBuffers %08x pData %08x\n",__LINE__,
            pContextBuffer->pBuffers, pContextBuffer->pBuffers->pData);*/
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
        dcSampleFreeStatefulContextBuffer2(pContextBuffer);
        return CPA_STATUS_FAIL;
    }

#ifdef DELETE_THIS_CODE
    for (i = 0; i < setup->sessions; i++)
    {

        numberOfFlatBuffsInLastList =
            roundUp(setup->fileSize[i], bufferSize) -
            ((roundUp(setup->fileSize[i], setup->inputListSize) - 1) *
             roundUp(setup->inputListSize, bufferSize));
        srcBuffListArray[i][setup->numberOfBuffers[i] - 1]->numBuffers =
            numberOfFlatBuffsInLastList;
        /*
        PRINT("%d - %d * %d = numberOfFlatBuffsInLastList\n",
                        roundUp(setup->fileSize[i],bufferSize),
                        roundUp(setup->fileSize[i],setup->inputListSize)-1,
                        roundUp(setup->inputListSize,bufferSize));
        PRINT("File %d has %d lists\n", i, setup->numberOfBuffers[i]);
        PRINT("numberOfBuffersInLists %d\n",
        roundUp(setup->inputListSize,bufferSize));
        PRINT("numberOfFlatBuffsInLastList %d\n",numberOfFlatBuffsInLastList);

        PRINT("fileSize[%d]: %d\n", i, setup->fileSize[i]);
        PRINT("bufferSize: %d\n", bufferSize);
        PRINT("numBuffers: %d\n",
        srcBuffListArray[i][setup->numberOfBuffers[i]-1]->numBuffers);
        */
        if (setup->fileSize[i] % bufferSize)
        {
/*if the flatBufferSize does not fit evenly into list, then
 * update the last flatBufferSize to be the remainder*/
#ifdef DEBUG_STATEFUL2
            PRINT("inputListSize %d\n", setup->inputListSize);
            PRINT(
                "Setting last Buffer(%d) from length %d to length %d\n",
                srcBuffListArray[i][setup->numberOfBuffers[i] - 1]->numBuffers -
                    1,
                srcBuffListArray[i][setup->numberOfBuffers[i] - 1]
                    ->pBuffers[srcBuffListArray[i]
                                               [setup->numberOfBuffers[i] - 1]
                                                   ->numBuffers -
                               1]
                    .dataLenInBytes,
                setup->fileSize[i] % bufferSize);
#endif
            /*the last buffer might be a remainder so we adjust the size*/
            srcBuffListArray[i][setup->numberOfBuffers[i] - 1]
                ->pBuffers[srcBuffListArray[i][setup->numberOfBuffers[i] - 1]
                               ->numBuffers -
                           1]
                .dataLenInBytes = setup->fileSize[i] % bufferSize;
        }
    }
#endif
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
        for (i = 0; i < setup->sessions; i++)
        {
            inflate_init(&stream, setup->setupData.sessState);
            /* call the compress api */
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (setup->corpus == RANDOM)
                {
                    populateRandomCorpus(setup->numberOfBuffers[i],
                                         srcBuffListArray[i],
                                         cmpBuffListArray[i]);
                }
                if (j == (setup->numberOfBuffers[i] - 1))
                {
                    setup->requestOps.flushFlag = CPA_DC_FLUSH_FINAL;
                    /*PRINT("bufferList %d of file %d, setting flush final\n",
                            j, i);*/
                }
                else
                {
                    setup->requestOps.flushFlag = CPA_DC_FLUSH_SYNC;
                }
                /*for(k=0;k<cmpBuffListArray[i][j]->numBuffers;k++)
                {
                    PRINT("cmp pbuff[%d]  buffer size %d \n", k,
                cmpBuffListArray[i][j]->pBuffers[k].dataLenInBytes);
                }*/
                status = submitList(setup,
                                    srcBuffListArray[i][j],
                                    dstBuffListArray[i][j],
                                    cmpBuffListArray[i][j],
                                    cmpResult[i][j],
                                    pSessionHandle,
                                    setup->requestOps.flushFlag,
                                    &stream);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("error submitting bufferList %d, %d\n", i, j);
                    break;
                }
            } /* End of number of buffers Loop */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Data Compression Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
                break;
            }
            inflate_destroy(&stream);
        } /* End of number of Files Loop*/
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Data Compression Failed %d\n\n", status);
            perfData->threadReturnStatus = CPA_STATUS_FAIL;
            break;
        }
    } /* End of compression Loops */
#ifndef USE_ZLIB
    /* check if synchronous flag is set
     * if set, invoke the callback API
     */
    if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
    {
        /* invoke the Compression Callback only */
        dcPerformStatefulCallback2(setup->performanceStats, status);
    }

    /* Stateful compression only supports a single request in flight
     * for each session, so wait for the semaphore to post on the
     * submitted request
     */
    status = waitForSemaphore(setup->performanceStats);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Wait for Semaphore Failed %d\n\n", status);
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return CPA_STATUS_FAIL;
    }
#endif
    /* Close the DC Session */
    status = cpaDcRemoveSession(setup->dcInstanceHandle, pSessionHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to remove session\n");
        perfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    qaeMemFreeNUMA((void **)&pSessionHandle);
    dcSampleFreeStatefulContextBuffer2(pContextBuffer);
    return status;
}

static CpaStatus compressCorpusStateful2(compression_test_params_t *setup,
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
#ifdef LATENCY_CODE
    Cpa32U submissions = 0;
    perf_cycles_t *request_submit_start = NULL;
    perf_cycles_t *request_respnse_time = NULL;
    const Cpa32U request_mem_sz = sizeof(perf_cycles_t) * MAX_LATENCY_COUNT;
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
        PRINT_ERR(
            "Failed to allocate memory for submission and response times\n");
        return CPA_STATUS_FAIL;
    }
    memset(request_submit_start, 0, request_mem_sz);
    memset(request_respnse_time, 0, request_mem_sz);

    perfData->nextCount =
        (setup->numberOfBuffers[0] * setup->numLoops) / MAX_LATENCY_COUNT;
    perfData->countIncrement =
        (setup->numberOfBuffers[0] * setup->numLoops) / MAX_LATENCY_COUNT;
    perfData->latencyCount = 0;
    perfData->response_times = request_respnse_time;
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

    status = dcSampleCreateStatefulContextBuffer2(
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
        dcCbFn = deCompressStatefulCallback2;
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
        dcSampleFreeStatefulContextBuffer2(pContextBuffer);
        return CPA_STATUS_FAIL;
    }
    /* calculate the number of buffers */
    for (i = 0; i < setup->sessions; i++)
    {
        numBuffs += setup->numberOfBuffers[i];
    }
    perfData->numOperations = numBuffs;

    /* Completion used in callback */
    sampleCodeSemaphoreInit(&perfData->comp, 0);
    /* compression API will be called for each buffer list
     * in the corpus File
     */
    for (i = 0; i < setup->sessions; i++)
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
                if (submissions + 1 == perfData->nextCount)
                {
                    request_submit_start[perfData->latencyCount] =
                        sampleCodeTimestamp();
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
            perfData->latencyCount++;
            submissions++;
#endif
            if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
            {
                /* invoke the Compression Callback only */
                deCompressStatefulCallback2(callbackTag[i][j], status);
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
    for (i = 0; i < perfData->latencyCount; i++)
    {
        perfData->aveLatency +=
            perfData->response_times[i] - request_submit_start[i];
    }
    if (perfData->latencyCount > 0)
    {
        do_div(perfData->aveLatency, perfData->latencyCount);
    }
    qaeMemFree((void **)&request_respnse_time);
    qaeMemFree((void **)&request_submit_start);
#endif
    dcSampleFreeStatefulContextBuffer2(pContextBuffer);
    return status;
}
static CpaStatus performDeCompressStateful2(compression_test_params_t *setup,
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
#ifdef LATENCY_CODE
    Cpa32U submissions = 0;
    perf_cycles_t *request_submit_start = NULL;
    perf_cycles_t *request_respnse_time = NULL;
    const Cpa32U request_mem_sz = sizeof(perf_cycles_t) * MAX_LATENCY_COUNT;
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
        PRINT_ERR(
            "Failed to allocate memory for submission and response times\n");
        return CPA_STATUS_FAIL;
    }
    memset(request_submit_start, 0, request_mem_sz);
    memset(request_respnse_time, 0, request_mem_sz);

    perfData->nextCount =
        (setup->numberOfBuffers[0] * setup->numLoops) / MAX_LATENCY_COUNT;
    perfData->countIncrement =
        (setup->numberOfBuffers[0] * setup->numLoops) / MAX_LATENCY_COUNT;
    perfData->latencyCount = 0;
    perfData->response_times = request_respnse_time;
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
        qaeMemAllocNUMA(setup->sessions * sizeof(dc_callbacktag_t **),
                        nodeId,
                        BYTE_ALIGNMENT_64);

    if (NULL == dcCallbackTag)
    {
        PRINT("Unable to allocate memory for callback tags\n");
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < setup->sessions; i++)
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
    for (i = 0; i < setup->sessions; i++)
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
    if (!useZlib_g)
    {
        status = compressCorpusStateful2(setup,
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
        for (i = 0; i < setup->sessions; i++)
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
                    PRINT("i: %d, j: %d, srcLen: %d, destLen: %d \n",
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

    dcSetBytesProducedAndConsumed2(cmpResult, setup->performanceStats, setup);

    /* calculate the number of buffers */
    for (i = 0; i < setup->sessions; i++)
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

    status = dcSampleCreateStatefulContextBuffer2(
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
        for (i = 0; i < setup->sessions; i++)
        {
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
                do
                {
#ifdef LATENCY_CODE
                    if (submissions + 1 == perfData->nextCount)
                    {
                        request_submit_start[perfData->latencyCount] =
                            sampleCodeTimestamp();
                    }
#endif
                    status = cpaDcDecompressData2(setup->dcInstanceHandle,
                                                  pSessionHandle,
                                                  dstBuffListArray[i][j],
                                                  cmpBuffListArray[i][j],
                                                  &setup->requestOps,
                                                  dcmpResult[i][j],
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

                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR(" Data De-Compression Failed\n");
                    perfData->threadReturnStatus = CPA_STATUS_FAIL;
                    break;
                }
#ifdef LATENCY_CODE
                perfData->latencyCount++;
                submissions++;
#endif
                /* check if synchronous flag is set
                 * if set, invoke the callback API
                 */
                if (CPA_SAMPLE_SYNCHRONOUS == setup->syncFlag)
                {
                    /* invoke the decompression Callback only */
                    dcPerformStatefulCallback2(perfData, status);
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
                if (dcmpResult[i][j]->produced >
                    setup->bufferSize * EXTRA_BUFFER * expansionFactor_g)
                {
                    PRINT(
                        "warning HW output is bigger than allocated memory\n");
                }
                /* Stateful decompression requires that the input buffer
                 * contains an even number of bytes for every request except the
                 * last, i.e. the last where CpaDcFlush is CPA_DC_FLUSH_FINAL
                 * Submitting a request with an odd number of bytes will result
                 * in a partial consumption of the input data.
                 * If partial consumption occurs, submit the remaining data as
                 * part of the
                 * next request.
                 */
                if (CPA_DC_FLUSH_FINAL != setup->requestOps.flushFlag &&
                    dcmpResult[i][j]->consumed <
                        dstBuffListArray[i][j]->pBuffers->dataLenInBytes)
                {

                    remainder =
                        dstBuffListArray[i][j]->pBuffers->dataLenInBytes -
                        dcmpResult[i][j]->consumed;
                    memcpy(
                        tempFB.pData,
                        dstBuffListArray[i][j + 1]->pBuffers->pData,
                        dstBuffListArray[i][j + 1]->pBuffers->dataLenInBytes);

                    tempFB.dataLenInBytes =
                        dstBuffListArray[i][j + 1]->pBuffers->dataLenInBytes;

                    /* Copy the remaining data to the start of the next request
                     */
                    memcpy(dstBuffListArray[i][j + 1]->pBuffers->pData,
                           &(dstBuffListArray[i][j]
                                 ->pBuffers->pData[dcmpResult[i][j]->consumed]),
                           remainder);
                    /* Copy the original data of the next request and append to
                     * the remaining data */
                    memcpy((dstBuffListArray[i][j + 1]->pBuffers->pData +
                            remainder),
                           tempFB.pData,
                           tempFB.dataLenInBytes);
                    /* Update the next request with the correct length */
                    dstBuffListArray[i][j + 1]->pBuffers->dataLenInBytes =
                        remainder + tempFB.dataLenInBytes;
                    /* Update the current request with the correct length */
                    dstBuffListArray[i][j]->pBuffers->dataLenInBytes =
                        dcmpResult[i][j]->consumed;
                }
            } /* End of number of buffers Loop */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Data De-Compression Failed %d\n\n", status);
                perfData->threadReturnStatus = CPA_STATUS_FAIL;
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
    freeCbTags(dcCallbackTag, setup->sessions, setup);
    qaeMemFreeNUMA((void **)&pSessionHandle);
#ifdef LATENCY_CODE
    for (i = 0; i < perfData->latencyCount; i++)
    {
        perfData->aveLatency +=
            perfData->response_times[i] - request_submit_start[i];
    }
    if (perfData->latencyCount > 0)
    {
        do_div(perfData->aveLatency, perfData->latencyCount);
    }
    qaeMemFree((void **)&request_respnse_time);
    qaeMemFree((void **)&request_submit_start);
#endif
    return status;
}

CpaStatus dcPerformStateful2(compression_test_params_t *setup)
{
    /* start of local variable declarations */
    Cpa32U i = 0;
    Cpa32U j = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U nodeId = 0;
    /* Initialize to 0 and set later to size as declared in setup */
    Cpa32U totalBuffs = 0;
    Cpa32U bufferSize = 0;
    CpaDcRqResults ***cmpResult = NULL;
    CpaDcRqResults ***dcmpResult = NULL;
    /*Cpa32U amountOfFullLists = 0;*/
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
    Cpa32U numberOfFlatBuffsInLastList = 0;
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
    srcBuffListArray = qaeMemAlloc(setup->sessions * sizeof(CpaBufferList *));
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
    dstBuffListArray = qaeMemAlloc((setup->sessions * sizeof(CpaBufferList *)));
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
    cmpBuffListArray = qaeMemAlloc((setup->sessions * sizeof(CpaBufferList *)));
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
    for (i = 0; i < setup->sessions; i++)
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
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
            return CPA_STATUS_FAIL;
        }
        dstBuffListArray[i] = qaeMemAlloc(
            (setup->numberOfBuffers[i] * (sizeof(CpaBufferList *))));
        /* Check for NULL */
        if (NULL == dstBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for File\n ");
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
            return CPA_STATUS_FAIL;
        }
        cmpBuffListArray[i] = qaeMemAlloc(
            (setup->numberOfBuffers[i] * (sizeof(CpaBufferList *))));
        /* Check for NULL */
        if (NULL == cmpBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate Memory for File\n ");
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
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
    for (i = 0; i < setup->sessions; i++)
    {
        status = createBuffers2(setup->inputListSize,
                                bufferSize,
                                setup->numberOfBuffers[i],
                                srcBuffListArray[i],
                                nodeId);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Create Buffers for source List array\n");
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
            return CPA_STATUS_FAIL;
        }
        /*update the numberOfBuffers to be used based on the fileSize,
         * this means we might have allocate many buffers but only use a
         * fraction of them if the file size is less that the buffersize*/

        /*set output size to be same as input, later on we shall use the
         * bufferList numBuffers member  to limit the output size*/

        status = createBuffers2(setup->outputListSize,
                                bufferSize,
                                setup->numberOfBuffers[i]
                                /*setup->numberOfBuffers[i]*/
                                /*setup->numberOfOutputLists[i]*/,
                                dstBuffListArray[i],
                                nodeId);
#ifdef DEBUG_STATEFUL2
        PRINT("DestArrayList 0 addr %08x, value %08x\n",
              dstBuffListArray[0],
              *dstBuffListArray[0]);
#endif
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Create Buffers for destination List array\n");
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
            return CPA_STATUS_FAIL;
        }
        /* When Decompression, the FW expects that the Buffer size
         * to be greater than the source buffer, so allocate double the
         * size of the source buffer
         */
        status = createBuffers2(setup->inputListSize,
                                bufferSize * 5,
                                setup->numberOfBuffers[i],
                                cmpBuffListArray[i],
                                nodeId);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Create Buffers for compare List array\n");
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
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
    cmpResult = qaeMemAlloc((setup->sessions * sizeof(CpaDcRqResults *)));
    if (NULL == cmpResult)
    {
        PRINT_ERR("unable to allocate memory for Results\n");
        freeBuffers2(srcBuffListArray,
                     setup->numberOfBuffers,
                     setup->inputListSize,
                     i,
                     setup->bufferSize);
        freeBuffers2(dstBuffListArray,
                     setup->numberOfBuffers,
                     setup->outputListSize,
                     i,
                     setup->bufferSize);
        freeBuffers2(cmpBuffListArray,
                     setup->numberOfBuffers,
                     setup->inputListSize * 2,
                     i,
                     setup->inputListSize * 2);
        return CPA_STATUS_FAIL;
    }
    /* Allocate Memory for the results structure */
    dcmpResult = qaeMemAlloc((setup->sessions * sizeof(CpaDcRqResults *)));
    if (NULL == dcmpResult)
    {
        PRINT_ERR("unable to allocate memory for Results\n");
        qaeMemFree((void **)&cmpResult);
        freeBuffers2(srcBuffListArray,
                     setup->numberOfBuffers,
                     setup->inputListSize,
                     i,
                     setup->bufferSize);
        freeBuffers2(dstBuffListArray,
                     setup->numberOfBuffers,
                     setup->outputListSize,
                     i,
                     setup->bufferSize);
        freeBuffers2(cmpBuffListArray,
                     setup->numberOfBuffers,
                     setup->inputListSize * 2,
                     i,
                     setup->inputListSize * 2);
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < setup->sessions; i++)
    {
        numberOfFlatBuffsInLastList =
            roundUp(setup->fileSize[i], bufferSize) -
            ((roundUp(setup->fileSize[i], setup->inputListSize) - 1) *
             roundUp(setup->inputListSize, bufferSize));
        srcBuffListArray[i][setup->numberOfBuffers[i] - 1]->numBuffers =
            numberOfFlatBuffsInLastList;

#ifdef DEBUG_STATEFUL2
        PRINT("%d - %d * %d = numberOfFlatBuffsInLastList\n",
              roundUp(setup->fileSize[i], bufferSize),
              roundUp(setup->fileSize[i], setup->inputListSize) - 1,
              roundUp(setup->inputListSize, bufferSize));
        PRINT("File %d has %d lists\n", i, setup->numberOfBuffers[i]);
        PRINT("numberOfBuffersInLists %d\n",
              roundUp(setup->inputListSize, bufferSize));
        PRINT("numberOfFlatBuffsInLastList %d\n", numberOfFlatBuffsInLastList);

        PRINT("fileSize[%d]: %d\n", i, setup->fileSize[i]);
        PRINT("bufferSize: %d\n", bufferSize);
        PRINT("numBuffers: %d\n",
              srcBuffListArray[i][setup->numberOfBuffers[i] - 1]->numBuffers);
#endif
        if (setup->fileSize[i] % bufferSize)
        {
/*if the flatBufferSize does not fit evenly into list, then
 * update the last flatBufferSize to be the remainder*/
#ifdef DEBUG_STATEFUL2
            PRINT("setup inputListSize %d\n", setup->inputListSize);
            PRINT(
                "Setting last Buffer(%d) from length %d to length %d\n",
                srcBuffListArray[i][setup->numberOfBuffers[i] - 1]->numBuffers -
                    1,
                srcBuffListArray[i][setup->numberOfBuffers[i] - 1]
                    ->pBuffers[srcBuffListArray[i]
                                               [setup->numberOfBuffers[i] - 1]
                                                   ->numBuffers -
                               1]
                    .dataLenInBytes,
                setup->fileSize[i] % bufferSize);
#endif
            /*the last buffer might be a remainder so we adjust the size*/
            srcBuffListArray[i][setup->numberOfBuffers[i] - 1]
                ->pBuffers[srcBuffListArray[i][setup->numberOfBuffers[i] - 1]
                               ->numBuffers -
                           1]
                .dataLenInBytes = setup->fileSize[i] % bufferSize;
        }
    }


    /* allocate the results structure for each buffer in the
     * corpus file
     */
    for (i = 0; i < setup->sessions; i++)
    {
        dcmpResult[i] =
            qaeMemAlloc(setup->numberOfBuffers[i] * sizeof(CpaDcRqResults *));
        if (NULL == dcmpResult[i])
        {
            PRINT_ERR("unable to allocate memory for"
                      "Results structure for each buffer\n");
            freeResults(dcmpResult, i, setup);
            qaeMemFree((void **)&cmpResult);
            freeBuffers2(srcBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(dstBuffListArray,
                         setup->numberOfBuffers,
                         setup->outputListSize,
                         i,
                         setup->bufferSize);
            freeBuffers2(cmpBuffListArray,
                         setup->numberOfBuffers,
                         setup->inputListSize * 2,
                         i,
                         setup->inputListSize * 2);
            return CPA_STATUS_FAIL;
        }
    }

    for (i = 0; i < setup->sessions; i++)
    {
        cmpResult[i] =
            qaeMemAlloc(setup->numberOfBuffers[i] * sizeof(CpaDcRqResults *));
        if (NULL == cmpResult[i])
        {
            PRINT_ERR("unable to allocate memory for"
                      "Results structure for each buffer\n");
            /*freeResults(cmpResult , i,setup);
            freeResults(dcmpResult , setup->sessions,setup);
            freeBuffers2(srcBuffListArray,
            setup->numberOfBuffers,setup->inputListSize ,i, setup);
            freeBuffers2(dstBuffListArray,
            setup->numberOfBuffers,setup->outputListSize ,i, setup);
            freeBuffers2(cmpBuffListArray,
            setup->numberOfBuffers,setup->inputListSize ,i, setup);
            return CPA_STATUS_FAIL;*/
            status = CPA_STATUS_FAIL;
            goto cleanup_memory;
        }
    }

    for (i = 0; i < setup->sessions; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            cmpResult[i][j] = qaeMemAlloc(sizeof(CpaDcRqResults));
            if (NULL == cmpResult[i][j])
            {
                /*freeResults(cmpResult,setup->sessions,setup);
                freeResults(dcmpResult , setup->sessions,setup);
                freeBuffers2(srcBuffListArray,
                setup->numberOfBuffers,setup->inputListSize ,i, setup);
                freeBuffers2(dstBuffListArray,
                setup->numberOfBuffers,setup->outputListSize ,i, setup);
                freeBuffers2(cmpBuffListArray,
                setup->numberOfBuffers,setup->inputListSize ,i, setup);
                return CPA_STATUS_FAIL;*/
                status = CPA_STATUS_FAIL;
                goto cleanup_memory;
            }
            dcmpResult[i][j] = qaeMemAlloc(sizeof(CpaDcRqResults));
            if (NULL == dcmpResult[i][j])
            {
                /*freeResults(cmpResult,setup->sessions,setup);
                freeResults(dcmpResult , setup->sessions,setup);
                freeBuffers2(srcBuffListArray,
                setup->numberOfBuffers,setup->inputListSize ,i, setup);
                freeBuffers2(dstBuffListArray,
                setup->numberOfBuffers,setup->outputListSize ,i, setup);
                freeBuffers2(cmpBuffListArray,
                setup->numberOfBuffers,setup->inputListSize ,i, setup);
                return CPA_STATUS_FAIL;*/
                status = CPA_STATUS_FAIL;
                goto cleanup_memory;
            }
        }
    }
    /* get the Meta Size for each buffer List and
     * allocate Private Meta Data
     */
    for (i = 0; i < setup->sessions; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            /* Get the Meta size for each file in buffers list */
            /*PRINT("%d:: SrcList Meta numBuffers %d\n",
                    __LINE__, srcBuffListArray[i][j]->numBuffers);*/
            status =
                cpaDcBufferListGetMetaSize(setup->dcInstanceHandle,
                                           srcBuffListArray[i][j]->numBuffers,
                                           &metaSize);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to get Meta Size\n");
                goto cleanup_memory;
            }
#ifdef DEBUG_STATEFUL2
            PRINT("output MetaSize %d\n", metaSize);
#endif
            srcBuffListArray[i][j]->pPrivateMetaData =
                qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
            if (NULL == srcBuffListArray[i][j]->pPrivateMetaData)
            {
                PRINT_ERR(" Unable to allocate pPrivateMetaData\n");
                status = CPA_STATUS_FAIL;
                goto cleanup_memory;
            }
            cmpBuffListArray[i][j]->pPrivateMetaData =
                qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
            if (NULL == cmpBuffListArray[i][j]->pPrivateMetaData)
            {
                PRINT_ERR(" Unable to allocate pPrivateMetaData\n");
                status = CPA_STATUS_FAIL;
                goto cleanup_memory;
            }
        }
        for (j = 0;
             j < setup->numberOfBuffers[i] /*setup->numberOfOutputLists[i]*/;
             j++)
        {
            status =
                cpaDcBufferListGetMetaSize(setup->dcInstanceHandle,
                                           dstBuffListArray[i][j]->numBuffers,
                                           &metaSize);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to get Meta Size\n");
                goto cleanup_memory;
            }
#ifdef DEBUG_STATEFUL2
            PRINT("output MetaSize %d\n", metaSize);
#endif
            dstBuffListArray[i][j]->pPrivateMetaData =
                qaeMemAllocNUMA(metaSize, nodeId, BYTE_ALIGNMENT_64);
            if (dstBuffListArray[i][j]->pPrivateMetaData == NULL)
            {
                PRINT_ERR(" Unable to allocate pPrivateMetaData\n");
                status = CPA_STATUS_FAIL;
                goto cleanup_memory;
            }
        }
    }

#if DC_API_VERSION_LESS_THAN(1, 6)
#endif

    if (CPA_DC_DIR_COMPRESS == dcSessDir)
    {
        status = performCompressStateful2(setup,
                                          srcBuffListArray,
                                          dstBuffListArray,
                                          cmpBuffListArray,
                                          cmpResult,
                                          dcPerformStatefulCallback2);
        dcSetBytesProducedAndConsumed2(
            cmpResult, setup->performanceStats, setup);
    }
    if (CPA_DC_DIR_DECOMPRESS == dcSessDir)
    {
        status = performDeCompressStateful2(setup,
                                            srcBuffListArray,
                                            dstBuffListArray,
                                            cmpBuffListArray,
                                            cmpResult,
                                            dcmpResult,
                                            dcPerformStatefulCallback2);
    }
    /*clean up the callback semaphore*/
    sampleCodeSemaphoreDestroy(&perfData->comp);
/* Free all the results structures */
cleanup_memory:
    freeResults(cmpResult, setup->sessions, setup);
    freeResults(dcmpResult, setup->sessions, setup);
/* Free all the Buffer Lists */
#ifdef DEBUG_STATEFUL2
    PRINT("%d SrcList[0] addr %08x, value: %08x\n",
          __LINE__,
          srcBuffListArray[0],
          *srcBuffListArray[0]);
    PRINT("%d SrcList[0][0] addr %08x\n", __LINE__, srcBuffListArray[0][0]);
    PRINT("Cleaning scrBuffListArray\n");

    for (i = 0; i < setup->sessions; i++)
    {
        PRINT(" numInputLists: %d\n", setup->numberOfBuffers[i]);
    }
#endif
    freeBuffers2(srcBuffListArray,
                 setup->numberOfBuffers,
                 setup->inputListSize,
                 setup->sessions,
                 setup->bufferSize);
#ifdef DEBUG_STATEFUL2
    PRINT("%d DestList[0] addr %08x, value: %08x\n",
          __LINE__,
          dstBuffListArray[0],
          *dstBuffListArray[0]);
    PRINT("%d DestList[0][0] addr %08x\n", __LINE__, dstBuffListArray[0][0]);
    PRINT("Cleaning dstBuffListArray\n");

    for (i = 0; i < setup->sessions; i++)
    {
        PRINT(" numOutputLists: %d\n", setup->numberOfOutputLists[i]);
    }
#endif
    freeBuffers2(dstBuffListArray,
                 setup->numberOfOutputLists,
                 setup->outputListSize,
                 setup->sessions,
                 setup->bufferSize);
#ifdef DEBUG_STATEFUL2
    // not used at the moment
    PRINT("Cleaning cmpBuffListArray\n");
#endif
    freeBuffers2(cmpBuffListArray,
                 setup->numberOfBuffers,
                 setup->inputListSize * 2,
                 setup->sessions,
                 setup->inputListSize * 2);

    return status;
}

CpaStatus calculateRequireBuffers2(compression_test_params_t *dcSetup)
{
    Cpa32U numberOfListsPerFile = 0, i = 0;
    Cpa32U numberOfListsPerOutputFile = 0;

    dcSetup->numberOfBuffers = qaeMemAlloc(dcSetup->sessions * sizeof(Cpa32U));
    if (NULL == dcSetup->numberOfBuffers)
    {
        PRINT("Could not allocate memory for dcSetup numberOfBuffers array");
        return CPA_STATUS_FAIL;
    }
    dcSetup->numberOfOutputLists =
        qaeMemAlloc(dcSetup->sessions * sizeof(Cpa32U));
    if (NULL == dcSetup->numberOfOutputLists)
    {
        PRINT("Could not allocate memory for dcSetup numberOfBuffers array");
        qaeMemFree((void **)&dcSetup->numberOfBuffers);
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < dcSetup->sessions; i++)
    {
        /*numberOfLists  = fileSize/numLists +1 if there is a remainder*/
        numberOfListsPerFile = dcSetup->fileSize[i] / dcSetup->inputListSize;
        if (dcSetup->fileSize[i] % dcSetup->inputListSize)
        {
            numberOfListsPerFile++;
        }
        numberOfListsPerOutputFile =
            dcSetup->fileSize[i] / dcSetup->outputListSize;
        if (dcSetup->fileSize[i] % dcSetup->inputListSize)
        {
            numberOfListsPerOutputFile++;
        }


        dcSetup->numberOfBuffers[i] = numberOfListsPerFile;
        dcSetup->numberOfOutputLists[i] = numberOfListsPerOutputFile;
    }
    return CPA_STATUS_SUCCESS;
}
/*********** Call Back Function **************/
void dcPerformanceStateful2(single_thread_test_data_t *testSetup)
{
    compression_test_params_t dcSetup, *tmpSetup = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;
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
    dcSetup.bufferSize = tmpSetup->flatBuffSize;
    dcSetup.flatBuffSize = tmpSetup->flatBuffSize;
    dcSetup.inputListSize = tmpSetup->inputListSize;
    dcSetup.outputListSize = tmpSetup->outputListSize;
    dcSetup.sessions = tmpSetup->sessions;
    for (i = 0; i < dcSetup.sessions; i++)
    {
        dcSetup.fileSize[i] = tmpSetup->fileSize[i];
    }


    /*give our thread a unique memory location to store performance stats*/
    dcSetup.performanceStats = testSetup->performanceStats;
    testSetup->performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;

    status = calculateRequireBuffers2(&dcSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("Error calculating required buffers\n");
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
        qaeMemFree((void **)&dcSetup.numberOfOutputLists);
        return;
    }
    if (0 == numInstances)
    {
        PRINT_ERR(" DC Instances are not present\n");
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        qaeMemFree((void **)&dcSetup.numberOfOutputLists);
        sampleCodeThreadExit();
    }
    instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == instances)
    {
        PRINT_ERR("Unable to allocate Memory for Instances\n");
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        qaeMemFree((void **)&dcSetup.numberOfOutputLists);
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
        qaeMemFree((void **)&dcSetup.numberOfOutputLists);
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
        qaeMemFree((void **)&dcSetup.numberOfOutputLists);
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
        qaeMemFree((void **)&dcSetup.numberOfOutputLists);
        sampleCodeThreadExit();
    }


    /*launch function that does all the work*/
    status = dcPerformStateful2(&dcSetup);
    if (CPA_STATUS_SUCCESS != status)
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
    qaeMemFree((void **)&dcSetup.numberOfOutputLists);
    qaeMemFree((void **)&instances);


    sampleCodeThreadComplete(testSetup->threadID);
}

CpaStatus setupDcStatefulTest2(CpaDcCompType algorithm,
                               CpaDcSessionDir direction,
                               CpaDcCompLvl compLevel,
                               CpaDcHuffType huffmanType,
                               Cpa32U flatBufferSize,
                               Cpa32U inputListSize,
                               Cpa32U outputListSize,
                               Cpa32U fileSize,
                               Cpa32U sessions,
                               corpus_type_t corpusType,
                               synchronous_flag_t syncFlag,
                               Cpa32U numLoops)
{

    compression_test_params_t *dcSetup = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;


    if (direction != CPA_DC_DIR_COMPRESS)
    {
        PRINT_ERR("decompress support is not yet supported\n");
        return CPA_STATUS_FAIL;
    }
    /* Initialize the Performance device */
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }
    if (sessions > 1)
    {
        PRINT_ERR("Only 1 session supported for now\n");
        freeCorpus();
        return CPA_STATUS_FAIL;
    }

    /*Start DC Services */
    status = startDcServices(DYNAMIC_BUFFER_AREA, TEMP_NUM_BUFFS);
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
        (performance_func_t)dcPerformanceStateful2;

    /* update the setup_g with buffersize */
    testSetupData_g[testTypeCount_g].packetSize = inputListSize;
    /* Data compression setup data */
    dcSetup->setupData.compLevel = compLevel;
    dcSetup->setupData.compType = algorithm;
    /* always Set the Session direction to COMBINED
     * but, the time stamps will be taken as per the
     * session direction given by the User
     */
    dcSetup->setupData.sessDirection = CPA_DC_DIR_COMBINED;
    dcSetup->setupData.checksum = checksum2_g;
    dcSetup->setupData.huffType = huffmanType_g;
    dcSetup->setupData.sessState = CPA_DC_STATEFUL;
#if DC_API_VERSION_LESS_THAN(1, 6)
    dcSetup->setupData.fileType = CPA_DC_FT_ASCII;
    dcSetup->setupData.deflateWindowSize = DEFAULT_COMPRESSION_WINDOW_SIZE;
#endif
    dcSetup->corpus = corpusType;
    dcSetup->bufferSize = flatBufferSize;
    dcSetup->flatBuffSize = flatBufferSize;
    dcSetup->inputListSize = inputListSize;
    dcSetup->outputListSize = outputListSize;
    dcSetup->fileSize[0] = fileSize;
    dcSetup->sessions = sessions;
    dcSetup->dcSessDir = direction;
    dcSetup->setupData.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;


    dcSetup->syncFlag = syncFlag;
    dcSetup->numLoops = numLoops;

    return status;
}
EXPORT_SYMBOL(setupDcStatefulTest2);

CpaStatus memAllocTest(Cpa32U limit)
{
    Cpa32U i = 0;
    Cpa32S j = 0;
    Cpa8U **ptrArray = NULL;

    ptrArray = qaeMemAllocNUMA(sizeof(Cpa8U *) * limit, 0, BYTE_ALIGNMENT_64);
    if (ptrArray == NULL)
    {
        PRINT("alloc ptrArray failed\n");
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < limit; i++)
    {
        ptrArray[i] = qaeMemAllocNUMA(4096, 0, BYTE_ALIGNMENT_64);
        if (ptrArray[i] == NULL)
        {
            PRINT("alloc failed at %d\n", i);
            qaeMemFreeNUMA((void **)&ptrArray[i]);
            break;
        }
        else
            PRINT("%d\n", i);
    }
    for (j = (Cpa32S)i; j >= 0; j--)
    {
        qaeMemFreeNUMA((void **)&ptrArray[j]);
    }

    qaeMemFreeNUMA((void **)&ptrArray);

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(memAllocTest);
