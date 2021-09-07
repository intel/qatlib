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
 * @file cpa_sample_code_dc_sgl.c
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

#define DYNAMIC_BUFFER_AREA_128K (131072)

void dcCallback(void *pCallbackTag, CpaStatus status)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DC Function Failed \n");
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
        /* generate end of the cycle stamp */
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
        sampleCodeSemaphorePost(&pPerfData->comp);
    }
}

CpaStatus doCompress(compression_test_params_t *pSetup,
                     CpaBufferList *pSrcSGL,
                     CpaBufferList *pDstSGL,
                     CpaDcSessionHandle *pSessionHandle,
                     CpaDcRqResults *pResults)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U perfLoops = 0;
    Cpa32U loopsToExecute = pSetup->numLoops;
    perf_data_t *pPerfData = pSetup->performanceStats;
    /* Set Flush flag to full for stateless requests */
    pSetup->requestOps.flushFlag = CPA_DC_FLUSH_FULL;

    if (CPA_DC_DIR_DECOMPRESS == pSetup->dcSessDir ||
        CPA_DC_DIR_COMBINED == pSetup->dcSessDir)
    {
        loopsToExecute = SINGLE_LOOP;
    }
    pPerfData->responses = 0;
    pPerfData->numOperations = loopsToExecute;
    pPerfData->numLoops = pSetup->numLoops;
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&pPerfData->comp, 0);
    sampleCodeBarrier();

    pPerfData->startCyclesTimestamp = sampleCodeTimestamp();
    for (perfLoops = 0; perfLoops < loopsToExecute; perfLoops++)
    {

        do
        {
            status = cpaDcCompressData2(pSetup->dcInstanceHandle,
                                        pSessionHandle,
                                        pSrcSGL,
                                        pDstSGL,
                                        &pSetup->requestOps,
                                        pResults,
                                        pPerfData);
            if (CPA_STATUS_RETRY == status)
            {
                pSetup->performanceStats->retries++;
                if (RETRY_LIMIT == pSetup->performanceStats->retries)
                {
                    pSetup->performanceStats->retries = 0;
                    AVOID_SOFTLOCKUP;
                }
            }
        } while (CPA_STATUS_RETRY == status);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Compression Failed with status %d\n\n", status);
            pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
            return CPA_STATUS_FAIL;
        }
        if (CPA_SAMPLE_SYNCHRONOUS == pSetup->syncFlag)
        {
            dcCallback(pPerfData, status);
        }
        if (CPA_STATUS_FAIL == pPerfData->threadReturnStatus)
        {
            return CPA_STATUS_FAIL;
        }

    } /* End loopsToExecute */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForSemaphore(pPerfData);
    }
    return status;
}

CpaStatus doDecompress(compression_test_params_t *pSetup,
                       CpaBufferList *pSrcSGL,
                       CpaBufferList *pDstSGL,
                       CpaDcSessionHandle *pSessionHandle,
                       CpaDcRqResults *pResults)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U perfLoops = 0;
    perf_data_t *pPerfData = pSetup->performanceStats;
    /* Set Flush flag to full for stateless requests */
    pSetup->requestOps.flushFlag = CPA_DC_FLUSH_FULL;
    pPerfData->numOperations = pSetup->numLoops;
    pPerfData->responses = 0;
    /* Completion used in callback */
    pPerfData->numLoops = pSetup->numLoops;
    sampleCodeSemaphoreInit(&pPerfData->comp, 0);
    sampleCodeBarrier();

    pPerfData->startCyclesTimestamp = sampleCodeTimestamp();
    for (perfLoops = 0; perfLoops < pSetup->numLoops; perfLoops++)
    {
        do
        {
            status = cpaDcDecompressData2(pSetup->dcInstanceHandle,
                                          pSessionHandle,
                                          pSrcSGL,
                                          pDstSGL,
                                          &pSetup->requestOps,
                                          pResults,
                                          pPerfData);
            if (CPA_STATUS_RETRY == status)
            {
                pSetup->performanceStats->retries++;
                if (RETRY_LIMIT == pSetup->performanceStats->retries)
                {
                    pSetup->performanceStats->retries = 0;
                    AVOID_SOFTLOCKUP;
                }
            }
        } while (CPA_STATUS_RETRY == status);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Compression Failed with status %d\n\n", status);
            pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
            return CPA_STATUS_FAIL;
        }
        if (CPA_SAMPLE_SYNCHRONOUS == pSetup->syncFlag)
        {
            dcCallback(pPerfData, status);
        }
        if (CPA_STATUS_FAIL == pPerfData->threadReturnStatus)
        {
            return CPA_STATUS_FAIL;
        }

    } /* End loopsToExecute */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForSemaphore(pPerfData);
    }
    sampleCodeSemaphoreDestroy(&pPerfData->comp);
    return status;
}

CpaStatus compareData(CpaBufferList *pSrcSGL,
                      CpaBufferList *pCompareSGL,
                      CpaDcRqResults *pCompressResults,
                      CpaDcRqResults *pDecompressResults)
{
    Cpa32U i = 0, count = 0;
    for (i = 0; i < pSrcSGL->numBuffers; i++)
    {
        count = memcmp(pSrcSGL->pBuffers[i].pData,
                       pCompareSGL->pBuffers[i].pData,
                       pSrcSGL->pBuffers[i].dataLenInBytes);
        if (count != 0)
        {
            PRINT("Data Integrity check Failed\n");
            return CPA_STATUS_FAIL;
        }
    }
    if (pCompressResults->checksum != pDecompressResults->checksum)
    {
        PRINT_ERR("Checksum comparison failed\n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus populateFlatBuffers(compression_test_params_t *setup,
                              CpaBufferList *pSGL)
{
    Cpa8U *filePtr = NULL;
    Cpa8U *data = NULL;
    char *offset = 0;
    Cpa32U i = 0;
    Cpa32U totalLength = 0;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);
    const corpus_file_t *const fileArray = getFilesInCorpus(setup->corpus);

    for (i = 0; i < numFiles; i++)
    {
        totalLength += fileArray[i].corpusBinaryDataLen;
    }
    data = qaeMemAlloc(totalLength);
    {
        if (NULL == data)
        {
            return CPA_STATUS_FAIL;
        }
    }

    offset = (char *)data;
    for (i = 0; i < numFiles; i++)
    {
        filePtr = fileArray[i].corpusBinaryData;
        memcpy((void *)data, (void *)filePtr, fileArray[i].corpusBinaryDataLen);
        offset += fileArray[i].corpusBinaryDataLen;
    }
    offset = (char *)data;

    for (i = 0; i < pSGL->numBuffers; i++)
    {
        memcpy((void *)pSGL->pBuffers[i].pData,
               (void *)offset,
               pSGL->pBuffers[i].dataLenInBytes);
        offset += pSGL->pBuffers[i].dataLenInBytes;
    }

    qaeMemFree((void **)&data);
    return CPA_STATUS_SUCCESS;
}

Cpa32U getTotalBuffers(Cpa32U bufferSize,
                       corpus_type_t corpus,
                       CpaBoolean dropRemainder)
{
    Cpa32U totalBuffers = 0, i = 0;
    Cpa32U totalLength = 0;
    Cpa32U numFiles = getNumFilesInCorpus(corpus);
    const corpus_file_t *const fileArray = getFilesInCorpus(corpus);

    for (i = 0; i < numFiles; i++)
    {
        totalLength += fileArray[i].corpusBinaryDataLen;
    }
    totalBuffers = totalLength / bufferSize;
    if (CPA_FALSE == dropRemainder)
    {
        totalBuffers++;
    }
    return totalBuffers;
}

CpaStatus allocateFlatBuffers(compression_test_params_t *pSetup,
                              CpaBufferList *pSGL)
{
    Cpa32U totalBuffers =
        getTotalBuffers(pSetup->bufferSize, pSetup->corpus, CPA_TRUE);
    pSGL->pBuffers = qaeMemAlloc(sizeof(CpaFlatBuffer) * totalBuffers);
    if (NULL == pSGL->pBuffers)
    {
        PRINT_ERR("Unable to allocate memory for SGL pBuffers");
        return CPA_STATUS_FAIL;
    }
    pSGL->numBuffers = totalBuffers;
    return CPA_STATUS_SUCCESS;
}

void freeFlatBuffers(compression_test_params_t *setup, CpaBufferList *pSGL)
{

    if (NULL != pSGL)
    {
        if (NULL != pSGL->pBuffers)
        {
            qaeMemFree((void **)(&(pSGL->pBuffers)));
        }
    }
}

CpaStatus allocateFlatBufferData(Cpa32U numaNode,
                                 CpaBufferList *pSGL,
                                 Cpa32U bufferSize)
{
    Cpa32U i = 0;

    for (i = 0; i < pSGL->numBuffers; i++)
    {
        pSGL->pBuffers[i].pData =
            qaeMemAllocNUMA(bufferSize, numaNode, BYTE_ALIGNMENT_64);
        if (NULL == pSGL->pBuffers[i].pData)
        {
            return CPA_STATUS_FAIL;
        }
        pSGL->pBuffers[i].dataLenInBytes = bufferSize;
    }

    return CPA_STATUS_SUCCESS;
}

void freeFlatBufferData(CpaBufferList *pSGL)
{
    Cpa32U i = 0;
    for (i = 0; i < pSGL->numBuffers; i++)
    {
        if (NULL != pSGL->pBuffers[i].pData)
        {
            qaeMemFreeNUMA((void **)&(pSGL->pBuffers[i].pData));
        }
    }
}

CpaStatus allocateMetaData(compression_test_params_t *setup,
                           Cpa32U numaNode,
                           CpaBufferList *pSrcSGL,
                           CpaBufferList *pDstSGL,
                           CpaBufferList *pCompareSGL)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U metaSize = 0;

    status = cpaDcBufferListGetMetaSize(
        setup->dcInstanceHandle, pSrcSGL->numBuffers, &metaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get meta size for pSrcSGL\n");
        return CPA_STATUS_FAIL;
    }
    pSrcSGL->pPrivateMetaData =
        qaeMemAllocNUMA(metaSize, numaNode, BYTE_ALIGNMENT_64);
    if (NULL == pSrcSGL->pPrivateMetaData)
    {
        PRINT_ERR("Unable to allocate pPrivateMetaData for pSrcSGL\n");
        return CPA_STATUS_FAIL;
    }
    pDstSGL->pPrivateMetaData =
        qaeMemAllocNUMA(metaSize, numaNode, BYTE_ALIGNMENT_64);
    if (NULL == pDstSGL->pPrivateMetaData)
    {
        PRINT_ERR("Unable to allocate pPrivateMetaData for pDstSGL\n");
        return CPA_STATUS_FAIL;
    }
    pCompareSGL->pPrivateMetaData =
        qaeMemAllocNUMA(metaSize, numaNode, BYTE_ALIGNMENT_64);
    if (NULL == pCompareSGL->pPrivateMetaData)
    {
        PRINT_ERR("Unable to allocate pPrivateMetaData for pCompareSGL\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

void freeMetaData(compression_test_params_t *pSetup,
                  CpaBufferList *pSrcSGL,
                  CpaBufferList *pDstSGL,
                  CpaBufferList *pCompareSGL)
{

    if (NULL != pSrcSGL->pPrivateMetaData)
    {
        qaeMemFreeNUMA((void **)&(pSrcSGL->pPrivateMetaData));
    }
    if (NULL != pDstSGL->pPrivateMetaData)
    {
        qaeMemFreeNUMA((void **)&(pDstSGL->pPrivateMetaData));
    }
    if (NULL != pCompareSGL->pPrivateMetaData)
    {
        qaeMemFreeNUMA((void **)&(pCompareSGL->pPrivateMetaData));
    }
}

CpaStatus createInitDcSession(compression_test_params_t *pSetup,
                              Cpa32U numaNode,
                              CpaDcSessionHandle **ppSessionHandle)
{
    Cpa32U sessionSize = 0, contextSize = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcCallbackFn dcCbFn;

    /* pContextBufferList is NULL for all stateless requests,
     * stateful operations are not supported
     */
    CpaBufferList *pContextBufferList = NULL;

    /* Set the callback function is asynchronous invocation is required, set to
     * NULL if not.
     */
    if (CPA_SAMPLE_ASYNCHRONOUS == pSetup->syncFlag)
    {
        dcCbFn = (CpaDcCallbackFn)&dcCallback;
    }
    else
    {
        dcCbFn = NULL;
    }
    /* Create and initialize compression session session */
    status = cpaDcGetSessionSize(pSetup->dcInstanceHandle,
                                 &(pSetup->setupData),
                                 &sessionSize,
                                 &contextSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetSessionSize() returned %d status.\n", status);
        return CPA_STATUS_FAIL;
    }
    *ppSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
        (sessionSize + contextSize), numaNode, BYTE_ALIGNMENT_64);
    if (NULL == *ppSessionHandle)
    {
        PRINT_ERR("Unable to allocate memory for session handle\n");
        return CPA_STATUS_FAIL;
    }
    status = cpaDcInitSession(pSetup->dcInstanceHandle,
                              *ppSessionHandle,
                              &(pSetup->setupData),
                              pContextBufferList,
                              dcCbFn);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to create DC session\n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

void removeDcSession(compression_test_params_t *pSetup,
                     CpaDcSessionHandle **ppSessionHandle)
{
    if (NULL != *ppSessionHandle)
    {
        cpaDcRemoveSession(pSetup->dcInstanceHandle, *ppSessionHandle);
        qaeMemFreeNUMA((void **)ppSessionHandle);
    }
}

CpaStatus dcPerformSGL(compression_test_params_t *pSetup)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U numaNode = 0;
    /* pSrcSGL for original uncompressed data */
    CpaBufferList srcSGL;
    /* pDstSGL target for compressed data */
    CpaBufferList dstSGL;
    /* pCompareSGL for target uncompressed data post decompression */
    CpaBufferList compareSGL;

    /* DC Session vars */
    CpaDcSessionHandle *pSessionHandle = NULL;
    /* Request Results Structures */
    CpaDcRqResults compressResult;
    CpaDcRqResults decompressResult;

    if (NULL == pSetup)
    {
        PRINT_ERR(" Setup Pointer is NULL\n");
        return CPA_STATUS_FAIL;
    }

    memset(&srcSGL, 0, sizeof(CpaBufferList));
    memset(&dstSGL, 0, sizeof(CpaBufferList));
    memset(&compareSGL, 0, sizeof(CpaBufferList));
    memset(&compressResult, 0, sizeof(CpaDcRqResults));
    memset(&decompressResult, 0, sizeof(CpaDcRqResults));

    status = sampleCodeDcGetNode(pSetup->dcInstanceHandle, &numaNode);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node ID\n");
        return CPA_STATUS_FAIL;
    }
    /* Allocate memory for SGLs */
    status = allocateFlatBuffers(pSetup, &srcSGL);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto cleanup;
    }
    status = allocateFlatBuffers(pSetup, &dstSGL);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto cleanup;
    }
    status = allocateFlatBuffers(pSetup, &compareSGL);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto cleanup;
    }

    /* Allocate memory for SGL Flat Buffers */
    status = allocateFlatBufferData(numaNode, &srcSGL, pSetup->bufferSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto cleanup;
    }
    status = allocateFlatBufferData(
        numaNode, &dstSGL, pSetup->bufferSize * EXTRA_BUFFER);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto cleanup;
    }
    status = allocateFlatBufferData(numaNode, &compareSGL, pSetup->bufferSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        goto cleanup;
    }
    /* Populate Source Flat buffers for compression with corpus data */
    status = populateFlatBuffers(pSetup, &srcSGL);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error populating flat buffers with corpus data\n");
        goto cleanup;
    }
    /* Allocate private meta data for each SGL */
    status = allocateMetaData(pSetup, numaNode, &srcSGL, &dstSGL, &compareSGL);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to allocate meta data\n");
        goto cleanup;
    }

    status = createInitDcSession(pSetup, numaNode, &pSessionHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to initialize DC session\n");
        goto cleanup;
    }

    status =
        doCompress(pSetup, &srcSGL, &dstSGL, pSessionHandle, &compressResult);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Data Compression Failed\n");
        goto cleanup;
    }

    pSetup->performanceStats->bytesConsumedPerLoop = compressResult.consumed;
    pSetup->performanceStats->bytesProducedPerLoop = compressResult.produced;
    if (CPA_DC_DIR_DECOMPRESS == pSetup->dcSessDir ||
        CPA_DC_DIR_COMBINED == pSetup->dcSessDir)
    {
        status = doDecompress(
            pSetup, &dstSGL, &compareSGL, pSessionHandle, &decompressResult);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Data Compression Failed\n");
            goto cleanup;
        }
        status = compareData(
            &srcSGL, &compareSGL, &compressResult, &decompressResult);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Buffer Comparison Failed\n");
            goto cleanup;
        }
    }
    status = CPA_STATUS_SUCCESS;
cleanup:
    removeDcSession(pSetup, &pSessionHandle);
    freeMetaData(pSetup, &srcSGL, &dstSGL, &compareSGL);
    freeFlatBufferData(&srcSGL);
    freeFlatBufferData(&dstSGL);
    freeFlatBufferData(&compareSGL);
    freeFlatBuffers(pSetup, &srcSGL);
    freeFlatBuffers(pSetup, &dstSGL);
    freeFlatBuffers(pSetup, &compareSGL);

    return status;
}

void dcPerformanceSGL(single_thread_test_data_t *testSetup)
{
    compression_test_params_t dcSetup, *tmpSetup = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcInstanceCapabilities capabilities = {0};

    /* Get the setup pointer */
    tmpSetup = (compression_test_params_t *)(testSetup->setupPtr);
    memcpy(&dcSetup.requestOps, &tmpSetup->requestOps, sizeof(CpaDcOpData));
    /* update the setup structure with setup parameters */
    dcSetup.bufferSize = tmpSetup->bufferSize;
    dcSetup.corpus = tmpSetup->corpus;
    dcSetup.setupData = tmpSetup->setupData;
    dcSetup.dcSessDir = tmpSetup->dcSessDir;
    dcSetup.syncFlag = tmpSetup->syncFlag;
    dcSetup.numLoops = tmpSetup->numLoops;
    dcSetup.isDpApi = tmpSetup->isDpApi;
    /*give our thread a unique memory location to store performance stats*/
    dcSetup.performanceStats = testSetup->performanceStats;
    testSetup->performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;

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
        return;
    }
    if (0 == numInstances)
    {
        PRINT_ERR(" DC Instances are not present\n");
        sampleCodeThreadExit();
    }

    instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == instances)
    {
        PRINT_ERR("Unable to allocate Memory for Instances\n");
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
        sampleCodeThreadExit();
    }
    if (CPA_FALSE == capabilities.dynamicHuffman)
    {
        PRINT("Dynamic is not supported on logical instance %d\n",
              (testSetup->logicalQaInstance) % numInstances);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        sampleCodeThreadExit();
    }

    /*launch function that does all the work*/
    status = dcPerformSGL(&dcSetup);
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
    qaeMemFree((void **)&instances);
    sampleCodeThreadComplete(testSetup->threadID);
}

CpaStatus setupDcSGLTest(CpaDcCompType algorithm,
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
    status = startDcServices(DYNAMIC_BUFFER_AREA_128K, TEMP_NUM_BUFFS);
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
        (performance_func_t)dcPerformanceSGL;

    /* update the setup_g with buffersize */
    testSetupData_g[testTypeCount_g].packetSize = testBufferSize;
    /* Data compression setup data */
    dcSetup->setupData.compLevel = compLevel;
    dcSetup->setupData.compType = algorithm;
    /* always Set the Session direction to COMBINED
     * but, the time stamps will be taken as per the
     * session direction given by the User
     */
    dcSetup->setupData.sessDirection = CPA_DC_DIR_COMBINED;
    dcSetup->setupData.checksum = CPA_DC_NONE;
#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
    dcSetup->setupData.huffType = huffmanType;
#else
    dcSetup->setupData.huffType = CPA_DC_HT_STATIC;
#endif
    dcSetup->setupData.sessState = CPA_DC_STATELESS;
#if DC_API_VERSION_LESS_THAN(1, 6)
    dcSetup->setupData.fileType = CPA_DC_FT_ASCII;
    dcSetup->setupData.deflateWindowSize = DEFAULT_COMPRESSION_WINDOW_SIZE;
#endif
    dcSetup->corpus = corpusType;
    dcSetup->bufferSize = testBufferSize;
    dcSetup->dcSessDir = direction;
    dcSetup->setupData.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
    dcSetup->numLoops = numLoops;
    dcSetup->syncFlag = syncFlag;
    dcSetup->isDpApi = CPA_FALSE;
    return status;
}
EXPORT_SYMBOL(setupDcSGLTest);
