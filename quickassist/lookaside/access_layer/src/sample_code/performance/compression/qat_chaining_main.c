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
 * @file qat_chaining_main.c
 *
 *
 * @ingroup compressionThreads
 *
 * @description
 *    This is a sample code that uses chaining APIs.

 *    This code preallocates a number of buffers as based on the size of each
 *    file defined in the calgary/canterbury corpus. The preallocated buffers
 *    are then populated with the corpus files as define in
 *    setup->testBuffersize.
 *    Time stamping is started prior to the first performed chaining
 *    Operation and is stopped when all callbacks have returned.
 *****************************************************************************/

#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_dc_utils.h"
#include "qat_compression_main.h"
#include "cpa_sample_code_crypto_utils.h"
#include "qat_perf_cycles.h"
#include "qat_perf_sleeptime.h"
#include "qat_compression_e2e.h"
#ifdef USER_SPACE
#include <openssl/aes.h>
#include <openssl/sha.h>
#else
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/crc32.h>
#include <linux/vmalloc.h>
#endif

#ifdef USER_SPACE
#include <zlib.h>
#else
#include <linux/zlib.h>
#endif

#include "icp_sal_poll.h"

static CpaStatus qatDcChainInduceOverflow(compression_test_params_t *setup,
                                          CpaDcSessionHandle pSessionHandle,
                                          CpaBufferList *srcBufferListArray,
                                          CpaBufferList *destBufferListArray,
                                          CpaBufferList *cmpBufferListArray,
                                          CpaDcChainRqResults *resultArray,
                                          CpaDcChainOpData *chainOpDataArray);

extern int latency_enable;
extern int latency_debug;
extern int latency_single_buffer_mode;



#define COUNT_RESPONSES dcPerformCallback(setup, status)

static inline void bufferDump(Cpa8U *pBuffer, Cpa32U bufferLength)
{
    int i = 0;
    for (i = 0; i < bufferLength; i++)
    {
        if (i && (i % 16 == 0))
        {
            PRINT("\n");
        }
        PRINT("%02X", pBuffer[i]);
    }
    PRINT("\n");
}

CpaStatus compareBuffers2(CpaBufferList ***ppSrc,
                          CpaBufferList ***ppDst,
                          CpaBufferList ***ppComp,
                          compression_test_params_t *setup);

static Cpa32U crc32_checksum(Cpa32U inputChecksum, Cpa8U *pData, Cpa32U length)
{
    Cpa32U resultChecksum = 0;
#ifdef KERNEL_SPACE
    resultChecksum =
        crc32(inputChecksum ^ CRC32_XOR_VALUE, pData, length) ^ CRC32_XOR_VALUE;
#else
    resultChecksum = crc32(inputChecksum, pData, length);
#endif
    return resultChecksum;
}

void computeSglChecksum(CpaBufferList *inputBuff,
                        const Cpa32U computationSize,
                        const CpaDcChecksum checksumType,
                        Cpa32U *swChecksum)
{
    Cpa32U numBuffs = 0;
    Cpa32U lenLeft = 0;
    Cpa32U totalLen = 0;

    for (numBuffs = 0; numBuffs < inputBuff->numBuffers; numBuffs++)
    {
        totalLen += inputBuff->pBuffers[numBuffs].dataLenInBytes;
        if (totalLen > computationSize)
        {
            totalLen -= inputBuff->pBuffers[numBuffs].dataLenInBytes;
            lenLeft = computationSize - totalLen;
            if (CPA_DC_CRC32 == checksumType)
            {
                *swChecksum = crc32_checksum(
                    *swChecksum, inputBuff->pBuffers[numBuffs].pData, lenLeft);
            }
            break;
        }
        else
        {
            lenLeft = inputBuff->pBuffers[numBuffs].dataLenInBytes;
        }

        if (CPA_DC_CRC32 == checksumType)
        {
            *swChecksum = crc32_checksum(
                *swChecksum, inputBuff->pBuffers[numBuffs].pData, lenLeft);
        }
    }
}

extern Cpa32U dcPollingInterval_g;

#define DOUBLE_SUBMISSIONS (2)

extern char *cpaStatusToString(CpaStatus status);

static CpaStatus checkAdler32Checksum(Cpa8U *inputBuff,
                                      Cpa32U inputBufferLen,
                                      CpaDcChainRqResults *results,
                                      Cpa32U *swChecksum)
{
#ifdef USER_SPACE
    /* Calculate s/w checksum */
    *swChecksum = adler32(*swChecksum, inputBuff, inputBufferLen);

    if (results->adler32 != *swChecksum)
    {
        PRINT("s/w checksum: %X    h/w checksum: %X\n",
              *swChecksum,
              results->adler32);
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}

static CpaStatus checkCrc32Checksum(Cpa8U *inputBuff,
                                    Cpa32U inputBufferLen,
                                    CpaDcChainRqResults *results,
                                    Cpa32U *swChecksum)
{
    /* Calculate s/w checksum */
    *swChecksum = crc32(*swChecksum, inputBuff, inputBufferLen);

    if (results->crc32 != *swChecksum)
    {
        PRINT("s/w checksum: %X    h/w checksum: %X\n",
              *swChecksum,
              results->crc32);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus qatDcChainSubmitRequest(compression_test_params_t *setup,
                                  CpaInstanceInfo2 *pInstanceInfo2,
                                  CpaDcSessionDir compressDirection,
                                  CpaDcSessionHandle pSessionHandle,
                                  CpaBufferList *arrayOfSrcBufferLists,
                                  CpaBufferList *arrayOfDestBufferLists,
                                  CpaBufferList *arrayOfCmpBufferLists,
                                  Cpa32U listNum,
                                  CpaDcChainRqResults *arrayOfResults,
                                  CpaDcChainOpData *arrayOfChainOpData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    static Cpa32U staticAssign = 0;
    Cpa8U numSessions = setup->numSessions;

    if (setup->requestOps.flushFlag != setup->flushFlag)
    {
        PRINT_ERR("Setup Disparity in Flush flag."
                  "RequestOps = %d, setup = %d\n",
                  setup->requestOps.flushFlag,
                  setup->flushFlag);
        setup->requestOps.flushFlag = setup->flushFlag;
    }

    do
    {
        /*To use reliability code, I set CpaBoolean reliability_g = CPA_TRUE
         * in cpa_sample_code_framework.c and defined USE_ZLIB from
         * command line
         */
        qatStartLatencyMeasurement(setup->performanceStats,
                                   setup->performanceStats->submissions);
        coo_req_start(setup->performanceStats);
        status = cpaDcChainPerformOp(
            setup->dcInstanceHandle,
            pSessionHandle,
            &arrayOfSrcBufferLists[listNum],
            &arrayOfDestBufferLists[listNum],
            setup->chainOperation,
            numSessions,
            &arrayOfChainOpData[listNum * setup->numSessions],
            &arrayOfResults[listNum],
            (void *)setup);
        coo_req_stop(setup->performanceStats, status);
        if (CPA_STATUS_RETRY == status)
        {
            qatDcRetryHandler(setup, pInstanceInfo2);
            /*check if sleeptime defined if yes then perform
            sleep in 100k intervals */
            if ((sleepTime_enable) && (setup->sleepTime != 0))
            {
                sleep_parsing(setup->sleepTime);
            }
            /*context switch to give firmware time to process*/
            AVOID_SOFTLOCKUP;
        }
        /*check the results structure for any failed responses
         * caught by the callback function*/
        qatDcChainResponseStatusCheck(setup, arrayOfResults, listNum, &status);

    } while (CPA_STATUS_RETRY == status);

    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        busyLoop(setup->performanceStats->busyLoopValue, &staticAssign);
        setup->performanceStats->busyLoopCount++;
    }
    return status;
}
EXPORT_SYMBOL(qatDcChainSubmitRequest);

/* chaining performance measurement function to compress a file for 'n' number
 * of loops
 * */
CpaStatus qatDcChainCompressData(compression_test_params_t *setup,
                                 CpaDcSessionHandle pSessionHandle,
                                 CpaDcSessionDir compressDirection,
                                 CpaBufferList *arrayOfSrcBufferLists,
                                 CpaBufferList *arrayOfDestBufferLists,
                                 CpaBufferList *arrayOfCmpBufferLists,
                                 CpaDcChainRqResults *arrayOfResults,
                                 CpaDcChainOpData *arrayOfChainOpData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceInfo2 instanceInfo2 = {0};
    Cpa32U numLoops = 0;
    Cpa32U listNum = 0;
    Cpa32U previousChecksum = 0;
    sleeptime_data_t sleeptime_data = {0};
    sleeptime_data.firstRunFlag = 1;

    /* init checksum */
    if (CPA_DC_ADLER32 == gChecksum)
    {
        previousChecksum = 1;
    }
    else if (CPA_DC_CRC32 == gChecksum)
    {
        previousChecksum = 0;
    }

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfSrcBufferLists,
                                                  status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfDestBufferLists,
                                                  status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfCmpBufferLists,
                                                  status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfResults, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfChainOpData, status);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatCompressionE2EInit(setup);
        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS("qatCompressionE2EInit",
                                                  status);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        setup->flushFlag = CPA_DC_FLUSH_FINAL;
        qatPerfInitStats(setup->performanceStats,
                         setup->numLists,
                         setup->numLoops,
                         dcPollingInterval_g);
        status = qatInitLatency(
            setup->performanceStats, setup->numLists, setup->numLoops);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*get the instance2 info, this is used to determine if the instance
         * being used is polled*/
        status = cpaDcInstanceGetInfo2(setup->dcInstanceHandle, &instanceInfo2);
        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS("cpaDcInstanceGetInfo2",
                                                  status);
    }
    if (status == CPA_STATUS_SUCCESS)
    {
        /*Initialize the semaphore, the callback function is responsible for
         * posting the semaphore once all responses are received*/

        /* Completion used in callback */
        status = sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);
        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS("sampleCodeSemaphoreInit",
                                                  status);
    }
    if (status == CPA_STATUS_SUCCESS)
    {
        /* this Barrier will waits until all the threads get to this point
         * this is to ensure that all threads that we measure performance on
         * start submitting at the same time*/
        sampleCodeBarrier();
        /* generate the start time stamps */
        setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();
        sleeptime_data.startLoopTimestamp =
            setup->performanceStats->startCyclesTimestamp;
        /*loop over compressing a file numLoop times*/
        for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
        {
            /*loop over lists that store the file*/
            for (listNum = 0; listNum < setup->numLists; listNum++)
            {
                /*exit loop mechanism to leave early if numLoops is large
                 * note that this might not work if the we get stuck in the
                 * do-while loop below*/
                checkStopTestExitFlag(setup->performanceStats,
                                      &setup->numLoops,
                                      &setup->numLists,
                                      numLoops);
                qatCompressionSetFlushFlag(setup, listNum);
                /*for stateful-lite carry over checksum from previous request*/
                if ((CPA_TRUE == setup->useStatefulLite) ||
                    (CPA_DC_STATEFUL == setup->setupData.sessState))
                {
                    arrayOfResults[listNum].crc32 = previousChecksum;
                }

                /*submit request*/
                status = qatDcChainSubmitRequest(setup,
                                                 &instanceInfo2,
                                                 compressDirection,
                                                 pSessionHandle,
                                                 arrayOfSrcBufferLists,
                                                 arrayOfDestBufferLists,
                                                 arrayOfCmpBufferLists,
                                                 listNum,
                                                 arrayOfResults,
                                                 arrayOfChainOpData);
                /* Check submit status and update thread status*/
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Data Compression Failed %d\n\n", status);
                    setup->performanceStats->threadReturnStatus =
                        CPA_STATUS_FAIL;
                    /*break out  of inner loop*/
                    break;
                }

                setup->performanceStats->submissions++;
                qatLatencyPollForResponses(setup->performanceStats,
                                           setup->performanceStats->submissions,
                                           setup->dcInstanceHandle,
                                           CPA_FALSE,
                                           CPA_FALSE);
                if (poll_inline_g && instanceInfo2.isPolled)
                {
                    /*poll every 'n' requests as set by
                     * dcPollingInterval_g*/
                    if (setup->performanceStats->submissions ==
                        setup->performanceStats->nextPoll)
                    {
                        qatDcPollAndSetNextPollCounter(setup);
                    }
                }

                /* check if synchronous flag is set,
                 *  if set, invoke the callback API
                 *  the driver does not use the callback in sync mode
                 *  the sample code uses the callback function to count the
                 *  responses and post the semaphore
                 */
                if (SYNC == setup->syncFlag)
                {
                    COUNT_RESPONSES;
                } /* End of SYNC Flag Check */
                if (CPA_STATUS_SUCCESS == status)
                {
                    status =
                        qatDcChainE2EVerify(setup,
                                            &arrayOfSrcBufferLists[listNum],
                                            &arrayOfDestBufferLists[listNum],
                                            &arrayOfResults[listNum]);
                }
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("%s returned status: %d\n",
                              "qatDcChainE2EVerify",
                              status);
                    break;
                }
            }
            /* number of lists/requests in a file */
            if (CPA_STATUS_SUCCESS != status)
            {
                setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
                /*break out of outerloop(numLoops)*/
                break;
            }
            if ((numLoops % QAT_COMP_MIN_LOOPS_FOR_SLEEP_CONTROL ==
                 QAT_COMP_MIN_LOOPS_FOR_SLEEP_CONTROL - 1) &&
                (sleepTime_enable) &&
                (setup->specific_sleeptime_flag == CPA_FALSE))
            {
                adjustSleeptime(setup->performanceStats,
                                &sleeptime_data,
                                &setup->compRate,
                                &setup->sleepTime,
                                setup->bufferSize);
            }
        } /* number of times we loop over same file */
        if (poll_inline_g)
        {
            if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2.isPolled))
            {
                /*
                 ** Now need to wait for all the inflight Requests.
                 */
                status =
                    dcPollNumOperations(setup->performanceStats,
                                        setup->dcInstanceHandle,
                                        setup->performanceStats->numOperations);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("dcPollNumOperations returned an error\n");
                    setup->performanceStats->threadReturnStatus =
                        CPA_STATUS_FAIL;
                }
            }
        }
        /* Wait 30 seconds for the semaphore to be posted by the callback*/
        if (CPA_STATUS_SUCCESS == status)
        {
            status = waitForSemaphore(setup->performanceStats);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("waitForSemaphore error\n");
                setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
            }
        }
        /*check the results structure for any failed responses
         * caught by the callback function*/
        qatDcChainResponseStatusCheck(setup, arrayOfResults, listNum, &status);
        qatSummariseLatencyMeasurements(setup->performanceStats);
        sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);
    } /* if semaphoreInit was successful */
    if (CPA_STATUS_SUCCESS != status)
    {
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    return status;
}
EXPORT_SYMBOL(qatDcChainCompressData);

/*update in sample code framework how much data was consumed and produced by
 * thread*/
void dcChainScSetBytesProducedAndConsumed(CpaDcChainRqResults *result,
                                          perf_data_t *perfData,
                                          compression_test_params_t *setup,
                                          CpaDcSessionDir direction)
{
    Cpa32U i = 0;

    if (direction == CPA_DC_DIR_COMPRESS)
    {
        for (i = 0; i < setup->numberOfBuffers[0]; i++)
        {
            perfData->bytesConsumedPerLoop += result[i].consumed;
            perfData->bytesProducedPerLoop += result[i].produced;
        }
    }
    else if (direction == CPA_DC_DIR_DECOMPRESS)
    {
        for (i = 0; i < setup->numberOfBuffers[0]; i++)
        {
            perfData->bytesConsumedPerLoop += result[i].produced;
            perfData->bytesProducedPerLoop += result[i].consumed;
        }
    }
}
EXPORT_SYMBOL(dcChainScSetBytesProducedAndConsumed);

void dcChainOpDataMemFree(CpaDcChainOpData *pOpdata,
                          Cpa32U numLists,
                          Cpa32U numSessions)
{
    Cpa32U k = 0;
    Cpa32U j = numSessions;
    CpaDcOpData *pDcOp = NULL;
    CpaCySymOpData *pCySymOp = NULL;


    for (k = 0; k < numLists; k++)
    {
        if (NULL != pOpdata)
        {
            if (pOpdata[k * j].opType == CPA_DC_CHAIN_SYMMETRIC_CRYPTO)
            {
                pCySymOp = pOpdata[k * j].pCySymOp;
                pDcOp = pOpdata[k * j + 1].pDcOp;
            }
            else
            {
                pCySymOp = pOpdata[k * j + 1].pCySymOp;
                pDcOp = pOpdata[k * j].pDcOp;
            }
            if (NULL != pCySymOp)
            {
                if (NULL != pCySymOp->pDigestResult)
                {
                    qaeMemFreeNUMA((void **)&(pCySymOp->pDigestResult));
                }
                if (NULL != pCySymOp->pIv)
                {
                    qaeMemFreeNUMA((void **)&(pCySymOp->pIv));
                }
                if (NULL != pCySymOp->pAdditionalAuthData)
                {
                    qaeMemFreeNUMA((void **)&(pCySymOp->pAdditionalAuthData));
                }
                qaeMemFree((void **)&pCySymOp);
            }
            if (NULL != pDcOp)
            {
                if (NULL != pDcOp->pCrcData)
                {
                    qaeMemFreeNUMA((void **)&(pDcOp->pCrcData));
                }
                qaeMemFree((void **)&pDcOp);
            }
        }
    }
}


CpaStatus dcChainPerformOpDataSetup(compression_test_params_t *setup,
                                    CpaBufferList *srcBufferListArray,
                                    CpaDcChainOpData *chainOpDataArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U listNum = 0;
    CpaDcOpData *pDcOp = NULL;
    CpaCySymOpData *pCySymOp = NULL;
    Cpa32U nodeId = 0;

    status = sampleCodeDcGetNode(setup->dcInstanceHandle, &nodeId);
    if (CPA_STATUS_SUCCESS != status)
    {
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }
    for (listNum = 0; listNum < setup->numLists; listNum++)
    {
        memset(&chainOpDataArray[listNum * setup->numSessions],
               0,
               sizeof(CpaDcChainOpData) * setup->numSessions);

        pDcOp = qaeMemAlloc(sizeof(CpaDcOpData));
        if (NULL == pDcOp)
        {
            PRINT_ERR("qaeMemAlloc for pDcOp error\n");
            dcChainOpDataMemFree(chainOpDataArray, listNum, setup->numSessions);
            return CPA_STATUS_FAIL;
        }
        memset(pDcOp, 0, sizeof(CpaDcOpData));
        pDcOp->flushFlag = CPA_DC_FLUSH_FINAL;
        pDcOp->compressAndVerify = setup->requestOps.compressAndVerify;
        pDcOp->compressAndVerifyAndRecover =
            setup->requestOps.compressAndVerifyAndRecover;
        pCySymOp = qaeMemAlloc(sizeof(CpaCySymOpData));
        if (NULL == pCySymOp)
        {
            PRINT_ERR("qaeMemAlloc for pCySymOp error\n");
            qaeMemFree((void **)&pDcOp);
            dcChainOpDataMemFree(chainOpDataArray, listNum, setup->numSessions);
            return CPA_STATUS_FAIL;
        }
        memset(pCySymOp, 0, sizeof(CpaCySymOpData));
        pCySymOp->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pCySymOp->cryptoStartSrcOffsetInBytes = 0;
        pCySymOp->messageLenToCipherInBytes =
            srcBufferListArray[listNum].pBuffers[0].dataLenInBytes;
        pCySymOp->hashStartSrcOffsetInBytes = 0;
        pCySymOp->messageLenToHashInBytes =
            srcBufferListArray[listNum].pBuffers[0].dataLenInBytes;
        if (0 != setup->symSetupData.hashSetupData.digestResultLenInBytes)
        {
            pCySymOp->pDigestResult = qaeMemAllocNUMA(
                setup->symSetupData.hashSetupData.digestResultLenInBytes,
                nodeId,
                BYTE_ALIGNMENT_64);
            if (NULL == pCySymOp->pDigestResult)
            {
                PRINT_ERR(
                    "qaeMemAllocNuMA for pCySymOp->pDigestResult error\n");
                qaeMemFree((void **)&pDcOp);
                qaeMemFree((void **)&pCySymOp);
                dcChainOpDataMemFree(
                    chainOpDataArray, listNum, setup->numSessions);
                return CPA_STATUS_FAIL;
            }
        }

        switch (setup->chainOperation)
        {
            case CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT:
                chainOpDataArray[listNum * setup->numSessions].opType =
                    CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
                chainOpDataArray[listNum * setup->numSessions].pDcOp = pDcOp;
                chainOpDataArray[listNum * setup->numSessions + 1].opType =
                    CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
                chainOpDataArray[listNum * setup->numSessions + 1].pCySymOp =
                    pCySymOp;
                break;
            case CPA_DC_CHAIN_DECRYPT_THEN_DECOMPRESS:
                chainOpDataArray[listNum * setup->numSessions].opType =
                    CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
                chainOpDataArray[listNum * setup->numSessions].pCySymOp =
                    pCySymOp;
                chainOpDataArray[listNum * setup->numSessions + 1].opType =
                    CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
                chainOpDataArray[listNum * setup->numSessions + 1].pDcOp =
                    pDcOp;
                break;
            case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
                chainOpDataArray[listNum * setup->numSessions].opType =
                    CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
                chainOpDataArray[listNum * setup->numSessions].pCySymOp =
                    pCySymOp;
                chainOpDataArray[listNum * setup->numSessions + 1].opType =
                    CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
                chainOpDataArray[listNum * setup->numSessions + 1].pDcOp =
                    pDcOp;
                break;
            default:
                PRINT_ERR("Unsupported chaining operation.\n");
                qaeMemFree((void **)&pDcOp);
                dcChainOpDataMemFree(
                    chainOpDataArray, listNum, setup->numSessions);
                qaeMemFreeNUMA((void **)&(pCySymOp->pDigestResult));
                qaeMemFree((void **)&pCySymOp);
                return CPA_STATUS_FAIL;
        }
    }
    return status;
}

/*Allocates buffers store a file for compression. The buffers are sent to
 * hardware, performance is recorded and stored in the setup parameter
 * the sample code framework prints out results after the thread completes*/
CpaStatus qatDcChainPerform(compression_test_params_t *setup)
{
    /***
    store file in array of CpaBufferLists:
        arrayOfSrcBufferLists[0].CpaFlatBuffer.pData         <-startOfFile
        arrayOfSrcBufferLists[0].CpaFlatBuffer.bufferSizeInBytes
        .
        .
        .
        arrayOfSrcBufferLists[n].CpaFlatBuffer.pData        <-endOfFile
        arrayOfSrcBufferLists[n].CpaFlatBuffer.bufferSizeInBytes

    where bufferSizeInBytes = testBufferSize
    n = numberOfLists required of the above mentioned size,
    required to store the file
    ***/
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U *testBufferSize = setup->packetSizeInBytesArray;
    Cpa32U numberOfBuffersPerList = 1;
    /* Src Buffer list for data to be compressed */
    CpaBufferList *srcBufferListArray = NULL;
    /* BufferList for de-compressed Data */
    CpaBufferList *destBufferListArray = NULL;
    /* BufferList for compressed data */
    CpaBufferList *cmpBufferListArray = NULL;
    CpaDcChainRqResults *resultArray = NULL;
    CpaDcSessionHandle pSessionHandle = NULL;
    CpaDcSessionHandle pDecompressSessionHandle = NULL;
    CpaDcCallbackFn dcCbFn = dcPerformCallback;
    Cpa32U numLoops = 0;
    Cpa32U listNum = 0;
    Cpa32U i = 0;
    Cpa32U nodeId = 0;
    Cpa32U softChecksum = 0;
    /* Chain operation data for compression chaining */
    CpaDcChainOpData *chainOpDataArray = NULL;
    CpaFlatBuffer *pSWDigestBuffer = NULL;
    const corpus_file_t *const fileArray = getFilesInCorpus(setup->corpus);
    coo_init(setup->performanceStats,
             (Cpa64U)setup->numLists * (Cpa64U)setup->numLoops);

    /* Allocate memory for source & destination bufferLists
     */
    status = qatAllocateCompressionLists(setup,
                                         &srcBufferListArray,
                                         &destBufferListArray,
                                         &cmpBufferListArray,
                                         NULL);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not allocate compression list arrays\n");
    }

    /* Allocate memory for DcChain results and chainOpData */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatAllocateDcChainLists(
            setup, (void **)&resultArray, (void **)&chainOpDataArray);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate DcChain result and ChainOpLists\n");
        }
    }

    /* Allocate the CpaFlatBuffers in each list */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatAllocateCompressionFlatBuffers(setup,
                                                   srcBufferListArray,
                                                   numberOfBuffersPerList,
                                                   testBufferSize,
                                                   destBufferListArray,
                                                   numberOfBuffersPerList,
                                                   testBufferSize,
                                                   cmpBufferListArray,
                                                   numberOfBuffersPerList,
                                                   testBufferSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate all flat buffers for compression\n");
        }
    }

    /* Copy corpus data into allocated buffers */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PopulateBuffers(
            srcBufferListArray,
            setup->numLists,
            fileArray[setup->corpusFileIndex].corpusBinaryData,
            fileArray[setup->corpusFileIndex].corpusBinaryDataLen,
            testBufferSize);
    }

    /* Initialize the compression session to use */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatDcChainSessionInit(
            setup, &pSessionHandle, &pDecompressSessionHandle, dcCbFn);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("compressionSessionInit returned status %d\n", status);
        }
    }
/*CNV Error Injection*/
    /* Set value for chainOpData */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcChainPerformOpDataSetup(
            setup, srcBufferListArray, chainOpDataArray);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("dcChainPerformOpDataSetup returned status %d\n", status);
        }
    }
    /* Compress the data */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (setup->induceOverflow == CPA_TRUE)
        {
            status = qatDcChainInduceOverflow(setup,
                                              pSessionHandle,
                                              srcBufferListArray,
                                              destBufferListArray,
                                              cmpBufferListArray,
                                              resultArray,
                                              chainOpDataArray);
        }
        else if (setup->dcSessDir == CPA_DC_DIR_COMPRESS &&
                 reliability_g == CPA_FALSE)
        {
            status = qatDcChainCompressData(setup,
                                            pSessionHandle,
                                            CPA_DC_DIR_COMPRESS,
                                            srcBufferListArray,
                                            destBufferListArray,
                                            cmpBufferListArray,
                                            resultArray,
                                            chainOpDataArray);
            qatDcChainUpdateProducedBufferLength(
                setup, destBufferListArray, resultArray);
            dcChainScSetBytesProducedAndConsumed(
                resultArray, setup->performanceStats, setup, setup->dcSessDir);
        }
        else if (setup->dcSessDir == CPA_DC_DIR_DECOMPRESS &&
                 reliability_g == CPA_FALSE)
        {
            PRINT("Chaining Decompression need to be developed\n");
            status = CPA_STATUS_FAIL;
        }
        else if (setup->dcSessDir == CPA_DC_DIR_COMPRESS &&
                 reliability_g == CPA_TRUE)
        {
            /*Copy numLoops, set setup->numLoops to 1 to do repeated
             * compress - sw-decompress for numLoops times
             */
            numLoops = setup->numLoops;
            setup->numLoops = 1;
            for (i = 0; i < numLoops; i++)
            {
                status = qatDcChainCompressData(setup,
                                                pSessionHandle,
                                                CPA_DC_DIR_COMPRESS,
                                                srcBufferListArray,
                                                destBufferListArray,
                                                cmpBufferListArray,
                                                resultArray,
                                                chainOpDataArray);
                qatDcChainUpdateProducedBufferLength(
                    setup, destBufferListArray, resultArray);
                dcChainScSetBytesProducedAndConsumed(resultArray,
                                                     setup->performanceStats,
                                                     setup,
                                                     setup->dcSessDir);
                if (CPA_STATUS_SUCCESS == status)
                {
                    status = qatSwChainDecompress(setup,
                                                  destBufferListArray,
                                                  cmpBufferListArray,
                                                  resultArray);
                    qatDcChainUpdateProducedBufferLength(
                        setup, cmpBufferListArray, resultArray);
                    if (CPA_STATUS_SUCCESS == status)
                    {
                        status = qatCmpBuffers(
                            setup, srcBufferListArray, cmpBufferListArray);
                        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS(
                            "qatCmpBuffers", status);
                        if (CPA_STATUS_SUCCESS != status)
                        {
                            break;
                        }
                    }

                    pSWDigestBuffer = qaeMemAlloc(sizeof(CpaFlatBuffer));
                    if (NULL == pSWDigestBuffer)
                    {
                        PRINT_ERR(
                            "Unable to allocate Memory for pSWDigestBuffer\n");
                        status = CPA_STATUS_FAIL;
                        break;
                    }
                    pSWDigestBuffer->pData =
                        qaeMemAllocNUMA(setup->symSetupData.hashSetupData
                                            .digestResultLenInBytes,
                                        nodeId,
                                        BYTE_ALIGNMENT_64);
                    if (NULL == pSWDigestBuffer->pData)
                    {
                        PRINT_ERR("Unable to allocate Memory for "
                                  "pSWDigestBuffer->pData\n");
                        qaeMemFree((void **)&pSWDigestBuffer);
                        status = CPA_STATUS_FAIL;
                        break;
                    }
                    for (listNum = 0; listNum < setup->numLists; listNum++)
                    {
                        status = calcSWDigest(
                            srcBufferListArray[listNum].pBuffers,
                            pSWDigestBuffer,
                            setup->symSetupData.hashSetupData.hashAlgorithm);
                        if (CPA_STATUS_SUCCESS != status)
                        {
                            PRINT_ERR("calcSWDigest returned status %d\n",
                                      status);
                        }
                        if (CPA_STATUS_SUCCESS == status)
                        {

                            if (memcmp(chainOpDataArray[listNum *
                                                        setup->numSessions]
                                           .pCySymOp->pDigestResult,
                                       pSWDigestBuffer->pData,
                                       setup->symSetupData.hashSetupData
                                           .digestResultLenInBytes))
                            {
                                status = CPA_STATUS_FAIL;
                                PRINT_ERR("Chaining Hash Buffers comparison "
                                          "failed\n");
                                PRINT("[HW Digest]\n");
                                bufferDump(chainOpDataArray[listNum *
                                                            setup->numSessions]
                                               .pCySymOp->pDigestResult,
                                           setup->symSetupData.hashSetupData
                                               .digestResultLenInBytes);
                                PRINT("[SW Digest]\n");
                                bufferDump(pSWDigestBuffer->pData,
                                           setup->symSetupData.hashSetupData
                                               .digestResultLenInBytes);
                            }
                        }
                    }
                    qaeMemFreeNUMA((void **)&(pSWDigestBuffer->pData));
                    qaeMemFree((void **)&pSWDigestBuffer);
                    if (CPA_STATUS_SUCCESS == status)
                    {
                        /* Reset destination buffer */
                        status = qatCompressResetBufferList(setup,
                                                            destBufferListArray,
                                                            testBufferSize,
                                                            CPA_FALSE);
                        status = qatCompressResetBufferList(setup,
                                                            cmpBufferListArray,
                                                            testBufferSize,
                                                            CPA_TRUE);
                        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS(
                            "qatCompressResetBufferList", status);
                    }
                    for (listNum = 0; listNum < setup->numLists; listNum++)
                    {
                        switch (setup->setupData.checksum)
                        {
                            case CPA_DC_NONE:

                                break;

                            case CPA_DC_CRC32:

                                softChecksum = 0;
                                status = checkCrc32Checksum(
                                    srcBufferListArray[listNum].pBuffers->pData,
                                    srcBufferListArray[listNum]
                                        .pBuffers->dataLenInBytes,
                                    &resultArray[listNum],
                                    &softChecksum);

                                break;

                            case CPA_DC_ADLER32:

                                softChecksum = 1;
                                status = checkAdler32Checksum(
                                    srcBufferListArray[listNum].pBuffers->pData,
                                    srcBufferListArray[listNum]
                                        .pBuffers->dataLenInBytes,
                                    &resultArray[listNum],
                                    &softChecksum);

                                break;

                            case CPA_DC_CRC32_ADLER32:

                                softChecksum = 0;
                                status = checkCrc32Checksum(
                                    srcBufferListArray[listNum].pBuffers->pData,
                                    srcBufferListArray[listNum]
                                        .pBuffers->dataLenInBytes,
                                    &resultArray[listNum],
                                    &softChecksum);

                                softChecksum = 1;
                                status = checkAdler32Checksum(
                                    srcBufferListArray[listNum].pBuffers->pData,
                                    srcBufferListArray[listNum]
                                        .pBuffers->dataLenInBytes,
                                    &resultArray[listNum],
                                    &softChecksum);

                                break;
#if DC_API_VERSION_AT_LEAST(3, 0)
                            default:

                                PRINT_ERR(
                                    "Checksum is not currently supported, "
                                    "defaulting to no checksum\n");
                                setup->setupData.checksum = CPA_DC_NONE;

                                break;
#endif
                        }
                    }
                }
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("qatCompressData returned status %d\n", status);
                    break;
                }
                if (CPA_TRUE == stopTestsIsEnabled_g)
                {
                    /* Check if terminated by global flag.
                     * stop issuing new requests
                     */
                    if (CPA_TRUE == exitLoopFlag_g)
                    {
                        break;
                    }
                }
            }
        }
        else if (setup->dcSessDir == CPA_DC_DIR_DECOMPRESS &&
                 reliability_g == CPA_TRUE)
        {
            PRINT("Chaining Decompression need to be developed\n");
            status = CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            qatDumpBufferListInfo(setup,
                                  srcBufferListArray,
                                  destBufferListArray,
                                  cmpBufferListArray,
                                  0);
        }
        if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
        {
            if (CPA_STATUS_SUCCESS !=
                performDcChainOffloadCalculationBusyLoop(setup,
                                                         srcBufferListArray,
                                                         destBufferListArray,
                                                         cmpBufferListArray,
                                                         resultArray,
                                                         chainOpDataArray,
                                                         dcCbFn,
                                                         setup->dcSessDir,
                                                         pSessionHandle))
            {
                PRINT_ERR("performDcChainOffloadCalculationBusyLoop error\n");
            }
        }
        coo_average(setup->performanceStats);
        coo_deinit(setup->performanceStats);
        /* Remove the session free the handle */
        if (CPA_STATUS_SUCCESS !=
            qatDcChainSessionTeardown(
                setup, &pSessionHandle, &pDecompressSessionHandle))
        {
            PRINT_ERR("DcChainSessionTeardown error\n");
            status = CPA_STATUS_FAIL;
        }
    }
    /* Free CpaFlatBuffers and privateMetaData in CpaBufferLists */
    if (CPA_STATUS_SUCCESS !=
        qatFreeCompressionFlatBuffers(
            setup, srcBufferListArray, destBufferListArray, cmpBufferListArray))
    {
        PRINT_ERR("freeCompressionFlatBuffers error\n");
        status = CPA_STATUS_FAIL;
    }

    dcChainOpDataMemFree(chainOpDataArray, setup->numLists, setup->numSessions);

    /* Free CpaBufferLists */
    if (CPA_STATUS_SUCCESS != qatFreeCompressionLists(setup,
                                                      &srcBufferListArray,
                                                      &destBufferListArray,
                                                      &cmpBufferListArray,
                                                      NULL))
    {
        PRINT_ERR("freeChainBuff error\n");
        status = CPA_STATUS_FAIL;
    }

    /* Free CpaChainingLists */
    if (CPA_STATUS_SUCCESS !=
        qatFreeDcChainLists((void **)&resultArray, (void **)&chainOpDataArray))
    {
        PRINT_ERR("freeChainList error\n");
        status = CPA_STATUS_FAIL;
    }

    return status;
}

/*This is the performance thread created by the sample code framework
 * after registering the setupDcChainTest and calling createPeformance threads
 * this function copies the setup into its own local copy and then calls
 * scChainingPoc to measure compression performance*/
void dcChainPerformance(single_thread_test_data_t *testSetup)
{
    compression_test_params_t dcSetup = {0};
    compression_test_params_t *tmpSetup = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U node = 0;
    CpaDcInstanceCapabilities capabilities = {0};
    CpaDcStats dcStats = {0};

    /* Get the setup pointer */
    tmpSetup = (compression_test_params_t *)(testSetup->setupPtr);
    testSetup->passCriteria = tmpSetup->passCriteria;
    dcSetup.passCriteria = tmpSetup->passCriteria;

    /* Update the setup structure with setup parameters */
    memcpy(&dcSetup.requestOps, &tmpSetup->requestOps, sizeof(CpaDcOpData));
    dcSetup.compRate = tmpSetup->compRate;
    dcSetup.compRate *= QAT_COMP_SCALING_FACTOR;
    /* Check number of threads types to look at number of threads for
     * Compression rate limit */
    if (testSetupData_g[1].numberOfThreads > 0)
    {
        do_div(dcSetup.compRate, testSetupData_g[1].numberOfThreads);
    }
    else
    {
        do_div(dcSetup.compRate, numCreatedThreads_g);
    }
    dcSetup.specific_sleeptime_flag = tmpSetup->specific_sleeptime_flag;
    dcSetup.sleepTime = tmpSetup->sleepTime;
    dcSetup.chainOperation = tmpSetup->chainOperation;
    dcSetup.numSessions = tmpSetup->numSessions;
    dcSetup.bufferSize = tmpSetup->bufferSize;
    dcSetup.corpus = tmpSetup->corpus;
    dcSetup.setupData = tmpSetup->setupData;
    dcSetup.dcSessDir = tmpSetup->dcSessDir;
    dcSetup.syncFlag = tmpSetup->syncFlag;
    dcSetup.numLoops = tmpSetup->numLoops;
    dcSetup.useE2E = tmpSetup->useE2E;
    dcSetup.useE2EVerify = tmpSetup->useE2EVerify;
    dcSetup.disableAdditionalCmpbufferSize =
        tmpSetup->disableAdditionalCmpbufferSize;
    /* In case of E2E Verify we need to use CRC32 only */
    if (dcSetup.useE2EVerify)
        dcSetup.setupData.checksum = CPA_DC_CRC32;

    /* Give our thread a unique memory location to store performance stats */
    dcSetup.performanceStats = testSetup->performanceStats;
    dcSetup.performanceStats->numLoops = tmpSetup->numLoops;
    dcSetup.isDpApi = CPA_FALSE;
    testSetup->performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
    testSetup->performanceStats->additionalStatus = CPA_STATUS_SUCCESS;
    dcSetup.symSetupData = tmpSetup->symSetupData;

    dcSetup.symIvLength = tmpSetup->symIvLength;
    dcSetup.legacyChainRequest = tmpSetup->legacyChainRequest;
    dcSetup.appendCRC = tmpSetup->appendCRC;
    dcSetup.testIntegrity = tmpSetup->testIntegrity;
    dcSetup.keyDerive = tmpSetup->keyDerive;

    status = calculateRequireBuffers(&dcSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("Error calculating required buffers\n");
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    dcSetup.numLists = dcSetup.numberOfBuffers[dcSetup.corpusFileIndex];
    if (CPA_STATUS_SUCCESS == status)
    {
        /*This barrier is to halt this thread when run in user space context,
         * the startThreads function releases this barrier, in kernel space is
         * does
         * nothing, but kernel space threads do not start
         * until we call startThreads anyway
         */
        startBarrier();

        /*Initialize the statsPrintFunc to dcChainPrintStats */
        testSetup->statsPrintFunc = (stats_print_func_t)dcChainPrintStats;

        /* Get the number of instances */
        status = cpaDcGetNumInstances(&numInstances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR(" Unable to get number of DC instances\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (0 == numInstances)
        {
            PRINT_ERR(" DC Instances are not present\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
        if (NULL == instances)
        {
            PRINT_ERR("Unable to allocate Memory for Instances\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Get the instance handles so that we can start
         * our thread on the selected instance
         */
        status = cpaDcGetInstances(numInstances, instances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to get DC instances\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Give our thread a logical quick assist instance to use
         * use % to wrap around the max number of instances
         */
        dcSetup.dcInstanceHandle =
            instances[(testSetup->logicalQaInstance) % numInstances];
        if (enableReadInstance_g)
        {
            dcSetup.dcChainReadInsHandle =
                instances[(testSetup->logicalQaReadInstance) % numInstances];
        }
        /* Find node that thread is running on */
        status = sampleCodeDcGetNode(dcSetup.dcInstanceHandle, &node);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("sampleCodeDcGetNode error\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            allocateAndSetArrayOfPacketSizes(&(dcSetup.packetSizeInBytesArray),
                                             dcSetup.bufferSize,
                                             dcSetup.numLists);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("allocateAndSetArrayOfPacketSizes error\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    /* Check if dynamic compression is supported */
    status = cpaDcQueryCapabilities(dcSetup.dcInstanceHandle, &capabilities);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaDcQueryCapabilities failed", __func__, __LINE__);
        QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
    }
    if (CPA_FALSE == capabilities.dynamicHuffman &&
        tmpSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
    {
        PRINT("Dynamic is not supported on logical instance %d\n",
              (testSetup->logicalQaInstance) % numInstances);
        QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
    }
    if (CPA_FALSE == CPA_BITMAP_BIT_TEST(capabilities.dcChainCapInfo,
                                         dcSetup.chainOperation))
    {
        switch ((int)dcSetup.chainOperation)
        {
            case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
                PRINT("Hash + compress chained operation is not supported on "
                      "logical "
                      "instance %d\n",
                      (testSetup->logicalQaInstance) % numInstances);
                break;
            case CPA_DC_CHAIN_COMPRESS_THEN_AEAD:
                PRINT("Compress then Encrypt(AEAD) chained operation is not "
                      "supported on logical "
                      "instance %d\n",
                      (testSetup->logicalQaInstance) % numInstances);
                break;
            case CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS:
                PRINT("Decrypt(AEAD) then Decompress chained operation is not "
                      "supported on logical "
                      "instance %d\n",
                      (testSetup->logicalQaInstance) % numInstances);
                break;
        }

        QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
    }
    if (CNV_RECOVERY(&dcSetup.requestOps) == CPA_TRUE)
    {
        if (CNV_RECOVERY(&capabilities) == CPA_FALSE)
        {
            PRINT_ERR("CnVnR requested but not supported on instance\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
        status = cpaDcGetStats(dcSetup.dcInstanceHandle, &dcStats);
        if (status == CPA_STATUS_SUCCESS)
        {
            testSetup->performanceStats->preTestRecoveryCount =
                GET_CNV_RECOVERY_COUNTERS(&dcStats);
        }
        else
        {
            testSetup->performanceStats->preTestRecoveryCount = 0;
        }
    }
    if (CPA_TRUE == dcSetup.useE2E)
    {
        PRINT("Do CRC integrity capabilities check for this instance. %d\n",
              testSetup->logicalQaInstance);
        if (CPA_FALSE == capabilities.integrityCrcs64b)
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
    }

    dcSetup.induceOverflow = CPA_FALSE;


    if (CPA_STATUS_SUCCESS == status)
    {
        /* Launch function that does all the work */
        if (dcSetup.legacyChainRequest)
        {
            status = qatDcChainPerform(&dcSetup);
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            dcChainPrintTestData(&dcSetup);
            PRINT_ERR("Compression Thread %u FAILED\n", testSetup->threadID);
            testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set the print function that can be used to print
         * statistics at the end of the test
         */

        /* Update values from the framework peak ptr to thread local ptr to be
         * seen by print function
         */
        testSetup->performanceStats->compRate = dcSetup.compRate;
        testSetup->performanceStats->sleepTime = dcSetup.sleepTime;
        testSetup->performanceStats->numLoops = dcSetup.numLoops;

        if (
            (CPA_TRUE == CNV_RECOVERY(&dcSetup.requestOps)))
        {
            status = cpaDcGetStats(dcSetup.dcInstanceHandle, &dcStats);
            if (status == CPA_STATUS_SUCCESS)
            {
                testSetup->performanceStats->postTestRecoveryCount =
                    GET_CNV_RECOVERY_COUNTERS(&dcStats);
            }
            else
            {
                testSetup->performanceStats->postTestRecoveryCount = 0;
            }
        }
    }

err:
    if (dcSetup.packetSizeInBytesArray != NULL)
    {
        qaeMemFree((void **)&(dcSetup.packetSizeInBytesArray));
    }
    if (instances != NULL)
    {
        qaeMemFree((void **)&instances);
    }
    if (dcSetup.numberOfBuffers != NULL)
    {
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    sampleCodeThreadComplete(testSetup->threadID);
}

CpaStatus setupDcChainTest(CpaDcChainOperations chainOperation,
                           Cpa8U numSessions,
                           CpaDcCompType algorithm,
                           CpaDcSessionDir direction,
                           CpaDcCompLvl compLevel,
                           CpaDcHuffType huffmanType,
                           CpaDcSessionState state,
                           Cpa32U windowsSize,
                           Cpa32U testBufferSize,
                           corpus_type_t corpusType,
                           sync_mode_t syncFlag,
                           CpaCySymOp opType,
                           CpaCySymCipherAlgorithm cipherAlg,
                           Cpa32U cipherKeyLengthInBytes,
                           CpaCySymCipherDirection cipherDir,
                           CpaCyPriority priority,
                           CpaCySymHashAlgorithm hashAlg,
                           CpaCySymHashMode hashMode,
                           Cpa32U authKeyLengthInBytes,
                           Cpa32U numLoops)
{

    compression_test_params_t *dcSetup = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sleepTime = 0;
    Cpa32U compRate = QAT_COMP_DEFAULT_COMP_RATE;
    Cpa32U corpusFileIndex = 0;

    /* Check that the sample code framework can register this test setup */
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    /* Check that atleast 1 loop of the data set is to be submitted */
    if (numLoops == 0)
    {
        PRINT_ERR("numLoops must be > 0\n");
        return CPA_STATUS_FAIL;
    }

    /* Populate Corpus: copy from file on disk into memory*/
    /* this method limits to compressing 1 corpus at any point in time */
    if (corpusType == CORPUS_TYPE_EXTENDED)
    {
        corpusType = getCorpusType();
        corpusFileIndex = getCorpusFileIndex();
    }

    status = populateCorpus(testBufferSize, corpusType);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to load one or more corpus files, have they been "
                  "extracted to %s?\n",
                  SAMPLE_CODE_CORPUS_PATH);
        return CPA_STATUS_FAIL;
    }

    /* Start DC Services */
    status = startDcServices(testBufferSize, TEMP_NUM_BUFFS);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error in Starting Dc Services\n");
        return CPA_STATUS_FAIL;
    }
    if (!poll_inline_g)
    {
        /* start polling threads if polling is enabled in the configuration
         * file */
        if (CPA_STATUS_SUCCESS != dcCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }

    /* Get memory location from sample code framework to store setup details */
    dcSetup = (compression_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    INIT_OPDATA_DEFAULT(&dcSetup->requestOps);
    /* If the setup is requesting non-default CnV behaviour for special
     * tests, set it accordingly.
     */
    if (getSetupCnVRequestFlag() != CNV_FLAG_DEFAULT)
    {
        setCnVFlags(getSetupCnVRequestFlag(), &dcSetup->requestOps);
    }

    /* Set the performance function to the actual performance function
     * that actually does all the performance
     */
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)dcChainPerformance;

    /* Update the setup_g with buffersize */
    testSetupData_g[testTypeCount_g].packetSize = testBufferSize;
    /* Operation for compression chaining */
    dcSetup->chainOperation = chainOperation;
    /* Number of sessions for compression chaining */
    dcSetup->numSessions = numSessions;
    /* Data compression setup data */
    dcSetup->setupData.compLevel = compLevel;
    dcSetup->setupData.compType = algorithm;
    dcSetup->setupData.sessDirection = direction;
    dcSetup->legacyChainRequest = 1;
#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
    dcSetup->setupData.huffType = huffmanType;
#else
    dcSetup->setupData.huffType = CPA_DC_HT_STATIC;
#endif
    dcSetup->setupData.sessState = state;
    dcSetup->specific_sleeptime_flag = CPA_FALSE;
    if (CPA_DC_STATELESS == state)
    {
        dcSetup->sleepTime = sleepTime;
        dcSetup->compRate = compRate;
    }
#if DC_API_VERSION_LESS_THAN(1, 6)
    /* Windows size is depreciated in new versions of the QA-API */
    dcSetup->setupData.deflateWindowSize = windowsSize;
#endif
    dcSetup->corpus = corpusType;
    dcSetup->corpusFileIndex = corpusFileIndex;
    dcSetup->bufferSize = testBufferSize;
    dcSetup->dcSessDir = direction;
    dcSetup->syncFlag = syncFlag;
    dcSetup->numLoops = numLoops;
    dcSetup->isDpApi = CPA_FALSE;

    dcSetup->setupData.autoSelectBestHuffmanTree = gAutoSelectBestMode;
    dcSetup->setupData.checksum = gChecksum;
    dcSetup->passCriteria = getPassCriteria();

    /* Stateful Compression only supports a single request in-flight for
     * each session. Each request can be submitted asynchronously but is
     * required to block until callback fires.
     * For the sample code we only issue Stateful requests synchronously.
     */
    if (CPA_DC_STATEFUL == state)
    {
        PRINT_ERR("Stateful Compression not supported in this sample code\n");
    }

    dcSetup->symSetupData.sessionPriority = priority;
    dcSetup->symSetupData.symOperation = opType;
    dcSetup->symSetupData.cipherSetupData.cipherAlgorithm = cipherAlg;
    dcSetup->symSetupData.cipherSetupData.cipherDirection = cipherDir;
    dcSetup->symSetupData.cipherSetupData.cipherKeyLenInBytes =
        cipherKeyLengthInBytes;
    dcSetup->symSetupData.hashSetupData.hashAlgorithm = hashAlg;
    dcSetup->symSetupData.hashSetupData.hashMode = hashMode;
    dcSetup->symSetupData.hashSetupData.digestResultLenInBytes =
        authKeyLengthInBytes;
    dcSetup->symSetupData.digestIsAppended = CPA_FALSE;
    dcSetup->symSetupData.verifyDigest = CPA_FALSE;

    return status;
}


static CpaStatus qatDcChainInduceOverflow(compression_test_params_t *setup,
                                          CpaDcSessionHandle pSessionHandle,
                                          CpaBufferList *srcBufferListArray,
                                          CpaBufferList *destBufferListArray,
                                          CpaBufferList *cmpBufferListArray,
                                          CpaDcChainRqResults *resultArray,
                                          CpaDcChainOpData *chainOpDataArray)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcChainRqResults *overflowResArray = NULL;
    Cpa32U numListOverflowed = 0;
    Cpa32U i, loop;
    const Cpa32U numLoops = setup->numLoops;
    const Cpa32U reductionFactor = 6;
    const Cpa32U lowerThresholdDstBufferSize = BUFFER_SIZE_128;
    Cpa32U *destBufferMemSize = NULL;
    const Cpa32U numLists = setup->numLists;

    overflowResArray = qaeMemAlloc(numLists * sizeof(CpaDcChainRqResults));
    if (overflowResArray == NULL)
    {
        PRINT_ERR("Failed to Allocate Overflow Result Array\n");
        return CPA_STATUS_FAIL;
    }

    destBufferMemSize = qaeMemAlloc(numLists * sizeof(Cpa32U));
    if (destBufferMemSize == NULL)
    {
        PRINT_ERR("Malloc failed for size %llu\n",
                  (unsigned long long)(numLists * sizeof(Cpa32U)));
        goto err;
    }

    setup->numLoops = 1;
    for (loop = 0; loop < numLoops; loop++)
    {
        /* Reduce the size of the destination buffer to
         * induce overflow
         */
        for (i = 0; i < numLists; i++)
        {
            if (destBufferListArray[i].numBuffers > 1)
            {
                PRINT_ERR("Multiple Flat buffer per list not supported\n");
                goto err;
            }
            /* Store the allocated size */
            destBufferMemSize[i] =
                destBufferListArray[i].pBuffers[0].dataLenInBytes;
            /* Pretend that the capacity of Output buffer is less than input
             * buffer
             * by the amount of 2 ^ reductionFactor.
             */
            destBufferListArray[i].pBuffers[0].dataLenInBytes =
                srcBufferListArray[i].pBuffers[0].dataLenInBytes >>
                reductionFactor;
            /* Adjust the length if it falls below threshold */
            if (destBufferListArray[i].pBuffers[0].dataLenInBytes <
                lowerThresholdDstBufferSize)
            {
                destBufferListArray[i].pBuffers[0].dataLenInBytes =
                    lowerThresholdDstBufferSize;
            }
        }
        /* Set value for chainOpData*/
        status = qatDcChainCompressData(setup,
                                        pSessionHandle,
                                        CPA_DC_DIR_COMPRESS,
                                        srcBufferListArray,
                                        destBufferListArray,
                                        cmpBufferListArray,
                                        resultArray,
                                        chainOpDataArray);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Failed to chaining compress Data with overflow setup\n");
            goto err;
        }
        /* Check all that have overflowed and construct a new SGL to handle
         * remaining data.
         */
        for (i = 0; i < numLists; i++)
        {
            if (resultArray[i].dcStatus == CPA_DC_OVERFLOW)
            {
                if (resultArray[i].consumed == 0 &&
                    resultArray[i].produced == 0)
                {
                    PRINT_ERR("Overflow reported with no bytes produced or"
                              " consumed for list: %d\n",
                              i);
                    status = CPA_STATUS_FAIL;
                    goto err;
                }
                numListOverflowed++;

                /* Find the amount of data unconsumed */
                srcBufferListArray[i].pBuffers[0].dataLenInBytes -=
                    resultArray[i].consumed;
                srcBufferListArray[i].pBuffers[0].pData +=
                    resultArray[i].consumed;
                /* Update Output buffers for the amount of bytes produced.
                 * From the amount of memory actually allocated for the buffer,
                 * reduced the amount taken up by produced data.
                 */
                destBufferListArray[i].pBuffers[0].dataLenInBytes =
                    destBufferMemSize[i] - resultArray[i].produced;
                destBufferListArray[i].pBuffers[0].pData +=
                    resultArray[i].produced;

                switch (setup->chainOperation)
                {
                    case CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT:
                        chainOpDataArray[i * setup->numSessions + 1]
                            .pCySymOp->messageLenToCipherInBytes =
                            srcBufferListArray[i].pBuffers[0].dataLenInBytes;
                        break;
                    case CPA_DC_CHAIN_DECRYPT_THEN_DECOMPRESS:
                        chainOpDataArray[i * setup->numSessions]
                            .pCySymOp->messageLenToCipherInBytes =
                            srcBufferListArray[i].pBuffers[0].dataLenInBytes;
                        break;
                    case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
                        chainOpDataArray[i * setup->numSessions]
                            .pCySymOp->messageLenToHashInBytes =
                            srcBufferListArray[i].pBuffers[0].dataLenInBytes;
                        break;
                    default:
                        PRINT_ERR("Unsupported chaining operation.\n");
                        status = CPA_STATUS_FAIL;
                        goto err;
                }
            }
            else
            {
                /* The test design aims to induce overflow in each list of
                 * the payload as the entire list array is submitted again.
                 * However if some lists don't overflow even after output
                 * buffer reduction, highlight the fact and ignore.
                 */
                PRINT("!!No Overflow reported for List Num: %d status: %d\n",
                      i,
                      resultArray[i].dcStatus);
            }
        } /* Post overflow processing for all lists*/

        if (numListOverflowed == 0)
        {
            PRINT_ERR("No overflow detected for Loop count: %d\n", loop + 1);
            status = CPA_STATUS_FAIL;
            goto err;
        }

        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Failed to setup chaining operation data\n");
            goto err;
        }
        /* Resubmits the bufferlist after updating buffers for overflow */
        status = qatDcChainCompressData(setup,
                                        pSessionHandle,
                                        CPA_DC_DIR_COMPRESS,
                                        srcBufferListArray,
                                        destBufferListArray,
                                        cmpBufferListArray,
                                        overflowResArray,
                                        chainOpDataArray);

        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Failed to compress unconsumed data after overflow\n");
            goto err;
        }

        /* Recheck that there is no overflow now and update the produced length
         * to the sum of pre overflow and post overflow compression.
         */
        for (i = 0; i < numLists; i++)
        {
            if (overflowResArray[i].dcStatus != CPA_DC_OVERFLOW)
            {
                if (overflowResArray[i].dcStatus != CPA_DC_OK)
                {
                    PRINT("Status: %d reported post overflow for List %d\n",
                          overflowResArray[i].dcStatus,
                          i);
                }
                /* Check if the list element overflowed previously and
                 * update accordingly.
                 */
                if (resultArray[i].dcStatus == CPA_DC_OVERFLOW)
                {
                    destBufferListArray[i].pBuffers[0].dataLenInBytes =
                        resultArray[i].produced + overflowResArray[i].produced;
                    destBufferListArray[i].pBuffers[0].pData -=
                        resultArray[i].produced;
                    srcBufferListArray[i].pBuffers[0].dataLenInBytes =
                        resultArray[i].consumed + overflowResArray[i].consumed;
                    srcBufferListArray[i].pBuffers[0].pData -=
                        resultArray[i].consumed;
                    /* Update the first pass result Array to have the total of
                     * bytes
                     * produced and consumed from the two operations.
                     */
                    resultArray[i].consumed += overflowResArray[i].consumed;
                    resultArray[i].produced += overflowResArray[i].produced;

                    /* Update stats here after the second call as performance
                     * stats
                     * are initialized on each call qatCompressData.
                     */
                    setup->performanceStats->overflow++;
                }
            } /* status != OVERFLOW */
            else
            {
                PRINT_ERR("Overflow reported AGAIN for list: %d\n", i);
                status = CPA_STATUS_FAIL;
                goto err;
            }
        } /* end of for loop for numLists */

        /* Update the stats from with result array as it has sum
         * of pre and post overflow.
         */
        dcChainScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, setup->dcSessDir);
        /* Perform Decompression using SW on the compressed
         * buffer.
         */
        status = qatSwChainDecompress(
            setup, destBufferListArray, cmpBufferListArray, resultArray);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("SW Decompression Failed\n");
            goto err;
        }

        qatDcChainUpdateProducedBufferLength(
            setup, cmpBufferListArray, resultArray);
        /* Compare the input buffer to SW decompressed buffer */
        status = qatCmpBuffers(setup, srcBufferListArray, cmpBufferListArray);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Buffer comparison Failed for Loop count:%d\n", loop + 1);
            goto err;
        }

        /*reset destination buffer*/
        status = qatCompressResetBufferList(setup,
                                            destBufferListArray,
                                            setup->packetSizeInBytesArray,
                                            CPA_FALSE);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Failed to reset buffer lists\n");
            goto err;
        }
        status = qatCompressResetBufferList(
            setup, cmpBufferListArray, setup->packetSizeInBytesArray, CPA_TRUE);
        if (stopTestsIsEnabled_g == CPA_TRUE && exitLoopFlag_g == CPA_TRUE)
        {
            break;
        }

        numListOverflowed = 0;
    } /* end of for loop for NumLoops */

err:
    qaeMemFree((void **)&destBufferMemSize);
    qaeMemFree((void **)&overflowResArray);
    return status;
}
