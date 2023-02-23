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
 * @file cpa_sample_code_dc_utils.c
 *
 * @defgroup compressionThreads
 *
 * @ingroup compressionThreads
 *
 * @description
 * Contains function prototypes and #defines used throughout code
 * and macros
 *
 ***************************************************************************/

#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_dc_utils.h"
#include "qat_perf_latency.h"
#include "qat_perf_utils.h"
#include "qat_perf_cycles.h"
#include "icp_sal_poll.h"

#define MAX_SESSION_REMOVE_RETRIES (15)

static struct
{
    corpus_type_t corpusType;
    Cpa32U corpusFileIndex;
} extCorpusInfo = {0, 0};

typedef struct
{
    corpus_type_t corpusType;
    const char *const corpusName;
    corpus_data_t corpusData;
} corpusInfo;

static compute_test_result_func_t pfuncPassCriteria = NULL;
static Cpa32U setupCnVRequestFlag = CNV_FLAG_DEFAULT;

Cpa32U dcPollingInterval_g = OPERATIONS_POLLING_INTERVAL;
EXPORT_SYMBOL(dcPollingInterval_g);
CpaBoolean gUseStatefulLite = CPA_FALSE;
EXPORT_SYMBOL(gUseStatefulLite);
CpaDcChecksum gChecksum = CPA_DC_NONE;
EXPORT_SYMBOL(gChecksum);
CpaDcAutoSelectBest gAutoSelectBestMode = CPA_DC_ASB_DISABLED;
EXPORT_SYMBOL(gAutoSelectBestMode);
CpaBoolean testOverFlow_g = CPA_FALSE;
EXPORT_SYMBOL(testOverFlow_g);
CpaBoolean gRetainPartials = CPA_FALSE;
EXPORT_SYMBOL(gRetainPartials);
long dcPollingThreadsInterval_g = DEFAULT_POLL_INTERVAL_NSEC;
EXPORT_SYMBOL(dcPollingThreadsInterval_g);
CpaBoolean disableAdditionalCmpbufferSize_g = CPA_FALSE;
EXPORT_SYMBOL(disableAdditionalCmpbufferSize_g);
#if DC_API_VERSION_AT_LEAST(3, 1)
volatile CpaBoolean LZ4BlockIndependence_g = CPA_TRUE;
CpaStatus setLZ4BlockIndependence(CpaBoolean val)
{
    if (val != 0)
    {
        LZ4BlockIndependence_g = CPA_TRUE;
    }
    else
    {
        LZ4BlockIndependence_g = CPA_FALSE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(LZ4BlockIndependence_g);
EXPORT_SYMBOL(setLZ4BlockIndependence);
#endif
CpaStatus setChecksum(CpaDcChecksum checksum)
{
    gChecksum = checksum;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setChecksum);

CpaStatus setAutoSelectBestMode(CpaDcAutoSelectBest mode)
{
    gAutoSelectBestMode = mode;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setAutoSelectBestMode);

CpaStatus disableAdditionalCmpbufferSize(CpaBoolean value)
{
    disableAdditionalCmpbufferSize_g = value;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableAdditionalCmpbufferSize);

CpaStatus setTestOverFlow(CpaBoolean value)
{
    testOverFlow_g = value;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setTestOverFlow);

void setDcPollingThreadsInterval(long interval)
{
    dcPollingThreadsInterval_g = interval;
}
EXPORT_SYMBOL(setDcPollingThreadsInterval);

/*********** Call Back Function **************/
void dcPerformCallback(void *pCallbackTag, CpaStatus status)
{
    compression_test_params_t *test_struct =
        (compression_test_params_t *)pCallbackTag;
    perf_data_t *pPerfData = test_struct->performanceStats;

    /*check perf_data pointer is valid*/
    if (NULL == pPerfData)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    pPerfData->responses++;
    /*check status */
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR(
            "%s Failed, status = %d, responseCount %llu, submissions %u\n",
            __func__,
            status,
            (long long int)pPerfData->responses,
            pPerfData->submissions);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
#ifdef LATENCY_CODE
    if (latency_enable)
    {
        /* Did we setup the array pointer? */
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(
            pPerfData->response_times, pPerfData->threadReturnStatus);

        /*Have we sampled too many buffer operations?*/
        if (pPerfData->latencyCount >= MAX_LATENCY_COUNT)
        {
            PRINT_ERR("max latency count exceeded\n");
            pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
        }
        /* Is this the buffer we calculate latency on?
         * And have we calculated too many for array? */
        if (pPerfData->threadReturnStatus == CPA_STATUS_SUCCESS &&
            pPerfData->responses == pPerfData->nextCount &&
            pPerfData->latencyCount < MAX_LATENCY_COUNT)
        {
            int i = pPerfData->latencyCount;
            /*Now get the end timestamp - before any print outs*/
            pPerfData->response_times[i] = sampleCodeTimestamp();
            pPerfData->nextCount += pPerfData->countIncrement;
            pPerfData->latencyCount++;
        }
    }
#endif

    if ((CPA_TRUE == gUseStatefulLite) ||
        (CPA_DC_STATEFUL == test_struct->setupData.sessState) ||
#if (DC_API_VERSION_AT_LEAST(3, 2))
        (reliability_g && ((CPA_TRUE == test_struct->useE2E) ||
                           (CPA_TRUE == test_struct->useE2EVerify))) ||
#else
        (CPA_TRUE == test_struct->useE2E) ||
        (CPA_TRUE == test_struct->useE2EVerify) ||
#endif
        (CPA_TRUE == test_struct->useStatefulLite))
    {
        sampleCodeSemaphorePost(&pPerfData->comp);
    }

    /* Release the semaphore if all the responses are gathered.
     * In case of failure, the number of responses will be for
     * submissions that had happened till the point of failure.
     */
    if ((pPerfData->responses >= pPerfData->numOperations) ||
        (pPerfData->threadReturnStatus != CPA_STATUS_SUCCESS &&
         pPerfData->responses >= pPerfData->submissions))
    {
        /* generate end of the cycle stamp for Corpus */
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
        sampleCodeSemaphorePost(&pPerfData->comp);
    }
}

Cpa32U expansionFactor_g = 1;
EXPORT_SYMBOL(expansionFactor_g);
#ifdef ZERO_BYTE_LAST_REQUEST
CpaBoolean zeroByteLastRequest_g = CPA_FALSE;
#endif
extern int signOfLife;

/* Global array of polling threads */
sample_code_thread_t *dcPollingThread_g = NULL;

/* Number of Compression instances enabled for polling */
Cpa32U numDcPolledInstances_g = 0;

/* Global array of instance handles */
CpaInstanceHandle *dcInstances_g = NULL;

/* Number of Compression instances available */
Cpa16U numDcInstances_g = 0;

/* Flag to indicate if the DC services are started */
volatile CpaBoolean dc_service_started_g = CPA_FALSE;

/* Flag to indicate if the DC polling threads have been created */
volatile CpaBoolean dc_polling_started_g = CPA_FALSE;

/* flag to define weather to use zlib to compress data before decompression*/
CpaBoolean useZlib_g = CPA_FALSE;
EXPORT_SYMBOL(useZlib_g);

/* Dynamic Buffer List buffer list used to start DC Services */
CpaBufferList ***pInterBuffList_g = NULL;

#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
CpaDcHuffType huffmanType_g = CPA_DC_HT_FULL_DYNAMIC;
#else
CpaDcHuffType huffmanType_g = CPA_DC_HT_STATIC;
#endif
EXPORT_SYMBOL(huffmanType_g);

#define SINGLE_INTER_BUFF_LIST (1)
#ifndef DO_CRYPTO
Cpa32U getThroughput(Cpa64U numPackets, Cpa32U packetSize, perf_cycles_t cycles)
{
    unsigned long long bytesSent = 0;
    unsigned long long time = cycles;
    unsigned long long rate = 0;
    /* declare frequency in kiloHertz*/
    Cpa32U freq = sampleCodeGetCpuFreq();
    bytesSent = packetSize;
    bytesSent = bytesSent * numPackets;

    /*get time in milli seconds by dividing numberOfClockCycles by frequency
     * in kilohertz ie: cycles/(cycles/millsec) = time (mSec) */
    do_div(time, freq);
    /*check that the sample time was not to small*/
    if (time == 0)
    {
        PRINT_ERR("Sample time is too small to calculate throughput\n");
        return 0;
    }
    /*set rate to be bytesSent, once we perform the do_div rate changes from
     * bytes to bytes/milli second or kiloBytes/second*/
    rate = bytesSent;
    /*rate in kBps*/
    do_div(rate, time);
    /*check that the rate is high enough to convert to Megabits per second*/
    if (rate == 0)
    {
        PRINT_ERR("no data was sent to calculate throughput\n");
        return 0;
    }
    /* convert Kilobytes/second to Kilobits/second*/
    rate = rate * NUM_BITS_IN_BYTE;
    /*then convert rate from Kilobits/second to Megabits/second*/
    do_div(rate, KILOBITS_IN_MEGABITS);
    return (Cpa32U)rate;
}
#endif /* not DO_CRYPTO */

static void freeDcBufferList(CpaBufferList **buffListArray,
                             Cpa32U numberOfBufferList)
{
    Cpa32U i = 0, j = 0;
    Cpa32U numberOfBuffers = 0;

    i = numberOfBufferList;
    for (i = 0; i < numberOfBufferList; i++)
    {
        numberOfBuffers = buffListArray[i]->numBuffers;
        for (j = 0; j < numberOfBuffers; j++)
        {
            if (buffListArray[i]->pBuffers[j].pData != NULL)
            {
                qaeMemFreeNUMA((void **)&buffListArray[i]->pBuffers[j].pData);
                buffListArray[i]->pBuffers[j].pData = NULL;
            }
        }
        if (buffListArray[i]->pBuffers != NULL)
        {

            qaeMemFreeNUMA((void **)&buffListArray[i]->pBuffers);
            buffListArray[i]->pBuffers = NULL;
        }

        if (buffListArray[i]->pPrivateMetaData != NULL)
        {

            qaeMemFreeNUMA((void **)&buffListArray[i]->pPrivateMetaData);
        }
    }
}


static char *canterburyFileNames[] = {
    /* Single Canterbury corpus file is a concatenation of the following
     * files:
     "alice29.txt", "asyoulik.txt", "cp.html",
     "fields.c","grammar.lsp", "kennedy.xls", "lcet10.txt" ,
     "plrabn12.txt", "ptt5"
     */
    "canterbury"};

static char *calgaryFullFileNames[] = {
    /* Single Calgary corpus file is a concatenation of the following
     * files: */
    "bib",
    "book1",
    "book2",
    "geo",
    "news",
    "obj1",
    "obj2",
    "paper1",
    "paper2",
    "paper3",
    "paper4",
    "paper5",
    "paper6",
    "pic",
    "progc",
    "progl",
    "progp",
    "trans"};

static char *calgarySixFileNames[] =
    {"paper4", "paper5", "paper4", "paper5", "paper5", "paper4"};

static char *calgaryFileNames[] = {
    /* Single Calgary file is a concatenation of all files
     * in calgaryFullFileNames.
     */
    "calgary"};


static char *signOfLifeFile[] = {/* 1st 32k of calgary corpus file */
                                 "calgary32"};

static char *zeroLengthFilenames[] =
    {"zero1", "progp", "paper4", "zero2", "obj1", "zero3"};

static char *overflowFileNames[] =
    {"paper4", "bib", "book1", "book2", "geo", "news"};

static char *overflowAndZeroFileNames[] =
    {"zero1", "book1", "zero2", "book2", "news", "zero2"};

#define CORPUS_DATA_EMPTY                                                      \
    {                                                                          \
        NULL, NULL, 0, CPA_FALSE                                               \
    }
#define CORPUS_DATA_INIT(name)                                                 \
    {                                                                          \
        NULL, name, sizeof(name) / sizeof(name[0]), CPA_FALSE                  \
    }
#define CORPUS_TO_STR(corpus) #corpus
#define CORPUS_STR(corpus) CORPUS_TO_STR(corpus)
static corpusInfo corpus[] = {
    [CANTERBURY_CORPUS] = { CANTERBURY_CORPUS,
                            CORPUS_STR(CANTERBURY_CORPUS),
                            CORPUS_DATA_INIT(canterburyFileNames) },
    [CALGARY_CORPUS] = { CALGARY_CORPUS,
                         CORPUS_STR(CALGARY_CORPUS),
                         CORPUS_DATA_INIT(calgaryFileNames) },
    [RANDOM] = { RANDOM, CORPUS_STR(RANDOM), CORPUS_DATA_EMPTY },
    [SIGN_OF_LIFE_CORPUS] = { SIGN_OF_LIFE_CORPUS,
                              CORPUS_STR(SIGN_OF_LIFE_CORPUS),
                              CORPUS_DATA_INIT(signOfLifeFile) },
    [CALGARY_SIX_FILES] = { CALGARY_SIX_FILES,
                            CORPUS_STR(CALGARY_SIX_FILES),
                            CORPUS_DATA_INIT(calgarySixFileNames) },
    [CALGARY_FULL_SET] = { CALGARY_FULL_SET,
                           CORPUS_STR(CALGARY_FULL_SET),
                           CORPUS_DATA_INIT(calgaryFullFileNames) },
    [ZERO_LENGTH_FILE] = { ZERO_LENGTH_FILE,
                           CORPUS_STR(ZERO_LENGTH_FILE),
                           CORPUS_DATA_INIT(zeroLengthFilenames) },
    [OVERFLOW_FILE] = { OVERFLOW_FILE,
                        CORPUS_STR(OVERFLOW_FILE),
                        CORPUS_DATA_INIT(overflowFileNames) },
    [OVERFLOW_AND_ZERO_FILE] = { OVERFLOW_AND_ZERO_FILE,
                                 CORPUS_STR(OVERFLOW_AND_ZERO_FILE),
                                 CORPUS_DATA_INIT(overflowAndZeroFileNames) },
    [CORPUS_TYPE_EXTENDED] = { CORPUS_TYPE_EXTENDED,
                               CORPUS_STR(CORPUS_TYPE_EXTENDED),
                               CORPUS_DATA_EMPTY },

    /*All Corpus type should added above
     * CORPUS_TYPE_INVALID.
     */
    [CORPUS_TYPE_INVALID] = { CORPUS_TYPE_INVALID,
                              CORPUS_STR(CORPUS_TYPE_INVALID),
                              CORPUS_DATA_EMPTY }
};

#define CHECK_CORPUS_TYPE_AND_RETURN(type, status)                             \
    do                                                                         \
    {                                                                          \
        if ((type) < 0 || (type) >= MAX_NUM_CORPUS_TYPE)                       \
        {                                                                      \
            PRINT_ERR("Invalid corpus Type %d\n", corpusType);                 \
            return status;                                                     \
        }                                                                      \
    } while (0)

static CpaStatus populateCorpusInternal(corpus_type_t corpusType)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numFiles = 0, i = 0;
    char **pCorpusFileNamesArray = NULL;
    corpus_file_t *pCorpusFile = NULL;

    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, CPA_STATUS_FAIL);

    if (corpus[corpusType].corpusData.read == CPA_FALSE)
    {
        pCorpusFileNamesArray = corpus[corpusType].corpusData.fileNameArray;
        numFiles = corpus[corpusType].corpusData.numFilesInCorpus;
        if (numFiles == 0)
        {
            PRINT_ERR("No files in corpus %s. Failed to populate\n",
                      corpus[corpusType].corpusName);
            return CPA_STATUS_FAIL;
        }
        if (pCorpusFileNamesArray == NULL)
        {
            PRINT_ERR(
                "No File Names present for Corpus %s. Failed to populate\n",
                corpus[corpusType].corpusName);
            return CPA_STATUS_FAIL;
        }
        /* allocate the memory for the corpus file structure */
        pCorpusFile = qaeMemAlloc(numFiles * sizeof(corpus_file_t));
        if (NULL == pCorpusFile)
        {
            PRINT_ERR(" Unable to allocate Memory for "
                      "corpus structure\n");
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < numFiles; i++)
        {
            switch (corpusType)
            {
                default:
                    status = getCorpusFile(&pCorpusFile[i].corpusBinaryData,
                                           pCorpusFileNamesArray[i],
                                           &pCorpusFile[i].corpusBinaryDataLen);
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Get \"%s\" Corpus File Failed\n",
                          pCorpusFileNamesArray[i]);
                qaeMemFree((void **)&pCorpusFile);
                return CPA_STATUS_FAIL;
            }
        }
        corpus[corpusType].corpusData.fileArray = pCorpusFile;
        corpus[corpusType].corpusData.read = CPA_TRUE;
    }

    return status;
}

CpaStatus populateCorpus(Cpa32U buffSize, corpus_type_t corpusType)
{
    return populateCorpusInternal(corpusType);
}
EXPORT_SYMBOL(populateCorpus);

inline Cpa32U getNumFilesInCorpus(corpus_type_t corpusType)
{
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, 0);
    return corpus[corpusType].corpusData.numFilesInCorpus;
}
EXPORT_SYMBOL(getNumFilesInCorpus);

inline char **getFileNamesInCorpus(corpus_type_t corpusType)
{
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, NULL);
    return corpus[corpusType].corpusData.fileNameArray;
}
EXPORT_SYMBOL(getFileNamesInCorpus);

inline const corpus_file_t *getFilesInCorpus(corpus_type_t corpusType)
{
    if (corpus[corpusType].corpusData.read == CPA_FALSE)
    {
        populateCorpusInternal(corpusType);
    }
    return corpus[corpusType].corpusData.fileArray;
}
EXPORT_SYMBOL(getFilesInCorpus);

inline const char *getCorpusName(corpus_type_t corpusType)
{
    static const char *unknownCorpus = "UNKNOWN CORPUS";
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, unknownCorpus);
    return corpus[corpusType].corpusName;
}

inline const char *getFileNameInCorpus(corpus_type_t corpusType,
                                       Cpa32U fileIndex)
{
    static const char *unknownCorpusFile = "UNKNOWN CORPUS FILE";
    CHECK_CORPUS_TYPE_AND_RETURN(corpusType, unknownCorpusFile);

    return corpus[corpusType].corpusData.fileNameArray[fileIndex];
}

inline corpus_type_t getCorpusTypeFromName(const char *name,
                                           const unsigned long name_max_size)
{
    corpus_type_t type = 0;
    for (; type < MAX_NUM_CORPUS_TYPE; type++)
    {
        if (strncmp(name, corpus[type].corpusName, name_max_size) == 0)
        {
            return type;
        }
    }
    return CORPUS_TYPE_INVALID;
}

void setCorpusType(corpus_type_t type)
{
    extCorpusInfo.corpusType = type;
}
EXPORT_SYMBOL(setCorpusType);

corpus_type_t getCorpusType(void)
{
    return extCorpusInfo.corpusType;
}

void setCorpusFileIndex(Cpa32U index)
{
    extCorpusInfo.corpusFileIndex = index;
}
EXPORT_SYMBOL(setCorpusFileIndex);

Cpa32U getCorpusFileIndex(void)
{
    return extCorpusInfo.corpusFileIndex;
}

compute_test_result_func_t getPassCriteria(void)
{
    return pfuncPassCriteria;
}

void setPassCriteria(compute_test_result_func_t pfunc)
{
    pfuncPassCriteria = pfunc;
}
EXPORT_SYMBOL(setPassCriteria);

Cpa32U getSetupCnVRequestFlag(void)
{
    return setupCnVRequestFlag;
}
EXPORT_SYMBOL(getSetupCnVRequestFlag);

void setSetupCnVRequestFlag(Cpa32U flag)
{
    setupCnVRequestFlag = flag;
}
EXPORT_SYMBOL(setSetupCnVRequestFlag);

CpaStatus startDcServices(Cpa32U buffSize, Cpa32U numBuffs)

{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U size = 0;
    Cpa32U i = 0, k = 0;
    Cpa32U nodeId = 0;
    Cpa32U nProcessorsOnline = 0;
    Cpa16U numBuffers = 0;
    CpaBufferList **tempBufferList = NULL;

    /*if the service started flag is false*/
    if (dc_service_started_g == CPA_FALSE)
    {
        /* Get the number of DC Instances */
        status = cpaDcGetNumInstances(&numDcInstances_g);
        /* Check the status */
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Get Number of DC instances\n");
            return CPA_STATUS_FAIL;
        }
        /* Check if at least one DC instance are present */
        if (0 == numDcInstances_g)
        {
            PRINT_ERR(" DC Instances are not present\n");
            return CPA_STATUS_FAIL;
        }
        /* Allocate memory for all the instances */
        dcInstances_g =
            qaeMemAlloc(sizeof(CpaInstanceHandle) * numDcInstances_g);
        /* Check For NULL */
        if (NULL == dcInstances_g)
        {
            PRINT_ERR(" Unable to allocate memory for Instances \n");
            return CPA_STATUS_FAIL;
        }

        /* Get DC Instances */
        status = cpaDcGetInstances(numDcInstances_g, dcInstances_g);
        /* Check Status */
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Get DC instances\n");
            qaeMemFree((void **)&dcInstances_g);
            return CPA_STATUS_FAIL;
        }

        /* Allocate the buffer list pointers to the number of Instances
         * this buffer list list is used only in case of dynamic
         * compression
         */
        pInterBuffList_g = (CpaBufferList ***)qaeMemAlloc(
            numDcInstances_g * sizeof(CpaBufferList **));
        /* Check For NULL */
        if (NULL == pInterBuffList_g)
        {
            PRINT_ERR("Unable to allocate dynamic buffer List\n");
            qaeMemFree((void **)&dcInstances_g);
            return CPA_STATUS_FAIL;
        }

        /* Initialize memory for buffer lists */
        memset(
            pInterBuffList_g, 0, numDcInstances_g * sizeof(CpaBufferList **));

        /* Start the Loop to create Buffer List for each instance*/
        for (i = 0; i < numDcInstances_g; i++)
        {
            /* get the Node ID for each instance Handle */
            status = sampleCodeDcGetNode(dcInstances_g[i], &nodeId);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to get NodeId\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            status =
                cpaDcGetNumIntermediateBuffers(dcInstances_g[i], &numBuffers);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to allocate Memory for Dynamic Buffer\n");
                qaeMemFree((void **)&dcInstances_g);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            if (numBuffers > 0)
            {
                /* allocate the buffer list memory for the dynamic Buffers
                 * only applicable for CPM prior to gen4 as it is done in HW */
                pInterBuffList_g[i] =
                    qaeMemAllocNUMA(sizeof(CpaBufferList *) * numBuffers,
                                    nodeId,
                                    BYTE_ALIGNMENT_64);
                if (NULL == pInterBuffList_g[i])
                {
                    PRINT_ERR("Unable to allocate Memory for Dynamic Buffer\n");
                    qaeMemFree((void **)&dcInstances_g);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }

                /* get the size of the Private meta data
                 * needed to create Buffer List
                 */
                status = cpaDcBufferListGetMetaSize(
                    dcInstances_g[i], numBuffers, &size);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Get Meta Size Data Failed\n");
                    qaeMemFree((void **)&dcInstances_g);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
            }
            tempBufferList = pInterBuffList_g[i];
            for (k = 0; k < numBuffers; k++)
            {
                tempBufferList[k] = (CpaBufferList *)qaeMemAllocNUMA(
                    sizeof(CpaBufferList), nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k])
                {
                    PRINT(" %s:: Unable to allocate memory for "
                          "tempBufferList\n",
                          __FUNCTION__);
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pPrivateMetaData =
                    qaeMemAllocNUMA(size, nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pPrivateMetaData)
                {
                    PRINT(" %s:: Unable to allocate memory for "
                          "pPrivateMetaData\n",
                          __FUNCTION__);
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->numBuffers = ONE_BUFFER_DC;
                /* allocate flat buffers */
                tempBufferList[k]->pBuffers = qaeMemAllocNUMA(
                    (sizeof(CpaFlatBuffer)), nodeId, BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pBuffers)
                {
                    PRINT_ERR("Unable to allocate memory for pBuffers\n");
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }

                tempBufferList[k]->pBuffers[0].pData = qaeMemAllocNUMA(
                    (size_t)expansionFactor_g * EXTRA_BUFFER * buffSize,
                    nodeId,
                    BYTE_ALIGNMENT_64);
                if (NULL == tempBufferList[k]->pBuffers[0].pData)
                {
                    PRINT_ERR("Unable to allocate Memory for pBuffers\n");
                    qaeMemFree((void **)&dcInstances_g);
                    freeDcBufferList(tempBufferList, k + 1);
                    qaeMemFree((void **)&pInterBuffList_g);
                    return CPA_STATUS_FAIL;
                }
                tempBufferList[k]->pBuffers[0].dataLenInBytes =
                    expansionFactor_g * EXTRA_BUFFER * buffSize;
            }

            /* When starting the DC Instance, the API expects that the
             * private meta data should be greater than the dataLength
             */
            /* Configure memory Configuration Function */
            status = cpaDcSetAddressTranslation(
                dcInstances_g[i], (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error setting memory config for instance\n");
                qaeMemFree((void **)&dcInstances_g);
                freeDcBufferList(pInterBuffList_g[i], numBuffers);
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
            /* Start DC Instance */
            status = cpaDcStartInstance(
                dcInstances_g[i], numBuffers, pInterBuffList_g[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Unable to start DC Instance\n");
                qaeMemFree((void **)&dcInstances_g);
                freeDcBufferList(pInterBuffList_g[i], numBuffers);
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
                qaeMemFree((void **)&pInterBuffList_g);
                return CPA_STATUS_FAIL;
            }
        }
        /*set the started flag to true*/
        dc_service_started_g = CPA_TRUE;
    }

    /*determine number of cores on system and limit the number of cores to be
     * used to be the smaller of the numberOf Instances or the number of cores*/
    nProcessorsOnline = sampleCodeGetNumberOfCpus();
    if (nProcessorsOnline > numDcInstances_g)
    {
        setCoreLimit(numDcInstances_g);
    }
    return status;
}
EXPORT_SYMBOL(startDcServices);

void freeCorpus(void)
{
    Cpa32U i = 0;
    corpus_type_t corpusType = 0;
    Cpa32U numFiles = 0;
    corpus_file_t *pCorpusFile = NULL;

    for (; corpusType < MAX_NUM_CORPUS_TYPE; corpusType++)
    {
        pCorpusFile = corpus[corpusType].corpusData.fileArray;
        numFiles = getNumFilesInCorpus(corpusType);
        if (numFiles == 0 || pCorpusFile == NULL)
        {
            continue;
        }
        for (i = 0; i < numFiles; i++)
        {
            if (NULL != pCorpusFile[i].corpusBinaryData)
            {
                qaeMemFree((void **)&pCorpusFile[i].corpusBinaryData);
                pCorpusFile[i].corpusBinaryData = NULL;
            }
        }
        /* Free corpus File Structure */
        qaeMemFree((void **)&pCorpusFile);
        corpus[corpusType].corpusData.fileArray = NULL;
        corpus[corpusType].corpusData.read = CPA_FALSE;
    }
    return;
}

/*stop all acceleration services*/
CpaStatus stopDcServices(void)
{
    Cpa32U i = 0, j = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBufferList **tempBufferList = NULL;
    Cpa16U numBuffers = 0;

    /*stop only if the services is in a started state*/
    if (dc_service_started_g == CPA_TRUE)
    {
        for (i = 0; i < numDcInstances_g; i++)
        {
            /* Free the Dynamic Buffers allocated
             * while starting DC Services
             */
            tempBufferList = pInterBuffList_g[i];
            status =
                cpaDcGetNumIntermediateBuffers(dcInstances_g[i], &numBuffers);
            for (j = 0; j < numBuffers; j++)
            {

                qaeMemFreeNUMA((void **)&tempBufferList[j]->pBuffers->pData);
                qaeMemFreeNUMA((void **)&tempBufferList[j]->pPrivateMetaData);
                qaeMemFreeNUMA((void **)&tempBufferList[j]->pBuffers);
                qaeMemFreeNUMA((void **)&tempBufferList[j]);
            }
            if (NULL != pInterBuffList_g[i])
            {
                /* free the buffer List*/
                qaeMemFreeNUMA((void **)&pInterBuffList_g[i]);
            }

            /*stop all instances*/
            cpaDcStopInstance(dcInstances_g[i]);
        }
        qaeMemFree((void **)&pInterBuffList_g);
        /*set the service started flag to false*/
        dc_service_started_g = CPA_FALSE;
    }
    /* Free the corpus Data */
    freeCorpus();
    if (dc_polling_started_g == CPA_TRUE)
    {
        /* set polling flag to false */
        dc_polling_started_g = CPA_FALSE;
        /* Wait for all threads_g to complete */
        for (i = 0; i < numDcPolledInstances_g; i++)
        {
            sampleCodeThreadJoin(&dcPollingThread_g[i]);
        }
        if (numDcPolledInstances_g > 0)
        {
            qaeMemFree((void **)&dcPollingThread_g);
            numDcPolledInstances_g = 0;
        }
    }
    if (dcInstances_g != NULL)
    {
        qaeMemFree((void **)&dcInstances_g);
        dcInstances_g = NULL;
    }
    return status;
}

CpaStatus calculateRequireBuffers(compression_test_params_t *dcSetup)
{
    Cpa32U numberOfBuffers = 0, i = 0;
    Cpa32U numFiles = getNumFilesInCorpus(dcSetup->corpus);
    const corpus_file_t *const pCorpusFile = getFilesInCorpus(dcSetup->corpus);


    if (dcSetup->corpusFileIndex >= numFiles)
    {
        dcSetup->corpusFileIndex = 0;
    }

    dcSetup->numberOfBuffers = qaeMemAlloc(numFiles * sizeof(Cpa32U));
    if (NULL == dcSetup->numberOfBuffers)
    {
        PRINT("Could not allocate memory for dcSetup numberOfBuffers array");
        return CPA_STATUS_FAIL;
    }
    for (i = 0; i < numFiles; i++)
    {
        /*get number of full sized buffers, ignoring the last bit less than
         * the full buffer size*/
        if (pCorpusFile[i].corpusBinaryDataLen < dcSetup->bufferSize)
        {
            PRINT("Warning the input file size(%d) is less than the specified "
                  "buffer size(%d), results may be skewed\n",
                  pCorpusFile[i].corpusBinaryDataLen,
                  dcSetup->bufferSize);
            numberOfBuffers = 1;
        }
        else
        {
            numberOfBuffers =
                pCorpusFile[i].corpusBinaryDataLen / dcSetup->bufferSize;
        }
        dcSetup->numberOfBuffers[i] = numberOfBuffers;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(calculateRequireBuffers);

CpaStatus dcCreatePollingThreadsIfPollingIsEnabled(void)
{
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa16U i = 0, j = 0, numCreatedPollingThreads = 0;
    Cpa32U coreAffinity = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    performance_func_t *pollFnArr = NULL;
#ifdef SC_CORE_NUM_POLICY
    Cpa32U numCores = 0;
    numCores = sampleCodeGetNumberOfCpus();
    if (numCores <= 0)
    {
        PRINT_ERR("sampleCodeGetNumberOfCpus() failed\n");
        return CPA_STATUS_FAIL;
    }
#endif
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
    int fd = -1;
#endif

    if (CPA_FALSE == dc_polling_started_g)
    {
        instanceInfo2 =
            qaeMemAlloc(numDcInstances_g * sizeof(CpaInstanceInfo2));
        if (NULL == instanceInfo2)
        {
            PRINT_ERR("Failed to allocate memory for pInstanceInfo2");
            return CPA_STATUS_FAIL;
        }
        pollFnArr = qaeMemAlloc(numDcInstances_g * sizeof(performance_func_t));
        if (NULL == pollFnArr)
        {
            PRINT_ERR("Failed to allocate memory for polling functions\n");
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
        for (i = 0; i < numDcInstances_g; i++)
        {
            status = cpaDcInstanceGetInfo2(dcInstances_g[i], &instanceInfo2[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                qaeMemFree((void **)&instanceInfo2);
                qaeMemFree((void **)&pollFnArr);
                return CPA_STATUS_FAIL;
            }
            pollFnArr[i] = NULL;
            if (CPA_TRUE == instanceInfo2[i].isPolled)
            {
                numDcPolledInstances_g++;
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
                status = icp_sal_DcGetFileDescriptor(dcInstances_g[i], &fd);
                if (CPA_STATUS_SUCCESS == status)
                {
                    pollFnArr[i] = sampleCodeDcEventPoll;
                    icp_sal_DcPutFileDescriptor(dcInstances_g[i], fd);
                    continue;
                }
                else if (CPA_STATUS_FAIL == status)
                {
                    PRINT_ERR("Error getting file descriptor for Event based "
                              "instance #%d\n",
                              i);
                    qaeMemFree((void **)&instanceInfo2);
                    qaeMemFree((void **)&pollFnArr);
                    return CPA_STATUS_FAIL;
                }
/* else feature is unsupported and sampleCodeDcPoll() is to be
 * used.
 */
#endif
                pollFnArr[i] = sampleCodeDcPoll;
            }
        }
        if (0 == numDcPolledInstances_g)
        {
            qaeMemFree((void **)&instanceInfo2);
            qaeMemFree((void **)&pollFnArr);
            return CPA_STATUS_SUCCESS;
        }
        dcPollingThread_g =
            qaeMemAlloc(numDcPolledInstances_g * sizeof(sample_code_thread_t));
        if (NULL == dcPollingThread_g)
        {
            PRINT_ERR("Failed to allocate memory for polling threads\n");
            qaeMemFree((void **)&instanceInfo2);
            qaeMemFree((void **)&pollFnArr);
            return CPA_STATUS_FAIL;
        }
        for (i = 0; i < numDcInstances_g; i++)
        {
            if (NULL != pollFnArr[i])
            {
                status = sampleCodeThreadCreate(
                    &dcPollingThread_g[numCreatedPollingThreads],
                    NULL,
                    pollFnArr[i],
                    dcInstances_g[i]);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("Error starting polling thread %d\n", status);
                    /*attempt to stop any started service, we don't check status
                     * as some instances may not have been started and
                     * this might return fail*/
                    qaeMemFree((void **)&instanceInfo2);
                    qaeMemFree((void **)&pollFnArr);
                    return CPA_STATUS_FAIL;
                }
                /*loop of the instanceInfo coreAffinity bitmask to find
                 * the core affinity*/
                for (j = 0; j < CPA_MAX_CORES; j++)
                {
                    if (CPA_BITMAP_BIT_TEST(instanceInfo2[i].coreAffinity, j))
                    {
#if defined(USER_SPACE)
                        coreAffinity = j;
#else
                        coreAffinity = j + 1;
#endif
                        break;
                    }
                }
#ifdef SC_CORE_NUM_POLICY
                if (numDcInstances_g % numCores == 0)
                {
                    /* To avoid recalculated and original core
                     * assignment equality */
                    coreAffinity =
                        (coreAffinity + numDcInstances_g + 1) % numCores;
                }
                else
                {
                    coreAffinity = (coreAffinity + numDcInstances_g) % numCores;
                }
#endif
                sampleCodeThreadBind(
                    &dcPollingThread_g[numCreatedPollingThreads], coreAffinity);
                sampleCodeThreadStart(
                    &dcPollingThread_g[numCreatedPollingThreads]);
                numCreatedPollingThreads++;
            }
        }
        qaeMemFree((void **)&instanceInfo2);
        qaeMemFree((void **)&pollFnArr);
        dc_polling_started_g = CPA_TRUE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dcCreatePollingThreadsIfPollingIsEnabled);

inline CpaStatus dcDpPollNumOperations(perf_data_t *pPerfData,
                                       CpaInstanceHandle instanceHandle,
                                       Cpa64U numOperations)
{
    Cpa32U retries;
    return dcDpPollNumOperationsRetries(
        pPerfData, instanceHandle, numOperations, &retries);
}

CpaStatus dcDpPollNumOperationsRetries(perf_data_t *pPerfData,
                                       CpaInstanceHandle instanceHandle,
                                       Cpa64U numOperations,
                                       Cpa32U *retries)
{
    CpaStatus status = CPA_STATUS_FAIL;

    perf_cycles_t startCycles = 0, totalCycles = 0;
    Cpa32U freq = sampleCodeGetCpuFreq();
    *retries = 0;
    startCycles = sampleCodeTimestamp();

    while (pPerfData->responses != numOperations)
    {
        coo_poll_dp_dc(pPerfData, instanceHandle, &status);
        /* in case when polling is used to process request's response
           which is not handled by coo measurement */
        if (CPA_STATUS_FAIL == status)
            status = icp_sal_DcPollDpInstance(instanceHandle, 0);
        if (CPA_STATUS_FAIL == status)
        {
            PRINT_ERR("Error polling instance\n");
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_RETRY == status)
        {
            (*retries)++;
            AVOID_SOFTLOCKUP;
        }
        totalCycles = (sampleCodeTimestamp() - startCycles);
        if (totalCycles > 0)
        {
            do_div(totalCycles, freq);
        }

        if (totalCycles > SAMPLE_CODE_WAIT_DEFAULT)
        {
            PRINT_ERR("Timeout on polling remaining Operations\n");
            PRINT("Expected %llu responses, revieved %llu\n",
                  (unsigned long long)numOperations,
                  (unsigned long long)pPerfData->responses);
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

/* If an error has occurred in-between the submissions loop,
 * wait for all inflight requests has been processed.
 * Post this function, memory resources that are used by the
 * SAL library are de-allocated.
 */
CpaStatus waitForInflightRequestAfterError(perf_data_t *perfData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U tryLoops = 0;

    /* Give 3 tries to collect all the responses while waiting on the
     * semaphore. The ASYNC callback should release the semaphore
     * only when the responses are equal to expected number of operation.
     * If an error occurs in between, the subsequent submission of requests
     * is stopped and hence the response will always be less than expected
     * number of operation, meaning the semaphore is never released by the
     * callback function. Hence it should be timing out always here.
     */
    while ((perfData->responses < perfData->submissions) && tryLoops < 3)
    {
        status =
            sampleCodeSemaphoreWait(&perfData->comp, SAMPLE_CODE_WAIT_DEFAULT);
        tryLoops++;
    }

    if (perfData->responses < perfData->submissions)
    {
        PRINT_ERR("WARNING: Not all inflight request collected!! "
                  "Submissions: %u, Responses: %llu\n",
                  perfData->submissions,
                  (unsigned long long)perfData->responses);
        if (status == CPA_STATUS_SUCCESS)
        {
            PRINT_ERR(" \tWait Semaphore released!\n");
        }
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus waitForSemaphore(perf_data_t *perfData)
{
    Cpa64S responsesReceived = INITIAL_RESPONSE_COUNT;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /*wait for the callback to receive all responses and free the
     * semaphore, or if in sync mode, the semaphore should already be free*/

    while (sampleCodeSemaphoreWait(&perfData->comp, SAMPLE_CODE_WAIT_DEFAULT) !=
           CPA_STATUS_SUCCESS)
    {
        if (INITIAL_RESPONSE_COUNT != responsesReceived &&
            responsesReceived != (Cpa64S)perfData->numOperations &&
            responsesReceived == (Cpa64S)perfData->responses)
        {
            PRINT_ERR("System is not responding\n");
            PRINT("Responses expected/received: %llu/%llu\n",
                  (unsigned long long)perfData->numOperations,
                  (unsigned long long)perfData->responses);
            status = CPA_STATUS_FAIL;
            break;
        }
        else
        {
            responsesReceived = perfData->responses;
        }
    }
    return status;
}
EXPORT_SYMBOL(waitForSemaphore);

CpaStatus sampleCodeDcGetNode(CpaInstanceHandle instanceHandle, Cpa32U *node)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceInfo2 pInstanceInfo2;
    status = cpaDcInstanceGetInfo2(instanceHandle, &pInstanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to get Node affinity\n");
        return status;
    }
    *node = pInstanceInfo2.nodeAffinity;
    return status;
}
EXPORT_SYMBOL(sampleCodeDcGetNode);

/* Change to a compression callback tag with parameter for poll interval */
void sampleCodeDcPoll(CpaInstanceHandle instanceHandle_in)
{
    CpaStatus status = CPA_STATUS_FAIL;
#ifdef USER_SPACE
    struct timespec reqTime, remTime;
    reqTime.tv_sec = 0;
    reqTime.tv_nsec = dcPollingThreadsInterval_g;
#endif
    while (dc_service_started_g == CPA_TRUE)
    {
        /*poll for 0 means process all packets on the ET ring */
        status = icp_sal_DcPollInstance(instanceHandle_in, 0);
        if (CPA_STATUS_SUCCESS == status || CPA_STATUS_RETRY == status)
        {
            /* do nothing */
        }
        else
        {
            PRINT_ERR("ERROR icp_sal_DcPollInstance returned status %d\n",
                      status);
            error_flag_g = CPA_TRUE;
            break;
        }
#ifdef USER_SPACE
        nanosleep(&reqTime, &remTime);
#else
        sampleCodeSleepMilliSec(DEFAULT_POLL_INTERVAL_KERNEL);
#endif
    }
    sampleCodeThreadExit();
}


CpaStatus stopDcServicesFromPrintStats(thread_creation_data_t *dummy_ptr)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* stop DC Services */
    status = stopDcServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop DC services\n");
    }
    return status;
}
EXPORT_SYMBOL(stopDcServicesFromPrintStats);

CpaStatus dcPrintStats(thread_creation_data_t *data)
{
    perf_cycles_t numOfCycles = {0};
    perf_data_t stats = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U throughput = 0;
    Cpa32U bytesConsumed = 0, bytesProduced = 0;
    Cpa32U averageNumLoops = 0;
    compression_test_params_t *dcSetup =
        (compression_test_params_t *)data->setupPtr;


    /* stop DC Services */
    status = stopDcServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop DC services\n");
        return status;
    }

    memset(&stats, 0, sizeof(perf_data_t));
    stats.averagePacketSizeInBytes = data->packetSize;

    /* get the longest start time and longest End time
     * from the performance stats structure
     */
    getLongestCycleCount(&stats, data->performanceStats, data->numberOfThreads);

    /* Get the total number of responses, bytes consumed and bytes produced
     * for all the threads */
    for (i = 0; i < data->numberOfThreads; i++)
    {
        if (CPA_STATUS_FAIL == data->performanceStats[i]->threadReturnStatus)
        {
            return CPA_STATUS_FAIL;
        }
        if (!signOfLife)
        {
#ifdef LATENCY_CODE
            if (latency_enable)
            {
                /* Accumulate over all tests. Before using later we divide
                 * by number of threads: data->numberOfThreads*/
                stats.minLatency += data->performanceStats[i]->minLatency;
                stats.aveLatency += data->performanceStats[i]->aveLatency;
                stats.maxLatency += data->performanceStats[i]->maxLatency;
            }
#endif
#ifdef LATENCY_CODE
            if (latency_debug)
            {
                /* NOTE: These numbers are in CPU cycles here */
                PRINT(", minLatency: %llu, aveLatency: %llu, maxLatency: %llu",
                      data->performanceStats[i]->minLatency,
                      data->performanceStats[i]->aveLatency,
                      data->performanceStats[i]->maxLatency);
                PRINT("\n");
            }
#endif
        }
        if (iaCycleCount_g)
        {
            stats.offloadCycles += data->performanceStats[i]->offloadCycles;
        }
        averageNumLoops += data->performanceStats[i]->numLoops;
        stats.retries += data->performanceStats[i]->retries;
        stats.responses += data->performanceStats[i]->responses;
        bytesConsumed += data->performanceStats[i]->bytesConsumedPerLoop;
        bytesProduced += data->performanceStats[i]->bytesProducedPerLoop;
        dcSetup->numLoops = data->performanceStats[i]->numLoops;
        clearPerfStats(data->performanceStats[i]);
    }
    /* get the maximum number of cycles Required */
    numOfCycles = (stats.endCyclesTimestamp - stats.startCyclesTimestamp);

    /*don't assume that all threads submitted all loops
     * if the averageNumLoops does not equal the plan then that means
     * the thread exited early, so we need to use the average to calculate the
     * throughput*/
    do_div(averageNumLoops, data->numberOfThreads);
    if (averageNumLoops != dcSetup->numLoops)
    {
        dcSetup->numLoops = averageNumLoops;
    }
    /* Print Statistics */
    dcPrintTestData(dcSetup);
    PRINT("Number of threads      %d\n", data->numberOfThreads);
    PRINT("Total Responses        %llu\n", (unsigned long long)stats.responses);
    PRINT("Total Retries          %llu\n", (unsigned long long)stats.retries);
    PRINT("Clock Cycles Start     %llu\n", stats.startCyclesTimestamp);
    PRINT("Clock Cycles End       %llu\n", stats.endCyclesTimestamp);
    if (!signOfLife)
    {
        PRINT("Total Cycles           %llu\n", numOfCycles);
        PRINT("CPU Frequency(kHz)     %u\n", sampleCodeGetCpuFreq());
        throughput =
            getDcThroughput(bytesConsumed, numOfCycles, dcSetup->numLoops);
        {
            PRINT("Throughput(Mbps)       %u\n", throughput);
        }

        dcCalculateAndPrintCompressionRatio(bytesConsumed, bytesProduced);
        if (iaCycleCount_g)
        {
            do_div(stats.offloadCycles, data->numberOfThreads);
            PRINT("Avg Offload Cycles        %llu\n", stats.offloadCycles);
        }
#ifdef LATENCY_CODE
        if (latency_enable)
        {
            perf_cycles_t statsLatency = 0;
            perf_cycles_t cpuFreqKHz = sampleCodeGetCpuFreq();

            /* Display how long it took on average to process a buffer in uSecs
             * Also include min/max to show variance */
            do_div(stats.minLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.minLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Min. Latency (uSecs)      %llu\n", statsLatency);
            do_div(stats.aveLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.aveLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Ave. Latency (uSecs)      %llu\n", statsLatency);
            do_div(stats.maxLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.maxLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Max. Latency (uSecs)      %llu\n", statsLatency);
        }
#endif
    }
    return status;
}
EXPORT_SYMBOL(dcPrintStats);

#ifdef SC_CHAINING_ENABLED
CpaStatus dcChainPrintStats(thread_creation_data_t *data)
{
    perf_cycles_t numOfCycles = {0};
    perf_data_t stats = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U throughput = 0, currentThroughput = 0;
    Cpa32U bytesConsumed = 0, bytesProduced = 0;
    Cpa32U averageNumLoops = 0;
    compression_test_params_t *dcSetup =
        (compression_test_params_t *)data->setupPtr;


    /* stop DC Services */
    status = stopDcServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop DC services\n");
        return status;
    }

    memset(&stats, 0, sizeof(perf_data_t));
    stats.averagePacketSizeInBytes = data->packetSize;

    /* get the longest start time and longest End time
     * from the performance stats structure
     */
    getLongestCycleCount(&stats, data->performanceStats, data->numberOfThreads);

    /* Get the total number of responses, bytes consumed and bytes produced
     * for all the threads */
    for (i = 0; i < data->numberOfThreads; i++)
    {
        if (CPA_STATUS_FAIL == data->performanceStats[i]->threadReturnStatus)
        {
            return CPA_STATUS_FAIL;
        }

        if (!signOfLife)
        {
            numOfCycles = data->performanceStats[i]->endCyclesTimestamp -
                          data->performanceStats[i]->startCyclesTimestamp;
            throughput =
                getDcThroughput(data->performanceStats[i]->bytesConsumedPerLoop,
                                numOfCycles,
                                data->performanceStats[i]->numLoops);
            PRINT(
                "Thread: %u, Retries: %llu, throughput: %u, consumedPerLoop %u,\
                    numLoops %u",
                i,
                (unsigned long long)data->performanceStats[i]->retries,
                throughput,
                data->performanceStats[i]->bytesConsumedPerLoop,
                data->performanceStats[i]->numLoops);
            if (latency_enable)
            {
                /* NOTE: These numbers are in CPU cycles here */
                PRINT(", minLatency: %llu, aveLatency: %llu, maxLatency: %llu",
                      data->performanceStats[i]->minLatency,
                      data->performanceStats[i]->aveLatency,
                      data->performanceStats[i]->maxLatency);

                /* Accumulate over all tests. Before using later we divide
                 * by number of threads: data->numberOfThreads*/
                stats.minLatency += data->performanceStats[i]->minLatency;
                stats.aveLatency += data->performanceStats[i]->aveLatency;
                stats.maxLatency += data->performanceStats[i]->maxLatency;
            }
            PRINT("\n");
        }

        averageNumLoops += data->performanceStats[i]->numLoops;
        stats.retries += data->performanceStats[i]->retries;
        stats.responses += data->performanceStats[i]->responses;
        bytesConsumed += data->performanceStats[i]->bytesConsumedPerLoop;
        bytesProduced += data->performanceStats[i]->bytesProducedPerLoop;
        dcSetup->numLoops = data->performanceStats[i]->numLoops;
        currentThroughput += data->performanceStats[i]->currentThroughput;
        clearPerfStats(data->performanceStats[i]);
    }
    /* get the maximum number of cycles Required */
    numOfCycles = (stats.endCyclesTimestamp - stats.startCyclesTimestamp);

    /*don't assume that all threads submitted all loops
     * if the averageNumLoops does not equal the plan then that means
     * the thread exited early, so we need to use the average to calculate the
     * throughput*/
    do_div(averageNumLoops, data->numberOfThreads);
    if (averageNumLoops != dcSetup->numLoops)
    {
        dcSetup->numLoops = averageNumLoops;
    }
    /* Print Statistics */
    dcChainPrintTestData(dcSetup);
    PRINT("Number of threads      %d\n", data->numberOfThreads);
    PRINT("Total Responses        %llu\n", (unsigned long long)stats.responses);
    PRINT("Total Retries          %llu\n", (unsigned long long)stats.retries);
    PRINT("Clock Cycles Start     %llu\n", stats.startCyclesTimestamp);
    PRINT("Clock Cycles End       %llu\n", stats.endCyclesTimestamp);
    if (!signOfLife)
    {
        PRINT("Total Cycles           %llu\n", numOfCycles);
        PRINT("CPU Frequency(kHz)     %u\n", sampleCodeGetCpuFreq());
        throughput =
            getDcThroughput(bytesConsumed, numOfCycles, dcSetup->numLoops);
        if (sleepTime_enable)
        {
            PRINT("Throughput(Mbps)       %u\n", currentThroughput);
        }
        else
        {
            PRINT("Throughput(Mbps)       %u\n", throughput);
        }

        dcCalculateAndPrintCompressionRatio(bytesConsumed, bytesProduced);
        if (latency_enable)
        {
            perf_cycles_t statsLatency = 0;
            perf_cycles_t cpuFreqKHz = sampleCodeGetCpuFreq();

            /* Display how long it took on average to process a buffer in uSecs
             * Also include min/max to show variance */
            do_div(stats.minLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.minLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Min. Latency (uSecs)   %llu\n", statsLatency);
            do_div(stats.aveLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.aveLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Ave. Latency (uSecs)   %llu\n", statsLatency);
            do_div(stats.maxLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.maxLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Max. Latency (uSecs)   %llu\n", statsLatency);
        }
    }
    return status;
}
EXPORT_SYMBOL(dcChainPrintStats);
#endif

void dcPrintTestData(compression_test_params_t *dcSetup)
{
    PRINT("API                    ");
    if (dcSetup->isDpApi)
    {
        PRINT("Data_Plane\n");
    }
    else
    {
        PRINT("Traditional\n");
    }
    PRINT("Session State          ");
    switch (dcSetup->setupData.sessState)
    {
        case (CPA_DC_STATEFUL):
            PRINT("STATEFUL\n");
            break;
        case (CPA_DC_STATELESS):
            PRINT("STATELESS\n");
            break;
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.sessState);
            break;
    }

    PRINT("Algorithm              ");
    switch (dcSetup->setupData.compType)
    {
        case (CPA_DC_DEFLATE):
            PRINT("DEFLATE\n");
            break;
#if DC_API_VERSION_AT_LEAST(3, 1)
        case (CPA_DC_LZ4):
            PRINT("CPA_DC_LZ4\n");
            break;
        case (CPA_DC_LZ4S):
            PRINT("CPA_DC_LZ4S\n");
            break;
#endif
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.compType);
            break;
    }

    PRINT("Huffman Type           ");
    switch (dcSetup->setupData.huffType)
    {
        case (CPA_DC_HT_STATIC):
            PRINT("STATIC\n");
            break;
        case (CPA_DC_HT_FULL_DYNAMIC):
            PRINT("DYNAMIC\n");
            break;
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.huffType);
            break;
    }

    PRINT("Mode                   ");
    switch (dcSetup->syncFlag)
    {
        case (SYNC):
            PRINT("SYNCHRONOUS\n");
            break;
        case (ASYNC):
            PRINT("ASYNCHRONOUS\n");
            break;
        default:
            PRINT("Unsupported %d\n", dcSetup->syncFlag);
            break;
    }

    if ((CPA_DC_STATELESS == dcSetup->setupData.sessState) &&
        (CPA_DC_DIR_COMPRESS == dcSetup->dcSessDir))
    {
        PRINT("CNV Enabled            ");
        switch (dcSetup->requestOps.compressAndVerify)
        {
            case (CPA_TRUE):
                PRINT("YES\n");
                break;
            case (CPA_FALSE):
                PRINT("NO\n");
                break;
            default:
                PRINT("Not known\n");
                break;
        }
    }

    PRINT("Direction              ");
    switch (dcSetup->dcSessDir)
    {
        case (CPA_DC_DIR_COMPRESS):
            PRINT("COMPRESS");
            break;
        case (CPA_DC_DIR_DECOMPRESS):
            PRINT("DECOMPRESS");
            break;
        case (CPA_DC_DIR_COMBINED):
            PRINT("COMBINED");
            break;
        default:
            PRINT("Unsupported        %d\n", dcSetup->setupData.sessDirection);
            break;
    }
    if (useZlib_g)
    {
        PRINT("(from SW lib compressed data)\n");
    }
    else
    {
        PRINT("\n");
    }

    PRINT("Packet Size            %d\n", dcSetup->bufferSize);

    PRINT("Compression Level      %d\n", dcSetup->setupData.compLevel);

    PRINT("Corpus                 ");
    PRINT("%s\n", getCorpusName(dcSetup->corpus));
    PRINT("Corpus Filename        ");
    PRINT("%s\n",
          getFileNameInCorpus(dcSetup->corpus, dcSetup->corpusFileIndex));
#if DC_API_VERSION_AT_LEAST(2, 2)
    PRINT("CNV Recovery Enabled   ");
    switch (CNV_RECOVERY(&dcSetup->requestOps))
    {
        case (CPA_TRUE):
            PRINT("YES\n");
            break;
        case (CPA_FALSE):
            PRINT("NO\n");
            break;
        default:
            PRINT("Not known\n");
            break;
    }
#endif
}
EXPORT_SYMBOL(dcPrintTestData);

#if defined(SC_CHAINING_ENABLED) || defined(SC_CHAINING_EXT_ENABLED)
void dcChainPrintTestData(compression_test_params_t *chainSetup)
{
    PRINT("API                    ");
    if (chainSetup->isDpApi)
    {
        PRINT("Data_Plane\n");
    }
    else
    {
        PRINT("Traditional\n");
    }

    PRINT("Algorithm Chaining     ");
    switch (chainSetup->chainOperation)
    {
        case (CPA_DC_CHAIN_HASH_THEN_COMPRESS):
            if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                    CPA_CY_SYM_HASH_SHA1 &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("SHA1 Stateless Static Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA256 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("SHA2-256 Stateless Static Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA1 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("SHA1 Stateless Dynamic Compression Chaining\n");
            }
            else if (chainSetup->symSetupData.hashSetupData.hashAlgorithm ==
                         CPA_CY_SYM_HASH_SHA256 &&
                     chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                     chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("SHA2-256 Stateless Dynamic Compression Chaining\n");
            }
            else
            {
                PRINT("Unsupported Algorithm Chaining\n");
            }
            break;
        case (CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT):
            if (chainSetup->symSetupData.cipherSetupData.cipherAlgorithm ==
                    CPA_CY_SYM_CIPHER_AES_CBC &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_STATIC)
            {
                PRINT("Static Stateless Compress AES_CBC Encrypt Chaining\n");
            }
            break;
        case (CPA_DC_CHAIN_COMPRESS_THEN_AEAD):
            if (chainSetup->symSetupData.cipherSetupData.cipherAlgorithm ==
                    CPA_CY_SYM_CIPHER_AES_GCM &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("Static Stateless Compress AES_GCM Encrypt Chaining\n");
            }
            break;
        case (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS):
            if (chainSetup->symSetupData.cipherSetupData.cipherAlgorithm ==
                    CPA_CY_SYM_CIPHER_AES_GCM &&
                chainSetup->setupData.sessState == CPA_DC_STATELESS &&
                chainSetup->setupData.huffType == CPA_DC_HT_FULL_DYNAMIC)
            {
                PRINT("Static Stateless AES_GCM Decrypt Decompression "
                      "Chaining\n");
            }
            break;
        default:
            PRINT("Unsupported        %d\n", chainSetup->chainOperation);
            break;
    }

    PRINT("Mode                   ");
    switch (chainSetup->syncFlag)
    {
        case (SYNC):
            PRINT("SYNCHRONOUS\n");
            break;
        case (ASYNC):
            PRINT("ASYNCHRONOUS\n");
            break;
        default:
            PRINT("Unsupported %d\n", chainSetup->syncFlag);
            break;
    }

    if ((CPA_DC_STATELESS == chainSetup->setupData.sessState) &&
        (CPA_DC_DIR_COMPRESS == chainSetup->dcSessDir))
    {
        PRINT("CNV Enabled            ");
        switch (chainSetup->requestOps.compressAndVerify)
        {
            case (CPA_TRUE):
                PRINT("YES\n");
                break;
            case (CPA_FALSE):
                PRINT("NO\n");
                break;
            default:
                PRINT("Not known\n");
                break;
        }
    }

#ifdef SC_CHAINING_EXT_ENABLED
    if ((CPA_DC_CHAIN_COMPRESS_THEN_AEAD == chainSetup->chainOperation) ||
        (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS == chainSetup->chainOperation))
    {
        PRINT("AppendCRC Enabled      ");
        switch (chainSetup->appendCRC)
        {
            case (CPA_TRUE):
                PRINT("YES\n");
                break;
            case (CPA_FALSE):
                PRINT("NO\n");
                break;
            default:
                PRINT("Not known\n");
                break;
        }
    }
#endif

    PRINT("Direction              ");
    switch (chainSetup->dcSessDir)
    {
        case (CPA_DC_DIR_COMPRESS):
            PRINT("COMPRESS");
            break;
        case (CPA_DC_DIR_DECOMPRESS):
            PRINT("DECOMPRESS");
            break;
        case (CPA_DC_DIR_COMBINED):
            PRINT("COMBINED");
            break;
        default:
            PRINT("Unsupported        %d\n",
                  chainSetup->setupData.sessDirection);
            break;
    }
    if (useZlib_g)
    {
        PRINT("(from SW lib compressed data)\n");
    }
    else
    {
        PRINT("\n");
    }

    PRINT("Packet Size            %d\n", chainSetup->bufferSize);

    PRINT("Compression Level      %d\n", chainSetup->setupData.compLevel);

    PRINT("Corpus                 ");
    PRINT("%s\n", getCorpusName(chainSetup->corpus));
    PRINT("Corpus Filename        ");
    PRINT("%s\n",
          getFileNameInCorpus(chainSetup->corpus, chainSetup->corpusFileIndex));
#if (CPA_DC_API_VERSION_NUM_MAJOR > 1) && (CPA_DC_API_VERSION_NUM_MINOR > 1)
    PRINT("CNV Recovery Enabled   ");
    switch (CNV_RECOVERY(&chainSetup->requestOps))
    {
        case (CPA_TRUE):
            PRINT("YES\n");
            break;
        case (CPA_FALSE):
            PRINT("NO\n");
            break;
        default:
            PRINT("Not known\n");
            break;
    }
#endif
}
EXPORT_SYMBOL(dcChainPrintTestData);

#endif

void dcDpSetBytesProducedAndConsumed(CpaDcDpOpData ***opdata,
                                     perf_data_t *perfData,
                                     compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    for (i = 0; i < numFiles; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            perfData->bytesConsumedPerLoop += opdata[i][j]->results.consumed;
            perfData->bytesProducedPerLoop += opdata[i][j]->results.produced;
        }
    }
}

void dcSetBytesProducedAndConsumed(CpaDcRqResults ***cmpResult,
                                   perf_data_t *perfData,
                                   compression_test_params_t *setup)
{

    Cpa32U i = 0, j = 0;
    Cpa32U numFiles = getNumFilesInCorpus(setup->corpus);

    for (i = 0; i < numFiles; i++)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {

            perfData->bytesConsumedPerLoop += cmpResult[i][j]->consumed;
            perfData->bytesProducedPerLoop += cmpResult[i][j]->produced;
        }
    }
}
EXPORT_SYMBOL(dcSetBytesProducedAndConsumed);

CpaStatus dcCalculateAndPrintCompressionRatio(Cpa32U bytesConsumed,
                                              Cpa32U bytesProduced)
{
    Cpa32U ratio = 0, remainder = 0;

    if (0 == bytesConsumed)
    {
        PRINT("Divide by zero error on calculating compression ratio\n");
        return CPA_STATUS_FAIL;
    }
#ifdef USER_SPACE
    PRINT("Compression Ratio      %.04f\n",
          ((float)bytesProduced / bytesConsumed));
    return CPA_STATUS_SUCCESS;
#endif

    ratio = bytesProduced * SCALING_FACTOR_1000;
    do_div(ratio, bytesConsumed);
    remainder = ratio % BASE_10;
    ratio = bytesProduced * SCALING_FACTOR_100;
    do_div(ratio, bytesConsumed);
    PRINT("Compression Ratio      0.%d%d\n", ratio, remainder);
    return CPA_STATUS_SUCCESS;
}

Cpa32U getDcThroughput(Cpa32U totalBytes,
                       perf_cycles_t cycles,
                       Cpa32U numOfLoops)
{
    unsigned long long bytesSent = 0;
    unsigned long long time = cycles;
    unsigned long long rate = 0;
    /* declare frequency in kiloHertz*/
    Cpa32U freq = sampleCodeGetCpuFreq();
    bytesSent = totalBytes;

    /*get time in milli seconds by dividing numberOfClockCycles by frequency
     * in kilohertz ie: cycles/(cycles/millsec) = time (mSec) */
    do_div(time, freq);
    /*check that the sample time was not to small*/
    if (time == 0)
    {
        PRINT_ERR("Sample time is too small to calculate throughput\n");
        return 0;
    }
    /*set rate to be bytesSent, once we perform the do_div rate changes from
     * bytes to bytes/milli second or kiloBytes/second*/
    rate = bytesSent * numOfLoops;
    /*rate in kBps*/
    do_div(rate, time);
    /*check that the rate is high enough to convert to Megabits per second*/
    if (rate == 0)
    {
        PRINT_ERR("no data was sent to calculate throughput\n");
        return 0;
    }
    /* convert Kilobytes/second to Kilobits/second*/
    rate = rate * NUM_BITS_IN_BYTE;
    /*then convert rate from Kilobits/second to Megabits/second*/
    do_div(rate, KILOBITS_IN_MEGABITS);
    return (Cpa32U)rate;
}

/*This function tells the compression sample code to use zLib software to
 * compress the data prior to calling the decompression*/
CpaStatus useZlib(void)
{
#ifdef USE_ZLIB
    useZlib_g = CPA_TRUE;
#else
#endif
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(useZlib);

/*This function tells the compression sample code to use zLib software to
 * compress the data prior to calling the decompression*/
CpaStatus useAccelCompression(void)
{
    useZlib_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(useAccelCompression);

#ifdef ZERO_BYTE_LAST_REQUEST
CpaStatus enableZeroByteRequest(void)
{
    zeroByteLastRequest_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableZeroByteRequest);

CpaStatus disableZeroByteRequest(void)
{
    zeroByteLastRequest_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableZeroByteRequest);
#endif
/*****************************************************************************
 * * @description
 * Poll the number of dc operations
 * ***************************************************************************/
CpaStatus dcPollNumOperations(perf_data_t *pPerfData,
                              CpaInstanceHandle instanceHandle,
                              Cpa64U numOperations)
{
    CpaStatus status = CPA_STATUS_FAIL;

    perf_cycles_t startCycles = 0, totalCycles = 0;
    Cpa32U freq = sampleCodeGetCpuFreq();
    startCycles = sampleCodeTimestamp();

    while (pPerfData->responses != numOperations)
    {
        coo_poll_trad_dc(pPerfData, instanceHandle, &status);
        if (CPA_STATUS_FAIL == status)
        {
            PRINT_ERR("Error polling instance\n");
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_RETRY == status)
        {
            AVOID_SOFTLOCKUP;
        }
        totalCycles = (sampleCodeTimestamp() - startCycles);
        if (totalCycles > 0)
        {
            do_div(totalCycles, freq);
        }

        if (totalCycles > SAMPLE_CODE_WAIT_DEFAULT)
        {
            PRINT_ERR("Timeout on polling remaining Operations\n");
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dcPollNumOperations);

CpaStatus dynamicHuffmanEnabled(CpaInstanceHandle *dcInstanceHandle,
                                CpaBoolean *isEnabled)
{
    CpaDcInstanceCapabilities capabilities = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle pLocalDcInstanceHandle = NULL;
    Cpa16U numInstances = 0;

    /* Initialize to CPA_FALSE */
    *isEnabled = CPA_FALSE;

    if (NULL == dcInstanceHandle)
    {
        status = cpaDcGetNumInstances(&numInstances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                      "cpaDcGetNumInstances failed with status: %d\n",
                      status);
            return CPA_STATUS_FAIL;
        }
        if (0 == numInstances)
        {
            PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                      "No DC instances available");
            return CPA_STATUS_FAIL;
        }
        status = cpaDcGetInstances(1, &pLocalDcInstanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                      "cpaDcGetInstances failed with status: %d"
                      "\n",
                      status);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        pLocalDcInstanceHandle = *dcInstanceHandle;
    }
    status = cpaDcQueryCapabilities(pLocalDcInstanceHandle, &capabilities);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to check if dynamic Huffman is enabled, "
                  "cpaDcQueryCapabilities failed with status: %d"
                  "\n",
                  status);
        return CPA_STATUS_FAIL;
    }
    if (CPA_TRUE == capabilities.dynamicHuffman)
    {
        *isEnabled = CPA_TRUE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dynamicHuffmanEnabled);

CpaStatus dcSampleCreateStatefulContextBuffer(Cpa32U buffSize,
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
EXPORT_SYMBOL(dcSampleCreateStatefulContextBuffer);

CpaStatus dcSampleFreeStatefulContextBuffer3(CpaBufferList *pBuffListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (NULL == pBuffListArray)
    {
        PRINT_ERR(" Buffers List Array is NULL\n");
        /* Return Silent */
        return CPA_STATUS_FAIL;
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

    return status;
}
void freeBuffers(CpaBufferList ***pBuffListArray,
                 Cpa32U numberOfFiles,
                 compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;


    if (NULL == pBuffListArray)
    {
        /* Return Silent */
        return;
    }
    if (0 != numberOfFiles)
    {
        for (i = 0; i < numberOfFiles; i++)
        {
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (NULL != pBuffListArray[i][j]->pBuffers->pData)
                {
                    qaeMemFreeNUMA(
                        (void **)&pBuffListArray[i][j]->pBuffers->pData);
                    if (NULL != pBuffListArray[i][j]->pBuffers->pData)
                    {
                        PRINT(
                            "Could not free bufferList[%d][%d]->pData\n", i, j);
                    }
                }
                if (NULL != pBuffListArray[i][j]->pPrivateMetaData)
                {
                    qaeMemFreeNUMA(
                        (void **)&pBuffListArray[i][j]->pPrivateMetaData);
                    if (NULL != pBuffListArray[i][j]->pPrivateMetaData)
                    {
                        PRINT("Could not free "
                              "bufferList[%d][%d]->pPrivateMetaData\n",
                              i,
                              j);
                    }
                }
                if (NULL != pBuffListArray[i][j]->pBuffers)
                {
                    qaeMemFree((void **)&pBuffListArray[i][j]->pBuffers);
                    if (NULL != pBuffListArray[i][j]->pBuffers)
                    {
                        PRINT("Could not free bufferList[%d][%d]->pBuffers\n",
                              i,
                              j);
                    }
                }
                if (NULL != pBuffListArray[i][j])
                {
                    qaeMemFree((void **)&pBuffListArray[i][j]);
                    if (NULL != pBuffListArray[i][j])
                    {
                        PRINT("Could not free bufferList[%d][%d]\n", i, j);
                    }
                }
            }
            if (NULL != pBuffListArray[i])
            {
                qaeMemFree((void **)&pBuffListArray[i]);
                if (NULL != pBuffListArray[i])
                {
                    PRINT("Could not free bufferList[%d]\n", i);
                }
            }
        }
    }
    qaeMemFree((void **)&pBuffListArray);
    if (NULL != pBuffListArray)
    {
        PRINT("Could not free bufferList\n");
    }
    return;
}

CpaStatus createBuffers(Cpa32U buffSize,
                        Cpa32U numBuffs,
                        CpaBufferList **pBuffListArray,
                        Cpa32U nodeId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;

    for (i = 0; i < numBuffs; i++)
    {
        pBuffListArray[i] = qaeMemAlloc(sizeof(CpaBufferList));
        if (NULL == pBuffListArray[i])
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]\n", i);
            return CPA_STATUS_FAIL;
        }
        pBuffListArray[i]->pBuffers = qaeMemAlloc(sizeof(CpaFlatBuffer));
        if (NULL == pBuffListArray[i]->pBuffers)
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]->pBuffers\n", i);
            return CPA_STATUS_FAIL;
        }
        /* Allocate Flat buffer for each buffer List */
        pBuffListArray[i]->pBuffers->dataLenInBytes = buffSize;
        pBuffListArray[i]->pBuffers->pData =
            qaeMemAllocNUMA(buffSize, nodeId, BYTE_ALIGNMENT_64);

        if (NULL == pBuffListArray[i]->pBuffers->pData)
        {
            PRINT_ERR("Unable to allocate pBuffListArray[%d]->pBuffers.pData\n",
                      i);
            return CPA_STATUS_FAIL;
        }
        memset(pBuffListArray[i]->pBuffers->pData, 0, buffSize);
        pBuffListArray[i]->numBuffers = ONE_BUFFER_DC;
    }

    return status;
}
void freeResults(CpaDcRqResults ***ppDcResult,
                 Cpa32U numFiles,
                 compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;


    if (NULL == ppDcResult)
    {
        /* Return Silent */
        return;
    }
    if (0 != numFiles)
    {
        for (i = 0; i < numFiles; i++)
        {
            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (NULL != ppDcResult[i][j])
                {
                    qaeMemFree((void **)&ppDcResult[i][j]);
                }
            }
            if (NULL != ppDcResult[i])
            {
                qaeMemFree((void **)&ppDcResult[i]);
            }
        }
    }
    qaeMemFree((void **)&ppDcResult);
}

void freeCbTags(dc_callbacktag_t ***callbackTag,
                Cpa32U numFiles,
                compression_test_params_t *setup)
{
    Cpa32U i = 0, j = 0;


    if (NULL == callbackTag)
    {
        /* Return Silent */
        return;
    }
    if (0 != numFiles)
    {
        for (i = 0; i < numFiles; i++)
        {

            for (j = 0; j < setup->numberOfBuffers[i]; j++)
            {
                if (NULL != callbackTag[i][j])
                {
                    qaeMemFreeNUMA((void **)&callbackTag[i][j]);
                }
            }
            if (NULL != callbackTag[i])
            {
                qaeMemFreeNUMA((void **)&callbackTag[i]);
            }
        }
    }
    qaeMemFreeNUMA((void **)&callbackTag);
}



CpaStatus sampleRemoveDcDpSession(CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U retries = 0;
    Cpa32U delay = REMOVE_SESSION_WAIT;

    /*
     * We do a incremental sleep starting from 50 micro secs and
     * by incrementing the sleep time by twice the previous value
     * for each retry. Total sleep time would be 1.6 secs
     * for 15 number of retries which would be enough for all
     * inflight requests to get processed.
     */
    do
    {
        status = cpaDcDpRemoveSession(dcInstance, pSessionHandle);
        delay *= 2;
        sleepNano(delay * 1000);
    } while ((CPA_STATUS_RETRY == status) &&
             (MAX_SESSION_REMOVE_RETRIES >= ++retries));

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Remove session failed with status %d\n", status);
        status = CPA_STATUS_FAIL;
    }

    return status;
}
EXPORT_SYMBOL(sampleRemoveDcDpSession);
