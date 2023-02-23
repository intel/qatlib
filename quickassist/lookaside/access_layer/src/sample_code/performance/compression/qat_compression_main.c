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

#include "cpa_sample_code_dc_utils.h"
#include "cpa_dc.h"
#include "qat_compression_main.h"
#include "icp_sal_poll.h"
#include "qat_perf_latency.h"
#include "qat_perf_sleeptime.h"
#include "qat_compression_e2e.h"
#include "qat_perf_cycles.h"
#include "busy_loop.h"
#include "icp_sal_user.h"
#include "qat_perf_utils.h"

extern void dcPerformCallback(void *pCallbackTag, CpaStatus status);

extern CpaStatus createStartandWaitForCompletion(Cpa32U instType);


#define COUNT_RESPONSES dcPerformCallback(setup, status)

#define RESET_PERF_STATS(perfStats, numLists, numLoops)                        \
    do                                                                         \
    {                                                                          \
        perfStats->responses = 0;                                              \
        perfStats->submissions = 0;                                            \
        perfStats->retries = 0;                                                \
        perfStats->pollRetries = 0;                                            \
        perfStats->nextPoll = 0;                                               \
        perfStats->numOperations = 0;                                          \
        coo_deinit(perfStats);                                                 \
        coo_init(perfStats, (Cpa64U)numLists *(Cpa64U)numLoops);               \
        qatFreeLatency(perfStats);                                             \
        qatInitLatency(perfStats, numLists, numLoops);                         \
    } while (0)

static CpaStatus qatInduceOverflow(compression_test_params_t *setup,
                                   CpaDcSessionHandle pSessionHandle,
                                   CpaBufferList *srcBufferListArray,
                                   CpaBufferList *destBufferListArray,
                                   CpaBufferList *cmpBufferListArray,
                                   CpaDcRqResults *resultArray);

static CpaStatus setupDcCommonTest(compression_test_params_t *dcSetup,
                                   CpaDcCompType algorithm,
                                   CpaDcSessionDir direction,
                                   CpaDcCompLvl compLevel,
                                   CpaDcSessionState state,
                                   Cpa32U testBufferSize,
                                   corpus_type_t corpusType,
                                   sync_mode_t syncFlag,
                                   Cpa32U numLoops);

#if DC_API_VERSION_AT_LEAST(3, 1)
CpaStatus setupDcLZ4Test(CpaDcCompType algorithm,
                         CpaDcSessionDir direction,
                         CpaDcCompLvl compLevel,
                         CpaDcSessionState state,
                         Cpa32U testBufferSize,
                         corpus_type_t corpusType,
                         CpaDcCompMinMatch minMatch,
                         CpaDcCompLZ4BlockMaxSize lz4BlockMaxSize,
                         sync_mode_t syncFlag,
                         Cpa32U numLoops)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* get memory location from sample code framework to store setup details*/
    compression_test_params_t *dcSetup = NULL;
    dcSetup = (compression_test_params_t *)&thread_setup_g[testTypeCount_g][0];

    /*Assign unique values used only by LZ4 */
    dcSetup->setupData.minMatch = minMatch;
    dcSetup->setupData.lz4BlockMaxSize = lz4BlockMaxSize;
    dcSetup->setupData.lz4BlockIndependence = LZ4BlockIndependence_g;

    status = setupDcCommonTest(dcSetup,
                               algorithm,
                               direction,
                               compLevel,
                               state,
                               testBufferSize,
                               corpusType,
                               syncFlag,
                               numLoops);

    return status;
}
EXPORT_SYMBOL(setupDcLZ4Test);
#endif

/*register a test with the sample code framework*/
CpaStatus setupDcTest(CpaDcCompType algorithm,
                      CpaDcSessionDir direction,
                      CpaDcCompLvl compLevel,
                      CpaDcHuffType huffmanType,
                      CpaDcSessionState state,
                      Cpa32U windowSize,
                      Cpa32U testBufferSize,
                      corpus_type_t corpusType,
                      sync_mode_t syncFlag,
                      Cpa32U numLoops)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* get memory location from sample code framework to store setup details*/
    compression_test_params_t *dcSetup = NULL;
    dcSetup = (compression_test_params_t *)&thread_setup_g[testTypeCount_g][0];

    /*Assign unique values used only by deflate */
#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
    dcSetup->setupData.huffType = huffmanType;
#else
    dcSetup->setupData.huffType = CPA_DC_HT_STATIC;
#endif
#if DC_API_VERSION_LESS_THAN(1, 6)
    /*windows size is depreciated in new versions of the QA-API*/
    dcSetup->setupData.deflateWindowSize = windowsSize;
#endif

    status = setupDcCommonTest(dcSetup,
                               algorithm,
                               direction,
                               compLevel,
                               state,
                               testBufferSize,
                               corpusType,
                               syncFlag,
                               numLoops);

    return status;
}
EXPORT_SYMBOL(setupDcTest);

CpaStatus setupDcStatefulTest(CpaDcCompType algorithm,
                              CpaDcSessionDir direction,
                              CpaDcCompLvl compLevel,
                              CpaDcHuffType huffmanType,
                              Cpa32U testBufferSize,
                              corpus_type_t corpusType,
                              sync_mode_t syncFlag,
                              Cpa32U numLoops)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = setupDcTest(algorithm,
                         direction,
                         compLevel,
                         huffmanType,
                         CPA_DC_STATEFUL,
                         DEFAULT_COMPRESSION_WINDOW_SIZE,
                         testBufferSize,
                         corpusType,
                         syncFlag,
                         numLoops);

    return status;
}
EXPORT_SYMBOL(setupDcStatefulTest);

static CpaStatus setupDcCommonTest(compression_test_params_t *dcSetup,
                                   CpaDcCompType algorithm,
                                   CpaDcSessionDir direction,
                                   CpaDcCompLvl compLevel,
                                   CpaDcSessionState state,
                                   Cpa32U testBufferSize,
                                   corpus_type_t corpusType,
                                   sync_mode_t syncFlag,
                                   Cpa32U numLoops)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U corpusFileIndex = 0;

    /* check that the sample code framework can register this test setup */
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    /*check that atleast 1 loop of the data set is to be submitted*/
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

    /*Start DC Services */
    status = startDcServices(testBufferSize, TEMP_NUM_BUFFS);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error in Starting Dc Services\n");
        return CPA_STATUS_FAIL;
    }
    if (iaCycleCount_g)
    {
#ifdef POLL_INLINE
        enablePollInline();
#endif
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

    INIT_OPDATA_DEFAULT(&dcSetup->requestOps);
    /* If the setup is requesting non-default CnV behaviour for special
     * tests, set it accordingly.
     */
    if (direction == CPA_DC_DIR_COMPRESS)
    {
        dcSetup->useE2E = dataIntegrity_g;
        dcSetup->useE2EVerify = dataIntegrityVerify_g;
    }
    if (getSetupCnVRequestFlag() != CNV_FLAG_DEFAULT)
    {
        setCnVFlags(getSetupCnVRequestFlag(), &dcSetup->requestOps);
    }

    /* Set the performance function to the actual performance function
     * that actually does all the performance
     */
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)dcPerformance;

    /* register the test buffersize */
    testSetupData_g[testTypeCount_g].packetSize = testBufferSize;
    if (CPA_FALSE == gUseStatefulLite)
    {
        dcSetup->useStatefulLite = CPA_FALSE;
    }
    /* Data compression setup data */
    dcSetup->setupData.compLevel = compLevel;
    dcSetup->setupData.compType = algorithm;
    dcSetup->setupData.sessDirection = direction;
    {
        dcSetup->setupData.sessState = state;
    }

    dcSetup->corpus = corpusType;
    dcSetup->corpusFileIndex = corpusFileIndex;
    dcSetup->bufferSize = testBufferSize;
    dcSetup->dcSessDir = direction;
    dcSetup->syncFlag = syncFlag;
    dcSetup->numLoops = numLoops;
    dcSetup->isDpApi = CPA_FALSE;
    dcSetup->disableAdditionalCmpbufferSize = disableAdditionalCmpbufferSize_g;
    dcSetup->setupData.autoSelectBestHuffmanTree = gAutoSelectBestMode;
    dcSetup->setupData.checksum = gChecksum;
    dcSetup->passCriteria = getPassCriteria();
    return status;
}

/*this is the performance thread created by the sample code framework
 * after registering the setupScDcTest and calling createPeformance threads
 * this function copies the setup into its own local copy and then calls scDcPoc
 * to measure compression performance*/
void dcPerformance(single_thread_test_data_t *testSetup)
{
    compression_test_params_t dcSetup = {0};
    compression_test_params_t *tmpSetup = NULL;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcInstanceCapabilities capabilities = {0};

    /* Get the setup pointer */
    tmpSetup = (compression_test_params_t *)(testSetup->setupPtr);
    testSetup->passCriteria = tmpSetup->passCriteria;
    dcSetup.passCriteria = tmpSetup->passCriteria;

    /* update the setup structure with setup parameters */
    memcpy(&dcSetup.requestOps, &tmpSetup->requestOps, sizeof(CpaDcOpData));
    dcSetup.useStatefulLite = tmpSetup->useStatefulLite;
    dcSetup.bufferSize = tmpSetup->bufferSize;
    dcSetup.corpus = tmpSetup->corpus;
    dcSetup.corpusFileIndex = tmpSetup->corpusFileIndex;
    dcSetup.setupData = tmpSetup->setupData;
    dcSetup.dcSessDir = tmpSetup->dcSessDir;
    dcSetup.syncFlag = tmpSetup->syncFlag;
    dcSetup.numLoops = tmpSetup->numLoops;
    dcSetup.setupData.checksum = tmpSetup->setupData.checksum;
    dcSetup.useE2E = tmpSetup->useE2E;
    dcSetup.useE2EVerify = tmpSetup->useE2EVerify;

    /*give our thread a unique memory location to store performance stats*/
    dcSetup.performanceStats = testSetup->performanceStats;
    dcSetup.performanceStats->averagePacketSizeInBytes = testSetup->packetSize;
    dcSetup.performanceStats->numLoops = tmpSetup->numLoops;
    dcSetup.isDpApi = CPA_FALSE;
    dcSetup.disableAdditionalCmpbufferSize =
        tmpSetup->disableAdditionalCmpbufferSize;
    testSetup->performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
    testSetup->performanceStats->additionalStatus = CPA_STATUS_SUCCESS;

    status = calculateRequireBuffers(&dcSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error calculating required buffers\n");
        testSetup->performanceStats->threadReturnStatus = status;
        return;
    }
    dcSetup.numLists = dcSetup.numberOfBuffers[dcSetup.corpusFileIndex];
    if (CPA_STATUS_SUCCESS == status)
    {
        /*this barrier is to halt this thread when run in user space context,
         * the startThreads function releases this barrier, in kernel space is
         * does nothing, but kernel space threads do not start until we call
         * startThreads anyway
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
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (0 == numInstances)
        {
            PRINT_ERR(" DC Instances are not present\n");
            status = CPA_STATUS_FAIL;
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        instances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
        if (NULL == instances)
        {
            PRINT_ERR("Unable to allocate Memory for Instances\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*get the instance handles so that we can start
         * our thread on the selected instance
         */
        status = cpaDcGetInstances(numInstances, instances);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR(" Unable to get DC instances\n");
            QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* give our thread a logical quick assist instance to use
         * use % to wrap around the max number of instances*/
        dcSetup.dcInstanceHandle =
            instances[(testSetup->logicalQaInstance) % numInstances];
        // find node that thread is running on
        status = sampleCodeDcGetNode(dcSetup.dcInstanceHandle, &dcSetup.node);
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
    }
    /*check if dynamic compression is supported*/
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
#if DC_API_VERSION_AT_LEAST(3, 1)
    if ((CPA_DC_STATELESS == tmpSetup->setupData.sessState) &&
        (CPA_DC_LZ4 == tmpSetup->setupData.compType) &&
        ((CPA_FALSE == capabilities.statelessLZ4Compression) ||
         (CPA_FALSE == capabilities.statelessLZ4Decompression)))
    {
        PRINT("LZ4 is not supported on logical instance %d\n",
              (testSetup->logicalQaInstance) % numInstances);

        status = CPA_STATUS_UNSUPPORTED;
        QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
    }
    if ((CPA_DC_STATELESS == tmpSetup->setupData.sessState) &&
        (CPA_DC_LZ4S == tmpSetup->setupData.compType) &&
        ((CPA_FALSE == capabilities.statelessLZ4Compression) ||
         (CPA_FALSE == capabilities.statelessLZ4Decompression)))
    {
        PRINT("LZ4s is not supported on logical instance %d\n",
              (testSetup->logicalQaInstance) % numInstances);

        status = CPA_STATUS_UNSUPPORTED;
        QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
    }
#endif

    if (CPA_STATUS_SUCCESS !=
        qatDcGetPreTestRecoveryCount(
            &dcSetup, &capabilities, testSetup->performanceStats))
    {
        QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(testSetup, err);
    }
    if (CPA_TRUE == dcSetup.useE2E)
    {
        PRINT("Do CRC integrity capabilities check for this instance. %d\n",
              testSetup->logicalQaInstance);
#if defined(SC_WITH_QAT20) || defined(SC_WITH_QAT20_UPSTREAM)
        if (CPA_FALSE == capabilities.integrityCrcs64b)
        {
#endif
            if (CPA_FALSE == capabilities.integrityCrcs)
            {

                PRINT("CRC integrity check is unsupported for this instance. "
                      "%d\n",
                      testSetup->logicalQaInstance);
                testSetup->performanceStats->threadReturnStatus =
                    CPA_STATUS_SUCCESS;
                qaeMemFree((void **)&instances);
                qaeMemFree((void **)&dcSetup.numberOfBuffers);
                qaeMemFree((void **)&dcSetup.packetSizeInBytesArray);
                sampleCodeThreadExit();
            }
#if defined(SC_WITH_QAT20) || defined(SC_WITH_QAT20_UPSTREAM)
        }
#endif
    }
    if (CPA_TRUE == dcSetup.useXlt && ASYNC == dcSetup.syncFlag)
    {
        PRINT("Async mode not supported in Xlt[%d]\n", dcSetup.useXlt);
        testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&instances);
        qaeMemFree((void **)&dcSetup.numberOfBuffers);
        qaeMemFree((void **)&dcSetup.packetSizeInBytesArray);
        sampleCodeThreadExit();
    }


    dcSetup.induceOverflow = CPA_FALSE;
    dcSetup.threadID = testSetup->threadID;


    if (CPA_STATUS_SUCCESS == status)
    {
        /*launch function that does all the work*/
        status = qatDcPerform(&dcSetup);
        if (CPA_STATUS_SUCCESS != status)
        {
            dcPrintTestData(&dcSetup);
            PRINT_ERR("Compression Thread %u FAILED\n", testSetup->threadID);
            testSetup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*set the print function that can be used to print
         * statistics at the end of the test
         * */
        // update values from the framework peak ptr to thread local ptr to be
        // seen by print function
        testSetup->performanceStats->numLoops = dcSetup.numLoops;
        testSetup->statsPrintFunc = (stats_print_func_t)dcPrintStats;

        qatDcGetPostTestRecoveryCount(&dcSetup, testSetup->performanceStats);
    }
    if ((CPA_STATUS_SUCCESS != status) ||
        (testSetup->performanceStats->threadReturnStatus == CPA_STATUS_FAIL))
    {
        // In case of test failure stopDcServicesFromPrintStats function call
        // from waitForThreadCompletion funtion stops the dc services and not
        // print the performance stats.
        testSetup->statsPrintFunc =
            (stats_print_func_t)stopDcServicesFromPrintStats;
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
        testSetup->performanceStats->threadReturnStatus = status;
    }
    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(dcPerformance);

/*allocates buffers store a file for compression. The buffers are sent to
 * hardware, performance is recorded and stored in the setup parameter
 * the sample code framework prints out results after the thread completes*/
CpaStatus qatDcPerform(compression_test_params_t *setup)
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
    Cpa32U numberOfBuffersPerList = dc_bufferCount_g;
    CpaBufferList *srcBufferListArray = NULL;
    CpaBufferList *destBufferListArray = NULL;
    CpaBufferList *cmpBufferListArray = NULL;
    CpaDcRqResults *resultArray = NULL;
    CpaDcSessionHandle pSessionHandle = NULL;
    CpaDcSessionHandle pDecompressSessionHandle = NULL;
    CpaBufferList contextBuffer = {0};
    CpaDcCallbackFn dcCbFn = dcPerformCallback;
    Cpa32U numLoops = 0;
    Cpa32U i = 0;
    int latency_enable_flag = latency_enable;
    const corpus_file_t *const fileArray = getFilesInCorpus(setup->corpus);

    saveClearRestorePerfStats(setup->performanceStats);
    coo_init(setup->performanceStats,
             (Cpa64U)setup->numLists * (Cpa64U)setup->numLoops);

    // allocate memory for source & destination bufferLists and results
    status = qatAllocateCompressionLists(setup,
                                         &srcBufferListArray,
                                         &destBufferListArray,
                                         &cmpBufferListArray,
                                         &resultArray);

    // Allocate the CpaFlatBuffers in each list
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

    // copy corpus data into allocated buffers
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PopulateBuffers(
            srcBufferListArray,
            setup->numLists,
            fileArray[setup->corpusFileIndex].corpusBinaryData,
            fileArray[setup->corpusFileIndex].corpusBinaryDataLen,
            testBufferSize);
    }
    {
        // Initialize the compression session to use
        if (CPA_STATUS_SUCCESS == status)
        {
            status = qatCompressionSessionInit(setup,
                                               &pSessionHandle,
                                               &pDecompressSessionHandle,
                                               &contextBuffer,
                                               dcCbFn);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("compressionSessionInit returned status %d\n",
                          status);
            }
        }
    }
/*CNV Error Injection*/
    /* compress the data */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (setup->induceOverflow == CPA_TRUE)
        {
                status = qatInduceOverflow(setup,
                                           pSessionHandle,
                                           srcBufferListArray,
                                           destBufferListArray,
                                           cmpBufferListArray,
                                           resultArray);
        }
        else if (setup->dcSessDir == CPA_DC_DIR_COMPRESS &&
                 reliability_g == CPA_FALSE)
        {
            status = qatCompressData(setup,
                                     pSessionHandle,
                                     CPA_DC_DIR_COMPRESS,
                                     srcBufferListArray,
                                     destBufferListArray,
                                     cmpBufferListArray,
                                     resultArray);
            qatDcUpdateProducedBufferLength(
                setup, destBufferListArray, resultArray);
            dcScSetBytesProducedAndConsumed(
                resultArray, setup->performanceStats, setup, setup->dcSessDir);
        }
        else if (setup->dcSessDir == CPA_DC_DIR_DECOMPRESS &&
                 reliability_g == CPA_FALSE)
        {

            /*copy numLoops, set setup->numLoops to 1 to compress data, then
             * restore setup->numLoops to measure decompress performance*/
            numLoops = setup->numLoops;
            setup->numLoops = 1;

            /* below qatCompressData() is invoked to generate compressed
             * test data that would be used for actual DECOMPRESSION test.
             * Hence disabling latency and COO measurement for below
             * COMPRESSION operation.
             */
            latency_enable = 0;
            coo_deinit(setup->performanceStats);

            status = qatCompressData(setup,
                                     pSessionHandle,
                                     CPA_DC_DIR_COMPRESS,
                                     srcBufferListArray,
                                     destBufferListArray,
                                     cmpBufferListArray,
                                     resultArray);

            /* Restore latency and COO measurement */
            latency_enable = latency_enable_flag;
            coo_init(setup->performanceStats,
                     (Cpa64U)setup->numLists * (Cpa64U)setup->numLoops);

            qatDcUpdateProducedBufferLength(
                setup, destBufferListArray, resultArray);
            if (CPA_STATUS_SUCCESS == status)
            {
                /*restore setup->NumLoops*/
                setup->numLoops = numLoops;
                if (setup->e2e)
                {
                    setup->e2e->swInputChecksum = 0x0;
                    setup->e2e->swOutputChecksum = 0x0;
                }
                RESET_PERF_STATS(
                    setup->performanceStats, setup->numLists, setup->numLoops);
                status = qatCompressData(setup,
                                         pDecompressSessionHandle,
                                         CPA_DC_DIR_DECOMPRESS,
                                         srcBufferListArray,
                                         destBufferListArray,
                                         cmpBufferListArray,
                                         resultArray);
                dcScSetBytesProducedAndConsumed(resultArray,
                                                setup->performanceStats,
                                                setup,
                                                setup->dcSessDir);
                qatDcUpdateProducedBufferLength(
                    setup, cmpBufferListArray, resultArray);
            }
        }
        else if (setup->dcSessDir == CPA_DC_DIR_COMPRESS &&
                 reliability_g == CPA_TRUE)
        {
            /*copy numLoops, set setup->numLoops to 1 to do repeated
             * compress - sw-decompress for numLoops times*/
            numLoops = setup->numLoops;
            setup->numLoops = 1;
            for (i = 0; i < numLoops; i++)
            {
                status = qatCompressData(setup,
                                         pSessionHandle,
                                         CPA_DC_DIR_COMPRESS,
                                         srcBufferListArray,
                                         destBufferListArray,
                                         cmpBufferListArray,
                                         resultArray);
                qatDcUpdateProducedBufferLength(
                    setup, destBufferListArray, resultArray);
                dcScSetBytesProducedAndConsumed(resultArray,
                                                setup->performanceStats,
                                                setup,
                                                setup->dcSessDir);
                if (CPA_STATUS_SUCCESS == status)
                {
                    status = qatSwDecompress(setup,
                                             destBufferListArray,
                                             cmpBufferListArray,
                                             resultArray);
                    qatDcUpdateProducedBufferLength(
                        setup, cmpBufferListArray, resultArray);
                    if (CPA_STATUS_SUCCESS == status)
                    {
                        status = qatCmpBuffers(
                            setup, srcBufferListArray, cmpBufferListArray);
                        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS(
                            "qatCmpBuffers", status);
                    }
                    if (CPA_STATUS_SUCCESS == status)
                    {
                        /*reset destination buffer*/
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
            /*copy numLoops, set setup->numLoops to 1 to do repeated
             * swcompress-decompress for numLoops times*/
            numLoops = setup->numLoops;
            setup->numLoops = 1;
            for (i = 0; i < numLoops; i++)
            {
                status = qatSwCompress(setup,
                                       srcBufferListArray,
                                       destBufferListArray,
                                       resultArray);
                qatDcUpdateProducedBufferLength(
                    setup, destBufferListArray, resultArray);
                if (CPA_STATUS_SUCCESS == status)
                {
                    status = qatCompressData(setup,
                                             pDecompressSessionHandle,
                                             CPA_DC_DIR_DECOMPRESS,
                                             srcBufferListArray,
                                             destBufferListArray,
                                             cmpBufferListArray,
                                             resultArray);
                    qatDcUpdateProducedBufferLength(
                        setup, cmpBufferListArray, resultArray);
                    dcScSetBytesProducedAndConsumed(resultArray,
                                                    setup->performanceStats,
                                                    setup,
                                                    setup->dcSessDir);
                    if (CPA_STATUS_SUCCESS == status)
                    {
                        status = qatCmpBuffers(
                            setup, srcBufferListArray, cmpBufferListArray);
                        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS(
                            "qatCmpBuffers", status);
                    }
                    if (CPA_STATUS_SUCCESS == status)
                    {
                        /*reset destination buffer*/
                        status = qatCompressResetBufferList(setup,
                                                            destBufferListArray,
                                                            testBufferSize,
                                                            CPA_FALSE);
                        QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS(
                            "qatCompressResetBufferList", status);
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
                performOffloadCalculationBusyLoop(setup,
                                                  srcBufferListArray,
                                                  destBufferListArray,
                                                  cmpBufferListArray,
                                                  resultArray,
                                                  dcCbFn,
                                                  setup->dcSessDir,
                                                  pSessionHandle))
            {
                PRINT_ERR("performOffloadCalculationBusyLoop error\n");
            }
        }
        coo_average(setup->performanceStats);
        coo_deinit(setup->performanceStats);
        // remove the session free the handle
        {
            if (CPA_STATUS_SUCCESS !=
                qatCompressionSessionTeardown(
                    setup, &pSessionHandle, &pDecompressSessionHandle))
            {
                PRINT_ERR("compressionSessionTeardown error\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }
    /*free CpaFlatBuffers and privateMetaData in CpaBufferLists*/
    if ((CPA_STATUS_SUCCESS !=
         qatFreeCompressionFlatBuffers(setup,
                                       srcBufferListArray,
                                       destBufferListArray,
                                       cmpBufferListArray)) &&
        (CPA_STATUS_SUCCESS != qatFreeFlatBuffersInList(&contextBuffer)))
    {
        PRINT_ERR("freeCompressionFlatBuffers error\n");
        status = CPA_STATUS_FAIL;
    }
    // free CpaBufferLists
    if (CPA_STATUS_SUCCESS != qatFreeCompressionLists(setup,
                                                      &srcBufferListArray,
                                                      &destBufferListArray,
                                                      &cmpBufferListArray,
                                                      &resultArray))
    {
        PRINT_ERR("freeCompressionLists error\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}
EXPORT_SYMBOL(qatDcPerform);

CpaStatus qatDcSubmitRequest(compression_test_params_t *setup,
                             const CpaInstanceInfo2 *pInstanceInfo2,
                             CpaDcSessionDir compressDirection,
                             CpaDcSessionHandle pSessionHandle,
                             CpaBufferList *arrayOfSrcBufferLists,
                             CpaBufferList *arrayOfDestBufferLists,
                             CpaBufferList *arrayOfCmpBufferLists,
                             Cpa32U listNum,
                             CpaDcRqResults *arrayOfResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    static Cpa32U staticAssign = 0;

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
        if (compressDirection == CPA_DC_DIR_COMPRESS)
        {
            coo_req_start(setup->performanceStats);
            {
                {
                    status =
                        cpaDcCompressData2(setup->dcInstanceHandle,
                                           pSessionHandle,
                                           &arrayOfSrcBufferLists[listNum],
                                           &arrayOfDestBufferLists[listNum],
                                           &(setup->requestOps),
                                           &arrayOfResults[listNum],
                                           (void *)setup);
                }
                coo_req_stop(setup->performanceStats, status);
            }
        }
        else if (compressDirection == CPA_DC_DIR_DECOMPRESS)
        {
            /*This is required as the cpaDcDecompressData2 function rejects
             *  request where compressAndVerify flag is set to true. However
             *  the setting of this flag should not matter for decompress*/
            setup->requestOps.compressAndVerify = CPA_FALSE;
            coo_req_start(setup->performanceStats);
            {
                status = cpaDcDecompressData2(setup->dcInstanceHandle,
                                              pSessionHandle,
                                              &arrayOfDestBufferLists[listNum],
                                              &arrayOfCmpBufferLists[listNum],
                                              &(setup->requestOps),
                                              &arrayOfResults[listNum],
                                              (void *)setup);
            }
            coo_req_stop(setup->performanceStats, status);
        }

        if (CPA_STATUS_RETRY == status)
        {
            qatDcRetryHandler(setup, pInstanceInfo2);
            /*context switch to give firmware time to process*/
            AVOID_SOFTLOCKUP;
        }
        /*check the results structure for any failed responses
         * caught by the callback function*/
        qatCompressionResponseStatusCheck(
            setup, arrayOfResults, listNum, &status);

    } while (CPA_STATUS_RETRY == status);
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        busyLoop(setup->performanceStats->busyLoopValue, &staticAssign);
        setup->performanceStats->busyLoopCount++;
    }
    return status;
}
EXPORT_SYMBOL(qatDcSubmitRequest);

/*performance measurement function to compress a file for 'n' number of loops
 * */
CpaStatus qatCompressData(compression_test_params_t *setup,
                          CpaDcSessionHandle pSessionHandle,
                          CpaDcSessionDir compressDirection,
                          CpaBufferList *arrayOfSrcBufferLists,
                          CpaBufferList *arrayOfDestBufferLists,
                          CpaBufferList *arrayOfCmpBufferLists,
                          CpaDcRqResults *arrayOfResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa32U numLoops = 0;
    Cpa32U listNum = 0;
    Cpa32U previousChecksum = 0;
    CpaDcChecksum checksum = CPA_DC_NONE;
    CpaDcStats dcStats = {0};
    CpaBoolean isCnVerrorRecovered = CPA_FALSE;

    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    checksum = setup->setupData.checksum;
    /* init checksum */
    if (CPA_DC_ADLER32 == checksum)
    {
        previousChecksum = 1;
    }
    else if (CPA_DC_CRC32 == checksum)
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
                         (setup->useStatefulLite == CPA_TRUE ||
                          setup->setupData.sessState == CPA_DC_STATEFUL)
                             ? 1
                             : dcPollingInterval_g);
        status = qatInitLatency(
            setup->performanceStats, setup->numLists, setup->numLoops);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*get the instance2 info, this is used to determine if the instance
         * being used is polled*/
        status = cpaDcInstanceGetInfo2(setup->dcInstanceHandle, instanceInfo2);
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
                /* Always set the checksum equal to the previous
                 * checksum. For stateless the previous checksum
                 * will still be the default value which is what
                 * we want to set it to anyway in that case.
                 */
                arrayOfResults[listNum].checksum = previousChecksum;
                /*submit request*/
                status = qatDcSubmitRequest(setup,
                                            instanceInfo2,
                                            compressDirection,
                                            pSessionHandle,
                                            arrayOfSrcBufferLists,
                                            arrayOfDestBufferLists,
                                            arrayOfCmpBufferLists,
                                            listNum,
                                            arrayOfResults);
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
                if (poll_inline_g && instanceInfo2->isPolled)
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
                else
                {
#if DC_API_VERSION_AT_LEAST(3, 2)
                    if (reliability_g)
#endif
                    {
                        if ((CPA_DC_STATELESS == setup->setupData.sessState) &&
                            (CPA_TRUE == setup->useE2E ||
                             CPA_TRUE == setup->useE2EVerify))
                        {
                            status = waitForSemaphore(setup->performanceStats);

                            if (CPA_STATUS_SUCCESS != status)
                            {
                                PRINT_ERR("waitForSemaphore error\n");
                                setup->performanceStats->threadReturnStatus =
                                    CPA_STATUS_FAIL;
                                break;
                            }
                        }
                    }
                }
                if ((CPA_TRUE == setup->useStatefulLite) ||
                    (CPA_DC_STATEFUL == setup->setupData.sessState))
                {
                    status = waitForSemaphore(setup->performanceStats);
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT_ERR("waitForSemaphore error\n");
                        setup->performanceStats->threadReturnStatus =
                            CPA_STATUS_FAIL;
                        break;
                    }
                    previousChecksum = arrayOfResults[listNum].checksum;
                    /*check for unconsumed data*/
                    if ((CPA_DC_DIR_DECOMPRESS == compressDirection) &&
                        (arrayOfDestBufferLists[listNum]
                             .pBuffers->dataLenInBytes !=
                         arrayOfResults[listNum].consumed))
                    {
                        if (CPA_STATUS_SUCCESS !=
                            qatCheckAndHandleUnconsumedData(
                                setup,
                                arrayOfDestBufferLists,
                                arrayOfResults,
                                listNum,
                                (const char *)instanceInfo2->partName))
                        {
                            PRINT_ERR("Decomp did not consume all data\n");
                            PRINT("Input Buffersize: %u\n",
                                  arrayOfDestBufferLists[listNum]
                                      .pBuffers[0]
                                      .dataLenInBytes);
                            PRINT("Amount Consumed:  %u\n",
                                  arrayOfResults[listNum].consumed);
                            PRINT("Amount Produced:  %u\n",
                                  arrayOfResults[listNum].produced);
                            setup->performanceStats->threadReturnStatus =
                                CPA_STATUS_FAIL;
                            setup->performanceStats->numOperations =
                                setup->performanceStats->submissions;
                            /*call the response thread so that the semaphore
                             * gets posted*/
                            dcPerformCallback(setup, status);
                            break;
                        }
                    }
                }
                if (CPA_STATUS_SUCCESS == status)
                {
#if DC_API_VERSION_AT_LEAST(3, 2)
                    if (reliability_g)
#endif
                    {
                        status = qatCompressionE2EVerify(
                            setup,
                            &arrayOfSrcBufferLists[listNum],
                            &arrayOfDestBufferLists[listNum],
                            &arrayOfResults[listNum]);
                    }
                }
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("%s returned status: %d\n",
                              "qatCompressionE2EVerify",
                              status);
                    break;
                }
            }
            /* number of lists/requests in a file */
            if (CPA_STATUS_SUCCESS != status)
            {
                /*break out of outerloop(numLoops)*/
                break;
            }
        } /* number of times we loop over same file */
        if (poll_inline_g)
        {
            if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2->isPolled))
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
        else
        {
            /* In case of failure during submissions, all inflight requests
             * should be collected before releasing memory that is used by
             * the SAL/Driver. This is specially true for async response
             * processing via callback function.
             */
            if (!(poll_inline_g || SYNC == setup->syncFlag ||
                  CPA_TRUE == setup->useStatefulLite ||
                  CPA_DC_STATEFUL == setup->setupData.sessState))
            {
                waitForInflightRequestAfterError(setup->performanceStats);
            }
        }

        if (CNV_RECOVERY(&(setup->requestOps)) == CPA_TRUE)
        {
            status = cpaDcGetStats(setup->dcInstanceHandle, &dcStats);
            if (status == CPA_STATUS_SUCCESS)
            {
                setup->performanceStats->postTestRecoveryCount =
                    GET_CNV_RECOVERY_COUNTERS(&dcStats);
            }
            else
            {
                setup->performanceStats->postTestRecoveryCount = 0;
            }

            if (setup->performanceStats->postTestRecoveryCount >
                setup->performanceStats->preTestRecoveryCount)
            {
                isCnVerrorRecovered = CPA_TRUE;
            }
        }
        /* As the destination buffer size for the compression request is
         * obtained using the Compress Bound APIs, There should not be any
         * unconsumed data left in the src buffer except for the case when
         * FW identifies CnV Error and recovers it. Any such case is treated as
         * test failure*/

        if (CPA_STATUS_SUCCESS == status &&
            (CPA_DC_DIR_COMPRESS == compressDirection) &&
            (setup->induceOverflow == CPA_FALSE) &&
            (isCnVerrorRecovered == CPA_FALSE))
        {

            status = qatCompressionVerifyOverflow(
                setup, arrayOfResults, arrayOfSrcBufferLists, listNum);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("qatCompressionVerifyOverflow Failed.\n");
                setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
            }
        }
        /*check the results structure for any failed responses
         * caught by the callback function*/
        qatCompressionResponseStatusCheck(
            setup, arrayOfResults, listNum, &status);

        qatSummariseLatencyMeasurements(setup->performanceStats);
        sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);
    } /* if semaphoreInit was successful */

    qaeMemFree((void **)&instanceInfo2);

    return status;
}
EXPORT_SYMBOL(qatCompressData);

/*update in sample code framework how much data was consumed and produced by
 * thread*/
void dcScSetBytesProducedAndConsumed(CpaDcRqResults *result,
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
EXPORT_SYMBOL(dcScSetBytesProducedAndConsumed);

static CpaStatus qatInduceOverflow(compression_test_params_t *setup,
                                   CpaDcSessionHandle pSessionHandle,
                                   CpaBufferList *srcBufferListArray,
                                   CpaBufferList *destBufferListArray,
                                   CpaBufferList *cmpBufferListArray,
                                   CpaDcRqResults *resultArray)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaDcRqResults *overflowResArray = NULL;
    Cpa32U numListOverflowed = 0;
    Cpa32U i, loop;
    const Cpa32U numLoops = setup->numLoops;
    const Cpa32U reductionFactor = 6;
    Cpa32U lowerThresholdDstBufferSize = 128;
    Cpa32U *destBufferMemSize = NULL;
    const Cpa32U numLists = setup->numLists;

    overflowResArray = qaeMemAlloc(numLists * sizeof(CpaDcRqResults));
    if (overflowResArray == NULL)
    {
        PRINT_ERR("Failed to Allocate Overflow Result Array\n");
        return CPA_STATUS_FAIL;
    }

    destBufferMemSize = qaeMemAlloc(numLists * sizeof(Cpa32U));
    if (destBufferMemSize == NULL)
    {
        PRINT_ERR("Malloc failed for size %llu\n",
                  (unsigned long long)(numLists) * sizeof(Cpa32U));
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

        status = qatCompressData(setup,
                                 pSessionHandle,
                                 CPA_DC_DIR_COMPRESS,
                                 srcBufferListArray,
                                 destBufferListArray,
                                 cmpBufferListArray,
                                 resultArray);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Failed to compress Data with overflow setup\n");
            goto err;
        }
        /* Check all that have overflowed and construct a new SGL to handle
         * remaining data.
         */
        for (i = 0; i < numLists; i++)
        {
            if (resultArray[i].status == CPA_DC_OVERFLOW)
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
                      resultArray[i].status);
            }
        } /* Post overflow processing for all lists*/

        if (numListOverflowed == 0)
        {
            PRINT_ERR("No overflow detected for Loop count: %d\n", loop + 1);
            status = CPA_STATUS_FAIL;
            goto err;
        }
        /* Resubmits the bufferlist after updating buffers for overflow */
        status = qatCompressData(setup,
                                 pSessionHandle,
                                 CPA_DC_DIR_COMPRESS,
                                 srcBufferListArray,
                                 destBufferListArray,
                                 cmpBufferListArray,
                                 overflowResArray);
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
            if (overflowResArray[i].status != CPA_DC_OVERFLOW)
            {
                if (overflowResArray[i].status != CPA_DC_OK)
                {
                    PRINT("Status: %d reported post overflow for List %d\n",
                          overflowResArray[i].status,
                          i);
                }
                /* Check if the list element overflowed previously and
                 * update accordingly.
                 */
                if (resultArray[i].status == CPA_DC_OVERFLOW)
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
        dcScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, setup->dcSessDir);
        /* Perform Decompression using SW on the compressed
         * buffer.
         */
        status = qatSwDecompress(
            setup, destBufferListArray, cmpBufferListArray, resultArray);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("SW Decompression Failed\n");
            goto err;
        }

        qatDcUpdateProducedBufferLength(setup, cmpBufferListArray, resultArray);
        {
            /* Compare the input buffer to SW decompressed buffer */
            status =
                qatCmpBuffers(setup, srcBufferListArray, cmpBufferListArray);
            if (status != CPA_STATUS_SUCCESS)
            {
                PRINT_ERR("Buffer comparison Failed for Loop count:%d\n",
                          loop + 1);
                goto err;
            }
        }

        /*reset destination buffer*/
        status = qatCompressResetBufferList(setup,
                                            destBufferListArray,
                                            setup->packetSizeInBytesArray,
                                            CPA_FALSE);
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

