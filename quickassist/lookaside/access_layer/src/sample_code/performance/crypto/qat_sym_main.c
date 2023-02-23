
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

#include "cpa_dc.h"
#include "cpa_sample_code_crypto_utils.h"
#include "qat_compression_main.h"
#include "icp_sal_poll.h"
#include "qat_perf_latency.h"
#include "qat_sym_utils.h"

extern volatile CpaBoolean reliability_g;
extern Cpa32U packageIdCount_g;
extern volatile CpaBoolean digestAppended_g;
extern CpaStatus createStartandWaitForCompletion(Cpa32U instType);

extern void symPerformCallback(void *pCallbackTag,
                               CpaStatus status,
                               const CpaCySymOp operationType,
                               void *pOpData,
                               CpaBufferList *pDstBuffer,
                               CpaBoolean verifyResult);

/*allocates buffers store a file for compression. The buffers are sent to
 * hardware, performance is recorded and stored in the setup parameter
 * the sample code framework prints out results after the thread completes*/
CpaStatus scSymPoc(symmetric_test_params_t *setup_sym)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U *testBufferSize = setup_sym->packetSizeInBytesArray;
    Cpa32U digestSizeInBytes =
        setup_sym->setupData.hashSetupData.digestResultLenInBytes;
    Cpa32U numberOfBuffersPerList = 1;
    CpaBufferList *srcBufferListArray = NULL;
    CpaBufferList *copyBufferListArray = NULL;
    CpaCySymOpData *encryptOpData = NULL;
    CpaCySymOpData *decryptOpData = NULL;
    CpaCySymSessionCtx encryptSessionCtx = NULL;
    CpaCySymSessionCtx decryptSessionCtx = NULL;
    CpaCySymCbFunc cySymCbFn = symPerformCallback;
    Cpa32U numLoops = 0;
    Cpa32U i = 0;

    /* Allocate memory for source & destination bufferLists and results */
    status = qatAllocateSymLists(setup_sym,
                                 &srcBufferListArray,
                                 &copyBufferListArray,
                                 &encryptOpData,
                                 &decryptOpData);

    /* Allocate the CpaFlatBuffers in each list */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatAllocateSymFlatBuffers(setup_sym,
                                           srcBufferListArray,
                                           numberOfBuffersPerList,
                                           testBufferSize,
                                           digestSizeInBytes,
                                           copyBufferListArray);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate all flat buffers for symmetric\n");
        }
    }

    /* Copy corpus data into allocated buffers */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PopulateBuffers(srcBufferListArray,
                                 setup_sym->numBuffLists,
                                 NULL,
                                 0,
                                 testBufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = copyBuffers(
            srcBufferListArray, copyBufferListArray, setup_sym->numBuffLists);
    }

    /* Initialize the compression session to use */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatSymSessionInit(
            setup_sym, &encryptSessionCtx, &decryptSessionCtx, cySymCbFn);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("qatSymSessionInit returned status %d\n", status);
        }
    }

    /* Initialize encrypt opData */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatSymOpDataSetup(setup_sym,
                                   encryptSessionCtx,
                                   /* testBufferSize, */
                                   setup_sym->packetSizeInBytesArray,
                                   encryptOpData,
                                   srcBufferListArray);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR(
                "qatSymPerformOpDataSetup for encrypt returned status %d\n",
                status);
        }
    }

    /* Initialize decrypt opData */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatSymOpDataSetup(setup_sym,
                                   decryptSessionCtx,
                                   /* testBufferSize, */
                                   setup_sym->packetSizeInBytesArray,
                                   encryptOpData,
                                   srcBufferListArray);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR(
                "qatSymPerformOpDataSetup for decrypt returned status %d\n",
                status);
        }
    }

    // encrypt or decrypt the data
    if (CPA_STATUS_SUCCESS == status)
    {
        if (setup_sym->setupData.cipherSetupData.cipherDirection ==
                CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT &&
            reliability_g == CPA_FALSE)
        {
            status =
                qatSymPerform(setup_sym, encryptOpData, srcBufferListArray);
        }

        else if (setup_sym->setupData.cipherSetupData.cipherDirection ==
                     CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT &&
                 reliability_g == CPA_FALSE)
        {
            /*copy numLoops, set setup->numLoops to 1 to compress data, then
             * restore setup->numLoops to measure decompress performance*/
            numLoops = setup_sym->numLoops;
            setup_sym->numLoops = 1;

            status =
                qatSymPerform(setup_sym, encryptOpData, srcBufferListArray);
            if (CPA_STATUS_SUCCESS == status)
            {
                /*restore setup->NumLoops*/
                setup_sym->numLoops = numLoops;
                status =
                    qatSymPerform(setup_sym, decryptOpData, srcBufferListArray);
            }
        }

        else if (setup_sym->setupData.cipherSetupData.cipherDirection ==
                     CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT &&
                 reliability_g == CPA_TRUE)
        {

            /*copy numLoops, set setup->numLoops to 1 to do repeated
             * compress-swdecompress for numLoops times*/
            numLoops = setup_sym->numLoops;
            setup_sym->numLoops = 1;
            for (i = 0; i < numLoops; i++)
            {

                status =
                    qatSymPerform(setup_sym, encryptOpData, srcBufferListArray);

                // now i need to decrypt

                if (CPA_STATUS_SUCCESS == status)
                {
                    status = qatSymPerform(
                        setup_sym, decryptOpData, srcBufferListArray);

                    if (CPA_STATUS_SUCCESS == status)
                    {
                        /*3rd param is compression setup struct, need to
                        resolve status = qatCmpBuffers(srcBufferListArray,
                            copyBufferListArray,
                            setup_sym);*/
                    }
                }
                if (CPA_STATUS_SUCCESS != status)
                {
                    break;
                }
            }
        }
    }

    // SYMMETRIC
    status = qatSymFreeOpData(setup_sym, encryptOpData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free pIv and auth memory in encryptOpData ");
        status = CPA_STATUS_FAIL;
    }

    status = qatSymFreeOpData(setup_sym, decryptOpData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free pIv and auth memory in decryptOpData ");
        status = CPA_STATUS_FAIL;
    }

    /* Remove the session free the handle */
    if (CPA_STATUS_SUCCESS != qatSymSessionTeardown(setup_sym,
                                                    &encryptSessionCtx,
                                                    &decryptSessionCtx))
    {
        PRINT_ERR("qatSymSessionTeardown error\n");
        status = CPA_STATUS_FAIL;
    }

    /* Free CpaFlatBuffers and privateMetaData in CpaBufferLists */
    if (CPA_STATUS_SUCCESS != qatFreeSymFlatBuffers(setup_sym,
                                                    srcBufferListArray,
                                                    copyBufferListArray))
    {
        PRINT_ERR("qatFreeSymFlatBuffers error\n");
        status = CPA_STATUS_FAIL;
    }

    /* Free CpaBufferLists and encrypt/decrypt OpData */
    if (CPA_STATUS_SUCCESS != qatFreeSymLists(&srcBufferListArray,
                                              &copyBufferListArray,
                                              &encryptOpData,
                                              &decryptOpData))
    {
        PRINT_ERR("qatFreeSymLists error\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}

void qatSymmetricPerformance(single_thread_test_data_t *testSetup)
{
    symmetric_test_params_t symTestSetup;
    symmetric_test_params_t *pSetup =
        ((symmetric_test_params_t *)testSetup->setupPtr);
    Cpa32U loopIteration = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    /*define the distribution of the packet mix
     * here we defined 2 lots of 10 sizes
     * later it is replicated into 100 buffers*/
    Cpa32U packetMix[NUM_PACKETS_IMIX] = {
        BUFFER_SIZE_64,   BUFFER_SIZE_752,  BUFFER_SIZE_1504, BUFFER_SIZE_64,
        BUFFER_SIZE_752,  BUFFER_SIZE_1504, BUFFER_SIZE_64,   BUFFER_SIZE_64,
        BUFFER_SIZE_1504, BUFFER_SIZE_1504, BUFFER_SIZE_752,  BUFFER_SIZE_64,
        BUFFER_SIZE_752,  BUFFER_SIZE_64,   BUFFER_SIZE_1504, BUFFER_SIZE_1504,
        BUFFER_SIZE_64,   BUFFER_SIZE_8992, BUFFER_SIZE_64,   BUFFER_SIZE_1504};
    Cpa32U *pPacketSize;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaInstanceInfo2 *instanceInfo = NULL;

    memset(&symTestSetup, 0, sizeof(symmetric_test_params_t));

    /*cast the setup to a known structure so that we can populate our local
     * test setup*/
    symTestSetup.setupData = pSetup->setupData;

    if (reliability_g)
    {
        PRINT("\nThread %u, LI %u,  ",
              testSetup->threadID,
              testSetup->logicalQaInstance);
        if (symTestSetup.setupData.symOperation == CPA_CY_SYM_OP_CIPHER)
        {
            PRINT("Cipher ");
            printCipherAlg(symTestSetup.setupData.cipherSetupData);
        }
        else if (symTestSetup.setupData.symOperation == CPA_CY_SYM_OP_HASH)
        {
            PRINT("Hash ");
            printHashAlg(symTestSetup.setupData.hashSetupData);
        }
        else if (symTestSetup.setupData.symOperation ==
                 CPA_CY_SYM_OP_ALGORITHM_CHAINING)
        {
            PRINT("AlgChain ");
            printCipherAlg(symTestSetup.setupData.cipherSetupData);
            PRINT(" ");
            printHashAlg(symTestSetup.setupData.hashSetupData);
        }
        PRINT(" in Reliability mode\n");
    }

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*give our thread a unique memory location to store performance stats*/
    symTestSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
        return;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    /* give our thread a logical crypto instance to use*/
    symTestSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    status = cpaCyInstanceGetInfo2(symTestSetup.cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (instanceInfo->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo->physInstId.packageId;
    }

    pPacketSize = qaeMemAlloc(sizeof(Cpa32U) * pSetup->numBuffLists);

    if (NULL == pPacketSize)
    {
        PRINT_ERR("Could not allocate memory for pPacketSize\n");
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadExit();
    }

    if (testSetup->packetSize == PACKET_IMIX)
    {
        /*we are testing IMIX so we copy buffer sizes from preallocated
         * array into symTestSetup.numBuffLists*/
        Cpa32U indexer = sizeof(packetMix) / sizeof(Cpa32U);
        for (loopIteration = 0; loopIteration < pSetup->numBuffLists;
             loopIteration++)
        {
            pPacketSize[loopIteration] = packetMix[loopIteration % indexer];
        }
    }
    else
    {
        /*we are testing a uniform bufferSize, so we set the bufferSize array
         * accordingly*/
        for (loopIteration = 0; loopIteration < pSetup->numBuffLists;
             loopIteration++)
        {
            pPacketSize[loopIteration] = testSetup->packetSize;
        }
    }
    /*initialize digestIsAppended with input parameter */
    symTestSetup.setupData.digestIsAppended = pSetup->digestAppend;

    symTestSetup.numBuffLists = pSetup->numBuffLists;
    symTestSetup.flatBufferSizeInBytes = pSetup->flatBufferSizeInBytes;
    symTestSetup.numLoops = pSetup->numLoops;
    /*reset the stats print function to NULL, we set it to the proper function
     * if the test passes at the end of this function*/
    testSetup->statsPrintFunc = NULL;
    /*assign the array of buffer sizes we are testing to the symmetric test
     * setup*/
    symTestSetup.packetSizeInBytesArray = pPacketSize;
    /*assign our thread a unique memory location to store performance stats*/
    symTestSetup.performanceStats = testSetup->performanceStats;
    symTestSetup.performanceStats->packageId =
        instanceInfo->physInstId.packageId;
    symTestSetup.performanceStats->averagePacketSizeInBytes =
        testSetup->packetSize;
    /* give our thread a logical crypto instance to use*/
    symTestSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    symTestSetup.syncMode = pSetup->syncMode;
    /*store core affinity, this assumes logical cpu core number is the same
     * logicalQaInstace */
    symTestSetup.performanceStats->logicalCoreAffinity =
        testSetup->logicalQaInstance;
    symTestSetup.threadID = testSetup->threadID;
    symTestSetup.isDpApi = pSetup->isDpApi;
    symTestSetup.cryptoSrcOffset = pSetup->cryptoSrcOffset;
    symTestSetup.digestAppend = pSetup->digestAppend;
    /*launch function that does all the work*/

    if (CPA_TRUE != checkCapability(cyInstances[testSetup->logicalQaInstance],
                                    &symTestSetup))
    {
        PRINT("\nThread %u Invalid test\n", testSetup->threadID);
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
        sampleCodeBarrier();
        qaeMemFree((void **)&pPacketSize);
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadComplete(testSetup->threadID);
    }

    status = scSymPoc(&symTestSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        printSymTestType(&symTestSetup);
        PRINT("Test %u FAILED\n", testSetup->threadID);
        symTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        if (reliability_g)
        {
            PRINT("Symmetric thread %u complete\n", testSetup->threadID);
        }
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
    }
    if ((CPA_STATUS_SUCCESS != status) ||
        (symTestSetup.performanceStats->threadReturnStatus == CPA_STATUS_FAIL))
    {
        /* Stop Cy Service function should be called after all threads
         * complete their execution. This function will be called from
         * WaitForThreadCompletion().*/
        testSetup->statsPrintFunc =
            (stats_print_func_t)stopCyServicesFromCallback;
    }

    /*free memory and exit*/
    qaeMemFree((void **)&pPacketSize);
    qaeMemFree((void **)&cyInstances);
    qaeMemFree((void **)&instanceInfo);
    sampleCodeThreadComplete(testSetup->threadID);
}

CpaStatus setupNewSymmetricTest(
    CpaCySymOp opType,
    CpaCySymCipherAlgorithm cipherAlg,
    Cpa32U cipherKeyLengthInBytes,
    Cpa32U cipherOffset,
    CpaCyPriority priority,
    CpaCySymHashAlgorithm hashAlg,
    CpaCySymHashMode hashMode,
    Cpa32U authKeyLengthInBytes,
    CpaCySymAlgChainOrder chainOrder,
    sync_mode_t syncMode,
    CpaCySymHashNestedModeSetupData *nestedModeSetupDataPtr,
    Cpa32U packetSize,
    Cpa32U bufferSizeInBytes,
    Cpa32U numBuffLists,
    Cpa32U numLoops,
    Cpa32U digestAppend)
{
    /*thread_setup_g is a multidimensional global array that stores the setup
     * for all thread variations in an array of characters. We store our test
     * setup at the start of the second array ie index 0. There maybe multiple
     * thread types(setups) running as counted by testTypeCount_g*/
    symmetric_test_params_t *symmetricSetup = NULL;
    Cpa8S name[] = {'S', 'Y', 'M', '\0'};

    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    /* Return an error if the number of packets is not modulus zero of the
     * number of packets to cover IMIX packet mix.
     */
    if (packetSize == PACKET_IMIX && (numBuffLists % NUM_PACKETS_IMIX) != 0)
    {
        PRINT_ERR("To ensure that the weighting of IMIX packets is correct "
                  ", the number of buffers (%d) should be a multiple of %d\n",
                  numBuffLists,
                  NUM_PACKETS_IMIX);
        return CPA_STATUS_FAIL;
    }

    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Failed to start Crypto services\n");
        return CPA_STATUS_FAIL;
    }
    if (!poll_inline_g)
    {
        /* start polling threads if polling is enabled in the configuration file
         */
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }
    /*as setup is a multidimensional char array we need to cast it to the
     * symmetric structure*/
    memcpy(&thread_name_g[testTypeCount_g][0], name, THREAD_NAME_LEN);
    symmetricSetup =
        (symmetric_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    memset(symmetricSetup, 0, sizeof(symmetric_test_params_t));
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)sampleSymmetricPerformance;
    testSetupData_g[testTypeCount_g].packetSize = packetSize;
    /*then we store the test setup in the above location*/
    // symmetricSetup->setupData.sessionPriority=CPA_CY_PRIORITY_HIGH;
    symmetricSetup->setupData.sessionPriority = priority;
    symmetricSetup->setupData.symOperation = opType;
    symmetricSetup->setupData.cipherSetupData.cipherAlgorithm = cipherAlg;
    symmetricSetup->setupData.cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    symmetricSetup->setupData.cipherSetupData.cipherKeyLenInBytes =
        cipherKeyLengthInBytes;
    symmetricSetup->setupData.hashSetupData.hashAlgorithm = hashAlg;
    symmetricSetup->setupData.hashSetupData.hashMode = hashMode;
    symmetricSetup->isDpApi = CPA_FALSE;
    symmetricSetup->cryptoSrcOffset = cipherOffset;
    /* in this code we limit the digest result len to be the same as the the
     * authentication key len*/
    symmetricSetup->setupData.hashSetupData.digestResultLenInBytes =
        authKeyLengthInBytes;

    /* GCM hash works only on 8,12 and 16 bytes, default to 16 if others */
    if (CPA_CY_SYM_HASH_AES_GCM == hashAlg &&
        (authKeyLengthInBytes != 8 && authKeyLengthInBytes != 12 &&
         authKeyLengthInBytes != 16))
    {
        PRINT("CPA_CY_SYM_HASH_AES_GCM digest length %u unsupported , "
              "defaulting to 16 \n",
              authKeyLengthInBytes);
        symmetricSetup->setupData.hashSetupData.digestResultLenInBytes = 16;
    }

#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
    // for SH3  keylength == blocklength. And keylength might be > = digestlen

    if (CPA_CY_SYM_HASH_SHA3_256 == hashAlg)
    {
        symmetricSetup->setupData.hashSetupData.digestResultLenInBytes =
            setHashDigestLen(hashAlg);
    }
#endif
    // check which kind of hash mode is selected
    if (CPA_CY_SYM_HASH_MODE_NESTED == hashMode)
    { // nested mode
        // set the struct for nested hash mode
        if (NULL == nestedModeSetupDataPtr)
        {
            // set a default nested mode setup data
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .outerHashAlgorithm = hashAlg;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .pInnerPrefixData = NULL;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .innerPrefixLenInBytes = 0;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .pOuterPrefixData = NULL;
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData
                .outerPrefixLenInBytes = 0;
        }
        else
        {
            symmetricSetup->setupData.hashSetupData.nestedModeSetupData =
                *nestedModeSetupDataPtr;
        }
    }

    if ((CPA_CY_SYM_HASH_AES_XCBC == hashAlg) &&
        (AES_XCBC_DIGEST_LENGTH_IN_BYTES != authKeyLengthInBytes))
    {
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = AES_XCBC_DIGEST_LENGTH_IN_BYTES;
    }
    else if ((CPA_CY_SYM_HASH_KASUMI_F9 == hashAlg) ||
             (CPA_CY_SYM_HASH_SNOW3G_UIA2 == hashAlg))
    {
        /*
         * KASUMI_F9 and SNOW3G_UIA2 supports authKeyLen=128bits
         * and digestResultLen=32bits
         */
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = KASUMI_F9_OR_SNOW3G_UIA2_KEY_SIZE_128_IN_BYTES;
        symmetricSetup->setupData.hashSetupData.digestResultLenInBytes =
            setHashDigestLen(hashAlg);
    }

#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
    // ZUC-EIA3 supports authKeyLen=128bits and digestResultLen=32bits
    else if (CPA_CY_SYM_HASH_ZUC_EIA3 == hashAlg)
    {
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = KEY_SIZE_128_IN_BYTES;
    }
#endif
    else
    {
        symmetricSetup->setupData.hashSetupData.authModeSetupData
            .authKeyLenInBytes = authKeyLengthInBytes;
    }

    symmetricSetup->setupData.algChainOrder = chainOrder;
    symmetricSetup->syncMode = syncMode;
    symmetricSetup->flatBufferSizeInBytes = bufferSizeInBytes;
    symmetricSetup->numLoops = numLoops;
    symmetricSetup->numBuffLists = numBuffLists;
    if (((bufferSizeInBytes != 0) && (packetSize == PACKET_IMIX)) ||
        (bufferSizeInBytes % IV_LEN_FOR_16_BYTE_BLOCK_CIPHER != 0))
    {
        PRINT_ERR("Doesn't support PACKET_IMIX  "
                  "when the flat buffer size is not 0 or "
                  " it's not align with block size (%d): ",
                  bufferSizeInBytes);
        return CPA_STATUS_FAIL;
    }
    symmetricSetup->digestAppend = digestAppend;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cipherNewPerformanceTest(CpaBoolean mode,
                                   Cpa32U mask,
                                   Cpa32U bufferSize,
                                   Cpa32U numBuffers,
                                   Cpa32U numLoops)
{
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

    if (CPA_STATUS_SUCCESS !=
        setupNewSymmetricTest(
            CPA_CY_SYM_OP_CIPHER,
            CPA_CY_SYM_CIPHER_AES_CBC,
            KEY_SIZE_128_IN_BYTES,
            NOT_USED,
            CPA_CY_PRIORITY_HIGH,
            NOT_USED /* hash alg not needed in cipher test*/,
            NOT_USED /* hash mode not needed in cipher test*/,
            NOT_USED /* auth key len not needed in cipher test*/,
            NOT_USED /* chain mode not needed in cipher test*/,
            1,
            NULL, /* nested hash data not needed in cipher test*/
            bufferSize,
            0,
            numBuffers,
            numLoops,
            digestAppended_g))
    {
        PRINT_ERR("Error setting up Cipher Test\n");
        retStatus = CPA_STATUS_FAIL;
    }
    else
    {
        if (CPA_STATUS_SUCCESS != createStartandWaitForCompletionCrypto(SYM))
        {
            retStatus = CPA_STATUS_FAIL;
            /*set status to fail,
             * but continue with rest of testing*/
        }
    }
    return retStatus;
}
