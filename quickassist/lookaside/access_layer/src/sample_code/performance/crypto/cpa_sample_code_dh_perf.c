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
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file cpa_sample_code_dh_perf.c
 *
 * @defgroup dhThreads
 *
 * @ingroup dhThreads
 *
 * @description
 *        This is a sample code that uses Diffie-Hellman APIs.
 *        In order to use this algorithm, 3 elements have to be set:
 *          - a prime number p (the modulus)
 *          - a base g
 *          - a random value x
 *
 *       This sample code defines arbitrary values for p, g and x. We simulate
 *       two peers, Bob and Alice who wish to create a shared secret key
 *
 *       Phase 1. Alices's & Bob's public value PV=g^x mod p is calculated. Both
 *       share the same p & g values but use a different x value
 *
 *       Phase 2. Based on the public value returned by the other peer, the
 *       prime number p and Alices secret value x, the private key for Alices is
 *       calculated
 *
 *       Alices Private Key = BobsPV^x mod p
 *       Bob's Private Key = AlicesPV^x mod p
 *
 *       Again the x for Alice and Bob is different, but both should calculate
 *       the same private key
 *
 *****************************************************************************/

#include "cpa.h"
#include "cpa_types.h"

#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_crypto_utils.h"

#ifdef SC_DEV_INFO_ENABLED
#include "cpa_dev.h"
#endif
#include "icp_sal_poll.h"
#include "qat_perf_cycles.h"
extern Cpa32U packageIdCount_g;

/*****************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * Diffie Hellman operation has been processed
 *****************************************************************************/
void dhCallback(void *pCallbackTag,
                CpaStatus status,
                void *pOpData,
                CpaFlatBuffer *pOut)
{
    processCallback(pCallbackTag);
}

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * DH PHASE 1 Secret number generator
 *
 * this function generates the secret value x to be used in the Diffie Hellman
 * phase 1 operation ie x in PublicValue = g^x mod p
 *
 ****************************************************************************/
void dhPhase1GenX(CpaCyDhPhase1KeyGenOpData *pCpaDhOpDataP1,
                  asym_test_params_t *setup)
{
    /*Choose x by some random method, where 0 < x < p-1*/
    generateRandomData(pCpaDhOpDataP1->privateValueX.pData,
                       pCpaDhOpDataP1->privateValueX.dataLenInBytes);

    /*make sure MSB is set*/
    setCpaFlatBufferMSB(&(pCpaDhOpDataP1->privateValueX));
    if (setup->modulusSizeInBytes == setup->exponentSizeInBytes)
    {
        makeParam1SmallerThanParam2(
            pCpaDhOpDataP1->privateValueX.pData,
            pCpaDhOpDataP1->primeP.pData,
            pCpaDhOpDataP1->privateValueX.dataLenInBytes,
            CPA_TRUE);
    }
    return;
}

#define FREE_DH_PHASE1_SETUP_MEM()                                             \
    dhMemFreePh1(setup,                                                        \
                 ppAlicePhase1,                                                \
                 ppAlicePublicValue,                                           \
                 ppBobPhase1,                                                  \
                 ppBobPublicValue)

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * populate 2 peers Phase1 opData with p, g & x, where p&g is shared and x is
 * random for each peer
 *
 * *************************************************************************/
CpaStatus dhPhase1Setup(asym_test_params_t *setup,
                        CpaCyDhPhase1KeyGenOpData **ppAlicePhase1,
                        CpaCyDhPhase1KeyGenOpData **ppBobPhase1,
                        CpaFlatBuffer **ppAlicePublicValue,
                        CpaFlatBuffer **ppBobPublicValue,
                        CpaCyRsaPublicKey **ppPublicKey)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;
    Cpa32U node = 0;

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return CPA_STATUS_FAIL;
    }

    if (NULL == ppAlicePhase1)
    {
        PRINT_ERR("Error ppAlicePhase1 Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == ppAlicePublicValue)
    {
        PRINT_ERR("Error ppAlicePublicValue Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == ppBobPhase1)
    {
        PRINT_ERR("Error ppBobPhase1 Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == ppBobPublicValue)
    {
        PRINT_ERR("Error ppAlicePhase1 Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    /*set Alice phase1 opData*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        ppAlicePhase1[i] = qaeMemAlloc(sizeof(CpaCyDhPhase1KeyGenOpData));
        /*use the pre-generated primeP if supplied*/
        /*allocate p*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &(ppAlicePhase1[i]->primeP),
                             setup->modulusSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE1_SETUP_MEM());
        /*allocate g*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &(ppAlicePhase1[i]->baseG),
                             setup->modulusSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE1_SETUP_MEM());
        /*allocate exponent x*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &(ppAlicePhase1[i]->privateValueX),
                             setup->exponentSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE1_SETUP_MEM());

        if (ppPublicKey != NULL)
        {
            memcpy(ppAlicePhase1[i]->primeP.pData,
                   ppPublicKey[i]->modulusN.pData,
                   ppPublicKey[i]->modulusN.dataLenInBytes);
            setCpaFlatBufferMSB(&(ppAlicePhase1[i]->primeP));
            ppAlicePhase1[i]->primeP.dataLenInBytes =
                ppPublicKey[i]->modulusN.dataLenInBytes;
        }
        else
        {
            if (useStaticPrime == 1)
            {
                /*generate hardcoded p, where p is a prime number*/
                status = generateHardCodedPrime1P(&(ppAlicePhase1[i]->primeP),
                                                  setup);
            }
            else
            {
                /*generate p, where p is a prime number*/
                status = generatePrime(&(ppAlicePhase1[i]->primeP),
                                       setup->cyInstanceHandle,
                                       setup);
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to generate primeP for phase1, %d\n", status);
                FREE_DH_PHASE1_SETUP_MEM();
                return status;
            }
        }
        /*Choose g by some random method, where 0 < g < p*/
        generateRandomData(ppAlicePhase1[i]->baseG.pData,
                           ppAlicePhase1[i]->baseG.dataLenInBytes);
        /*make sure MSB in baseG is set and that it a smaller value than p*/
        setCpaFlatBufferMSB(&(ppAlicePhase1[i]->baseG));
        makeParam1SmallerThanParam2(ppAlicePhase1[i]->baseG.pData,
                                    ppAlicePhase1[i]->primeP.pData,
                                    ppAlicePhase1[i]->baseG.dataLenInBytes,
                                    CPA_TRUE);
        /*generate the random x value*/
        dhPhase1GenX(ppAlicePhase1[i], setup);
        /* Allocate memory for the PublicValue buffer */
        ppAlicePublicValue[i] = qaeMemAlloc(sizeof(CpaFlatBuffer));
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             ppAlicePublicValue[i],
                             setup->modulusSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE1_SETUP_MEM());

        /*set Bob phase1 opData*/
        ppBobPhase1[i] = qaeMemAlloc(sizeof(CpaCyDhPhase1KeyGenOpData));
        /* we only allocate exponent x, both clients share p & g*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &(ppBobPhase1[i]->privateValueX),
                             setup->exponentSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE1_SETUP_MEM());
        ppBobPhase1[i]->primeP.dataLenInBytes = setup->modulusSizeInBytes;
        /*both clients share the same P, so point Bobs data to Alices data*/
        ppBobPhase1[i]->primeP.pData = ppAlicePhase1[i]->primeP.pData;
        ppBobPhase1[i]->baseG.dataLenInBytes = setup->modulusSizeInBytes;
        /*both clients share the same G*/
        ppBobPhase1[i]->baseG.pData = ppAlicePhase1[i]->baseG.pData;
        dhPhase1GenX(ppBobPhase1[i], setup);
        /* Allocate memory for the PublicValue buffer */
        ppBobPublicValue[i] = qaeMemAlloc(sizeof(CpaFlatBuffer));
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             ppBobPublicValue[i],
                             setup->modulusSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE1_SETUP_MEM());
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dhPhase1Setup);

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * DH-PHASE1
 *
 * this function performs the Diffie Hellman phase 1 operation
 *
 * *************************************************************************/
CpaStatus dhPhase1(CpaCyDhPhase1KeyGenOpData **pCpaDhOpDataP1,
                   CpaFlatBuffer **pLocalOctetStringPV,
                   asym_test_params_t *setup,
                   Cpa32U numBuffers,
                   Cpa32U numLoops)
{
    Cpa32U loops = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;
    CpaInstanceInfo2 *instanceInfo = NULL;
    Cpa32U busyLoopValue = busyLoopCounter_g;
    perf_cycles_t startBusyLoop = 0, endBusyLoop = 0;
    Cpa32U busyLoopCount = 0, staticAssign = 0;

#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_FAIL;
    perf_data_t *pPerfData = setup->performanceStats;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
#endif

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        qaeMemFree((void **)&instanceInfo);
        return CPA_STATUS_FAIL;
    }
    /*pre-set the number of ops we plan to submit*/
    setup->performanceStats->numOperations = (Cpa64U)numBuffers * numLoops;
    setup->performanceStats->responses = 0;
    setup->performanceStats->packageId = instanceInfo->physInstId.packageId;
    coo_init(setup->performanceStats, setup->performanceStats->numOperations);
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);

    /*Should not wait at barrier if only 1 loop, as this implies Alice and we
     * want to measure this
     */
    if (DH_PHASE_1 == setup->phase)
    {
        // we will execute only phase 1
        sampleCodeBarrier();
        setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();
    }
    /** Perform Diffie-Hellman Phase 1 operations */
    for (loops = 0; loops < numLoops; loops++)
    {

        for (i = 0; i < numBuffers; i++)
        {
            do
            {
                coo_req_start(setup->performanceStats);
                status = cpaCyDhKeyGenPhase1(
                    setup->cyInstanceHandle,
                    dhCallback,              /* asynchronous mode */
                    setup->performanceStats, /* Opaque user data; */
                    pCpaDhOpDataP1[i], /* Structure containing p, g and x*/
                    pLocalOctetStringPV[i]); /*Public value (output) */
                coo_req_stop(setup->performanceStats, status);
                /*this is a back off mechanism to stop the code
                 * continually submitting requests. Without this the CPU
                 * can report a soft lockup if it continually loops
                 * on busy*/
                if (status == CPA_STATUS_RETRY)
                {
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo->isPolled)
                        {
                            sampleCodeAsymPollInstance(setup->cyInstanceHandle,
                                                       0);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    setup->performanceStats->retries++;
                    if (RETRY_LIMIT ==
                        (setup->performanceStats->retries % (RETRY_LIMIT + 1)))
                    {
                        /*perform a context switch to give other processes
                         * a go*/
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);
            if (DH_PHASE_1 == setup->phase &&
                CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                busyLoop(busyLoopValue, &staticAssign);
                busyLoopCount++;
            }
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(setup->performanceStats,
                                         setup->cyInstanceHandle,
                                         &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif
        }
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, setup->cyInstanceHandle, pPerfData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            setup->performanceStats, setup->syncMode, numBuffers, numLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Thread %u timeout.", setup->threadID);
        }
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        setup->performanceStats->busyLoopCount = busyLoopCount;
        setup->performanceStats->busyLoopValue = busyLoopValue;
        busyLoopTimeStamp();
        startBusyLoop = busyLoopTimeStamp();
        for (i = 0; i < busyLoopCount; i++)
        {
            busyLoop(busyLoopValue, &staticAssign);
        }
        endBusyLoop = busyLoopTimeStamp();

        setup->performanceStats->totalBusyLoopCycles =
            endBusyLoop - startBusyLoop;
        setup->performanceStats->offloadCycles =
            (setup->performanceStats->endCyclesTimestamp -
             setup->performanceStats->startCyclesTimestamp) -
            setup->performanceStats->totalBusyLoopCycles;
        do_div(setup->performanceStats->offloadCycles,
               setup->performanceStats->responses);
    }
    coo_average(setup->performanceStats);
    coo_deinit(setup->performanceStats);

    sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);
    qaeMemFree((void **)&instanceInfo);

    return status;
}
EXPORT_SYMBOL(dhPhase1);

#define FREE_DH_PHASE2_SETUP_MEM()                                             \
    do                                                                         \
    {                                                                          \
        Cpa32U j = 0;                                                          \
        for (j = 0; j < setup->numBuffers; j++)                                \
        {                                                                      \
            if (NULL != pSecretKey[j])                                         \
            {                                                                  \
                qaeMemFreeNUMA((void **)&pSecretKey[j]->pData);                \
                qaeMemFree((void **)&pSecretKey[j]);                           \
            }                                                                  \
            if (NULL != pCpaDhOpDataP2[j])                                     \
            {                                                                  \
                qaeMemFree((void **)&pCpaDhOpDataP2[j]);                       \
            }                                                                  \
        }                                                                      \
    } while (0);

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * Phase2 setup, copy the peers Public Value in the phase2 op data structure
 * use the same p and random number from phase 1
 *
 * *************************************************************************/
CpaStatus dhPhase2Setup(CpaFlatBuffer *pSecretKey[],
                        CpaCyDhPhase1KeyGenOpData *pCpaDhOpDataP1[],
                        CpaCyDhPhase2SecretKeyGenOpData *pCpaDhOpDataP2[],
                        CpaFlatBuffer *pLocalOctetStringPV[],
                        asym_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U node = 0;
    CpaStatus status = CPA_STATUS_FAIL;

    if (NULL == pSecretKey)
    {
        PRINT_ERR("Error pSecretKey Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == pCpaDhOpDataP1)
    {
        PRINT_ERR("Error pCpaDhOpDataP1 Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == pCpaDhOpDataP2)
    {
        PRINT_ERR("Error pCpaDhOpDataP2 Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == pLocalOctetStringPV)
    {
        PRINT_ERR("Error pLocalOctetStringPV Null pointer passed\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return CPA_STATUS_FAIL;
    }

    /** In a typical application, at this stage, the public information
     * (prime number, base and the public value that has just been
     * calculated by cpaCyDhKeyGenPhase1) would be sent to the other user.
     * As cpaCyDhKeyGenPhase1 runs in asynchronous mode, it is sure that the
     * public value has been calculated.
     * The user would then send back a remoteOctet value.
     */
    for (i = 0; i < setup->numBuffers; i++)
    {
        pSecretKey[i] = qaeMemAlloc(sizeof(CpaFlatBuffer));
        if (NULL == pSecretKey[i])
        {
            PRINT_ERR("could not allocate mem for secret key %u\n", i);
            FREE_DH_PHASE2_SETUP_MEM();
            return CPA_STATUS_FAIL;
        }
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pSecretKey[i],
                             setup->modulusSizeInBytes,
                             NULL,
                             0,
                             FREE_DH_PHASE2_SETUP_MEM());
        pCpaDhOpDataP2[i] =
            qaeMemAlloc(sizeof(CpaCyDhPhase2SecretKeyGenOpData));
        if (NULL == pCpaDhOpDataP2[i])
        {
            PRINT("pCpaDhOpDataP2[%d] is NULL \n", i);
            FREE_DH_PHASE2_SETUP_MEM();
            return CPA_STATUS_FAIL;
        }
        memset(pCpaDhOpDataP2[i], 0, sizeof(CpaCyDhPhase2SecretKeyGenOpData));

        pCpaDhOpDataP2[i]->primeP.pData = pCpaDhOpDataP1[i]->primeP.pData;
        pCpaDhOpDataP2[i]->primeP.dataLenInBytes = setup->modulusSizeInBytes;
        pCpaDhOpDataP2[i]->remoteOctetStringPV.pData =
            pLocalOctetStringPV[i]->pData;
        pCpaDhOpDataP2[i]->remoteOctetStringPV.dataLenInBytes =
            pLocalOctetStringPV[i]->dataLenInBytes;
        pCpaDhOpDataP2[i]->privateValueX.pData =
            pCpaDhOpDataP1[i]->privateValueX.pData;
        pCpaDhOpDataP2[i]->privateValueX.dataLenInBytes =
            pCpaDhOpDataP1[i]->privateValueX.dataLenInBytes;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dhPhase2Setup);

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * perform the phase2 operation to produce the secret key
 *
 * *************************************************************************/
CpaStatus dhPhase2Perform(CpaFlatBuffer **pOctetStringSecretKey,
                          CpaCyDhPhase2SecretKeyGenOpData **pCpaDhOpDataP2,
                          asym_test_params_t *setup,
                          Cpa32U numBuffers,
                          Cpa32U numLoops)
{
    Cpa32U i = 0;
    Cpa32U loops = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;
    CpaInstanceInfo2 *instanceInfo = NULL;

#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_FAIL;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
    perf_data_t *pPerfData = setup->performanceStats;
#endif

    DECLARE_IA_CYCLE_COUNT_VARIABLES();

    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        timeStampTime_g = getTimeStampTime();
        PRINT("timeStampTime_g %llu\n", timeStampTime_g);
    }
    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        qaeMemFree((void **)&instanceInfo);
        return CPA_STATUS_FAIL;
    }
    /*pre-set the number of ops we plan to submit*/
    memset(setup->performanceStats, 0, sizeof(perf_data_t));
    setup->performanceStats->numOperations = (Cpa64U)numLoops * numBuffers;
    setup->performanceStats->responses = 0;
    setup->performanceStats->retries = 0;
    setup->performanceStats->packageId = instanceInfo->physInstId.packageId;
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);
    coo_init(setup->performanceStats, setup->performanceStats->numOperations);
    if (NULL == pOctetStringSecretKey)
    {
        PRINT_ERR("Error pOctetStringSecretKey Null pointer passed\n");
        qaeMemFree((void **)&instanceInfo);
        return CPA_STATUS_FAIL;
    }
    if (NULL == pCpaDhOpDataP2)
    {
        PRINT_ERR("Error pCpaDhOpDataP2 Null pointer passed\n");
        qaeMemFree((void **)&instanceInfo);
        return CPA_STATUS_FAIL;
    }
    if (ASYNC == setup->syncMode)
    {
        cbFunc = dhCallback;
    }
    /*this barrier will wait until all threads get to this point*/
    /*don't want to wait here if its alice as she only loops once*/
    sampleCodeBarrier();
    setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();
    for (loops = 0; loops < numLoops; loops++)
    {
        for (i = 0; i < numBuffers; i++)
        {
            do
            {
                coo_req_start(setup->performanceStats);
                status = cpaCyDhKeyGenPhase2Secret(setup->cyInstanceHandle,
                                                   cbFunc,
                                                   setup->performanceStats,
                                                   pCpaDhOpDataP2[i],
                                                   pOctetStringSecretKey[i]);
                coo_req_stop(setup->performanceStats, status);
                /* this is a back off mechanism to stop the code
                 * continually calling the Decrypt operation when the
                 * acceleration units are busy. Without this the CPU
                 * can report a soft lockup if it continually loops
                 * on busy
                 */
                if (status == CPA_STATUS_RETRY)
                {
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo->isPolled)
                        {
                            icp_sal_CyPollInstance(setup->cyInstanceHandle, 0);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    setup->performanceStats->retries++;
                    if (RETRY_LIMIT ==
                        (setup->performanceStats->retries) % (RETRY_LIMIT + 1))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);
            if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                BUSY_LOOP();
            }
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(setup->performanceStats,
                                         setup->cyInstanceHandle,
                                         &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif

            if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, setup->cyInstanceHandle, pPerfData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            setup->performanceStats, setup->syncMode, numBuffers, numLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Thread %u timeout.", setup->threadID);
        }
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        IA_CYCLE_COUNT_CALCULATION();
    }
    coo_average(setup->performanceStats);
    coo_deinit(setup->performanceStats);

    /* Completion used in callback */
    sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);

    qaeMemFree((void **)&instanceInfo);

    return status;
}
EXPORT_SYMBOL(dhPhase2Perform);

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * free the memory allocated during phase1
 *
 * *************************************************************************/
void dhMemFreePh1(asym_test_params_t *setup,
                  CpaCyDhPhase1KeyGenOpData **ppAlicePhase1,
                  CpaFlatBuffer **ppAlicePublicValue,
                  CpaCyDhPhase1KeyGenOpData **ppBobPhase1,
                  CpaFlatBuffer **ppBobPublicValue)
{
    Cpa32U i = 0;

    for (i = 0; i < setup->numBuffers; i++)
    {
        if (NULL != ppAlicePublicValue)
        {
            if (NULL != ppAlicePublicValue[i])
            {
                qaeMemFreeNUMA((void **)&ppAlicePublicValue[i]->pData);
                qaeMemFree((void **)&ppAlicePublicValue[i]);
            }
        }
        if (NULL != ppAlicePhase1)
        {
            /* Free opData buffers */
            if (NULL != ppAlicePhase1[i])
            {
                if (NULL != ppAlicePhase1[i]->primeP.pData)
                    qaeMemFreeNUMA((void **)&ppAlicePhase1[i]->primeP.pData);
                if (NULL != ppAlicePhase1[i]->baseG.pData)
                    qaeMemFreeNUMA((void **)&ppAlicePhase1[i]->baseG.pData);
                if (NULL != ppAlicePhase1[i]->privateValueX.pData)
                    qaeMemFreeNUMA(
                        (void **)&ppAlicePhase1[i]->privateValueX.pData);

                qaeMemFree((void **)&ppAlicePhase1[i]);
            }
        }
        if (NULL != ppBobPhase1)
        {
            if (NULL != ppBobPhase1[i])
            {
                if (NULL != ppBobPhase1[i]->privateValueX.pData)
                    qaeMemFreeNUMA(
                        (void **)&ppBobPhase1[i]->privateValueX.pData);

                qaeMemFree((void **)&ppBobPhase1[i]);
            }
        }
        if (NULL != ppBobPublicValue)
        {
            if (NULL != ppBobPublicValue[i])
            {
                if (NULL != ppBobPublicValue[i]->pData)
                    qaeMemFreeNUMA((void **)&ppBobPublicValue[i]->pData);

                qaeMemFree((void **)&ppBobPublicValue[i]);
            }
        }
    }
}
EXPORT_SYMBOL(dhMemFreePh1);

/***************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * This function frees the phase 2 dynamic memory, since we point to some of the
 * memory allocated in phase1, we only need to free the private key
 * and the Phase2 opData
 *
 * *************************************************************************/
void dhMemFreePh2(asym_test_params_t *setup,
                  CpaFlatBuffer **pAliceSecretKey,
                  CpaCyDhPhase2SecretKeyGenOpData **pAlicePhase2,
                  CpaFlatBuffer **pBobSecretKey,
                  CpaCyDhPhase2SecretKeyGenOpData **pBobPhase2)
{
    Cpa32U i = 0;

    for (i = 0; i < setup->numBuffers; i++)
    {
        if (NULL != pAliceSecretKey)
        {
            if (NULL != pAliceSecretKey[i])
            {
                qaeMemFreeNUMA((void **)&pAliceSecretKey[i]->pData);
                qaeMemFree((void **)&pAliceSecretKey[i]);
            }
        }
        if (NULL != pBobSecretKey)
        {
            if (NULL != pBobSecretKey[i])
            {
                qaeMemFreeNUMA((void **)&pBobSecretKey[i]->pData);
                qaeMemFree((void **)&pBobSecretKey[i]);
            }
        }
        if (NULL != pBobPhase2)
        {
            if (NULL != pBobPhase2[i])
            {
                qaeMemFree((void **)&pBobPhase2[i]);
            }
        }
        if (NULL != pAlicePhase2)
        {
            if (NULL != pAlicePhase2[i])
            {
                qaeMemFree((void **)&pAlicePhase2[i]);
            }
        }
    }
}
EXPORT_SYMBOL(dhMemFreePh2);

#define DH_MEM_FREE()                                                          \
    do                                                                         \
    {                                                                          \
        FREE_DH_PHASE1_SETUP_MEM();                                            \
        qaeMemFree((void **)&ppAlicePublicValue);                              \
        qaeMemFree((void **)&ppBobPublicValue);                                \
        qaeMemFree((void **)&ppAlicePhase1);                                   \
        qaeMemFree((void **)&ppBobPhase1);                                     \
        dhMemFreePh2(                                                          \
            setup, pAliceSecretKey, pAlicePhase2, pBobSecretKey, pBobPhase2);  \
        qaeMemFree((void **)&pAliceSecretKey);                                 \
        qaeMemFree((void **)&pBobSecretKey);                                   \
        qaeMemFree((void **)&pBobPhase2);                                      \
        qaeMemFree((void **)&pAlicePhase2);                                    \
    } while (0)

/*****************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * Perform Diffie-Hellman phase 1 and 2 operations
 *****************************************************************************/
static CpaStatus dhPerform(asym_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    perf_data_t *pDhData = NULL;
    /** Pointer that will contain the public value for Alice(returned by
     * cpaCyDhKeyGenPhase1) */
    CpaFlatBuffer **ppAlicePublicValue = NULL;
    /** Pointer that will contain the public value for Bob(returned by
     * cpaCyDhKeyGenPhase1) */
    CpaFlatBuffer **ppBobPublicValue = NULL;
    /** Pointer that will contain the private key created by Alice
     * (returned by cpaCyDhKeyGenPhase2) */
    CpaFlatBuffer **pAliceSecretKey = NULL;
    /** Pointer that will contain the private key created by Bob
     * (returned by cpaCyDhKeyGenPhase2) */
    CpaFlatBuffer **pBobSecretKey = NULL;
    CpaCyDhPhase2SecretKeyGenOpData **pAlicePhase2 = NULL;
    CpaCyDhPhase2SecretKeyGenOpData **pBobPhase2 = NULL;
    CpaCyDhPhase1KeyGenOpData **ppAlicePhase1 = NULL;
    CpaCyDhPhase1KeyGenOpData **ppBobPhase1 = NULL;
    Cpa32U node = 0;
    Cpa32U numLoopsPhase1 = 1;
    CpaBoolean stopAtPhase1 = CPA_FALSE;
    CpaInstanceInfo2 *instanceInfo2 = NULL;


    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }

    status = allocArrayOfVirtPointers((void **)&ppAlicePublicValue,
                                      setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate ppAlicePublicValue\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status =
        allocArrayOfVirtPointers((void **)&ppBobPublicValue, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate ppBobPublicValue\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status =
        allocArrayOfVirtPointers((void **)&ppAlicePhase1, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate ppAlicePhase1\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status = allocArrayOfVirtPointers((void **)&ppBobPhase1, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate ppBobPhase1\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status =
        allocArrayOfVirtPointers((void **)&pAliceSecretKey, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate pAliceSecretKey\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status =
        allocArrayOfVirtPointers((void **)&pBobSecretKey, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate pBobSecretKey\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status =
        allocArrayOfVirtPointers((void **)&pAlicePhase2, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate pAlicePhase2\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    status = allocArrayOfVirtPointers((void **)&pBobPhase2, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate pBobPhase2\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }

    /*use the pre-allocate performance stats to store performance data, this
     * points to an element in perfStats_g array in the framework, each thread
     * points to a unique element of perfStats_g array, perfStats_g is a
     * section of memory that the framework allocates to threads to store
     * performance data*/
    pDhData = setup->performanceStats;
    if (pDhData == NULL)
    {
        PRINT_ERR("perf stats pointer is NULL\n");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    memset(pDhData, 0, sizeof(perf_data_t));
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        DH_MEM_FREE();
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    if (cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2) !=
        CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        DH_MEM_FREE();
        qaeMemFree((void **)&instanceInfo2);
        return CPA_STATUS_FAIL;
    }

    pDhData->packageId = instanceInfo2->physInstId.packageId;
    qaeMemFree((void **)&instanceInfo2);

    /***************************************************************************
     * PHASE1
     ***************************************************************************/
    if (DH_PHASE_1 == setup->phase)
    {
        // we will execute only phase 1
        numLoopsPhase1 = setup->numLoops;
        stopAtPhase1 = CPA_TRUE;
    }
    /*generate p, g & x and populate into Alice and Bobs phase1 opData
     * Allocate memory for public values*/
    status = dhPhase1Setup(setup,
                           ppAlicePhase1,
                           ppBobPhase1,
                           ppAlicePublicValue,
                           ppBobPublicValue,
                           NULL);
    if (CPA_STATUS_SUCCESS != status)
    {
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }
    /*calculate Alices secret keys*/
    /* we only need to loop once to calculate all secret keys, later we
     * loop multiple times on Bob to measure performance*/
    status = dhPhase1(ppAlicePhase1,
                      ppAlicePublicValue,
                      setup,
                      setup->numBuffers,
                      1 /*loop once over all buffers*/);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("error performing DH Phase 1 for Alice\n");
        /* Free Memory */
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }
    status = dhPhase1(ppBobPhase1,
                      ppBobPublicValue,
                      setup,
                      setup->numBuffers,
                      numLoopsPhase1);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("error performing DH Phase 1 for Bob\n");
        /* Free Memory */
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }

    // check if we should stop at phase 1
    if (CPA_TRUE == stopAtPhase1)
    {
        /* Free Memory */
        DH_MEM_FREE();
        return status;
    }

    /***************************************************************************
     * PHASE2
     ***************************************************************************/
    status = dhPhase2Setup(
        pAliceSecretKey, ppAlicePhase1, pAlicePhase2, ppBobPublicValue, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("error performing DH Phase 2 setup for Alice\n");
        /* Free Memory */
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }
    status = dhPhase2Setup(
        pBobSecretKey, ppBobPhase1, pBobPhase2, ppAlicePublicValue, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("error performing DH Phase 2 setup for Bob\n");
        /* Free Memory */
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }
    /*calculate Alices secret keys*/
    /* we only need to loop once to calculate all private keys, later we
     * loop multiple times on Bob to measure performance*/
    status = dhPhase2Perform(pAliceSecretKey,
                             pAlicePhase2,
                             setup,
                             setup->numBuffers,
                             1 /*loop once over all buffers*/);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("error performing DH Phase 2 for Alice\n");
        /* Free Memory */
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }

    /*calculate Bobs secret keys*/
    status = dhPhase2Perform(
        pBobSecretKey, pBobPhase2, setup, setup->numBuffers, setup->numLoops);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("error performing DH Phase 2 for Bob\n");
        /* Free Memory */
        DH_MEM_FREE();
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return status;
    }
    /*check that the secret keys match*/
    /*should really check at the end of each loop in bob*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        if (memcmp(pAliceSecretKey[i]->pData,
                   pBobSecretKey[i]->pData,
                   setup->modulusSizeInBytes) != 0)
        {
            PRINT_ERR("Error Secret Keys do not match %d\n", i);
            status = CPA_STATUS_FAIL;
        }
    }

    /* Free Memory */
    DH_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/*****************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * Print the diffie hellman performance stats
 *****************************************************************************/
CpaStatus dhPrintStats(thread_creation_data_t *data)
{
    if (DH_PHASE_1 == ((asym_test_params_t *)data->setupPtr)->phase)
    {
        PRINT("DIFFIE-HELLMAN PHASE 1\n");
    }
    else
    {
        PRINT("DIFFIE-HELLMAN PHASE 2\n");
    }
    PRINT("Modulus Size %17u\n", data->packetSize * NUM_BITS_IN_BYTE);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * This function is called by the framework to start DH performance threads
 *****************************************************************************/
void dhPerformance(single_thread_test_data_t *testSetup)
{
    asym_test_params_t dhSetup = { 0 };
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    asym_test_params_t *params = (asym_test_params_t *)testSetup->setupPtr;
    CpaInstanceInfo2 *instanceInfo = NULL;
#ifdef SC_DEV_INFO_ENABLED
    CpaDeviceInfo deviceInfo = {0};
#endif

    testSetup->passCriteria = getPassCriteria();

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space is does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*set the print function that can be used to print stats at the end of the
     * test*/
    testSetup->statsPrintFunc = (stats_print_func_t)dhPrintStats;
    /*give our thread a unique memory location to store performance stats*/
    dhSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances*/
    dhSetup.threadID = testSetup->threadID;
    dhSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(dhSetup.cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }

#ifdef SC_DEV_INFO_ENABLED
    /* check whether asym service enabled or not for the instance */
    status = cpaGetDeviceInfo(instanceInfo->physInstId.packageId, &deviceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaGetDeviceInfo failed", __func__, __LINE__);
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadExit();
    }
    if (CPA_FALSE == deviceInfo.cyAsymEnabled)
    {
        PRINT_ERR("%s::%d Error! cyAsymEnabled service not enabled for the "
                  "configured instance\n",
                  __func__,
                  __LINE__);
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadExit();
    }
#endif
    if (instanceInfo->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo->physInstId.packageId;
    }

    dhSetup.modulusSizeInBytes = params->modulusSizeInBytes;
    dhSetup.exponentSizeInBytes = params->exponentSizeInBytes;
    dhSetup.numBuffers = params->numBuffers;
    dhSetup.numLoops = params->numLoops;
    dhSetup.syncMode = params->syncMode;
    dhSetup.phase = params->phase;
    /*launch function that does all the work*/
    status = dhPerform(&dhSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        sampleCodeBarrier();
        PRINT("DH Thread %u FAILED\n", testSetup->threadID);
    }
    else
    {
        dhSetup.performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
    }
    qaeMemFree((void **)&cyInstances);
    qaeMemFree((void **)&instanceInfo);
    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(dhPerformance);

/*****************************************************************************
 * @ingroup dhThreads
 *
 * @description
 * this function is used to setup a DH test. Once called, the framework
 * createThreads function can be called to created multiple DH threads over
 * many cores
 *****************************************************************************/
CpaStatus setupDhTest(Cpa32U modSizeInBits,
                      Cpa32U expSizeInBits,
                      sync_mode_t syncMode,
                      dh_phase_t phase,
                      Cpa32U numBuffs,
                      Cpa32U numLoops)
{
    /*thread_setup_g is a multi-dimensional array that stores the setup for all
     * thread
     * variations in an array of characters. we store our test setup at the
     * start of the second array ie index 0. There maybe multi thread types
     * (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure*/
    asym_test_params_t *dhSetup = NULL;

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
    if (iaCycleCount_g)
    {
#ifdef POLL_INLINE
        enablePollInline();
#endif
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

    dhSetup = (asym_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)dhPerformance;
    testSetupData_g[testTypeCount_g].packetSize =
        modSizeInBits / NUM_BITS_IN_BYTE;
    dhSetup->modulusSizeInBytes = modSizeInBits / NUM_BITS_IN_BYTE;
    dhSetup->exponentSizeInBytes = expSizeInBits / NUM_BITS_IN_BYTE;
    dhSetup->syncMode = syncMode;
    dhSetup->numBuffers = numBuffs;
    dhSetup->numLoops = numLoops;
    dhSetup->phase = phase;
    return CPA_STATUS_SUCCESS;
}
