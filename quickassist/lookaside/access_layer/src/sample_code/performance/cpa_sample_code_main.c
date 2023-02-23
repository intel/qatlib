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
 **************************************************************************/

/**
 ***************************************************************************
 * @file cpa_sample_code_main.c
 *
 * This file provides the main function, which calls out what to measure the
 * performance of
 *
 **************************************************************************/

// Local define to allow CRYPTO to be included or excluded from compilation
// Redundant here (except for test purposes)as set by performance sample code
// Makefile.
//#define DO_CRYPTO

#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_cy_im.h"
#ifdef INCLUDE_COMPRESSION
#include "cpa_dc.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_dc_utils.h"
#include "cpa_sample_code_dc_dp.h"
#include "qat_compression_main.h"
#endif
#include "cpa_sample_code_sym_perf_dp.h"

#ifndef INCLUDE_COMPRESSION
/*define this just so that sample code will build without compression code*/
#define MIN_DC_LOOPS (1)
#ifdef __x86_64__
#define DEFAULT_DC_LOOPS (100)
#else
#define DEFAULT_DC_LOOPS (200)
#endif
#define SINGLE_REQUEST (1)
#else
corpus_type_t sampleCorpus;
#endif

#if CY_API_VERSION_AT_LEAST(3, 0)

#ifdef SC_KPT2_ENABLED
#ifdef SC_SM2_ENABLED
#define ASYMETRIC_CODE                                                         \
    (RSA_CODE | DSA_CODE | ECDSA_CODE | DH_CODE | KPT_RSA_CODE |               \
     KPT_ECDSA_CODE | SM2_CODE)
#else /*#SC_SM2_ENABLED*/
#define ASYMETRIC_CODE                                                         \
    (RSA_CODE | DSA_CODE | ECDSA_CODE | DH_CODE | KPT_RSA_CODE | KPT_ECDSA_CODE)
#endif /*#SC_SM2_ENABLED*/
#else  /*#SC_KPT2_ENABLED*/
#ifdef SC_SM2_ENABLED
#define ASYMETRIC_CODE (RSA_CODE | DSA_CODE | ECDSA_CODE | DH_CODE | SM2_CODE)
#else
#define ASYMETRIC_CODE (RSA_CODE | DSA_CODE | ECDSA_CODE | DH_CODE)
#endif
#endif /*#SC_KPT2_ENABLED*/
#else  /*#if CY_API_VERSION_AT_LEAST(3, 0)*/
#define ASYMETRIC_CODE (RSA_CODE | DSA_CODE | ECDSA_CODE | DH_CODE)
#endif /*#if CY_API_VERSION_AT_LEAST(3, 0)*/

#if CY_API_VERSION_AT_LEAST(3, 0)
/*add for SM3 and SM4*/
extern smx_key_size_pairs_t cipherSM4TestList[];
extern smx_key_size_pairs_t algChainSM4SM3TestList[];
extern int cipherSM4TestList_count;
extern int algChainSM4SM3TestList_count;
#endif

#ifdef USER_SPACE

extern CpaStatus qaeMemInit(void);
extern void qaeMemDestroy(void);
extern Cpa32U getCPUSpeed(void);
extern Cpa32U updateCPUSpeed(void);

int runTests;
int signOfLife;
int cyNumBuffers;
int cyAsymLoops;
int cySymLoops;
int dcLoops;
int includeWirelessAlgs;
int configFileVersion;
int runStateful;
int includeLZ4;

option_t optArray[MAX_NUMOPT] = {
    {"signOfLife", DEFAULT_SIGN_OF_LIFE},
    {"runTests", RUN_ALL_TESTS},
    {"cyNumBuffers", DEFAULT_CY_BUFFERS},
    {"cyAsymLoops", DEFAULT_ASYM_LOOPS},
    {"cySymLoops", DEFAULT_SYM_LOOPS},
    {"dcLoops", DEFAULT_DC_LOOPS},
    {"includeWirelessAlgs", DEFAULT_INCLUDE_WIRELESS_ALGS},
    {"configFileVer", USE_V2_CONFIG_FILE},
    {"runStateful", 0},
    {"useStaticPrime", 1},
    {"getLatency", 0},
    {"getOffloadCost", 0},
    {"includeLZ4", DEFAULT_INCLUDE_LZ4},
    {"compOnly", 0},
    {"verboseOutput", 1}};

#define SIGN_OF_LIFE_OPT_ARRAY_POS (0)
#define RUN_TEST_OPT_ARRAY_POS (1)
#define NUM_BUFFERS_OPT_ARRAY_POS (2)
#define ASYM_LOOPS_OPT_ARRAY_POS (3)
#define SYM_LOOPS_OPT_ARRAY_POS (4)
#define DC_LOOPS_OPT_ARRAY_POS (5)
#define WIRELESS_ALGS_OPT_ARRAY_POS (6)
#define CONFIG_FILE_OPT_ARRAY_POS (7)
#define RUN_STATEFUL_ARRAY_POS (8)
#define USE_STATIC_PRIME (9)
#define GET_LATENCY_POS (10)
#define GET_OFFLOAD_COST_POS (11)
#define RUN_LZ4_TEST_POS (12)

#else /* #ifdef USER_SPACE */

extern int cyNumBuffers;
extern int cySymLoops;
extern int cyAsymLoops;
extern int dcLoops;
extern int runTests;
extern int includeWirelessAlgs;
extern int signOfLife;
extern int runStateful;
extern int verboseOutput;

#endif /* #ifdef USER_SPACE */

/*this function contains the top level tests, it is called main to support
 * user space executable, otherwise it is called in kernel space by the kernel
 * space init upon loading of the kernel module
 *
 * A test is made of of the following:
 *
 * 1. User calls their setup Test function, to set the feature specific
 * parameters that will be used when threads are created
 *
 * 2. user calls createPerfomanceThreads to create the test as setup in step2
 * across IA cores and acceleration units
 *
 * 3. User repeats steps 1-2 to setup more tests, ie to test co-existence of
 * crypto and datacompression, we call step 1-2 to setup crypto threads, then
 * step 1-2 again to setup data compression threads.
 *
 * 4. User calls startThreads so that the OS can start all the created threads
 *
 * 5. User waits for all threads to complete, when complete the statsPrintOut
 * function is called for each type of thread (the user is expect to provide
 * a statsPrintFunc in implementation of there setup Function used in step 1)
 *
 * 6. Repeat 1-5 for each test
 * */

CpaInstanceHandle *cyInst_g = NULL;
CpaInstanceHandle *symCyInst_g = NULL;
CpaInstanceHandle *asymCyInst_g = NULL;
CpaInstanceHandle *dcInst_g = NULL;
Cpa32U *cyInstMap_g = NULL;
Cpa32U *symCyInstMap_g = NULL;
Cpa32U *asymCyInstMap_g = NULL;
Cpa32U *dcInstMap_g = NULL;
Cpa32U instMap_g;
Cpa16U numInst_g = 0;
Cpa8U singleInstRequired_g = 0;
extern Cpa32U packageIdCount_g;
extern CpaBoolean devicesCounted_g;

#ifdef USER_SPACE
#define MAX_SAMPLE_LOOPS 5
#define ONE_KILO 1000
/* check the core frequency stability */
static CpaStatus isCoreFreqStable(void)
{
    Cpa32U curr_freq = 0;
    Cpa32U prev_freq = 0;
    Cpa32U i = 0;
    getCPUSpeed();
    curr_freq = sampleCodeGetCpuFreq() / ONE_KILO;
    prev_freq = curr_freq;
    for (i = 0; i < MAX_SAMPLE_LOOPS; i++)
    {
        updateCPUSpeed();
        curr_freq = sampleCodeGetCpuFreq() / ONE_KILO;
        if (curr_freq != prev_freq)
        {
            return CPA_STATUS_FAIL;
        }
        prev_freq = curr_freq;
    }
    return CPA_STATUS_SUCCESS;
}

/* check if only one QAT instance is enabled*/
CpaStatus checkSingleInstance()
{
    Cpa16U numInstances = 0;
    CpaStatus status = CPA_STATUS_FAIL;
#ifdef DO_CRYPTO
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances > 1)
    {
        return CPA_STATUS_FAIL;
    }
    numInstances = 0;
#endif /* DO_CRYPTO */
#ifdef INCLUDE_COMPRESSION
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances > 1)
    {
        return CPA_STATUS_FAIL;
    }
#endif /* INCLUDE_COMPRESSION */
    return CPA_STATUS_SUCCESS;
}
#endif /* USER_SPACE */

/***************************************************************************
 * what code to run
 **************************************************************************/

#define SYMMETRIC_CODE (1)
#define RSA_CODE (2)
#define DSA_CODE (4)
#define ECDSA_CODE (8)
#define DH_CODE (16)
#define COMPRESSION_CODE (32)
#define CHAINING_CODE (128)
#if CY_API_VERSION_AT_LEAST(3, 0)
#define SMx_CODE (2048)
#ifdef SC_KPT2_ENABLED
#define KPT_RSA_CODE (256)
#define KPT_ECDSA_CODE (512)
#endif
#ifdef SC_SM2_ENABLED
#define SM2_CODE (1024)
#endif
#endif
#define FIRST_INSTANCE (1)

/***************************************************************************
 * number of simultaneous threads to run for stateful compression
 **************************************************************************/
#define NUMBER_SIMILTANEOUS_THREADS (16)
#define NUMBER_OF_CORES_TO_USE (8)

#define KASUMI_40_BYTE_BUFFER (40)

/*add for SM2*/
#ifdef SC_SM2_ENABLED
#define SM2_TEST_ALL_STEPS (6)
#endif

int main(int argc, char *argv[])
{

    /*These are the packet sizes to measure performance off PACKET_IMIX is an
     * average of a mix of packet sizes - see PACKET_IMIX definition for this
     * mix*/
    Cpa32U lv_count = 0;
    Cpa16U i = 0;
    Cpa16S prevDevId = -1;
#ifdef INCLUDE_COMPRESSION
    Cpa16U numDcInst = 0;
    Cpa32U statefulMultiThreadCoreMap[NUMBER_SIMILTANEOUS_THREADS];
    Cpa32U dcBufferSize = 0;
    CpaBoolean dynamicEnabled = CPA_FALSE;
    CpaDcInstanceCapabilities dcCap = {0};
#endif

    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;
#ifdef USER_SPACE
#ifdef SC_CHAINING_ENABLED
    Cpa32U prevCnVRequestFlag = 0;
#endif
#endif
    CpaInstanceInfo2 *info = NULL;
#ifdef DO_CRYPTO
    CpaStatus status_asym = CPA_STATUS_FAIL;
    CpaCySymCapabilitiesInfo symCapInfo = {{0}};
    Cpa32U computeLatency = 0;
    CpaCyCapabilitiesInfo symCap = {0};
    CpaCyCapabilitiesInfo asymCap = {0};
    Cpa16U includeKasumiAlg = 0;
    Cpa16U includeSnow3GAlgChain = 0;
#else
#ifdef USER_SPACE
    Cpa32U computeLatency = 0;
#endif
#endif
#ifdef USER_SPACE
    char *processName = NULL;
    Cpa32U computeOffloadCost = 0;

    if (0 != parseArg(argc, argv, optArray, MAX_NUMOPT))
    {
        return 0;
    }
    signOfLife = optArray[SIGN_OF_LIFE_OPT_ARRAY_POS].optValue;
    runTests = optArray[RUN_TEST_OPT_ARRAY_POS].optValue;
    cyNumBuffers = optArray[NUM_BUFFERS_OPT_ARRAY_POS].optValue;
    cyAsymLoops = optArray[ASYM_LOOPS_OPT_ARRAY_POS].optValue;
    cySymLoops = optArray[SYM_LOOPS_OPT_ARRAY_POS].optValue;
    dcLoops = optArray[DC_LOOPS_OPT_ARRAY_POS].optValue;
    includeWirelessAlgs = optArray[WIRELESS_ALGS_OPT_ARRAY_POS].optValue;
    configFileVersion = optArray[CONFIG_FILE_OPT_ARRAY_POS].optValue;
    runStateful = optArray[RUN_STATEFUL_ARRAY_POS].optValue;
    computeLatency = optArray[GET_LATENCY_POS].optValue;
    computeOffloadCost = optArray[GET_OFFLOAD_COST_POS].optValue;
    includeLZ4 = optArray[RUN_LZ4_TEST_POS].optValue;

#ifndef LATENCY_CODE
    /* If Latency support is not compiled in and the user asks
     * for latency computation, flag the warning.
     */
    if (computeLatency != 0)
    {
        PRINT("Warning! Latency computation is not supported\n");
        computeLatency = 0;
    }
#endif

    if (computeLatency != 0 && computeOffloadCost != 0)
    {
        PRINT_ERR(
            "ERROR: Latency and Offload cost cannot be computed together\n");
        return CPA_STATUS_FAIL;
    }

    if (computeLatency != 0)
    {
        /*the asym operations are generally long and it takes a while to wait
         * for a completion in the latency mode. Therefore we decrease it to
         * a smaller value*/
        cyAsymLoops = 100;
    }

    if (computeLatency != 0 || computeOffloadCost != 0)
    {
        const char *const op = computeLatency != 0 ? "Latency" : "Offload Cost";

        /* use single instance for latency and COO */
        singleInstRequired_g = 1;
        /* Sign of Life has too little iteration to do
         * computation of latency or offload cost. Flag
         * a warning and continue with the test.
         */
        if (signOfLife != 0)
        {
            PRINT("WARNING! %s computation is unavailable with signOfLife.\n",
                  op);
        }
#ifdef SC_PARAM_CHECK_ENABLED
        PRINT("WARNING! Param Check is enabled, this may effect %s computation"
              "\n",
              op);
#endif
#ifdef SC_STATS_ENABLED
        PRINT("WARNING! Stats enabled, this may effect %s computation\n", op);
#endif
        if (CPA_STATUS_SUCCESS != isCoreFreqStable())
        {
            PRINT("WARNING! Core frequency is not stable, this may effect %s"
                  "computation\n",
                  op);
        }
    }

#ifdef LATENCY_CODE
    enableLatencyMeasurements(computeLatency != 0 ? 1 : 0);
#endif

    if (computeOffloadCost != 0)
    {
        enableCycleCount();
    }
    else
    {
        disableCycleCount();
    }

    useStaticPrime = optArray[USE_STATIC_PRIME].optValue;

    if (CPA_STATUS_SUCCESS != qaeMemInit())
    {
        PRINT_ERR("Could not start usdm_drv for user space\n");
        PRINT("Has the usdm_drv module been loaded?\n");
        return CPA_STATUS_FAIL;
    }
    else
    {
        PRINT("qaeMemInit started\n");
    }
    processName = "SSL";

    if (USE_V1_CONFIG_FILE == configFileVersion)
    {
        if (CPA_STATUS_SUCCESS != icp_sal_userStart(processName))
        {
            PRINT_ERR("Could not start sal for user space\n");
            return CPA_STATUS_FAIL;
        }
        else
        {
            PRINT("icp_sal_userStart(\"%s\") started\n", processName);
        }
    }
    else if (USE_V2_CONFIG_FILE == configFileVersion)
    {
        if (CPA_STATUS_SUCCESS !=
            icp_sal_userStartMultiProcess(processName, CPA_FALSE))
        {
            PRINT_ERR("Could not start sal for user space\n");
            return CPA_STATUS_FAIL;
        }
        else
        {
            PRINT("icp_sal_userStartMultiProcess(\"%s\") started\n",
                  processName);
        }
    }
    else
    {
        PRINT_ERR("Invalid configFileVer specified(%d) "
                  "valid values are 1 or 2\n",
                  configFileVersion);
        return CPA_STATUS_FAIL;
    }

#endif // USER_SPACE

    if (signOfLife)
    {
        cyNumBuffers = MIN_CY_BUFFERS;
        cySymLoops = MIN_SYM_LOOPS;
        cyAsymLoops = MIN_ASYM_LOOPS;
        dcLoops = MIN_DC_LOOPS;
    }

#ifdef DO_CRYPTO
    status = cpaCyGetNumInstances(&numInst_g);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", status);
        return status;
    }
    if (numInst_g > 0)
    {
        /* use single instance for latency and COO */
        if (singleInstRequired_g)
        {
            numInst_g = 1;
        }
        /*allocate memory to store the instance handles*/
        cyInst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInst_g);
        if (cyInst_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instances\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        /*get the instances handles and place in allocated memory*/
        status = cpaCyGetInstances(numInst_g, cyInst_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyGetInstances failed with status: %d\n", status);
            freeInstanceMapping();
            return status;
        }

        /*allocate memory for the instance core mapping*/
        cyInstMap_g = qaeMemAlloc(sizeof(Cpa32U) * numInst_g);
        if (cyInstMap_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instance mapping\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        info = qaeMemAlloc(sizeof(CpaInstanceInfo2));
        if (info == NULL)
        {
            PRINT_ERR("Failed to allocate memory for info");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }
        memset(info, 0, sizeof(CpaInstanceInfo2));

        for (i = 0; i < numInst_g; i++)
        {
            status = cpaCyInstanceGetInfo2(cyInst_g[i], info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                freeInstanceMapping();
                qaeMemFree((void **)&info);
                return status;
            }
            if (prevDevId == info->physInstId.packageId)
            {
                continue;
            }
            prevDevId = info->physInstId.packageId;
            printDriverVersion(prevDevId);
        }
        qaeMemFree((void **)&info);

        if (runTests & SYMMETRIC_CODE)
        {
            status = getCryptoInstanceCapabilities(&symCap, SYM);
        }

        if (runTests & ASYMETRIC_CODE)
        {
            status_asym = getCryptoInstanceCapabilities(&asymCap, ASYM);
        }
        if ((CPA_STATUS_SUCCESS != status) &&
            (CPA_STATUS_SUCCESS != status_asym))
        {
            PRINT_ERR("getCryptoInstanceCapabilities failed to fetch CRYPTO "
                      "Instance Capabilities.\n");
            return CPA_STATUS_FAIL;
        }

        if (symCap.symSupported == CPA_FALSE && runTests & SYMMETRIC_CODE)
        {
            PRINT("Warning! Skipping SYMMETRIC tests as they are not supported "
                  "on Instance\n");
            runTests ^= 1 << 0;
            PRINT("runTests=%d\n", runTests);
        }

        if (asymCap.rsaSupported == CPA_FALSE && runTests & RSA_CODE)
        {
            PRINT("Warning! Skipping RSA tests as they are not supported on "
                  "Instance\n");
            runTests ^= 1 << 1;
            PRINT("runTests=%d\n", runTests);
        }
        if (asymCap.dsaSupported == CPA_FALSE && runTests & DSA_CODE)
        {
            PRINT("Warning! Skipping DSA tests as they are not supported on "
                  "Instance\n");
            runTests ^= 1 << 2;
            PRINT("runTests=%d\n", runTests);
        }
        if (asymCap.ecdsaSupported == CPA_FALSE && runTests & ECDSA_CODE)
        {
            PRINT("Warning! Skipping ECDSA tests as they are not supported on "
                  "Instance\n");
            runTests ^= 1 << 3;
            PRINT("runTests=%d\n", runTests);
        }
        if (asymCap.dhSupported == CPA_FALSE && runTests & DH_CODE)
        {
            PRINT("Warning! Skipping DH tests as they are not supported on "
                  "Instance\n");
            runTests ^= 1 << 4;
            PRINT("runTests=%d\n", runTests);
        }
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (asymCap.kptSupported == CPA_FALSE && (runTests & KPT_RSA_CODE))
        {
            PRINT(
                "Warning! Skipping KPT RSA tests as they are not supported on "
                "Instance\n");
            runTests ^= 1 << 8;
            PRINT("runTests=%d\n", runTests);
        }
        if (asymCap.kptSupported == CPA_FALSE && (runTests & KPT_ECDSA_CODE))
        {
            PRINT("Warning! Skipping KPT ECDSA tests as they are not supported "
                  "on Instance\n");
            runTests ^= 1 << 9;
            PRINT("runTests=%d\n", runTests);
        }
#endif
#ifdef SC_SM2_ENABLED
        if (asymCap.ecSm2Supported == CPA_FALSE && (runTests & SM2_CODE))
        {
            PRINT("Warning! Skipping SM2 tests as they are not supported "
                  "on Instance\n");
            runTests ^= 1 << 10;
            PRINT("runTests=%d\n", runTests);
        }
#endif
#endif

        /* Check capabilities before running kasumi wireless alg tests*/
        if (symCap.symSupported == CPA_TRUE && (runTests & SYMMETRIC_CODE))
        {
            status = getCySymQueryCapabilities(&symCapInfo);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaCySymQueryCapabilities failed with status: %d\n",
                          status);
                return status;
            }

            if (1 == includeWirelessAlgs)
            {
                includeKasumiAlg = 1;
                includeSnow3GAlgChain = 1;

                if (!CPA_BITMAP_BIT_TEST(symCapInfo.ciphers,
                                         CPA_CY_SYM_CIPHER_KASUMI_F8))
                {
                    PRINT(
                        "Warning! Skipping Kasumi wireless algorithm tests as "
                        "they are not supported on "
                        "Instance\n");
                    includeKasumiAlg = 0;
                    PRINT("includeKasumiAlgs = %d\n", includeKasumiAlg);
                }

                if ((!CPA_BITMAP_BIT_TEST(symCapInfo.ciphers,
                                          CPA_CY_SYM_CIPHER_SNOW3G_UEA2)) ||
                    (!CPA_BITMAP_BIT_TEST(symCapInfo.hashes,
                                          CPA_CY_SYM_HASH_SNOW3G_UIA2)))
                {
                    PRINT("Warning! Skipping Snow3G wireless algorithm chain "
                          "tests as they are not supported on "
                          "Instance\n");
                    includeSnow3GAlgChain = 0;
                    PRINT("includeSnow3GAlgChain = %d\n",
                          includeSnow3GAlgChain);
                }
            }
        }
    }
    else
    {
        PRINT("There are no crypto instances\n");
        /* Check if compression service need to be tested
         * and update the runTests accordingly.
         * */
        if (COMPRESSION_CODE & runTests)
        {
            runTests = COMPRESSION_CODE;
        }
    }
#endif /* DO_CRYPTO */

#ifdef INCLUDE_COMPRESSION
    status = cpaDcGetNumInstances(&numInst_g);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetNumInstances failed with status: %d\n", status);
        return status;
    }

    if (numInst_g > 0)
    {
        /* use single instance for latency and COO */
        if (singleInstRequired_g)
        {
            numInst_g = 1;
        }
        /*allocate memory to store the instance handles*/
        dcInst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInst_g);
        if (dcInst_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instances\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        /*get the instances handles and place in allocated memory*/
        status = cpaDcGetInstances(numInst_g, dcInst_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcGetInstances failed with status: %d\n", status);
            freeInstanceMapping();
            return status;
        }

        /*allocate memory for the instance core mapping*/
        dcInstMap_g = qaeMemAlloc(sizeof(Cpa32U) * numInst_g);
        if (dcInstMap_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instance mapping\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        info = qaeMemAlloc(sizeof(CpaInstanceInfo2));
        if (info == NULL)
        {
            PRINT_ERR("Failed to allocate memory for info");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }
        memset(info, 0, sizeof(CpaInstanceInfo2));

        for (i = 0; i < numInst_g; i++)
        {
            status = cpaDcInstanceGetInfo2(dcInst_g[i], info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                qaeMemFree((void **)&info);
                return status;
            }
            if (prevDevId == info->physInstId.packageId)
            {
                continue;
            }
            prevDevId = info->physInstId.packageId;
            printDriverVersion(prevDevId);
        }
        qaeMemFree((void **)&info);

        status = cpaDcQueryCapabilities(dcInst_g[0], &dcCap);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcQueryCapabilities failed with status: %d\n",
                      status);
            return status;
        }
    }
    else
    {
        PRINT("There are no compression instances\n");
    }

#endif /* INCLUDE_COMPRESSION */

    freeInstanceMapping();
#ifdef USER_SPACE
    if (((computeLatency != 0) || (computeOffloadCost != 0)) &&
        (checkSingleInstance() != CPA_STATUS_SUCCESS))
    {
        PRINT("Limiting to use single QAT Instance for %s computation\n",
              computeLatency != 0 ? "Latency" : "Offload Cost");
    }
#endif /* USER_SPACE */

#ifdef DO_CRYPTO
    /***************************************************************************
     * SYMMETRIC PERFORMANCE
     **************************************************************************/
    if ((SYMMETRIC_CODE & runTests) == SYMMETRIC_CODE)
    {
        /*AES128-CBC TEST*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {
            status = setupCipherTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                     KEY_SIZE_128_IN_BYTES,
                                     CPA_CY_PRIORITY_NORMAL,
                                     ASYNC,
                                     packetSizes[lv_count],
                                     DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                     cyNumBuffers,
                                     cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupCipherTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }

        /*AES256-CBC TEST*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {
            status = setupCipherTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                     KEY_SIZE_256_IN_BYTES,
                                     CPA_CY_PRIORITY_NORMAL,
                                     ASYNC,
                                     packetSizes[lv_count],
                                     DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                     cyNumBuffers,
                                     cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupCipherTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }

        /*AES256-CBC HMAC-SHA512 test*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {
            status =
                setupAlgChainTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                  KEY_SIZE_256_IN_BYTES,
                                  CPA_CY_SYM_HASH_SHA512,
                                  CPA_CY_SYM_HASH_MODE_AUTH,
                                  SHA512_AUTH_KEY_LENGTH_IN_BYTES,
                                  CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                                  CPA_CY_PRIORITY_NORMAL,
                                  ASYNC,
                                  packetSizes[lv_count],
                                  DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                  cyNumBuffers,
                                  cySymLoops);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupAlgChainTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        } /*End of test*/

        /*AES256-CBC AES-XCBC-MAC test*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {
            status =
                setupAlgChainTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                  KEY_SIZE_256_IN_BYTES,
                                  CPA_CY_SYM_HASH_AES_XCBC,
                                  CPA_CY_SYM_HASH_MODE_AUTH,
                                  AES_XCBC_DIGEST_LENGTH_IN_BYTES,
                                  CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                                  CPA_CY_PRIORITY_NORMAL,
                                  ASYNC,
                                  packetSizes[lv_count],
                                  DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                  cyNumBuffers,
                                  cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupAlgChainTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        } /*End of test*/

        /*AES256-CBC HMAC-SHA512 test*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {

            status =
                setupAlgChainDpTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                    KEY_SIZE_256_IN_BYTES,
                                    CPA_CY_SYM_HASH_SHA512,
                                    CPA_CY_SYM_HASH_MODE_AUTH,
                                    SHA512_AUTH_KEY_LENGTH_IN_BYTES,
                                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                                    CPA_CY_PRIORITY_HIGH,
                                    ASYNC,
                                    packetSizes[lv_count],
                                    SYM_DP_ENQUEUEING,
                                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                    SINGLE_REQUEST,
                                    SYM_DP_SINGLE_SESSION,
                                    cyNumBuffers,
                                    cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupAlgChainDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        } /*End of test*/

        /*AES256-CBC AES-XCBC-MAC test*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {

            status =
                setupAlgChainDpTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                    KEY_SIZE_256_IN_BYTES,
                                    CPA_CY_SYM_HASH_AES_XCBC,
                                    CPA_CY_SYM_HASH_MODE_AUTH,
                                    AES_XCBC_DIGEST_LENGTH_IN_BYTES,
                                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                                    CPA_CY_PRIORITY_HIGH,
                                    ASYNC,
                                    packetSizes[lv_count],
                                    SYM_DP_ENQUEUEING,
                                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                    SINGLE_REQUEST,
                                    SYM_DP_SINGLE_SESSION,
                                    cyNumBuffers,
                                    cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupAlgChainDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        } /*End of test*/

        /*AES128-CBC TEST*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {

            status = setupCipherDpTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                       KEY_SIZE_128_IN_BYTES,
                                       CPA_CY_PRIORITY_HIGH,
                                       ASYNC,
                                       packetSizes[lv_count],
                                       SYM_DP_ENQUEUEING,
                                       DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                       SINGLE_REQUEST,
                                       SYM_DP_SINGLE_SESSION,
                                       cyNumBuffers,
                                       cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupCipherDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }

        /*AES256-CBC TEST*/
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {

            status = setupCipherDpTest(CPA_CY_SYM_CIPHER_AES_CBC,
                                       KEY_SIZE_256_IN_BYTES,
                                       CPA_CY_PRIORITY_HIGH,
                                       ASYNC,
                                       packetSizes[lv_count],
                                       SYM_DP_ENQUEUEING,
                                       DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                       SINGLE_REQUEST,
                                       SYM_DP_SINGLE_SESSION,
                                       cyNumBuffers,
                                       cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupCipherDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }

        if (includeKasumiAlg)
        {
            /*KASUMI TEST*/
            for (lv_count = 0; lv_count < numWirelessPacketSizes; lv_count++)
            {
                status = setupCipherTest(CPA_CY_SYM_CIPHER_KASUMI_F8,
                                         KEY_SIZE_128_IN_BYTES,
                                         CPA_CY_PRIORITY_HIGH,
                                         ASYNC,
                                         wirelessPacketSizes[lv_count],
                                         DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                         cyNumBuffers,
                                         cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupCipherDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }

            /*KASUMI TEST*/
            for (lv_count = 0; lv_count < numWirelessPacketSizes; lv_count++)
            {

                status = setupCipherDpTest(CPA_CY_SYM_CIPHER_KASUMI_F8,
                                           KEY_SIZE_128_IN_BYTES,
                                           CPA_CY_PRIORITY_HIGH,
                                           ASYNC,
                                           wirelessPacketSizes[lv_count],
                                           SYM_DP_ENQUEUEING,
                                           DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                                           SINGLE_REQUEST,
                                           SYM_DP_SINGLE_SESSION,
                                           cyNumBuffers,
                                           cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupCipherDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
        }

        if (includeSnow3GAlgChain)
        {
            /*SNOW3G-UEA2 HMAC-SNOW3G-UIA2 TEST*/
            for (lv_count = 0; lv_count < numWirelessPacketSizes; lv_count++)
            {
                status = setupAlgChainTest(
                    CPA_CY_SYM_CIPHER_SNOW3G_UEA2,
                    KEY_SIZE_128_IN_BYTES,
                    CPA_CY_SYM_HASH_SNOW3G_UIA2,
                    CPA_CY_SYM_HASH_MODE_AUTH,
                    SNOW3G_UIA2_DIGEST_LENGTH_IN_BYTES,
                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                    CPA_CY_PRIORITY_NORMAL,
                    ASYNC,
                    wirelessPacketSizes[lv_count],
                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                    cyNumBuffers,
                    cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupAlgChainTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            } /*End of test*/

            /*SNOW3G-UEA2 HMAC-SNOW3G-UIA2 TEST*/
            for (lv_count = 0; lv_count < numWirelessPacketSizes; lv_count++)
            {
                status = setupAlgChainDpTest(
                    CPA_CY_SYM_CIPHER_SNOW3G_UEA2,
                    KEY_SIZE_128_IN_BYTES,
                    CPA_CY_SYM_HASH_SNOW3G_UIA2,
                    CPA_CY_SYM_HASH_MODE_AUTH,
                    SNOW3G_UIA2_DIGEST_LENGTH_IN_BYTES,
                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                    CPA_CY_PRIORITY_HIGH,
                    ASYNC,
                    wirelessPacketSizes[lv_count],
                    SYM_DP_ENQUEUEING,
                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                    SINGLE_REQUEST,
                    SYM_DP_SINGLE_SESSION,
                    cyNumBuffers,
                    cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupAlgChainDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            } /*End of test*/
        }
    }
#endif /* DO_CRYPTO */

#ifdef DO_CRYPTO
    /**************************************************************************
     * RSA PERFORMANCE
     **************************************************************************/
    if ((RSA_CODE & runTests) == RSA_CODE)
    {
        if (signOfLife)
        {
            numModSizes = ONE_PACKET;
        }
        for (lv_count = 0; lv_count < numModSizes; lv_count++)
        {
            status = setupRsaTest(modSizes[lv_count],
                                  CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2,
                                  ASYNC,
                                  cyNumBuffers,
                                  cyAsymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupRsaTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(ASYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }
    }
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef USER_SPACE
#ifdef SC_KPT2_ENABLED
    /**************************************************************************
     * KPT RSA PERFORMANCE
     **************************************************************************/
    if ((KPT_RSA_CODE & runTests) == KPT_RSA_CODE)
    {
        if (signOfLife)
        {
            numModSizes = ONE_PACKET;
        }
        for (lv_count = 0; lv_count < numModSizes; lv_count++)
        {
            status = setupKpt2RsaTest(modSizes[lv_count],
                                      CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2,
                                      ASYNC,
                                      cyNumBuffers,
                                      cyAsymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupKpt2RsaTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(ASYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }
    }

    /***************************************************************************
     * KPT ECDSA PERFORMANCE
     **************************************************************************/
    if (((KPT_ECDSA_CODE & runTests) == KPT_ECDSA_CODE) &&
        (computeLatency == 0))
    {
        status = setupKpt2EcdsaTest(GFP_P384_SIZE_IN_BITS,
                                    CPA_CY_EC_FIELD_TYPE_PRIME,
                                    ASYNC,
                                    ECDSA_STEP_VERIFY,
                                    cyNumBuffers,
                                    cyAsymLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error calling setupKpt2EcdsaTest\n");
            return CPA_STATUS_FAIL;
        }
        status = createStartandWaitForCompletionCrypto(ASYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            retStatus = CPA_STATUS_FAIL;
        }
    }
#endif
#endif /*USER_SPACE*/
#endif
#endif /*DO_CRYPTO*/

#ifdef DO_CRYPTO
    /**************************************************************************
     * DH PERFORMANCE
     **************************************************************************/

    if (((DH_CODE & runTests) == DH_CODE) && (computeLatency == 0))
    {
        if (signOfLife)
        {
            numModSizes = ONE_PACKET;
        }
        for (lv_count = 0; lv_count < numModSizes; lv_count++)
        {
            status = setupDhTest(modSizes[lv_count],
                                 EXPONENT_180_BIT,
                                 ASYNC,
                                 DH_PHASE_2,
                                 cyNumBuffers,
                                 cyAsymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDhTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(ASYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }
    }
#endif /*DO_CRYPTO*/

#ifdef DO_CRYPTO

    /***************************************************************************
     * DSA CRYPTO TESTS
     **************************************************************************/
    if (((DSA_CODE & runTests) == DSA_CODE) && (computeLatency == 0))
    {
        status = setupDsaTest(MODULUS_2048_BIT,
                              EXPONENT_256_BIT,
                              ASYNC,
                              cyNumBuffers,
                              cyAsymLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error calling setupDsaTest\n");
            return CPA_STATUS_FAIL;
        }
        status = createStartandWaitForCompletionCrypto(ASYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            retStatus = CPA_STATUS_FAIL;
        }
    }
#endif /*DO_CRYPTO*/

#ifdef DO_CRYPTO
    /***************************************************************************
     * ECDSA CRYPTO TESTS
     **************************************************************************/
    if (((ECDSA_CODE & runTests) == ECDSA_CODE) && (computeLatency == 0))
    {
        status = setupEcdsaTest(GFP_P384_SIZE_IN_BITS /*GFP_P192_SIZE_IN_BITS*/,
                                CPA_CY_EC_FIELD_TYPE_PRIME,
                                ASYNC,
                                ECDSA_STEP_VERIFY,
                                cyNumBuffers,
                                cyAsymLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error calling setupEcdsaTest\n");
            return CPA_STATUS_FAIL;
        }
        status = createStartandWaitForCompletionCrypto(ASYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            retStatus = CPA_STATUS_FAIL;
        }
    }
#endif /*DO_CRYPTO*/

#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_SM2_ENABLED
#ifdef DO_CRYPTO
    /***************************************************************************
     * SM2 TESTS
     **************************************************************************/

    if ((SM2_CODE & runTests) == SM2_CODE)
    {
        Cpa32U sm2_step = 0;
        for (sm2_step = 0; sm2_step < SM2_TEST_ALL_STEPS; sm2_step++)
        {
            status = setupSm2Test(GFP_SM2_SIZE_IN_BITS,
                                  CPA_CY_EC_FIELD_TYPE_PRIME,
                                  ASYNC,
                                  sm2_step,
                                  cyNumBuffers,
                                  cyAsymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                switch (sm2_step)
                {
                    case SM2_STEP_SIGN:
                        PRINT_ERR("Error setting up SM2_STEP_SIGN Test");
                        break;
                    case SM2_STEP_VERIFY:
                        PRINT_ERR("Error setting up SM2_STEP_VERIFY Test");
                        break;
                    case SM2_STEP_ENC:
                        PRINT_ERR("Error setting up SM2_STEP_ENC Test");
                        break;
                    case SM2_STEP_DEC:
                        PRINT_ERR("Error setting up SM2_STEP_DEC Test");
                        break;
                    case SM2_STEP_KEYEX_P1:
                        PRINT_ERR("Error setting up SM2_STEP_KEYEX_P1 Test");
                        break;
                    case SM2_STEP_KEYEX_P2:
                        PRINT_ERR("Error setting up SM2_STEP_KEYEX_P2 Test");
                        break;
                }
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(ASYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }
    }
#endif /*DO_CRYPTO*/
#endif /*SC_SM2_ENABLED*/
#endif

#ifdef INCLUDE_COMPRESSION
    if (signOfLife)
    {
        sampleCorpus = SIGN_OF_LIFE_CORPUS;
        dcBufferSize = BUFFER_SIZE_32768;
    }
    else
    {
        sampleCorpus = CALGARY_CORPUS;
        dcBufferSize = BUFFER_SIZE_65536;
    }
    /***************************************************************************
     *  START OF COMPRESSION TESTS CALGARY CORPUS
     **************************************************************************/
    if (((COMPRESSION_CODE & runTests) == COMPRESSION_CODE) ||
        ((CHAINING_CODE & runTests) == CHAINING_CODE))
    {
        status = cpaDcGetNumInstances(&numDcInst);
        /* Check the status */
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Unable to Get Number of DC instances\n");
            return CPA_STATUS_FAIL;
        }
    }
    /**************************************************************************
     * COMPRESSION TESTS CALGARY CORPUS
     **************************************************************************/

    if ((COMPRESSION_CODE & runTests) == COMPRESSION_CODE)
    {

        if (numDcInst > 0)
        {
            disableAdditionalCmpbufferSize_g = 1;
            dynamicHuffmanEnabled(NULL, &dynamicEnabled);

#if !defined(_KERNEL)
            /*STATIC L1 & L3 COMPRESSION*/
            status = setupDcTest(CPA_DC_DEFLATE,
                                 CPA_DC_DIR_COMPRESS,
                                 SAMPLE_CODE_CPA_DC_L1,
                                 CPA_DC_HT_STATIC,
                                 CPA_DC_STATELESS,
                                 DEFAULT_COMPRESSION_WINDOW_SIZE,
                                 BUFFER_SIZE_8192,
                                 sampleCorpus,
                                 ASYNC,
                                 dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            status = setupDcTest(CPA_DC_DEFLATE,
                                 CPA_DC_DIR_DECOMPRESS,
                                 SAMPLE_CODE_CPA_DC_L1,
                                 CPA_DC_HT_STATIC,
                                 CPA_DC_STATELESS,
                                 DEFAULT_COMPRESSION_WINDOW_SIZE,
                                 BUFFER_SIZE_8192,
                                 sampleCorpus,
                                 ASYNC,
                                 dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            status = setupDcTest(CPA_DC_DEFLATE,
                                 CPA_DC_DIR_COMPRESS,
                                 SAMPLE_CODE_CPA_DC_L2,
                                 CPA_DC_HT_STATIC,
                                 CPA_DC_STATELESS,
                                 DEFAULT_COMPRESSION_WINDOW_SIZE,
                                 BUFFER_SIZE_8192,
                                 sampleCorpus,
                                 ASYNC,
                                 dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
            status = setupDcTest(CPA_DC_DEFLATE,
                                 CPA_DC_DIR_DECOMPRESS,
                                 SAMPLE_CODE_CPA_DC_L2,
                                 CPA_DC_HT_STATIC,
                                 CPA_DC_STATELESS,
                                 DEFAULT_COMPRESSION_WINDOW_SIZE,
                                 BUFFER_SIZE_8192,
                                 sampleCorpus,
                                 ASYNC,
                                 dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            /*DYNAMIC L1 & L3 COMPRESSION*/
            if (dynamicEnabled)
            {
                status = setupDcTest(CPA_DC_DEFLATE,
                                     CPA_DC_DIR_COMPRESS,
                                     SAMPLE_CODE_CPA_DC_L1,
                                     CPA_DC_HT_FULL_DYNAMIC,
                                     CPA_DC_STATELESS,
                                     DEFAULT_COMPRESSION_WINDOW_SIZE,
                                     BUFFER_SIZE_8192,
                                     sampleCorpus,
                                     ASYNC,
                                     dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                status = setupDcTest(CPA_DC_DEFLATE,
                                     CPA_DC_DIR_DECOMPRESS,
                                     SAMPLE_CODE_CPA_DC_L1,
                                     CPA_DC_HT_FULL_DYNAMIC,
                                     CPA_DC_STATELESS,
                                     DEFAULT_COMPRESSION_WINDOW_SIZE,
                                     BUFFER_SIZE_8192,
                                     sampleCorpus,
                                     ASYNC,
                                     dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                status = setupDcTest(CPA_DC_DEFLATE,
                                     CPA_DC_DIR_COMPRESS,
                                     SAMPLE_CODE_CPA_DC_L2,
                                     CPA_DC_HT_FULL_DYNAMIC,
                                     CPA_DC_STATELESS,
                                     DEFAULT_COMPRESSION_WINDOW_SIZE,
                                     BUFFER_SIZE_8192,
                                     sampleCorpus,
                                     ASYNC,
                                     dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
                status = setupDcTest(CPA_DC_DEFLATE,
                                     CPA_DC_DIR_DECOMPRESS,
                                     SAMPLE_CODE_CPA_DC_L2,
                                     CPA_DC_HT_FULL_DYNAMIC,
                                     CPA_DC_STATELESS,
                                     DEFAULT_COMPRESSION_WINDOW_SIZE,
                                     BUFFER_SIZE_8192,
                                     sampleCorpus,
                                     ASYNC,
                                     dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }

            /*DECOMPRESSION OF ZLIB COMPRESSED DATA*/
            useZlib();
            status =
                setupDcTest(CPA_DC_DEFLATE,
                            CPA_DC_DIR_DECOMPRESS,
                            SAMPLE_CODE_CPA_DC_L1, /*not used in this test*/
                            CPA_DC_HT_STATIC,      /*not used in this test*/
                            CPA_DC_STATELESS,
                            DEFAULT_COMPRESSION_WINDOW_SIZE,
                            dcBufferSize,
                            sampleCorpus,
                            ASYNC,
                            dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
            useAccelCompression();

            if (runStateful && dynamicEnabled)
            {
                /*STATEFUL COMPRESSION TEST*/
                status = setupDcStatefulTest(CPA_DC_DEFLATE,
                                             CPA_DC_DIR_COMPRESS,
                                             SAMPLE_CODE_CPA_DC_L1,
                                             CPA_DC_HT_FULL_DYNAMIC,
                                             BUFFER_SIZE_8192,
                                             sampleCorpus,
                                             SYNC,
                                             dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Stateful setup failed\n");
                }

                /*set the array of cores to create threads on*/
                for (lv_count = 0;
                     lv_count <
                     sizeof(statefulMultiThreadCoreMap) / sizeof(Cpa32U);
                     lv_count++)
                {
                    statefulMultiThreadCoreMap[lv_count] =
                        lv_count % NUMBER_OF_CORES_TO_USE;
                }
                /*create the threads using all available instances*/
                status = createPerfomanceThreads(
                    sizeof(statefulMultiThreadCoreMap) / sizeof(Cpa32U),
                    statefulMultiThreadCoreMap,
                    numInst_g,
                    0);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Could not create threads\n");
                    return status;
                }
                status = startThreads();
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error starting threads\n");
                    return status;
                }
                status = waitForThreadCompletion();
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Stateful Compression thread(s) failed\n");
                    return status;
                }
            }
#endif /* _KERNEL */

            /* Data Plane API Sample Code Test */
            /*STATIC DP_API L1 & L3 COMPRESS & DECOMPRESS*/
            status = setupDcDpTest(CPA_DC_DEFLATE,
                                   CPA_DC_DIR_COMPRESS,
                                   SAMPLE_CODE_CPA_DC_L1,
                                   CPA_DC_HT_STATIC,
                                   DEFAULT_COMPRESSION_WINDOW_SIZE,
                                   BUFFER_SIZE_8192,
                                   sampleCorpus,
                                   ASYNC,
                                   DC_DP_ENQUEUEING,
                                   SINGLE_REQUEST,
                                   dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            status = setupDcDpTest(CPA_DC_DEFLATE,
                                   CPA_DC_DIR_DECOMPRESS,
                                   SAMPLE_CODE_CPA_DC_L1,
                                   CPA_DC_HT_STATIC,
                                   DEFAULT_COMPRESSION_WINDOW_SIZE,
                                   BUFFER_SIZE_8192,
                                   sampleCorpus,
                                   ASYNC,
                                   DC_DP_ENQUEUEING,
                                   SINGLE_REQUEST,
                                   dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            status = setupDcDpTest(CPA_DC_DEFLATE,
                                   CPA_DC_DIR_COMPRESS,
                                   SAMPLE_CODE_CPA_DC_L2,
                                   CPA_DC_HT_STATIC,
                                   DEFAULT_COMPRESSION_WINDOW_SIZE,
                                   BUFFER_SIZE_8192,
                                   sampleCorpus,
                                   ASYNC,
                                   DC_DP_ENQUEUEING,
                                   SINGLE_REQUEST,
                                   dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            status = setupDcDpTest(CPA_DC_DEFLATE,
                                   CPA_DC_DIR_DECOMPRESS,
                                   SAMPLE_CODE_CPA_DC_L2,
                                   CPA_DC_HT_STATIC,
                                   DEFAULT_COMPRESSION_WINDOW_SIZE,
                                   BUFFER_SIZE_8192,
                                   sampleCorpus,
                                   ASYNC,
                                   DC_DP_ENQUEUEING,
                                   SINGLE_REQUEST,
                                   dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
            if (dynamicEnabled)
            {
                /*DYNAMIC DP_API L1 & L3 COMPRESS & DECOMPRESS*/
                status = setupDcDpTest(CPA_DC_DEFLATE,
                                       CPA_DC_DIR_COMPRESS,
                                       SAMPLE_CODE_CPA_DC_L1,
                                       CPA_DC_HT_FULL_DYNAMIC,
                                       DEFAULT_COMPRESSION_WINDOW_SIZE,
                                       BUFFER_SIZE_8192,
                                       sampleCorpus,
                                       ASYNC,
                                       DC_DP_ENQUEUEING,
                                       SINGLE_REQUEST,
                                       dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                status = setupDcDpTest(CPA_DC_DEFLATE,
                                       CPA_DC_DIR_DECOMPRESS,
                                       SAMPLE_CODE_CPA_DC_L1,
                                       CPA_DC_HT_FULL_DYNAMIC,
                                       DEFAULT_COMPRESSION_WINDOW_SIZE,
                                       BUFFER_SIZE_8192,
                                       sampleCorpus,
                                       ASYNC,
                                       DC_DP_ENQUEUEING,
                                       SINGLE_REQUEST,
                                       dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                status = setupDcDpTest(CPA_DC_DEFLATE,
                                       CPA_DC_DIR_COMPRESS,
                                       SAMPLE_CODE_CPA_DC_L2,
                                       CPA_DC_HT_FULL_DYNAMIC,
                                       DEFAULT_COMPRESSION_WINDOW_SIZE,
                                       BUFFER_SIZE_8192,
                                       sampleCorpus,
                                       ASYNC,
                                       DC_DP_ENQUEUEING,
                                       SINGLE_REQUEST,
                                       dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                status = setupDcDpTest(CPA_DC_DEFLATE,
                                       CPA_DC_DIR_DECOMPRESS,
                                       SAMPLE_CODE_CPA_DC_L2,
                                       CPA_DC_HT_FULL_DYNAMIC,
                                       DEFAULT_COMPRESSION_WINDOW_SIZE,
                                       BUFFER_SIZE_8192,
                                       sampleCorpus,
                                       ASYNC,
                                       DC_DP_ENQUEUEING,
                                       SINGLE_REQUEST,
                                       dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
#ifdef USER_SPACE
#if DC_API_VERSION_AT_LEAST(3, 1)
            if (includeLZ4 == 1)
            {
                /*LZ4 Tests Compression & Decompression */
                /*XXhash global flag need to be set for LZ4 tests*/
                setChecksum(CPA_DC_XXHASH32);
                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_COMPRESS,
                               SAMPLE_CODE_CPA_DC_L1,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_8192,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_COMPRESS,
                               SAMPLE_CODE_CPA_DC_L1,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_65536,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_COMPRESS,
                               SAMPLE_CODE_CPA_DC_L9,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_8192,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_COMPRESS,
                               SAMPLE_CODE_CPA_DC_L9,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_65536,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_DECOMPRESS,
                               SAMPLE_CODE_CPA_DC_L1,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_8192,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_DECOMPRESS,
                               SAMPLE_CODE_CPA_DC_L1,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_65536,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_DECOMPRESS,
                               SAMPLE_CODE_CPA_DC_L9,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_8192,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }

                setupDcLZ4Test(CPA_DC_LZ4,
                               CPA_DC_DIR_DECOMPRESS,
                               SAMPLE_CODE_CPA_DC_L9,
                               CPA_DC_STATELESS,
                               BUFFER_SIZE_65536,
                               sampleCorpus,
                               CPA_DC_MIN_4_BYTE_MATCH,
                               CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                               ASYNC,
                               dcLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupDcLZ4Test\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletion(COMPRESSION);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
#else
            if (includeLZ4 == 1)
            {
                PRINT("LZ4 not supported with this API version\n");
            }
#endif
#endif
        } // End of if(numDcInst>0)
    }     // End of if((COMPRESSION_CODE & runTests)== COMPRESSION_CODE

#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef DO_CRYPTO
    /***************************************************************************
     * SM3 and SM4 TESTS
     **************************************************************************/

    if ((SMx_CODE & runTests) == SMx_CODE)
    {
        Cpa32U sm_count = 0;

        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {
            status = setupHashTest(CPA_CY_SYM_HASH_SM3,
                                   CPA_CY_SYM_HASH_MODE_PLAIN,
                                   SM3_DIGEST_LENGTH_IN_BYTES,
                                   CPA_CY_PRIORITY_HIGH,
                                   ASYNC,
                                   packetSizes[lv_count],
                                   cyNumBuffers,
                                   cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupHashTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }
        for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
        {
            status = setupHashDpTest(CPA_CY_SYM_HASH_SM3,
                                     CPA_CY_SYM_HASH_MODE_PLAIN,
                                     SM3_DIGEST_LENGTH_IN_BYTES,
                                     CPA_CY_PRIORITY_HIGH,
                                     ASYNC,
                                     packetSizes[lv_count],
                                     SYM_DP_ENQUEUEING,
                                     SINGLE_REQUEST,
                                     SYM_DP_SINGLE_SESSION,
                                     cyNumBuffers,
                                     cySymLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupHashDpTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletionCrypto(SYM);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }
        }
        for (sm_count = 0; sm_count < algChainSM4SM3TestList_count; sm_count++)
        {
            for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
            {
                status = setupAlgChainTest(
                    algChainSM4SM3TestList[sm_count].cipherAlg,
                    algChainSM4SM3TestList[sm_count].cipherKeySizeInBytes,
                    algChainSM4SM3TestList[sm_count].hashAlg,
                    CPA_CY_SYM_HASH_MODE_AUTH,
                    algChainSM4SM3TestList[sm_count].hashKeySizeInBytes,
                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                    CPA_CY_PRIORITY_HIGH,
                    ASYNC,
                    packetSizes[lv_count],
                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                    cyNumBuffers,
                    cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupAlgChainTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
        }
        for (sm_count = 0; sm_count < cipherSM4TestList_count; sm_count++)
        {
            for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
            {
                status = setupCipherTest(
                    cipherSM4TestList[sm_count].cipherAlg,
                    cipherSM4TestList[sm_count].cipherKeySizeInBytes,
                    CPA_CY_PRIORITY_HIGH,
                    ASYNC,
                    packetSizes[lv_count],
                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                    cyNumBuffers,
                    cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupCipherTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
        }

        for (sm_count = 0; sm_count < algChainSM4SM3TestList_count; sm_count++)
        {
            for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
            {
                status = setupAlgChainDpTest(
                    algChainSM4SM3TestList[sm_count].cipherAlg,
                    algChainSM4SM3TestList[sm_count].cipherKeySizeInBytes,
                    algChainSM4SM3TestList[sm_count].hashAlg,
                    CPA_CY_SYM_HASH_MODE_AUTH,
                    algChainSM4SM3TestList[sm_count].hashKeySizeInBytes,
                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                    CPA_CY_PRIORITY_HIGH,
                    ASYNC,
                    packetSizes[lv_count],
                    SYM_DP_ENQUEUEING,
                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                    SINGLE_REQUEST,
                    SYM_DP_SINGLE_SESSION,
                    cyNumBuffers,
                    cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupAlgChainDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
        }
        for (sm_count = 0; sm_count < cipherSM4TestList_count; sm_count++)
        {
            for (lv_count = 0; lv_count < numPacketSizes; lv_count++)
            {
                status = setupCipherDpTest(
                    cipherSM4TestList[sm_count].cipherAlg,
                    cipherSM4TestList[sm_count].cipherKeySizeInBytes,
                    CPA_CY_PRIORITY_HIGH,
                    ASYNC,
                    packetSizes[lv_count],
                    SYM_DP_ENQUEUEING,
                    DEFAULT_CPA_FLAT_BUFFERS_PER_LIST,
                    SINGLE_REQUEST,
                    SYM_DP_SINGLE_SESSION,
                    cyNumBuffers,
                    cySymLoops);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Error calling setupCipherDpTest\n");
                    return CPA_STATUS_FAIL;
                }
                status = createStartandWaitForCompletionCrypto(SYM);
                if (CPA_STATUS_SUCCESS != status)
                {
                    retStatus = CPA_STATUS_FAIL;
                }
            }
        }
    }
#endif /*DO_CRYPTO*/
#endif

#ifdef USER_SPACE
#ifdef SC_CHAINING_ENABLED
    /*
     * Chaining Sample Code
     */
    if ((CHAINING_CODE & runTests) == CHAINING_CODE)
    {
        if (numDcInst > 0)
        {
            useZlib();
            prevCnVRequestFlag = getSetupCnVRequestFlag();
            setSetupCnVRequestFlag(STRICT_CNV_WITH_RECOVERY |
                                   LOOSE_CNV_WITH_RECOVERY);

            /* sha256 + stateless static compress chaining */
            status = setupDcChainTest(CPA_DC_CHAIN_HASH_THEN_COMPRESS,
                                      2,
                                      CPA_DC_DEFLATE,
                                      CPA_DC_DIR_COMPRESS,
                                      SAMPLE_CODE_CPA_DC_L1,
                                      CPA_DC_HT_STATIC,
                                      CPA_DC_STATELESS,
                                      DEFAULT_COMPRESSION_WINDOW_SIZE,
                                      dcBufferSize,
                                      sampleCorpus,
                                      ASYNC,
                                      CPA_CY_SYM_OP_HASH,
                                      CPA_CY_SYM_CIPHER_NULL,
                                      0,
                                      CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
                                      CPA_CY_PRIORITY_NORMAL,
                                      CPA_CY_SYM_HASH_SHA256,
                                      CPA_CY_SYM_HASH_MODE_PLAIN,
                                      SHA256_DIGEST_LENGTH_IN_BYTES,
                                      dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcChainTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            /* sha256 + stateless dynamic compress chaining */
            status = setupDcChainTest(CPA_DC_CHAIN_HASH_THEN_COMPRESS,
                                      2,
                                      CPA_DC_DEFLATE,
                                      CPA_DC_DIR_COMPRESS,
                                      SAMPLE_CODE_CPA_DC_L1,
                                      CPA_DC_HT_FULL_DYNAMIC,
                                      CPA_DC_STATELESS,
                                      DEFAULT_COMPRESSION_WINDOW_SIZE,
                                      dcBufferSize,
                                      sampleCorpus,
                                      ASYNC,
                                      CPA_CY_SYM_OP_HASH,
                                      CPA_CY_SYM_CIPHER_NULL,
                                      0,
                                      CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
                                      CPA_CY_PRIORITY_NORMAL,
                                      CPA_CY_SYM_HASH_SHA256,
                                      CPA_CY_SYM_HASH_MODE_PLAIN,
                                      SHA256_DIGEST_LENGTH_IN_BYTES,
                                      dcLoops);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error calling setupDcChainTest\n");
                return CPA_STATUS_FAIL;
            }
            status = createStartandWaitForCompletion(COMPRESSION);
            if (CPA_STATUS_SUCCESS != status)
            {
                retStatus = CPA_STATUS_FAIL;
            }

            setSetupCnVRequestFlag(prevCnVRequestFlag);
            useAccelCompression();
        }
    }
#endif
#endif

#endif
#ifdef USER_SPACE
    if (CPA_STATUS_SUCCESS != icp_sal_userStop())
    {
        PRINT_ERR("Could not stop sal for user space\n");
        return CPA_STATUS_FAIL;
    }
    qaeMemDestroy();
#endif /* USER_SPACE */
    if (retStatus == CPA_STATUS_SUCCESS)
    {
        PRINT("Sample code completed successfully.\n");
        return CPA_STATUS_SUCCESS;
    }
    return retStatus;
}
