/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 ***************************************************************************
 * @file cpa_sample_code_drbg_perf.h
 *
 * @defgroup sampleDrbgFunctional
 *
 * @ingroup sampleCode
 *
 * @description
 *     Deterministic Random Bit Generation Performance Sample Code functions.
 *
 ***************************************************************************/
#ifndef CPA_SAMPLE_CODE_DRBG_PERF_H
#define CPA_SAMPLE_CODE_DRBG_PERF_H
#include "cpa.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_cy_drbg.h"
#include "cpa_cy_nrbg.h"
#include "cpa_cy_im.h"
#include "icp_sal_drbg_impl.h"

#define DRBG_MAX_THREAD 256
#define DRBG_MAX_SESSION_PERTHREAD 256

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      DRBGSetup Data.
 * @description
 *      This structure contains data relating to setting up a DRBG test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct drbg_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* derivation function required or not */
    CpaBoolean dFReq;
    /* security strength */
    Cpa32U secStrength;
    /* predication Resistance Required */
    CpaBoolean predictionResistanceRequired;
    /* length in bytes */
    Cpa32U lengthInBytes;
    /* number of loops to be used*/
    Cpa32U numLoops;
    Cpa32U numSessions;
} drbg_test_params_t;

// void nrbgRegisterDrbgImplFunctions(CpaBoolean dFReq);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupDrbgTest
 *
 * @description
 *      setup a test to run an DRBG test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupDrbgTest(CpaBoolean dFReq,
                        Cpa32U secStrength,
                        CpaBoolean predictionResistanceRequired,
                        Cpa32U lengthInBytes,
                        Cpa32U numSessions,
                        Cpa32U numLoops);

#endif
