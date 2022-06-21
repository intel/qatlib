/***************************************************************************
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
 ***************************************************************************/

/**
***************************************************************************
* @file lac_prime.c Prime API Implementation
*
* @ingroup Lac_Prime
*
* @description
*      This file contains the implementation of Prime functions
*
***************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

/* Include API files */
#include "cpa.h"
#include "cpa_cy_prime.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Include Osal files */
#include "Osal.h"

/* Include QAT files */
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"
#include "icp_qat_fw_la.h"

/* Include ADF files */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* Include LAC files */
#include "lac_common.h"
#include "lac_log.h"
#include "lac_pke_qat_comms.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_hooks.h"
#include "lac_prime.h"
#include "lac_pke_utils.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "sal_service_state.h"
#include "lac_sal_ctrl.h"
#include "sal_statistics.h"
/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/* Number of Prime statistics */
#define LAC_PRIME_NUM_STATS (sizeof(CpaCyPrimeStats64) / sizeof(Cpa64U))
/* Minimal MillerRabin round size in byte */
#define LAC_PRIME_MIN_MILLER_RABIN_SIZE_IN_BYTES 64
/*
********************************************************************************
* Static Variables
********************************************************************************
*/

#define LAC_PRIME_STATS_INIT(pCryptoService)                                   \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_PRIME_NUM_STATS; i++)                              \
        {                                                                      \
            osalAtomicSet(0, &(pCryptoService)->pLacPrimeStatsArr[i]);         \
        }                                                                      \
    } while (0)
/**<
 * macro to initialize all Prime stats (stored in internal array of atomics) */

#ifndef DISABLE_STATS
#define LAC_PRIME_STAT_INC(statistic, pCryptoService)                          \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bPrimeStatsEnabled)    \
        {                                                                      \
            osalAtomicInc(&(pCryptoService)                                    \
                               ->pLacPrimeStatsArr[offsetof(CpaCyPrimeStats64, \
                                                            statistic) /       \
                                                   sizeof(Cpa64U)]);           \
        }                                                                      \
    } while (0)
/**<
 * macro to increment a Prime stat (derives offset into array of atomics) */
#else
#define LAC_PRIME_STAT_INC(statistic, pCryptoService)                          \
    (pCryptoService) = (pCryptoService)
#endif

#define LAC_PRIME_STATS32_GET(primeStats, pCryptoService)                      \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_PRIME_NUM_STATS; i++)                              \
        {                                                                      \
            ((Cpa32U *)&(primeStats))[i] = (Cpa32U)osalAtomicGet(              \
                &(pCryptoService)->pLacPrimeStatsArr[i]);                      \
        }                                                                      \
    } while (0)
/**<
 * macro to get all Prime 32bit stats (from internal array of atomics) into
 * user supplied structure CpaCyPrimeStats pointed by primeStats pointer */

#define LAC_PRIME_STATS64_GET(primeStats, pCryptoService)                      \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_PRIME_NUM_STATS; i++)                              \
        {                                                                      \
            ((Cpa64U *)&(primeStats))[i] =                                     \
                osalAtomicGet(&(pCryptoService)->pLacPrimeStatsArr[i]);        \
        }                                                                      \
    } while (0)
/**<
 * macro to get all Prime 64bit stats (from internal array of atomics) into
 * user supplied structure CpaCyPrimeStats64 pointed by primeStats pointer */

static const Cpa32U lacGcdSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_160_BITS, PKE_GCD_PT_192},
    {LAC_192_BITS, PKE_GCD_PT_192},
    {LAC_256_BITS, PKE_GCD_PT_256},
    {LAC_384_BITS, PKE_GCD_PT_384},
    {LAC_512_BITS, PKE_GCD_PT_512},
    {LAC_768_BITS, PKE_GCD_PT_768},
    {LAC_1024_BITS, PKE_GCD_PT_1024},
    {LAC_1536_BITS, PKE_GCD_PT_1536},
    {LAC_2048_BITS, PKE_GCD_PT_2048},
    {LAC_3072_BITS, PKE_GCD_PT_3072},
    {LAC_4096_BITS, PKE_GCD_PT_4096}};
/**<
 * Maps between operation sizes and GCD PKE function ids */

static const Cpa32U lacFermatSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_160_BITS, PKE_FERMAT_PT_160},
    {LAC_512_BITS, PKE_FERMAT_PT_512},
    {LAC_768_BITS, PKE_FERMAT_PT_768},
    {LAC_1024_BITS, PKE_FERMAT_PT_1024},
    {LAC_1536_BITS, PKE_FERMAT_PT_1536},
    {LAC_2048_BITS, PKE_FERMAT_PT_2048},
    {LAC_3072_BITS, PKE_FERMAT_PT_3072},
    {LAC_4096_BITS, PKE_FERMAT_PT_4096}};
/**<
 * Maps between operation sizes and Fermat PKE function ids */

static const Cpa32U lacLucasSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_160_BITS, PKE_LUCAS_PT_160},
    {LAC_512_BITS, PKE_LUCAS_PT_512},
    {LAC_768_BITS, PKE_LUCAS_PT_768},
    {LAC_1024_BITS, PKE_LUCAS_PT_1024},
    {LAC_1536_BITS, PKE_LUCAS_PT_1536},
    {LAC_2048_BITS, PKE_LUCAS_PT_2048},
    {LAC_3072_BITS, PKE_LUCAS_PT_3072},
    {LAC_4096_BITS, PKE_LUCAS_PT_4096}};
/**<
 * Maps between operation sizes and Lucas PKE function ids */

static const Cpa32U lacMrSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_160_BITS, PKE_MR_PT_160},
    {LAC_512_BITS, PKE_MR_PT_512},
    {LAC_768_BITS, PKE_MR_PT_768},
    {LAC_1024_BITS, PKE_MR_PT_1024},
    {LAC_1536_BITS, PKE_MR_PT_1536},
    {LAC_2048_BITS, PKE_MR_PT_2048},
    {LAC_3072_BITS, PKE_MR_PT_3072},
    {LAC_4096_BITS, PKE_MR_PT_4096}};
/**<
 * Maps between operation sizes and Miller-Rabin PKE function ids */

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
********************************************************************************
* Global Variables
********************************************************************************
*/
/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Test internal callback function
 ******************************************************************************/
void LacPrimeTestCallback(CpaStatus status,
                          CpaBoolean pass,
                          CpaInstanceHandle instanceHandle,
                          lac_pke_op_cb_data_t *pCbData)
{
    CpaCyPrimeTestCbFunc pCb = NULL;
    CpaCyPrimeTestOpData *pOpData = NULL;
    CpaFlatBuffer *pBuffInMillerRabin = NULL;
    void *pCallbackTag = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* retrieve data from the callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyPrimeTestCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOpData =
        (CpaCyPrimeTestOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pBuffInMillerRabin = (CpaFlatBuffer *)(pCbData->pOpaqueData);
    pCallbackTag = pCbData->pCallbackTag;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);

    /* free the array of the input/output flat buffers */
    if (NULL != pBuffInMillerRabin)
    {
        Lac_MemPoolEntryFree(pBuffInMillerRabin);
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_PRIME_STAT_INC(numPrimeTestCompleted, pCryptoService);
        if (CPA_FALSE == pass)
        {
            LAC_PRIME_STAT_INC(numPrimeTestFailures, pCryptoService);
        }
    }
    else
    {
        LAC_PRIME_STAT_INC(numPrimeTestCompletedErrors, pCryptoService);
    }
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pass);
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Get Function ID function
 ******************************************************************************/
Cpa32U LacPrimeGetFuncID(lac_prime_test_t testId, Cpa32U *pOpLenInBits)
{
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;

    /*
     * get functionality ID for GCD request
     */
    if (LAC_PRIME_GCD == testId)
    {
        functionalityId = LacPke_GetMmpId(
            (*pOpLenInBits), lacGcdSizeIdMap, LAC_ARRAY_LEN(lacGcdSizeIdMap));
        if ((LAC_PKE_INVALID_FUNC_ID == functionalityId) &&
            ((*pOpLenInBits) < LAC_512_BITS))
        {
            functionalityId = PKE_GCD_PT_512;
            /* Select new OpLen */
            *pOpLenInBits = LAC_512_BITS;
        }
    }
    /*
     * get functionality ID for Fermat request
     */
    else if (LAC_PRIME_FERMAT == testId)
    {
        functionalityId = LacPke_GetMmpId((*pOpLenInBits),
                                          lacFermatSizeIdMap,
                                          LAC_ARRAY_LEN(lacFermatSizeIdMap));
        if ((LAC_PKE_INVALID_FUNC_ID == functionalityId) &&
            ((*pOpLenInBits) < LAC_512_BITS))
        {
            functionalityId = PKE_FERMAT_PT_L512;
            /* Select new OpLen */
            *pOpLenInBits = LAC_512_BITS;
        }
    }
    /*
     * get functionality ID for Miller-Rabin request
     */
    else if (LAC_PRIME_MILLER_RABIN == testId)
    {
        functionalityId = LacPke_GetMmpId(
            (*pOpLenInBits), lacMrSizeIdMap, LAC_ARRAY_LEN(lacMrSizeIdMap));
        if ((LAC_PKE_INVALID_FUNC_ID == functionalityId) &&
            ((*pOpLenInBits) < LAC_512_BITS))
        {
            functionalityId = PKE_MR_PT_L512;
            /* Select new OpLen */
            *pOpLenInBits = LAC_512_BITS;
        }
    }
    /*
     * get functionality ID for Lucas request
     */
    else if (LAC_PRIME_LUCAS == testId)
    {
        functionalityId = LacPke_GetMmpId((*pOpLenInBits),
                                          lacLucasSizeIdMap,
                                          LAC_ARRAY_LEN(lacLucasSizeIdMap));
        if ((LAC_PKE_INVALID_FUNC_ID == functionalityId) &&
            ((*pOpLenInBits) < LAC_512_BITS))
        {
            functionalityId = PKE_LUCAS_PT_L512;
            /* Select new OpLen */
            *pOpLenInBits = LAC_512_BITS;
        }
    }

    return functionalityId;
}

/**
*******************************************************************************
* @ingroup Lac_Prime
*      Populate Prime Input and Output Parameter function
******************************************************************************/
void LacPrimePopulateParam(lac_prime_test_t testId,
                           Cpa32U opSizeInBytes,
                           icp_qat_fw_mmp_input_param_t *pIn,
                           icp_qat_fw_mmp_output_param_t *pOut,
                           Cpa32U *pInSize,
                           CpaBoolean *pInternalMemInList,
                           CpaBoolean internalPrimeMem,
                           CpaFlatBuffer *pPrimeBuff,
                           const CpaFlatBuffer *pInputMillerRabinBuffer)
{
    /*
     * populate input/output parameters for GCD request
     * using mmp_gcd_pt_192 as generic structure
     */
    if (LAC_PRIME_GCD == testId)
    {
        LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->mmp_gcd_pt_192.m, pPrimeBuff);
        pInSize[0] = opSizeInBytes;
        pInternalMemInList[0] = internalPrimeMem;
    }
    /*
     * populate input/output parameters for Fermat request
     * using mmp_fermat_pt_160 as generic structure
     */
    else if (LAC_PRIME_FERMAT == testId)
    {
        LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->mmp_fermat_pt_160.m, pPrimeBuff);
        pInSize[0] = opSizeInBytes;
        pInternalMemInList[0] = internalPrimeMem;
    }
    /*
     * populate input/output parameters Miller-Rabin request
     * using mmp_mr_pt_160 as generic structure
     */
    else if (LAC_PRIME_MILLER_RABIN == testId)
    {
        /* populate input/output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->mmp_mr_pt_160.x,
                                      pInputMillerRabinBuffer);
        pInSize[LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x)] =
            opSizeInBytes;
        /* FlatBuffer is internally allocated but the memory we send to QAT is
           externally allocated */
        pInternalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x)] =
            CPA_FALSE;
        LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->mmp_mr_pt_160.m, pPrimeBuff);
        pInSize[LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m)] =
            opSizeInBytes;
        pInternalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m)] =
            internalPrimeMem;
    }
    /*
     * populate input/output parameters for Lucas request
     * using mmp_lucas_pt_160 as generic structure
     */
    else if (LAC_PRIME_LUCAS == testId)
    {
        LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->mmp_lucas_pt_160.m, pPrimeBuff);
        pInSize[0] = opSizeInBytes;
        pInternalMemInList[0] = internalPrimeMem;
    }
}

#ifdef ICP_PARAM_CHECK
/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Test parameter check
 ******************************************************************************/
CpaStatus LacPrimeParameterCheck(CpaCyPrimeTestCbFunc pCb,
                                 CpaCyPrimeTestOpData *pOpData,
                                 CpaBoolean *pTestPassed)
{
    Cpa32U roundMillerRabin = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);
    /* check for null Operational Data parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    /* Check for bad pointer */
    LAC_CHECK_NULL_PARAM(pTestPassed);

    /* check for null Prime candidate parameter */
    LAC_CHECK_FLAT_BUFFER(&pOpData->primeCandidate);

    /* for the better readability assign the number of rounds for
     *  Miller-Rabin test and Prime Candidate data length */
    roundMillerRabin = pOpData->numMillerRabinRounds;

    /* Check that the Prime Candidate is within size limits,
     *  not-even (LSB is set) and not-null */
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(&pOpData->primeCandidate,
                                    CHECK_LESS_EQUALS,
                                    LAC_MAX_PRIME_SIZE_IN_BITS,
                                    LAC_CHECK_LSB_YES);

    /* It is an error if no test is booked */
    if (!((pOpData->performGcdTest) || (pOpData->performFermatTest) ||
          (roundMillerRabin != 0) || (pOpData->performLucasTest)))
    {
        LAC_INVALID_PARAM_LOG("No prime test was selected");
        status = CPA_STATUS_INVALID_PARAM;
    }

    /* Check that, if test has been booked, the Miller-Rabin parameters are set
     *  correctly */
    if ((roundMillerRabin > 0) && (CPA_STATUS_SUCCESS == status))
    {
        /* Number of Miller-Rabin rounds must not exceed maximum allowed! */
        if (roundMillerRabin <= LAC_PRIME_MAX_MR)
        {
            /* Check the input buffer size for Miller-Rabin (array of random
             *  numbers) the size of the buffer is validated later */
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &pOpData->millerRabinRandomInput, CHECK_NONE, 0);
        }
        else
        {
            LAC_INVALID_PARAM_LOG("Number of Miller-Rabin rounds too high");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    return status;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Prime
 *      Prime Test synchronous function
 ***************************************************************************/

STATIC CpaStatus LacPrimeTestSyn(const CpaInstanceHandle instanceHandle,
                                 CpaCyPrimeTestOpData *pOpData,
                                 CpaBoolean *pTestPassed)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyPrimeTest(instanceHandle,
                                LacSync_GenVerifyCb,
                                pSyncCallbackData,
                                pOpData,
                                pTestPassed);
    }
    else
    {
        LAC_PRIME_STAT_INC(numPrimeTestRequestErrors, pCryptoService);
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pTestPassed);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_PRIME_STAT_INC(numPrimeTestCompletedErrors, pCryptoService);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the Request was not sent the Callback will never
         * be called, so need to indicate that we're finished
         * with cookie so it can be destroyed. */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }
    LacSync_DestroySyncCookie(&pSyncCallbackData);
    return status;
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Test API function
 ******************************************************************************/

CpaStatus cpaCyPrimeTest(const CpaInstanceHandle instanceHandle_in,
                         const CpaCyPrimeTestCbFunc pCb,
                         void *pCallbackTag,
                         const CpaCyPrimeTestOpData *pOpData,
                         CpaBoolean *pTestPassed)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    lac_prime_test_t testId = LAC_PRIME_FERMAT;
    Cpa32U roundMillerRabin = 0;
    Cpa32U functionalityId = 0;
    Cpa32U numRounds = 0;
    Cpa32U indexMillerRabin = 0;
    Cpa32U round = 0;
    Cpa32U inputLenInBits = 0;     /* bit length of prime candidate */
    Cpa32U inputLenInBytes = 0;    /* byte length of prime candidate */
    Cpa32U mrRoundSizeInBytes = 0; /* byte length of a MR round buffer */
    CpaBoolean isZero = CPA_FALSE;
    Cpa32U tempOpLenInBits = 0;
    Cpa32U dataOpLenInBytes = 0; /* Number of bytes required by PKE service */
    sal_crypto_service_t *pCryptoService = NULL;

    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalPrimeMem = CPA_FALSE;

    /* Array of random numbers for MIller-Rabin test is stored in a block of
     *  memory. For further processing, one flat buffer has to be formed for
     * each random number.
     *
     *  Define array of flat buffers to hold input random numbers
     *  for prime test. */
    CpaFlatBuffer *pBuffInputMillerRabin = NULL;

    /*
     *  Pointer to flat buffer used to hold the prime candidate this can
     *  be either the user supplied buffer or an internal flat buffer
     *  in the case where the prime input has been resized by pke_common.
     *  This prevents further copies in the chain.
     */
    CpaFlatBuffer *pBuffPrimeInternal = NULL;

    /* Data that will be passed back in call back function - opaque data */
    lac_pke_op_cb_data_t primeTestData = {0};

    /* For a single request, or the first request in a chain of requests, the
     *  requestHandle value must be zero (i.e. LAC_PKE_INVALID_HANDLE). The
     *  non-zero value means that the new request is chained to the
     *  request (chain) already associated with the handle. */
    lac_pke_request_handle_t requestHandle = LAC_PKE_INVALID_HANDLE;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status = LacPrimeTestSyn(
            instanceHandle, LAC_CONST_PTR_CAST(pOpData), pTestPassed);

        if (NULL != pTestPassed)
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx, 0x%lx[%d]\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pTestPassed,
                     *pTestPassed);
        }
        else
        {
            LAC_LOG5("Called with params (0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx, 0x%lx\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pTestPassed);
        }
        return status;
#else
        return LacPrimeTestSyn(
            instanceHandle, LAC_CONST_PTR_CAST(pOpData), pTestPassed);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check that the input parameters are valid */
    status =
        LacPrimeParameterCheck(pCb, LAC_CONST_PTR_CAST(pOpData), pTestPassed);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* for the better readability assign the number of rounds for
         *  Miller-Rabin test and Prime Candidate data length */
        roundMillerRabin = pOpData->numMillerRabinRounds;

        /* Get bit and byte length of the primeCandidate */
        status = LacPke_GetBitPos(&(pOpData->primeCandidate),
                                  &inputLenInBits,
                                  &inputLenInBytes,
                                  &isZero);
        inputLenInBits++;
        inputLenInBytes =
            pOpData->primeCandidate.dataLenInBytes - inputLenInBytes;
        /* The size of a MR buffer MUST be
         * max(LAC_PRIME_MIN_MILLER_RABIN_SIZE_IN_BYTES, x)
         * where: x is the minimum number of bytes required to represent the
         * prime candidate, i.e. x = ceiling((ceiling(log2(p)))/8). */
        mrRoundSizeInBytes =
            LAC_MAX(LAC_PRIME_MIN_MILLER_RABIN_SIZE_IN_BYTES, inputLenInBytes);
    }

    if ((CPA_STATUS_SUCCESS == status) && (roundMillerRabin > 0))
    {

        /* In the case of MR we need to divide up the client provided
           millerRabinRandomInput buffer the best we can. To do this we
           need to find out the PKE service we will use and the size of the
           input it expects */
        tempOpLenInBits = inputLenInBits;
        functionalityId = LacPrimeGetFuncID(testId, &tempOpLenInBits);
        if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
        {
            LAC_INVALID_PARAM_LOG("Prime candidate bit length not"
                                  " supported. Supported bit lengths include"
                                  " all lengths less than 512, 512, 768, 1024"
                                  " 1536, 2048, 3072 and 4096");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) && (roundMillerRabin > 0))
    {
        /* check the buffer size of millerRabinRandomInput */
        if (pOpData->millerRabinRandomInput.dataLenInBytes ==
            (roundMillerRabin * mrRoundSizeInBytes))
        {
            /* Each random number MUST be greater than 1 and less than the prime
             * candidate - 1*/
            CpaFlatBuffer randomNumber = {
                .pData = pOpData->millerRabinRandomInput.pData,
                .dataLenInBytes = mrRoundSizeInBytes};
            Cpa32U round = 0;
            for (round = 1; round <= roundMillerRabin; round++)
            {
                if ((LacPke_CompareZero(&randomNumber, -1) <= 0) ||
                    (LacPke_Compare(
                         &randomNumber, 0, &(pOpData->primeCandidate), -1) >=
                     0))

                {
                    LAC_INVALID_PARAM_LOG1("pOpData->millerRabinRandomInput "
                                           "#%u has incorrect range",
                                           round);
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                }
                randomNumber.pData += mrRoundSizeInBytes;
            }
        }
        else
        {
            /* not enough random buffer provided */
            LAC_INVALID_PARAM_LOG("pOpData->millerRabinRandomInput has "
                                  "incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {

        /* Allocating the memory for the array of flat buffers in which the
         *  elements to hold input random numbers for Miller-Rabin test is
         *  stored.
         *  The first element of this array is reserved for storing the
         *  resized prime if required.
         */
        do
        {
            pBuffInputMillerRabin = (CpaFlatBuffer *)Lac_MemPoolEntryAlloc(
                pCryptoService->lac_prime_pool);
            if (NULL == pBuffInputMillerRabin)
            {
                LAC_LOG_ERROR("Cannot get mem pool entry");
                /* on failure increment stats: */
                LAC_PRIME_STAT_INC(numPrimeTestRequestErrors, pCryptoService);
                status = CPA_STATUS_RESOURCE;
            }
            else if ((void *)CPA_STATUS_RETRY == pBuffInputMillerRabin)
            {
                osalYield();
            }
        } while ((void *)CPA_STATUS_RETRY == pBuffInputMillerRabin);
    }

    if ((CPA_STATUS_SUCCESS == status) && (roundMillerRabin > 0))
    {
        /* pointer to the array of random numbers for Miller-Rabin test. Used to
         *  calculate the addresses of the array members */
        Cpa8U *pCurrentAddress = pOpData->millerRabinRandomInput.pData;

        /* Link the random number from Miller-Rabin array to the designated
         * member of the array of flat buffers.
         * First flat buffer is not used as it is reserved for resized prime */
        for (indexMillerRabin = 1; indexMillerRabin <= roundMillerRabin;
             indexMillerRabin++)
        {
            /* Members of the array of flat buffers that will hold random
             *  number for M-R test. In fact, each buffer's pData pointer is
             *  assigned the address of the corresponding random number in the
             *  user given block of memory. */

            pBuffInputMillerRabin[indexMillerRabin].pData = pCurrentAddress;
            pBuffInputMillerRabin[indexMillerRabin].dataLenInBytes =
                mrRoundSizeInBytes;
            pCurrentAddress += mrRoundSizeInBytes;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* Prime is user supplied prime until after we have resized */
        pBuffPrimeInternal = (CpaFlatBuffer *)(&(pOpData->primeCandidate));

        /* preserve user parameters and the OutputBuffer for when our Call Back
           function kicks in, after sending the head request */
        /* Note for all prime messages this should be the same as we do not know
           what request in the chain will generate the response - this means we
           allocate pBuffInputMillerRabin even if we do not need it */
        primeTestData.pClientCb = pCb;
        primeTestData.pCallbackTag = pCallbackTag;
        primeTestData.pClientOpData = pOpData;
        primeTestData.pOpaqueData = pBuffInputMillerRabin;
    }

    /* Create the PKE request and chain as necessary for multiple tests in
     *  order of the increasing complexity: Fermat->Miller-Rabin->Lucas.
     *  Send the request when finished. */

    for (testId = (lac_prime_test_t)(LAC_PRIME_TEST_START_DELIMITER + 1);
         (testId < LAC_PRIME_TEST_END_DELIMITER) &&
         (CPA_STATUS_SUCCESS == status);
         testId++)
    {
        /* assign the number of rounds per test */
        if (testId == LAC_PRIME_GCD)
        {
            numRounds = (pOpData->performGcdTest ? 1 : 0);
        }
        if (testId == LAC_PRIME_FERMAT)
        {
            numRounds = (pOpData->performFermatTest ? 1 : 0);
        }
        if (testId == LAC_PRIME_MILLER_RABIN)
        {
            numRounds = roundMillerRabin;
        }
        if (testId == LAC_PRIME_LUCAS)
        {
            numRounds = (pOpData->performLucasTest ? 1 : 0);
        }

        /* get functionality ID and dataOpLen for undergoing test */
        if (numRounds > 0)
        {
            tempOpLenInBits = inputLenInBits;
            /* tempOpLenInBits may get rounded updated by this function */
            functionalityId = LacPrimeGetFuncID(testId, &tempOpLenInBits);
            if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
            {
                LAC_INVALID_PARAM_LOG(
                    "Prime candidate bit length not"
                    " supported. Supported bit lengths include"
                    " all lengths less than 512, 512, 768, 1024"
                    " 1536, 2048, 3072 and 4096");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }

        /* populate parameters and create request for each round */
        for (round = 1; (round <= numRounds) && (CPA_STATUS_SUCCESS == status);
             round++)
        {
            LAC_OS_BZERO(&inArgList, sizeof(icp_qat_fw_mmp_input_param_t));
            LAC_OS_BZERO(&outArgList, sizeof(icp_qat_fw_mmp_output_param_t));

            /* Number of bytes required by PKE - needs to be rounded up to
               nearest QW multiple */
            /* Note that the the number of bytes required by PKE for Fermat,
               MR and Lucas tests are the same but the number of bytes
               required for GCD tests may be different */
            dataOpLenInBytes = LAC_ALIGN_POW2_ROUNDUP(
                LAC_BITS_TO_BYTES(tempOpLenInBits), LAC_QUAD_WORD_IN_BYTES);

            /* populate input/output parameters first */
            LacPrimePopulateParam(
                testId,
                dataOpLenInBytes,
                &inArgList,
                &outArgList,
                inArgSizeList,
                internalMemInList,
                internalPrimeMem,
                ((LAC_PRIME_GCD == testId)
                     ? (CpaFlatBuffer *)(&pOpData->primeCandidate)
                     : pBuffPrimeInternal),
                (LAC_PRIME_MILLER_RABIN == testId)
                    ? &pBuffInputMillerRabin[round]
                    : NULL);

            /* Create PKE request */
            status = LacPke_CreateRequest(&requestHandle,
                                          functionalityId,
                                          inArgSizeList,
                                          NULL,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          NULL,
                                          LacPrimeTestCallback,
                                          &primeTestData,
                                          instanceHandle);

            if ((CPA_STATUS_SUCCESS == status) && (LAC_PRIME_GCD != testId) &&
                (pBuffPrimeInternal->dataLenInBytes < dataOpLenInBytes))
            {
                /* Request was successfully created, the test is not GCD and
                   the prime buffer size was less than required - that means
                   that an internal resize buffer was allocated by pke_common.
                   As Fermat, MR and Lucas all require the same input buffer
                   sizes we should use this new correctly sized buffer as
                   input to all other prime requests in the chain to
                   avoid further resizing */

                /* Assumption here is that all prime services except GCD
                   are the same size, i.e. one of 160,512,L512,768,1024,
                   1536, 2048,3072 or 4096 */

                lac_pke_qat_req_data_t *pReq = requestHandle;
                if (NULL != pReq->pNextReqData)
                {
                    /* Not first request in chain  - i.e. a GCD message has
                       already been built */
                    pReq = pReq->pNextReqData;
                }
                if (LAC_PRIME_MILLER_RABIN == testId)
                {
                    pBuffInputMillerRabin[0].pData =
                        pReq->paramInfo.pkeInputParams[LAC_IDX_OF(
                            icp_qat_fw_mmp_mr_pt_160_input_t, m)];
                }
                else
                {
                    /* For all other cases prime is first in the list */
                    pBuffInputMillerRabin[0].pData =
                        pReq->paramInfo.pkeInputParams[0];
                }
                pBuffInputMillerRabin[0].dataLenInBytes = dataOpLenInBytes;
                internalPrimeMem = CPA_TRUE;
                pBuffPrimeInternal = &(pBuffInputMillerRabin[0]);
            }
        }
    }

    /* now, after the requests has been created,
     *  send the head request to the QAT */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* send request chain */
        status = LacPke_SendRequest(&requestHandle, instanceHandle);
    }
    /* update stats. In case of failure free the memory */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* increment stats:
         *  Total number of prime number test requested operations */
        LAC_PRIME_STAT_INC(numPrimeTestRequests, pCryptoService);
    }
    else
    {
        /* on failure increment stats:
         * Total number of prime number test errors recorded */
        LAC_PRIME_STAT_INC(numPrimeTestRequestErrors, pCryptoService);

        /* if allocated, free the memory on failure */
        if (NULL != pBuffInputMillerRabin)
        {
            /* free the array of the input flat buffers */
            Lac_MemPoolEntryFree(pBuffInputMillerRabin);
        }
    }
    return status;
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Statistics Query API function
 ******************************************************************************/
CpaStatus cpaCyPrimeQueryStats(CpaInstanceHandle instanceHandle_in,
                               struct _CpaCyPrimeStats *pPrimeStats)
{
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pPrimeStats);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);

    /* ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);

    /* check this is a crypto instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pPrimeStats);

    /* get stats into user supplied stats structure */
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    LAC_PRIME_STATS32_GET(*pPrimeStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Statistics Query API function
 ******************************************************************************/
CpaStatus cpaCyPrimeQueryStats64(CpaInstanceHandle instanceHandle_in,
                                 CpaCyPrimeStats64 *pPrimeStats)
{
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pPrimeStats);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);

    /* ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);

    /* check this is a crypto instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pPrimeStats);

    /* get stats into user supplied stats structure */
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    LAC_PRIME_STATS64_GET(*pPrimeStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Initialization function
 ******************************************************************************/
CpaStatus LacPrime_Init(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&(pCryptoService->pLacPrimeStatsArr),
                           LAC_PRIME_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        /* initialize stats to zero */
        LAC_PRIME_STATS_INIT(pCryptoService);
    }

    /* Call compile time param check function to ensure it is included
      in the build by the compiler */
    LacPrime_CompileTimeAssertions();
    return status;
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Stats cleanup function
 ******************************************************************************/
void LacPrime_StatsFree(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (NULL != pCryptoService->pLacPrimeStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacPrimeStatsArr);
    }
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Stats reset function
 ******************************************************************************/
void LacPrime_StatsReset(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    LAC_PRIME_STATS_INIT(pCryptoService);
}

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Stats Show function
 ******************************************************************************/
void LacPrime_StatsShow(CpaInstanceHandle instanceHandle)
{
    CpaCyPrimeStats64 primeStats = {0};

    /* retrieve the stats */
    (void)cpaCyPrimeQueryStats64(instanceHandle, &primeStats);

    /* log the stats to the standard output */

    /* Engine Info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            " PRIME Stats                                " BORDER
            "\n" SEPARATOR);

    /* Parameter generation requests - PRIME stats */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " PRIME successfull requests:     %16llu " BORDER "\n" BORDER
                   " PRIME failed requests:          %16llu " BORDER "\n" BORDER
                   " PRIME successfully completed:   %16llu " BORDER "\n" BORDER
                   " PRIME failed completion:        %16llu " BORDER "\n" BORDER
                   " PRIME completed - not a prime:  %16llu " BORDER
                   "\n" SEPARATOR,
            primeStats.numPrimeTestRequests,
            primeStats.numPrimeTestRequestErrors,
            primeStats.numPrimeTestCompleted,
            primeStats.numPrimeTestCompletedErrors,
            primeStats.numPrimeTestFailures);
}
