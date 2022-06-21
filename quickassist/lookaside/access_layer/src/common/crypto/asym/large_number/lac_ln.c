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
* @file lac_ln.c Large Number API Implementation
*
* @ingroup LacAsymLn
*
* @description
*      This file contains the implementation of Large Number
*      functions
*
***************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

/* Include API files */
#include "cpa.h"
#include "cpa_cy_ln.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Osal Includes */
#include "Osal.h"

/* adf Includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "sal_service_state.h"
#include "lac_sal_ctrl.h"
#include "lac_pke_qat_comms.h"
#include "lac_hooks.h"
#include "lac_ln.h"
#include "lac_pke_utils.h"
#include "sal_statistics.h"

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/* Number of LN statistics */
#define LAC_LN_NUM_STATS (sizeof(CpaCyLnStats64) / sizeof(Cpa64U))
/*
********************************************************************************
* Static Variables
********************************************************************************
*/

/* macro to initialize all Large Number (LN) Service stats
 * (stored in internal array of atomics) */
#define LAC_LN_STATS_INIT(pCryptoService)                                      \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_LN_NUM_STATS; i++)                                 \
        {                                                                      \
            osalAtomicSet(0, &pCryptoService->pLacLnStatsArr[i]);              \
        }                                                                      \
    } while (0)

/* macro to increment a Large Number (LN) Service stat
 * (derives offset into array of atomics) */

#ifndef DISABLE_STATS
#define LAC_LN_STAT_INC(statistic, pCryptoService)                             \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bLnStatsEnabled)       \
        {                                                                      \
            osalAtomicInc(                                                     \
                &pCryptoService                                                \
                     ->pLacLnStatsArr[offsetof(CpaCyLnStats64, statistic) /    \
                                      sizeof(Cpa64U)]);                        \
        }                                                                      \
    } while (0)
#else
#define LAC_LN_STAT_INC(statistic, pCryptoService)
#endif

/* macro to get Large Number (LN) Service 32bit stats (from internal array of
 * atomics)
 *  into user supplied structure CpaCyLnStats pointed by lnStats
 *  pointer */
#define LAC_LN_STATS32_GET(lnStats, pCryptoService)                            \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_LN_NUM_STATS; i++)                                 \
        {                                                                      \
            ((Cpa32U *)&(lnStats))[i] =                                        \
                (Cpa32U)osalAtomicGet(&pCryptoService->pLacLnStatsArr[i]);     \
        }                                                                      \
    } while (0)

/* macro to get Large Number (LN) Service 64bit stats (from internal array of
 * atomics)
 *  into user supplied structure CpaCyLnStats pointed by lnStats
 *  pointer */
#define LAC_LN_STATS64_GET(lnStats, pCryptoService)                            \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_LN_NUM_STATS; i++)                                 \
        {                                                                      \
            ((Cpa64U *)&(lnStats))[i] =                                        \
                osalAtomicGet(&pCryptoService->pLacLnStatsArr[i]);             \
        }                                                                      \
    } while (0)

/* Maps between operation sizes and Large Number Modular Exponentiation
 *  function ids */
static const Cpa32U lacMathsModexpSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_512_BITS, MATHS_MODEXP_L512},
    {LAC_1024_BITS, MATHS_MODEXP_L1024},
    {LAC_1536_BITS, MATHS_MODEXP_L1536},
    {LAC_2048_BITS, MATHS_MODEXP_L2048},
    {LAC_2560_BITS, MATHS_MODEXP_L2560},
    {LAC_3072_BITS, MATHS_MODEXP_L3072},
    {LAC_3584_BITS, MATHS_MODEXP_L3584},
    {LAC_4096_BITS, MATHS_MODEXP_L4096},
    {LAC_8192_BITS, MATHS_MODEXP_L8192}};

/* Maps between operation sizes and Large Number Modular Inversion Odd
 *  function ids */
static const Cpa32U lacMathsModinvOddSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_128_BITS, MATHS_MODINV_ODD_L128},
    {LAC_192_BITS, MATHS_MODINV_ODD_L192},
    {LAC_256_BITS, MATHS_MODINV_ODD_L256},
    {LAC_384_BITS, MATHS_MODINV_ODD_L384},
    {LAC_512_BITS, MATHS_MODINV_ODD_L512},
    {LAC_768_BITS, MATHS_MODINV_ODD_L768},
    {LAC_1024_BITS, MATHS_MODINV_ODD_L1024},
    {LAC_1536_BITS, MATHS_MODINV_ODD_L1536},
    {LAC_2048_BITS, MATHS_MODINV_ODD_L2048},
    {LAC_3072_BITS, MATHS_MODINV_ODD_L3072},
    {LAC_4096_BITS, MATHS_MODINV_ODD_L4096},
    {LAC_8192_BITS, MATHS_MODINV_ODD_L8192}};

/* Maps between operation sizes and Large Number Modular Inversion Even
 *  function ids */
static const Cpa32U lacMathsModinvEvenSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_128_BITS, MATHS_MODINV_EVEN_L128},
    {LAC_192_BITS, MATHS_MODINV_EVEN_L192},
    {LAC_256_BITS, MATHS_MODINV_EVEN_L256},
    {LAC_384_BITS, MATHS_MODINV_EVEN_L384},
    {LAC_512_BITS, MATHS_MODINV_EVEN_L512},
    {LAC_768_BITS, MATHS_MODINV_EVEN_L768},
    {LAC_1024_BITS, MATHS_MODINV_EVEN_L1024},
    {LAC_1536_BITS, MATHS_MODINV_EVEN_L1536},
    {LAC_2048_BITS, MATHS_MODINV_EVEN_L2048},
    {LAC_3072_BITS, MATHS_MODINV_EVEN_L3072},
    {LAC_4096_BITS, MATHS_MODINV_EVEN_L4096},
    {LAC_8192_BITS, MATHS_MODINV_EVEN_L8192}};

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln Get Buffer Data Size in Bytes function
 * The function scans the input buffer to locate the most significant non-zero
 * byte of a number in big endian order.
 ******************************************************************************/
STATIC
Cpa32U LacGetBufferDataSizeInBytes(const CpaFlatBuffer *pBuffer)
{
    Cpa32U dataSizeInBytes = 0;
    Cpa32U counter = 0;

    if (NULL != pBuffer)
    {
        Cpa32U maxDataSize = pBuffer->dataLenInBytes;

        for (counter = 0; (counter < maxDataSize) && (0 == dataSizeInBytes);
             counter++)
        {
            if (pBuffer->pData[counter])
            {
                dataSizeInBytes = maxDataSize - counter;
            }
        }
    }
    return dataSizeInBytes;
}

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Large Number Modular Exponentation internal callback function
 ******************************************************************************/
STATIC
void LacLnModExpCallback(CpaStatus status,
                         CpaBoolean pass,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    CpaCyLnModExpOpData *pOpData = NULL;
    void *pCallbackTag = NULL;
    CpaFlatBuffer *pResult = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* retrieve data from the callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOpData = (CpaCyLnModExpOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCallbackTag = pCbData->pCallbackTag;
    pResult = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pResult);

    /* pass flag is not used here */

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_LN_STAT_INC(numLnModExpCompleted, pCryptoService);
    }
    else
    {
        LAC_LN_STAT_INC(numLnModExpCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pResult);
}

#ifdef ICP_PARAM_CHECK
/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln ModExp parameter check
 ******************************************************************************/
STATIC
CpaStatus LacLnModExpParameterCheck(const CpaCyGenFlatBufCbFunc pCb,
                                    CpaCyLnModExpOpData *pOpData,
                                    CpaFlatBuffer *pResult)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);
    /* check for null Operational Data parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    /* check for null result pointer */
    LAC_CHECK_NULL_PARAM(pResult);

    /* check for null argument parameters */
    LAC_CHECK_FLAT_BUFFER(&pOpData->base);
    LAC_CHECK_ZERO_SIZE(&pOpData->base);
    LAC_CHECK_FLAT_BUFFER(&pOpData->exponent);
    LAC_CHECK_ZERO_SIZE(&pOpData->exponent);
    LAC_CHECK_FLAT_BUFFER(&pOpData->modulus);
    LAC_CHECK_ZERO_SIZE(&pOpData->modulus);
    LAC_CHECK_FLAT_BUFFER(pResult);
    LAC_CHECK_ZERO_SIZE(pResult);

    /* Zero modulus is an invalid parameter */
    LAC_CHECK_NON_ZERO_PARAM(&pOpData->modulus);

    return status;
}
#endif

/**
 ***************************************************************************
 * @ingroup LacAsymLn
 *      Large Number Modular Exponentation synchronous function
 ***************************************************************************/
STATIC CpaStatus LacLnModExpSyn(const CpaInstanceHandle instanceHandle,
                                const CpaCyLnModExpOpData *pLnModExpOpData,
                                CpaFlatBuffer *pResult)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyLnModExp(instanceHandle,
                               LacSync_GenFlatBufCb,
                               pSyncCallbackData,
                               pLnModExpOpData,
                               pResult);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_LN_STAT_INC(numLnModExpRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_LN_STAT_INC(numLnModExpCompletedErrors, pCryptoService);
#endif
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
 * @ingroup LacAsymLn
 *      Large Number Modular Exponentation API function
 ******************************************************************************/
CpaStatus cpaCyLnModExp(const CpaInstanceHandle instanceHandle_in,
                        const CpaCyGenFlatBufCbFunc pLnModExpCb,
                        void *pCallbackTag,
                        const CpaCyLnModExpOpData *pLnModExpOpData,
                        CpaFlatBuffer *pResult)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U index = LAC_PKE_INVALID_INDEX;
    Cpa32U dataOperationSize = 0;

    Cpa32U dataLenCommon = 0;
    Cpa32U dataLenBase = 0;
    Cpa32U dataLenExponent = 0;
    Cpa32U dataLenModulus = 0;
    Cpa32U dataLenResult = 0;

#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
#endif
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};

    /* Holding the calculated size of the input/output parameters */
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

    /* Data that will be passed back in call back function - opaque data */
    lac_pke_op_cb_data_t lnModExpData = {0};

#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pLnModExpCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pLnModExpOpData,
             (LAC_ARCH_UINT)pResult);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* check for valid acceleration handle */
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

    /* Check if the API has been called in sync mode */
    if (NULL == pLnModExpCb)
    {
        return LacLnModExpSyn(instanceHandle, pLnModExpOpData, pResult);
    }

#ifdef ICP_PARAM_CHECK
    /* check that the input parameters are valid */
    status = LacLnModExpParameterCheck(
        pLnModExpCb, LAC_CONST_PTR_CAST(pLnModExpOpData), pResult);
#endif
#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* calculate the actual data size of the input parameters in bytes */
        dataLenBase = LacGetBufferDataSizeInBytes(&pLnModExpOpData->base);
        dataLenExponent =
            LacGetBufferDataSizeInBytes(&pLnModExpOpData->exponent);
        dataLenModulus = LacGetBufferDataSizeInBytes(&pLnModExpOpData->modulus);
        dataLenResult = pResult->dataLenInBytes;

        /* the Result buffer size has to be at least the size of the Modulus */
        if (dataLenResult < dataLenModulus)
        {
            LAC_INVALID_PARAM_LOG("Result buffer size must be >= Modulus size");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* calculate the biggest common bit size for the three
         *  input parameters */
        dataLenCommon =
            (dataLenBase > dataLenExponent) ? dataLenBase : dataLenExponent;
        dataLenCommon =
            (dataLenCommon > dataLenModulus) ? dataLenCommon : dataLenModulus;
        dataLenCommon = LAC_BYTES_TO_BITS(dataLenCommon);

        /* One row in the mapping table contains operation size and matching
         *  function Id. First, calculate the index of that row using the common
         *  data length */
        index = LacPke_GetIndex_VariableSize(
            dataLenCommon,
            lacMathsModexpSizeIdMap,
            LAC_ARRAY_LEN(lacMathsModexpSizeIdMap));
        if (LAC_PKE_INVALID_INDEX == index)
        {
            LAC_LOG_ERROR("The input data size is not supported");
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* the input/output parameters have to be padded to the operation size
         *  for QAT processing so assign the new size in bytes to each parameter
         *  before the request has been sent out to QAT */

        dataOperationSize = LAC_BITS_TO_BYTES(
            (lacMathsModexpSizeIdMap[index][LAC_PKE_SIZE_COLUMN]));

        /* get the functionality ID that matches operation size */
        functionalityId = lacMathsModexpSizeIdMap[index][LAC_PKE_ID_COLUMN];

        /* preserve user parameters for when our Call Back
         *  function kicks in, after sending the head request */

        lnModExpData.pClientCb = pLnModExpCb;
        lnModExpData.pCallbackTag = pCallbackTag;
        lnModExpData.pClientOpData = pLnModExpOpData;
        lnModExpData.pOpaqueData = NULL;
        lnModExpData.pOutputData1 = pResult;

        /* User allocated some memory for the result. Initialise it with zeros
         *  beforehand  */
        LAC_OS_BZERO(pResult->pData, dataLenResult);

        /* populate input/output parameters - use maths_modexp_l512 structure
           for all functionalityIDs - verified at compile time */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.maths_modexp_l512.g,
                                      &pLnModExpOpData->base);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g)] =
            dataOperationSize;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g)] =
            CPA_FALSE;
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.maths_modexp_l512.e,
                                      &pLnModExpOpData->exponent);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e)] =
            dataOperationSize;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e)] =
            CPA_FALSE;
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.maths_modexp_l512.m,
                                      &pLnModExpOpData->modulus);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m)] =
            dataOperationSize;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.maths_modexp_l512.r, pResult);
        outArgSizeList[0] = dataOperationSize;
        internalMemOutList[0] = CPA_FALSE;

        /* Send a PKE request */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacLnModExpCallback,
                                          &lnModExpData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* update stats. */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* increment stats:
         *  Total number of LN ModExp test requested operations */
        LAC_LN_STAT_INC(numLnModExpRequests, pCryptoService);
    }
    else
    {
        /* on failure increment stats:
         * Total number of LN ModExp test errors recorded */
        LAC_LN_STAT_INC(numLnModExpRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Large Number Modular Inversion internal callback function
 ******************************************************************************/
STATIC
void LacLnModInvCallback(CpaStatus status,
                         CpaBoolean pass,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    CpaCyLnModInvOpData *pOpData = NULL;
    void *pCallbackTag = NULL;
    CpaFlatBuffer *pResult = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* retrieve data from the callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOpData = (CpaCyLnModInvOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCallbackTag = pCbData->pCallbackTag;
    pResult = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pResult);

    /* pass flag is not used here */

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_LN_STAT_INC(numLnModInvCompleted, pCryptoService);
    }
    else
    {
        LAC_LN_STAT_INC(numLnModInvCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pResult);
}

#ifdef ICP_PARAM_CHECK
/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln ModInv parameter check
 ******************************************************************************/
STATIC
CpaStatus LacLnModInvParameterCheck(const CpaCyGenFlatBufCbFunc pCb,
                                    CpaCyLnModInvOpData *pOpData,
                                    CpaFlatBuffer *pResult)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);
    /* check for null Operational Data parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    /* check for null result pointer */
    LAC_CHECK_NULL_PARAM(pResult);

    /* check for null argument parameters */

    LAC_CHECK_FLAT_BUFFER(&pOpData->A);
    LAC_CHECK_ZERO_SIZE(&pOpData->A);
    LAC_CHECK_FLAT_BUFFER(&pOpData->B);
    LAC_CHECK_ZERO_SIZE(&pOpData->B);
    LAC_CHECK_FLAT_BUFFER(pResult);
    LAC_CHECK_ZERO_SIZE(pResult);

    /* Input parameters should not be equal to zero */
    LAC_CHECK_NON_ZERO_PARAM(&pOpData->A);
    LAC_CHECK_NON_ZERO_PARAM(&pOpData->B);

    /* the input parameters are invalid if both modulus (B) and the value to be
     *  inverted (A) are even (LSB is not set)*/

    if ((!(pOpData->A.pData[pOpData->A.dataLenInBytes - 1] & 0x01)) &&
        (!(pOpData->B.pData[pOpData->B.dataLenInBytes - 1] & 0x01)))
    {
        LAC_INVALID_PARAM_LOG("Both modulus and value to invert are even");
        status = CPA_STATUS_INVALID_PARAM;
    }

    return status;
}
#endif

/**
 ***************************************************************************
 * @ingroup LacAsymLn
 *      Large Number Modular Inversion synchronous function
 ***************************************************************************/
STATIC CpaStatus LacLnModInvSyn(const CpaInstanceHandle instanceHandle,
                                const CpaCyLnModInvOpData *pLnModInvOpData,
                                CpaFlatBuffer *pResult)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyLnModInv(instanceHandle,
                               LacSync_GenFlatBufCb,
                               pSyncCallbackData,
                               pLnModInvOpData,
                               pResult);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_LN_STAT_INC(numLnModInvRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_LN_STAT_INC(numLnModInvCompletedErrors, pCryptoService);
#endif
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
 * @ingroup LacAsymLn
 *      Large Number Modular Inversion API function
 ******************************************************************************/
CpaStatus cpaCyLnModInv(const CpaInstanceHandle instanceHandle_in,
                        const CpaCyGenFlatBufCbFunc pLnModInvCb,
                        void *pCallbackTag,
                        const CpaCyLnModInvOpData *pLnModInvOpData,
                        CpaFlatBuffer *pResult)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U index = LAC_PKE_INVALID_INDEX;
    Cpa32U dataOperationSize = 0;

    Cpa32U dataLenCommon = 0;
    Cpa32U dataLenA = 0;
    Cpa32U dataLenB = 0;
    Cpa32U dataLenResult = 0;

#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
#endif
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};

    /* Holding the calculated size of the input/output parameters */
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

    /* Data that will be passed back in call back function - opaque data */
    lac_pke_op_cb_data_t lnModInvData = {0};

#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pLnModInvCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pLnModInvOpData,
             (LAC_ARCH_UINT)pResult);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* check for valid acceleration handle */
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

    /* Check if the API has been called in sync mode */
    if (NULL == pLnModInvCb)
    {
        return LacLnModInvSyn(instanceHandle, pLnModInvOpData, pResult);
    }

#ifdef ICP_PARAM_CHECK
    /* check that the input parameters are valid */
    status = LacLnModInvParameterCheck(
        pLnModInvCb, LAC_CONST_PTR_CAST(pLnModInvOpData), pResult);
#endif
#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* calculate the actual data size of the input parameters in bytes */
        dataLenA = LacGetBufferDataSizeInBytes(&pLnModInvOpData->A);
        dataLenB = LacGetBufferDataSizeInBytes(&pLnModInvOpData->B);
        dataLenResult = pResult->dataLenInBytes;

        /* the Result buffer size has to be at least the size of the Modulus */
        if (dataLenResult < dataLenB)
        {
            LAC_INVALID_PARAM_LOG("Result buffer size less then Modulus size");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {

        /* calculate the biggest common bit size for the two input params */
        dataLenCommon = (dataLenA > dataLenB) ? dataLenA : dataLenB;
        dataLenCommon = LAC_BYTES_TO_BITS(dataLenCommon);

        /* Both ODD and EVEN mapping table contain the same operation sizes.
         *  data length. The ODD table is used here */
        index = LacPke_GetIndex_VariableSize(
            dataLenCommon,
            lacMathsModinvOddSizeIdMap,
            LAC_ARRAY_LEN(lacMathsModinvOddSizeIdMap));
        if (LAC_PKE_INVALID_INDEX == index)
        {
            LAC_INVALID_PARAM_LOG("The input data size is not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* the input/output parameters have to be padded to the operation size
         *  for QAT processing so assign the new size in bytes to each parameter
         *  before the request has been sent out to QAT */

        /* Both ODD and EVEN mapping tables can give the right operation size
         *  that corresponds to the index. The ODD table is used here. */
        dataOperationSize = LAC_BITS_TO_BYTES(
            (lacMathsModinvOddSizeIdMap[index][LAC_PKE_SIZE_COLUMN]));

        /* get functionality ID based on odd/even character of the parameters -
         *  we already confirmed that at least one parameter is odd, otherwise
         *  we wouldn't reach this point */

        if (!(pLnModInvOpData->B.pData[pLnModInvOpData->B.dataLenInBytes - 1] &
              0x01))
        {
            /* if pA is odd and pB is even (already confirmed that at least
             *  one is odd), look into EVEN functionality ID pool */
            functionalityId =
                lacMathsModinvEvenSizeIdMap[index][LAC_PKE_ID_COLUMN];
        }
        else
        {
            /* if pA is odd/even and pB parameter is odd, look into ODD
             *  functionality ID pool */
            functionalityId =
                lacMathsModinvOddSizeIdMap[index][LAC_PKE_ID_COLUMN];
        }

        /* preserve user parameters for when our Call Back
         *  function kicks in, after sending the head request */

        lnModInvData.pClientCb = pLnModInvCb;
        lnModInvData.pCallbackTag = pCallbackTag;
        lnModInvData.pClientOpData = pLnModInvOpData;
        lnModInvData.pOpaqueData = NULL;
        lnModInvData.pOutputData1 = pResult;

        /* User allocated some memory for the result. Initialise it with zeros
         *  beforehand  */
        LAC_OS_BZERO(pResult->pData, dataLenResult);

        /* populate input/output parameters - using maths_modinv_odd_l128
           structure for all - verified at compile time that this can be
           done */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.maths_modinv_odd_l128.a,
                                      &pLnModInvOpData->A);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a)] =
            dataOperationSize;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t,
                                     a)] = CPA_FALSE;
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.maths_modinv_odd_l128.b,
                                      &pLnModInvOpData->B);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b)] =
            dataOperationSize;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t,
                                     b)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.maths_modinv_odd_l128.c,
                                      pResult);
        outArgSizeList[0] = dataOperationSize;
        internalMemOutList[0] = CPA_FALSE;

        /* Send a PKE request */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacLnModInvCallback,
                                          &lnModInvData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* update stats. */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* increment stats:
         *  Total number of LN ModExp test requested operations */
        LAC_LN_STAT_INC(numLnModInvRequests, pCryptoService);
    }
    else
    {
        /* on failure increment stats:
         * Total number of LN ModExp test errors recorded */
        LAC_LN_STAT_INC(numLnModInvRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln Statistics Query API function
 ******************************************************************************/
CpaStatus cpaCyLnStatsQuery(CpaInstanceHandle instanceHandle_in,
                            CpaCyLnStats *pLnStats)
{
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
#endif
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pLnStats);
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
    LAC_CHECK_NULL_PARAM(pLnStats);

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    /* get stats into user supplied stats structure */
    LAC_LN_STATS32_GET(*pLnStats, pCryptoService);
#endif
    return CPA_STATUS_SUCCESS;
}

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln Statistics Query API function
 ******************************************************************************/
CpaStatus cpaCyLnStatsQuery64(CpaInstanceHandle instanceHandle_in,
                              CpaCyLnStats64 *pLnStats)
{
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
#endif
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pLnStats);
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
    LAC_CHECK_NULL_PARAM(pLnStats);

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    /* get stats into user supplied stats structure */
    LAC_LN_STATS64_GET(*pLnStats, pCryptoService);
#endif
    return CPA_STATUS_SUCCESS;
}

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln Initialization function
 ******************************************************************************/
CpaStatus LacLn_Init(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    status = LAC_OS_MALLOC(&(pCryptoService->pLacLnStatsArr),
                           LAC_LN_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        /* initialize stats to zero */
        LAC_LN_STATS_INIT(pCryptoService);
    }
#endif

    /* Call compile time param check function to ensure it is included
       in the build by the compiler */
    LacLn_CompileTimeAssertions();

    return status;
}

void LacLn_StatsFree(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (NULL != pCryptoService->pLacLnStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacLnStatsArr);
    }
}

void LacLn_StatsReset(CpaInstanceHandle instanceHandle)
{
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    LAC_LN_STATS_INIT(pCryptoService);
#endif
}

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      Ln Stats Show function
 ******************************************************************************/
void LacLn_StatsShow(CpaInstanceHandle instanceHandle)
{
    CpaCyLnStats64 lnStats = {0};

    /* retrieve the stats */
    (void)cpaCyLnStatsQuery64(instanceHandle, &lnStats);

    /* log the stats to the standard output */

    /* Engine Info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            " LN ModExp/ModInv Stats                     " BORDER
            "\n" SEPARATOR);

    /* Large Number Modular Exponentationstats operations stats */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " LN ModEXP successful requests:  %16llu " BORDER "\n" BORDER
                   " LN ModEXP requests with error:  %16llu " BORDER "\n" BORDER
                   " LN ModEXP completed operations: %16llu " BORDER "\n" BORDER
                   " LN ModEXP not completed-errors: %16llu " BORDER
                   "\n" SEPARATOR,
            lnStats.numLnModExpRequests,
            lnStats.numLnModExpRequestErrors,
            lnStats.numLnModExpCompleted,
            lnStats.numLnModExpCompletedErrors);

    /*  Large Number Modular Inversion operations stats */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " LN ModINV successful requests:  %16llu " BORDER "\n" BORDER
                   " LN ModINV requests with error:  %16llu " BORDER "\n" BORDER
                   " LN ModINV completed operations: %16llu " BORDER "\n" BORDER
                   " LN ModINV not completed-errors: %16llu " BORDER
                   "\n" SEPARATOR,
            lnStats.numLnModInvRequests,
            lnStats.numLnModInvRequestErrors,
            lnStats.numLnModInvCompleted,
            lnStats.numLnModInvCompletedErrors);
}
