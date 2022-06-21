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
 *
 * @file lac_ecdh.c
 *
 * @ingroup Lac_Ec
 *
 * Elliptic Curve Diffie Hellman functions
 *
 * @lld_start
 *
 * @lld_overview
 * This file implements the Elliptic Curve Diffie-Hellman apis.
 * @lld_dependencies
 * - \ref LacAsymCommonQatComms "PKE QAT Comms" : For creating and sending
 * messages to the QAT
 * - \ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @lld_initialisation
 * On initialization this component clears the stats.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 ***************************************************************************/

/*
****************************************************************************
* Include public/global header files
****************************************************************************
*/

/* API Includes */
#include "cpa.h"
#include "cpa_cy_ecdh.h"

/* OSAL Includes */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* Include QAT files */
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"
#include "icp_qat_fw_la.h"

/* Look Aside Includes */
#include "lac_log.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_sync.h"
#include "lac_ec.h"

#include "lac_sym.h"
#include "lac_list.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "sal_statistics.h"

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/**< number of 'in' arguments in the arguments size list for point verify */
#define LAC_ECDH_POINT_VERIFY_NUM_IN_ARGS 5
/**< number of 'in' arguments in the arguments size list for point multiply */
#define LAC_ECDH_POINT_MULTIPLY_NUM_IN_ARGS 7
/**< number of 'out' arguments in the arguments size list for point multiply */
#define LAC_ECDH_POINT_MULTIPLY_NUM_OUT_ARGS 2

/**< number of ECDH statistics */
#define LAC_ECDH_NUM_STATS (sizeof(CpaCyEcdhStats64) / sizeof(Cpa64U))

#ifndef DISABLE_STATS
#define LAC_ECDH_STAT_INC(statistic, pCryptoService)                           \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bEccStatsEnabled)      \
        {                                                                      \
            osalAtomicInc(                                                     \
                &pCryptoService->pLacEcdhStatsArr[offsetof(CpaCyEcdhStats64,   \
                                                           statistic) /        \
                                                  sizeof(Cpa64U)]);            \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ecdh
 * macro to increment a ECDH stat (derives offset into array of atomics) */
#else
#define LAC_ECDH_STAT_INC(statistic, pCryptoService)                           \
    do                                                                         \
    {                                                                          \
    } while (0)
#endif

#define LAC_ECDH_STATS_GET(ecdhStats, pCryptoService)                          \
    do                                                                         \
    {                                                                          \
        Cpa32U i = 0;                                                          \
                                                                               \
        for (i = 0; i < LAC_ECDH_NUM_STATS; i++)                               \
        {                                                                      \
            ((Cpa64U *)&(ecdhStats))[i] =                                      \
                osalAtomicGet(&pCryptoService->pLacEcdhStatsArr[i]);           \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ecdh
 * macro to collect a ECDH stat in sample period of performance counters */

/**< @ingroup Lac_Ecdh
 * macro to get all ECDH stats (from internal array of atomics) */

#define LacEcdhPointMultiplyOpDataWrite(in, out, pOpData, pXk, pYk)            \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xg, &pOpData->xg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yg, &pOpData->yg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.h, &pOpData->h);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.q, &pOpData->q);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.a, &pOpData->a);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.b, &pOpData->b);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, &pOpData->k);                      \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.xk, pXk);                            \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.yk, pYk);                            \
    } while (0);
/**< @ingroup Lac_Ecdh
 * macro to write in/out parameters for the ECDH Point Multiply operation*/

#define LacEcdhPointVerifyOpDataWrite(in, pOpData)                             \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xq, &pOpData->xg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yq, &pOpData->yg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.q, &pOpData->q);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.a, &pOpData->a);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.b, &pOpData->b);                      \
    } while (0);
/**< @ingroup Lac_Ecdh
 * macro to write in parameters for the Point Verify operation */

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/
/**
 ***************************************************************************
 * @ingroup Lac_Ecdh
 *      return the min size in bytes of biggest number in flat buffer
 *      in CpaCyEcdhPointMultiplyOpData structure
 *
 * @description
 *      return the size of the biggest number in
 *      CpaCyEcdhPointMultiplyOpData.
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcdhPointMultiplyOpData structure
 *
 * @retval max  the size of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U LacEcdh_PointMultiplyOpDataSizeGetMax(
    const CpaCyEcdhPointMultiplyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers .. */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->h)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->q)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->a)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->b)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);

    return max;
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ecdh
 *      ECDH Point Multiply function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus LacEcdh_PointMultiplyBasicParamCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcdhPointMultiplyOpData *pOpData,
    const CpaBoolean *pMultiplyStatus,
    const CpaFlatBuffer *pXk,
    const CpaFlatBuffer *pYk)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->a.pData);
    LAC_CHECK_SIZE(&(pOpData->a), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->b.pData);
    LAC_CHECK_SIZE(&(pOpData->b), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->q.pData);
    LAC_CHECK_SIZE(&(pOpData->q), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xg.pData);
    LAC_CHECK_SIZE(&(pOpData->xg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yg.pData);
    LAC_CHECK_SIZE(&(pOpData->yg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pXk);
    LAC_CHECK_NULL_PARAM(pYk);
    LAC_CHECK_NULL_PARAM(pXk->pData);
    LAC_CHECK_SIZE(pXk, CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pYk->pData);
    LAC_CHECK_SIZE(pYk, CHECK_NONE, 0);

    /* Check Cofactor - pData of FlatBuffer can be NULL if dataLenInBytes=0 */
    LAC_CHECK_NULL_PARAM(&pOpData->h);
    if ((NULL == pOpData->h.pData) && (0 != pOpData->h.dataLenInBytes))
    {
        LAC_INVALID_PARAM_LOG("pOpData->h.pData is NULL and "
                              "pOpData->h.dataLenInBytes !=0");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (NULL != pOpData->h.pData)
    {
        LAC_CHECK_SIZE(&(pOpData->h), CHECK_NONE, 0);
    }

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pOpData->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pOpData->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /*Check that q is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->q));

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Ecdh
 *      ECDH Point Multiply synchronous function
 ***************************************************************************/
STATIC CpaStatus
LacEcdh_PointMultiplySyn(const CpaInstanceHandle instanceHandle,
                         const CpaCyEcdhPointMultiplyOpData *pOpData,
                         CpaBoolean *pMultiplyStatus,
                         CpaFlatBuffer *pXk,
                         CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcdhPointMultiply(instanceHandle,
                                        LacSync_GenDualFlatBufVerifyCb,
                                        pSyncCallbackData,
                                        pOpData,
                                        pMultiplyStatus,
                                        pXk,
                                        pYk);
    }
    else
    {
        LAC_ECDH_STAT_INC(numEcdhPointMultiplyRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_ECDH_STAT_INC(numEcdhPointMultiplyCompletedError,
                              pCryptoService);
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
 ***************************************************************************
 * @ingroup Lac_Ecdh
 *      ECDH Point Multiply internal callback
 ***************************************************************************/
STATIC void LacEcdh_PointMultiplyCallback(CpaStatus status,
                                          CpaBoolean multiplyStatus,
                                          CpaInstanceHandle instanceHandle,
                                          lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcdhPointMultiplyCbFunc pCb = NULL;
    CpaCyEcdhPointMultiplyOpData *pOpData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif
    void *pCallbackTag = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcdhPointMultiplyCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcdhPointMultiplyOpData *)pCbData->pClientOpData;
    pXk = pCbData->pOutputData1;
    pYk = pCbData->pOutputData2;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pXk);
    LAC_ASSERT_NOT_NULL(pYk);

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDH_STAT_INC(numEcdhPointMultiplyCompleted, pCryptoService);
    }
    else
    {
        LAC_ECDH_STAT_INC(numEcdhPointMultiplyCompletedError, pCryptoService);
    }

    /* check for exception */
    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECDH_STAT_INC(numEcdhRequestCompletedOutputInvalid, pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pXk, pYk);
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecdh
 *
 ***************************************************************************/
CpaStatus cpaCyEcdhPointMultiply(const CpaInstanceHandle instanceHandle_in,
                                 const CpaCyEcdhPointMultiplyCbFunc pCb,
                                 void *pCallbackTag,
                                 const CpaCyEcdhPointMultiplyOpData *pOpData,
                                 CpaBoolean *pMultiplyStatus,
                                 CpaFlatBuffer *pXk,
                                 CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
#ifdef ICP_PARAM_CHECK
    Cpa32U bit_pos_k = 0, bit_pos_h = 0, bit_pos_q = 0;
    Cpa32U temp = 0;
    Cpa32U maxModLen = 0;
    CpaBoolean isZero = CPA_FALSE;
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
    /* instance checks - if fail, no inc stats just return */
    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* ensure LAC is initialised - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
#ifdef ICP_PARAM_CHECK
        /* Check for valid pointers */
        LAC_CHECK_NULL_PARAM(pMultiplyStatus);
#endif
        status = LacEcdh_PointMultiplySyn(
            instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);
        LAC_LOG7("Called with params (0x%x, 0x%x, 0x%x, 0x%x, "
                 "%d, 0x%x, 0x%x)\n",
                 (LAC_ARCH_UINT)instanceHandle_in,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 *pMultiplyStatus,
                 (LAC_ARCH_UINT)pXk,
                 (LAC_ARCH_UINT)pYk);
        return status;
#else
        /* Call synchronous mode function */
        return LacEcdh_PointMultiplySyn(
            instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcdh_PointMultiplyBasicParamCheck(
        instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);

    /* Check that output buffers are big enough */
    if (CPA_STATUS_SUCCESS == status)
    {
        maxModLen = LacPke_GetMinBytes(&(pOpData->q));
        if ((pXk->dataLenInBytes < maxModLen) ||
            (pYk->dataLenInBytes < maxModLen))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
#endif
        /* Determine size */
        status = LacEc_GetRange(LacEcdh_PointMultiplyOpDataSizeGetMax(pOpData),
                                &dataOperationSizeBytes);
#ifdef ICP_PARAM_CHECK
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        if ((LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            /* Check if it is a NIST curve if not use 8QW */
            LacEc_CheckCurve4QWGF2(&dataOperationSizeBytes,
                                   &(pOpData->q),
                                   &(pOpData->a),
                                   &(pOpData->b),
                                   NULL,
                                   &(pOpData->h));
        }
    }

#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) &&
        (LAC_EC_SIZE_QW9_IN_BYTES == dataOperationSizeBytes))
    {
        /* 9QW checks */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Check if it is a NIST curve if not inval param */
            /* Also checks that xG and yG are less than 2^521 */
            status = LacEc_CheckCurve9QWGFP(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            NULL,
                                            &(pOpData->h),
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
        else
        {
            /*Check if it is a NIST curve if not inval param */
            /* Also checks that deg of xG and yG are less than deg q */
            status = LacEc_CheckCurve9QWGF2(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            NULL,
                                            &(pOpData->h),
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check size of h*k result                                   */
        /* log2(h*k) = log2(h) +log2(k)                               */
        /* highest bit position of (h*k) = floor[log2(h*k)]           */
        /* max(floor[log2(h*k)]) = floor[log2(h)] +floor[log2(k)] + 1 */
        /* for h>1 and k>1, else if h=1 or k=1 check is already done */
        /* by earlier buffer checks                                   */
        LacPke_GetBitPos(&(pOpData->k), &bit_pos_k, &temp, &isZero);

        if (NULL == pOpData->h.pData)
        {
            bit_pos_h = 0;
        }
        else
        {
            LacPke_GetBitPos(&(pOpData->h), &bit_pos_h, &temp, &isZero);
        }

        if ((bit_pos_h > 0) && (bit_pos_k > 0))
        {
            /* So h>1 and k>1 so we need to check i
               floor[log2(h)] +floor[log2(k)] + 1 */
            if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
            {
                /* In GFP case h*k should fit in dataOperationSizeBytes */
                if ((LAC_BYTES_TO_BITS(dataOperationSizeBytes) - 1) <
                    (bit_pos_k + bit_pos_h + 1))
                {
                    if (dataOperationSizeBytes != LAC_EC_SIZE_QW4_IN_BYTES)
                    {
                        /* In 8QW case invalid param (similarly for 9QW but
                            code won't get this far */
                        LAC_INVALID_PARAM_LOG("log2(k)+log2(h) is NOT <512");
                        status = CPA_STATUS_INVALID_PARAM;
                    }
                    else
                    {
                        /* Use 8QW service instead */
                        dataOperationSizeBytes = LAC_EC_SIZE_QW8_IN_BYTES;
                    }
                }
            }
            else
            {
                /* In GF2 9QW and 4QW speacial cases h has already been
                   checked (and is known by MMP) and the size of k has already
                   been checked in getRange function so just need to check
                   8QW case */
                if (LAC_EC_SIZE_QW8_IN_BYTES == dataOperationSizeBytes)
                {
                    /* For 8QW h*k should fit in 9QW */
                    if ((LAC_BYTES_TO_BITS(LAC_EC_SIZE_QW9_IN_BYTES) - 1) <
                        (bit_pos_k + bit_pos_h + 1))
                    {
                        LAC_INVALID_PARAM_LOG("log2(k)+log2(h) is NOT <576");
                        status = CPA_STATUS_INVALID_PARAM;
                    }
                }
            }
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure that h!=0 */
        /* This is invalid for all secure curves */
        /* pH=NULL is sent to PKE as h=0 which is understood by MMP program as
            h=1 as required - therefore need to eliminate invalid h=0 case here
         */
        if (NULL != pOpData->h.pData)
        {
            if (0 == LacPke_CompareZero(&(pOpData->h), 0))
            {
                LAC_INVALID_PARAM_LOG("Cofactor == 0");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that q>3 for GFP (i.e. highest bit position needs to be greater
           than 1) or that deg(q)>2 for GF2 (i.e. highest bit position needs to
           be greater than 2) */
        LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
        if (((CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType) &&
             (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GF2)) ||
            ((CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType) &&
             (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GFP)))
        {
            LAC_INVALID_PARAM_LOG("q is not as required - too small");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        icp_qat_fw_mmp_input_param_t inPointVerify = {.flat_array = {0}};
        icp_qat_fw_mmp_input_param_t inPointMultiply = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t outPointVerify = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t outPointMultiply = {.flat_array = {0}};

        /* Holding the calculated size of the input/output parameters */
        Cpa32U inArgSizeListPointVerify[LAC_MAX_MMP_INPUT_PARAMS] = {0};
        Cpa32U inArgSizeListPointMultiply[LAC_MAX_MMP_INPUT_PARAMS] = {0};
        /*Cpa32U outArgSizeListMultiply[LAC_MAX_MMP_OUTPUT_PARAMS]    = {0};*/

        CpaBoolean internalMemInListVerify[LAC_MAX_MMP_INPUT_PARAMS] = {
            CPA_FALSE};
        CpaBoolean internalMemInListMultiply[LAC_MAX_MMP_INPUT_PARAMS] = {
            CPA_FALSE};
        CpaBoolean internalMemOutListMultiply[LAC_MAX_MMP_OUTPUT_PARAMS] = {
            CPA_FALSE};

        lac_pke_op_cb_data_t cbData = {0};
        Cpa32U functionIdPointVerify = 0;
        Cpa32U functionIdPointMultiply = 0;

        lac_pke_request_handle_t pRequestHandle = LAC_PKE_INVALID_HANDLE;
        /* Clear output buffers */
        osalMemSet(pXk->pData, 0, pXk->dataLenInBytes);
        osalMemSet(pYk->pData, 0, pYk->dataLenInBytes);

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pXk;
        cbData.pOutputData2 = pYk;
        /* Set the size for all parameters to be padded to */
        LAC_EC_SET_LIST_PARAMS(inArgSizeListPointVerify,
                               LAC_ECDH_POINT_VERIFY_NUM_IN_ARGS,
                               dataOperationSizeBytes);
        LAC_EC_SET_LIST_PARAMS(inArgSizeListPointMultiply,
                               LAC_ECDH_POINT_MULTIPLY_NUM_IN_ARGS,
                               dataOperationSizeBytes);
        /*LAC_EC_SET_LIST_PARAMS(
                outArgSizeListMultiply,
                LAC_ECDH_POINT_MULTIPLY_NUM_OUT_ARGS,
                dataOperationSizeBytes); unused param */

        /* Set all memory to be externally allocated */
        LAC_EC_SET_LIST_PARAMS(internalMemInListVerify,
                               LAC_ECDH_POINT_VERIFY_NUM_IN_ARGS,
                               CPA_FALSE);
        LAC_EC_SET_LIST_PARAMS(internalMemInListMultiply,
                               LAC_ECDH_POINT_MULTIPLY_NUM_IN_ARGS,
                               CPA_FALSE);
        LAC_EC_SET_LIST_PARAMS(internalMemOutListMultiply,
                               LAC_ECDH_POINT_MULTIPLY_NUM_OUT_ARGS,
                               CPA_FALSE);

        /* Populate input buffers and output buffer and set function ID */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcdhPointVerifyOpDataWrite(
                        inPointVerify.maths_point_verify_gfp_l256, pOpData);
                    functionIdPointVerify = MATHS_POINT_VERIFY_GFP_L256;
                    LacEcdhPointMultiplyOpDataWrite(
                        inPointMultiply.maths_point_multiplication_gfp_l256,
                        outPointMultiply.maths_point_multiplication_gfp_l256,
                        pOpData,
                        pXk,
                        pYk);
                    functionIdPointMultiply =
                        MATHS_POINT_MULTIPLICATION_GFP_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcdhPointVerifyOpDataWrite(
                        inPointVerify.maths_point_verify_gfp_l512, pOpData);
                    functionIdPointVerify = MATHS_POINT_VERIFY_GFP_L512;
                    LacEcdhPointMultiplyOpDataWrite(
                        inPointMultiply.maths_point_multiplication_gfp_l512,
                        outPointMultiply.maths_point_multiplication_gfp_l512,
                        pOpData,
                        pXk,
                        pYk);
                    functionIdPointMultiply =
                        MATHS_POINT_MULTIPLICATION_GFP_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                {
                    Cpa32U index = 0;
                    LacEcdhPointVerifyOpDataWrite(
                        inPointVerify.maths_point_verify_gfp_521, pOpData);
                    functionIdPointVerify = MATHS_POINT_VERIFY_GFP_521;
                    LacEcdhPointMultiplyOpDataWrite(
                        inPointMultiply.maths_point_multiplication_gfp_521,
                        outPointMultiply.maths_point_multiplication_gfp_521,
                        pOpData,
                        pXk,
                        pYk);
                    functionIdPointMultiply =
                        MATHS_POINT_MULTIPLICATION_GFP_521;
                    /* cofactor size is 1 qw */
                    index = LAC_IDX_OF(
                        icp_qat_fw_maths_point_multiplication_gfp_521_input_t,
                        h);
                    LAC_ASSERT(LAC_MAX_MMP_INPUT_PARAMS > index,
                               "invalid cofactor index");
                    inArgSizeListPointMultiply[index] = LAC_QUAD_WORD_IN_BYTES;
                    break;
                }
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcdhPointVerifyOpDataWrite(
                        inPointVerify.maths_point_verify_gf2_l256, pOpData);
                    functionIdPointVerify = MATHS_POINT_VERIFY_GF2_L256;
                    LacEcdhPointMultiplyOpDataWrite(
                        inPointMultiply.maths_point_multiplication_gf2_l256,
                        outPointMultiply.maths_point_multiplication_gf2_l256,
                        pOpData,
                        pXk,
                        pYk);
                    functionIdPointMultiply =
                        MATHS_POINT_MULTIPLICATION_GF2_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcdhPointVerifyOpDataWrite(
                        inPointVerify.maths_point_verify_gf2_l512, pOpData);
                    functionIdPointVerify = MATHS_POINT_VERIFY_GF2_L512;
                    LacEcdhPointMultiplyOpDataWrite(
                        inPointMultiply.maths_point_multiplication_gf2_l512,
                        outPointMultiply.maths_point_multiplication_gf2_l512,
                        pOpData,
                        pXk,
                        pYk);
                    functionIdPointMultiply =
                        MATHS_POINT_MULTIPLICATION_GF2_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                {
                    Cpa32U index = 0;
                    LacEcdhPointVerifyOpDataWrite(
                        inPointVerify.maths_point_verify_gf2_571, pOpData);
                    functionIdPointVerify = MATHS_POINT_VERIFY_GF2_571;
                    LacEcdhPointMultiplyOpDataWrite(
                        inPointMultiply.maths_point_multiplication_gf2_571,
                        outPointMultiply.maths_point_multiplication_gf2_571,
                        pOpData,
                        pXk,
                        pYk);
                    functionIdPointMultiply =
                        MATHS_POINT_MULTIPLICATION_GF2_571;
                    /* cofactor size is 1 qw */
                    index = LAC_IDX_OF(
                        icp_qat_fw_maths_point_multiplication_gf2_571_input_t,
                        h);
                    LAC_ASSERT(LAC_MAX_MMP_INPUT_PARAMS > index,
                               "invalid cofactor index");
                    inArgSizeListPointMultiply[index] = LAC_QUAD_WORD_IN_BYTES;
                    break;
                }
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }

        /* Chain 2 requests: Point Verify and Point Multiply
           iff pointVerify flag is set */
        if (CPA_TRUE == pOpData->pointVerify)
        {
            if (CPA_STATUS_SUCCESS == status)
            {
                /* create a PKE request to the QAT */
                status = LacPke_CreateRequest(&pRequestHandle,
                                              functionIdPointVerify,
                                              inArgSizeListPointVerify,
                                              NULL,
                                              &inPointVerify,
                                              &outPointVerify,
                                              internalMemInListVerify,
                                              NULL,
                                              LacEcdh_PointMultiplyCallback,
                                              &cbData,
                                              instanceHandle);
            }
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            /* create a PKE request to the QAT */
            status = LacPke_CreateRequest(&pRequestHandle,
                                          functionIdPointMultiply,
                                          inArgSizeListPointMultiply,
                                          inArgSizeListPointMultiply,
                                          &inPointMultiply,
                                          &outPointMultiply,
                                          internalMemInListMultiply,
                                          internalMemOutListMultiply,
                                          LacEcdh_PointMultiplyCallback,
                                          &cbData,
                                          instanceHandle);
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            /* send request chain */
            status = LacPke_SendRequest(&pRequestHandle, instanceHandle);
        }
    }

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDH_STAT_INC(numEcdhPointMultiplyRequests, pCryptoService);
    }
    else
    {
        LAC_ECDH_STAT_INC(numEcdhPointMultiplyRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecdh
 *
 ***************************************************************************/
CpaStatus cpaCyEcdhQueryStats64(const CpaInstanceHandle instanceHandle_in,
                                CpaCyEcdhStats64 *pEcdhStats)
{
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%x, 0x%x)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pEcdhStats);
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

    /* ensure LAC is initialised - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pEcdhStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* get stats into user supplied stats structure */
    LAC_ECDH_STATS_GET(*pEcdhStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}
