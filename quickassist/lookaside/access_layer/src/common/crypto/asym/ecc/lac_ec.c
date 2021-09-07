/***************************************************************************
 *
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 * @file lac_ec.c
 *
 * @ingroup Lac_Ec
 *
 * Elliptic Curve functions
 *
 * @lld_start
 *
 * @lld_overview
 * This file implements Elliptic Curve api funcitons.
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
#include "cpa_cy_ec.h"

/* OSAL Includes */
#include "Osal.h"

/* ADF Includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* QAT FW includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"

/* Look Aside Includes */
#include "lac_log.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_sync.h"
#include "lac_ec.h"
#include "lac_ec_nist_curves.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "sal_service_state.h"
#include "sal_statistics.h"

typedef struct _OptCurveParams
{
    Cpa32U dataOperationSizeBytes;
    Cpa32U function_point;
    const Cpa8U *p;
    const Cpa8U *h;
    const Cpa8U *a;
    const Cpa8U *b;
} OptCurveParams;

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

/**< number of 'in' arguments in the arguments size list for point verify */
#define LAC_EC_POINT_VERIFY_NUM_IN_ARGS 5
/**< number of 'in' arguments in the arguments size list for point multiply */
#define LAC_EC_POINT_MULTIPLY_NUM_IN_ARGS 7
/**< number of 'out' arguments in the arguments size list for point multiply */
#define LAC_EC_POINT_MULTIPLY_NUM_OUT_ARGS 2
/**< number of 'in' arguments in the arguments size list for the P256 and P384
 * Point Multiply operation */
#define LAC_POINT_MULTIPLY_P256P384_NUM_IN_ARGS 3
/**< number of 'out' arguments in the arguments size list for the P256 and P384
 * Point Multiply operation */
#define LAC_POINT_MULTIPLY_P256P384_NUM_OUT_ARGS 2

/**< number of EC statistics */
#define LAC_EC_NUM_STATS (sizeof(CpaCyEcStats64) / sizeof(Cpa64U))

#define LAC_EC_STATS_GET(ecStats, pCryptoService)                              \
    do                                                                         \
    {                                                                          \
        Cpa32U i = 0;                                                          \
                                                                               \
        for (i = 0; i < LAC_EC_NUM_STATS; i++)                                 \
        {                                                                      \
            ((Cpa64U *)&(ecStats))[i] =                                        \
                osalAtomicGet(&pCryptoService->pLacEcStatsArr[i]);             \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ec
 * macro to get all EC stats (from internal array of atomics)
 * assumes pCryptoService has already been validated */

/**< @ingroup Lac_Ec
 * macro to collect EC stats in sample period of time */

#define LacEcPointMultiplyOpDataWrite(in, out, pOpData, pXk, pYk)              \
    do                                                                         \
    {                                                                          \
                                                                               \
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
/**< @ingroup Lac_Ec
 * macro to write in/out parameters for the Point Multiply operation*/

#define LacEcP256P384PointMultiplyWrite(in, out, pOpData, pXk, pYk)            \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xp, &pOpData->xg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yp, &pOpData->yg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, &pOpData->k);                      \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.xr, pXk);                            \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.yr, pYk);                            \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in/out parameters for the P256 and P384 Point Multiply
 * operation */

#define LacEcPointVerifyOpDataWrite(in, pOpData)                               \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xq, &pOpData->xq);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yq, &pOpData->yq);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.q, &pOpData->q);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.a, &pOpData->a);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.b, &pOpData->b);                      \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in parameters for the Point Verify operation */

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      return the size in bytes of biggest number in CpaCyEcPointMultiplyOpData
 *
 * @description
 *      return the size of the biggest number in
 *      CpaCyEcPointMultiplyOpData.
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcPointMultiplyOpData structure
 *
 * @retval max  the size in bytes of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEc_PointMultiplyOpDataSizeGetMax(const CpaCyEcPointMultiplyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->h)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->q)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->a)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->b)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);

    return max;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      return the size in bytes of biggest number in CpaCyEcPointVerifyOpData
 *
 * @description
 *      return the size of the biggest number in CpaCyEcPointVerifyOpData.
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcPointVerifyOpData structure
 *
 * @retval max  the size of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEc_PointVerifyOpDataSizeGetMax(const CpaCyEcPointVerifyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xq)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yq)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->q)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->a)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->b)), max);

    return max;
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      EC Point Multiply function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEc_PointMultiplyBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                   const CpaCyEcPointMultiplyOpData *pOpData,
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

    /* Check that q is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->q));

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      EC Point Multiply synchronous function
 ***************************************************************************/
STATIC CpaStatus
LacEc_PointMultiplySyn(const CpaInstanceHandle instanceHandle,
                       const CpaCyEcPointMultiplyOpData *pOpData,
                       CpaBoolean *pMultiplyStatus,
                       CpaFlatBuffer *pXk,
                       CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcPointMultiply(instanceHandle,
                                      LacSync_GenDualFlatBufVerifyCb,
                                      pSyncCallbackData,
                                      pOpData,
                                      pMultiplyStatus,
                                      pXk,
                                      pYk);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
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
            LAC_EC_STAT_INC(numEcPointMultiplyCompletedError, pCryptoService);
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
 * @ingroup Lac_Ec
 *      EC Point Multiply internal callback
 ***************************************************************************/
STATIC void LacEc_PointMultiplyCallback(CpaStatus status,
                                        CpaBoolean multiplyStatus,
                                        CpaInstanceHandle instanceHandle,
                                        lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcPointMultiplyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcPointMultiplyOpData *pOpData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcPointMultiplyCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcPointMultiplyOpData *)pCbData->pClientOpData;
    pXk = pCbData->pOutputData1;
    pYk = pCbData->pOutputData2;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pXk);
    LAC_ASSERT_NOT_NULL(pYk);

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyCompleted, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyCompletedError, pCryptoService);
    }

    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_EC_STAT_INC(numEcPointMultiplyCompletedOutputInvalid,
                        pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pXk, pYk);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      EC Point Verify function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEc_PointVerifyBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                 const CpaCyEcPointVerifyOpData *pOpData,
                                 const CpaBoolean *pVerifyStatus)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pVerifyStatus);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->a.pData);
    LAC_CHECK_SIZE(&(pOpData->a), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->b.pData);
    LAC_CHECK_SIZE(&(pOpData->b), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->q.pData);
    LAC_CHECK_SIZE(&(pOpData->q), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xq.pData);
    LAC_CHECK_SIZE(&(pOpData->xq), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yq.pData);
    LAC_CHECK_SIZE(&(pOpData->yq), CHECK_NONE, 0);

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pOpData->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pOpData->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that q is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->q));

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      EC Point Verify synchronous function
 ***************************************************************************/
STATIC CpaStatus LacEc_PointVerifySyn(const CpaInstanceHandle instanceHandle,
                                      const CpaCyEcPointVerifyOpData *pOpData,
                                      CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcPointVerify(instanceHandle,
                                    LacSync_GenVerifyCb,
                                    pSyncCallbackData,
                                    pOpData,
                                    pVerifyStatus);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointVerifyRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pVerifyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_EC_STAT_INC(numEcPointVerifyCompletedErrors, pCryptoService);
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
 * @ingroup Lac_Ec
 *      EC Point Verify internal callback
 ***************************************************************************/
STATIC void LacEc_PointVerifyCallback(CpaStatus status,
                                      CpaBoolean verifyStatus,
                                      CpaInstanceHandle instanceHandle,
                                      lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcPointVerifyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcPointVerifyOpData *pOpData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcPointVerifyCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcPointVerifyOpData *)pCbData->pClientOpData;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointVerifyCompleted, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointVerifyCompletedErrors, pCryptoService);
    }

    if ((CPA_FALSE == verifyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_EC_STAT_INC(numEcPointVerifyCompletedOutputInvalid, pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, verifyStatus);
}

/**
 ***************************************************************************
 * @ingroup LacEc
 * Detect P256 or P384 and get optimised MMP function id
 ***************************************************************************/
STATIC CpaBoolean
LacEc_GetOptFunctionId(const CpaCyEcPointMultiplyOpData *pOpData,
                       Cpa32U *dataOperationSizeBytes,
                       Cpa32U *function)
{
    int i = 0;

    OptCurveParams curves[] = {
        /* P256 */
        {.dataOperationSizeBytes = LAC_BITS_TO_BYTES(LAC_256_BITS),
         .function_point = PKE_EC_POINT_MULTIPLICATION_P256,
         .p = nist_p256_p,
         .h = nist_p256_h,
         .a = nist_p256_a,
         .b = nist_p256_b},

        /* P384 */
        {.dataOperationSizeBytes = LAC_BITS_TO_BYTES(LAC_384_BITS),
         .function_point = PKE_EC_POINT_MULTIPLICATION_P384,
         .p = nist_p384_p,
         .h = nist_p384_h,
         .a = nist_p384_a,
         .b = nist_p384_b}};

    /* Loop through each curve returning when found and setting
     * dataOperationSizeBytes and function id */
    for (i = 0; i < ARRAY_SIZE(curves); i++)
    {
        CpaBoolean res = CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType;

        /* if the curve has not the prime representation continue searching */
        if (!res)
            continue;

        res = (NULL == pOpData->h.pData) ||
              LacPke_CompareFlatAndPtr(
                  &(pOpData->h), curves[i].h, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            &(pOpData->q), curves[i].p, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            &(pOpData->a), curves[i].a, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            &(pOpData->b), curves[i].b, curves[i].dataOperationSizeBytes);

        if (res == CPA_TRUE)
        {
            *dataOperationSizeBytes = curves[i].dataOperationSizeBytes;
            *function = curves[i].function_point;
            return CPA_TRUE;
        }
    }

    return CPA_FALSE; /* not found any optimised curve */
}

/**
 ***************************************************************************
 * @ingroup LacEc
 * Fill MMP struct for optimised P256 and P384 Point Multiply
 ***************************************************************************/
STATIC CpaStatus
LacEc_FillOptMMPStructs(icp_qat_fw_mmp_input_param_t *in,
                        Cpa32U *inSizes,
                        CpaBoolean *inAlloc,
                        icp_qat_fw_mmp_output_param_t *out,
                        Cpa32U *outSizes,
                        CpaBoolean *outAlloc,
                        Cpa32U function,
                        Cpa32U size,
                        const CpaCyEcPointMultiplyOpData *pOpData,
                        CpaFlatBuffer *pXk,
                        CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* All input and output memory is externally allocated */
    const CpaBoolean externallyAllocated = CPA_FALSE;

    /* Populate input and output buffers for optimised MMP functions */
    switch (function)
    {
        case PKE_EC_POINT_MULTIPLICATION_P256:
            LAC_EC_SET_LIST_PARAMS(
                inSizes, LAC_POINT_MULTIPLY_P256P384_NUM_IN_ARGS, size);
            LAC_EC_SET_LIST_PARAMS(inAlloc,
                                   LAC_POINT_MULTIPLY_P256P384_NUM_IN_ARGS,
                                   externallyAllocated);
            LAC_EC_SET_LIST_PARAMS(
                outSizes, LAC_POINT_MULTIPLY_P256P384_NUM_OUT_ARGS, size);
            LAC_EC_SET_LIST_PARAMS(outAlloc,
                                   LAC_POINT_MULTIPLY_P256P384_NUM_OUT_ARGS,
                                   externallyAllocated);
            LacEcP256P384PointMultiplyWrite(
                in->mmp_ec_point_multiplication_p256,
                out->mmp_ec_point_multiplication_p256,
                pOpData,
                pXk,
                pYk);
            break;

        case PKE_EC_POINT_MULTIPLICATION_P384:
            LAC_EC_SET_LIST_PARAMS(
                inSizes, LAC_POINT_MULTIPLY_P256P384_NUM_IN_ARGS, size);
            LAC_EC_SET_LIST_PARAMS(inAlloc,
                                   LAC_POINT_MULTIPLY_P256P384_NUM_IN_ARGS,
                                   externallyAllocated);
            LAC_EC_SET_LIST_PARAMS(
                outSizes, LAC_POINT_MULTIPLY_P256P384_NUM_OUT_ARGS, size);
            LAC_EC_SET_LIST_PARAMS(outAlloc,
                                   LAC_POINT_MULTIPLY_P256P384_NUM_OUT_ARGS,
                                   externallyAllocated);
            LacEcP256P384PointMultiplyWrite(
                in->mmp_ec_point_multiplication_p384,
                out->mmp_ec_point_multiplication_p384,
                pOpData,
                pXk,
                pYk);
            break;

        default:
            status = CPA_STATUS_INVALID_PARAM;
            break;
    }

    return status;
}

CpaStatus LacEc_OptimisedPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcPointMultiplyOpData *pOpData,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_UNSUPPORTED;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaBoolean optCurve = CPA_FALSE;
    Cpa32U functionID = 0;
    Cpa32U dataOperationSize = 0;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;


    optCurve = LacEc_GetOptFunctionId(pOpData, &dataOperationSize, &functionID);
    if (optCurve == CPA_FALSE)
        /* The optimised path is not supported for the curve */
        return CPA_STATUS_UNSUPPORTED;

    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    lac_pke_op_cb_data_t cbData = {0};

    /* Holding the calculated size of the input/output parameters */
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

    /* Zero the output buffers */
    osalMemSet(pXk->pData, 0, pXk->dataLenInBytes);
    osalMemSet(pYk->pData, 0, pYk->dataLenInBytes);

    /* populate callback data */
    cbData.pClientCb = pCb;
    cbData.pCallbackTag = pCallbackTag;
    cbData.pClientOpData = pOpData;
    cbData.pOpaqueData = NULL;
    cbData.pOutputData1 = pXk;
    cbData.pOutputData2 = pYk;

    status = LacEc_FillOptMMPStructs(&in,
                                     inArgSizeList,
                                     internalMemInList,
                                     &out,
                                     outArgSizeList,
                                     internalMemOutList,
                                     functionID,
                                     dataOperationSize,
                                     pOpData,
                                     pXk,
                                     pYk);

    /* Send pke request */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionID,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEc_PointMultiplyCallback,
                                          &cbData,
                                          instanceHandle);
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequests, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcPointMultiply(const CpaInstanceHandle instanceHandle_in,
                               const CpaCyEcPointMultiplyCbFunc pCb,
                               void *pCallbackTag,
                               const CpaCyEcPointMultiplyOpData *pOpData,
                               CpaBoolean *pMultiplyStatus,
                               CpaFlatBuffer *pXk,
                               CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa32U bit_pos_k = 0, bit_pos_h = 0, bit_pos_q = 0;
    Cpa32U temp = 0;
    Cpa32U maxModLen = 0;
    CpaBoolean isZero = CPA_FALSE;
#endif
    sal_crypto_service_t *pCryptoService = NULL;

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
    /* ensure LAC is running - return error if not */
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
        status = LacEc_PointMultiplySyn(
            instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);
        LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                 "%d, 0x%lx, 0x%lx)\n",
                 (LAC_ARCH_UINT)instanceHandle,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 *pMultiplyStatus,
                 (LAC_ARCH_UINT)pXk,
                 (LAC_ARCH_UINT)pYk);
        return status;
#else
        /* Call synchronous mode function */
        return LacEc_PointMultiplySyn(
            instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic NULL Param Checking  */
    status = LacEc_PointMultiplyBasicParamCheck(
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
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus isSupported = CPA_STATUS_SUCCESS;

        isSupported = LacEc_OptimisedPointMultiply(
            instanceHandle, pCb, pCallbackTag, pOpData, pXk, pYk);

        /* If LacEc_OptimisedPointMultiply returns CPA_STATUS_UNSUPPORTED,
         * this means that the optimised path is not supported for the curve.
         * Continue with the unoptimised in that case.
         */

        if (CPA_STATUS_UNSUPPORTED != isSupported)
            return isSupported;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(LacEc_PointMultiplyOpDataSizeGetMax(pOpData),
                                &dataOperationSizeBytes);
    }

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
            /* Check if it is a NIST curve (if not, then  invalid param) */
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
            /*Check if it is a NIST curve (if not, invalid param) */
            /* Also checks that deg xG and yG are less than deg q */
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
        /* for h>1 and k>1, else if h=1 or k=1 check is already done  */
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
                           code won't get this far)*/
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
                /* In GF2 9QW and 4QW special cases h has already been
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
        icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
        lac_pke_op_cb_data_t cbData = {0};

        /* Holding the calculated size of the input/output parameters */
        Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
        Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

        CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
        CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

        Cpa32U functionID = 0;

        /* Zero the output buffers */
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
        LAC_EC_SET_LIST_PARAMS(inArgSizeList,
                               LAC_EC_POINT_MULTIPLY_NUM_IN_ARGS,
                               dataOperationSizeBytes);
        LAC_EC_SET_LIST_PARAMS(outArgSizeList,
                               LAC_EC_POINT_MULTIPLY_NUM_OUT_ARGS,
                               dataOperationSizeBytes);

        /* Set all input and output memory to externally allocated */
        LAC_EC_SET_LIST_PARAMS(
            internalMemInList, LAC_EC_POINT_MULTIPLY_NUM_IN_ARGS, CPA_FALSE);
        LAC_EC_SET_LIST_PARAMS(
            internalMemOutList, LAC_EC_POINT_MULTIPLY_NUM_OUT_ARGS, CPA_FALSE);

        /* Populate input and output buffers for MMP and set function ID */

        /* Note datalenInBytes of input flatbuffers can be greater than
           dataOperationSizeBytes */
        /* CreateRequest() allows for this
                    - pke buffer will offset into client buffer */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcPointMultiplyOpDataWrite(
                        in.maths_point_multiplication_gfp_l256,
                        out.maths_point_multiplication_gfp_l256,
                        pOpData,
                        pXk,
                        pYk);
                    functionID = MATHS_POINT_MULTIPLICATION_GFP_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcPointMultiplyOpDataWrite(
                        in.maths_point_multiplication_gfp_l512,
                        out.maths_point_multiplication_gfp_l512,
                        pOpData,
                        pXk,
                        pYk);
                    functionID = MATHS_POINT_MULTIPLICATION_GFP_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                {
                    Cpa32U index = 0;
                    LacEcPointMultiplyOpDataWrite(
                        in.maths_point_multiplication_gfp_521,
                        out.maths_point_multiplication_gfp_521,
                        pOpData,
                        pXk,
                        pYk);
                    functionID = MATHS_POINT_MULTIPLICATION_GFP_521;
                    /* cofactor size is 1 qw */
                    index = LAC_IDX_OF(
                        icp_qat_fw_maths_point_multiplication_gfp_521_input_t,
                        h);
                    LAC_ASSERT(LAC_MAX_MMP_INPUT_PARAMS > index,
                               "invalid cofactor index");
                    inArgSizeList[index] = LAC_QUAD_WORD_IN_BYTES;
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
                    LacEcPointMultiplyOpDataWrite(
                        in.maths_point_multiplication_gf2_l256,
                        out.maths_point_multiplication_gf2_l256,
                        pOpData,
                        pXk,
                        pYk);
                    functionID = MATHS_POINT_MULTIPLICATION_GF2_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcPointMultiplyOpDataWrite(
                        in.maths_point_multiplication_gf2_l512,
                        out.maths_point_multiplication_gf2_l512,
                        pOpData,
                        pXk,
                        pYk);
                    functionID = MATHS_POINT_MULTIPLICATION_GF2_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                {
                    Cpa32U index = 0;
                    LacEcPointMultiplyOpDataWrite(
                        in.maths_point_multiplication_gf2_571,
                        out.maths_point_multiplication_gf2_571,
                        pOpData,
                        pXk,
                        pYk);
                    functionID = MATHS_POINT_MULTIPLICATION_GF2_571;
                    /* cofactor size is 1 qw */
                    index = LAC_IDX_OF(
                        icp_qat_fw_maths_point_multiplication_gf2_571_input_t,
                        h);
                    LAC_ASSERT(LAC_MAX_MMP_INPUT_PARAMS > index,
                               "invalid cofactor index");
                    inArgSizeList[index] = LAC_QUAD_WORD_IN_BYTES;
                    break;
                }
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            /* send a PKE request to the QAT */
            status = LacPke_SendSingleRequest(functionID,
                                              inArgSizeList,
                                              outArgSizeList,
                                              &in,
                                              &out,
                                              internalMemInList,
                                              internalMemOutList,
                                              LacEc_PointMultiplyCallback,
                                              &cbData,
                                              instanceHandle);
        }
    }
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequests, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcPointVerify(const CpaInstanceHandle instanceHandle_in,
                             const CpaCyEcPointVerifyCbFunc pCb,
                             void *pCallbackTag,
                             const CpaCyEcPointVerifyOpData *pOpData,
                             CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa32U bit_pos_q = 0;
    Cpa32U temp = 0;
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
        LAC_CHECK_NULL_PARAM(pVerifyStatus);
#endif
        status = LacEc_PointVerifySyn(instanceHandle, pOpData, pVerifyStatus);
        LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, "
                 "0x%lx, 0x%lx[%d])\n",
                 (LAC_ARCH_UINT)instanceHandle,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 (LAC_ARCH_UINT)pVerifyStatus,
                 *pVerifyStatus);
        return status;
#else
        /* Call synchronous mode function */
        return LacEc_PointVerifySyn(instanceHandle, pOpData, pVerifyStatus);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic NULL Param Checking  */
    status = LacEc_PointVerifyBasicParamCheck(
        instanceHandle, pOpData, pVerifyStatus);

    if (CPA_STATUS_SUCCESS == status)
    {
#endif
        /* Determine size */
        status = LacEc_GetRange(LacEc_PointVerifyOpDataSizeGetMax(pOpData),
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
                                   NULL);
        }
    }
#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) &&
        (LAC_EC_SIZE_QW9_IN_BYTES == dataOperationSizeBytes))
    {
        /* 9QW checks */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Check if it is a NIST curve (if not, then invalid param) */
            /* Also checks that xq and yq are less than 2^521 */
            status = LacEc_CheckCurve9QWGFP(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            NULL,
                                            NULL,
                                            &(pOpData->xq),
                                            &(pOpData->yq));
        }
        else
        {
            /*Check if it is a NIST curve (if not, then invalid param) */
            /* Also checks that deg xq and yq are less than deg q */
            status = LacEc_CheckCurve9QWGF2(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            NULL,
                                            NULL,
                                            &(pOpData->xq),
                                            &(pOpData->yq));
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
        icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
        lac_pke_op_cb_data_t cbData = {0};
        Cpa32U functionID = 0;

        /* Holding the calculated size of the input parameters */
        Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};

        CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};

        /* Set the size for all parameters to be padded to */
        LAC_EC_SET_LIST_PARAMS(inArgSizeList,
                               LAC_EC_POINT_VERIFY_NUM_IN_ARGS,
                               dataOperationSizeBytes);
        /* Set input memory to externally allocated */
        LAC_EC_SET_LIST_PARAMS(
            internalMemInList, LAC_EC_POINT_VERIFY_NUM_IN_ARGS, CPA_FALSE);

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = NULL;
        cbData.pOutputData2 = NULL;

        /* Populate input buffers and output buffer and set function ID */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcPointVerifyOpDataWrite(in.maths_point_verify_gfp_l256,
                                                pOpData);
                    functionID = MATHS_POINT_VERIFY_GFP_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcPointVerifyOpDataWrite(in.maths_point_verify_gfp_l512,
                                                pOpData);
                    functionID = MATHS_POINT_VERIFY_GFP_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcPointVerifyOpDataWrite(in.maths_point_verify_gfp_521,
                                                pOpData);
                    functionID = MATHS_POINT_VERIFY_GFP_521;
                    break;
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
                    LacEcPointVerifyOpDataWrite(in.maths_point_verify_gf2_l256,
                                                pOpData);
                    functionID = MATHS_POINT_VERIFY_GF2_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcPointVerifyOpDataWrite(in.maths_point_verify_gf2_l512,
                                                pOpData);
                    functionID = MATHS_POINT_VERIFY_GF2_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcPointVerifyOpDataWrite(in.maths_point_verify_gf2_571,
                                                pOpData);
                    functionID = MATHS_POINT_VERIFY_GF2_571;
                    break;
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* send a PKE request to the QAT */
            status = LacPke_SendSingleRequest(functionID,
                                              inArgSizeList,
                                              NULL,
                                              &in,
                                              &out,
                                              internalMemInList,
                                              NULL,
                                              LacEc_PointVerifyCallback,
                                              &cbData,
                                              instanceHandle);
        }
    }

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointVerifyRequests, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointVerifyRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
CpaStatus cpaCyEcQueryStats64(const CpaInstanceHandle instanceHandle_in,
                              CpaCyEcStats64 *pEcStats)
{
    sal_crypto_service_t *pCryptoService;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pEcStats);
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

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pEcStats);

    /* get stats into user supplied stats structure */
    LAC_EC_STATS_GET(*pEcStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}
