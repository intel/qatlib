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

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

typedef struct _OptCurveParams
{
    Cpa32U dataOperationSizeBytes;
    Cpa32U function_point;
    Cpa32U function_generator;
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

typedef const CpaCyEcCurveParametersWeierstrass *LacEc_WSCurvePtr;
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

typedef struct _PointMultiplyOpData
{
    const CpaFlatBuffer *xg;
    const CpaFlatBuffer *yg;
    const CpaFlatBuffer *h;
    const CpaFlatBuffer *q;
    const CpaFlatBuffer *a;
    const CpaFlatBuffer *b;
    const CpaFlatBuffer *k;
    const CpaFlatBuffer *pXk;
    const CpaFlatBuffer *pYk;
} PointMultiplyOpData;

#define LacEcPointMultiplyOpDataWrite(in, out, data)                           \
    do                                                                         \
    {                                                                          \
                                                                               \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xg, (data)->xg);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yg, (data)->yg);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.h, (data)->h);                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.q, (data)->q);                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.a, (data)->a);                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.b, (data)->b);                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, (data)->k);                        \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.xk, (data)->pXk);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.yk, (data)->pYk);                    \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in/out parameters for the Point Multiply operation*/

#define LacEcGeneratorPointMultiplyWrite(in, out, data)                        \
    do                                                                         \
    {                                                                          \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, (data)->k);                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.xr, (data)->pXk);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.yr, (data)->pYk);                    \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in/out parameters for the Generator
 * Point Multiply operation*/

#define LacEcP256P384PointMultiplyWrite(in, out, data)                         \
    do                                                                         \
    {                                                                          \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xp, (data)->xg);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yp, (data)->yg);                      \
        LacEcGeneratorPointMultiplyWrite(in, out, data)                        \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in/out parameters for the Generic P256 and P384
 * Point Multiply operation*/

#define LacEcPointVerifyFillStruct(in, px, py, pp, pa, pb)                     \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xq, px);                              \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yq, py);                              \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.q, pp);                               \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.a, pa);                               \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.b, pb);                               \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in parameters for the Point Verify operation */

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/
STATIC CpaStatus
LacEc_CommonPointVerify(const CpaInstanceHandle instanceHandle_in,
                        const void *pCb,
                        void *pCallbackTag,
                        const CpaCyEcPointVerifyOpData *pOpData_Legacy,
                        const CpaCyEcGenericPointVerifyOpData *pOpData_Generic,
                        CpaBoolean *pVerifyStatus);
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
    return LacPke_GetMaxLnOfNBuffers(7,
                                     &(pOpData->xg),
                                     &(pOpData->yg),
                                     &(pOpData->h),
                                     &(pOpData->q),
                                     &(pOpData->a),
                                     &(pOpData->b),
                                     &(pOpData->k));
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
Cpa32U LacEc_PointMultiplyWeierstrassSizeGetMax(
    LacEc_WSCurvePtr pCurveWeierstrass)
{
    return LacPke_GetMaxLnOfNBuffers(4,
                                     &(pCurveWeierstrass->h),
                                     &(pCurveWeierstrass->p),
                                     &(pCurveWeierstrass->a),
                                     &(pCurveWeierstrass->b));
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
Cpa32U LacEc_GenericPointMultiplyOperationSizeGetMax(
    const CpaCyEcGenericPointMultiplyOpData *pOpData)
{

    return LAC_MAX(LacEc_PointMultiplyWeierstrassSizeGetMax(
                       &(pOpData->pCurve->parameters.weierstrassParameters)),
                   LacPke_GetMaxLnOfNBuffers(
                       3, &(pOpData->xP), &(pOpData->yP), &(pOpData->k)));
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

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
CpaStatus LacEc_BasicParamCheckWeierstrass(const CpaCyEcCurve *pCurve)
{
    LAC_CHECK_NULL_PARAM(pCurve);

    const CpaCyEcCurveType curveType = pCurve->curveType;
    /* Valid curve types are:
     * CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_PRIME = 1
     * CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_BINARY = 2
     * CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_KOBLITZ_BINARY = 3
     * They are all covered by mask of 3 */
    const Cpa32U validTypesMask = 3U;
    if ((curveType & validTypesMask) != curveType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_CY_EC_FIELD_TYPE_PRIME !=
            pCurve->parameters.weierstrassParameters.fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY !=
            pCurve->parameters.weierstrassParameters.fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pCurve->parameters.weierstrassParameters.p), CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&(pCurve->parameters.weierstrassParameters.p));
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pCurve->parameters.weierstrassParameters.a), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pCurve->parameters.weierstrassParameters.b), CHECK_NONE, 0);

    if (NULL == pCurve->parameters.weierstrassParameters.h.pData)
    {
        if (0 != pCurve->parameters.weierstrassParameters.h.dataLenInBytes)
        {
            LAC_INVALID_PARAM_LOG(
                "pCurve->parameters.weierstrassParameters.h.pData is NULL and "
                "pCurve->parameters.weierstrassParameters.h.dataLenInBytes "
                "!=0");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        LAC_CHECK_SIZE(
            &(pCurve->parameters.weierstrassParameters.h), CHECK_NONE, 0);
    }

    return CPA_STATUS_SUCCESS;
}
#endif

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
CpaStatus LacEc_GenericPointMultiplyBasicParamCheck(
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    const CpaBoolean *pMultiplyStatus,
    const CpaFlatBuffer *pOutX,
    const CpaFlatBuffer *pOutY)
{
    LAC_CHECK_NULL_PARAM(pOpData);

    LAC_CHECK_FLAT_BUFFER_PARAM(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pOpData->xP), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pOpData->yP), CHECK_NONE, 0);

    LAC_CHECK_NULL_PARAM(pMultiplyStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(pOutX, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pOutY, CHECK_NONE, 0);

    /* Currently we require Weierstrass curve - no other type is supported */
    return LacEc_BasicParamCheckWeierstrass(pOpData->pCurve);
}
#endif

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/

STATIC
void LacEcc_PointMultiplySynchronousCallback(void *pCallbackTag,
                                             CpaStatus status,
                                             void *pOpdata,
                                             CpaBoolean opResult,
                                             CpaFlatBuffer *pOutX,
                                             CpaFlatBuffer *pOutY)
{
    LacSync_GenVerifyWakeupSyncCaller(pCallbackTag, status, opResult);
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/

STATIC
CpaStatus LacEcc_CommonPathPointMultiplyOperation(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcPointMultiplyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pOutX,
    CpaFlatBuffer *pOutY);

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/

STATIC
CpaStatus LacEc_CommonPathPointMultiplySynchronous(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pOutX,
    CpaFlatBuffer *pOutY)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacEcc_CommonPathPointMultiplyOperation(
            instanceHandle,
            LacEcc_PointMultiplySynchronousCallback,
            pSyncCallbackData,
            pOpData_Legacy,
            pOpData,
            pMultiplyStatus,
            pOutX,
            pOutY);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacSync_WaitForCallback(pSyncCallbackData,
                                         LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                         &status,
                                         pMultiplyStatus);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_EC_STAT_INC(numEcPointMultiplyCompletedError, pCryptoService);
        }
    }
    else
    {
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
    void *pOpData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcPointMultiplyCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)pCbData->pClientOpData;
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
STATIC CpaStatus LacEc_PointVerifyBasicParamCheckWeierstrass(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcGenericPointVerifyOpData *pOpData,
    const CpaBoolean *pVerifyStatus)
{

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pOpData->pCurve);
    LAC_CHECK_NULL_PARAM(pVerifyStatus);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LacEc_WSCurvePtr pWeirstrassCurve =
        &(pOpData->pCurve->parameters.weierstrassParameters);

    LAC_CHECK_FLAT_BUFFER_PARAM(&(pWeirstrassCurve->a), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pWeirstrassCurve->b), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pWeirstrassCurve->p), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pOpData->xP), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pOpData->yP), CHECK_NONE, 0);

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pWeirstrassCurve->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pWeirstrassCurve->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that p is odd */
    LAC_CHECK_ODD_PARAM(&(pWeirstrassCurve->p));

    return CPA_STATUS_SUCCESS;
}

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
STATIC CpaStatus LacEc_CommonPointVerifySyn(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointVerifyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointVerifyOpData *pOpData_Generic,
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
        status = LacEc_CommonPointVerify(instanceHandle,
                                         LacSync_GenVerifyCb,
                                         pSyncCallbackData,
                                         pOpData_Legacy,
                                         pOpData_Generic,
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
LacEc_GetSimpleOptFunctionId(const CpaCyEcPointMultiplyOpData *pOpData,
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

    PointMultiplyOpData data;

    data.xg = &pOpData->xg;
    data.yg = &pOpData->yg;
    data.h = &pOpData->h;
    data.q = &pOpData->q;
    data.a = &pOpData->a;
    data.b = &pOpData->b;
    data.k = &pOpData->k;
    data.pXk = pXk;
    data.pYk = pYk;

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
                &data);
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
                &data);
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


    optCurve = LacEc_GetSimpleOptFunctionId(pOpData, &dataOperationSize, &functionID);
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
CpaStatus cpaCyEcPointVerify(const CpaInstanceHandle instanceHandle_in,
                             const CpaCyEcPointVerifyCbFunc pCb,
                             void *pCallbackTag,
                             const CpaCyEcPointVerifyOpData *pOpData,
                             CpaBoolean *pVerifyStatus)
{
    return LacEc_CommonPointVerify(
        instanceHandle_in, pCb, pCallbackTag, pOpData, NULL, pVerifyStatus);
}

/**
 ***************************************************************************
 * @ingroup LacEc
 * Detect P256 or P384 and get optimised MMP function id
 ***************************************************************************/
STATIC
CpaBoolean LacEc_GetOptFunctionId(const sal_crypto_service_t *pService,
                                  CpaCyEcFieldType primeRepresentation,
                                  const CpaFlatBuffer *pP,
                                  const CpaFlatBuffer *pH,
                                  const CpaFlatBuffer *pA,
                                  const CpaFlatBuffer *pB,
                                  Cpa32U *dataOperationSizeBytes,
                                  Cpa32U *function,
                                  CpaBoolean generator)
{
    *function = 0;

    if (!pService->generic_service_info.isGen4)
        return CPA_FALSE;

    int i = 0;

    OptCurveParams curves[] = {
        /* P256 */
        { .dataOperationSizeBytes = LAC_BITS_TO_BYTES(LAC_256_BITS),
          .function_point = PKE_EC_POINT_MULTIPLICATION_P256,
          .function_generator = PKE_EC_GENERATOR_MULTIPLICATION_P256,
          .p = nist_p256_p,
          .h = nist_p256_h,
          .a = nist_p256_a,
          .b = nist_p256_b },

        /* P384 */
        { .dataOperationSizeBytes = LAC_BITS_TO_BYTES(LAC_384_BITS),
          .function_point = PKE_EC_POINT_MULTIPLICATION_P384,
          .function_generator = PKE_EC_GENERATOR_MULTIPLICATION_P384,
          .p = nist_p384_p,
          .h = nist_p384_h,
          .a = nist_p384_a,
          .b = nist_p384_b }
    };

    /* Loop through each curve returning when found and setting
     * dataOperationSizeBytes and function id */
    for (i = 0; i < ARRAY_SIZE(curves); i++)
    {
        CpaBoolean res = CPA_CY_EC_FIELD_TYPE_PRIME == primeRepresentation;

        /* if the curve has not the prime representation continue searching
         */
        if (!res)
            continue;

        res = (NULL == pH->pData) || LacPke_CompareFlatAndPtr(
            pH, curves[i].h, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            pP, curves[i].p, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            pA, curves[i].a, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            pB, curves[i].b, curves[i].dataOperationSizeBytes);

        if (res == CPA_TRUE)
        {
            *dataOperationSizeBytes = curves[i].dataOperationSizeBytes;
            if (generator)
            {
                *function = curves[i].function_generator;
            }
            else
            {
                *function = curves[i].function_point;
            }
            return CPA_TRUE;
        }
    }

    return CPA_FALSE; /* not found any optimised curve */
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
CpaStatus LacEcc_PointMultiplyFillMMPStructsOpDataWrite(
    icp_qat_fw_mmp_input_param_t *in,
    Cpa32U *inSizes,
    CpaBoolean *inAlloc,
    icp_qat_fw_mmp_output_param_t *out,
    Cpa32U *outSizes,
    CpaBoolean *outAlloc,
    Cpa32U *function,
    Cpa32U size,
    Cpa32U representation,
    const PointMultiplyOpData *data);

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
CpaStatus LacEcc_CommonPathPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcPointMultiplyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pOutX,
    CpaFlatBuffer *pOutY);

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcPointMultiply(const CpaInstanceHandle instanceHandle,
                               const CpaCyEcPointMultiplyCbFunc pCb,
                               void *pCallbackTag,
                               const CpaCyEcPointMultiplyOpData *pOpData,
                               CpaBoolean *pMultiplyStatus,
                               CpaFlatBuffer *pXk,
                               CpaFlatBuffer *pYk)
{
    LAC_CHECK_NULL_PARAM(pOpData);

    return LacEcc_CommonPathPointMultiply(instanceHandle,
                                          pCb,
                                          pCallbackTag,
                                          pOpData,
                                          NULL,
                                          pMultiplyStatus,
                                          pXk,
                                          pYk);
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
STATIC
CpaStatus LacEcc_CommonPathUnoptimised(
    const CpaCyEcPointMultiplyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaCyEcFieldType primeRepresentation,
    const CpaFlatBuffer *pP,
    const CpaFlatBuffer *pA,
    const CpaFlatBuffer *pB,
    const CpaFlatBuffer *pH,
    const CpaFlatBuffer *pK,
    const CpaFlatBuffer *pXp,
    const CpaFlatBuffer *pYp,
    Cpa32U *dataOperationSizeBytes)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxDataSize = 0u;
    if (pOpData_Legacy)
    {
        maxDataSize = LacEc_PointMultiplyOpDataSizeGetMax(pOpData_Legacy);
    }
    else
    {
        maxDataSize = LacEc_GenericPointMultiplyOperationSizeGetMax(pOpData);
    }
    status = LacEc_GetRange(maxDataSize, dataOperationSizeBytes);

    LAC_CHECK_STATUS(status);
    if ((LAC_EC_SIZE_QW4_IN_BYTES == *dataOperationSizeBytes) &&
        (CPA_CY_EC_FIELD_TYPE_BINARY == primeRepresentation))
    {
        LacEc_CheckCurve4QWGF2(dataOperationSizeBytes, pP, pA, pB, NULL, pH);
    }

#ifdef ICP_PARAM_CHECK
    if (LAC_EC_SIZE_QW9_IN_BYTES == *dataOperationSizeBytes)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == primeRepresentation)
        {
            status = LacEc_CheckCurve9QWGFP(pP, pA, pB, NULL, pH, pXp, pYp);
        }
        else
        {
            status = LacEc_CheckCurve9QWGF2(pP, pA, pB, NULL, pH, pXp, pYp);
        }
    }

    LAC_CHECK_STATUS(status);
    /* Check size of h*k result                                   */
    /* log2(h*k) = log2(h) +log2(k)                               */
    /* highest bit position of (h*k) = floor[log2(h*k)]           */
    /* max(floor[log2(h*k)]) = floor[log2(h)] +floor[log2(k)] + 1 */
    /* for h>1 and k>1, else if h=1 or k=1 check is already done  */
    /* by earlier buffer checks                                   */
    Cpa32U bit_pos_k = 0u;
    Cpa32U bit_pos_h = 0u;
    Cpa32U temp = 0u;
    CpaBoolean isZero = CPA_FALSE;
    LacPke_GetBitPos(pK, &bit_pos_k, &temp, &isZero);
    if (NULL == pH->pData)
    {
        bit_pos_h = 0u;
    }
    else
    {
        LacPke_GetBitPos(pH, &bit_pos_h, &temp, &isZero);
    }
    if ((bit_pos_h > 0u) && (bit_pos_k > 0u))
    {
        Cpa32U requiredBits = bit_pos_k + bit_pos_h + 1;
        if (CPA_CY_EC_FIELD_TYPE_PRIME == primeRepresentation)
        {
            /* In GFP case h*k should fit in dataOperationSizeBytes */
            Cpa32U bufferBits = LAC_BYTES_TO_BITS(*dataOperationSizeBytes) - 1;
            if (bufferBits < requiredBits)
            {
                if (LAC_EC_SIZE_QW4_IN_BYTES == *dataOperationSizeBytes)
                {
                    /* Use 8QW service instead */
                    *dataOperationSizeBytes = LAC_EC_SIZE_QW8_IN_BYTES;
                }
                else
                {
                    /* In 8QW case invalid param (similarly for 9QW but
                        code won't get this far)*/
                    LAC_INVALID_PARAM_LOG("log2(k)+log2(h) is NOT <512");
                    status = CPA_STATUS_INVALID_PARAM;
                }
            }
        }
        else
        {
            /* In GF2 9QW and 4QW special cases h has already been
                checked (and is known by MMP) and the size of k has already
                been checked in getRange function so just need to chec
                8QW case */
            Cpa32U bufferBits = LAC_BYTES_TO_BITS(LAC_EC_SIZE_QW9_IN_BYTES) - 1;
            if (bufferBits < requiredBits)
            {
                if (LAC_EC_SIZE_QW8_IN_BYTES == *dataOperationSizeBytes)
                /* For 8QW h*k should fit in 9QW */
                {
                    LAC_INVALID_PARAM_LOG("log2(k)+log2(h) is NOT <576");
                    status = CPA_STATUS_INVALID_PARAM;
                }
            }
        }
    }

    /* Ensure that h!=0 */
    /* This is invalid for all secure curves */
    /* pH=NULL is sent to PKE as h=0 which is understood by MMP program as
       h=1 as required - therefore need to eliminate invalid h=0 case here */
    LAC_CHECK_STATUS(status);
    if (NULL != pH->pData && (0 == LacPke_CompareZero(pH, 0)))
    {
        LAC_INVALID_PARAM_LOG("Cofactor == 0");
        status = CPA_STATUS_INVALID_PARAM;
    }

    LAC_CHECK_STATUS(status);
    /* Check that q>3 for GFP (i.e. highest bit position needs to be greater
        than 1) or that deg(q)>2 for GF2 (i.e. highest bit position needs to
        be greater than 2) */
    Cpa32U bit_pos_p = 0u;
    LacPke_GetBitPos(pP, &bit_pos_p, &temp, &isZero);
    if (((CPA_CY_EC_FIELD_TYPE_BINARY == primeRepresentation) &&
         (bit_pos_p < LAC_EC_MIN_MOD_BIT_POS_GF2)) ||
        ((CPA_CY_EC_FIELD_TYPE_PRIME == primeRepresentation) &&
         (bit_pos_p < LAC_EC_MIN_MOD_BIT_POS_GFP)))
    {
        LAC_INVALID_PARAM_LOG("q is too small");
        status = CPA_STATUS_INVALID_PARAM;
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
STATIC
CpaStatus LacEcc_CommonPathPointMultiplyOperation(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcPointMultiplyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pOutX,
    CpaFlatBuffer *pOutY)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    CpaCyEcFieldType primeRepresentation = CPA_CY_EC_FIELD_TYPE_PRIME;
    const CpaFlatBuffer *pP = NULL;
    const CpaFlatBuffer *pA = NULL;
    const CpaFlatBuffer *pB = NULL;
    const CpaFlatBuffer *pH = NULL;
    const CpaFlatBuffer *pK = NULL;
    const CpaFlatBuffer *pXp = NULL;
    const CpaFlatBuffer *pYp = NULL;
    CpaBoolean generator = CPA_FALSE;

    lac_pke_op_cb_data_t cbData = {0};

    if (pOpData_Legacy)
    {
#ifdef ICP_PARAM_CHECK
        /* Basic NULL Param Checking  */
        status = LacEc_PointMultiplyBasicParamCheck(
            instanceHandle, pOpData_Legacy, pMultiplyStatus, pOutX, pOutY);
        LAC_CHECK_STATUS(status);
#endif

        primeRepresentation = pOpData_Legacy->fieldType;
        pP = &pOpData_Legacy->q;
        pA = &pOpData_Legacy->a;
        pB = &pOpData_Legacy->b;
        pH = &pOpData_Legacy->h;
        pK = &pOpData_Legacy->k;
        pXp = &pOpData_Legacy->xg;
        pYp = &pOpData_Legacy->yg;
        cbData.pClientOpData = pOpData_Legacy;
    }
    else
    {
#ifdef ICP_PARAM_CHECK
        /* Basic NULL Param Checking  */
        status = LacEc_GenericPointMultiplyBasicParamCheck(
            pOpData, pMultiplyStatus, pOutX, pOutY);
        LAC_CHECK_STATUS(status);
#endif

        LacEc_WSCurvePtr cpWpCp =
            &pOpData->pCurve->parameters.weierstrassParameters;
        primeRepresentation = cpWpCp->fieldType;
        pP = &cpWpCp->p;
        pA = &cpWpCp->a;
        pB = &cpWpCp->b;
        pH = &cpWpCp->h;
        pK = &pOpData->k;
        pXp = &pOpData->xP;
        pYp = &pOpData->yP;
        generator = pOpData->generator;
        cbData.pClientOpData = pOpData;
    }

#ifdef ICP_PARAM_CHECK
    /* Check that output buffers are big enough */
    Cpa32U maxModLen = LacPke_GetMinBytes(pP);
    LAC_CHECK_SIZE(pOutX, CHECK_GREATER_EQUALS, maxModLen);
    LAC_CHECK_SIZE(pOutY, CHECK_GREATER_EQUALS, maxModLen);
#endif

    cbData.pCallbackTag = pCallbackTag;
    cbData.pOpaqueData = NULL;
    cbData.pOutputData1 = pOutX;
    cbData.pOutputData2 = pOutY;
    cbData.pClientCb = pCb;

    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    Cpa32U functionID = 0u;
    Cpa32U dataOperationSizeBytes = 0u;
    CpaBoolean optimisedSupported = CPA_FALSE;

    PointMultiplyOpData data = {.xg = pXp,
                                .yg = pYp,
                                .h = pH,
                                .q = pP,
                                .a = pA,
                                .b = pB,
                                .k = pK,
                                .pXk = pOutX,
                                .pYk = pOutY};

    optimisedSupported =
        LacEc_GetOptFunctionId((sal_crypto_service_t *)instanceHandle,
                               primeRepresentation,
                               pP,
                               pH,
                               pA,
                               pB,
                               &dataOperationSizeBytes,
                               &functionID,
                               generator);
    if (!optimisedSupported)
    {
        status = LacEcc_CommonPathUnoptimised(pOpData_Legacy,
                                              pOpData,
                                              primeRepresentation,
                                              pP,
                                              pA,
                                              pB,
                                              pH,
                                              pK,
                                              pXp,
                                              pYp,
                                              &dataOperationSizeBytes);
    }

    LAC_CHECK_STATUS(status);

    /* Zero the output buffers */
    osalMemSet(pOutX->pData, 0, pOutX->dataLenInBytes);
    osalMemSet(pOutY->pData, 0, pOutY->dataLenInBytes);

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
     * dataOperationSizeBytes. CreateRequest() allows for this - pke buffer
     * will offset into client buffer. */
    status =
        LacEcc_PointMultiplyFillMMPStructsOpDataWrite(&in,
                                                      inArgSizeList,
                                                      internalMemInList,
                                                      &out,
                                                      outArgSizeList,
                                                      internalMemOutList,
                                                      &functionID,
                                                      dataOperationSizeBytes,
                                                      primeRepresentation,
                                                      &data);
    LAC_CHECK_STATUS(status);

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
    return status;
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
CpaStatus LacEcc_PointMultiplyFillMMPStructsOpDataWrite(
    icp_qat_fw_mmp_input_param_t *in,
    Cpa32U *inSizes,
    CpaBoolean *inAlloc,
    icp_qat_fw_mmp_output_param_t *out,
    Cpa32U *outSizes,
    CpaBoolean *outAlloc,
    Cpa32U *function,
    Cpa32U size,
    Cpa32U representation,
    const PointMultiplyOpData *data)
{
    /* All input and output memory is externally allocated */
    const CpaBoolean externallyAllocated = CPA_FALSE;

    /* Populate input and output buffers for optimised MMP functions */
    switch (*function)
    {
        case PKE_EC_POINT_MULTIPLICATION_P256:
            LAC_EC_SET_LIST_PARAMS(inSizes, 3, size);
            LAC_EC_SET_LIST_PARAMS(inAlloc, 3, externallyAllocated);
            LAC_EC_SET_LIST_PARAMS(outSizes, 2, size);
            LAC_EC_SET_LIST_PARAMS(outAlloc, 2, externallyAllocated);
            LacEcP256P384PointMultiplyWrite(
                in->mmp_ec_point_multiplication_p256,
                out->mmp_ec_point_multiplication_p256,
                data);
            return CPA_STATUS_SUCCESS;
        case PKE_EC_GENERATOR_MULTIPLICATION_P256:
            LAC_EC_SET_LIST_PARAMS(inSizes, 1, size);
            LAC_EC_SET_LIST_PARAMS(inAlloc, 1, externallyAllocated);
            LAC_EC_SET_LIST_PARAMS(outSizes, 2, size);
            LAC_EC_SET_LIST_PARAMS(outAlloc, 2, externallyAllocated);
            LacEcGeneratorPointMultiplyWrite(
                in->mmp_ec_generator_multiplication_p256,
                out->mmp_ec_generator_multiplication_p256,
                data);
            return CPA_STATUS_SUCCESS;
        case PKE_EC_POINT_MULTIPLICATION_P384:
            LAC_EC_SET_LIST_PARAMS(inSizes, 3, size);
            LAC_EC_SET_LIST_PARAMS(inAlloc, 3, externallyAllocated);
            LAC_EC_SET_LIST_PARAMS(outSizes, 2, size);
            LAC_EC_SET_LIST_PARAMS(outAlloc, 2, externallyAllocated);
            LacEcP256P384PointMultiplyWrite(
                in->mmp_ec_point_multiplication_p384,
                out->mmp_ec_point_multiplication_p384,
                data);
            return CPA_STATUS_SUCCESS;
        case PKE_EC_GENERATOR_MULTIPLICATION_P384:
            LAC_EC_SET_LIST_PARAMS(inSizes, 1, size);
            LAC_EC_SET_LIST_PARAMS(inAlloc, 1, externallyAllocated);
            LAC_EC_SET_LIST_PARAMS(outSizes, 2, size);
            LAC_EC_SET_LIST_PARAMS(outAlloc, 2, externallyAllocated);
            LacEcGeneratorPointMultiplyWrite(
                in->mmp_ec_generator_multiplication_p384,
                out->mmp_ec_generator_multiplication_p384,
                data);
            return CPA_STATUS_SUCCESS;
    }

    LAC_ASSERT(0 == *function, "Here *functionID should be 0");

    /* Populate input and output buffers for MMP and set function ID */
    if (CPA_CY_EC_FIELD_TYPE_PRIME == representation)
    {
        switch (size)
        {
            case LAC_EC_SIZE_QW4_IN_BYTES:
                LacEcPointMultiplyOpDataWrite(
                    in->maths_point_multiplication_gfp_l256,
                    out->maths_point_multiplication_gfp_l256,
                    data);
                *function = MATHS_POINT_MULTIPLICATION_GFP_L256;
                return CPA_STATUS_SUCCESS;
            case LAC_EC_SIZE_QW8_IN_BYTES:
                LacEcPointMultiplyOpDataWrite(
                    in->maths_point_multiplication_gfp_l512,
                    out->maths_point_multiplication_gfp_l512,
                    data);
                *function = MATHS_POINT_MULTIPLICATION_GFP_L512;
                return CPA_STATUS_SUCCESS;
            case LAC_EC_SIZE_QW9_IN_BYTES:
            {
                Cpa32U index = LAC_IDX_OF(
                    icp_qat_fw_maths_point_multiplication_gfp_521_input_t, h);
                LacEcPointMultiplyOpDataWrite(
                    in->maths_point_multiplication_gfp_521,
                    out->maths_point_multiplication_gfp_521,
                    data);
                *function = MATHS_POINT_MULTIPLICATION_GFP_521;
                LAC_ASSERT(LAC_MAX_MMP_INPUT_PARAMS > index,
                           "invalid cofactor index");
                inSizes[index] = LAC_QUAD_WORD_IN_BYTES;
                return CPA_STATUS_SUCCESS;
            }
            default:
                return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        switch (size)
        {
            case LAC_EC_SIZE_QW4_IN_BYTES:
                LacEcPointMultiplyOpDataWrite(
                    in->maths_point_multiplication_gf2_l256,
                    out->maths_point_multiplication_gf2_l256,
                    data);
                *function = MATHS_POINT_MULTIPLICATION_GF2_L256;
                return CPA_STATUS_SUCCESS;
            case LAC_EC_SIZE_QW8_IN_BYTES:
                LacEcPointMultiplyOpDataWrite(
                    in->maths_point_multiplication_gf2_l512,
                    out->maths_point_multiplication_gf2_l512,
                    data);
                *function = MATHS_POINT_MULTIPLICATION_GF2_L512;
                return CPA_STATUS_SUCCESS;
            case LAC_EC_SIZE_QW9_IN_BYTES:
            {
                Cpa32U index = LAC_IDX_OF(
                    icp_qat_fw_maths_point_multiplication_gf2_571_input_t, h);
                LacEcPointMultiplyOpDataWrite(
                    in->maths_point_multiplication_gf2_571,
                    out->maths_point_multiplication_gf2_571,
                    data);
                *function = MATHS_POINT_MULTIPLICATION_GF2_571;
                LAC_ASSERT(LAC_MAX_MMP_INPUT_PARAMS > index,
                           "invalid cofactor index");
                inSizes[index] = LAC_QUAD_WORD_IN_BYTES;
                return CPA_STATUS_SUCCESS;
            }
            default:
                return CPA_STATUS_INVALID_PARAM;
        }
    }
    return CPA_STATUS_INVALID_PARAM;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      EC Point Verify for Weierstrass curves
 ***************************************************************************/
STATIC CpaStatus
LacEc_CommonPointVerify(const CpaInstanceHandle instanceHandle_in,
                        const void *pCb,
                        void *pCallbackTag,
                        const CpaCyEcPointVerifyOpData *pOpData_Legacy,
                        const CpaCyEcGenericPointVerifyOpData *pOpData_Generic,
                        CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    void *pOpData;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    const CpaFlatBuffer *pX;
    const CpaFlatBuffer *pY;
    const CpaFlatBuffer *pMod;
    const CpaFlatBuffer *pA;
    const CpaFlatBuffer *pB;
    const Cpa32U pCount = 5;
    CpaCyEcFieldType fieldType;
    CpaCyEcCurveParameters *pCurveParameters;
#ifdef ICP_PARAM_CHECK
    Cpa32U bit_pos_q = 0;
    Cpa32U temp = 0;
    CpaBoolean isZero = CPA_FALSE;
#endif

    if (pOpData_Legacy != NULL && pOpData_Generic == NULL)
    {
        /* legacy api parameters */
        pOpData = (void *)pOpData_Legacy;

        pX = &pOpData_Legacy->xq;
        pY = &pOpData_Legacy->yq;
        pMod = &pOpData_Legacy->q;
        pA = &pOpData_Legacy->a;
        pB = &pOpData_Legacy->b;
        fieldType = pOpData_Legacy->fieldType;
    }
    else if (pOpData_Legacy == NULL && pOpData_Generic != NULL)
    {
        /* generic api parameters */
        pOpData = (void *)pOpData_Generic;
        pCurveParameters = &pOpData_Generic->pCurve->parameters;

        pX = &pOpData_Generic->xP;
        pY = &pOpData_Generic->yP;
        pMod = &pCurveParameters->weierstrassParameters.p;
        pA = &pCurveParameters->weierstrassParameters.a;
        pB = &pCurveParameters->weierstrassParameters.b;
        fieldType = pCurveParameters->weierstrassParameters.fieldType;
    }
    else
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {

#ifdef ICP_PARAM_CHECK
        /* Check for valid pointers */
        LAC_CHECK_NULL_PARAM(pVerifyStatus);
#endif
        status = LacEc_CommonPointVerifySyn(
            instanceHandle, pOpData_Legacy, pOpData_Generic, pVerifyStatus);
#ifdef ICP_TRACE
        LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, "
                 "0x%lx[%d])\n",
                 (LAC_ARCH_UINT)instanceHandle,
                 (LAC_ARCH_UINT)pOpData_Legacy,
                 (LAC_ARCH_UINT)pOpData_Generic,
                 (LAC_ARCH_UINT)pVerifyStatus,
                 *pVerifyStatus);
#endif
        return status;
    }
#ifdef ICP_PARAM_CHECK
    /* Basic NULL Param Checking  */
    if (pOpData_Legacy)
    {
        status = LacEc_PointVerifyBasicParamCheck(
            instanceHandle, pOpData_Legacy, pVerifyStatus);
    }
    else
    {
        status = LacEc_PointVerifyBasicParamCheckWeierstrass(
            instanceHandle, pOpData_Generic, pVerifyStatus);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
#endif
        /* Determine size */
        status = LacEc_GetRange(
            LacPke_GetMaxLnOfNBuffers(pCount, pX, pY, pMod, pA, pB),
            &dataOperationSizeBytes);
#ifdef ICP_PARAM_CHECK
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        if ((LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == fieldType))
        {
            /* Check if it is a NIST curve if not use 8QW */
            LacEc_CheckCurve4QWGF2(
                &dataOperationSizeBytes, pMod, pA, pB, NULL, NULL);
        }
    }
#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) &&
        (LAC_EC_SIZE_QW9_IN_BYTES == dataOperationSizeBytes))
    {
        /* 9QW checks */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == fieldType)
        {
            /* Check if it is a NIST curve (if not, then invalid param) */
            /* Also checks that xq and yq are less than 2^521 */
            status = LacEc_CheckCurve9QWGFP(pMod, pA, pB, NULL, NULL, pX, pY);
        }
        else
        {
            /*Check if it is a NIST curve (if not, then invalid param) */
            /* Also checks that deg xq and yq are less than deg q */
            status = LacEc_CheckCurve9QWGF2(pMod, pA, pB, NULL, NULL, pX, pY);
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that q>3 for GFP (i.e. highest bit position needs to be
           greater than 1) or that deg(q)>2 for GF2 (i.e. highest bit
           position needs to be greater than 2) */
        LacPke_GetBitPos(pMod, &bit_pos_q, &temp, &isZero);
        if (((CPA_CY_EC_FIELD_TYPE_BINARY == fieldType) &&
             (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GF2)) ||
            ((CPA_CY_EC_FIELD_TYPE_PRIME == fieldType) &&
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
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientCb = pCb;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = NULL;
        cbData.pOutputData2 = NULL;

        /* Populate input buffers and output buffer and set function ID */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcPointVerifyFillStruct(
                        in.maths_point_verify_gfp_l256, pX, pY, pMod, pA, pB);
                    functionID = MATHS_POINT_VERIFY_GFP_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcPointVerifyFillStruct(
                        in.maths_point_verify_gfp_l512, pX, pY, pMod, pA, pB);
                    functionID = MATHS_POINT_VERIFY_GFP_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcPointVerifyFillStruct(
                        in.maths_point_verify_gfp_521, pX, pY, pMod, pA, pB);
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
                    LacEcPointVerifyFillStruct(
                        in.maths_point_verify_gf2_l256, pX, pY, pMod, pA, pB);
                    functionID = MATHS_POINT_VERIFY_GF2_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcPointVerifyFillStruct(
                        in.maths_point_verify_gf2_l512, pX, pY, pMod, pA, pB);
                    functionID = MATHS_POINT_VERIFY_GF2_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcPointVerifyFillStruct(
                        in.maths_point_verify_gf2_571, pX, pY, pMod, pA, pB);
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

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      Generic ECC point verification operation
 ***************************************************************************/
CpaStatus cpaCyEcGenericPointVerify(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointVerifyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcGenericPointVerifyOpData *pOpData,
    CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pOpData->pCurve);

    switch (pOpData->pCurve->curveType)
    {
        case CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_PRIME: /* Fall through */
        case CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_BINARY:
        case CPA_CY_EC_CURVE_TYPE_WEIERSTRASS_KOBLITZ_BINARY:
            status = LacEc_CommonPointVerify(instanceHandle,
                                             pCb,
                                             pCallbackTag,
                                             NULL,
                                             pOpData,
                                             pVerifyStatus);
            break;

        default: /* other curve types are currently unsupported */
            status = CPA_STATUS_INVALID_PARAM;
            break;
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
STATIC
CpaStatus LacEcc_CommonPathPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcPointMultiplyOpData *pOpData_Legacy,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pOutX,
    CpaFlatBuffer *pOutY)
{
    CpaInstanceHandle usedInstanceHandle = instanceHandle;
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&usedInstanceHandle));

    CpaStatus status = CPA_STATUS_SUCCESS;

    if (NULL == pCb) /* Synchronous mode */
    {
        status = LacEc_CommonPathPointMultiplySynchronous(usedInstanceHandle,
                                                          pOpData_Legacy,
                                                          pOpData,
                                                          pMultiplyStatus,
                                                          pOutX,
                                                          pOutY);
    }
    else
    {
        status = LacEcc_CommonPathPointMultiplyOperation(usedInstanceHandle,
                                                         pCb,
                                                         pCallbackTag,
                                                         pOpData_Legacy,
                                                         pOpData,
                                                         pMultiplyStatus,
                                                         pOutX,
                                                         pOutY);
    }
#ifdef ICP_TRACE
    LAC_LOG7("Called with params (0x%lx -> 0x%1x, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx, 0x%1x ",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)usedInstanceHandle,
             (LAC_ARCH_UINT)pCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pOpData_Legacy,
             (LAC_ARCH_UINT)pOpData,
             (LAC_ARCH_UINT)pMultiplyStatus);
    LAC_LOG2(" 0x%lx, 0x%lx\n)", (LAC_ARCH_UINT)pOutX, (LAC_ARCH_UINT)pOutY);
#endif

    sal_crypto_service_t *pService = (sal_crypto_service_t *)usedInstanceHandle;
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequests, pService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup LacEc
 *
 ***************************************************************************/
CpaStatus cpaCyEcGenericPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pOutX,
    CpaFlatBuffer *pOutY)
{
    LAC_CHECK_NULL_PARAM(pOpData);

    return LacEcc_CommonPathPointMultiply(instanceHandle,
                                          pCb,
                                          pCallbackTag,
                                          NULL,
                                          pOpData,
                                          pMultiplyStatus,
                                          pOutX,
                                          pOutY);
}
