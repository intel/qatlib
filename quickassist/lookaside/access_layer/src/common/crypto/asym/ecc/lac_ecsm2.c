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
 * @file lac_ecsm2.c
 *
 * @ingroup Lac_Ecsm2
 *
 * SM2 functions
 * SM2 algorithm is using a fixed EC curve.
 * The length of the params is fixed to LAC_EC_SM2_SIZE_BYTES(32 bytes).
 * More details in http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *
 * @lld_start
 *
 * @lld_overview
 * This file implements SM2 api funcitons.
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
 * ****************************************************************************
 * * Include public/global header files
 * ****************************************************************************
 * */
/* API Includes */
#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_ecsm2.h"

/* OSAL Includes */
#include "Osal.h"

/* ADF Includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* QAT includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"
#include "icp_qat_fw_pke.h"

/* Look Aside Includes */
#include "lac_log.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_sync.h"
#include "lac_ec.h"
#include "lac_sym.h"
#include "lac_list.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "sal_statistics.h"

#define LAC_EC_SM2_SIZE_BYTES LAC_BITS_TO_BYTES(LAC_256_BITS)

/**< number of ECSM2 statistics */
#define LAC_ECSM2_NUM_STATS (sizeof(CpaCyEcsm2Stats64) / sizeof(Cpa64U))

#ifndef DISABLE_STATS
#define LAC_ECSM2_STAT_INC(statistic, pCryptoService)                          \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bEccStatsEnabled)      \
        {                                                                      \
            osalAtomicInc(&(pCryptoService)                                    \
                               ->pLacEcsm2StatsArr[offsetof(CpaCyEcsm2Stats64, \
                                                            statistic) /       \
                                                   sizeof(Cpa64U)]);           \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ec
 * macro to increment a ECSM2 stat (derives offset into array of atomics) */
#else
#define LAC_ECSM2_STAT_INC(statistic, pCryptoService)                          \
    (pCryptoService) = (pCryptoService)
#endif

#define LAC_ECSM2_STATS_GET(ecsm2Stats, pCryptoService)                        \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_ECSM2_NUM_STATS; i++)                              \
        {                                                                      \
            ((Cpa64U *)&(ecsm2Stats))[i] =                                     \
                osalAtomicGet(&pCryptoService->pLacEcsm2StatsArr[i]);          \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ec
 * macro to collect a ECDSA stat in sample period of performance counters */

#if defined(COUNTERS) && !defined(DISABLE_STATS)

#define LAC_ECSM2_TIMESTAMP_BEGIN(pCbData, OperationDir, instanceHandle)       \
    LacEcsm2_StatsBegin(pCbData, OperationDir, instanceHandle);

#define LAC_ECSM2_TIMESTAMP_END(pCbData, OperationDir, instanceHandle)         \
    LacEcsm2_StatsEnd(pCbData, OperationDir, instanceHandle);

void LacEcsm2_StatsBegin(void *pCbData,
                         ecsm2_request_type_t OperationDir,
                         CpaInstanceHandle instanceHandle);

void LacEcsm2_StatsEnd(void *pCbData,
                       ecsm2_request_type_t OperationDir,
                       CpaInstanceHandle instanceHandle);

#else
#define LAC_ECSM2_TIMESTAMP_BEGIN(pCbData, OperationDir, instanceHandle)
#define LAC_ECSM2_TIMESTAMP_END(pCbData, OperationDir, instanceHandle)
#endif

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/
/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      return the size in bytes of biggest number in
 *CpaCyEcsm2PointMultiplyOpData
 *
 * @description
 *      return the size of the biggest number in
 *      CpaCyEcsm2PointMultiplyOpData.
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcsm2PointMultiplyOpData structure
 *
 * @retval max  the size in bytes of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEcsm2_PointMulOpDataSizeGetMax(const CpaCyEcsm2PointMultiplyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->x)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->y)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);
    return max;
}

STATIC Cpa32U LacEcsm2_GeneratorMulOpDataSizeGetMax(
    const CpaCyEcsm2GeneratorMultiplyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);
    return max;
}

STATIC Cpa32U
LacEcsm2_PointVerifyOpDataSizeGetMax(const CpaCyEcsm2PointVerifyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->x)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->y)), max);
    return max;
}

STATIC Cpa32U LacEcsm2_SignOpDataSizeGetMax(const CpaCyEcsm2SignOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->e)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->d)), max);
    return max;
}

STATIC Cpa32U
LacEcsm2_VerifyOpDataSizeGetMax(const CpaCyEcsm2VerifyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->e)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->r)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->s)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xP)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yP)), max);
    return max;
}

STATIC Cpa32U
LacEcsm2_EncOpDataSizeGetMax(const CpaCyEcsm2EncryptOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xP)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yP)), max);
    return max;
}

STATIC Cpa32U
LacEcsm2_DecOpDataSizeGetMax(const CpaCyEcsm2DecryptOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->d)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->x1)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->y1)), max);
    return max;
}

STATIC Cpa32U
LacEcsm2_KeyExPhase1OpDataSizeGetMax(const CpaCyEcsm2KeyExPhase1OpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->r)), max);
    return max;
}

STATIC Cpa32U
LacEcsm2_KeyExPhase2OpDataSizeGetMax(const CpaCyEcsm2KeyExPhase2OpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->r)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->d)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->x1)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->x2)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->y2)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xP)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yP)), max);
    return max;
}

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Signature synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_SignSyn(const CpaInstanceHandle instanceHandle,
                                  const CpaCyEcsm2SignOpData *pEcsm2SignOpData,
                                  CpaBoolean *pSignStatus,
                                  CpaFlatBuffer *pR,
                                  CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status =
            cpaCyEcsm2Sign(instanceHandle,
                           (CpaCyEcsm2SignCbFunc)LacSync_GenDualFlatBufVerifyCb,
                           pSyncCallbackData,
                           pEcsm2SignOpData,
                           pSignStatus,
                           pR,
                           pS);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pSignStatus);
        if ((CPA_STATUS_SUCCESS != wCbStatus) || (CPA_TRUE != *pSignStatus))
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 SIGN FAILED!!\n");
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
 * @ingroup Lac_Ecsm2
 *      SM2 signature verify synchronous function
 ***************************************************************************/
STATIC CpaStatus LacEcsm2_VerifySyn(const CpaInstanceHandle instanceHandle,
                                    const CpaCyEcsm2VerifyOpData *pOpData,
                                    CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the generic synchronous callback function as a parameter.
         */
        status = cpaCyEcsm2Verify(instanceHandle,
                                  (CpaCyEcsm2VerifyCbFunc)LacSync_GenVerifyCb,
                                  pSyncCallbackData,
                                  pOpData,
                                  pVerifyStatus);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pVerifyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus || CPA_TRUE != *pVerifyStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 SIGN VERIFY FAILED!!\n");
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

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 point multiply synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_PointMultiplySyn(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcsm2PointMultiplyOpData *pEcsm2PointMulOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status = cpaCyEcsm2PointMultiply(
            instanceHandle,
            (CpaCyEcPointMultiplyCbFunc)LacSync_GenDualFlatBufVerifyCb,
            pSyncCallbackData,
            pEcsm2PointMulOpData,
            pMultiplyStatus,
            pXk,
            pYk);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus || CPA_TRUE != *pMultiplyStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 POINT MULTIPLY FAILED!!\n");
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

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 generator multiply synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_GenMultiplySyn(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcsm2GeneratorMultiplyOpData *pEcsm2GenMulOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pXy)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status = cpaCyEcsm2GeneratorMultiply(
            instanceHandle,
            (CpaCyEcPointMultiplyCbFunc)LacSync_GenDualFlatBufVerifyCb,
            pSyncCallbackData,
            pEcsm2GenMulOpData,
            pMultiplyStatus,
            pXk,
            pXy);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus || CPA_TRUE != *pMultiplyStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 GENERATOR MULTIPLY FAILED!!\n");
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

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 point verify synchronous function
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_PointVerifySyn(const CpaInstanceHandle instanceHandle,
                        const CpaCyEcsm2PointVerifyOpData *pOpData,
                        CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the generic synchronous callback function as a parameter.
         */
        status =
            cpaCyEcsm2PointVerify(instanceHandle,
                                  (CpaCyEcPointVerifyCbFunc)LacSync_GenVerifyCb,
                                  pSyncCallbackData,
                                  pOpData,
                                  pVerifyStatus);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pVerifyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus || CPA_TRUE != *pVerifyStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 POINT VERIFY FAILED!!\n");
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

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Encryption synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_EncSyn(const CpaInstanceHandle instanceHandle,
                                 const CpaCyEcsm2EncryptOpData *pEcsm2EncOpData,
                                 CpaCyEcsm2EncryptOutputData *pEcsm2EncOutput)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status = cpaCyEcsm2Encrypt(instanceHandle,
                                   (CpaCyGenFlatBufCbFunc)LacSync_GenFlatBufCb,
                                   pSyncCallbackData,
                                   pEcsm2EncOpData,
                                   pEcsm2EncOutput);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 ENCRYPTION FAILED!!\n");
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

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Decryption synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_DecSyn(const CpaInstanceHandle instanceHandle,
                                 const CpaCyEcsm2DecryptOpData *pEcsm2DecOpData,
                                 CpaCyEcsm2DecryptOutputData *pEcsm2DecOutput)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status = cpaCyEcsm2Decrypt(instanceHandle,
                                   (CpaCyGenFlatBufCbFunc)LacSync_GenFlatBufCb,
                                   pSyncCallbackData,
                                   pEcsm2DecOpData,
                                   pEcsm2DecOutput);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 DECRYPTION FAILED!!\n");
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

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 key exchange phase 1 synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_KeyexPhase1Syn(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcsm2KeyExPhase1OpData *pEcsm2KeyExPhase1OpData,
    CpaCyEcsm2KeyExOutputData *pEcsm2KeyExPhase1OutputData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status =
            cpaCyEcsm2KeyExPhase1(instanceHandle,
                                  (CpaCyGenFlatBufCbFunc)LacSync_GenFlatBufCb,
                                  pSyncCallbackData,
                                  pEcsm2KeyExPhase1OpData,
                                  pEcsm2KeyExPhase1OutputData);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 KEY EXCHANGE PHASE 1 FAILED!!\n");
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

/**********************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 key exchange phase 2 synchronous function
 *
 **********************************************************************/
STATIC CpaStatus LacEcsm2_KeyexPhase2Syn(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcsm2KeyExPhase2OpData *pEcsm2KeyExPhase2OpData,
    CpaCyEcsm2KeyExOutputData *pEcsm2KeyExPhase2OutputData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Call the asynchronous version of the function
         * with the synchronous callback function as a parameter.
         */
        status =
            cpaCyEcsm2KeyExPhase2(instanceHandle,
                                  (CpaCyGenFlatBufCbFunc)LacSync_GenFlatBufCb,
                                  pSyncCallbackData,
                                  pEcsm2KeyExPhase2OpData,
                                  pEcsm2KeyExPhase2OutputData);
    }
    else
    {
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            status = wCbStatus;
            LAC_LOG("ECSM2 KEY EXCHANGE PHASE 2 FAILED!!\n");
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

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Signature internal callback
 ***************************************************************************/
STATIC void LacEcsm2_SignCb(CpaStatus status,
                            CpaBoolean signStatus,
                            CpaInstanceHandle instanceHandle,
                            lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcsm2SignCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2SignOpData *pOpData = NULL;
    CpaFlatBuffer *pR = NULL;
    CpaFlatBuffer *pS = NULL;
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyEcsm2SignCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pR = pCbData->pOutputData1;
    pS = pCbData->pOutputData2;

#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* increment Sign stats */
    LAC_ECSM2_TIMESTAMP_END(pCbData, LAC_ECSM2_SIGN_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2SignCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2SignCompletedError, pCryptoService);
    }
    if ((CPA_FALSE == signStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2SignCompletedOutputInvalid, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, signStatus, pR, pS);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Signature Verify internal callback
 ***************************************************************************/

STATIC void LacEcsm2_VerifyCb(CpaStatus status,
                              CpaBoolean verifyStatus,
                              CpaInstanceHandle instanceHandle,
                              lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcsm2VerifyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2VerifyOpData *pOpData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyEcsm2VerifyCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);

#ifndef DISABLE_STATS
    /* increment Verify stats */
    LAC_ECSM2_TIMESTAMP_END(pCbData, LAC_ECSM2_VERIFY_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2VerifyCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2VerifyCompletedError, pCryptoService);
    }

    if ((CPA_FALSE == verifyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2VerifyCompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, verifyStatus);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Encryption internal callback
 ***************************************************************************/
STATIC void LacEcsm2_EncCb(CpaStatus status,
                           CpaBoolean encStatus,
                           CpaInstanceHandle instanceHandle,
                           lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2EncryptOpData *pOpData = NULL;
    CpaCyEcsm2EncryptOutputData *pOutData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOutData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutData);

#ifndef DISABLE_STATS
    /* increment Enc stats */
    LAC_ECSM2_TIMESTAMP_END(pCbData, LAC_ECSM2_ENC_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2EncryptCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2EncryptCompletedError, pCryptoService);
    }
    if ((CPA_FALSE == encStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2EncryptCompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, (void *)pOutData);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Decryption internal callback
 ***************************************************************************/
STATIC void LacEcsm2_DecCb(CpaStatus status,
                           CpaBoolean decStatus,
                           CpaInstanceHandle instanceHandle,
                           lac_pke_op_cb_data_t *pCbData)
{

    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2DecryptOpData *pOpData = NULL;
    CpaCyEcsm2DecryptOutputData *pOutData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOutData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutData);

#ifndef DISABLE_STATS
    /* increment Decrypt stats */
    LAC_ECSM2_TIMESTAMP_END(pCbData, LAC_ECSM2_DEC_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2DecryptCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2DecryptCompletedError, pCryptoService);
    }

    if ((CPA_FALSE == decStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2DecryptCompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, (void *)pOutData);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Key Exchange Phase 1 internal callback
 ***************************************************************************/
STATIC void LacEcsm2_KeyExPhase1Cb(CpaStatus status,
                                   CpaBoolean keyexStatus,
                                   CpaInstanceHandle instanceHandle,
                                   lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2KeyExPhase1OpData *pOpData = NULL;
    CpaCyEcsm2KeyExOutputData *pOutData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOutData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutData);

#ifndef DISABLE_STATS
    /* increment Key Exchange Phase1 stats */
    LAC_ECSM2_TIMESTAMP_END(
        pCbData, LAC_ECSM2_KEY_EXCHANGE_P1_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase1Completed, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase1CompletedError, pCryptoService);
    }
    if ((CPA_FALSE == keyexStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase1CompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, (void *)pOutData);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Key Exchange Phase 2 internal callback
 ***************************************************************************/
STATIC void LacEcsm2_KeyExPhase2Cb(CpaStatus status,
                                   CpaBoolean keyexStatus,
                                   CpaInstanceHandle instanceHandle,
                                   lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2KeyExPhase2OpData *pOpData = NULL;
    CpaCyEcsm2KeyExOutputData *pOutData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOutData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutData);

#ifndef DISABLE_STATS
    /* increment Key Exchange Phase 2 stats */
    LAC_ECSM2_TIMESTAMP_END(
        pCbData, LAC_ECSM2_KEY_EXCHANGE_P2_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase2Completed, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase2CompletedError, pCryptoService);
    }
    if ((CPA_FALSE == keyexStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase2CompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, (void *)pOutData);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Point Multiplication internal callback
 ***************************************************************************/
STATIC void LacEcsm2_PointMulCb(CpaStatus status,
                                CpaBoolean multiplyStatus,
                                CpaInstanceHandle instanceHandle,
                                lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcPointMultiplyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2PointMultiplyOpData *pOpData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyEcPointMultiplyCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pXk = pCbData->pOutputData1;
    pYk = pCbData->pOutputData2;
    LAC_ASSERT_NOT_NULL(pXk);
    LAC_ASSERT_NOT_NULL(pYk);

#ifndef DISABLE_STATS
    /* increment Point Multiply stats */
    LAC_ECSM2_TIMESTAMP_END(
        pCbData, LAC_ECSM2_POINT_MULTIPLY_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointMultiplyCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointMultiplyCompletedError, pCryptoService);
    }
    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointMultiplyCompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pXk, pYk);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      SM2 Generator Multiplication internal callback
 ***************************************************************************/
STATIC void LacEcsm2_GenMulCb(CpaStatus status,
                              CpaBoolean multiplyStatus,
                              CpaInstanceHandle instanceHandle,
                              lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcPointMultiplyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2GeneratorMultiplyOpData *pOpData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyEcPointMultiplyCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pXk = pCbData->pOutputData1;
    pYk = pCbData->pOutputData2;
    LAC_ASSERT_NOT_NULL(pXk);
    LAC_ASSERT_NOT_NULL(pYk);

#ifndef DISABLE_STATS
    /* increment Point Generator stats */
    LAC_ECSM2_TIMESTAMP_END(
        pCbData, LAC_ECSM2_GEN_POINT_MULTIPLY_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2GeneratorMultiplyCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2GeneratorMultiplyCompletedError,
                           pCryptoService);
    }
    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2GeneratorMultiplyCompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pXk, pYk);
}

/***************************************************************************
 * @ingroup Lac_Ecsm2
 *      EC Point Verify internal callback
 ***************************************************************************/
STATIC void LacEcsm2_PointVerifyCb(CpaStatus status,
                                   CpaBoolean verifyStatus,
                                   CpaInstanceHandle instanceHandle,
                                   lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcPointVerifyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcsm2PointVerifyOpData *pOpData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (void *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyEcPointVerifyCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);

#ifndef DISABLE_STATS
    /* increment Point Verify stats */
    LAC_ECSM2_TIMESTAMP_END(
        pCbData, LAC_ECSM2_POINT_VERIFY_REQUEST, instanceHandle);
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointVerifyCompleted, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointVerifyCompletedError, pCryptoService);
    }
    if ((CPA_FALSE == verifyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointVerifyCompletedOutputInvalid,
                           pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, verifyStatus);
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Check if SM2 is supported by
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_HwCapabilityCheck(const CpaInstanceHandle instanceHandle)
{
    CpaCyCapabilitiesInfo capInfo;
    cpaCyQueryCapabilities(instanceHandle, &capInfo);
    if (!capInfo.ecSm2Supported)
    {
        LAC_UNSUPPORTED_PARAM_LOG("Unsupported Algorithm ECSM2");
        return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Point Multiply function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus LacEcsm2_PointMultiplyBasicParamCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcsm2PointMultiplyOpData *pOpData,
    const CpaBoolean *pMultiplyStatus,
    const CpaFlatBuffer *pXk,
    const CpaFlatBuffer *pYk)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(instanceHandle);
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);
    LAC_CHECK_NULL_PARAM(pXk);
    LAC_CHECK_NULL_PARAM(pYk);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->x.pData);
    LAC_CHECK_SIZE(&(pOpData->x), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->y.pData);
    LAC_CHECK_SIZE(&(pOpData->y), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pXk->pData);
    LAC_CHECK_SIZE(pXk, CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pYk->pData);
    LAC_CHECK_SIZE(pYk, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Generator Multiply function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus LacEcsm2_GenMultiplyBasicParamCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcsm2GeneratorMultiplyOpData *pOpData,
    const CpaBoolean *pMultiplyStatus,
    const CpaFlatBuffer *pXk,
    const CpaFlatBuffer *pYk)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);
    LAC_CHECK_NULL_PARAM(pXk);
    LAC_CHECK_NULL_PARAM(pYk);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pXk->pData);
    LAC_CHECK_SIZE(pXk, CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pYk->pData);
    LAC_CHECK_SIZE(pYk, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Point Verify function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_PointVerifyBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                    const CpaCyEcsm2PointVerifyOpData *pOpData,
                                    const CpaBoolean *pVerifyStatus)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pVerifyStatus);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->x.pData);
    LAC_CHECK_SIZE(&(pOpData->x), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->y.pData);
    LAC_CHECK_SIZE(&(pOpData->y), CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Signature function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_SignBasicParamCheck(const CpaInstanceHandle instanceHandle,
                             const CpaBoolean *pSignStatus,
                             const CpaCyEcsm2SignOpData *pOpData,
                             CpaFlatBuffer *pR,
                             CpaFlatBuffer *pS)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pSignStatus);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->e.pData);
    LAC_CHECK_SIZE(&(pOpData->e), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->d.pData);
    LAC_CHECK_SIZE(&(pOpData->d), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pR);
    LAC_CHECK_NULL_PARAM(pS);
    LAC_CHECK_NULL_PARAM(pR->pData);
    LAC_CHECK_SIZE(pR, CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pS->pData);
    LAC_CHECK_SIZE(pS, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Signature Verify function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_VerifyBasicParamCheck(const CpaInstanceHandle instanceHandle,
                               const CpaCyEcsm2VerifyOpData *pOpData,
                               const CpaBoolean *pVerifyStatus)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pVerifyStatus);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->e.pData);
    LAC_CHECK_SIZE(&(pOpData->e), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->r.pData);
    LAC_CHECK_SIZE(&(pOpData->r), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->s.pData);
    LAC_CHECK_SIZE(&(pOpData->s), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xP.pData);
    LAC_CHECK_SIZE(&(pOpData->xP), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yP.pData);
    LAC_CHECK_SIZE(&(pOpData->yP), CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Encryption function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_EncBasicParamCheck(const CpaInstanceHandle instanceHandle,
                            const CpaCyEcsm2EncryptOpData *pOpData,
                            const CpaCyEcsm2EncryptOutputData *pOut)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xP.pData);
    LAC_CHECK_SIZE(&(pOpData->xP), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yP.pData);
    LAC_CHECK_SIZE(&(pOpData->yP), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut);
    LAC_CHECK_NULL_PARAM(pOut->x1.pData);
    LAC_CHECK_SIZE(&(pOut->x1), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut->y1.pData);
    LAC_CHECK_SIZE(&(pOut->y1), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut->x2.pData);
    LAC_CHECK_SIZE(&(pOut->x2), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut->y2.pData);
    LAC_CHECK_SIZE(&(pOut->y2), CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Decryption function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_DecBasicParamCheck(const CpaInstanceHandle instanceHandle,
                            const CpaCyEcsm2DecryptOpData *pOpData,
                            const CpaCyEcsm2DecryptOutputData *pOut)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->d.pData);
    LAC_CHECK_SIZE(&(pOpData->d), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->x1.pData);
    LAC_CHECK_SIZE(&(pOpData->x1), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->y1.pData);
    LAC_CHECK_SIZE(&(pOpData->y1), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut);
    LAC_CHECK_NULL_PARAM(pOut->x2.pData);
    LAC_CHECK_SIZE(&(pOut->x2), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut->y2.pData);
    LAC_CHECK_SIZE(&(pOut->y2), CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Key Exchange Phase1 function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_KeyExPhase1BasicParamCheck(const CpaInstanceHandle instanceHandle,
                                    const CpaCyEcsm2KeyExPhase1OpData *pOpData,
                                    const CpaCyEcsm2KeyExOutputData *pOut)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->r.pData);
    LAC_CHECK_SIZE(&(pOpData->r), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut);
    LAC_CHECK_NULL_PARAM(pOut->x.pData);
    LAC_CHECK_SIZE(&(pOut->x), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut->y.pData);
    LAC_CHECK_SIZE(&(pOut->y), CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *      ECSM2 Key Exchange Phase2 function to perform basic checks on the IN
 *      parameters (e.g. checks data buffers for NULL and 0 dataLen)
 ***************************************************************************/
STATIC CpaStatus
LacEcsm2_KeyExPhase2BasicParamCheck(const CpaInstanceHandle instanceHandle,
                                    const CpaCyEcsm2KeyExPhase2OpData *pOpData,
                                    const CpaCyEcsm2KeyExOutputData *pOut)
{
    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->r.pData);
    LAC_CHECK_SIZE(&(pOpData->r), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->d.pData);
    LAC_CHECK_SIZE(&(pOpData->d), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->x1.pData);
    LAC_CHECK_SIZE(&(pOpData->x1), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->x2.pData);
    LAC_CHECK_SIZE(&(pOpData->x2), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->y2.pData);
    LAC_CHECK_SIZE(&(pOpData->y2), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xP.pData);
    LAC_CHECK_SIZE(&(pOpData->xP), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yP.pData);
    LAC_CHECK_SIZE(&(pOpData->yP), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut);
    LAC_CHECK_NULL_PARAM(pOut->x.pData);
    LAC_CHECK_SIZE(&(pOut->x), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOut->y.pData);
    LAC_CHECK_SIZE(&(pOut->y), CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif /* ICP_PARAM_CHECK */

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 point multiplication operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2PointMultiply(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyEcPointMultiplyCbFunc pEcsm2PointMulCb,
    void *pCallbackTag,
    const CpaCyEcsm2PointMultiplyOpData *pEcsm2PointMulOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2PointMulCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_PointMultiplySyn(
            instanceHandle, pEcsm2PointMulOpData, pMultiplyStatus, pXk, pYk);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_PointMultiplyBasicParamCheck(
        instanceHandle, pEcsm2PointMulOpData, pMultiplyStatus, pXk, pYk);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(
            LacEcsm2_PointMulOpDataSizeGetMax(pEcsm2PointMulOpData),
            &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that output buffers are big enough
         * for SM2 algorithm, the length is fixed
         * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
         */
        if ((pXk->dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pYk->dataLenInBytes < LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2PointMulOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_POINT_MULTIPLICATION;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(
            inArgList.mmp_ecsm2_point_multiplication.k,
            &(pEcsm2PointMulOpData->k));
        pInArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_input_t, k)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_input_t, k)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            inArgList.mmp_ecsm2_point_multiplication.x,
            &(pEcsm2PointMulOpData->x));
        pInArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_input_t, x)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_input_t, x)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            inArgList.mmp_ecsm2_point_multiplication.y,
            &(pEcsm2PointMulOpData->y));
        pInArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_input_t, y)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_input_t, y)] = CPA_FALSE;

        /* Fill output list, x,y */
        LAC_MEM_SHARED_WRITE_FROM_PTR(
            outArgList.mmp_ecsm2_point_multiplication.xd, pXk);
        pOutArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, xd)] =
            dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, xd)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            outArgList.mmp_ecsm2_point_multiplication.yd, pYk);
        pOutArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, yd)] =
            dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, yd)] =
            CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2PointMulOpData;
        cbData.pClientCb = pEcsm2PointMulCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pXk;
        cbData.pOutputData2 = pYk;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_POINT_MULTIPLY_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_PointMulCb,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointMultiplyRequests, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointMultiplyRequestErrors, pCryptoService);
    }
#endif

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 point generator multiplication operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2GeneratorMultiply(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyEcPointMultiplyCbFunc pEcsm2GenMulCb,
    void *pCallbackTag,
    const CpaCyEcsm2GeneratorMultiplyOpData *pEcsm2GenMulOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2GenMulCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_GenMultiplySyn(
            instanceHandle, pEcsm2GenMulOpData, pMultiplyStatus, pXk, pYk);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_GenMultiplyBasicParamCheck(
        instanceHandle, pEcsm2GenMulOpData, pMultiplyStatus, pXk, pYk);
#endif

    /* Check that output buffers are big enough
     * for SM2 algorithm, the length is fixed
     * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
     */

    /* Determine size - based on input numbers */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacEc_GetRange(
            LacEcsm2_GeneratorMulOpDataSizeGetMax(pEcsm2GenMulOpData),
            &dataOperationSizeBytes);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if ((pXk->dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pYk->dataLenInBytes < LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2GenMulOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_GENERATOR_MULTIPLICATION;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(
            inArgList.mmp_ecsm2_generator_multiplication.k,
            &(pEcsm2GenMulOpData->k));
        pInArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_generator_multiplication_input_t, k)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_generator_multiplication_input_t, k)] =
            CPA_FALSE;

        /* Fill output list, x,y */
        LAC_MEM_SHARED_WRITE_FROM_PTR(
            outArgList.mmp_ecsm2_point_multiplication.xd, pXk);
        pOutArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, xd)] =
            dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, xd)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            outArgList.mmp_ecsm2_point_multiplication.yd, pYk);
        pOutArgSizeList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, yd)] =
            dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(
            icp_qat_fw_mmp_ecsm2_point_multiplication_output_t, yd)] =
            CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2GenMulOpData;
        cbData.pClientCb = pEcsm2GenMulCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pXk;
        cbData.pOutputData2 = pYk;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_GEN_POINT_MULTIPLY_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_GenMulCb,
                                          &cbData,
                                          instanceHandle);

#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2GeneratorMultiplyRequests,
                               pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2GeneratorMultiplyRequestErrors,
                               pCryptoService);
        }
#endif
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 point verify operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2PointVerify(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyEcPointVerifyCbFunc pEcsm2PointVerifyCb,
    void *pCallbackTag,
    const CpaCyEcsm2PointVerifyOpData *pEcsm2PointVerifyOpData,
    CpaBoolean *pPointVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2PointVerifyCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_PointVerifySyn(
            instanceHandle, pEcsm2PointVerifyOpData, pPointVerifyStatus);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_PointVerifyBasicParamCheck(
        instanceHandle, pEcsm2PointVerifyOpData, pPointVerifyStatus);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(
            LacEcsm2_PointVerifyOpDataSizeGetMax(pEcsm2PointVerifyOpData),
            &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2PointVerifyOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_POINT_VERIFY;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_point_verify.x,
                                      &(pEcsm2PointVerifyOpData->x));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_point_verify_input_t,
                                  x)] = dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_point_verify_input_t,
                                     x)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_point_verify.y,
                                      &(pEcsm2PointVerifyOpData->y));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_point_verify_input_t,
                                  y)] = dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_point_verify_input_t,
                                     y)] = CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2PointVerifyOpData;
        cbData.pClientCb = pEcsm2PointVerifyCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = NULL;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_POINT_VERIFY_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_PointVerifyCb,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointVerifyRequests, pCryptoService);
    }
    else
    {
        LAC_ECSM2_STAT_INC(numEcsm2PointVerifyRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 signature operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2Sign(const CpaInstanceHandle instanceHandle_in,
                         const CpaCyEcsm2SignCbFunc pEcsm2SignCb,
                         void *pCallbackTag,
                         const CpaCyEcsm2SignOpData *pEcsm2SignOpData,
                         CpaBoolean *pSignStatus,
                         CpaFlatBuffer *pR,
                         CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2SignCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_SignSyn(
            instanceHandle, pEcsm2SignOpData, pSignStatus, pR, pS);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_SignBasicParamCheck(
        instanceHandle, pSignStatus, pEcsm2SignOpData, pR, pS);
#endif

    /* Determine size - based on input numbers */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacEc_GetRange(LacEcsm2_SignOpDataSizeGetMax(pEcsm2SignOpData),
                                &dataOperationSizeBytes);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that output buffers are big enough
         * for SM2 algorithm, the length is fixed
         * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
         */
        if ((pR->dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pS->dataLenInBytes < LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2SignOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_SIGN_RS;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_sign_rs.k,
                                      &(pEcsm2SignOpData->k));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_input_t, k)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_input_t, k)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_sign_rs.e,
                                      &(pEcsm2SignOpData->e));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_input_t, e)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_input_t, e)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_sign_rs.d,
                                      &(pEcsm2SignOpData->d));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_input_t, d)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_input_t, d)] =
            CPA_FALSE;
        /* Fill output list, R, S */
        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_sign_rs.r, pR);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_output_t, r)] =
            dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_output_t,
                                      r)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_sign_rs.s, pS);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_output_t, s)] =
            dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_sign_rs_output_t,
                                      s)] = CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2SignOpData;
        cbData.pClientCb = pEcsm2SignCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pR;
        cbData.pOutputData2 = pS;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_SIGN_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_SignCb,
                                          &cbData,
                                          instanceHandle);

#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2SignRequests, pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2SignRequestErrors, pCryptoService);
        }
#endif
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 signature verify operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2Verify(const CpaInstanceHandle instanceHandle_in,
                           const CpaCyEcsm2VerifyCbFunc pEcsm2VerifyCb,
                           void *pCallbackTag,
                           const CpaCyEcsm2VerifyOpData *pEcsm2VerifyOpData,
                           CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2VerifyCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_VerifySyn(
            instanceHandle, pEcsm2VerifyOpData, pVerifyStatus);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_VerifyBasicParamCheck(
        instanceHandle, pEcsm2VerifyOpData, pVerifyStatus);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status =
            LacEc_GetRange(LacEcsm2_VerifyOpDataSizeGetMax(pEcsm2VerifyOpData),
                           &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2VerifyOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_VERIFY;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_verify.e,
                                      &(pEcsm2VerifyOpData->e));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, e)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, e)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_verify.r,
                                      &(pEcsm2VerifyOpData->r));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, r)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, r)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_verify.s,
                                      &(pEcsm2VerifyOpData->s));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, s)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, s)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_verify.xp,
                                      &(pEcsm2VerifyOpData->xP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, xp)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, xp)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_verify.yp,
                                      &(pEcsm2VerifyOpData->yP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, yp)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_verify_input_t, yp)] =
            CPA_FALSE;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2VerifyOpData;
        cbData.pClientCb = pEcsm2VerifyCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = NULL;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_VERIFY_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_VerifyCb,
                                          &cbData,
                                          instanceHandle);
#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2VerifyRequests, pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2VerifyRequestErrors, pCryptoService);
        }
#endif
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 encryption operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2Encrypt(const CpaInstanceHandle instanceHandle_in,
                            const CpaCyGenFlatBufCbFunc pEcsm2EncCb,
                            void *pCallbackTag,
                            const CpaCyEcsm2EncryptOpData *pEcsm2EncOpData,
                            CpaCyEcsm2EncryptOutputData *pEcsm2EncOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2EncCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_EncSyn(
            instanceHandle, pEcsm2EncOpData, pEcsm2EncOutputData);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_EncBasicParamCheck(
        instanceHandle, pEcsm2EncOpData, pEcsm2EncOutputData);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(LacEcsm2_EncOpDataSizeGetMax(pEcsm2EncOpData),
                                &dataOperationSizeBytes);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that output buffers are big enough
         * for SM2 algorithm, the length is fixed
         * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
         */
        if ((pEcsm2EncOutputData->x1.dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pEcsm2EncOutputData->y1.dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pEcsm2EncOutputData->x2.dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pEcsm2EncOutputData->y2.dataLenInBytes < LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2EncOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_ENCRYPTION;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_encryption.k,
                                      &(pEcsm2EncOpData->k));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_input_t, k)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_input_t,
                                     k)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_encryption.xp,
                                      &(pEcsm2EncOpData->xP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_input_t,
                                  xp)] = dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_input_t,
                                     xp)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_encryption.yp,
                                      &(pEcsm2EncOpData->yP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_input_t,
                                  yp)] = dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_input_t,
                                     yp)] = CPA_FALSE;
        /* Fill output list, x1,y1,x2,y2 */
        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_encryption.xc,
                                      &(pEcsm2EncOutputData->x1));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                   xc)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                      xc)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_encryption.yc,
                                      &(pEcsm2EncOutputData->y1));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                   yc)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                      yc)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_encryption.xpb,
                                      &(pEcsm2EncOutputData->x2));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                   xpb)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                      xpb)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_encryption.ypb,
                                      &(pEcsm2EncOutputData->y2));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                   ypb)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_encryption_output_t,
                                      ypb)] = CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2EncOpData;
        cbData.pClientCb = pEcsm2EncCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pEcsm2EncOutputData;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_ENC_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_EncCb,
                                          &cbData,
                                          instanceHandle);

#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2EncryptRequests, pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2EncryptRequestErrors, pCryptoService);
        }
#endif
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 point decryption operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2Decrypt(const CpaInstanceHandle instanceHandle_in,
                            const CpaCyGenFlatBufCbFunc pEcsm2DecCb,
                            void *pCallbackTag,
                            const CpaCyEcsm2DecryptOpData *pEcsm2DecOpData,
                            CpaCyEcsm2DecryptOutputData *pEcsm2DecOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2DecCb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_DecSyn(
            instanceHandle, pEcsm2DecOpData, pEcsm2DecOutputData);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_DecBasicParamCheck(
        instanceHandle, pEcsm2DecOpData, pEcsm2DecOutputData);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(LacEcsm2_DecOpDataSizeGetMax(pEcsm2DecOpData),
                                &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that output buffers are big enough
         * for SM2 algorithm, the length is fixed
         * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
         */
        if ((pEcsm2DecOutputData->x2.dataLenInBytes < LAC_EC_SM2_SIZE_BYTES) ||
            (pEcsm2DecOutputData->y2.dataLenInBytes < LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2DecOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_DECRYPTION;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_decryption.d,
                                      &(pEcsm2DecOpData->d));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_input_t, d)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_input_t,
                                     d)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_decryption.xpb,
                                      &(pEcsm2DecOpData->x1));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_input_t,
                                  xpb)] = dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_input_t,
                                     xpb)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_decryption.ypb,
                                      &(pEcsm2DecOpData->y1));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_input_t,
                                  ypb)] = dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_input_t,
                                     ypb)] = CPA_FALSE;

        /* Fill output list x2 y2 */
        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_decryption.xd,
                                      &(pEcsm2DecOutputData->x2));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_output_t,
                                   xd)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_output_t,
                                      xd)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_decryption.yd,
                                      &(pEcsm2DecOutputData->y2));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_output_t,
                                   yd)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_decryption_output_t,
                                      yd)] = CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2DecOpData;
        cbData.pClientCb = pEcsm2DecCb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pEcsm2DecOutputData;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_DEC_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_DecCb,
                                          &cbData,
                                          instanceHandle);

#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2DecryptRequests, pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2DecryptRequestErrors, pCryptoService);
        }
#endif
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 key exchange phase 1 operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2KeyExPhase1(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyGenFlatBufCbFunc pEcsm2KeyExPhase1Cb,
    void *pCallbackTag,
    const CpaCyEcsm2KeyExPhase1OpData *pEcsm2KeyExPhase1OpData,
    CpaCyEcsm2KeyExOutputData *pEcsm2KeyExPhase1OutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2KeyExPhase1Cb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_KeyexPhase1Syn(instanceHandle,
                                       pEcsm2KeyExPhase1OpData,
                                       pEcsm2KeyExPhase1OutputData);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_KeyExPhase1BasicParamCheck(
        instanceHandle, pEcsm2KeyExPhase1OpData, pEcsm2KeyExPhase1OutputData);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(
            LacEcsm2_KeyExPhase1OpDataSizeGetMax(pEcsm2KeyExPhase1OpData),
            &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that output buffers are big enough
         * for SM2 algorithm, the length is fixed
         * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
         */
        if ((pEcsm2KeyExPhase1OutputData->x.dataLenInBytes <
             LAC_EC_SM2_SIZE_BYTES) ||
            (pEcsm2KeyExPhase1OutputData->y.dataLenInBytes <
             LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2KeyExPhase1OpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_KEYEX_P1;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p1.k,
                                      &(pEcsm2KeyExPhase1OpData->r));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p1_input_t, k)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p1_input_t,
                                     k)] = CPA_FALSE;

        /* Fill output list, x,y */
        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_keyex_p1.xd,
                                      &(pEcsm2KeyExPhase1OutputData->x));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p1_output_t,
                                   xd)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p1_output_t,
                                      xd)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_keyex_p1.yd,
                                      &(pEcsm2KeyExPhase1OutputData->y));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p1_output_t,
                                   yd)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p1_output_t,
                                      yd)] = CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2KeyExPhase1OpData;
        cbData.pClientCb = pEcsm2KeyExPhase1Cb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pEcsm2KeyExPhase1OutputData;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_KEY_EXCHANGE_P1_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_KeyExPhase1Cb,
                                          &cbData,
                                          instanceHandle);
#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase1Requests, pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase1RequestErrors,
                               pCryptoService);
        }
#endif
    }
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ecsm2
 *
 * @description
 *     SM2 key exchange phase 2 operation
 *
 ***************************************************************************/
CpaStatus cpaCyEcsm2KeyExPhase2(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyGenFlatBufCbFunc pEcsm2KeyExPhase2Cb,
    void *pCallbackTag,
    const CpaCyEcsm2KeyExPhase2OpData *pEcsm2KeyExPhase2OpData,
    CpaCyEcsm2KeyExOutputData *pEcsm2KeyExPhase2OutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
    Cpa32U dataOperationSizeBytes = 0;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = 0;
    lac_pke_op_cb_data_t cbData = {0};
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    /* check for HW support */
    LAC_CHECK_STATUS(LacEcsm2_HwCapabilityCheck(instanceHandle));

    /* Check if the API has been called in synchronous mode */
    if (NULL == pEcsm2KeyExPhase2Cb)
    {
        /* Call synchronous mode function */
        return LacEcsm2_KeyexPhase2Syn(instanceHandle,
                                       pEcsm2KeyExPhase2OpData,
                                       pEcsm2KeyExPhase2OutputData);
    }
#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking - NULL params, buffer lengths etc. */
    status = LacEcsm2_KeyExPhase2BasicParamCheck(
        instanceHandle, pEcsm2KeyExPhase2OpData, pEcsm2KeyExPhase2OutputData);
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size - based on input numbers */
        status = LacEc_GetRange(
            LacEcsm2_KeyExPhase2OpDataSizeGetMax(pEcsm2KeyExPhase2OpData),
            &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check that output buffers are big enough
         * for SM2 algorithm, the length is fixed
         * equal to LAC_EC_SM2_SIZE_BYTES (32 bytes)
         */
        if ((pEcsm2KeyExPhase2OutputData->x.dataLenInBytes <
             LAC_EC_SM2_SIZE_BYTES) ||
            (pEcsm2KeyExPhase2OutputData->y.dataLenInBytes <
             LAC_EC_SM2_SIZE_BYTES))
        {
            LAC_INVALID_PARAM_LOG("Output buffers not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pEcsm2KeyExPhase2OpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    functionalityId = PKE_ECSM2_KEYEX_P2;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
                default:
                    LAC_INVALID_PARAM_LOG(
                        "SM2 curves other than GFP P-256 not supported");
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            LAC_INVALID_PARAM_LOG("SM2 curve over binary field not supported");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Fill input list */
        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.r,
                                      &(pEcsm2KeyExPhase2OpData->r));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, r)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     r)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.d,
                                      &(pEcsm2KeyExPhase2OpData->d));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, d)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     d)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.x1,
                                      &(pEcsm2KeyExPhase2OpData->x1));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, x1)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     x1)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.x2,
                                      &(pEcsm2KeyExPhase2OpData->x2));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, x2)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     x2)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.y2,
                                      &(pEcsm2KeyExPhase2OpData->y2));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, y2)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     y2)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.xp,
                                      &(pEcsm2KeyExPhase2OpData->xP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, xp)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     xp)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_ecsm2_keyex_p2.yp,
                                      &(pEcsm2KeyExPhase2OpData->yP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t, yp)] =
            dataOperationSizeBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_input_t,
                                     yp)] = CPA_FALSE;

        /* Fill output list, x,y */
        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_keyex_p2.xus,
                                      &(pEcsm2KeyExPhase2OutputData->x));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_output_t,
                                   xus)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_output_t,
                                      xus)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_ecsm2_keyex_p2.yus,
                                      &(pEcsm2KeyExPhase2OutputData->y));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_output_t,
                                   yus)] = dataOperationSizeBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_ecsm2_keyex_p2_output_t,
                                      yus)] = CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEcsm2KeyExPhase2OpData;
        cbData.pClientCb = pEcsm2KeyExPhase2Cb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pEcsm2KeyExPhase2OutputData;

        LAC_ECSM2_TIMESTAMP_BEGIN(&cbData,
                                  LAC_ECSM2_KEY_EXCHANGE_P2_REQUEST,
                                  (sal_crypto_service_t *)instanceHandle);

        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcsm2_KeyExPhase2Cb,
                                          &cbData,
                                          instanceHandle);

#ifndef DISABLE_STATS
        pCryptoService = (sal_crypto_service_t *)instanceHandle;
        /* increment stats */
        if (CPA_STATUS_SUCCESS == status)
        {
            LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase2Requests, pCryptoService);
        }
        else
        {
            LAC_ECSM2_STAT_INC(numEcsm2KeyExPhase2RequestErrors,
                               pCryptoService);
        }
#endif
    }
    return status;
}

CpaStatus cpaCyEcsm2QueryStats64(const CpaInstanceHandle instanceHandle_in,
                                 CpaCyEcsm2Stats64 *pEcsm2Stats)
{
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = instanceHandle_in;
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pEcsm2Stats);
#endif

    /* instance checks */
    LAC_CHECK_STATUS(LacEc_ValidateInstance(&instanceHandle));

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(pEcsm2Stats);

    /* get stats into user supplied stats structure */
    LAC_ECSM2_STATS_GET(*pEcsm2Stats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}
