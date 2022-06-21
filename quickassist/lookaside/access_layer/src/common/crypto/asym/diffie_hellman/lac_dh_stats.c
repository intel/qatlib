/******************************************************************************
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
 *****************************************************************************/

/**
 *****************************************************************************
 *
 * @file lac_dh_stats.c diffie hellman stats functions
 *
 * @ingroup LacDh

 * @description This file implements functions for Diffie Hellman stats.
 *****************************************************************************/

#include "cpa.h"
#include "cpa_cy_dh.h"

/* Osal include */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "lac_common.h"
#include "lac_hooks.h"
#include "sal_service_state.h"
#include "sal_statistics.h"

#include "lac_dh_stats_p.h"

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

/* Number of Diffie Helman statistics */
#define LAC_DH_NUM_STATS (sizeof(CpaCyDhStats64) / sizeof(Cpa64U))

/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

CpaStatus LacDh_StatsInit(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&(pCryptoService->pLacDhStatsArr),
                           LAC_DH_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_OS_BZERO(
            LAC_CONST_VOLATILE_PTR_CAST(pCryptoService->pLacDhStatsArr),
            LAC_DH_NUM_STATS * sizeof(OsalAtomic));
    }

    return status;
}

void LacDh_StatsFree(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    if (NULL != pCryptoService->pLacDhStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacDhStatsArr);
    }
}

void LacDh_StatsReset(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    LAC_OS_BZERO(LAC_CONST_VOLATILE_PTR_CAST(pCryptoService->pLacDhStatsArr),
                 LAC_DH_NUM_STATS * sizeof(OsalAtomic));
}

CpaStatus cpaCyDhQueryStats(CpaInstanceHandle instanceHandle_in,
                            CpaCyDhStats *pDhStats)
{
    Cpa32U i = 0;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pDhStats);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_RUNNING_CHECK(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
    LAC_CHECK_NULL_PARAM(pDhStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    for (i = 0; i < LAC_DH_NUM_STATS; i++)
    {
        ((Cpa32U *)pDhStats)[i] =
            (Cpa32U)osalAtomicGet(&pCryptoService->pLacDhStatsArr[i]);
    }
    return CPA_STATUS_SUCCESS;
} /* cpaCyDhQueryStats */

CpaStatus cpaCyDhQueryStats64(const CpaInstanceHandle instanceHandle_in,
                              CpaCyDhStats64 *pDhStats)
{
    Cpa32U i = 0;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pDhStats);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_RUNNING_CHECK(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
    LAC_CHECK_NULL_PARAM(pDhStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    for (i = 0; i < LAC_DH_NUM_STATS; i++)
    {
        ((Cpa64U *)pDhStats)[i] =
            osalAtomicGet(&pCryptoService->pLacDhStatsArr[i]);
    }
    return CPA_STATUS_SUCCESS;
} /* cpaCyDhQueryStats64 */

#ifndef DISABLE_STATS
void LacDh_StatsInc(Cpa32U offset, CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    if (CPA_TRUE == pCryptoService->generic_service_info.stats->bDhStatsEnabled)
    {
        osalAtomicInc(&pCryptoService->pLacDhStatsArr[offset / sizeof(Cpa64U)]);
    }
} /* LacDh_StatIncrement */
#endif /* DISABLE_STATS */

void LacDh_StatsShow(CpaInstanceHandle instanceHandle)
{
    CpaCyDhStats64 dhStats = {0};

    (void)cpaCyDhQueryStats64(instanceHandle, &dhStats);

    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "               Diffie Hellman Stats               " BORDER
            "\n" SEPARATOR);

    /* perform Info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DH Phase1 Key Gen Requests:     %16llu " BORDER "\n" BORDER
                   " DH Phase1 Key Gen Request Err:  %16llu " BORDER "\n" BORDER
                   " DH Phase1 Key Gen Completed:    %16llu " BORDER "\n" BORDER
                   " DH Phase1 Key Gen Completed Err:%16llu " BORDER
                   "\n" SEPARATOR,
            dhStats.numDhPhase1KeyGenRequests,
            dhStats.numDhPhase1KeyGenRequestErrors,
            dhStats.numDhPhase1KeyGenCompleted,
            dhStats.numDhPhase1KeyGenCompletedErrors);

    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DH Phase2 Key Gen Requests:     %16llu " BORDER "\n" BORDER
                   " DH Phase2 Key Gen Request Err:  %16llu " BORDER "\n" BORDER
                   " DH Phase2 Key Gen Completed:    %16llu " BORDER "\n" BORDER
                   " DH Phase2 Key Gen Completed Err:%16llu " BORDER
                   "\n" SEPARATOR,
            dhStats.numDhPhase2KeyGenRequests,
            dhStats.numDhPhase2KeyGenRequestErrors,
            dhStats.numDhPhase2KeyGenCompleted,
            dhStats.numDhPhase2KeyGenCompletedErrors);
}
