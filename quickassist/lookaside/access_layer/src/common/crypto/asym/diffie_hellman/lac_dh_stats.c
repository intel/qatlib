/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
#ifdef QAT_LEGACY_ALGORITHMS
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
    SAL_CHECK_INSTANCE_CRYPTO_CAPABILITY(instanceHandle, dh);
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
    SAL_CHECK_INSTANCE_CRYPTO_CAPABILITY(instanceHandle, dh);
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
#else
CpaStatus LacDh_StatsInit(CpaInstanceHandle instanceHandle)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
    return CPA_STATUS_UNSUPPORTED;
}

void LacDh_StatsFree(CpaInstanceHandle instanceHandle)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
}

void LacDh_StatsReset(CpaInstanceHandle instanceHandle)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
}

CpaStatus cpaCyDhQueryStats(CpaInstanceHandle instanceHandle_in,
                            CpaCyDhStats *pDhStats)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDhQueryStats64(const CpaInstanceHandle instanceHandle_in,
                              CpaCyDhStats64 *pDhStats)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
    return CPA_STATUS_UNSUPPORTED;
}

void LacDh_StatsInc(Cpa32U offset, CpaInstanceHandle instanceHandle)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
}

void LacDh_StatsShow(CpaInstanceHandle instanceHandle)
{
    LAC_LOG_DEBUG("DH algorithm is not supported\n");
}
#endif
