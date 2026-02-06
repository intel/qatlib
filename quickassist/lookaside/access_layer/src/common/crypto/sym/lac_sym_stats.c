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
 ***************************************************************************
 * @file lac_sym_stats.c   Implementation of symmetric stats
 *
 * @ingroup LacSym
 *
 ***************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_cy_sym.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "lac_mem_pools.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"
#include "icp_qat_fw_la.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "sal_statistics.h"

/* Number of Symmetric Crypto statistics */
#define LAC_SYM_NUM_STATS (sizeof(CpaCySymStats64) / sizeof(Cpa64U))

CpaStatus LacSym_StatsInit(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&(pService->pLacSymStatsArr),
                           LAC_SYM_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_OS_BZERO(
            (void *)LAC_CONST_VOLATILE_PTR_CAST(pService->pLacSymStatsArr),
            LAC_SYM_NUM_STATS * sizeof(OsalAtomic));
    }
    return status;
}

void LacSym_StatsFree(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;
    if (NULL != pService->pLacSymStatsArr)
    {
        LAC_OS_FREE(pService->pLacSymStatsArr);
    }
}

void LacSym_StatsReset(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

    LAC_OS_BZERO((void *)LAC_CONST_VOLATILE_PTR_CAST(pService->pLacSymStatsArr),
                 LAC_SYM_NUM_STATS * sizeof(OsalAtomic));
}

#ifndef DISABLE_STATS
void LacSym_StatsInc(Cpa32U offset, CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;
    if (CPA_TRUE == pService->generic_service_info.stats->bSymStatsEnabled)
    {
        osalAtomicInc(&pService->pLacSymStatsArr[offset / sizeof(Cpa64U)]);
    }
}
#endif /* DISABLE_STATS */

void LacSym_Stats32CopyGet(CpaInstanceHandle instanceHandle,
                           CpaCySymStats *const pSymStats)
{
    int i = 0;
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;
    LAC_ENSURE(NULL != instanceHandle, "invalid handle\n");
    LAC_ENSURE_NOT_NULL(pSymStats);

    for (i = 0; i < LAC_SYM_NUM_STATS; i++)
    {
        ((Cpa32U *)pSymStats)[i] =
            (Cpa32U)osalAtomicGet(&pService->pLacSymStatsArr[i]);
    }
}

void LacSym_Stats64CopyGet(CpaInstanceHandle instanceHandle,
                           CpaCySymStats64 *const pSymStats)
{
    int i = 0;
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;
    LAC_ENSURE(NULL != instanceHandle, "invalid handle\n");
    LAC_ENSURE_NOT_NULL(pSymStats);

    for (i = 0; i < LAC_SYM_NUM_STATS; i++)
    {
        ((Cpa64U *)pSymStats)[i] = osalAtomicGet(&pService->pLacSymStatsArr[i]);
    }
}

void LacSym_StatsShow(CpaInstanceHandle instanceHandle)
{
    CpaCySymStats64 symStats = {0};

    LacSym_Stats64CopyGet(instanceHandle, &symStats);

    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "              Symmetric Stats               " BORDER
            "\n" SEPARATOR);

    /* Session Info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " Sessions Initialized:           %16llu " BORDER "\n" BORDER
                   " Sessions Removed:               %16llu " BORDER "\n" BORDER
                   " Session Errors:                 %16llu " BORDER
                   "\n" SEPARATOR,
            symStats.numSessionsInitialized,
            symStats.numSessionsRemoved,
            symStats.numSessionErrors);

    /* Session info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " Symmetric Requests:             %16llu " BORDER "\n" BORDER
                   " Symmetric Request Errors:       %16llu " BORDER "\n" BORDER
                   " Symmetric Completed:            %16llu " BORDER "\n" BORDER
                   " Symmetric Completed Errors:     %16llu " BORDER "\n" BORDER
                   " Symmetric Verify Failures:      %16llu " BORDER
                   "\n" SEPARATOR,
            symStats.numSymOpRequests,
            symStats.numSymOpRequestErrors,
            symStats.numSymOpCompleted,
            symStats.numSymOpCompletedErrors,
            symStats.numSymOpVerifyFailures);
}
