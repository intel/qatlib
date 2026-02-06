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
 *****************************************************************************
 * @file sal_misc_error_stats.c
 *
 * @defgroup SalMiscErrorStats   Sal Miscellaneous Error Statistics
 *
 * @ingroup SalMiscErrorStats
 *
 * @description
 *    This file contains implementation of Miscellaneous error statistic related
 *functions
 *
 *****************************************************************************/

#include "cpa.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "icp_adf_cfg.h"
#include "icp_accel_devices.h"
#include "sal_statistics.h"

#include "icp_adf_user_proxy.h"
#include "icp_adf_debug.h"
#include "lac_sal_types.h"
#include "lac_sal.h"

STATIC OsalAtomic *numMiscError;

/* @ingroup SalMiscErrorStats */
CpaStatus Sal_IncMiscErrStats(sal_service_t *pService)
{
    if (!pService)
    {
        LAC_LOG_ERROR("Invalid Parameter.\n");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (numMiscError && CPA_TRUE == pService->stats->bMiscStatsEnabled)
    {
        osalAtomicInc(numMiscError);
    }
    return CPA_STATUS_SUCCESS;
}

/* @ingroup SalMiscErrorStats */
CpaStatus Sal_GetMiscErrStats(sal_service_t *pService, OsalAtomic *pMiscStats)
{
    if (!pService || !pMiscStats)
    {
        LAC_LOG_ERROR("Invalid Parameter.\n");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (numMiscError && CPA_TRUE == pService->stats->bMiscStatsEnabled)
    {
        *(Cpa64U *)pMiscStats = osalAtomicGet(numMiscError);
    }
    else
    {
        return CPA_STATUS_RESOURCE;
    }

    return CPA_STATUS_SUCCESS;
}

/* @ingroup SalMiscErrorStats */
CpaStatus Sal_InitMiscErrStats(sal_statistics_collection_t *pStats)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (!numMiscError && pStats && CPA_TRUE == pStats->bStatsEnabled)
    {
        icp_adf_mmap_misc_counter((Cpa64U **)&numMiscError);
    }
    return status;
}

/* @ingroup SalMiscErrorStats */
CpaStatus Sal_CleanMiscErrStats(sal_service_t *pService)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (numMiscError && pService && pService->stats &&
        CPA_TRUE == pService->stats->bMiscStatsEnabled)
    {
        icp_adf_unmap_misc_counter((Cpa64U *)numMiscError);
        numMiscError = NULL;
    }
    return status;
}
