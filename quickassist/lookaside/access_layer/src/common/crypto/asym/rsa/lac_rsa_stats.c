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
 * @file lac_rsa_stats.c
 *
 * @ingroup LacRsa
 *
 * @description This file implements functions for RSA stats.
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

/* Include API files */
#include "cpa.h"
#include "cpa_cy_rsa.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Osal include */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp_ids.h"

/* Include LAC files */
#include "lac_common.h"
#include "lac_pke_qat_comms.h"
#include "lac_pke_utils.h"
#include "lac_pke_mmp.h"
#include "lac_sym.h"
#include "lac_list.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "lac_rsa_p.h"
#include "sal_statistics.h"
#include "lac_rsa_stats_p.h"

/* Number of RSA statistics */
#define LAC_RSA_NUM_STATS32 (sizeof(CpaCyRsaStats) / sizeof(Cpa32U))
#define LAC_RSA_NUM_STATS (sizeof(CpaCyRsaStats64) / sizeof(Cpa64U))

CpaStatus LacRsa_StatsInit(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&(pCryptoService->pLacRsaStatsArr),
                           LAC_RSA_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_OS_BZERO(
            LAC_CONST_VOLATILE_PTR_CAST(pCryptoService->pLacRsaStatsArr),
            LAC_RSA_NUM_STATS * sizeof(OsalAtomic));
    }

    return status;
}

void LacRsa_StatsFree(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    if (NULL != pCryptoService->pLacRsaStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacRsaStatsArr);
    }
}

void LacRsa_StatsReset(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    LAC_OS_BZERO(LAC_CONST_VOLATILE_PTR_CAST(pCryptoService->pLacRsaStatsArr),
                 LAC_RSA_NUM_STATS * sizeof(OsalAtomic));
}

/**
 *****************************************************************************
 * @ingroup LacRsa
 *
 *****************************************************************************/
CpaStatus cpaCyRsaQueryStats(CpaInstanceHandle instanceHandle_in,
                             CpaCyRsaStats *pRsaStats)
{
    Cpa32U i = 0;
    sal_crypto_service_t *pCryptoService;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pRsaStats);
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
    LAC_CHECK_NULL_PARAM(pRsaStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    for (i = 0; i < LAC_RSA_NUM_STATS32; i++)
    {
        ((Cpa32U *)pRsaStats)[i] =
            (Cpa32U)osalAtomicGet(&pCryptoService->pLacRsaStatsArr[i]);
    }
    return CPA_STATUS_SUCCESS;
} /* cpaCyRsaQueryStats */

/**
 *****************************************************************************
 * @ingroup LacRsa
 *
 *****************************************************************************/
CpaStatus cpaCyRsaQueryStats64(CpaInstanceHandle instanceHandle_in,
                               CpaCyRsaStats64 *pRsaStats)
{
    Cpa32U i = 0;
    sal_crypto_service_t *pCryptoService;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pRsaStats);
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
    LAC_CHECK_NULL_PARAM(pRsaStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    for (i = 0; i < LAC_RSA_NUM_STATS; i++)
    {
        ((Cpa64U *)pRsaStats)[i] =
            osalAtomicGet(&pCryptoService->pLacRsaStatsArr[i]);
    }
    return CPA_STATUS_SUCCESS;
} /* cpaCyRsaQueryStats64 */

#ifndef DISABLE_STATS
void LacRsa_StatsInc(Cpa32U offset, CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (CPA_TRUE ==
        pCryptoService->generic_service_info.stats->bRsaStatsEnabled)
    {
        osalAtomicInc(
            &pCryptoService->pLacRsaStatsArr[offset / sizeof(Cpa64U)]);
    }
} /* LacRsa_StatIncrement */
#endif /* DISABLE_STATS */

void LacRsa_StatsShow(CpaInstanceHandle instanceHandle)
{
    CpaCyRsaStats64 rsaStats = {0};
    (void)cpaCyRsaQueryStats64(instanceHandle, &rsaStats);

    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "                  RSA Stats                 " BORDER
            "\n" SEPARATOR);

    /*Perform Info*/
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " RSA Key Gen Requests:           %16llu " BORDER "\n" BORDER
                   " RSA Key Gen Request Errors      %16llu " BORDER "\n" BORDER
                   " RSA Key Gen Completed:          %16llu " BORDER "\n" BORDER
                   " RSA Key Gen Completed Errors:   %16llu " BORDER
                   "\n" SEPARATOR,
            rsaStats.numRsaKeyGenRequests,
            rsaStats.numRsaKeyGenRequestErrors,
            rsaStats.numRsaKeyGenCompleted,
            rsaStats.numRsaKeyGenCompletedErrors);

    /*Perform Info*/
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " RSA Encrypt Requests:           %16llu " BORDER "\n" BORDER
                   " RSA Encrypt Request Errors:     %16llu " BORDER "\n" BORDER
                   " RSA Encrypt Completed:          %16llu " BORDER "\n" BORDER
                   " RSA Encrypt Completed Errors:   %16llu " BORDER
                   "\n" SEPARATOR,
            rsaStats.numRsaEncryptRequests,
            rsaStats.numRsaEncryptRequestErrors,
            rsaStats.numRsaEncryptCompleted,
            rsaStats.numRsaEncryptCompletedErrors);

    /*Perform Info*/
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " RSA Decrypt Requests:           %16llu " BORDER "\n" BORDER
                   " RSA Decrypt Request Errors:     %16llu " BORDER "\n" BORDER
                   " RSA Decrypt Completed:          %16llu " BORDER "\n" BORDER
                   " RSA Decrypt Completed Errors:   %16llu " BORDER
                   "\n" SEPARATOR,
            rsaStats.numRsaDecryptRequests,
            rsaStats.numRsaDecryptRequestErrors,
            rsaStats.numRsaDecryptCompleted,
            rsaStats.numRsaDecryptCompletedErrors);
}
