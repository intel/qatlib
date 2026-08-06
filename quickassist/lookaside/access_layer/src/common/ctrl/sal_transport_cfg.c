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
 ***************************************************************************
 * @file sal_transport_cfg.c
 *
 * @description
 *   This file contains implementation of ResponseMode APIs
 *   allowing to configure an instance for POLL / EPOLL modes.
 *
 ***************************************************************************/

#include "adf_dev_ring_ctl.h"
#include "cpa.h"

#include "lac_sal_types.h"
#include "lac_common.h"
#include "sal_types_compression.h"
#include "lac_log.h"
#include "lac_sal_types_crypto.h"

STATIC CpaStatus SalCtrl_GetTransHandleRx(
    const CpaInstanceHandle instanceHandle,
    const CpaAccelerationServiceType accelerationServiceType,
    icp_comms_trans_handle *pTrans_handle_rx)
{
    sal_compression_service_t *pCompressionService = NULL;
    sal_crypto_service_t *pCyService = NULL;

    switch (accelerationServiceType)
    {
        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
            pCyService = (sal_crypto_service_t *)instanceHandle;
            if (pCyService->generic_service_info.type !=
                    SAL_SERVICE_TYPE_CRYPTO_SYM &&
                pCyService->generic_service_info.type !=
                    SAL_SERVICE_TYPE_CRYPTO)
            {
                LAC_LOG_ERROR("Invalid Service Type");
                return CPA_STATUS_INVALID_PARAM;
            }
            *pTrans_handle_rx = pCyService->trans_handle_sym_rx;
            break;
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
            pCyService = (sal_crypto_service_t *)instanceHandle;
            if (pCyService->generic_service_info.type !=
                    SAL_SERVICE_TYPE_CRYPTO_ASYM &&
                pCyService->generic_service_info.type !=
                    SAL_SERVICE_TYPE_CRYPTO)
            {
                LAC_LOG_ERROR("Invalid Service Type");
                return CPA_STATUS_INVALID_PARAM;
            }
            *pTrans_handle_rx = pCyService->trans_handle_asym_rx;
            break;
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
            pCompressionService = (sal_compression_service_t *)instanceHandle;
            *pTrans_handle_rx =
                pCompressionService->trans_handle_compression_rx;
            break;
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            pCompressionService = (sal_compression_service_t *)instanceHandle;
            *pTrans_handle_rx =
                pCompressionService->trans_handle_decompression_rx;
            break;
        default:
            LAC_LOG_ERROR("Invalid Acceleration Service Type");
            return CPA_STATUS_INVALID_PARAM;
    }

    if (!*pTrans_handle_rx)
    {
        LAC_LOG_ERROR("pTrans_handle_rx is NULL");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaInstanceSetResponseMode(
    const CpaInstanceHandle instanceHandle,
    const CpaAccelerationServiceType accelerationServiceType,
    const CpaInstanceResponseMode responseMode)
{
    icp_comms_trans_handle trans_handle_rx[2] = { NULL, NULL };
    sal_compression_service_t *pCompressionService = NULL;
    sal_compression_service_t *pDecompressionService = NULL;
    sal_crypto_service_t *pCyService = NULL;
    CpaBoolean irq_enable = CPA_FALSE;
    Cpa8U *pIsPolled = NULL;
    int i, num_handles = 1;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, %d, %d)\n",
             (LAC_ARCH_UINT)instanceHandle,
             accelerationServiceType,
             responseMode);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(instanceHandle);
#endif

    switch (responseMode)
    {
        case CPA_INST_RX_NOTIFY_NONE:
            irq_enable = CPA_FALSE;
            break;
        case CPA_INST_RX_NOTIFY_BY_EVENT:
            irq_enable = CPA_TRUE;
            break;
        default:
            LAC_LOG_ERROR("Invalid Response Mode");
            return CPA_STATUS_UNSUPPORTED;
    }

    switch (accelerationServiceType)
    {
        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
            pCyService = (sal_crypto_service_t *)instanceHandle;
            if (pCyService->generic_service_info.type !=
                SAL_SERVICE_TYPE_CRYPTO_SYM)
            {
                LAC_LOG_ERROR("Invalid Service Type");
                return CPA_STATUS_INVALID_PARAM;
            }
            trans_handle_rx[0] = pCyService->trans_handle_sym_rx;
            pIsPolled = &pCyService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
            pCyService = (sal_crypto_service_t *)instanceHandle;
            if (pCyService->generic_service_info.type !=
                SAL_SERVICE_TYPE_CRYPTO_ASYM)
            {
                LAC_LOG_ERROR("Invalid Service Type");
                return CPA_STATUS_INVALID_PARAM;
            }
            trans_handle_rx[0] = pCyService->trans_handle_asym_rx;
            pIsPolled = &pCyService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_CRYPTO:
            pCyService = (sal_crypto_service_t *)instanceHandle;
            if (pCyService->generic_service_info.type !=
                SAL_SERVICE_TYPE_CRYPTO)
            {
                LAC_LOG_ERROR("Invalid Service Type");
                return CPA_STATUS_INVALID_PARAM;
            }
            trans_handle_rx[0] = pCyService->trans_handle_sym_rx;
            trans_handle_rx[1] = pCyService->trans_handle_asym_rx;
            num_handles = 2; /* Only crypto has 2 handles */
            pIsPolled = &pCyService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
            pCompressionService = (sal_compression_service_t *)instanceHandle;
            trans_handle_rx[0] =
                pCompressionService->trans_handle_compression_rx;
            pIsPolled = (Cpa8U *)&pCompressionService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            pDecompressionService = (sal_compression_service_t *)instanceHandle;
            trans_handle_rx[0] =
                pDecompressionService->trans_handle_decompression_rx;
            pIsPolled = (Cpa8U *)&pDecompressionService->isPolled;
            break;
        default:
            LAC_LOG_ERROR("Invalid Acceleration Service Type");
            return CPA_STATUS_INVALID_PARAM;
    }

    for (i = 0; i < num_handles; i++)
    {
        CpaStatus inflight_status = CPA_STATUS_SUCCESS;
        Cpa32U maxInflightRequests = 0;
        Cpa32U numInflightRequests = 0;

        if (!trans_handle_rx[i])
        {
            LAC_LOG_ERROR("trans_handle_rx is NULL");
            return CPA_STATUS_FAIL;
        }

        /* Check for inflight requests before switching mode */
        inflight_status = icp_adf_getInflightRequests(
            trans_handle_rx[i], &maxInflightRequests, &numInflightRequests);
        if (CPA_STATUS_SUCCESS != inflight_status)
        {
            LAC_LOG_ERROR1("Failed to get inflight requests (status=%d)",
                           inflight_status);
            return CPA_STATUS_FAIL;
        }

        if (numInflightRequests > 0)
        {
            LAC_LOG_ERROR1(
                "Cannot switch response mode with %u inflight requests",
                numInflightRequests);
            return CPA_STATUS_RETRY;
        }
        (void)maxInflightRequests;

        if (CPA_STATUS_SUCCESS !=
            icp_adf_transSetRespMode(trans_handle_rx[i], irq_enable))
        {
            LAC_LOG_ERROR("icp_adf_transSetRespMode() failed");
            return CPA_STATUS_FAIL;
        }
    }
    *pIsPolled = irq_enable ? SAL_RESP_EPOLL_CFG_FILE : SAL_RESP_POLL_CFG_FILE;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaInstanceGetResponseMode(
    const CpaInstanceHandle instanceHandle,
    const CpaAccelerationServiceType accelerationServiceType,
    CpaInstanceResponseMode *responseMode)
{
    sal_compression_service_t *pCompressionService = NULL;
    sal_compression_service_t *pDecompressionService = NULL;
    sal_crypto_service_t *pCyService = NULL;
    Cpa8U isPolled = SAL_RESP_POLL_CFG_FILE;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, %d, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             accelerationServiceType,
             (LAC_ARCH_UINT)responseMode);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(instanceHandle);
    LAC_CHECK_NULL_PARAM(responseMode);
#endif
    *responseMode = CPA_INST_RX_NOTIFY_NONE;

    switch (accelerationServiceType)
    {
        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
            pCyService = (sal_crypto_service_t *)instanceHandle;
            isPolled = pCyService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
            pCompressionService = (sal_compression_service_t *)instanceHandle;
            isPolled = pCompressionService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            pDecompressionService = (sal_compression_service_t *)instanceHandle;
            isPolled = pDecompressionService->isPolled;
            break;
        default:
            LAC_LOG_ERROR("Invalid Acceleration Service Type");
            return CPA_STATUS_INVALID_PARAM;
    }

    if (isPolled == SAL_RESP_EPOLL_CFG_FILE)
    {
        *responseMode = CPA_INST_RX_NOTIFY_BY_EVENT;
    }
    else if (isPolled == SAL_RESP_POLL_CFG_FILE)
    {
        *responseMode = CPA_INST_RX_NOTIFY_NONE;
    }
    else
    {
        LAC_LOG_ERROR("Invalid Poll Mode");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaInstanceSetIntCoalescingTimer(
    const CpaInstanceHandle instanceHandle,
    const CpaAccelerationServiceType accelerationServiceType,
    const Cpa32U coalescingTimerInNs)
{
    /*
     * CPA_ACC_SVC_TYPE_CRYPTO is not valid here; callers must use
     * CPA_ACC_SVC_TYPE_CRYPTO_SYM or CPA_ACC_SVC_TYPE_CRYPTO_ASYM.
     * SalCtrl_GetTransHandleRx returns CPA_STATUS_INVALID_PARAM for it.
     */
    icp_comms_trans_handle trans_handle_rx = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, %d, %u)\n",
             (LAC_ARCH_UINT)instanceHandle,
             accelerationServiceType,
             coalescingTimerInNs);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(instanceHandle);
#endif

    status = SalCtrl_GetTransHandleRx(
        instanceHandle, accelerationServiceType, &trans_handle_rx);
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            icp_adf_transSetIntCoalTimer(trans_handle_rx, coalescingTimerInNs);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to set interrupt coalescing "
                          "information for the instance");
        }
    }

    return status;
}

CpaStatus cpaInstanceGetRxInterruptMetaData(
    const CpaInstanceHandle instanceHandle,
    const CpaAccelerationServiceType accelerationServiceType,
    CpaRxInterruptMetaData *pInterruptData)
{
    icp_comms_trans_handle trans_handle_rx = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, %d, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             accelerationServiceType,
             (LAC_ARCH_UINT)pInterruptData);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(instanceHandle);
    LAC_CHECK_NULL_PARAM(pInterruptData);
#endif

    status = SalCtrl_GetTransHandleRx(
        instanceHandle, accelerationServiceType, &trans_handle_rx);
    if (CPA_STATUS_SUCCESS == status)
    {
        status = icp_adf_transGetIntCoalTimerData(
            trans_handle_rx,
            &pInterruptData->coalescingTimerInNs,
            &pInterruptData->coalescingTimerMaxInNs,
            &pInterruptData->coalescingTimerGranularityInNs);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to get interrupt coalescing "
                          "information for the instance");
        }
        else
        {
            pInterruptData->reserved1 = 0;
            pInterruptData->reserved2 = 0;
        }
    }

    return status;
}
