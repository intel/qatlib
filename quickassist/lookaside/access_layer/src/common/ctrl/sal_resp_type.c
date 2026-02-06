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
 * @file sal_resp_type.c
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

CpaStatus cpaInstanceSetResponseMode(
    const CpaInstanceHandle instanceHandle,
    const CpaAccelerationServiceType accelerationServiceType,
    const CpaInstanceResponseMode responseMode)
{
    icp_comms_trans_handle trans_handle_rx[2] = {NULL, NULL};
    sal_compression_service_t *pCompressionService = NULL;
    sal_compression_service_t *pDecompressionService = NULL;
    sal_crypto_service_t *pCyService = NULL;
    CpaBoolean irq_enable = CPA_FALSE;
    Cpa8U *pIsPolled = NULL;
    int i, num_handles = 1;

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
            trans_handle_rx[0] = pCompressionService->trans_handle_compression_rx;
            pIsPolled = (Cpa8U *)&pCompressionService->isPolled;
            break;
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            pDecompressionService = (sal_compression_service_t *)instanceHandle;
            trans_handle_rx[0] = pDecompressionService->trans_handle_decompression_rx;
            pIsPolled = (Cpa8U *)&pDecompressionService->isPolled;
            break;
        default:
            LAC_LOG_ERROR("Invalid Acceleration Service Type");
            return CPA_STATUS_INVALID_PARAM;
    }

    for (i = 0; i < num_handles; i++)
    {
        if (!trans_handle_rx[i])
        {
            LAC_LOG_ERROR("trans_handle_rx is NULL");
            return CPA_STATUS_FAIL;
        }
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
