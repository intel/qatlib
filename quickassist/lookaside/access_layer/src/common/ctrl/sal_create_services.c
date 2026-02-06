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
 * @file sal_create_services.c
 *
 * @defgroup SalCtrl Service Access Layer Controller
 *
 * @ingroup SalCtrl
 *
 * @description
 *      This file contains the main function to create a specific service.
 *
 *****************************************************************************/

#include "cpa.h"
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "Osal.h"
#include "lac_list.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

#include "icp_qat_fw_la.h"
#include "lac_sym_qat.h"
#include "sal_types_compression.h"
#include "lac_sal_types_crypto.h"

#include "icp_adf_init.h"

#include "lac_sal.h"
#include "lac_sal_ctrl.h"

CpaStatus SalCtrl_ServiceCreate(sal_service_type_t serviceType,
                                Cpa32U instance,
                                sal_service_t **ppInst)
{
#ifndef ICP_DC_ONLY
    sal_crypto_service_t *pCrypto_service = NULL;
#endif
    sal_compression_service_t *pCompression_service = NULL;

    switch ((sal_service_type_t)serviceType)
    {
#ifndef ICP_DC_ONLY
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
        case SAL_SERVICE_TYPE_CRYPTO:
        {
            pCrypto_service = osalMemAlloc(sizeof(sal_crypto_service_t));
            if (NULL == pCrypto_service)
            {
                LAC_LOG_ERROR("Failed to allocate crypto service memory");
                *(ppInst) = NULL;
                return CPA_STATUS_RESOURCE;
            }

            /* Zero memory */
            osalMemSet(pCrypto_service, 0, sizeof(sal_crypto_service_t));
            pCrypto_service->generic_service_info.virt2PhysClient =
                osalMemAlloc(sizeof(CpaVirtualToPhysical));
            if (NULL == pCrypto_service->generic_service_info.virt2PhysClient)
            {
                LAC_LOG_ERROR("Failed to allocate address translation");
                osalMemFree(pCrypto_service);
                *(ppInst) = NULL;
                return CPA_STATUS_RESOURCE;
            }
            *(pCrypto_service->generic_service_info.virt2PhysClient) = 0;
            pCrypto_service->generic_service_info.type =
                (sal_service_type_t)serviceType;
            pCrypto_service->generic_service_info.state =
                SAL_SERVICE_STATE_UNINITIALIZED;
            pCrypto_service->generic_service_info.instance = instance;

            pCrypto_service->generic_service_info.init = SalCtrl_CryptoInit;
            pCrypto_service->generic_service_info.start = SalCtrl_CryptoStart;
            pCrypto_service->generic_service_info.stop = SalCtrl_CryptoStop;
            pCrypto_service->generic_service_info.shutdown =
                SalCtrl_CryptoShutdown;
            pCrypto_service->generic_service_info.error = SalCtrl_CryptoError;
            pCrypto_service->generic_service_info.restarting =
                SalCtrl_CryptoRestarting;
            pCrypto_service->generic_service_info.restarted =
                SalCtrl_CryptoRestarted;

            *(ppInst) = &(pCrypto_service->generic_service_info);

            return CPA_STATUS_SUCCESS;
        }
#endif
        case SAL_SERVICE_TYPE_COMPRESSION:
        case SAL_SERVICE_TYPE_DECOMPRESSION:
        {
            pCompression_service =
                osalMemAlloc(sizeof(sal_compression_service_t));
            if (NULL == pCompression_service)
            {
                LAC_LOG_ERROR("Failed to allocate compression service memory");
                *(ppInst) = NULL;
                return CPA_STATUS_RESOURCE;
            }

            /* Zero memory */
            osalMemSet(
                pCompression_service, 0, sizeof(sal_compression_service_t));
            pCompression_service->generic_service_info.virt2PhysClient =
                osalMemAlloc(sizeof(CpaVirtualToPhysical));
            if (NULL ==
                pCompression_service->generic_service_info.virt2PhysClient)
            {
                LAC_LOG_ERROR("Failed to allocate address translation");
                osalMemFree(pCompression_service);
                *(ppInst) = NULL;
                return CPA_STATUS_RESOURCE;
            }

            *(pCompression_service->generic_service_info.virt2PhysClient) = 0;
            pCompression_service->generic_service_info.type =
                (sal_service_type_t)serviceType;
            pCompression_service->generic_service_info.state =
                SAL_SERVICE_STATE_UNINITIALIZED;
            pCompression_service->generic_service_info.instance = instance;

            pCompression_service->generic_service_info.init =
                SalCtrl_CompressionInit;
            pCompression_service->generic_service_info.start =
                SalCtrl_CompressionStart;
            pCompression_service->generic_service_info.stop =
                SalCtrl_CompressionStop;
            pCompression_service->generic_service_info.shutdown =
                SalCtrl_CompressionShutdown;
            pCompression_service->generic_service_info.error =
                SalCtrl_CompressionError;
            pCompression_service->generic_service_info.restarting =
                SalCtrl_CompressionRestarting;
            pCompression_service->generic_service_info.restarted =
                SalCtrl_CompressionRestarted;

            *(ppInst) = &(pCompression_service->generic_service_info);
            return CPA_STATUS_SUCCESS;
        }

        default:
        {
            LAC_LOG_ERROR("Not a valid service type");
            (*ppInst) = NULL;
            return CPA_STATUS_FAIL;
        }
    }
}
