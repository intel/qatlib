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
 * @file dev_info.c
 *
 * @defgroup cpaDev
 *
 * @description
 *    This file contains implementation of functions for device level APIs
 *
 *****************************************************************************/
/* Osal includes */
#include "Osal.h"

/* QAT-API includes */
#include "cpa_dev.h"
#include "icp_accel_devices.h"
#include "adf_user_cfg.h"
#include "lac_common.h"
#include "icp_adf_cfg.h"
#include "lac_sal_types.h"
#include "icp_adf_accel_mgr.h"
#include "icp_platform.h"
#include "sal_string_parse.h"
#include "adf_devmgr.h"
#include "lac_sal.h"

CpaStatus cpaGetNumDevices(Cpa16U *numDevices)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(numDevices);
#endif

    return icp_adf_getNumInstances(numDevices);
}

CpaStatus cpaGetDeviceInfo(Cpa16U device, CpaDeviceInfo *deviceInfo)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t *pDevice = NULL;
    Cpa16U numDevicesAvail = 0;
    Cpa32U capabilitiesMask = 0;
    Cpa32U enabledServices = 0;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(deviceInfo);
#endif
    icp_adf_getNumInstances(&numDevicesAvail);
    /* Check if the application is not attempting to access a
     * device that does not exist.
     */
    if (0 == numDevicesAvail)
    {
        LAC_LOG_ERROR("Failed to retrieve number of devices!");
        return CPA_STATUS_FAIL;
    }
    if (device >= numDevicesAvail)
    {
        LAC_LOG_ERROR1("Invalid device access! Number of devices "
                       "available: %d",
                       numDevicesAvail);
        return CPA_STATUS_FAIL;
    }

    /* Clear the entire capability structure before initialising it */
    osalMemSet(deviceInfo, sizeof(CpaDeviceInfo), 0x00);
    /* Bus/Device/Function should be 0xFF until initialised */
    deviceInfo->bdf = 0xffff;

    pDevice = icp_adf_getAccelDevByAccelId(device);
    if (NULL == pDevice)
    {
        LAC_LOG_ERROR("Failed to retrieve device");
        return CPA_STATUS_FAIL;
    }

    /* Device of interest is found, retrieve the information for it */
    deviceInfo->sku = pDevice->sku;
    deviceInfo->deviceId = pDevice->pciDevId;
    deviceInfo->bdf = icp_adf_cfgGetBusAddress(pDevice->accelId);
    deviceInfo->numaNode = pDevice->numa_node;

    deviceInfo->isVf = pDevice->isVf;

    status = SalCtrl_GetEnabledServices(pDevice, &enabledServices);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to retrieve enabled services!");
        return status;
    }

    status = icp_adf_getAccelDevCapabilities(pDevice, &capabilitiesMask);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to retrieve accel capabilities mask!");
        return status;
    }

    /* Determine if Compression service is enabled */
    if (enabledServices & SAL_SERVICE_TYPE_COMPRESSION)
    {
        deviceInfo->dcEnabled =
            (((capabilitiesMask & ICP_ACCEL_CAPABILITIES_COMPRESSION) != 0)
                 ? CPA_TRUE
                 : CPA_FALSE);
    }

    /* Determine if Inline service is enabled */
    if (enabledServices & SAL_SERVICE_TYPE_INLINE)
    {
        deviceInfo->inlineEnabled =
            (((capabilitiesMask & ICP_ACCEL_CAPABILITIES_INLINE) != 0)
                 ? CPA_TRUE
                 : CPA_FALSE);
    }

    /* Determine if Crypto service is enabled */
    if (enabledServices & SAL_SERVICE_TYPE_CRYPTO)
    {
        deviceInfo->cySymEnabled =
            (((capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC))
                 ? CPA_TRUE
                 : CPA_FALSE);
        deviceInfo->cyAsymEnabled =
            (((capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) !=
              0)
                 ? CPA_TRUE
                 : CPA_FALSE);
    }
    /* Determine if Crypto Sym service is enabled */
    if (enabledServices & SAL_SERVICE_TYPE_CRYPTO_SYM)
    {
        deviceInfo->cySymEnabled =
            (((capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC))
                 ? CPA_TRUE
                 : CPA_FALSE);
    }
    /* Determine if Crypto Asym service is enabled */
    if (enabledServices & SAL_SERVICE_TYPE_CRYPTO_ASYM)
    {
        deviceInfo->cyAsymEnabled =
            (((capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) !=
              0)
                 ? CPA_TRUE
                 : CPA_FALSE);
    }
    deviceInfo->deviceMemorySizeAvailable = pDevice->deviceMemAvail;

    return status;
}
