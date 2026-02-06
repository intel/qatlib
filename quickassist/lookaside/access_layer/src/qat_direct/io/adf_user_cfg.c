/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#include "cpa.h"
#include "adf_io_cfg.h"
#include "icp_adf_accel_mgr.h"

CpaStatus icp_adf_cfgGetParamValue(icp_accel_dev_t *accel_dev,
                                   const char *pSection,
                                   const char *pParamName,
                                   char *pParamValue)
{
    return adf_io_cfgGetParamValue(
        accel_dev, pSection, pParamName, pParamValue);
}

Cpa32S icp_adf_cfgGetDomainAddress(Cpa16U accelId)
{
    return adf_io_cfgGetDomainAddress(accelId);
}

Cpa16U icp_adf_cfgGetBusAddress(Cpa16U accelId)
{
    return adf_io_cfgGetBusAddress(accelId);
}

/*
 * icp_adf_cfgCheckUserSection
 * check if user process section exists in device cfg
 */
int icp_adf_cfgCheckUserSection(int dev_id, uint8_t *pSectionPresent)
{
    return adf_io_cfgCheckUserSection(dev_id, pSectionPresent);
}

CpaStatus icp_adf_resetDevice(Cpa32U accelId)
{
    if (!icp_adf_isDevIdValid(accelId))
    {
        return CPA_STATUS_FAIL;
    }

    return adf_io_reset_device(accelId);
}

CpaBoolean icp_adf_isDeviceAvailable(void)
{
    return adf_io_isDeviceAvailable();
}
