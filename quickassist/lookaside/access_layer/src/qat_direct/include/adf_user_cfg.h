/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef ADF_USER_CFG_H
#define ADF_USER_CFG_H

#include "icp_accel_devices.h"

CpaStatus icp_adf_cfgGetParamValue(icp_accel_dev_t *accel_dev,
                                   const char *section,
                                   const char *param,
                                   char *value);
Cpa16U icp_adf_cfgGetBusAddress(Cpa16U accelId);
Cpa32S icp_adf_cfgGetDomainAddress(Cpa16U accelId);
int icp_adf_cfgCheckUserSection(int dev_id, uint8_t *pSectionPresent);

#endif /* end of include guard: ADF_USER_CFG_H */
