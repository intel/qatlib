/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/
/******************************************************************************
 * @file icp_adf_cfg.h
 *
 * @defgroup icp_AdfCfg Acceleration Driver Framework Configuration Interface.
 *
 * @ingroup icp_Adf
 *
 * @description
 *      This is the top level header file for the run-time system configuration
 *      parameters. This interface may be used by components of this API to
 *      access the supported run-time configuration parameters.
 *
 *****************************************************************************/

#ifndef ICP_ADF_CFG_H
#define ICP_ADF_CFG_H

#include "cpa.h"
#include "icp_accel_devices.h"

/******************************************************************************
 * Section for #define's & typedef's
 ******************************************************************************/
/* MMP firmware version */
#ifndef ADF_MMP_VER_KEY
#define ADF_MMP_VER_KEY ("Firmware_MmpVer")
#endif
/* UOF firmware version */
#ifndef ADF_UOF_VER_KEY
#define ADF_UOF_VER_KEY ("Firmware_UofVer")
#endif
/* Hardware rev id */
#ifndef ADF_HW_REV_ID_KEY
#define ADF_HW_REV_ID_KEY ("HW_RevId")
#endif
/* Lowest Compatible Driver Version */
#define ICP_CFG_LO_COMPATIBLE_DRV_KEY ("Lowest_Compat_Drv_Ver")
/* Device node id, tells to which die the device is connected to */
#define ADF_DEV_NODE_ID ("Device_NodeId")
/* Device package id, this is accel_dev id */
#define ADF_DEV_PKG_ID ("Device_PkgId")

/*
 * icp_adf_cfgGetParamValue
 *
 * Description:
 * This function is used to determine the value for a given parameter name.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_cfgGetParamValue(icp_accel_dev_t *accel_dev,
                                   const char *section,
                                   const char *param_name,
                                   char *param_value);
/*
 * icp_adf_cfgGetRingNumber
 *
 * Description:
 * Function returns ring number configured for the service.
 * NOTE: this function will only be used by QATAL in kernelspace.
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_cfgGetRingNumber(icp_accel_dev_t *accel_dev,
                                   const char *section_name,
                                   const Cpa32U accel_num,
                                   const Cpa32U bank_num,
                                   const char *pServiceName,
                                   Cpa32U *pRingNum);

/*
 * icp_adf_getBusAddress
 * Gets the B.D.F. of the accelerator device.
 */
Cpa16U icp_adf_getBusAddress(Cpa16U accelId);

#endif /* ICP_ADF_CFG_H */
