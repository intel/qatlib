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
 * @file adf_io_cfg.h
 *
 * @defgroup adf_io
 *
 * @description
 *      This file contains defines the low level API of the configuration
 *      module in adf user.
 *
 *****************************************************************************/
#ifndef ADF_IO_CFG
#define ADF_IO_CFG

#include "cpa.h"
#include "icp_accel_devices.h"

/*
 * Error code for functions which return variable of Cpa32S type
 */
#define ADF_IO_OPERATION_FAIL_CPA32S -1

/*
 * Error code for functions which return variable of Cpa16U type
 */
#define ADF_IO_OPERATION_FAIL_U16 0xFFFF

/**
 * @ingroup adf_io
 *
 * @description
 *      This function returns the number of acceleration devices that
 *      are addressable by the current user space process.
 *
 * @param[in] num_devices    Pointer to integer allocated by the caller.
 *                           This location will be updated by this function
 *                           with the number of available devices.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  An invalid parameter was passed as input
 *                                   to the function.
 * @retval CPA_STATUS_UNSUPPORTED    This function is not supported for given
 *                                   target platform.
 */
CpaStatus adf_io_getNumDevices(unsigned int *num_devices);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function returns the value of a configured parameter for
 *      a particular accelerator.
 *
 * @param[in] accel_dev      Pointer to an icp_accel_dev_t structure.
 * @param[in] pSection       Null terminated string that contains the section
 *                           name associated to the parameter.
 * @param[in] pParamName     Null terminated string that contains the parameter
 *                           to query.
 * @param[out] pParamValue   Pointer to a string allocated by the caller
 *                           of size ADF_CFG_MAX_VAL_LEN_IN_BYTES. If the
 *                           function is successful, this will contain the
 *                           value of the parameter queried.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_INVALID_PARAM  An invalid parameter was passed as input
 *                                   to the function.
 * @retval CPA_STATUS_FAIL           Function failed. This might occur if
 *                                   the requested parameter is not present
 *                                   in the database.
 */
CpaStatus adf_io_cfgGetParamValue(icp_accel_dev_t *accel_dev,
                                  const char *pSection,
                                  const char *pParamName,
                                  char *pParamValue);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function returns the domain address associated to an accelerator.
 *
 * @param[in] accelId        Id of the accelerator.
 *
 * @retval Cpa32S            Domain address of the accelerator.
 * @retval -1                Function failed.
 */
Cpa32S adf_io_cfgGetDomainAddress(Cpa16U accelId);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function returns the Bus Device Function (BDF) encoded in two
 *      bytes associated to an accelerator.
 *
 * @param[in] accelId        Id of the accelerator.
 *
 * @retval Cpa16U            Bus Device Function of the accelerator.
 * @retval 0xFFFF            Function failed.
 */
Cpa16U adf_io_cfgGetBusAddress(Cpa16U accelId);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function checks if user process section
 *      exists in device cfg.
 *
 * @param[in] dev_id           Id of the accelerator device to be checked.
 * @param[out] pSectionPresent Pointer to the check result.
 * @retval 0                   Function executed successfully, the result is
 *                             present in *pSectionPresent.
 * @retval < 0                 Function failed.
 */
int adf_io_cfgCheckUserSection(int dev_id, uint8_t *pSectionPresent);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function resets the accelerator device.
 *
 * @param[in] accelId        Id of the accelerator device to be reset.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully, the device
 *                                   has been reset.
 * @retval CPA_STATUS_UNSUPPORTED    This function is not supported.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_RETRY          Device is busy and reset is not possible.
 */
CpaStatus adf_io_reset_device(Cpa32U accelId);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function checks if there is an available device
 *
 * @retval CPA_TRUE          At least one device is available.
 * @retval CPA_FALSE         No available devices found.
 */
CpaBoolean adf_io_isDeviceAvailable(void);

/**
 * @ingroup adf_io
 *
 * @description
 *      Function returns the number of PFs in the system
 *
 * @retval Cpa16U            The number of PFs.
 */
Cpa16U adf_io_getNumPfs(void);

/**
 * @ingroup adf_io
 *
 * @description
 *      Populates a pre-allocated list of PF info, only returned if the process
 *      has privileges to access the QAT debugfs/sysfs entries.
 *
 * @param[out] pPfInfo               Pre-allocated list of PF info, the size of
 *                                   this should match the number of PFs on
 *                                   the platform.
 *
 * @retval CPA_STATUS_FAIL           No PFs detected.
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 */
CpaStatus adf_io_getPfInfo(icp_accel_pf_info_t *pPfInfo);

/**
 * @ingroup adf_io
 *
 * @description
 *      Function checks the status of the firmware/hardware
 *
 * @param[in] accelId        Id of the accelerator device.
 *
 * @retval CPA_STATUS_UNSUPPORTED    This function is not supported.
 * @retval CPA_STATUS_FAIL           Device is Non-Responsive.
 * @retval CPA_STATUS_SUCCESS        Device is Alive.
 */
CpaStatus adf_io_getHeartBeatStatus(Cpa32U packageId);

#ifdef ICP_HB_FAIL_SIM
/**
 * @ingroup adf_io
 *
 * @description
 *      Function helps simulate heartbeat failure
 *
 * @param[in] accelId        Id of the accelerator device.
 *
 * @retval CPA_STATUS_UNSUPPORTED    This function is not supported.
 * @retval CPA_STATUS_FAIL           Failure simulation failed for device.
 * @retval CPA_STATUS_SUCCESS        Failure simulation successful for device.
 */
CpaStatus adf_io_heartbeatSimulateFailure(Cpa32U packageId);
#endif

#endif
