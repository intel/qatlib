/******************************************************************************
 *
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
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
#define ADF_IO_OPERATION_FAIL_CPA16U 0xFFFF

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
 *      This function returns the domain address associated to an accelerator
 *      package.
 *
 * @param[in] packageId      Id of the package.
 *
 * @retval Cpa32S            Domain address of the accelerator.
 * @retval -1                Function failed.
 */
Cpa32S adf_io_cfgGetDomainAddress(Cpa16U packageId);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function returns the Bus Device Function (BDF) encoded in two
 *      bytes associated to an accelerator package.
 *
 * @param[in] packageId      Id of the package.
 *
 * @retval Cpa16U            Bus Device Function of the accelerator.
 * @retval -1                Function failed.
 */
Cpa16U adf_io_cfgGetBusAddress(Cpa16U packageId);

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

#endif
