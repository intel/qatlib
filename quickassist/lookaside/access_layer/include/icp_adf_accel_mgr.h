/*****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
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
 *
 *****************************************************************************/

/*****************************************************************************
 * @file icp_adf_accel_mgr.h
 *
 * @description
 *      This file contains the function prototype for accel
 *      instances management
 *
 *****************************************************************************/
#ifndef ICP_ADF_ACCEL_MGR_H
#define ICP_ADF_ACCEL_MGR_H

#include "cpa.h"
#include "icp_accel_devices.h"

/*
 * Device reset mode type.
 * If device reset is triggered from atomic context
 * it needs to be in ICP_ADF_DEV_RESET_ASYNC mode.
 * Otherwise can be either.
 */
typedef enum icp_adf_dev_reset_mode_e
{
    ICP_ADF_DEV_RESET_ASYNC = 0,
    ICP_ADF_DEV_RESET_SYNC
} icp_adf_dev_reset_mode_t;

/*
 * icp_adf_resetDev
 *
 * Description:
 * Function resets the given device.
 * If device reset is triggered from atomic context
 * it needs to be in ICP_ADF_DEV_RESET_ASYNC mode.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_resetDev(icp_accel_dev_t *accel_dev,
                           icp_adf_dev_reset_mode_t mode);

/*
 * icp_adf_isDevInError
 *
 * Description:
 * Check if device is in error state.
 *
 * Returns:
 *   CPA_TRUE   device is in error state
 *   CPA_FALSE  device is not in error state
 */
CpaBoolean icp_adf_isDevInError(icp_accel_dev_t *accel_dev);

/*
 * icp_adf_getNumInstances
 *
 * Description:
 * Returns number of accel instances in the system.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_getNumInstances(Cpa16U *pNumInstances);

/*
 * icp_adf_getInstances
 *
 * Description:
 * Returns table of accel instances in the system.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_getInstances(Cpa16U numInstances,
                               icp_accel_dev_t **pAccel_devs);
/*
 * icp_adf_getAccelDevByCapabilities
 *
 * Description:
 * Returns a started accel device that implements the capabilities
 * specified in capabilitiesMask.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_getAccelDevByCapabilities(Cpa32U capabilitiesMask,
                                            icp_accel_dev_t **pAccel_devs,
                                            Cpa16U *pNumInstances);
/*
 * icp_adf_getAllAccelDevByCapabilities
 *
 * Description:
 * Returns table of accel devices that are started and implement
 * the capabilities specified in capabilitiesMask.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 */
CpaStatus icp_adf_getAllAccelDevByCapabilities(Cpa32U capabilitiesMask,
                                               icp_accel_dev_t **pAccel_devs,
                                               Cpa16U *pNumInstances);

/*
 * icp_adf_getAllAccelDevByEachCapability
 *
 * Description:
 * Returns table of accel devices that are started and implement
 * each of the capability specified in capabilitiesMask.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_getAllAccelDevByEachCapability(Cpa32U capabilitiesMask,
                                                 icp_accel_dev_t **pAccel_devs,
                                                 Cpa16U *pNumInstances);

/*
 * icp_adf_getAccelDevCapabilities
 * Returns accel devices capabilities specified in capabilitiesMask.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_getAccelDevCapabilities(icp_accel_dev_t *accel_dev,
                                          Cpa32U *pCapabilitiesMask);

/*
 * icp_adf_qaDevGet
 *
 * Description:
 * Function increments the device usage counter.
 *
 * Returns: void
 */
void icp_adf_qaDevGet(icp_accel_dev_t *pDev);

/*
 * icp_adf_qaDevPut
 *
 * Description:
 * Function decrements the device usage counter.
 *
 * Returns: void
 */
void icp_adf_qaDevPut(icp_accel_dev_t *pDev);

/*
 * icp_adf_getAccelDevByAccelId
 *
 * Description:
 * Gets the accel_dev structure based on accelId
 *
 * Returns: a pointer to the accelerator structure or NULL if not found.
 */
icp_accel_dev_t *icp_adf_getAccelDevByAccelId(Cpa32U accelId);

/*
 * icp_adf_getNumDevices
 *
 * Description:
 * This function is used to determine the number of acceleration devices.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_getNumDevices(Cpa32U *num_dev);

/*
 * icp_adf_checkDevId
 *
 * Description:
 * This function checks the validity of a device id
 *
 * Returns:
 *   CPA_TRUE             if the dev_id provided is valid
 *   CPA_FALSE            if the dev_id is invalid
 */
CpaBoolean icp_adf_isDevIdValid(Cpa32U dev_id);

#endif /* ICP_ADF_ACCEL_MGR_H */
