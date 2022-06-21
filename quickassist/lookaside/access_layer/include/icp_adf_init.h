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
 * @file icp_adf_init.h
 *
 * @description
 *      This file contains the function prototype used to register a subsystem
 *      into the Acceleration Driver Framework (ADF).
 *
 *****************************************************************************/
#ifndef ICP_ADF_INIT_H
#define ICP_ADF_INIT_H

#include "icp_accel_devices.h"
#include "adf_kernel_types.h"

/*
 * Ring info operation used to enable or disable ring polling by ME
 */
typedef enum icp_adf_ringInfoOperation_e
{
    ICP_ADF_RING_ENABLE = 0,
    ICP_ADF_RING_DISABLE
} icp_adf_ringInfoOperation_t;

/*
 * Ring generic serivce info private data
 */
typedef enum icp_adf_ringInfoService_e
{
    ICP_ADF_RING_SERVICE_0 = 0,
    ICP_ADF_RING_SERVICE_1,
    ICP_ADF_RING_SERVICE_2,
    ICP_ADF_RING_SERVICE_3,
    ICP_ADF_RING_SERVICE_4,
    ICP_ADF_RING_SERVICE_5,
    ICP_ADF_RING_SERVICE_6,
    ICP_ADF_RING_SERVICE_7,
    ICP_ADF_RING_SERVICE_8,
    ICP_ADF_RING_SERVICE_9,
    ICP_ADF_RING_SERVICE_10,
} icp_adf_ringInfoService_t;

/*
 * Ring info callback. Function is used to send operation and ring info
 * to enable or disable ring polling by ME
 */
typedef CpaStatus (*ringInfoCb)(icp_accel_dev_t *accel_dev,
                                Cpa32U ringNumber,
                                icp_adf_ringInfoOperation_t operation,
                                icp_adf_ringInfoService_t info);

/*
 * Registration handle structure
 * Each subservice has to have an instance of it.
 */
typedef struct subservice_registation_handle_s
{
    CpaStatus (*subserviceEventHandler)(icp_accel_dev_t *accel_dev,
                                        enum adf_event event,
                                        void *param);
    struct
    {
        Cpa32U subsystemInitBit : 1;
        Cpa32U subsystemStartBit : 1;
        Cpa32U subsystemFailedBit : 1;
    } subsystemStatus[ADF_MAX_DEVICES];
    char *subsystem_name;
    struct subservice_registation_handle_s *pNext;
    struct subservice_registation_handle_s *pPrev;
} subservice_registation_handle_t;

/*
 * icp_adf_subsystemRegister
 *
 * Description:
 *  Function used by subsystem to register within ADF
 *  Should be called during insertion of a subsystem
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_subsystemRegister(subservice_registation_handle_t *handle);

/*
 * icp_adf_subsystemUnregister
 *
 * Description:
 *  Function used by subsystem to unregister from ADF
 *  Should be called while subsystem in removed
 *  If the subsystem is initialised and/or started
 *  it will be stopped and shutdown by this function
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_subsystemUnregister(subservice_registation_handle_t *handle);

/*
 * icp_adf_isSubsystemStarted
 *
 * Description:
 * Function returns true if the service is started on a device
 *
 * Returns:
 *   CPA_TRUE   if subsystem is started
 *   CPA_FALSE  if subsystem is not started
 */
CpaBoolean icp_adf_isSubsystemStarted(
    subservice_registation_handle_t *subsystem_hdl);

/*
 * icp_adf_isDevStarted
 *
 * Description:
 * Function returns true if the device is started
 * Returns:
 *   CPA_TRUE   if dev is started
 *   CPA_FALSE  if dev is not started
 */
CpaBoolean icp_adf_isDevStarted(icp_accel_dev_t *accel_dev);

/*
 * adf_subsystemRestarting
 *
 * Description:
 * Function sends restarting event to all subsystems.
 * This function should be used by error handling funct. only
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus adf_subsystemRestarting(icp_accel_dev_t *accel_dev);

/*
 * adf_subsystemRestarted
 *
 * Description:
 * Function sends restarted event to all subsystems.
 * This function should be used by error handling funct. only
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus adf_subsystemRestarted(icp_accel_dev_t *accel_dev);

/*
 * adf_subsystemError
 *
 * Description:
 * Function sends error event to all subsystems.
 * This function should be used by error handling funct. only
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus adf_subsystemError(icp_accel_dev_t *accel_dev);

/*
 * icp_adf_resetSubsystemTable
 *
 * Description:
 * Function to reset subsystem table head, the pointer
 * to the head of the list and lock.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_resetSubsystemTable(void);

#endif /* ICP_ADF_INIT_H */
