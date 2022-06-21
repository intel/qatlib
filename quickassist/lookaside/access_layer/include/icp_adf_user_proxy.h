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
 * @file icp_adf_user_proxy.h
 *
 * @description
 *      This file contains the function prototype to initialize ADF proxy
 *      in user space.
 *
 *****************************************************************************/
#ifndef ICP_ADF_USER_PROXY_H
#define ICP_ADF_USER_PROXY_H

/*
 * icp_adf_userProcessToStart
 *
 * Description:
 *  This function checks if a user space process with a given name has
 *  already been started.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userProcessToStart(const char *const name_tml, char *name);

/*
 * icp_adf_userProxyInit
 *
 * Description:
 *  This function is used to initialize the ADF proxy in user space.
 *  It takes a process name as a parameter. Caller should check if
 *  such process name is not already started using
 *  icp_adf_userProcessStarted function.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userProxyInit(const char *const name);

/*
 * icp_adf_userProxyShutdown
 *
 * Description:
 *  This function is used to shutdown the ADF proxy in user space.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userProxyShutdown(void);

/*
 * icp_adf_userProcessStop
 *
 * Description:
 *  This function closes the processes info file.
 *  It should be called before a process exits if icp_adf_userProcessToStart()
 *  has been used to obtain unique user process name.
 *
 * Returns: void
 */
void icp_adf_userProcessStop(void);

/*
 * icp_adf_userFindNewDevices
 *
 * Description:
 *  Function tries to connect to devices.
 *  This function is used in threadless mode in user space.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userFindNewDevices(void);

/*
 * icp_adf_pollDeviceEvents
 *
 * Description:
 *  Function polls new device events.
 *  This function is used in threadless mode in user space.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_pollDeviceEvents(void);

/*
 * icp_adf_userCheckDevice
 *
 * Description:
 *  Function checks the status of the firmware/hardware for a given device.
 *  This function is used as part of the heartbeat functionality.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userCheckDevice(Cpa32U accelId);

/*
 * icp_adf_userCheckAllDevices
 *
 * Description:
 *  Function checks the status of the firmware/hardware for all devices.
 *  This function is used as part of the heartbeat functionality.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userCheckAllDevices(void);

#ifdef ICP_HB_FAIL_SIM
/*
 * icp_adf_heartbeatSimulateFailure
 *
 * Description:
 *  Function simulates a heartbeat failure.
 *  If icp_adf_userCheckDevice is used along with this call, a heartbeat
 *  failure will be detected
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_heartbeatSimulateFailure(Cpa32U accelId);

#endif


/*
 * icp_adf_resetDevice
 *
 * Description:
 *  reset device - calls the IOCTL in
 *  the driver which resets the device based on accelId
 *
 * Returns:
 *   CPA_STATUS_SUCCESS on success
 *   CPA_STATUS_FAIL    on failure
 *   CPA_STATUS_UNSUPPORTED on unsupported
 */
CpaStatus icp_adf_resetDevice(Cpa32U accelId);

/*
 * icp_adf_mmap_misc_counter
 *
 * Description:
 *  Function mmap miscellaneous counter.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS on success
 *   CPA_STATUS_FAIL    on failure
 */
CpaStatus icp_adf_mmap_misc_counter(Cpa64U **miscCounter);

/*
 * icp_adf_unmap_misc_counter
 *
 * Description:
 *  Function unmap miscellaneous counter.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS on success
 *   CPA_STATUS_FAIL    on failure
 */
CpaStatus icp_adf_unmap_misc_counter(Cpa64U *miscCounter);

/*
 * icp_adf_isDeviceAvailable
 *
 * Description:
 *  check if there are available devices
 *
 * Returns:
 *   CPA_TRUE           on success - found available device
 *   CPA_FALSE          on failure
 */
CpaBoolean icp_adf_isDeviceAvailable(void);

#endif /* ICP_ADF_USER_PROXY_H */
