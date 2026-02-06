/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
#include "cpa.h"
#include "icp_accel_devices.h"

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
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userProcessStop(void);

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
 * icp_adf_userGetNumPfs
 *
 * Description:
 *  Returns the number of PFs in the system, only returned if the process has
 *  privileges to access the QAT debugfs/sysfs entries.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userGetNumPfs(Cpa16U *pNumPFs);

/*
 * icp_adf_userGetPfInfo
 *
 * Description:
 *  Populates a pre-allocated list of PF info.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_userGetPfInfo(icp_accel_pf_info_t *pPfInfo);

/*
 * icp_adf_userCheckDevice
 *
 * Description:
 *  Function checks the status of the firmware/hardware for a given device.
 *  This function is used as part of the heartbeat functionality.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS     on success
 *   CPA_STATUS_FAIL        on failure
 *   CPA_STATUS_UNSUPPORTED on unsupported
 */
CpaStatus icp_adf_userCheckDevice(Cpa32U packageId);

/*
 * icp_adf_userCheckAllDevices
 *
 * Description:
 *  Function checks the status of the firmware/hardware for all devices.
 *  This function is used as part of the heartbeat functionality.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS     on success
 *   CPA_STATUS_FAIL        on failure
 *   CPA_STATUS_UNSUPPORTED on unsupported
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
CpaStatus icp_adf_heartbeatSimulateFailure(Cpa32U packageId);

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
