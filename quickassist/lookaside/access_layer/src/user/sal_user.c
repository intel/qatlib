/***************************************************************************
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
 ***************************************************************************/

/**
 *****************************************************************************
 * @file sal_user.c
 *
 * @defgroup SalUser
 *
 * @description
 *    This file contains implementation of functions to start/stop user process
 *
 *****************************************************************************/

/* QAT-API includes */
#include "cpa.h"
#include "cpa_dc.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_accel_devices.h"
#include "icp_adf_accel_mgr.h"
#include "icp_adf_user_proxy.h"
#include "icp_adf_transport.h"
#include "icp_adf_cfg.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"

/* SAL includes */
#include "icp_sal_user.h"
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#ifndef ICP_DC_ONLY
#include "lac_sal_types_crypto.h"
#endif
#include "sal_types_compression.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "dc_session.h"

static OsalMutex sync_lock;
#define START_REF_COUNT_MAX 64
CpaStatus icp_adf_resetUserProxy(void);

/* Start reference count to keep track of multiple calls to
 * icp_sal_userStartMulti() and icp_sal_userStop() from the same application.
 * Only the first call to start will map the instances and
 * the last call to stop will free them.
 * This is added to support co-existence scenario (two libraries using
 * QAT in same application).
 */
static int start_ref_count = 0;
static pid_t start_ref_pid = -1;

static CpaStatus do_userReset()
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /* there is no option to reset the mutex, hence destroying
     * it and re-initializing. */
    if (sync_lock)
        osalMutexDestroy(&sync_lock);
    if (CPA_STATUS_SUCCESS != LAC_INIT_MUTEX(&sync_lock))
    {
        LAC_LOG_ERROR("Mutex init failed for sync_lock\n");
        status = CPA_STATUS_RESOURCE;
    }
    else
    {
        start_ref_count = 0;
        if (CPA_STATUS_SUCCESS == icp_adf_resetUserProxy())
        {
            status = icp_adf_resetSubsystemTable();
        }
        else
        {
            LAC_LOG_ERROR("Error resetting user proxy\n");
            status = CPA_STATUS_FAIL;
        }
    }
    return status;
}

static CpaStatus do_userStart(const char *process_name)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    status = icpSetProcessName(process_name);
    LAC_CHECK_STATUS(status);
    status = SalCtrl_AdfServicesRegister();
    LAC_CHECK_STATUS(status);

    status = icp_adf_userProxyInit(process_name);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to initialize proxy\n");
        SalCtrl_AdfServicesUnregister();
        return status;
    }
    status = SalCtrl_AdfServicesStartedCheck();
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to start services\n");
        SalCtrl_AdfServicesUnregister();
    }
    return status;
}

CpaStatus icp_sal_userStart(const char *process_name)
{
    char name[ADF_CFG_MAX_SECTION_LEN_IN_BYTES + 1] = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    pid_t pid = getpid();

    if (start_ref_pid != pid)
    {
        status = do_userReset();
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("do_userReset failed\n");
            return CPA_STATUS_FAIL;
        }
    }

    if (osalMutexLock(&sync_lock, OSAL_WAIT_FOREVER))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        osalMutexDestroy(&sync_lock);
        return CPA_STATUS_FAIL;
    }

    if (0 == start_ref_count)
    {
        status = icp_adf_userProcessToStart(process_name, name);

        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_DEBUG("icp_adf_userProcessToStart failed\n");
            osalMutexUnlock(&sync_lock);
            osalMutexDestroy(&sync_lock);
            return CPA_STATUS_FAIL;
        }
        status = do_userStart(name);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* To handle overflow case */
        if (start_ref_count >= START_REF_COUNT_MAX)
        {
            LAC_LOG_ERROR("start_ref_count overflow!\n");
            osalMutexUnlock(&sync_lock);
            osalMutexDestroy(&sync_lock);
            return CPA_STATUS_FAIL;
        }
        else
        {
            start_ref_count += 1;
        }
    }
    if (osalMutexUnlock(&sync_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        osalMutexDestroy(&sync_lock);
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        start_ref_pid = pid;
    }
    return status;
}

CpaStatus icp_sal_userStartMultiProcess(const char *pProcessName,
                                        CpaBoolean limitDevAccess)
{
    return icp_sal_userStart(pProcessName);
}

static CpaStatus do_userStop()
{
    CpaStatus status = SalCtrl_AdfServicesUnregister();

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to unregister\n");
        return status;
    }

    status = icp_adf_userProxyShutdown();
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to shutdown proxy\n");
        return status;
    }
    icp_adf_userProcessStop();
    return status;
}

CpaStatus icp_sal_userStop()
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    pid_t pid = getpid();

    if (start_ref_pid != pid)
    {
        LAC_LOG_DEBUG("Process id mismatch\n");
        return CPA_STATUS_FAIL;
    }
    if (osalMutexLock(&sync_lock, OSAL_WAIT_FOREVER))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        osalMutexDestroy(&sync_lock);
        return CPA_STATUS_FAIL;
    }
    if (1 == start_ref_count)
    {
        status = do_userStop();
    }
    if (0 < start_ref_count)
    {
        start_ref_count -= 1;
    }
    if (osalMutexUnlock(&sync_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        osalMutexDestroy(&sync_lock);
        return CPA_STATUS_FAIL;
    }
    if (0 == start_ref_count)
    {
        osalMutexDestroy(&sync_lock);
        start_ref_pid = -1;
    }

    return status;
}

CpaStatus icp_sal_find_new_devices(void)
{
    return icp_adf_userFindNewDevices();
}

CpaStatus icp_sal_poll_device_events(void)
{
    return icp_adf_pollDeviceEvents();
}

CpaStatus icp_sal_check_device(Cpa32U accelId)
{
    return icp_adf_userCheckDevice(accelId);
}

CpaStatus icp_sal_check_all_devices(void)
{
    return icp_adf_userCheckAllDevices();
}

#ifdef ICP_HB_FAIL_SIM
CpaStatus icp_sal_heartbeat_simulate_failure(Cpa32U accelId)
{
    return icp_adf_heartbeatSimulateFailure(accelId);
}

#endif


CpaStatus icp_sal_reset_device(Cpa32U accelId)
{
    return icp_adf_resetDevice(accelId);
}

#ifdef ICP_DC_ERROR_SIMULATION
CpaStatus icp_sal_cnv_simulate_error(CpaInstanceHandle dcInstance,
                                     CpaDcSessionHandle pSessionHandle)
{
    return dcSetCnvError(dcInstance, pSessionHandle);
}
#endif /* ICP_DC_ERROR_SIMULATION */

CpaBoolean icp_sal_userIsQatAvailable(void)
{
    return icp_adf_isDeviceAvailable();
}
