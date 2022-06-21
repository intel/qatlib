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

/******************************************************************************
 * @file adf_process_proxy.c
 *
 * @description
 * User space interface to ADF in kernel space
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#ifdef QAT_WITH_LIBUDEV
#include <libudev.h>
#include <poll.h>
#endif
#include "cpa.h"
#include "icp_accel_devices.h"
#include "icp_platform.h"
#include "adf_platform.h"
#include "adf_kernel_types.h"
#include "icp_adf_init.h"
#include "icp_adf_accel_mgr.h"
#include "icp_adf_transport.h"
#include "adf_transport_ctrl.h"
#include "adf_user_init.h"
#include "adf_user_transport.h"
#include "adf_init.h"
#include "adf_user.h"
#include "adf_user_cfg.h"

#include "adf_io_user_proxy.h"

#define EVENT_MAX_LEN 20
#define ACCELID_MAX_LEN 5

/*
 * Time to sleep between each loop iteration in monitor devices func
 */

#ifdef QAT_WITH_LIBUDEV
STATIC struct udev *udev;
STATIC struct udev_monitor *mon;
#endif

/*
 * Proxy init counter
 */
STATIC Cpa16U init_ctr = 0;

/*
 * Process proxy running state
 */
STATIC OsalAtomic process_proxy_status = 0;

/*
 * icp_adf_resetUserProxy
 *
 * Description:
 *  Function to reset the ADF proxy status in user space.
 *  It resets proxy status and related parameters.
 *
 * CPA_STATUS_SUCCESS on resetting ADF proxy status
 * CPA_STATUS_RESOURCE when mutex init fails
 */
CpaStatus icp_adf_resetUserProxy(void);

/*
 * adf_process_proxy_stop
 * Sets the process proxy running state to stopped
 */
STATIC inline void adf_process_proxy_stop(void)
{
    osalAtomicSet(0, &process_proxy_status);
}

/*
 * adf_process_proxy_start
 * Sets the process proxy running state to started
 */
STATIC inline void adf_process_proxy_start(void)
{
    osalAtomicSet(1, &process_proxy_status);
}

STATIC inline Cpa32U adf_process_proxy_running(void)
{
    return (Cpa32U)osalAtomicGet(&process_proxy_status);
}

#ifdef QAT_WITH_LIBUDEV
STATIC CpaStatus adf_event_monitor_create(void)
{
    int ret = CPA_STATUS_SUCCESS;

    udev = udev_new();
    if (!udev)
    {
        ADF_ERROR("Can't create udev\n");
        ret = CPA_STATUS_FAIL;
    }

    if (ret == CPA_STATUS_SUCCESS)
    {
        mon = udev_monitor_new_from_netlink(udev, "udev");
        if (!mon)
        {
            ADF_ERROR("Can't create udev monitor\n");
            ret = CPA_STATUS_FAIL;
        }
    }

    if (ret == CPA_STATUS_SUCCESS)
    {
        if (udev_monitor_filter_add_match_subsystem_devtype(mon, "pci", NULL))
        {
            ADF_ERROR("Can't add udev match filter\n");
            ret = CPA_STATUS_FAIL;
        }
    }

    if (ret == CPA_STATUS_SUCCESS)
    {
        if (udev_monitor_enable_receiving(mon))
        {
            ADF_ERROR("Can't bind monitor to event source\n");
            ret = CPA_STATUS_FAIL;
        }
    }

    if (ret != CPA_STATUS_SUCCESS)
    {
        if (mon)
            udev_monitor_unref(mon);
        mon = NULL;
        if (udev)
            udev_unref(udev);
        udev = NULL;
    }
    return ret;
}

void adf_event_monitor_delete(void)
{
    if (mon)
    {
        udev_monitor_unref(mon);
        mon = NULL;
    }
    if (udev)
    {
        udev_unref(udev);
        udev = NULL;
    }
}
#endif

/*
 * adf_process_proxy_init
 * Init process proxy and connect to kernel space.
 * For every acceleration device in the system open
 * events and rings interface and start event listening threads
 */
STATIC CpaStatus adf_process_proxy_init(void)
{
    if (adf_process_proxy_running())
    {
        ADF_ERROR("Proxy already running\n");
        return CPA_STATUS_FAIL;
    }

#ifdef QAT_WITH_LIBUDEV
    if (adf_event_monitor_create() != CPA_STATUS_SUCCESS)
        return CPA_STATUS_FAIL;
#endif

    adf_process_proxy_start();
    if (adf_init_devices())
    {
        ADF_ERROR("Error initializing devices\n");
        return CPA_STATUS_FAIL;
    }

    return adf_proxy_get_devices();
}

/*
 * adf_process_proxy_shutdown
 * User space proxy is shutting down. Close and clean all opened devices
 */
static __inline__ CpaStatus adf_process_proxy_shutdown()
{
#ifdef QAT_WITH_LIBUDEV
    adf_event_monitor_delete();
#endif

    return adf_cleanup_devices();
}

/*
 * icp_adf_userProxyInit
 * This function is called by the application to bring the proxy up & running
 * Every userspace process has to call it to be able to create rings
 * and receive events.
 */
CpaStatus icp_adf_userProxyInit(char const *const name)
{
    CpaStatus status = CPA_STATUS_FAIL;

    ICP_CHECK_FOR_NULL_PARAM(name);
    /* Allow the user to call init just once */
    if (init_ctr)
    {
        ADF_ERROR("User proxy alreay initialized\n");
        return status;
    }
    init_ctr = 1;
    /* Connect to kernel space. */
    status = adf_process_proxy_init();
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("adf_process_proxy_init failed\n");
        return status;
    }

    status = adf_io_userProxyInit(name);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("Init adf_io proxy failed\n");
        return status;
    }

    return status;
}

/*
 * icp_adf_userProxyShutdown
 * This function is called by the application to shutdown the proxy
 */
CpaStatus icp_adf_userProxyShutdown(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    adf_process_proxy_stop();
    status = adf_process_proxy_shutdown();
    init_ctr = 0;

    adf_io_userProxyShutdown();

    return status;
}

/*
 * icp_adf_userProcessToStart
 *
 *  This function checks if an user space process with a given name has
 *  already been started.
 *  Returns:
 *  False - process with a given name is not started. I.e. it is safe
 *          to start one.
 *  True - process is started or couldn't figure out if it is started.
 */
CpaStatus icp_adf_userProcessToStart(char const *const name_tml, char *name)
{
    int name_len;
    int ret;

    /* Validate process name */
    if (!name_tml || !name)
    {
        ADF_ERROR("Invalid pointer\n");
        return CPA_STATUS_FAIL;
    }

    name_len = strnlen(name_tml, ADF_CFG_MAX_SECTION_LEN_IN_BYTES + 1);
    if (name_len + 1 > ADF_CFG_MAX_SECTION_LEN_IN_BYTES || 0 == name_len)
    {
        ADF_ERROR("Invalid Process name\n");
        return CPA_STATUS_FAIL;
    }

    ret = adf_io_userProcessToStart(
        name_tml, name_len, name, ADF_CFG_MAX_SECTION_LEN_IN_BYTES);
    if (ret)
    {
        ADF_ERROR("Failed to start %s\n", name_tml);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_userProcessStop
 *
 *  This function stops the user process.
 */
void icp_adf_userProcessStop(void)
{
    adf_io_userProcessStop();

    return;
}

/*
 * icp_adf_getBusAddress
 *
 *  This function gets the bus address of the device.
 */
Cpa16U icp_adf_getBusAddress(Cpa16U packageId)
{
    return icp_adf_cfgGetBusAddress(packageId);
}

/*
 * icp_adf_resetUserProxy
 *
 *  Function to reset the ADF proxy status in user space.
 */
CpaStatus icp_adf_resetUserProxy(void)
{
    init_ctr = 0;
    osalAtomicSet(0, &process_proxy_status);

    return adf_io_resetUserProxy();
}
