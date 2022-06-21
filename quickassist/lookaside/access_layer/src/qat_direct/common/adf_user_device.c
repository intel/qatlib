/***************************************************************************
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
 ***************************************************************************/
#include <errno.h>
#include <adf_user_init.h>
#include <icp_platform.h>
#include <adf_user_transport.h>
#include <sys/ioctl.h>

#include "adf_io_user_proxy.h"
#include "icp_adf_user_proxy.h"

#include "adf_user.h"
#include "adf_io_cfg.h"

#define ADF_DEV_EVENT_TIMEOUT 10

typedef struct adf_event_node_s
{
    enum adf_event event;
    OsalTimeval start; /* record the start time of the event */
    struct adf_event_node_s *next;
} adf_event_node_t;

typedef struct adf_event_queue_s
{
    adf_event_node_t *head;
    adf_event_node_t *tail;
} adf_event_queue_t;

STATIC adf_event_queue_t adf_event_queue[ADF_MAX_DEVICES] = {{0}};

/*
 * User space copy of acceleration devices
 */
STATIC icp_accel_dev_t *accel_tbl[ADF_MAX_DEVICES] = {0};

/*
 * Need to keep track of what device is curently in error
 */
STATIC char accel_dev_error_stat[ADF_MAX_DEVICES] = {0};

/*
 * Mutex guarding access to accel_tbl on exit
 */
STATIC OsalMutex accel_tbl_mutex;

/*
 * Number of acceleration devices
 */
STATIC Cpa16U num_of_instances = 0;

/*
 * icp_adf_getNumDevices
 * This function is used to determine the number of devices
 */
CpaStatus icp_adf_getNumDevices(Cpa32U *num_devices)
{
    return adf_io_getNumDevices(num_devices);
}

/*
 * icp_adf_isDevIdValid
 * Check if a device id is valid
 */
CpaBoolean icp_adf_isDevIdValid(Cpa32U dev_id)
{
    if (dev_id >= ADF_MAX_DEVICES)
        return CPA_FALSE;

    if (NULL == accel_tbl[dev_id])
        return CPA_FALSE;

    return CPA_TRUE;
}

int32_t adf_cleanup_device(int32_t dev_id)
{
    int32_t stat = CPA_STATUS_SUCCESS;
    icp_accel_dev_t *dev;

    if (osalMutexLock(&accel_tbl_mutex, OSAL_WAIT_FOREVER))
    {
        ADF_ERROR("Failed to lock mutex \n");
        return CPA_STATUS_FAIL;
    }

    if (accel_tbl[dev_id] == NULL)
    {
        osalMutexUnlock(&accel_tbl_mutex);
        return 0;
    }

    dev = accel_tbl[dev_id];


    stat = adf_user_transport_exit(dev);
    adf_io_destroy_accel(accel_tbl[dev_id]);
    accel_tbl[dev_id] = NULL;

    num_of_instances--;
    osalMutexUnlock(&accel_tbl_mutex);

    return stat;
}

int32_t adf_clean_device(int32_t dev_id)
{
    int32_t stat = CPA_STATUS_SUCCESS;
    icp_accel_dev_t *dev;

    if (ICP_MUTEX_LOCK(&accel_tbl_mutex))
    {
        ADF_ERROR("Failed to lock mutex \n");
        return CPA_STATUS_FAIL;
    }

    if (accel_tbl[dev_id] == NULL)
    {
        ICP_MUTEX_UNLOCK(&accel_tbl_mutex);
        return 0;
    }

    dev = accel_tbl[dev_id];


    stat = adf_user_transport_clean(dev);
    num_of_instances--;
    ICP_MUTEX_UNLOCK(&accel_tbl_mutex);

    return stat;
}

int32_t adf_cleanup_devices(void)
{
    int32_t i;

    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        if (adf_cleanup_device(i) != 0)
        {
            osalMutexDestroy(&accel_tbl_mutex);
            ADF_ERROR("Failed to cleanup device %d\n", i);
            return CPA_STATUS_FAIL;
        }
    }
    osalMutexDestroy(&accel_tbl_mutex);

    return 0;
}

int32_t adf_init_devices(void)
{
    int32_t i = 0;

    if (OSAL_SUCCESS != ICP_MUTEX_INIT(&accel_tbl_mutex))
    {
        ADF_ERROR("Mutex init failed for accel_tbl_mutex\n");
        return CPA_STATUS_RESOURCE;
    }
    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        accel_tbl[i] = NULL;
    }

    return 0;
}
/*
 * adf_stop_system
 * Sets the user proxy running state to stopped
 */
STATIC inline void adf_stop_system(icp_accel_dev_t *accel_dev)
{
    accel_dev->adfSubsystemStatus = 0;
}

/*
 * adf_start_system
 * Sets the user proxy running state to started
 */
STATIC inline void adf_start_system(icp_accel_dev_t *accel_dev)
{
    accel_dev->adfSubsystemStatus = 1;
}

/*
 * adf_event_queue_is_empty
 * Returns CPA_TRUE if the event queue for this device
 * is empty.
 */
STATIC CpaBoolean adf_event_queue_is_empty(Cpa32U accelId)
{
    return (NULL == adf_event_queue[accelId].head);
}

/*
 * adf_event_queue_head
 * Gets the head of the queue but won't dequeue it.
 * The caller must ensure that the event queue is
 * not empty.
 */
STATIC void adf_event_queue_head(Cpa32U accelId,
                                 enum adf_event *event,
                                 OsalTimeval *event_start)
{
    *event = adf_event_queue[accelId].head->event;
    event_start->secs = adf_event_queue[accelId].head->start.secs;
    return;
}

/*
 * adf_event_enqueue
 * Enqueues a event node to the tail of a queue.
 */
STATIC CpaStatus adf_event_enqueue(Cpa32U accelId, enum adf_event event)
{
    adf_event_queue_t *queue = &adf_event_queue[accelId];
    adf_event_node_t *node = NULL;

    node = (adf_event_node_t *)osalMemAlloc(sizeof(adf_event_node_t));

    if (!node)
    {
        ADF_ERROR("Failed to allocate memory - adf_event_node_t\n");
        return CPA_STATUS_RESOURCE;
    }

    node->event = event;
    node->next = NULL;
    osalTimeGet(&node->start);

    if (!queue->head)
    {
        queue->head = node;
    }

    if (!queue->tail)
    {
        queue->tail = node;
    }
    else
    {
        queue->tail->next = node;
        queue->tail = node;
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * adf_event_dequeue
 * Dequeues the head of the queue and free it.
 */
STATIC void adf_event_dequeue(Cpa32U accelId, enum adf_event event)
{
    adf_event_queue_t *queue = &adf_event_queue[accelId];
    adf_event_node_t *node = queue->head;
    if (!adf_event_queue_is_empty(accelId))
    {
        if (queue->head == queue->tail)
        {
            queue->head = NULL;
            queue->tail = NULL;
        }
        else
        {
            queue->head = queue->head->next;
        }
        osalMemFree(node);
    }
}

STATIC int adf_proxy_get_dev_events(int dev_id);
STATIC int32_t adf_proxy_get_device(int dev_id);
STATIC int32_t adf_proxy_restart_device(int dev_id);

/*
 * subsystem_notify
 * Forwards the event to each registered subsystem
 * The caller must ensure a valid accelId variable
 */
STATIC CpaStatus subsystem_notify(Cpa32U accelId, Cpa32U event)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;
    CpaStatus stat_proxy = CPA_STATUS_SUCCESS;
    CpaStatus stat_restart = CPA_STATUS_SUCCESS;
    icp_accel_dev_t *accel_dev;

    accel_dev = accel_tbl[accelId];
    if (!accel_dev && event != ADF_EVENT_RESTARTED)
        return CPA_STATUS_INVALID_PARAM;

    switch (event)
    {
        case ADF_EVENT_INIT:
            stat = adf_user_subsystemInit(accel_dev);
            break;
        case ADF_EVENT_START:
            stat = adf_user_subsystemStart(accel_dev);
            adf_start_system(accel_dev);
            break;
        case ADF_EVENT_STOP:
            adf_stop_system(accel_dev);
            stat = adf_user_subsystemStop(accel_dev);
            break;
        case ADF_EVENT_SHUTDOWN:
            stat = adf_user_subsystemShutdown(accel_dev);
            /* Close user proxy for given device */
            stat_proxy = adf_cleanup_device(accel_dev->accelId);
            break;
        case ADF_EVENT_RESTARTING:
            adf_stop_system(accel_dev);
            stat = adf_subsystemRestarting(accel_dev);
            stat_proxy = adf_clean_device(accel_dev->accelId);
            break;
        case ADF_EVENT_RESTARTED:
            stat_restart = adf_proxy_restart_device(accelId);
            if (CPA_STATUS_SUCCESS == stat_restart)
            {
                adf_start_system(accel_tbl[accelId]);
            }
            accel_dev_error_stat[accelId] = 0;
            break;
        case ADF_EVENT_ERROR:
            /* accel_dev_error_stat is set after calling adf_subsystemError
             * to prevent repeated fatal error event notifications to the
             * application.
             * This may occur if the event error is being replayed as a
             * result of status retry. */
            stat = adf_subsystemError(accel_dev);
            accel_dev_error_stat[accel_dev->accelId] = 1;
            break;
        default:
            stat = CPA_STATUS_INVALID_PARAM;
    }
    if (CPA_STATUS_SUCCESS != stat_proxy)
    {
        ADF_ERROR("Failed to close process proxy\n");
    }
    if (CPA_STATUS_SUCCESS != stat_restart)
    {
        ADF_ERROR("Failed to restart device\n");
        stat = stat_restart;
    }
    return stat;
}

/*
 * adf_poll_enqueued_events
 * Poll events from the queue and notify
 * connected subsystems
 */
STATIC void adf_poll_enqueued_events(void)
{
    enum adf_event event;
    Cpa32U accelId;
    OsalTimeval event_start;
    OsalTimeval event_curr;
    Cpa32U event_time;
    CpaStatus stat = CPA_STATUS_SUCCESS;

    for (accelId = 0; accelId < ADF_MAX_DEVICES; accelId++)
    {
        while (!adf_event_queue_is_empty(accelId))
        {
            adf_event_queue_head(accelId, &event, &event_start);
            stat = subsystem_notify(accelId, event);

            /* In the case of a device error, if the instance
             * is not being polled, software responses will not
             * be generated for the in-flight requests. */
            osalTimeGet(&event_curr);
            event_time = event_curr.secs - event_start.secs;
            if (CPA_STATUS_SUCCESS == stat ||
                event_time > ADF_DEV_EVENT_TIMEOUT)
            {
                adf_event_dequeue(accelId, event);
            }
            else if (CPA_STATUS_RETRY == stat)
            {
                break;
            }
        }
    }
}

STATIC int32_t adf_proxy_get_device(int dev_id)
{
    int32_t err;

    if ((dev_id >= ADF_MAX_DEVICES) || (NULL != accel_tbl[dev_id]))
        return 0; /* Invalid dev_id or Already created. */

    if (!adf_io_accel_dev_exist(dev_id))
        return 0;

    if (adf_io_create_accel(&accel_tbl[dev_id], dev_id))
    {
        err = ENOMEM;
        goto adf_proxy_get_device_exit;
    }

    err = adf_user_transport_init(accel_tbl[dev_id]);
    if (0 != err)
    {
        goto adf_proxy_get_device_init_failed;
    }
    adf_proxy_get_dev_events(dev_id);
    num_of_instances++;


    return 0;

adf_proxy_get_device_init_failed:
    free(accel_tbl[dev_id]);
    accel_tbl[dev_id] = NULL;
adf_proxy_get_device_exit:
    return err;
}

STATIC int32_t adf_proxy_restart_device(int dev_id)
{
    int32_t err;

    if ((dev_id >= ADF_MAX_DEVICES))
        return 0; /* Invalid dev_id or Already created. */

    if (!adf_io_accel_dev_exist(dev_id))
        return 0;

    if (adf_io_reinit_accel(&accel_tbl[dev_id], dev_id))
    {
        err = ENOMEM;
        goto adf_proxy_restart_device_exit;
    }

    err = adf_user_transport_reinit(accel_tbl[dev_id]);
    if (0 != err)
    {
        goto adf_proxy_restart_device_init_failed;
    }

    err = adf_subsystemRestarted(accel_tbl[dev_id]);
    if (0 != err)
    {
        goto adf_proxy_restart_device_init_failed;
    }
    num_of_instances++;


    return 0;

adf_proxy_restart_device_init_failed:
    adf_user_transport_exit(accel_tbl[dev_id]);
    free(accel_tbl[dev_id]);
    accel_tbl[dev_id] = NULL;
adf_proxy_restart_device_exit:
    return err;
}

STATIC int adf_proxy_get_dev_events(int dev_id)
{
    enum adf_event event[] = {ADF_EVENT_INIT, ADF_EVENT_START};
    size_t i = 0;

    if (accel_tbl[dev_id] != NULL)
    {
        for (i = 0; i < sizeof(event) / sizeof(event[0]); i++)
        {
            subsystem_notify(dev_id, event[i]);
        }
    }

    return 0;
}

CpaStatus adf_proxy_get_devices(void)
{
    int32_t ctr = 0;
    Cpa32U num_dev = 0;

    if (icp_adf_getNumDevices(&num_dev))
        return CPA_STATUS_FAIL;
    for (ctr = 0; ctr < num_dev; ctr++)
    {
        if (adf_proxy_get_device(ctr))
        {
            ADF_ERROR("adf_proxy_get_device error ctr\n");
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_userFindNewDevices(void)
{
    return adf_proxy_get_devices();
}

CpaStatus icp_adf_pollDeviceEvents(void)
{
    Cpa32U accelId;
    enum adf_event event;
    CpaStatus stat;

    adf_poll_enqueued_events();

    while (adf_io_pollProxyEvent(&accelId, &event))
    {
        if (accelId >= ADF_MAX_DEVICES)
        {
            ADF_ERROR("Invalid accelId (%d) from event poll\n", accelId);
            continue;
        }

        if (adf_event_queue_is_empty(accelId))
        {
            stat = subsystem_notify(accelId, event);

            if (CPA_STATUS_RETRY == stat)
            {
                stat = adf_event_enqueue(accelId, event);
                if (CPA_STATUS_SUCCESS != stat)
                {
                    ADF_ERROR("Failed to enqueue the event\n");
                }
            }
        }
        else
        {
            stat = adf_event_enqueue(accelId, event);
            if (CPA_STATUS_SUCCESS != stat)
            {
                ADF_ERROR("Failed to enqueue the event\n");
            }
        }
    }
    return CPA_STATUS_SUCCESS;
}

/*
 *  * icp_adf_qaDevGet
 *   * Function increments the device usage counter.
 *    */
void icp_adf_qaDevGet(icp_accel_dev_t *pAccelDev)
{
    __sync_fetch_and_add(&pAccelDev->usageCounter, 1);
    return;
}

/*
 *  * icp_adf_qaDevGet
 *   * Function decrements the device usage counter.
 *    */
void icp_adf_qaDevPut(icp_accel_dev_t *pAccelDev)
{
    __sync_fetch_and_sub(&pAccelDev->usageCounter, 1);
    return;
}

/*
 * adf_devmgrGetAccelDevByAccelId
 * Check the accel table for a structure that contains the correct
 * accel ID. If the accelId is found return the pointer to the accelerator
 * structure.
 * Returns a pointer to the accelerator structure or NULL if not found.
 */
icp_accel_dev_t *adf_devmgrGetAccelDevByAccelId(Cpa32U accelId)
{
    icp_accel_dev_t **ptr = accel_tbl;
    Cpa16U i = 0;

    for (i = 0; i < ADF_MAX_DEVICES; i++, ptr++)
    {
        if (NULL != *ptr)
        {
            if ((*ptr)->accelId == accelId)
            {
                return *ptr;
            }
        }
    }
    return NULL;
}

/*
 * icp_adf_getAccelDevByAccelId
 * Same as adf_devmgrGetAccelDevByAccelId() but for external use
 * structure.
 * Returns a pointer to the accelerator structure or NULL if not found.
 */
icp_accel_dev_t *icp_adf_getAccelDevByAccelId(Cpa32U accelId)
{
    return adf_devmgrGetAccelDevByAccelId(accelId);
}

/*
 * icp_adf_isDevInError
 * Check if device is in error state.
 */
CpaBoolean icp_adf_isDevInError(icp_accel_dev_t *accel_dev)
{
    return (CpaBoolean)accel_dev_error_stat[accel_dev->accelId];
}

/*
 * icp_adf_userCheckDevice_by_fd
 * Function checks the status of the firmware/hardware for a given device
 * provided the fd has already been opened.
 */
STATIC CpaStatus icp_adf_userCheckDevice_by_fd(int fd, Cpa32U accelId)
{
    struct adf_dev_heartbeat_status_ctl hb_status = {0};

    if (fd < 0)
        return CPA_STATUS_FAIL;

    hb_status.device_id = accelId;
    if (ioctl(fd, IOCTL_HEARTBEAT_ACCEL_DEV, &hb_status))
        return CPA_STATUS_FAIL;

    switch (hb_status.status)
    {
        case DEV_HB_ALIVE:
            return CPA_STATUS_SUCCESS;
        case DEV_HB_UNSUPPORTED:
            return CPA_STATUS_UNSUPPORTED;
        case DEV_HB_UNRESPONSIVE:
        default:
            return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_FAIL;
}

/*
 * icp_adf_get_num_devices_by_fd
 * Function get the number of accel devices for a given device
 * provided the fd has already been opened.
 */
STATIC CpaStatus icp_adf_get_num_devices_by_fd(int fd, Cpa32U *num_devices)
{
    int res = 0;
    Cpa32U num_dev = 0;
    CpaStatus status = CPA_STATUS_FAIL;

    if (fd < 0)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    /* send the request down to get the device
     * information from kernel space. */
    res = ioctl(fd, IOCTL_GET_NUM_DEVICES, &num_dev);
    if (!res)
    {
        *num_devices = num_dev;
        status = CPA_STATUS_SUCCESS;
    }

    return status;
}

/*
 * icp_adf_userCheckDevice
 * Function checks the status of the firmware/hardware for a given device.
 */
CpaStatus icp_adf_userCheckDevice(Cpa32U accelId)
{
    CpaStatus ret = CPA_STATUS_FAIL;
    int fd = open(ADF_CTL_DEVICE_NAME, O_RDONLY);
    if (fd < 0)
        return CPA_STATUS_UNSUPPORTED;

    ret = icp_adf_userCheckDevice_by_fd(fd, accelId);
    close(fd);
    return ret;
}

/*
 * icp_adf_userCheckAllDevices
 * Function checks the status of the firmware/hardware for all devices.
 */
CpaStatus icp_adf_userCheckAllDevices(void)
{
    Cpa32U i;
    Cpa32U num_dev = 0;
    CpaStatus res = CPA_STATUS_FAIL;
    CpaBoolean all_unsup = CPA_TRUE;
    CpaBoolean any_dev = CPA_FALSE;

    int fd = open(ADF_CTL_DEVICE_NAME, O_RDONLY);
    if (fd < 0)
        return CPA_STATUS_UNSUPPORTED;

    if (icp_adf_get_num_devices_by_fd(fd, &num_dev))
    {
        close(fd);
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < num_dev; i++)
    {
        any_dev = CPA_TRUE;
        res = icp_adf_userCheckDevice_by_fd(fd, i);

        if (CPA_STATUS_UNSUPPORTED != res)
        {
            all_unsup = CPA_FALSE;

            if (CPA_STATUS_SUCCESS != res)
            {
                ADF_ERROR("Device Check failed for "
                          "device %d\n",
                          i);
                close(fd);
                return res;
            }
        }
    }

    close(fd);

    if (CPA_TRUE == any_dev && CPA_TRUE == all_unsup)
        return CPA_STATUS_UNSUPPORTED;
    else
        return CPA_STATUS_SUCCESS;
}

#ifdef ICP_HB_FAIL_SIM
/*
 * icp_adf_heartbeatSimulateFailure
 * Function simulates a heartbeat failure for a given device.
 */
CpaStatus icp_adf_heartbeatSimulateFailure(Cpa32U accelId)
{
    CpaStatus ret = CPA_STATUS_SUCCESS;
    int fd = open(ADF_CTL_DEVICE_NAME, O_RDONLY);

    if (fd < 0)
        return CPA_STATUS_UNSUPPORTED;

    if (ioctl(fd, IOCTL_HEARTBEAT_SIM_FAIL, accelId))
        ret = CPA_STATUS_FAIL;

    close(fd);
    return ret;
}

#endif
/*
 * icp_adf_mmap_misc_counter
 * Function get the mmap address for miscellaneous counter
 */
CpaStatus icp_adf_mmap_misc_counter(Cpa64U **miscCounter)
{
    CpaStatus ret = CPA_STATUS_SUCCESS;
    Cpa32U size = 0;
    void *addr = NULL;

    ICP_CHECK_FOR_NULL_PARAM(miscCounter);

    int fd = open(ADF_CTL_DEVICE_NAME, O_RDWR);
    if (fd < 0)
        return CPA_STATUS_UNSUPPORTED;

    size = getpagesize();

    addr = ICP_MMAP(
        NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (!addr || addr == MAP_FAILED)
    {
        close(fd);
        return CPA_STATUS_FAIL;
    }

    *miscCounter = &((struct adf_dev_miscellaneous_stats *)addr)->misc_counter;

    close(fd);
    return ret;
}

/*
 * icp_adf_ummap_misc_counter
 * Function unmap micellaneous counter
 */
CpaStatus icp_adf_unmap_misc_counter(Cpa64U *miscCounter)
{
    Cpa32U size = getpagesize();

    ICP_CHECK_FOR_NULL_PARAM(miscCounter);

    int ret = munmap(miscCounter, size);
    if (ret < 0)
        return CPA_STATUS_FAIL;

    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_getNumInstances
 * Return the number of acceleration devices it the system.
 */
CpaStatus icp_adf_getNumInstances(Cpa16U *pNumInstances)
{
    ICP_CHECK_FOR_NULL_PARAM(pNumInstances);
    *pNumInstances = num_of_instances;
    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_getInstances
 * Return table of acceleration instances it the system.
 */
CpaStatus icp_adf_getInstances(Cpa16U numInstances,
                               icp_accel_dev_t **pCyInstances)
{
    Cpa16U i = 0, x = 0;
    ICP_CHECK_FOR_NULL_PARAM(pCyInstances);

    if (numInstances > num_of_instances)
    {
        /* Too many acceleration devices requested */
        ADF_ERROR("Too many instances of accel device requested\n");
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        if (NULL != accel_tbl[i])
        {
            pCyInstances[x++] = (icp_accel_dev_t *)accel_tbl[i];
        }
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_getAccelDevByCapabilities
 * Returns a started accel device that implements
 * the capabilities specified in capabilitiesMask.
 */
CpaStatus icp_adf_getAccelDevByCapabilities(Cpa32U capabilitiesMask,
                                            icp_accel_dev_t **pAccel_devs,
                                            Cpa16U *pNumInstances)
{
    icp_accel_dev_t **ptr = accel_tbl;
    ICP_CHECK_FOR_NULL_PARAM(pAccel_devs);
    ICP_CHECK_FOR_NULL_PARAM(pNumInstances);
    Cpa16U i = 0;

    *pNumInstances = 0;
    for (i = 0; i < ADF_MAX_DEVICES; i++, ptr++)
    {
        if (NULL != *ptr)
        {
            if ((*ptr)->accelCapabilitiesMask & capabilitiesMask)
            {
                if ((*ptr)->adfSubsystemStatus)
                {
                    *pAccel_devs = (icp_accel_dev_t *)*ptr;
                    *pNumInstances = 1;
                    return CPA_STATUS_SUCCESS;
                }
            }
        }
    }
    return CPA_STATUS_FAIL;
}

/*
 * icp_adf_getAllAccelDevByCapabilities
 * Returns table of accel devices that are started and implement
 * the capabilities specified in capabilitiesMask.
 */
CpaStatus icp_adf_getAllAccelDevByCapabilities(Cpa32U capabilitiesMask,
                                               icp_accel_dev_t **pAccel_devs,
                                               Cpa16U *pNumInstances)
{
    icp_accel_dev_t **ptr = accel_tbl;
    ICP_CHECK_FOR_NULL_PARAM(pAccel_devs);
    ICP_CHECK_FOR_NULL_PARAM(pNumInstances);
    Cpa16U i = 0;

    *pNumInstances = 0;
    for (i = 0; i < ADF_MAX_DEVICES; i++, ptr++)
    {
        if (NULL != *ptr)
        {
            if ((*ptr)->accelCapabilitiesMask & capabilitiesMask)
            {
                if ((*ptr)->adfSubsystemStatus)
                {
                    pAccel_devs[(*pNumInstances)++] = (icp_accel_dev_t *)*ptr;
                }
            }
        }
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * icp_amgr_getAllAccelDevByEachCapabilities
 * Returns table of accel devices that are started and implement
 * each of the capabilities specified in capabilitiesMask.
 */
CpaStatus icp_adf_getAllAccelDevByEachCapability(Cpa32U capabilitiesMask,
                                                 icp_accel_dev_t **pAccel_devs,
                                                 Cpa16U *pNumInstances)
{
    icp_accel_dev_t **ptr = accel_tbl;
    ICP_CHECK_FOR_NULL_PARAM(pAccel_devs);
    ICP_CHECK_FOR_NULL_PARAM(pNumInstances);
    Cpa16U i = 0;

    *pNumInstances = 0;
    for (i = 0; i < ADF_MAX_DEVICES; i++, ptr++)
    {
        if (NULL != *ptr)
        {
            Cpa32U enabled_caps =
                (*ptr)->accelCapabilitiesMask & capabilitiesMask;
            if (enabled_caps == capabilitiesMask)
            {
                if ((*ptr)->adfSubsystemStatus)
                {
                    pAccel_devs[(*pNumInstances)++] = (icp_accel_dev_t *)*ptr;
                }
            }
        }
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_getAccelDevCapabilities
 * Returns accel devices capabilities specified in capabilitiesMask.
 */
CpaStatus icp_adf_getAccelDevCapabilities(icp_accel_dev_t *accel_dev,
                                          Cpa32U *pCapabilitiesMask)
{
    icp_accel_dev_t *pAccelDev = NULL;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_FOR_NULL_PARAM(pCapabilitiesMask);

    pAccelDev = accel_dev;
    *pCapabilitiesMask = pAccelDev->accelCapabilitiesMask;
    return CPA_STATUS_SUCCESS;
}

/*
 * adf_devmgrGetAccelHead
 * Sets the AccelDev to the head of the accelerator table.
 * Note: This function returns pointer to acceleration table
 * unlike the same function in kernelspace where is returns
 * pointer to list head.
 */
CpaStatus adf_devmgrGetAccelHead(icp_accel_dev_t **pAccelDev)
{
    ICP_CHECK_FOR_NULL_PARAM(pAccelDev);
    *pAccelDev = (icp_accel_dev_t *)accel_tbl;
    return CPA_STATUS_SUCCESS;
}
