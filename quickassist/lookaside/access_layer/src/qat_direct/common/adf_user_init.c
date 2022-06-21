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
 * @file  adf_user_init.c
 *
 * @description
 *        This file contains the subcomponent module initialisation code
 *        for the Acceleration Driver Framework (ADF).
 *
 *****************************************************************************/

#include "cpa.h"
#include "icp_platform.h"
#include "icp_adf_init.h"
#include "adf_init.h"
#include "adf_user_init.h"
#include "adf_devmgr.h"

/*
 * The subsystem_table variable described the current position of the
 * tail of the list, this will also be the newest entry to the list.
 *
 * The subsystem_table_head contains the pointer to the head of the list.
 */
STATIC subservice_registation_handle_t *pSubsystemTable = NULL;
STATIC subservice_registation_handle_t *pSubsystemTableHead = NULL;
STATIC ICP_MUTEX subsystemTableLock = {0};
char *icp_module_name = "ADF_UIO_PROXY";

/* Slepping time before subsystem is started */
#define SLEEP_TIME 50000
/* Loop times before subsystem is started */
#define SLEEP_TIMES 10000000
Cpa32U userStartSleepTime = SLEEP_TIME;
Cpa32U userStartSleepLoops = SLEEP_TIMES;

STATIC void set_sleep_time(Cpa32U sleep_time, Cpa32U sleep_loops)
{
    userStartSleepTime = sleep_time;
    userStartSleepLoops = sleep_loops;
}

/*
 * adf_subsystemAdd
 * Add a new subsystem structure to the subsystem Table
 */
STATIC inline CpaStatus adf_subsystemAdd(
    subservice_registation_handle_t *subsystem)
{
    CpaStatus status = CPA_STATUS_FAIL;
    subservice_registation_handle_t *subsystem_hdl = NULL;
    ICP_CHECK_FOR_NULL_PARAM(subsystem);

    subsystem_hdl = pSubsystemTableHead;
    if (0 == subsystemTableLock)
    {
        if (OSAL_SUCCESS != ICP_MUTEX_INIT(&subsystemTableLock))
        {
            ADF_ERROR("Mutex init failed for subsystemTableLock\n");
            return CPA_STATUS_RESOURCE;
        }
        set_sleep_time(SLEEP_TIME, SLEEP_TIMES);
    }

    ICP_MUTEX_LOCK(&subsystemTableLock);
    /* Search the linked list for the subsystem */
    ICP_FIND_ELEMENT_IN_LIST(subsystem, subsystem_hdl, status);
    if (CPA_STATUS_SUCCESS == status)
    {
        ADF_ERROR("subservice %s already in table.\n",
                  subsystem->subsystem_name);
        ICP_MUTEX_UNLOCK(&subsystemTableLock);
        return CPA_STATUS_FAIL;
    }
    ICP_ADD_ELEMENT_TO_END_OF_LIST(
        subsystem, pSubsystemTable, pSubsystemTableHead);
    ICP_MUTEX_UNLOCK(&subsystemTableLock);
    return CPA_STATUS_SUCCESS;
}

/*
 * adf_subsystemRemove
 * Remove the subsystem structure from the subsystem Table
 */
STATIC inline CpaStatus adf_subsystemRemove(
    subservice_registation_handle_t *subsystem)
{
    subservice_registation_handle_t *subsystem_hdl = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    ICP_CHECK_FOR_NULL_PARAM(subsystem);

    subsystem_hdl = pSubsystemTableHead;
    ICP_MUTEX_LOCK(&subsystemTableLock);
    ICP_FIND_ELEMENT_IN_LIST(subsystem, subsystem_hdl, status);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("subservice %s not found.\n", subsystem->subsystem_name);
        ICP_MUTEX_UNLOCK(&subsystemTableLock);
        return CPA_STATUS_FAIL;
    }
    else
    {
        ADF_DEBUG("subservice in table - removing.\n");
    }
    ICP_REMOVE_ELEMENT_FROM_LIST(
        subsystem, pSubsystemTable, pSubsystemTableHead);
    ICP_MUTEX_UNLOCK(&subsystemTableLock);
    if (0 != subsystemTableLock && NULL == pSubsystemTableHead)
    {
        ICP_MUTEX_UNINIT(&subsystemTableLock);
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_subsystemRegister
 * Register a new subsystem.
 */
CpaStatus icp_adf_subsystemRegister(
    subservice_registation_handle_t *subsystem_hdl)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;
    ICP_CHECK_FOR_NULL_PARAM(subsystem_hdl);

    status = adf_subsystemAdd(subsystem_hdl);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("Failed to add subsystem to the linked list.\n");
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        /* Initialising the masks during the subsystem registration
         * and prior to init. */
        CLEAR_STATUS_BIT(subsystem_hdl->subsystemStatus[i].subsystemInitBit, 0);
        CLEAR_STATUS_BIT(subsystem_hdl->subsystemStatus[i].subsystemStartBit,
                         0);
        CLEAR_STATUS_BIT(subsystem_hdl->subsystemStatus[i].subsystemFailedBit,
                         0);
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * do_shutdown
 * Function sends a shutdown event to a subsystem.
 */
STATIC CpaStatus do_shutdown(icp_accel_dev_t *accel_dev,
                             subservice_registation_handle_t *subsystem_hdl)
{
    CpaStatus status = CPA_STATUS_FAIL;
    ICP_CHECK_FOR_NULL_PARAM(subsystem_hdl);
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_PARAM_RANGE(accel_dev->accelId, 0, ADF_MAX_DEVICES - 1);

    /* Shutdown the subsystem if required */
    if (BIT_IS_SET(
            subsystem_hdl->subsystemStatus[accel_dev->accelId].subsystemInitBit,
            0))
    {
        /* Send shutdown event */
        ADF_DEBUG("Sending event %d to %s\n",
                  ADF_EVENT_SHUTDOWN,
                  subsystem_hdl->subsystem_name);

        status = subsystem_hdl->subserviceEventHandler(
            accel_dev, ADF_EVENT_SHUTDOWN, NULL);

        if (CPA_STATUS_SUCCESS != status)
        {
            ADF_ERROR("Failed to shutdown subservice %s\n",
                      subsystem_hdl->subsystem_name);
        }
        else
        {
            CLEAR_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                                 .subsystemInitBit,
                             0);
        }
    }
    return status;
}

/*
 * icp_adf_subsystemUnregister
 * Unregister a subsystem that is about to be removed.
 * If the system is initialised and started it will be stopped first.
 */
CpaStatus icp_adf_subsystemUnregister(
    subservice_registation_handle_t *subsystem_hdl)
{
    CpaStatus status = CPA_STATUS_FAIL;
    icp_accel_dev_t *accel_dev = NULL;
    icp_accel_dev_t **accel_tbl = NULL;
    Cpa32U sleepflag = 0, i = 0;

    ICP_CHECK_FOR_NULL_PARAM(subsystem_hdl);

    status = adf_devmgrGetAccelHead(&accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("Failed to get accel head.\n");
        return status;
    }
    accel_tbl = (icp_accel_dev_t **)accel_dev;
    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        if (NULL != *accel_tbl)
        {
            /* Stop the subsystem if required */
            if (BIT_IS_SET(subsystem_hdl->subsystemStatus[(*accel_tbl)->accelId]
                               .subsystemStartBit,
                           0))
            {
                ADF_DEBUG("Sending event %d to %s\n",
                          ADF_EVENT_STOP,
                          subsystem_hdl->subsystem_name);

                status = subsystem_hdl->subserviceEventHandler(
                    (*accel_tbl), ADF_EVENT_STOP, NULL);
                if (CPA_STATUS_SUCCESS != status)
                {
                    if (CPA_STATUS_RETRY == status)
                    {
                        sleepflag++;
                        CLEAR_STATUS_BIT(
                            subsystem_hdl
                                ->subsystemStatus[(*accel_tbl)->accelId]
                                .subsystemStartBit,
                            0);

                        ADF_DEBUG("Received pending from subservice %s.\n",
                                  subsystem_hdl->subsystem_name);
                    }
                    else
                    {
                        ADF_ERROR("Failed to stop subservice %s for dev %d\n",
                                  subsystem_hdl->subsystem_name,
                                  (*accel_tbl)->accelId);
                    }
                }
                else
                {
                    CLEAR_STATUS_BIT(
                        subsystem_hdl->subsystemStatus[(*accel_tbl)->accelId]
                            .subsystemStartBit,
                        0);
                }
            }
        }
        accel_tbl++;
    }

    /* sleep for PENDING_DELAY msecs before calling shutdown. */
    if (sleepflag)
    {
        ICP_MSLEEP(PENDING_DELAY);
    }

    accel_tbl = (icp_accel_dev_t **)accel_dev;
    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        if (NULL != *accel_tbl)
        {
            status = do_shutdown((*accel_tbl), subsystem_hdl);
            if (CPA_STATUS_SUCCESS != status)
            {
                ADF_ERROR("Failed to shutdown subservice %s.\n",
                          subsystem_hdl->subsystem_name);
                ADF_DEBUG("Removing subservice from the subservice table.\n");
            }
        }
        accel_tbl++;
    }
    return adf_subsystemRemove(subsystem_hdl);
}

/*
 * adf_user_subsystemInit
 * This function initiates the initialisation of all sub-component modules.
 * Sub-component initialisation involves initing the AEs, allocating
 * interrupt resources, loading the firmware and sending an INIT event to
 * the subservice.
 */
CpaStatus adf_user_subsystemInit(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_FAIL;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    while (NULL != subsystem_hdl)
    {
        ADF_DEBUG("Sending event %d to %s\n",
                  ADF_EVENT_INIT,
                  subsystem_hdl->subsystem_name);

        CLEAR_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                             .subsystemFailedBit,
                         0);

        status = subsystem_hdl->subserviceEventHandler(
            accel_dev, ADF_EVENT_INIT, NULL);
        if (CPA_STATUS_SUCCESS == status)
        {
            SET_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                               .subsystemInitBit,
                           0);
        }
        else
        {
            ADF_ERROR("Failed to initialise Subservice %s\n",
                      subsystem_hdl->subsystem_name);
            SET_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                               .subsystemFailedBit,
                           0);
            return status;
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    return status;
}

/*
 * adf_user_subsystemStart
 * This function sends a start event to the registered subcomponents
 */
CpaStatus adf_user_subsystemStart(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_FAIL;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    while (NULL != subsystem_hdl)
    {
        ADF_DEBUG("Sending event %d to %s\n",
                  ADF_EVENT_START,
                  subsystem_hdl->subsystem_name);

        status = subsystem_hdl->subserviceEventHandler(
            accel_dev, ADF_EVENT_START, NULL);

        if (CPA_STATUS_SUCCESS == status)
        {
            SET_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                               .subsystemStartBit,
                           0);
        }
        else
        {
            ADF_ERROR("Failed to start Subservice %s\n",
                      subsystem_hdl->subsystem_name);
            SET_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                               .subsystemFailedBit,
                           0);
            return status;
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    return status;
}

/*
 * adf_user_subsystemStop
 * This function sends a stop event to the registered subcomponents
 */
CpaStatus adf_user_subsystemStop(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_FAIL;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;
    Cpa32U sleepflag = 0;
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    while (NULL != subsystem_hdl)
    {
        if (BIT_IS_SET(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                           .subsystemStartBit,
                       0))
        {
            status = subsystem_hdl->subserviceEventHandler(
                accel_dev, ADF_EVENT_STOP, NULL);

            if (CPA_STATUS_SUCCESS != status)
            {
                if (CPA_STATUS_RETRY == status)
                {
                    sleepflag++;

                    CLEAR_STATUS_BIT(
                        subsystem_hdl->subsystemStatus[accel_dev->accelId]
                            .subsystemStartBit,
                        0);

                    ADF_DEBUG("Pending received from %s\n",
                              subsystem_hdl->subsystem_name);
                }
                else
                {
                    ADF_ERROR("Failed to stop subservice %s.\n",
                              subsystem_hdl->subsystem_name);
                }
            }
            else
            {
                CLEAR_STATUS_BIT(
                    subsystem_hdl->subsystemStatus[accel_dev->accelId]
                        .subsystemStartBit,
                    0);
            }
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    /*
     * If a pending was received need to return pending.
     */
    if ((CPA_STATUS_SUCCESS == status) && sleepflag)
    {
        status = CPA_STATUS_RETRY;
    }
    return status;
}

/*
 * adf_user_subsystemShutdown
 * This function sends a shutdown event to the registered subcomponents
 */
CpaStatus adf_user_subsystemShutdown(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_FAIL;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    while (NULL != subsystem_hdl)
    {
        if (BIT_IS_SET(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                           .subsystemInitBit,
                       0))
        {
            ADF_DEBUG("Sending event %d to %s\n",
                      ADF_EVENT_SHUTDOWN,
                      subsystem_hdl->subsystem_name);
            status = subsystem_hdl->subserviceEventHandler(
                accel_dev, ADF_EVENT_SHUTDOWN, NULL);
            if (CPA_STATUS_SUCCESS != status)
            {
                ADF_ERROR("Failed to shutdown Subservice %s\n",
                          subsystem_hdl->subsystem_name);
            }
            else
            {
                CLEAR_STATUS_BIT(
                    subsystem_hdl->subsystemStatus[accel_dev->accelId]
                        .subsystemInitBit,
                    0);
            }
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    return status;
}

/*
 * icp_adf_isSubsystemStarted
 * Function returns true if the service is started
 */
CpaBoolean icp_adf_isSubsystemStarted(
    subservice_registation_handle_t *subsystem_hdl)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean ret = CPA_FALSE;
    icp_accel_dev_t *accel_dev = NULL;
    icp_accel_dev_t **accel_tbl = NULL;
    Cpa32U i = 0, ctr = 0, wait_ctr = 0;

    ICP_CHECK_FOR_NULL_PARAM(subsystem_hdl);
    status = adf_devmgrGetAccelHead(&accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("Failed to get accel head.\n");
        return ret;
    }
    accel_tbl = (icp_accel_dev_t **)accel_dev;
    ICP_USLEEP(SLEEP_TIME);
    for (i = 0; i < ADF_MAX_DEVICES; i++)
    {
        if (NULL != *accel_tbl)
        {
            /* If the device is started in the system
             * need to wait till the subsystem is started
             * for this device or
             */
            while (!BIT_IS_SET(
                subsystem_hdl->subsystemStatus[i].subsystemStartBit, 0))
            {
                ICP_USLEEP(SLEEP_TIME);
                wait_ctr++;
                if (BIT_IS_SET(
                        subsystem_hdl->subsystemStatus[i].subsystemFailedBit,
                        0))
                {
                    return CPA_FALSE;
                }
                if (wait_ctr > SLEEP_TIMES)
                {
                    ctr--;
                    break;
                }
            }
            ctr++;
        }
        accel_tbl++;
    }
    ret = (ctr > 0) ? CPA_TRUE : CPA_FALSE;
    return ret;
}

/*
 * Function sends restarting event to all subsystems.
 * This function should be used by error handling funct. only
 */
CpaStatus adf_subsystemRestarting(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;
    Cpa32U retryflag = 0;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_PARAM_RANGE(accel_dev->accelId, 0, ADF_MAX_DEVICES - 1);

    while (NULL != subsystem_hdl)
    {
        enum adf_event event = ADF_EVENT_RESTARTING;
        ADF_DEBUG(
            "Sending event %d to %s\n", event, subsystem_hdl->subsystem_name);
        if (BIT_IS_SET(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                           .subsystemStartBit,
                       0))
        {
            status =
                subsystem_hdl->subserviceEventHandler(accel_dev, event, NULL);

            if (CPA_STATUS_SUCCESS != status)
            {
                if (CPA_STATUS_RETRY == status)
                {
                    retryflag++;

                    CLEAR_STATUS_BIT(
                        subsystem_hdl->subsystemStatus[accel_dev->accelId]
                            .subsystemStartBit,
                        0);
                    CLEAR_STATUS_BIT(
                        subsystem_hdl->subsystemStatus[accel_dev->accelId]
                            .subsystemInitBit,
                        0);
                    ADF_DEBUG("Pending received from %s\n",
                              subsystem_hdl->subsystem_name);
                }
                else
                {
                    ADF_ERROR("Failed to restart subservice %s.\n",
                              subsystem_hdl->subsystem_name);
                }
            }
            else
            {
                CLEAR_STATUS_BIT(
                    subsystem_hdl->subsystemStatus[accel_dev->accelId]
                        .subsystemStartBit,
                    0);
                CLEAR_STATUS_BIT(
                    subsystem_hdl->subsystemStatus[accel_dev->accelId]
                        .subsystemInitBit,
                    0);
            }
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    /*
     * If a pending was received need to return pending.
     */
    if ((CPA_STATUS_SUCCESS == status) && retryflag)
    {
        status = CPA_STATUS_RETRY;
    }
    return status;
}

/*
 * Function sends restarted event to all subsystems.
 * This function should be used by error handling funct. only
 */
CpaStatus adf_subsystemRestarted(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_PARAM_RANGE(accel_dev->accelId, 0, ADF_MAX_DEVICES - 1);

    while (NULL != subsystem_hdl)
    {
        enum adf_event event = ADF_EVENT_RESTARTED;
        ADF_DEBUG(
            "Sending event %d to %s\n", event, subsystem_hdl->subsystem_name);

        status = subsystem_hdl->subserviceEventHandler(accel_dev, event, NULL);
        if (CPA_STATUS_FAIL == status)
        {
            ADF_ERROR("Failed to restart subservice %s.\n",
                      subsystem_hdl->subsystem_name);
        }
        else
        {
            CLEAR_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                                 .subsystemFailedBit,
                             0);
            SET_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                               .subsystemInitBit,
                           0);
            SET_STATUS_BIT(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                               .subsystemStartBit,
                           0);
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * Function sends error event to all subsystems.
 * This function should be used by error handling funct. only
 */
CpaStatus adf_subsystemError(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U pendingflag = 0;
    subservice_registation_handle_t *subsystem_hdl = pSubsystemTableHead;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_PARAM_RANGE(accel_dev->accelId, 0, ADF_MAX_DEVICES - 1);

    while (NULL != subsystem_hdl)
    {
        enum adf_event event = ADF_EVENT_ERROR;
        ADF_DEBUG(
            "Sending event %d to %s\n", event, subsystem_hdl->subsystem_name);

        if (BIT_IS_SET(subsystem_hdl->subsystemStatus[accel_dev->accelId]
                           .subsystemStartBit,
                       0))
        {
            status =
                subsystem_hdl->subserviceEventHandler(accel_dev, event, NULL);
            if (CPA_STATUS_FAIL == status)
            {
                ADF_ERROR("Failed to send error event to %s.\n",
                          subsystem_hdl->subsystem_name);
            }
            else if (CPA_STATUS_RETRY == status)
            {
                pendingflag++;
                ADF_DEBUG("Pending received from %s\n",
                          subsystem_hdl->subsystem_name);
            }
        }
        subsystem_hdl = subsystem_hdl->pNext;
    }
    if ((CPA_STATUS_SUCCESS == status) && pendingflag)
    {
        status = CPA_STATUS_RETRY;
    }
    return status;
}

/*
 * Function to reset subsystem table head, the pointer
 * to the head of the list and lock.
 */
CpaStatus icp_adf_resetSubsystemTable(void)
{
    pSubsystemTable = NULL;
    pSubsystemTableHead = NULL;
    if (0 == subsystemTableLock)
    {
        if (OSAL_SUCCESS != ICP_MUTEX_INIT(&subsystemTableLock))
        {
            ADF_ERROR("Mutex init failed for subsystemTabl lock\n");
            return CPA_STATUS_RESOURCE;
        }
    }
    return CPA_STATUS_SUCCESS;
}
