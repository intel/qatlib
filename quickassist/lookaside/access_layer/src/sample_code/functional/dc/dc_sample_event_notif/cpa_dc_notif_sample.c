/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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

/*
 * This is sample code that demonstrates usage of event notifications for
 * DC instance. The test flow as followed:
 * 1) the instance is created and notification callback is registered
 * 2) user issues adf_ctl reset
 * 3) the test code polls the device events until CPA_INSTANCE_EVENT_RESTARTED
 *    notification has arrived.
 */

#include "cpa.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

extern int gDebugParam;
CpaStatus restartedEventArrived_g = CPA_FALSE;

/*
 * Callback function, this is an event handler.
 */
static void dcEventCallback(const CpaInstanceHandle instanceHandle,
                            void *pCallbackTag,
                            const CpaInstanceEvent instanceEvent)
{
    switch (instanceEvent)
    {
        case CPA_INSTANCE_EVENT_RESTARTING:
            PRINT_DBG("Event 'restarting' detected\n");
            break;
        case CPA_INSTANCE_EVENT_RESTARTED:
            PRINT_DBG("Event 'restarted' detected\n");
            restartedEventArrived_g = CPA_TRUE;
            break;
        case CPA_INSTANCE_EVENT_FATAL_ERROR:
            PRINT_DBG("'Fatal error' event detected\n");
            break;
    }
}

/*
 * This is the main entry point.
 */
CpaStatus dcSampleEventNotif(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaInstanceInfo2 dcInstanceInfo;

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     */
    sampleDcGetInstance(&dcInstHandle);
    if (NULL == dcInstHandle)
    {
        return CPA_STATUS_FAIL;
    }

    PRINT_DBG("Setting Instance notification callback...");
    status = cpaDcInstanceSetNotificationCb(
        dcInstHandle, dcEventCallback, &dcInstanceInfo);

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT("Done\n");
    }
    else
    {
        PRINT("\nFAILURE.  status= %d\n", status);
        return status;
    }

    PRINT("Please reset the device with the adf_ctl reset command\n");

    /*While loop, waiting for the device restarting event */
    while ((!restartedEventArrived_g) && (CPA_STATUS_SUCCESS == status))
    {
        status = icp_sal_poll_device_events();
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_DBG("Failure. icp_sal_poll_device_events() returned %d", status);
    }
    return status;
}
