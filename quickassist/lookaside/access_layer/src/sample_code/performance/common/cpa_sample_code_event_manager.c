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

//#include <stdlib.h>

#include "cpa.h"
#include "icp_sal_versions.h"
#include "cpa_sample_code_utils.h"

#include "cpa_cy_common.h"
#include "icp_sal_user.h"

//#include "lac_common.h"
#include "cpa_cy_common.h"

#include <signal.h>
#include <unistd.h>

#define MAX_DEVICE 4
#define MAX_VF_DEVICE 32

/* Message definition. */
#define SAMPLE_CODE_EMPTY_MSG 0x0000000
#define SAMPLE_CODE_TEST_MSG 0x0000001
#define SAMPLE_CODE_TEST_ACK 0x0000002
#define SAMPLE_CODE_RESET_REQUEST 0x0000004
#define SAMPLE_CODE_RESET_ACK 0x0000008
#define SAMPLE_CODE_MSG_LIMIT 0x00003FF
#define SAMPLE_CODE_MSG_OUT_OF_BOUNDS 0xFFFFC00

#define RESET_TIME_DELAY 60

#define RESET SAMPLE_CODE_RESET_REQUEST
#define TEST_MSG SAMPLE_CODE_TEST_MSG

#define AVOID_SOFTLOCKUP                                                       \
    do                                                                         \
    {                                                                          \
        sched_yield();                                                         \
    } while (0)

static CpaBoolean reset_ack_rx[MAX_DEVICE][MAX_VF_DEVICE] = {{CPA_FALSE}};
static CpaBoolean vf_pf_host_set[MAX_DEVICE][MAX_VF_DEVICE] = {{CPA_FALSE}};
static CpaBoolean vf_pf_guest_set[MAX_VF_DEVICE] = {CPA_FALSE};
static Cpa32U max_count = 10;

#define USER_SPACE 1
CpaBoolean isHost_g = CPA_TRUE;

/******************************************************************************
 * This section defines the VF and PF communications
 *****************************************************************************/
#ifdef USER_SPACE

/* API list for testCli */

/*PF Specific Tests */
void enableHostPfVF(Cpa32U accelId, Cpa32U vfNum);
void displayStatusHostPfVf();
void disablePfVf(Cpa32U accelId, Cpa32U vfNum);
void sendMsgToVf(Cpa32U accelId, Cpa32U VfId, Cpa32U message);
void sendMsgToAllVf(Cpa32U message);
CpaStatus getMsgFromVf(Cpa32U accelId, Cpa32U VfId);
void getMsgFromAllVf(Cpa32U accelId);
void sendMsgToVfWithAck(Cpa32U accelId, Cpa32U VfId, Cpa32U msg);
void sendMsgToMultipleVfWithAck(Cpa32U accelId, Cpa32U VfId, Cpa32U msg);
void startTimer();
void processMsgInHost(Cpa32U accelId,
                      Cpa32U vfNum,
                      Cpa32U message,
                      Cpa32U messageCounter);
void rxMsgFromVf(Cpa32U accId);
void txMsgToVf(Cpa32U accelId, Cpa32U VfId, Cpa32U message);
void *txStartInstance(void *count);
void *rxStartInstance(void *count);

/* VF Specific Test */
void enableGuestVfPf(Cpa32U accelId);
void displayStatusGuestPfVf();
CpaBoolean isDeviceEnabled(Cpa32U accelId);
void sendMsgToPf(Cpa32U accelId, Cpa32U message);
void sendMsgToAllPf(Cpa32U message);
CpaStatus getMsgFromPf(Cpa32U accelId);
void getMsgFromAllPf();
void sendMsgToPfWithAck(Cpa32U accelId, Cpa32U VfId, Cpa32U msg);
void eventTrigger(Cpa32U accelId, Cpa32U VfId, Cpa32U message);
void processMsgInGuest(Cpa32U accelId, Cpa32U message, Cpa32U messageCount);

static CpaBoolean reset_accelId[MAX_DEVICE] = {CPA_FALSE};

/* Enable the Host PF VF entries manually
 * */
void enableHostPfVF(Cpa32U accelId, Cpa32U vfNum)
{
    vf_pf_host_set[accelId][vfNum] = CPA_TRUE;
    return;
}

/* Enable the Guest device manually
 * */
void enableGuestVfPf(Cpa32U accelId)
{

    vf_pf_guest_set[accelId] = CPA_TRUE;
    return;
}

/* Display the list enabled PF & VF entries at HOST
 * */

void displayStatusHostPfVf()
{
    Cpa32U accelId = 0;
    Cpa32U vfNum = 0;
    printf("Enabled device PF and VF list \n");
    for (accelId = 0; accelId < MAX_DEVICE; accelId++)
    {
        for (vfNum = 0; vfNum < MAX_VF_DEVICE; vfNum++)
        {
            printf("accelId : vfNum %d,%d - %d \n",
                   accelId,
                   vfNum,
                   vf_pf_host_set[accelId][vfNum]);

            if (vf_pf_host_set[accelId][vfNum] == CPA_TRUE)
            {
                printf("accelId : vfNum %d,%d \n", accelId, vfNum);
            }
        }
    }
}

/* Display the list enabled VF entries at Guest
 * */
void displayStatusGuestPfVf()
{
    Cpa32U accelId = 0;
    Cpa32U vfNum = 0;
    printf("Enabled device PF and VF list \n");
    for (accelId = 0; accelId < MAX_DEVICE; accelId++)
    {
        if (vf_pf_guest_set[accelId] == CPA_TRUE)
        {
            printf("accelId : vfNum %d,%d \n", accelId, vfNum);
        }
    }
}

/* Disable the entries for Devices mapped to  VF entries
 * */
void disablePfVf(Cpa32U accelId, Cpa32U vfNum)
{
    vf_pf_host_set[accelId][vfNum] = CPA_FALSE;
}

/* Validating if the device is enabled
 * */
CpaBoolean isDeviceEnabled(Cpa32U accelId)
{
    int vfId = 0;
    for (vfId = 0; vfId < MAX_VF_DEVICE; vfId++)
    {
        if (vf_pf_host_set[accelId][vfId] == CPA_TRUE)
        {
            //	printf("Device :%d Enabled \n",accelId);
            return CPA_TRUE;
        }
    }
    //	printf("Device :%d Disabled \n",accelId);
    return CPA_FALSE;
}

/* Sending message to the guest if the device is enabled
 * */

void sendMsgToPf(Cpa32U accelId, Cpa32U message)
{
    if (isDeviceEnabled(accelId))
    {
        icp_sal_userSendMsgToPf(accelId, message);
    }
}

/* Sending message to all the Host devices from the guest VF's
 * */
void sendMsgToAllPf(Cpa32U message)
{
    Cpa32U accelId = 0;

    for (accelId = 0; accelId < MAX_DEVICE; accelId++)
    {
        if (isDeviceEnabled(accelId))
        {
            icp_sal_userSendMsgToPf(accelId, message);
        }
    }
}

/* Sending message to all the guest  VF's
 * */

void sendMsgToAllVf(Cpa32U message)
{
    Cpa32U accelId = 0;
    Cpa32U VfId = 0;
    CpaStatus status = CPA_STATUS_FAIL;

    for (accelId = 0; accelId < MAX_DEVICE; accelId++)
    {
        for (VfId = 0; VfId < MAX_VF_DEVICE; VfId++)
        {
            status = icp_sal_userSendMsgToVf(accelId, VfId, message);
            if (status == CPA_STATUS_SUCCESS)
            {
                printf("Sending Message to AccelId ;%d ,Vf :%d Msg : %x \n",
                       accelId,
                       VfId,
                       message);
            }
        }
    }
}

/* Sending message to the VF with out checking the conditional check
 * */
void sendMsgToVf(Cpa32U accelId, Cpa32U VfId, Cpa32U message)
{
    icp_sal_userSendMsgToVf(accelId, VfId, message);
}

/* Check if the message has arrived and print the message if present
 * */

CpaStatus getMsgFromVf(Cpa32U accelId, Cpa32U VfId)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;

    status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (status == CPA_STATUS_SUCCESS && msgStatus == CPA_TRUE)
    {
        status =
            icp_sal_userGetMsgFromVf(accelId, VfId, &message, &messageCounter);
        printf("Accl Id :%d VfId :%d, Message : %x Msgcnt : %x \n",
               accelId,
               VfId,
               message,
               messageCounter);
    }
    return status;
}

/* Poll to check if message has been revived from the Guest */
void getMsgFromAllVf(Cpa32U accelId)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    Cpa32U VfId = 0;
    do
    {
        status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    } while (msgStatus == CPA_FALSE);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (msgStatus == CPA_TRUE)
    {
        for (VfId = 1; VfId < 8; VfId++)
        {
            do
            {
                status = icp_sal_userGetMsgFromVf(
                    accelId, VfId, &message, &messageCounter);
                //		printf("sendMsgToVfWithAck Status : %d 	\n",status);
            } while (messageCounter == 0);
            if (status == CPA_STATUS_SUCCESS)
            {
                printf("PF Rx Msg :Accl Id :%d VFId : %d Message : %x Msgcnt : "
                       "%x \n",
                       accelId,
                       VfId,
                       message,
                       messageCounter);
            }
        }
    }
}

/* Rx from host */
CpaStatus getMsgFromPf(Cpa32U accelId)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (status == CPA_STATUS_SUCCESS && msgStatus == CPA_TRUE)
    {
        status = icp_sal_userGetMsgFromPf(accelId, &message, &messageCounter);
        printf("Accl Id :%d Message : %x Msgcnt : %x \n",
               accelId,
               message,
               messageCounter);
    }
    return status;
}
CpaStatus icp_sal_userSendMsgToPf(Cpa32U accelId, Cpa32U message);

/* => VF */
void sendMsgToVfWithAck(Cpa32U accelId, Cpa32U VfId, Cpa32U msg)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    status = icp_sal_userSendMsgToVf(accelId, VfId, msg);
    if (status != CPA_STATUS_SUCCESS)
    {
        printf("Sending message to accelId :%d VfId :%d , msg ;%x \n",
               accelId,
               VfId,
               msg);
    }
    do
    {
        status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    } while (msgStatus == CPA_FALSE);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (msgStatus == CPA_TRUE)
    {
        do
        {
            status = icp_sal_userGetMsgFromVf(
                accelId, (VfId), &message, &messageCounter);
            //		printf("sendMsgToVfWithAck Status : %d 	\n",status);
        } while (messageCounter == 0);
        if (status == CPA_STATUS_SUCCESS)
        {
            if (message == (msg + 1))
            {
                printf("Ack :Accl Id :%d VFId : %d Message : %x Msgcnt : %x \n",
                       accelId,
                       VfId,
                       message,
                       messageCounter);
            }
            else
            {
                printf("Ack Out : Accl Id :%d VFId %d  Message : %x Msgcnt : "
                       "%x \n",
                       accelId,
                       VfId,
                       message,
                       messageCounter);
            }
        }
    }
}

void sendMsgToMultipleVfWithAck(Cpa32U accelId, Cpa32U VfId, Cpa32U msg)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;

    status = icp_sal_userSendMsgToVf(accelId, VfId, msg);
    if (status != CPA_STATUS_SUCCESS)
    {
        printf("Sending message to accelId :%d VfId :%d , msg ;%x \n",
               accelId,
               VfId,
               msg);
    }
    do
    {
        status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    } while (msgStatus == CPA_FALSE);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (msgStatus == CPA_TRUE)
    {
        do
        {
            status = icp_sal_userGetMsgFromVf(
                accelId, (VfId), &message, &messageCounter);
            //		printf("sendMsgToVfWithAck Status : %d 	\n",status);
        } while (messageCounter == 0);
        if (status == CPA_STATUS_SUCCESS)
        {
            if (message == (msg + 1))
            {
                printf("Ack :Accl Id :%d VFId : %d Message : %x Msgcnt : %x \n",
                       accelId,
                       VfId,
                       message,
                       messageCounter);
            }
            else
            {
                printf("Ack Out : Accl Id :%d VFId %d  Message : %x Msgcnt : "
                       "%x \n",
                       accelId,
                       VfId,
                       message,
                       messageCounter);
            }
        }
    }
}

void txMsgToVf(Cpa32U accelId, Cpa32U VfId, Cpa32U message)
{
    Cpa32U VfIds = 0;
    printf("txMsgToVf : Msg send :(%d,%d) %x \n", accelId, VfId, message);
    switch (message)
    {
        case RESET:
            for (VfIds = 1; VfIds < MAX_VF_DEVICE; VfIds++)
            {
                icp_sal_userSendMsgToVf(
                    accelId, VfIds, SAMPLE_CODE_RESET_REQUEST);
            }
            break;
        case TEST_MSG:
            icp_sal_userSendMsgToVf(accelId, VfId, SAMPLE_CODE_TEST_MSG);
            break;
        default:
            icp_sal_userSendMsgToVf(accelId, VfId, message);
            break;
    }
}

void startTimer()
{
    Cpa32U accelId = 0;
    Cpa32U VfId = 0;
    Cpa32U ackCount = 0;
    sleep(10);
    printf("Resetting the device \n");
    for (accelId = 0; accelId < MAX_DEVICE; accelId++)
    {
        if (reset_accelId[accelId])
        {
            for (VfId = 0; VfId < MAX_VF_DEVICE; VfId++)
            {
                if (reset_ack_rx[accelId][VfId] == CPA_TRUE)
                {
                    printf("RESET ACK Rx : accelId :%d VfId :%d \n",
                           accelId,
                           VfId);
                    ackCount++;
                }
                printf("Total Ack Recived :%d \n", ackCount);
            }
            //	icp_reset_device((Cpa32U) accelId);
        }

        reset_accelId[accelId] = CPA_FALSE;
    }
}

void processMsgInHost(Cpa32U accelId,
                      Cpa32U vfNum,
                      Cpa32U message,
                      Cpa32U messageCounter)
{
    printf("accelId %d, vfNum %d, message %x, messageCounter %x\n",
           accelId,
           vfNum,
           message,
           messageCounter);
    switch (message)
    {
        case SAMPLE_CODE_RESET_ACK:
            PRINT("SAMPLE_CODE_RESET_ACK \n");
            reset_ack_rx[accelId][vfNum] = CPA_TRUE;
            break;
        case SAMPLE_CODE_TEST_ACK:
            PRINT("SAMPLE_CODE_TEST_ACK \n");
            break;
        default:
            printf("Received invalid message %x \n", message);
            break;
    }
}

void rxMsgFromVf(Cpa32U accId)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    Cpa32U count = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    Cpa32U VfId = 0;
    Cpa32U accelId;
    //	while ( count++ < max_count)
    {
        printf("Count :%d \n", count);
        accelId = accId;
        printf("Accel Id :%d \n", accelId);
        do
        {
            status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
        } while (msgStatus == CPA_FALSE);
        printf("Status : %x msgStatus :%x \n", status, msgStatus);
        if (msgStatus == CPA_TRUE)
        {
            do
            {
                for (VfId = 1; VfId < MAX_VF_DEVICE; VfId++)
                {
                    if (vf_pf_host_set[accelId][VfId] == CPA_TRUE)
                    {
                        status = icp_sal_userGetMsgFromVf(
                            accelId, VfId, &message, &messageCounter);
                        break;
                    }
                }

                //		printf("sendMsgToVfWithAck Status : %d 	\n",status);
            } while (messageCounter == 0);
            if (status == CPA_STATUS_SUCCESS)
            {
                processMsgInHost(accelId, VfId, message, messageCounter);
                printf("PF Rx Msg :Accl Id :%d VFId : %d Message : %x Msgcnt : "
                       "%x \n",
                       accelId,
                       VfId,
                       message,
                       messageCounter);
            }
        }
    }
    count = 0;
    max_count = 50;
}

void eventRestTrigger(Cpa32U accelId, Cpa32U message)
{
    if (message == RESET)
    {
        reset_accelId[accelId] = CPA_TRUE;
        if (accelId < MAX_DEVICE)
        {
            signal(SIGALRM, startTimer);
            alarm(RESET_TIME_DELAY);
        }
    }
    else
    {
        printf("Only supported event : %d \n", message);
    }
}

void hostEventTrigger(Cpa32U accelId, Cpa32U vfNum, Cpa32U message)
{
    if (message == RESET)
    {
        eventRestTrigger(accelId, message);
    }
    txMsgToVf(accelId, vfNum, message);
}

void instanceStart(Cpa32U loop)
{
    pthread_t threadRx;
    pthread_t threadTx;

    pthread_create(&threadTx, NULL, txStartInstance, (void *)&loop);
    pthread_create(&threadRx, NULL, rxStartInstance, (void *)&loop);
    pthread_join(threadTx, NULL);
    pthread_join(threadRx, NULL);
}

/* Guest VF details */

void processMsgInGuest(Cpa32U accelId, Cpa32U message, Cpa32U messageCount)
{
    switch (message)
    {
        case SAMPLE_CODE_RESET_REQUEST:
            PRINT("SAMPLE_CODE_RESET_REQUEST \n");
            icp_sal_userSendMsgToPf(accelId, SAMPLE_CODE_RESET_ACK);
            break;
        case SAMPLE_CODE_TEST_MSG:
            PRINT("SAMPLE_CODE_TEST_MSG \n");
            icp_sal_userSendMsgToPf(accelId, SAMPLE_CODE_TEST_ACK);
            break;
        default:
            PRINT(" Unknown message \n");
            break;
    }
}

void *rxMsgFromPf(void *accId)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    Cpa32U count = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    Cpa32U accelId = -1;
    while (count++ < max_count)
    {
        printf("Count :%d \n", count);
        accelId = *((Cpa32U *)accId);
        printf("Accel Id :%d \n", accelId);
        do
        {
            status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
        } while (msgStatus == CPA_FALSE);
        printf("Status : %x msgStatus :%x \n", status, msgStatus);
        if (msgStatus == CPA_TRUE)
        {
            do
            {
                status = icp_sal_userGetMsgFromPf(
                    accelId, &message, &messageCounter);
            } while (messageCounter == 0);
            if (status == CPA_STATUS_SUCCESS)
            {
                processMsgInGuest(accelId, message, messageCounter);
                printf("PF Rx Msg :Accl Id :%d Message : %x Msgcnt : %x \n",
                       accelId,
                       message,
                       messageCounter);
            }
        }
    }
    count = 0;
    max_count = 50;
    return NULL;
}

void guestRxMsgapp(Cpa32U accelId, Cpa32U loop)
{
    static pthread_t threadRx[MAX_DEVICE];
    if (max_count < loop)
    {
        max_count = loop;
    }
    pthread_create(&threadRx[accelId], NULL, rxMsgFromPf, (void *)&accelId);
    pthread_join(threadRx[accelId], NULL);
}

void getMsgFromAllPf()
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    Cpa32U accelId = 0;
    do
    {
        status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    } while (msgStatus == CPA_FALSE);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (msgStatus == CPA_TRUE)
    {
        for (accelId = 0; accelId < 4; accelId++)
        {
            do
            {
                status = icp_sal_userGetMsgFromPf(
                    accelId, &message, &messageCounter);
            } while (messageCounter == 0);
            if (status == CPA_STATUS_SUCCESS)
            {
                printf("PF Rx Msg :Accl Id :%d Message : %x Msgcnt : %x \n",
                       accelId,
                       message,
                       messageCounter);
            }
        }
    }
}

void *txStartInstance(void *count)
{
    Cpa32U accelId = 0;
    Cpa32U vfNum = 0;

    Cpa32U loop = 0;
    loop = *((Cpa32U *)count);
    while (loop--)
    {
        printf("Enabled device PF and VF list \n");
        for (accelId = 0; accelId < MAX_DEVICE; accelId++)
        {
            for (vfNum = 0; vfNum < MAX_VF_DEVICE; vfNum++)
            {
                if (vf_pf_host_set[accelId][vfNum] == CPA_TRUE)
                {
                    hostEventTrigger(accelId, vfNum, RESET);
                    printf("accelId : vfNum %d,%d \n", accelId, vfNum);
                }
            }
        }
        sleep(4);
    }
    return NULL;
}

void *rxStartInstance(void *count)
{
    Cpa32U accelId = 0;

    Cpa32U loop = 0;
    accelId = *((Cpa32U *)count);
    while (loop--)
    {
        printf("Enabled device PF and VF list \n");
        for (accelId = 0; accelId < MAX_DEVICE; accelId++)
        {
            if (isDeviceEnabled(accelId))
            {
                rxMsgFromVf(accelId);
                printf("accelId : %d \n", accelId);
            }
        }
        sleep(5);
    }
    return NULL;
}

/* => PF */
void sendMsgToPfWithAck(Cpa32U accelId, Cpa32U VfId, Cpa32U msg)
{
    Cpa32U message = SAMPLE_CODE_EMPTY_MSG;
    Cpa32U messageCounter = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean msgStatus = CPA_FALSE;
    do
    {
        status = icp_sal_userGetPfVfcommsStatus(&msgStatus);
    } while (msgStatus == CPA_FALSE);
    printf("Status : %x msgStatus :%x \n", status, msgStatus);
    if (msgStatus == CPA_TRUE)
    {
        do
        {
            status =
                icp_sal_userGetMsgFromPf(accelId, &message, &messageCounter);
            //		printf("sendMsgToVfWithAck Status : %d 	\n",status);
        } while (messageCounter == 0);
        if (status == CPA_STATUS_SUCCESS)
        {

            status = icp_sal_userSendMsgToPf(accelId, message + 1);
            if (status != CPA_STATUS_SUCCESS)
            {
                printf("Sending message to accelId :%d VfId :%d , msg ;%x \n",
                       accelId,
                       VfId,
                       message);
            }

            if (message == (msg + 1))
            {
                printf("Accl Id :%d Message : %x SendMsg : %x  Msgcnt : %x \n",
                       accelId,
                       message,
                       msg,
                       messageCounter);
            }
            else
            {
                printf("Out of Sync Ack Rx Accl Id :%d Message : %x Msgcnt : "
                       "%x \n",
                       accelId,
                       message,
                       messageCounter);
            }
        }
    }
}

void *txStartGuestInstance(void *count)
{
    Cpa32U accelId = 0;
    Cpa32U vfNum = 0;

    Cpa32U loop = 0;
    loop = *((Cpa32U *)count);
    while (loop--)
    {
        printf("Enabled device PF and VF list \n");
        for (accelId = 0; accelId < MAX_DEVICE; accelId++)
        {
            for (vfNum = 0; vfNum < MAX_VF_DEVICE; vfNum++)
            {
                if (vf_pf_host_set[accelId][vfNum] == CPA_TRUE)
                {
                    hostEventTrigger(accelId, vfNum, TEST_MSG);
                    printf("accelId : vfNum %d,%d \n", accelId, vfNum);
                }
            }
        }
    };
    return NULL;
}

void *rxStartGuestInstance(void *count)
{
    Cpa32U accelId = 0;
    Cpa32U vfNum = 0;

    Cpa32U loop = 0;
    loop = *((Cpa32U *)count);
    while (loop--)
    {
        printf("Enabled device PF and VF list \n");
        for (accelId = 0; accelId < MAX_DEVICE; accelId++)
        {
            for (vfNum = 0; vfNum < MAX_VF_DEVICE; vfNum++)
            {
                if (vf_pf_host_set[accelId][vfNum] == CPA_TRUE)
                {
                    hostEventTrigger(accelId, vfNum, RESET);
                    printf("accelId : vfNum %d,%d \n", accelId, vfNum);
                }
            }
        }
    };
    return NULL;
}

void instanceStartGuest(Cpa32U loop)
{
    pthread_t threadRx;
    pthread_t threadTx;
    if (loop < 10)
        loop = 10;
    pthread_create(&threadTx, NULL, txStartGuestInstance, (void *)&loop);
    pthread_create(&threadRx, NULL, rxStartGuestInstance, (void *)&loop);
    pthread_join(threadTx, NULL);
    pthread_join(threadRx, NULL);
}

#endif // USER_SPACE
