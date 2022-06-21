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
 * @file icp_adf_transport_dp.h
 *
 * @description
 *      File contains Public API definitions for ADF transport for data plane.
 *
 *****************************************************************************/
#ifndef ICP_ADF_TRANSPORT_DP_H
#define ICP_ADF_TRANSPORT_DP_H

#include "cpa.h"
#include "icp_adf_transport.h"

/*
 * icp_adf_getQueueMemory
 * Data plane support function - returns the pointer to next message on the ring
 * or NULL if there is not enough space.
 */
extern void icp_adf_getQueueMemory(icp_comms_trans_handle trans_handle,
                                   Cpa32U numberRequests,
                                   void **pCurrentQatMsg);
/*
 * icp_adf_getSingleQueueAddr
 * Data plane support function - returns the pointer to next message on the ring
 * or NULL if there is not enough space - it also updates the shadow tail copy.
 */
extern void icp_adf_getSingleQueueAddr(icp_comms_trans_handle trans_handle,
                                       void **pCurrentQatMsg);

/*
 * icp_adf_getQueueNext
 * Data plane support function - increments the tail pointer and returns
 * the pointer to next message on the ring.
 */
extern void icp_adf_getQueueNext(icp_comms_trans_handle trans_handle,
                                 void **pCurrentQatMsg);

/*
 * icp_adf_updateQueueTail
 * Data plane support function - Writes the tail shadow copy to the device.
 */
extern void icp_adf_updateQueueTail(icp_comms_trans_handle trans_handle);

/*
 * icp_adf_isRingEmpty
 * Data plane support function - check if the ring is empty
 */
extern CpaBoolean icp_adf_isRingEmpty(icp_comms_trans_handle trans_handle);

/*
 * icp_adf_pollQueue
 * Data plane support function - Poll messages from the queue.
 */
extern CpaStatus icp_adf_pollQueue(icp_comms_trans_handle trans_handle,
                                   Cpa32U response_quota);

/*
 * icp_adf_queueDataToSend
 * LAC lite support function - Indicates if there is data on the ring to be
 * send. This should only be called on request rings. If the function returns
 * true then it is ok to call icp_adf_updateQueueTail() function on this ring.
 */
extern CpaBoolean icp_adf_queueDataToSend(icp_comms_trans_handle trans_hnd);

/*
 * icp_adf_getDpInflightRequests
 * Retrieves in-flight and max in-flight request counts
 */
extern void icp_adf_getDpInflightRequests(icp_comms_trans_handle trans_handle,
                                          Cpa32U *maxInflightRequests,
                                          Cpa32U *numInflightRequests);

#endif /* ICP_ADF_TRANSPORT_DP_H */
