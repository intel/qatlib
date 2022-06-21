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
 * @file icp_adf_transport.h
 *
 * @description
 *      File contains Public API Definitions for ADF transport.
 *
 *****************************************************************************/
#ifndef ICP_ADF_TRANSPORT_H
#define ICP_ADF_TRANSPORT_H

#include "cpa.h"
#include "icp_accel_devices.h"
#include "icp_adf_init.h"

/* Invalid sequence number. */
#define ICP_ADF_INVALID_SEND_SEQ ((Cpa64U)~0)

/*
 * Enumeration on Transport Types exposed
 */
typedef enum icp_transport_type_e
{
    ICP_TRANS_TYPE_NONE = 0,
    ICP_TRANS_TYPE_ETR,
    ICP_TRANS_TYPE_DP_ETR,
    ICP_TRANS_TYPE_DELIMIT
} icp_transport_type;

/*
 * Enumeration on response delivery method
 */
typedef enum icp_resp_deliv_method_e
{
    ICP_RESP_TYPE_NONE = 0,
    ICP_RESP_TYPE_IRQ,
    ICP_RESP_TYPE_POLL,
    ICP_RESP_TYPE_DELIMIT
} icp_resp_deliv_method;

/*
 * Unique identifier of a transport handle
 */
typedef Cpa32U icp_trans_identifier;

/*
 * Opaque Transport Handle
 */
typedef void *icp_comms_trans_handle;

/*
 * Function Pointer invoked when a set of messages is received for the given
 * transport handle
 */
typedef void (*icp_trans_callback)(void *pMsg);

/*
 * icp_adf_getDynInstance
 *
 * Description:
 * Get an available instance from dynamic instance pool
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 */
CpaStatus icp_adf_getDynInstance(icp_accel_dev_t *accel_dev,
                                 adf_service_type_t stype,
                                 Cpa32U *pinstance_id);

/*
 * icp_adf_putDynInstance
 *
 * Description:
 * Put back an instance to dynamic instance pool
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 */
CpaStatus icp_adf_putDynInstance(icp_accel_dev_t *accel_dev,
                                 adf_service_type_t stype,
                                 Cpa32U instance_id);

/*
 * icp_adf_getNumAvailDynInstance
 *
 * Description:
 * Get the number of the available dynamic instances
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 */
CpaStatus icp_adf_getNumAvailDynInstance(icp_accel_dev_t *accel_dev,
                                         adf_service_type_t stype,
                                         Cpa32U *num);

/*
 * icp_adf_transGetFdForHandle
 *
 * Description:
 * Get a file descriptor for a particular transaction handle.
 * If more than one transaction handler
 * are ever present, this will need to be refactored to
 * return the appropiate fd of the appropiate bank.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 *
 */
CpaStatus icp_adf_transGetFdForHandle(icp_comms_trans_handle trans_hnd,
                                      int *fd);

/*
 * icp_adf_transCreateHandle
 *
 * Description:
 * Create a transport handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 *   The message size is variable: requests can be 64 or 128 bytes, responses
 *   can be 16, 32 or 64 bytes.
 *   Supported num_msgs:
 *     32, 64, 128, 256, 512, 1024, 2048 number of messages.
 *
 */
CpaStatus icp_adf_transCreateHandle(icp_accel_dev_t *accel_dev,
                                    icp_transport_type trans_type,
                                    const char *section,
                                    const Cpa32U accel_nr,
                                    const Cpa32U bank_nr,
                                    const char *service_name,
                                    const icp_adf_ringInfoService_t info,
                                    icp_trans_callback callback,
                                    icp_resp_deliv_method resp,
                                    const Cpa32U num_msgs,
                                    const Cpa32U msg_size,
                                    icp_comms_trans_handle *trans_handle);
/*
 * icp_adf_transReinitHandle
 *
 * Description:
 * Reinitialize a transport handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 *   The message size is variable: requests can be 64 or 128 bytes, responses
 *   can be 16, 32 or 64 bytes.
 *   Supported num_msgs:
 *     32, 64, 128, 256, 512, 1024, 2048 number of messages.
 *
 */
CpaStatus icp_adf_transReinitHandle(icp_accel_dev_t *accel_dev,
                                    icp_transport_type trans_type,
                                    const char *section,
                                    const Cpa32U accel_nr,
                                    const Cpa32U bank_nr,
                                    const char *service_name,
                                    const icp_adf_ringInfoService_t info,
                                    icp_trans_callback callback,
                                    icp_resp_deliv_method resp,
                                    const Cpa32U num_msgs,
                                    const Cpa32U msg_size,
                                    icp_comms_trans_handle *trans_handle);

/*
 * icp_adf_transGetHandle
 *
 * Description:
 * Gets a pointer to a previously created transport handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 *
 */
CpaStatus icp_adf_transGetHandle(icp_accel_dev_t *accel_dev,
                                 icp_transport_type trans_type,
                                 const char *section,
                                 const Cpa32U accel_nr,
                                 const Cpa32U bank_nr,
                                 const char *service_name,
                                 icp_comms_trans_handle *trans_handle);

/*
 * icp_adf_transReleaseHandle
 *
 * Description:
 * Release a transport handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_transReleaseHandle(icp_comms_trans_handle trans_handle);

/*
 * icp_adf_transResetHandle
 *
 * Description:
 * Reset a transport handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_transResetHandle(icp_comms_trans_handle trans_handle);

/*
 * icp_adf_transPutMsg
 *
 * Description:
 * Put Message onto the transport handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_transPutMsg(icp_comms_trans_handle trans_handle,
                              Cpa32U *inBufs,
                              Cpa32U bufLen,
                              Cpa64U *seq_num);

/*
 * icp_adf_getInflightRequests
 *
 * Description:
 * Retrieves in-flight and max in-flight request counts
 *
 * Returns:
 *   CPA_STATUS_SUCCESS        on success
 *   CPA_STATUS_FAIL           on failure
 *   CPA_STATUS_INVALID_PARAM  invalid parameter
 */
CpaStatus icp_adf_getInflightRequests(icp_comms_trans_handle trans_handle,
                                      Cpa32U *maxInflightRequests,
                                      Cpa32U *numInflightRequests);

/*
 * icp_adf_transPutMsgSync
 *
 * Description:
 * Put Message onto the transport handle and waits for a response.
 * Note: Not all transports support method.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_transPutMsgSync(icp_comms_trans_handle trans_handle,
                                  Cpa32U *inBuf,
                                  Cpa32U *outBuf,
                                  Cpa32U bufsLen);

/*
 * icp_adf_transGetRingNum
 *
 * Description:
 *  Function Returns ring number of the given trans_handle
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on success
 *   CPA_STATUS_FAIL      on failure
 */
CpaStatus icp_adf_transGetRingNum(icp_comms_trans_handle trans_handle,
                                  Cpa32U *ringNum);

#endif /* ICP_ADF_TRANSPORT_H */
