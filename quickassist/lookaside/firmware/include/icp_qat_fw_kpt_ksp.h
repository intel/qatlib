/*
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
 */

/**
 * @file icp_qat_fw_kpt_ksp.h
 * @defgroup icp_qat_fw_kpt_ksp ICP QAT FW KPT KSP Processing Definitions
 * @ingroup icp_qat_fw
 * $Revision: 0.1 $
 * @brief
 *      This file documents the external interfaces that the QAT FW running
 *      on the QAT Acceleration Engine provides to clients wanting to
 *      accelerate crypto asymmetric applications
 */

#ifndef __ICP_QAT_FW_KPT_KSP_H__
#define __ICP_QAT_FW_KPT_KSP_H__

/**
 ***************************************************************************
 * @ingroup icp_qat_fw_kpt_ksp
 *      Request data for QAT messages
 *
 * @description
 *      This structure defines the request data for KPT KSP QAT messages. This
 *      is used to store data which is known when the message is sent and which
 *      we wish to retrieve when the response message is processed.
 **************************************************************************/
typedef struct icp_qat_fw_kpt_ksp_request_s
{
    Cpa8U resrvd0;
    Cpa8U cmdID;
    /* Kpt Ksp Command id */
    Cpa8U serviceType;
    /* Kpt Ksp service type */
    Cpa8U valid;
    Cpa16U keysel_flags;
    /* loadkey selection flag */
    Cpa16U resrvd1;
    /* iteration count */
    Cpa32U kpthandle_l;
    Cpa32U kpthandle_h;
    Cpa64U resrvd2;
    Cpa64U opaque_data;
    Cpa64U input_data;
    /* physical addr of SWK format */
    Cpa64U output_data;
    /* Output data physical addr, Loading WPK from QAT mode */
    Cpa8U resrvd3[16];
} icp_qat_fw_kpt_ksp_request_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_kpt_ksp
 *
 * @description
 *     Define the KPT ksp response format
 *
 *****************************************************************************/
typedef struct icp_qat_fw_kpt_ksp_resp_data_s
{
    Cpa8U resrvd0;
    Cpa8U cmdID;
    /* Kpt Ksp request command id */
    Cpa8U serviceType;
    /* Kpt Ksp request service type */
    Cpa8U value;
    Cpa16U rspStatus;
    /* Kpt Ksp request operation result */
    Cpa16U resrvd1;
    Cpa64U opaque_data;
    /* opaque data pointer, it's a copy of the callback data
     * passed when the request was created */
    Cpa8U resrvd3[16];
} icp_qat_fw_kpt_ksp_resp_data_t;

/**
 ***************************************************************************
 * @ingroup icp_qat_fw_kpt_ksp
 *      wrapping key format
 *
 * @description
 *      This structure defines the wrapping key format which will be used to
 *      decrypt wrapped private key in KPT PKE request
 **************************************************************************/
typedef struct icp_qat_kpt_ksp_key_format_s
{
    Cpa8U alg;
    /* wrapping algorithm */
    Cpa8U hmac_type;
    /* HMAC type */
    Cpa16U ic;
    /* iteration count */
    Cpa8U action;
    /* key action */
    Cpa8U resrvd[3];
    Cpa8U iv[16];
    /* initialization vector */
    Cpa8U state[40];
    /* GCM precompute state2 or HMAC key */
} icp_qat_kpt_ksp_key_format_t;
#endif
