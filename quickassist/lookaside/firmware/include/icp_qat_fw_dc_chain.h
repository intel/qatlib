/*
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
 */

/**
 * @file icp_qat_fw_dc_chain.h
 * @defgroup icp_qat_fw_dc_chain ICP QAT FW CHAIN Processing Definitions
 * @ingroup icp_qat_fw
 * $Revision: 0.1 $
 * @brief
 *      This file documents the external interfaces that the QAT FW running
 *      on the QAT Acceleration Engine provides to clients wanting to
 *      accelerate chaining applications
 */
#include "lac_common.h"

#ifndef __ICP_QAT_FW_DC_CHAIN_H__
#define __ICP_QAT_FW_DC_CHAIN_H__

#define ICP_QAT_FW_COMP_CHAIN_REQ_EXTEND_FLAGS_BUILD(                          \
    cnv, asb, cbc, xts, ccm, cnvnr)                                            \
    (((cnv & ICP_QAT_FW_COMP_CHAIN_CNV_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_CNV_BITPOS) |                                   \
     ((asb & ICP_QAT_FW_COMP_CHAIN_ASB_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_ASB_BITPOS) |                                   \
     ((cbc & ICP_QAT_FW_COMP_CHAIN_CBC_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_CBC_BITPOS) |                                   \
     ((xts & ICP_QAT_FW_COMP_CHAIN_XTS_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_XTS_BITPOS) |                                   \
     ((ccm & ICP_QAT_FW_COMP_CHAIN_CCM_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_CCM_BITPOS) |                                   \
     ((cnvnr & ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_MASK)                        \
      << ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_BITPOS))

#define ICP_QAT_FW_COMP_CHAIN_NO_CNV 0
#define ICP_QAT_FW_COMP_CHAIN_CNV 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CNV_RECOVERY 0
#define ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY 1
#define ICP_QAT_FW_COMP_CHAIN_NO_ASB 0
#define ICP_QAT_FW_COMP_CHAIN_ASB 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CBC 0
#define ICP_QAT_FW_COMP_CHAIN_CBC 1
#define ICP_QAT_FW_COMP_CHAIN_NO_XTS 0
#define ICP_QAT_FW_COMP_CHAIN_XTS 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CCM 0
#define ICP_QAT_FW_COMP_CHAIN_CCM 1
#define ICP_QAT_FW_COMP_CHAIN_CNV_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CNV_BITPOS 0
#define ICP_QAT_FW_COMP_CHAIN_ASB_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_ASB_BITPOS 4
#define ICP_QAT_FW_COMP_CHAIN_CBC_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CBC_BITPOS 6
#define ICP_QAT_FW_COMP_CHAIN_XTS_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_XTS_BITPOS 10
#define ICP_QAT_FW_COMP_CHAIN_CCM_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CCM_BITPOS 8
#define ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_BITPOS 12
#define DC_CHAIN_MAX_LINK 0x3
typedef enum
{
    ICP_QAT_FW_NO_CHAINING,
    ICP_QAT_FW_CHAINING_CMD_DECRYPT_DECOMPRESS,
    ICP_QAT_FW_CHAINING_CMD_HASH_DECOMPRESS,
    ICP_QAT_FW_CHAINING_CMD_HASH_STATIC_COMP,
    ICP_QAT_FW_CHAINING_CMD_HASH_DYNAMIC_COMP,
    ICP_QAT_FW_CHAINING_CMD_DECOMPRESS_HASH,
    ICP_QAT_FW_CHAINING_CMD_STATIC_COMP_ENCRYPT,
    ICP_QAT_FW_CHAINING_CMD_STATIC_COMP_ENCRYPT_HASH,
    ICP_QAT_FW_CHAINING_CMD_STATIC_COMP_HASH,
    ICP_QAT_FW_CHAINING_CMD_DYNAMIC_COMP_ENCRYT,
    ICP_QAT_FW_CHAINING_CMD_DYNAMIC_COMP_ENCRYPT_HASH,
    ICP_QAT_FW_CHAINING_CMD_DYNAMIC_COMP_HASH,
} icp_qat_comp_chain_cmd_id_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *
 * @description
 *     Define the chaining request discriptor header
 *
 *****************************************************************************/
typedef struct icp_qat_comp_chain_req_hdr_s
{
    /* LW0 */
    Cpa8U resrvd1;
    /* Reserved field */
    Cpa8U service_cmd_id;
    /* Service Command Id  - this field is service-specific
     * valid value are in enum icp_qat_comp_chain_cmd_id_t
     * except ICP_QAT_FW_NO_CHAINING
     */
    Cpa8U service_type;
    /* Service type */
    Cpa8U hdr_flags;
    /* This represents a flags field for the Service Request.
     * The most significant bit is the 'valid' flag and the only
     * one used. All remaining bit positions are unused and
     * are therefore reserved and need to be set to 0.
     */

    /* LW1 */
    Cpa16U numLinks;
    /* Number of links for chaining request */
} icp_qat_comp_chain_req_hdr_t;

/**
 ***************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *      Request data for chaining QAT messages
 *
 * @description
 *      This structure defines the request data for chaining QAT messages. This
 * is used to store data which is known when the message is sent and which we
 * wish to retrieve when the response message is processed.
 **************************************************************************/
typedef struct icp_qat_fw_comp_chain_req_s
{
    icp_qat_comp_chain_req_hdr_t hdr;
    /* Chaining request header */
    Cpa16U extendFlags;
    /* Extend flags for CBC, CNV, ASB */
    Cpa32U resrvd1[4];
    Cpa64U opaque_data;
    /* Chaining cookie pointer */
    Cpa32U resrvd2[8];
    Cpa64U compReqAddr;
    /* Physical address for compression request */
    Cpa64U compRespAddr;
    /* Physical address for compression response */
    Cpa64U symCryptoReqAddr;
    /* Physical address for symmetric crypto request */
    Cpa64U symCryptoRespAddr;
    /* Physical address for symmetric crypto response */
    Cpa32U resrvd3[8];
} icp_qat_fw_comp_chain_req_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *
 * @description
 *     Define the chaining response format
 *
 *****************************************************************************/
typedef struct icp_qat_fw_comp_chain_resp_s
{
    Cpa8U resrvd0;
    Cpa8U cmdID;
    /* Chaining Command id */
    Cpa8U serviceType;
    /* Chaining service type */
    Cpa8U valid;

    Cpa16U resrvd1;
    Cpa8U rspStatus;
    /* Response status */
    Cpa8U chainCmdID;
    /* Chaining Command id */
    Cpa64U opaque_data;
    /*
     * Opaque data pointer, it's a copy of the callback data
     * passed when the request was created
     */
    Cpa32U numLinks;
    /* Number of links in chain */
    Cpa32U resrvd2[3];
} icp_qat_fw_comp_chain_resp_t;
#endif
