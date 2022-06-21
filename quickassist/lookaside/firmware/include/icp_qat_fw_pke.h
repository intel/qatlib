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
 * @file icp_qat_fw_pke.h
 * @defgroup icp_qat_fw_pke ICP QAT FW PKE Processing Definitions
 * @ingroup icp_qat_fw
 * $Revision: 0.1 $
 * @brief
 *      This file documents the external interfaces that the QAT FW running
 *      on the QAT Acceleration Engine provides to clients wanting to
 *      accelerate crypto assymetric applications
 */

#ifndef _ICP_QAT_FW_PKE_
#define _ICP_QAT_FW_PKE_

/*
****************************************************************************
* Include local header files
****************************************************************************
*/
#include "icp_qat_fw.h"

/**
 *****************************************************************************
 *
 * @ingroup icp_qat_fw_pke
 *
 * @brief
 *      PKE response status field structure contained
 *      within LW1, comprising the common error codes and
 *      the response flags.
 *
 *****************************************************************************/
typedef struct icp_qat_fw_pke_resp_status_s
{
    uint8_t comn_err_code;
    /**< 8 bit common error code */

    uint8_t pke_resp_flags;
    /**< 8-bit PKE response flags  */

} icp_qat_fw_pke_resp_status_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_pke
 *      Definition of the QAT FW PKE request header pars field.
 *      Structure differs from the DH895xxCC common base header structure, hence
 *      redefined here.
 * @description
 *      PKE request message header pars structure
 *
 *****************************************************************************/
typedef struct icp_qat_fw_req_hdr_pke_cd_pars_s
{
    /**< LWs 2-3 */
    uint64_t content_desc_addr;
    /**< Content descriptor pointer */

    /**< LW 4 */
    uint32_t content_desc_resrvd;
    /**< Content descriptor reserved field */

    /**< LW 5 */
    uint32_t func_id;
    /**< MMP functionality Id */

} icp_qat_fw_req_hdr_pke_cd_pars_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_pke
 *      Definition of the QAT FW PKE request header mid section.
 *      Structure differs from the DH895xxCC common base header structure,
 *      instead following the DH89xxCC format, hence redefined here.
 * @description
 *      PKE request message header middle structure
 *
 *****************************************************************************/
typedef struct icp_qat_fw_req_pke_mid_s
{
    /**< LWs 6-11 */
    uint64_t opaque_data;
    /**< Opaque data passed unmodified from the request to response messages by
     * firmware (fw) */

    uint64_t src_data_addr;
    /**< Generic definition of the source data supplied to the QAT AE. The
     * common flags are used to further describe the attributes of this
     * field */

    uint64_t dest_data_addr;
    /**< Generic definition of the destination data supplied to the QAT AE. The
     * common flags are used to further describe the attributes of this
     * field */

    /**< Following DH89xxCC structure format - footer is excluded */

} icp_qat_fw_req_pke_mid_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_pke
 *      Definition of the QAT FW PKE request header.
 *      Structure differs from the DH895xxCC common base header structure,
 *      instead following the DH89xxCC format, hence redefined here.
 * @description
 *      PKE request message header structure
 *
 *****************************************************************************/
typedef struct icp_qat_fw_req_pke_hdr_s
{
    /**< LW0 */
    uint8_t resrvd1;
    /**< reserved field */

    uint8_t resrvd2;
    /**< reserved field */

    uint8_t service_type;
    /**< Service type */

    uint8_t hdr_flags;
    /**< This represents a flags field for the Service Request.
     * The most significant bit is the 'valid' flag and the only
     * one used. All remaining bit positions are unused and
     * are therefore reserved and need to be set to 0. */

    /**< LW1 */
    icp_qat_fw_comn_flags comn_req_flags;
    /**< Common Request flags must indicate flat buffer (as per DH89xxCC)
     * Common Request flags - PKE slice flags no longer used - slice
     * allocated to a threadstrand.*/

    uint8_t resrvd3;
    /**< reserved field */

    uint8_t resrvd4;
    /**< reserved field */

    /**< LWs 2-5 */
    icp_qat_fw_req_hdr_pke_cd_pars_t cd_pars;
    /**< PKE request message header pars structure - this differs
     * from the DH895xxCC common base structure */

} icp_qat_fw_req_pke_hdr_t;

/**
 ***************************************************************************
 *
 * @ingroup icp_qat_fw_pke
 *
 * @brief
 *      PKE request message structure (64 bytes)
 *
 *****************************************************************************/
typedef struct icp_qat_fw_pke_request_s
{
    /**< LWs 0-5 */
    icp_qat_fw_req_pke_hdr_t pke_hdr;
    /**< Request header for PKE - CD Header/Param size
     * must be zero */

    /**< LWs 6-11 (same as DH89xxCC) */
    icp_qat_fw_req_pke_mid_t pke_mid;
    /**< Request middle section for PKE */

    /**< LW 12 */
    uint8_t output_param_count;
    /**< Number of output large integers
     * for request */

    uint8_t input_param_count;
    /**< Number of input large integers
     * for request */

    uint16_t resrvd1;
    /** Reserved **/

    /**< LW 13 */
    uint32_t resrvd2;
    /**< Reserved */

    /**< LWs 14-15 */
    uint64_t next_req_adr;
    /** < PKE - next request address */

} icp_qat_fw_pke_request_t;

/**
 *****************************************************************************
 *
 * @ingroup icp_qat_fw_pke
 *
 * @brief
 *      PKE response message header structure
 *
 *****************************************************************************/
typedef struct icp_qat_fw_resp_pke_hdr_s
{
    /**< LW0 */
    uint8_t resrvd1;
    /**< The Response Destination Id has been removed
     * from first QWord */

    uint8_t resrvd2;
    /**< Response Pipe Id field is unused (reserved)
     * - Functionality within DH895xxCC uses arbiter instead */

    uint8_t response_type;
    /**< Response type - copied from the request to
     * the response message */

    uint8_t hdr_flags;
    /**< This represents a flags field for the Response.
     * The most significant bit is the 'valid' flag and the only
     * one used. All remaining bit positions are unused and
     * are therefore reserved */

    /**< LW1 */
    icp_qat_fw_pke_resp_status_t resp_status;

    uint16_t resrvd4;
    /**< (DH89xxCC) CD Header Size and CD Params Size fields unused.
     * Set to zero. */

} icp_qat_fw_resp_pke_hdr_t;

/**
 *****************************************************************************
 *
 * @ingroup icp_qat_fw_pke
 *
 * @brief
 *      PKE response message structure (32 bytes)
 *
 *****************************************************************************/
typedef struct icp_qat_fw_pke_resp_s
{
    /**< LWs 0-1 */
    icp_qat_fw_resp_pke_hdr_t pke_resp_hdr;
    /**< Response header for PKE */

    /**< LWs 2-3 */
    uint64_t opaque_data;
    /**< Opaque data passed from the request to the response message */

    /**< LWs 4-5 */
    uint64_t src_data_addr;
    /**< Generic definition of the source data supplied to the QAT AE. The
     * common flags are used to further describe the attributes of this
     * field */

    /**< LWs 6-7 */
    uint64_t dest_data_addr;
    /**< Generic definition of the destination data supplied to the QAT AE. The
     * common flags are used to further describe the attributes of this
     * field */

} icp_qat_fw_pke_resp_t;

/* ========================================================================= */
/*                           MACRO DEFINITIONS                               */
/* ========================================================================= */

/**< @ingroup icp_qat_fw_pke
 * Macro defining the bit position and mask of the 'valid' flag, within the
 * hdr_flags field of LW0 (service request and response) of the PKE request */
#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_BITPOS 7
#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_MASK 0x1

/**< @ingroup icp_qat_fw_pke
 * Macro defining the bit position and mask of the PKE status flag, within the
 * status field LW1 of a PKE response message */
#define QAT_COMN_RESP_PKE_STATUS_BITPOS 6
/**< @ingroup icp_qat_fw_pke
 * Starting bit position indicating the PKE status flag within the PKE response
 * pke_resp_flags byte.  */

#define QAT_COMN_RESP_PKE_STATUS_MASK 0x1
/**< @ingroup icp_qat_fw_pke
 * One bit mask used to determine PKE status mask */

/*
 *  < @ingroup icp_qat_fw_pke
 *  *** PKE Response Status Field Definition ***
 *  The PKE response follows the CPM 1.5 message format. The status field is 16
 *  bits wide, where the status flags are contained within the most significant
 *  byte of the icp_qat_fw_pke_resp_status_t structure. The lower 8 bits of this
 *  word now contain the common error codes, which are defined in the common
 *  header file(*).
 */

#ifdef __CLANG_FORMAT__
/* clang-format off */
#endif
/*  + ===== + ----- + ---- + ----- + ----- + ----- + ----- + ----- + ----- + ----------------------- +
 *  |  Bit  |  15   |  14  |  13   |  12   |  11   |  10   |   9   |   8   |        [7....0]         |
 *  + ===== + ----- + ---- + ----- + ----- + ----- + ----- + ----- + ----- + ----------------------- +
 *  | Flags | Rsrvd | Pke  | Rsrvd | Rsrvd | Rsrvd | Rsrvd | Rsrvd | Rsrvd |   Common error codes(*) |
 *  + ===== + ----- + ---- + ----- + ----- + ----- + ----- + ----- + ----- + ----------------------- +
 */
#ifdef __CLANG_FORMAT__
/* clang-format on */
#endif

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Macro for extraction of the PKE bit from the 16-bit status field
 *      particular to a PKE response. The status flags are contained within
 *      the most significant byte of the word. The lower 8 bits of this status
 *      word now contain the common error codes, which are defined in the common
 *      header file. The appropriate macro definition to extract the PKE status
 *      flag from the PKE response assumes that a single byte i.e.
 *      pke_resp_flags is passed to the macro.
 *
 * @param status
 *      Status to extract the PKE status bit
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_RESP_PKE_STAT_GET(flags)                                \
    QAT_FIELD_GET((flags),                                                     \
                  QAT_COMN_RESP_PKE_STATUS_BITPOS,                             \
                  QAT_COMN_RESP_PKE_STATUS_MASK)

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Extract the valid flag from the PKE Request's header flags. Note that
 *      this invokes the common macro which may be used by either the request
 *      or the response.
 *
 * @param icp_qat_fw_req_pke_hdr_t  Structure passed to extract the valid bit
 *                                  from the 'hdr_flags' field.
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_RQ_VALID_FLAG_GET(icp_qat_fw_req_pke_hdr_t)             \
    ICP_QAT_FW_PKE_HDR_VALID_FLAG_GET(icp_qat_fw_req_pke_hdr_t)

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Set the valid bit in the PKE Request's header flags. Note that
 *      this invokes the common macro which may be used by either the request
 *      or the response.
 *
 * @param icp_qat_fw_req_pke_hdr_t  Structure passed to set the valid bit.
 * @param val    Value of the valid bit flag.
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_RQ_VALID_FLAG_SET(icp_qat_fw_req_pke_hdr_t, val)        \
    ICP_QAT_FW_PKE_HDR_VALID_FLAG_SET(icp_qat_fw_req_pke_hdr_t, val)

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Extract the valid flag from the PKE Response's header flags. Note that
 *      invokes the common macro which may be used by either the request
 *      or the response.
 *
 * @param icp_qat_fw_resp_pke_hdr_t  Structure to extract the valid bit
 *                                    from the 'hdr_flags' field.
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_RESP_VALID_FLAG_GET(icp_qat_fw_resp_pke_hdr_t)          \
    ICP_QAT_FW_PKE_HDR_VALID_FLAG_GET(icp_qat_fw_resp_pke_hdr_t)

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Set the valid bit in the PKE Response's header flags. Note that
 *      this invokes the common macro which may be used by either the
 *      request or the response.
 *
 * @param icp_qat_fw_resp_pke_hdr_t  Structure to set the valid bit
 * @param val    Value of the valid bit flag.
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_RESP_VALID_FLAG_SET(icp_qat_fw_resp_pke_hdr_t, val)     \
    ICP_QAT_FW_PKE_HDR_VALID_FLAG_SET(icp_qat_fw_resp_pke_hdr_t, val)

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Common macro to extract the valid flag from the header flags field
 *      within the header structure (request or response).
 *
 * @param hdr_t  Structure (request or response) to extract the
 *               valid bit from the 'hdr_flags' field.
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_GET(hdr_t)                               \
    QAT_FIELD_GET(hdr_t.hdr_flags,                                             \
                  ICP_QAT_FW_PKE_HDR_VALID_FLAG_BITPOS,                        \
                  ICP_QAT_FW_PKE_HDR_VALID_FLAG_MASK)

/**
 ******************************************************************************
 * @ingroup icp_qat_fw_pke
 *
 * @description
 *      Common macro to set the valid bit in the header flags field within
 *      the header structure (request or response).
 *
 * @param hdr_t  Structure (request or response) containing the header
 *               flags field, to allow the valid bit to be set.
 * @param val    Value of the valid bit flag.
 *
 *****************************************************************************/
#define ICP_QAT_FW_PKE_HDR_VALID_FLAG_SET(hdr_t, val)                          \
    QAT_FIELD_SET((hdr_t.hdr_flags),                                           \
                  (val),                                                       \
                  ICP_QAT_FW_PKE_HDR_VALID_FLAG_BITPOS,                        \
                  ICP_QAT_FW_PKE_HDR_VALID_FLAG_MASK)

#endif /* _ICP_QAT_FW_PKE_ */
