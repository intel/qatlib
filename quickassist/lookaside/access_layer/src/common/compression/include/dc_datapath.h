/****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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

/**
 *****************************************************************************
 * @file dc_datapath.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression datapath parameters.
 *
 *******************
 * **********************************************************/
#ifndef DC_DATAPATH_H_
#define DC_DATAPATH_H_

/* Include batch and pack definitions */
#include "cpa_dc_bp.h"

#define LAC_QAT_DC_REQ_SZ_LW 32
#define LAC_QAT_DC_RESP_SZ_LW 8

/* Restriction on the source buffer size for compression due to the firmware
 * processing */
#define DC_SRC_BUFFER_MIN_SIZE (15)

/* Restriction on the destination buffer size for compression due to
 * the management of skid buffers in the firmware */
#define DC_DEST_BUFFER_DYN_MIN_SIZE (128)
#define DC_DEST_BUFFER_STA_MIN_SIZE (64)
/* C62x and c3xxx pcie rev0 devices require an additional 32bytes */
#define DC_DEST_BUFFER_STA_ADDITIONAL_SIZE (32)

/* Minimum destination buffer size for decompression */
#define DC_DEST_BUFFER_DEC_MIN_SIZE (1)

/* Restriction on the source and destination buffer sizes for compression due
 * to the firmware taking 32 bits parameters. The max size is 2^32-1 */
#define DC_BUFFER_MAX_SIZE (0xFFFFFFFF)

/* DC Source & Destination buffer type (FLAT/SGL) */
#define DC_DEFAULT_QAT_PTR_TYPE QAT_COMN_PTR_TYPE_SGL
#define DC_DP_QAT_PTR_TYPE QAT_COMN_PTR_TYPE_FLAT

/* Mask used to set the most significant bit to zero */
#define DC_STATE_REGISTER_ZERO_MSB_MASK (0x7F)

/* Mask used to keep only the most significant bit and set the others to zero */
#define DC_STATE_REGISTER_KEEP_MSB_MASK (0x80)

/* Compression state register word containing the parity bit */
#define DC_STATE_REGISTER_PARITY_BIT_WORD (5)

/* Location of the parity bit within the compression state register word */
#define DC_STATE_REGISTER_PARITY_BIT (7)

/* size which needs to be reserved before the results field to
 * align the results field with the API struct  */
#define DC_API_ALIGNMENT_OFFSET (offsetof(CpaDcDpOpData, results))

/* Mask used to check the CompressAndVerify capability bit */
#define DC_CNV_EXTENDED_CAPABILITY (0x01)

/* Mask used to check the CompressAndVerifyAndRecover capability bit */
#define DC_CNVNR_EXTENDED_CAPABILITY (0x100)

/**
*******************************************************************************
* @ingroup cpaDc Data Compression
*      Compression cookie
* @description
*      This cookie stores information for a particular compression perform op.
*      This includes various user-supplied parameters for the operation which
*      will be needed in our callback function.
*      A pointer to this cookie is stored in the opaque data field of the QAT
*      message so that it can be accessed in the asynchronous callback.
* @note
*      The order of the parameters within this structure is important. It needs
*      to match the order of the parameters in CpaDcDpOpData up to the
*      pSessionHandle. This allows the correct processing of the callback.
*****************************************************************************/
typedef struct dc_compression_cookie_s
{
    Cpa8U dcReqParamsBuffer[DC_API_ALIGNMENT_OFFSET];
    /**< Memory block  - was previously reserved for request parameters.
     * Now size maintained so following members align with API struct,
     * but no longer used for request parameters */
    CpaDcRqResults reserved;
    /**< This is reserved for results to correctly align the structure
     * to match the one from the data plane API */
    CpaInstanceHandle dcInstance;
    /**< Compression instance handle */
    CpaDcSessionHandle pSessionHandle;
    /**< Pointer to the session handle */
    icp_qat_fw_comp_req_t request;
    /**< Compression request */
    void *callbackTag;
    /**< Opaque data supplied by the client */
    dc_session_desc_t *pSessionDesc;
    /**< Pointer to the session descriptor */
    CpaDcFlush flushFlag;
    /**< Flush flag */
    CpaDcRqResults *pResults;
    /**< Pointer to result buffer holding consumed and produced data */
    Cpa32U srcTotalDataLenInBytes;
    /**< Total length of the source data */
    Cpa32U dstTotalDataLenInBytes;
    /**< Total length of the destination data */
    dc_request_dir_t compDecomp;
    /**< Used to know whether the request is compression or decompression.
     * Useful when defining the session as combined */
#ifdef ICP_DC_ERROR_SIMULATION
    CpaDcReqStatus dcErrorToSimulate;
/**< Dc error inject simulation */
#endif
} dc_compression_cookie_t;

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Callback function called for compression and decompression requests in
 *      asynchronous mode
 *
 * @description
 *      Called to process compression and decompression response messages. This
 *      callback will check for errors, update the statistics and will call the
 *      user callback
 *
 * @param[in]   pRespMsg        Response message
 *
 *****************************************************************************/
void dcCompression_ProcessCallback(void *pRespMsg);

/**
*****************************************************************************
* @ingroup Dc_DataCompression
*      Describes CNV and CNVNR modes
*
* @description
*      This enum is used to indicate the CNV modes.
*
*****************************************************************************/
typedef enum dc_cnv_mode_s
{
    DC_NO_CNV = 0,
    /* CNV = CPA_FALSE, CNVNR = CPA_FALSE */
    DC_CNV,
    /* CNV = CPA_TRUE, CNVNR = CPA_FALSE */
    DC_CNVNR,
    /* CNV = CPA_TRUE, CNVNR = CPA_TRUE */
} dc_cnv_mode_t;

#endif /* DC_DATAPATH_H_ */
