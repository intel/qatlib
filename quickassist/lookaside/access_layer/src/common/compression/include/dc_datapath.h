/****************************************************************************
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

#include "cpa_dc.h"
#include "dc_session.h"
#include "sal_types_compression.h"
#include "lac_mem_pools.h"
#include "icp_qat_fw_dc_chain.h"

#define LAC_QAT_DC_REQ_SZ_LW 32
#define LAC_QAT_DC_RESP_SZ_LW 8

/* C62x and C3xxx pcie rev0 devices require an additional 32bytes */
#define DC_DEST_BUFFER_STA_ADDITIONAL_SIZE (32)

/* Minimum destination buffer size for decompression */
#define DC_DEST_BUFFER_DEC_MIN_SIZE (1)

/* Restriction on the source and destination buffer sizes for compression due
 * to the firmware taking 32 bits parameters. The max size is 2^32-1 */
#define DC_BUFFER_MAX_SIZE (0xFFFFFFFF)

/* DC Source & Destination buffer type (FLAT/SGL) */
#define DC_DEFAULT_QAT_PTR_TYPE QAT_COMN_PTR_TYPE_SGL
#define DC_DP_QAT_PTR_TYPE QAT_COMN_PTR_TYPE_FLAT

/* Offset to first byte of Input Byte Counter (IBC) in state register */
#define DC_STATE_IBC_OFFSET (8)
/* Size in bytes of input byte counter (IBC) in state register */
#define DC_IBC_SIZE_IN_BYTES (4)

/* Offset to first byte to CRC32 in state register */
#define DC_STATE_CRC32_OFFSET (40)
/* Offset to first byte to output CRC32 in state register */
#define DC_STATE_OUTPUT_CRC32_OFFSET (48)
/* Offset to first byte to input CRC32 in state register */
#define DC_STATE_INPUT_CRC32_OFFSET (52)

/* Offset to first byte of ADLER32 in state register */
#define DC_STATE_ADLER32_OFFSET (44)

/* 8 bit mask value */
#define DC_8_BIT_MASK (0xff)

/* 8 bit shift position */
#define DC_8_BIT_SHIFT_POS (8)

/* Size in bytes of checksum */
#define DC_CHECKSUM_SIZE_IN_BYTES (4)

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

/* Default values for CNV integrity checks,
 * those are used to inform hardware of specifying CRC parameters to be used
 * when calculating CRCs */
#define DC_CRC_POLY_DEFAULT 0x04c11db7
#define DC_CRC64_POLY_DEFAULT 0x42f0e1eba9ea3693ULL
#define DC_XOR_FLAGS_DEFAULT 0x000e0000
#define DC_XOR_OUT_DEFAULT 0xffffffff
#define DC_XOR64_OUT_DEFAULT 0x0ULL
#define DC_XOR64_MASK_DEFAULT 0x0ULL
#define DC_DEFAULT_CRC 0x0
#define DC_DEFAULT_ADLER32 0x1
#define DC_REFLECT_IN_DEFAULT 0x0
#define DC_REFLECT_OUT_DEFAULT 0x0

/* DC Chain info in compression cookie */
typedef struct dc_chain_info_s
{
    CpaBoolean isDcChaining;
    /* True if this request is part of a DC Chain operation */
} dc_chain_info_t;

/* List of the different OpData types supported as defined in the DC API header
 * file.
 */
typedef enum dc_opdata_type_e
{
    DC_OPDATA_TYPE0 = 0,
    /**< Refer to the API definition for CpaDcOpData format */
    DC_OPDATA_TYPE1
    /**< Refer to the API definition for CpaDcOpData2 format */
} dc_opdata_type_t;

typedef struct dc_opdata_ext_s
{
    void *pOpData;
    /**< Pointer to the OpData structure being used */
    dc_opdata_type_t opDataType;
    /**< Indicates the type of OpData being used */
} dc_opdata_ext_t;

/**
*******************************************************************************
* @ingroup cpaDc Data Compression
*      Compression cookie
* @description
*      This cookie stores information for a particular compression or
*      decompression perform op.
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
    /**< Pointer to the session handle. It is either a real address or a
     * special value used to identify requests coming from the NS API. */
    icp_qat_fw_comp_req_t request;
    /**< Compression request */
    void *callbackTag;
    /**< Opaque data supplied by the client */
    dc_session_desc_t *pSessionDesc;
    /**< Pointer to the session descriptor */
    CpaDcFlush flushFlag;
    /**< Flush flag */
    CpaDcOpData *pDcOpData;
    /**< struct containing flags and CRC related data for this session */
    CpaBoolean integrityCrcCheck;
    /**< If set to true, the implementation will verify that data
     * integrity is preserved through the processing pipeline.
     * This behaviour supports stateless and stateful behavior for
     * both static and dynamic Huffman encoding.
     *
     * Integrity CRC checking is not supported for decompression operations
     * over data that contains multiple gzip headers. */
    CpaBoolean verifyHwIntegrityCrcs;
    /**< If set to true, software calculated CRCs will be compared
     * against hardware generated integrity CRCs to ensure that data
     * integrity is maintained when transferring data to and from the
     * hardware accelerator. */
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
    CpaBufferList *pUserSrcBuff;
    /**< virtual userspace ptr to source SGL */
    CpaBufferList *pUserDestBuff;
    /**< virtual userspace ptr to destination SGL */
    CpaDcCallbackFn pCbFunc;
    /**< Callback function defined for the traditional sessionless API */
    CpaDcChecksum checksumType;
    /**< Type of checksum */
    dc_integrity_crc_fw_t dataIntegrityCrcs;
    /**< Data integrity table */
    dc_chain_info_t dcChain;
    /**< DC Chain info if DC used as part of a DC Chain operation. */
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

#ifndef KERNEL_SPACE
#ifdef ICP_PARAM_CHECK
CpaStatus dcCheckOpData(sal_compression_service_t *pService,
                        CpaDcOpData *pOpData,
                        CpaDcSessionDir sessDirection);
#endif
#endif

/**
 ***************************************************************************
 * @ingroup Dc_DataCompression
 *      Generates DC dummy response
 *
 * @description
 *      This function is called during the error state of the device to
 * generate dummy responses from the DC request memory pool.
 *
 * @param[in] pBucket               pointer to the bucket of memblks
 *
 * @retval CPA_STATUS_SUCCESS       Successfully polled a memory pool with data
 *                                  that generate dummy responses.
 * @retval CPA_STATUS_RETRY         There are no inflight requests in the
 *                                  memory pool associated with the instance
 *
 ***************************************************************************/
CpaStatus dcCompression_SwRespMsgCallback(lac_memblk_bucket_t *pBucket);

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

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Create the requests for compression or decompression
 *
 * @description
 *      Create the requests for compression or decompression. This function
 *      will update the cookie will all required information.
 *
 * @param[out]  pCookie             Pointer to the compression cookie
 * @param[in]   pService            Pointer to the compression service
 * @param[in]   pSessionDesc        Pointer to the session descriptor
 * @param[in]   pSessionHandle      Session handle
 * @param[in]   pSrcBuff            Pointer to data buffer for compression
 * @param[in]   pDestBuff           Pointer to buffer space for data after
 *                                  compression
 * @param[in]   pResults            Pointer to results structure
 * @param[in]   flushFlag           Indicates the type of flush to be
 *                                  performed
 * @param[in]   pOpData             Pointer to request information structure
 *                                  holding parameters for cpaDcCompress2
 *                                  and CpaDcDecompressData2
 * @param[in]   callbackTag         Pointer to the callback tag
 * @param[in]   compDecomp          Direction of the operation
 * @param[in]   cnvMode             CNV Mode
 * @param[in]   pDictionaryData     Pointer to CpaDcDictionaryData structure
 *                                  containing parameters for dictionary
 *                                  compression requests. If it is not a
 *                                  dictionary request then this parameter
 *                                  should be passed as NULL.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcCreateRequest(dc_compression_cookie_t *pCookie,
                          sal_compression_service_t *pService,
                          dc_session_desc_t *pSessionDesc,
                          CpaDcSessionHandle pSessionHandle,
                          CpaBufferList *pSrcBuff,
                          CpaBufferList *pDestBuff,
                          CpaDcRqResults *pResults,
                          CpaDcFlush flushFlag,
                          CpaDcOpData *pOpData,
                          void *callbackTag,
                          dc_request_dir_t compDecomp,
                          dc_cnv_mode_t cnvMode,
                          CpaDcDictionaryData *pDictionaryData);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression request parameters
 *
 * @description
 *      This function will populate the compression request parameters
 *
 * @param[out]  pCompReqParams   Pointer to the compression request parameters
 * @param[in]   pCookie          Pointer to the compression cookie
 *
 *****************************************************************************/
void dcCompRequestParamsPopulate(icp_qat_fw_comp_req_params_t *pCompReqParams,
                                 dc_compression_cookie_t *pCookie);

void dcHandleIntegrityChecksums(dc_compression_cookie_t *pCookie,
                                CpaCrcData *crc_external,
                                CpaDcRqResults *pDcResults,
                                CpaDcHuffType huffType,
                                CpaDcCompType compType,
                                CpaDcChecksum checksumType,
                                CpaBoolean isDcNs,
                                icp_qat_comp_chain_20_cmd_id_t chain_id);

void dcHandleIntegrityChecksumsLegacy(dc_compression_cookie_t *pCookie,
                                      CpaCrcData *crc_external,
                                      CpaDcRqResults *pDcResults,
                                      CpaDcHuffType huffType,
                                      CpaDcChecksum checksumType,
                                      CpaDcSessionState sessState,
                                      CpaDcSessionDir sessDirection,
                                      CpaBoolean isDcNs);

CpaStatus dcParamCheck(const CpaInstanceHandle dcInstance,
                       const CpaDcSessionHandle pSessionHandle,
                       const sal_compression_service_t *pService,
                       const CpaBufferList *pSrcBuff,
                       const CpaBufferList *pDestBuff,
                       const CpaDcRqResults *pResults,
                       const dc_session_desc_t *pSessionDesc,
                       const CpaDcFlush flushFlag,
                       const Cpa64U srcBuffSize);

CpaStatus dcCompDecompData(sal_compression_service_t *pService,
                           dc_session_desc_t *pSessionDesc,
                           CpaInstanceHandle dcInstance,
                           CpaDcSessionHandle pSessionHandle,
                           CpaBufferList *pSrcBuff,
                           CpaBufferList *pDestBuff,
                           CpaDcRqResults *pResults,
                           CpaDcFlush flushFlag,
                           CpaDcOpData *pOpData,
                           void *callbackTag,
                           dc_request_dir_t compDecomp,
                           CpaBoolean isAsyncMode,
                           dc_cnv_mode_t cnvMode,
                           CpaDcDictionaryData *pDictionaryData);

CpaStatus dcCheckSourceData(sal_compression_service_t *pService,
                            CpaDcSessionHandle pSessionHandle,
                            CpaBufferList *pSrcBuff,
                            CpaBufferList *pDestBuff,
                            CpaDcRqResults *pResults,
                            CpaDcFlush flushFlag,
                            Cpa64U srcBuffSize,
                            CpaDcSkipData *skipData);

CpaStatus dcCheckDestinationData(sal_compression_service_t *pService,
                                 CpaDcSessionHandle pSessionHandle,
                                 CpaBufferList *pDestBuff,
                                 dc_request_dir_t compDecomp);

CpaStatus dcCheckOpData(sal_compression_service_t *pService,
                        CpaDcOpData *pOpData,
                        CpaDcSessionDir sessDirection);

CpaStatus dcCheckDictData(CpaDcDictionaryData *pDictionaryData,
                          sal_compression_service_t *pService,
                          dc_session_desc_t *pSessionDesc);

#endif /* DC_DATAPATH_H_ */
