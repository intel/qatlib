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
 * @file dc_ns_datapath.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the No-Session (NS) variant of Data Compression
 *      datapath operations.
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_dc.h"
#include "cpa_dc_dp.h"

#include "icp_qat_hw_20_comp.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "dc_session.h"
#include "dc_datapath.h"
#include "dc_ns_datapath.h"
#include "sal_statistics.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_log.h"
#include "sal_types_compression.h"
#include "dc_stats.h"
#include "lac_buffer_desc.h"
#include "lac_sal.h"
#include "lac_sync.h"
#include "sal_service_state.h"
#include "sal_qat_cmn_msg.h"
#ifdef ICP_DC_ERROR_SIMULATION
#include "dc_err_sim.h"
#endif
#include "dc_error_counter.h"
#include "dc_crc32.h"
#include "dc_crc64.h"
#include "sal_misc_error_stats.h"

void dcNsCompression_ProcessCallback(void *pRespMsg)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_comp_resp_t *pCompRespMsg = NULL;
    void *callbackTag = NULL;
    Cpa64U *pReqData = NULL;
    CpaDcDpOpData *pDpOpData = NULL;
    CpaDcRqResults *pResults = NULL;
    CpaDcCallbackFn pCbFunc = NULL;
    sal_compression_service_t *pService = NULL;
    dc_compression_cookie_t *pCookie = NULL;
    CpaDcOpData *pOpData = NULL;
    CpaBoolean cmpPass = CPA_TRUE, xlatPass = CPA_TRUE;
    CpaBoolean integrityCrcCheck = CPA_FALSE;
    Cpa8S cmpErr = ERR_CODE_NO_ERROR;
#ifndef ICP_DC_DYN_NOT_SUPPORTED
    Cpa8S xlatErr = ERR_CODE_NO_ERROR;
#endif
    dc_request_dir_t compDecomp = DC_COMPRESSION_REQUEST;
    Cpa8U opStatus = ICP_QAT_FW_COMN_STATUS_FLAG_OK;
    Cpa8U hdrFlags = 0;
    CpaDcChecksum checksumType = CPA_DC_NONE;
    CpaBoolean isDcDp = CPA_FALSE;
    CpaDcCompType compType = CPA_DC_DEFLATE;
    CpaDcHuffType huffType = CPA_DC_HT_STATIC;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean bypassIncompleteFileErr = CPA_FALSE;
    CpaBoolean uncompressedDataSupported = CPA_FALSE;
    CpaDcSessionDir sessDirection = CPA_DC_DIR_COMPRESS;
    dc_hw_gen_types_t hw_gen;

    /* Cast response message to compression response message type */
    pCompRespMsg = (icp_qat_fw_comp_resp_t *)pRespMsg;

#ifdef ICP_PARAM_CHECK
    LAC_ASSERT_NOT_NULL(pCompRespMsg);
    if (!pCompRespMsg)
        return;
#endif

    /* Extract request data pointer from the opaque data */
    LAC_MEM_SHARED_READ_TO_PTR(pCompRespMsg->opaque_data, pReqData);

#ifdef ICP_PARAM_CHECK
    LAC_ASSERT_NOT_NULL(pReqData);
    if (!pReqData)
        return;
#endif

    /* Extract fields from the request data structure */
    pCookie = (dc_compression_cookie_t *)pReqData;

    pService = (sal_compression_service_t *)(pCookie->dcInstance);

#ifdef ICP_PARAM_CHECK
    LAC_ASSERT_NOT_NULL(pService);
#endif

    /* Retrieve capabilities */
    pDcCapabilities = &pService->dc_capabilities;
    bypassIncompleteFileErr = pDcCapabilities->deflate.bypassIncompleteFileErr;
    uncompressedDataSupported =
        pDcCapabilities->deviceData.uncompressedDataSupported;
    hw_gen = pDcCapabilities->deviceData.hw_gen;

    if (DCDPNS == (LAC_ARCH_UINT)pCookie->pSessionHandle)
    {
        isDcDp = CPA_TRUE;
        pDpOpData = (CpaDcDpOpData *)pReqData;
        pResults = &pDpOpData->results;

        if (CPA_DC_DIR_DECOMPRESS == pDpOpData->sessDirection)
        {
            compDecomp = DC_DECOMPRESSION_REQUEST;
        }

        compType = pDpOpData->pSetupData->compType;
        huffType = pDpOpData->pSetupData->huffType;
        checksumType = pDpOpData->pSetupData->checksum;
        pCookie = NULL;
    }
    else
    {
        pResults = pCookie->pResults;
        callbackTag = pCookie->callbackTag;
        pCbFunc = pCookie->pCbFunc;
        compDecomp = pCookie->compDecomp;
        pOpData = pCookie->pDcOpData;
        checksumType = pCookie->checksumType;

        switch (pCookie->request.comn_hdr.service_cmd_id)
        {
            case ICP_QAT_FW_COMP_20_CMD_LZ4_COMPRESS:
            case ICP_QAT_FW_COMP_20_CMD_LZ4_DECOMPRESS:
                compType = CPA_DC_LZ4;
                break;
            case ICP_QAT_FW_COMP_20_CMD_LZ4S_COMPRESS:
                compType = CPA_DC_LZ4S;
                break;
        }

        if (ICP_QAT_FW_COMP_CMD_DYNAMIC ==
            pCookie->request.comn_hdr.service_cmd_id)
        {
            huffType = CPA_DC_HT_FULL_DYNAMIC;
        }
    }

    if (DC_DECOMPRESSION_REQUEST == compDecomp)
    {
        sessDirection = CPA_DC_DIR_DECOMPRESS;
    }

    opStatus = pCompRespMsg->comn_resp.comn_status;

    if (NULL != pOpData)
    {
        integrityCrcCheck = pOpData->integrityCrcCheck;
    }

    hdrFlags = pCompRespMsg->comn_resp.hdr_flags;

    /* Get the cmp error code */
    cmpErr = (Cpa8S)pCompRespMsg->comn_resp.comn_error.s1.cmp_err_code;

#ifdef ICP_DC_ERROR_SIMULATION
    if (!isDcDp && 0 != pCookie->dcErrorToSimulate)
    {
        cmpErr = pCookie->dcErrorToSimulate;
    }
#endif

    if (ICP_QAT_FW_COMN_RESP_UNSUPPORTED_REQUEST_STAT_GET(opStatus))
    {
        /* Compression not supported by firmware, set produced/consumed to
         * zero and call the cb function with status CPA_STATUS_UNSUPPORTED
         */
        LAC_LOG_ERROR("Compression feature not supported");
        status = CPA_STATUS_UNSUPPORTED;

        pResults->status = cmpErr;
        pResults->consumed = 0;
        pResults->produced = 0;

        if (isDcDp)
        {
            pDpOpData->responseStatus = status;
            (pService->pDcDpCb)(pDpOpData);
        }
        else
        {
            /* Free the memory pool */
            if (NULL != pCookie)
            {
                Lac_MemPoolEntryFree(pCookie);
                pCookie = NULL;
            }

            if (NULL != pCbFunc)
            {
                pCbFunc(callbackTag, status);
            }
        }

        if (DC_COMPRESSION_REQUEST == compDecomp)
        {
            COMPRESSION_STAT_INC(numCompCompletedErrors, pService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompCompletedErrors, pService);
        }

        SAL_MISC_ERR_STATS_INC(cmpErr, &pService->generic_service_info);
        return;
    }
    else
    {
        /* Check compression response status */
        cmpPass = ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                  ICP_QAT_FW_COMN_RESP_CMP_STAT_GET(opStatus);

        SAL_MISC_ERR_STATS_INC(cmpErr, &pService->generic_service_info);
    }

    switch (cmpErr)
    {
        case ERR_CODE_HW_INCOMPLETE_FILE:
            /* Cancel the incomplete file error code only for DEFLATE algorithm
             */
            if ((CPA_TRUE == bypassIncompleteFileErr) &&
                (CPA_DC_DEFLATE == compType))
            {
                cmpPass = CPA_TRUE;
                cmpErr = ERR_CODE_NO_ERROR;
            }
            break;
        case ERR_CODE_SSM_ERROR:
            /* log the slice hang error inside the response */
            LAC_LOG_ERROR(
                "The slice hang is detected on the compression slice");
            break;
        case ERR_CODE_SSM_PARITY_ERROR:
            /* log ssm parity error inside the response */
            LAC_LOG_ERROR("Operation resulted in a parity error in one or more "
                          "accelerators.");
            break;
        case ERR_CODE_ENDPOINT_ERROR:
            /* log the endpoint push/pull error inside the response */
            LAC_LOG_ERROR(
                "The PCIe End Point Push/Pull or TI/RI Parity error detected.");
            break;
    }

    /* We return the compression error code for now. We would need to update
     * the API if we decide to return both error codes */
    pResults->status = cmpErr;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
    /* Check the translator status */
    if ((DC_COMPRESSION_REQUEST == compDecomp) &&
        (CPA_DC_HT_FULL_DYNAMIC == huffType))
    {
        /* Check translator response status */
        xlatPass = ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                   ICP_QAT_FW_COMN_RESP_XLAT_STAT_GET(opStatus);

        /* Get the translator error code */
        xlatErr = (Cpa8S)pCompRespMsg->comn_resp.comn_error.s1.xlat_err_code;

        /* Return a fatal error or a potential error in the translator slice
         * if the compression slice did not return any error */
        if ((ERR_CODE_NO_ERROR == cmpErr) || (ERR_CODE_FATAL_ERROR == xlatErr))
        {
            pResults->status = xlatErr;
        }
    }
#endif

    /* Update dc error counter */
    dcErrorLog(pResults->status);

    if (!isDcDp)
    {
        if (DC_COMPRESSION_REQUEST == compDecomp)
        {
            /* Overflow is a valid use case for Traditional API only.
             * Stateless Overflow is supported only in compression direction.
             */
            if (ERR_CODE_OVERFLOW_ERROR == cmpErr)
                cmpPass = CPA_TRUE;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
            if (ERR_CODE_OVERFLOW_ERROR == xlatErr)
                xlatPass = CPA_TRUE;
#endif
        }
    }
    else
    {
        if (ERR_CODE_OVERFLOW_ERROR == cmpErr)
            cmpPass = CPA_FALSE;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
        if (ERR_CODE_OVERFLOW_ERROR == xlatErr)
            /* XLT overflow is not valid for Data Plane requests */
            xlatPass = CPA_FALSE;
#endif
    }

    if ((CPA_TRUE == cmpPass) && (CPA_TRUE == xlatPass))
    {
        /* Extract the response from the firmware */
        pResults->consumed = pCompRespMsg->comp_resp_pars.input_byte_counter;
        pResults->produced = pCompRespMsg->comp_resp_pars.output_byte_counter;

        /* Handle Checksum for end to end data integrity. */
        if ((CPA_TRUE == integrityCrcCheck) &&
            (CPA_TRUE == pDcCapabilities->crcIntegrity.supported))
        {
            if (hw_gen >= DC_CAPS_GEN4_HW)
            {
                dcHandleIntegrityChecksums(pCookie,
                                           pOpData->pCrcData,
                                           pResults,
                                           huffType,
                                           compType,
                                           checksumType,
                                           CPA_TRUE,
                                           ICP_QAT_FW_NO_CHAINING_20);
            }
            else
            {
                dcHandleIntegrityChecksumsLegacy(pCookie,
                                                 pOpData->pCrcData,
                                                 pResults,
                                                 huffType,
                                                 checksumType,
                                                 CPA_DC_STATELESS,
                                                 sessDirection,
                                                 CPA_TRUE);
            }

            if (pResults->status == CPA_DC_CRC_INTEG_ERR)
            {
                cmpPass = CPA_FALSE;
            }
        }
        else
        {
            if (CPA_DC_CRC32 == checksumType)
            {
                pResults->checksum =
                    pCompRespMsg->comp_resp_pars.crc.legacy.curr_crc32;
            }
            else if ((CPA_DC_ADLER32 == checksumType) ||
                     (CPA_DC_XXHASH32 == checksumType))
            {
                pResults->checksum =
                    pCompRespMsg->comp_resp_pars.crc.legacy.curr_adler_32;
            }
        }
    }

    if ((CPA_TRUE == cmpPass) && (CPA_TRUE == xlatPass))
    {
        if ((DC_COMPRESSION_REQUEST == compDecomp) &&
            (CPA_TRUE == uncompressedDataSupported))
        {
            /* Check if returned data is a stored block
             * in compression direction
             */
            pResults->dataUncompressed =
                ICP_QAT_FW_COMN_HDR_ST_BLK_FLAG_GET(hdrFlags);
        }

        if (DC_DECOMPRESSION_REQUEST == compDecomp)
        {
            pResults->endOfLastBlock =
                ICP_QAT_FW_COMN_STATUS_CMP_END_OF_LAST_BLK_FLAG_SET ==
                ICP_QAT_FW_COMN_RESP_CMP_END_OF_LAST_BLK_FLAG_GET(opStatus);
        }

        /* Check if a CNV recovery happened and
         * increase stats counter
         */
        if ((DC_COMPRESSION_REQUEST == compDecomp) &&
            ICP_QAT_FW_COMN_HDR_CNV_FLAG_GET(hdrFlags) &&
            ICP_QAT_FW_COMN_HDR_CNVNR_FLAG_GET(hdrFlags))
        {
            COMPRESSION_STAT_INC(numCompCnvErrorsRecovered, pService);
        }

        if (isDcDp)
        {
            pDpOpData->responseStatus = CPA_STATUS_SUCCESS;
        }
        else
        {
            if (DC_COMPRESSION_REQUEST == compDecomp)
            {
                COMPRESSION_STAT_INC(numCompCompleted, pService);
            }
            else
            {
                COMPRESSION_STAT_INC(numDecompCompleted, pService);
            }
        }
    }

    if ((CPA_FALSE == cmpPass) || (CPA_FALSE == xlatPass))
    {
#ifdef ICP_DC_RETURN_COUNTERS_ON_ERROR
        /* Extract the response from the firmware */
        pResults->consumed = pCompRespMsg->comp_resp_pars.input_byte_counter;
        pResults->produced = pCompRespMsg->comp_resp_pars.output_byte_counter;
#else
        pResults->consumed = 0;
        pResults->produced = 0;
#endif
        if (ERR_CODE_OVERFLOW_ERROR == pResults->status)
        {
            /* With Traditional API this error message will be returned only in
             * stateless decompression direction */
            LAC_LOG_ERROR(
                "Unrecoverable error: stateless overflow. You may "
                "need to increase the size of your destination buffer");
        }

        if (isDcDp)
        {
            pDpOpData->responseStatus = CPA_STATUS_FAIL;
        }
        else
        {
            if (ERR_CODE_NO_ERROR != pResults->status &&
                ERR_CODE_HW_INCOMPLETE_FILE != pResults->status)
            {
                status = CPA_STATUS_FAIL;
            }

            if (DC_COMPRESSION_REQUEST == compDecomp)
            {
                COMPRESSION_STAT_INC(numCompCompletedErrors, pService);
            }
            else
            {
                COMPRESSION_STAT_INC(numDecompCompletedErrors, pService);
            }
        }
    }

    if (isDcDp)
    {
        (pService->pDcDpCb)(pDpOpData);
    }
    else
    {
        /* Free the memory pool */
        if (NULL != pCookie)
        {
            Lac_MemPoolEntryFree(pCookie);
            pCookie = NULL;
        }

        if (NULL != pCbFunc)
        {
            pCbFunc(callbackTag, status);
        }
    }
}

#ifdef ICP_PARAM_CHECK
STATIC CpaStatus dcNsCheckDestinationData(sal_compression_service_t *pService,
                                          CpaDcNsSetupData *pSetupData,
                                          CpaBufferList *pDestBuff,
                                          dc_request_dir_t compDecomp)
{
    dc_capabilities_t *pDcCapabilities = &pService->dc_capabilities;
    Cpa16U numInterBuffs = pDcCapabilities->numInterBuffs;
    Cpa64U destBuffSize = 0;

    if (LacBuffDesc_BufferListVerify(
            pDestBuff, &destBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
        CPA_STATUS_SUCCESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid destination buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (compDecomp == DC_COMPRESSION_REQUEST)
    {
        if (pSetupData->huffType == CPA_DC_HT_FULL_DYNAMIC)
        {
#ifndef ICP_DC_DYN_NOT_SUPPORTED
            /* Check if intermediate buffers are available */
            if ((numInterBuffs > 0) &&
                (pService->pInterBuffPtrsArrayPhyAddr == 0 ||
                 pService->pInterBuffPtrsArray == NULL))
            {
                LAC_LOG_ERROR(
                    "No intermediate buffer defined for this instance "
                    "- see cpaDcStartInstance");
                return CPA_STATUS_INVALID_PARAM;
            }

            /* Ensure that the destination buffer size is greater or equal
             * to devices min output buffer size for dynamic compression */
            if (destBuffSize <
                pDcCapabilities->deviceData.minOutputBuffSizeDynamic)
            {
                LAC_INVALID_PARAM_LOG1(
                    "Destination buffer size should be "
                    "greater or equal to %u bytes",
                    pDcCapabilities->deviceData.minOutputBuffSizeDynamic);
                return CPA_STATUS_INVALID_PARAM;
            }
#else
            LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic compression "
                                  "not supported");
            return CPA_STATUS_INVALID_PARAM;
#endif
        }
        else
        {
            /* Ensure that the destination buffer size is greater or equal
             * to devices min output buff size for static compression */
            if (destBuffSize < pDcCapabilities->deviceData.minOutputBuffSize)
            {
                LAC_INVALID_PARAM_LOG1(
                    "Destination buffer size should be "
                    "greater or equal to %d bytes",
                    pDcCapabilities->deviceData.minOutputBuffSize);
                return CPA_STATUS_INVALID_PARAM;
            }
        }
    }
    else
    {
        /* Ensure that the destination buffer size is greater than
         * 0 bytes */
        if (destBuffSize < DC_DEST_BUFFER_DEC_MIN_SIZE)
        {
            LAC_INVALID_PARAM_LOG("Destination buffer size should be "
                                  "greater than 0 bytes");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    /* The firmware expects the size of the destination to be a Cpa32U
     * parameter. However, the total size (all flat buffers added up) could be
     * bigger, as it's allocated by the user. We ensure that this is not the
     * case. */
    if (destBuffSize > DC_BUFFER_MAX_SIZE)
    {
        LAC_INVALID_PARAM_LOG("The destination buffer size needs to be less "
                              "than or equal to 2^32-1 bytes");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus dcNsCheckSourceData(Cpa64U srcBuffSize)
{
    /* Compressing zero bytes is not supported for stateless operation */
    if (srcBuffSize == 0)
    {
        LAC_INVALID_PARAM_LOG("The source buffer size needs to be greater than "
                              "zero bytes for stateless operation");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* The firmware expects the size of the source to be a Cpa32U parameter.
     * However, the total size (all flat buffers added up) could be bigger, as
     * it's allocated by the user. We ensure that this is not the case. */
    if (srcBuffSize > DC_BUFFER_MAX_SIZE)
    {
        LAC_INVALID_PARAM_LOG("The source buffer size needs to be less than or "
                              "equal to 2^32-1 bytes");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}
#endif

void dcNsCompHwBlockPopulate(void *pServiceType,
                             void *pSessionDescp,
                             CpaDcNsSetupData *pSetupData,
                             icp_qat_hw_compression_config_t *pCompConfig,
                             void *compDecompDir,
                             CpaBoolean bNsOp)
{
    sal_compression_service_t *pService = NULL;
    dc_request_dir_t compDecomp;

    pService = (sal_compression_service_t *)pServiceType;
    compDecomp = *(dc_request_dir_t *)compDecompDir;

    icp_qat_hw_compression_direction_t dir =
        ICP_QAT_HW_COMPRESSION_DIR_DECOMPRESS;
    icp_qat_hw_compression_algo_t algo = ICP_QAT_HW_COMPRESSION_ALGO_DEFLATE;
    icp_qat_hw_compression_depth_t depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
    /* The file type is set to ICP_QAT_HW_COMPRESSION_FILE_TYPE_0. The other
     * modes will be used in the future for precompiled huffman trees */
    icp_qat_hw_compression_file_type_t filetype =
        ICP_QAT_HW_COMPRESSION_FILE_TYPE_0;
    icp_qat_hw_compression_delayed_match_t dmm;

    if (pSetupData->compType != CPA_DC_DEFLATE)
    {
        LAC_ENSURE(CPA_FALSE, "Algorithm not supported for Compression\n");
    }

    /* Set delay match mode */
    if (CPA_TRUE == pService->dc_capabilities.deviceData.enableDmm)
    {
        dmm = ICP_QAT_HW_COMPRESSION_DELAYED_MATCH_ENABLED;
    }
    else
    {
        dmm = ICP_QAT_HW_COMPRESSION_DELAYED_MATCH_DISABLED;
    }

    /* Dealing with compression, so reset the direction and depth. */
    if (compDecomp == DC_COMPRESSION_REQUEST)
    {
        dir = ICP_QAT_HW_COMPRESSION_DIR_COMPRESS;

        switch (pSetupData->compLevel)
        {
            case CPA_DC_L1:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
                break;
            case CPA_DC_L2:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_4;
                break;
            case CPA_DC_L3:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_8;
                break;
            case CPA_DC_L4:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_16;
                break;
            default:
                depth = pService->dc_capabilities.deviceData
                            .highestHwCompressionDepth;
                break;
        }
    }

    pCompConfig->lower_val =
        ICP_QAT_HW_COMPRESSION_CONFIG_BUILD(dir, dmm, algo, depth, filetype);

    /* Upper 32-bits of the configuration word do not need to be
     * configured with legacy devices.
     */
    pCompConfig->upper_val = 0;
}

STATIC void dcNsCompContentDescPopulate(sal_compression_service_t *pService,
                                        CpaDcNsSetupData *pSetupData,
                                        CpaPhysicalAddr contextBufferAddrPhys,
                                        icp_qat_fw_comp_req_t *pMsg,
                                        icp_qat_fw_slice_t nextSlice,
                                        dc_request_dir_t compDecomp)
{
    icp_qat_fw_comp_cd_hdr_t *pCompControlBlock = NULL;
    icp_qat_hw_compression_config_t *pCompConfig = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;

    LAC_ENSURE_NOT_NULL(pService);
    LAC_ENSURE_NOT_NULL(pSetupData);
    LAC_ENSURE_NOT_NULL(pMsg);

    pCompControlBlock = &pMsg->comp_cd_ctrl;

    /* Retrieve capabilities */
    pDcCapabilities = &pService->dc_capabilities;

    /* Non-standard aliasing on the following line. */
    pCompConfig = (icp_qat_hw_compression_config_t *)(pMsg->cd_pars.sl
                                                          .comp_slice_cfg_word);
    ICP_QAT_FW_COMN_NEXT_ID_SET(pCompControlBlock, nextSlice);
    ICP_QAT_FW_COMN_CURR_ID_SET(pCompControlBlock, ICP_QAT_FW_SLICE_COMP);

    pCompControlBlock->comp_cfg_offset = 0;

    /* Disable all banks */
    pCompControlBlock->ram_bank_flags = 0;

    pCompControlBlock->comp_state_addr = 0;

    pCompControlBlock->ram_banks_addr = 0;

    pCompControlBlock->resrvd = 0;

    /* Populate Compression Hardware Setup Block */
    (pDcCapabilities->dcNsCompHwBlockPopulate)((void *)pService,
                                               NULL,
                                               pSetupData,
                                               pCompConfig,
                                               (void *)&compDecomp,
                                               CPA_TRUE);
}

CpaStatus dcNsCreateBaseRequest(icp_qat_fw_comp_req_t *pMsg,
                                sal_compression_service_t *pService,
                                CpaDcNsSetupData *pSetupData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_serv_specif_flags cmdFlags = 0;
    Cpa8U secureRam = ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
    Cpa8U sessType = ICP_QAT_FW_COMP_STATELESS_SESSION;
    Cpa8U autoSelectBest = ICP_QAT_FW_COMP_NOT_AUTO_SELECT_BEST;
    Cpa8U enhancedAutoSelectBest = ICP_QAT_FW_COMP_NOT_ENH_AUTO_SELECT_BEST;
    Cpa8U disableType0EnhancedAutoSelectBest =
        ICP_QAT_FW_COMP_NOT_DISABLE_TYPE0_ENH_AUTO_SELECT_BEST;
    Cpa8U dcCmdId = ICP_QAT_FW_COMP_CMD_STATIC;
    icp_qat_fw_comn_flags cmnRequestFlags = 0;
    icp_qat_fw_ext_serv_specif_flags extServiceCmdFlags = 0;
    CpaDcAutoSelectBest autoSelectBestProfile;
    dc_capabilities_t *pDcCapabilities = NULL;
    Cpa16U numInterBuffs = 0;
    dc_hw_gen_types_t hw_gen;

    LAC_OS_BZERO(pMsg, sizeof(icp_qat_fw_comp_req_t));

    cmnRequestFlags = ICP_QAT_FW_COMN_FLAGS_BUILD(
        DC_DEFAULT_QAT_PTR_TYPE, QAT_COMN_CD_FLD_TYPE_16BYTE_DATA);

    LAC_ASSERT_NOT_NULL(pService);

    pDcCapabilities = &pService->dc_capabilities;
    numInterBuffs = pDcCapabilities->numInterBuffs;
    hw_gen = pDcCapabilities->deviceData.hw_gen;

    if (pService->generic_service_info.capabilitiesMask &
        ICP_ACCEL_CAPABILITIES_INLINE)
    {
        secureRam = ICP_QAT_FW_COMP_DISABLE_SECURE_RAM_USED_AS_INTMD_BUF;
    }
    else
    {
        secureRam = pService->dc_capabilities.deviceData.useDevRam;
    }

    autoSelectBestProfile = pSetupData->autoSelectBestHuffmanTree;

    /* Enable or disable ASB in the uniform manner for all the algorithms */
    if (hw_gen >= DC_CAPS_GEN4_HW)
    {
        switch (autoSelectBestProfile)
        {
            case CPA_DC_ASB_STATIC_DYNAMIC:
            case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS:
            case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_NO_HDRS:
                /* Enable compression ratio optimization */
                autoSelectBestProfile = CPA_DC_ASB_ENABLED;
                break;
            case CPA_DC_ASB_DISABLED:
            default:
                /* Keep setting from setup data */
                break;
        }
    }

    if (pSetupData->sessDirection == CPA_DC_DIR_COMPRESS)
    {
        dcNsCompContentDescPopulate(pService,
                                    pSetupData,
                                    0,
                                    pMsg,
                                    ICP_QAT_FW_SLICE_DRAM_WR,
                                    DC_COMPRESSION_REQUEST);
    }
    else
    {
        dcNsCompContentDescPopulate(pService,
                                    pSetupData,
                                    0,
                                    pMsg,
                                    ICP_QAT_FW_SLICE_DRAM_WR,
                                    DC_DECOMPRESSION_REQUEST);
    }

#ifndef ICP_DC_DYN_NOT_SUPPORTED
    if ((numInterBuffs > 0) &&
        (pSetupData->sessDirection == CPA_DC_DIR_COMPRESS) &&
        (pSetupData->huffType == CPA_DC_HT_FULL_DYNAMIC))
    {
        pMsg->u1.xlt_pars.inter_buff_ptr = pService->pInterBuffPtrsArrayPhyAddr;
    }
#endif

    /* Clearing translator content descriptor header, largely for several
     * reserved members, as it's otherwise unused. */
    memset(&pMsg->u2.xlt_cd_ctrl, 0, sizeof(icp_qat_fw_xlt_cd_hdr_t));

    /* Populate the cmdFlags */
    switch (autoSelectBestProfile)
    {
        case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_NO_HDRS:
            disableType0EnhancedAutoSelectBest =
                ICP_QAT_FW_COMP_DISABLE_TYPE0_ENH_AUTO_SELECT_BEST;
        /* Fall through. */
        case CPA_DC_ASB_ENABLED:
        case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS:
            enhancedAutoSelectBest = ICP_QAT_FW_COMP_ENH_AUTO_SELECT_BEST;
        /* Fall through. */
        case CPA_DC_ASB_STATIC_DYNAMIC:
            autoSelectBest = ICP_QAT_FW_COMP_AUTO_SELECT_BEST;
            break;
        case CPA_DC_ASB_DISABLED:
            break;
    }

    cmdFlags = ICP_QAT_FW_COMP_FLAGS_BUILD(sessType,
                                           autoSelectBest,
                                           enhancedAutoSelectBest,
                                           disableType0EnhancedAutoSelectBest,
                                           secureRam);

    if (pSetupData->sessDirection == CPA_DC_DIR_COMPRESS)
    {
        status = dcGetCompressCommandId(
            pService, (CpaDcSessionSetupData *)pSetupData, &dcCmdId);
    }
    else
    {
        status = dcGetDecompressCommandId(
            pService, (CpaDcSessionSetupData *)pSetupData, &dcCmdId);
    }

    if (status != CPA_STATUS_SUCCESS)
    {
        LAC_LOG_ERROR("Couldn't get command ID for current parameters.");

        return status;
    }

    pMsg->comp_pars.crc.legacy.initial_adler = 1;
    pMsg->comp_pars.crc.legacy.initial_crc32 = 0;

    /* Populate header of the common request message */
    SalQatMsg_CmnHdrWrite((icp_qat_fw_comn_req_t *)pMsg,
                          ICP_QAT_FW_COMN_REQ_CPM_FW_COMP,
                          dcCmdId,
                          cmnRequestFlags,
                          cmdFlags,
                          extServiceCmdFlags);

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus dcNsCreateRequest(dc_compression_cookie_t *pCookie,
                                   sal_compression_service_t *pService,
                                   CpaDcNsSetupData *pSetupData,
                                   CpaBufferList *pSrcBuff,
                                   CpaBufferList *pDestBuff,
                                   CpaDcRqResults *pResults,
                                   CpaDcFlush flushFlag,
                                   CpaDcOpData *pOpData,
                                   void *callbackTag,
                                   dc_request_dir_t compDecomp,
                                   dc_cnv_mode_t cnvMode)
{
    icp_qat_fw_comp_req_t *pMsg = NULL;
    icp_qat_fw_comp_req_params_t *pCompReqParams = NULL;
    Cpa64U srcAddrPhys = 0, dstAddrPhys = 0;
    Cpa64U srcTotalDataLenInBytes = 0, dstTotalDataLenInBytes = 0;
    Cpa32U rpCmdFlags = 0;
    Cpa8U sop = ICP_QAT_FW_COMP_SOP;
    Cpa8U eop = ICP_QAT_FW_COMP_EOP;
    Cpa8U bFinal = ICP_QAT_FW_COMP_NOT_BFINAL;
    Cpa8U crcMode = ICP_QAT_FW_COMP_CRC_MODE_LEGACY;
    Cpa8U cnvDecompReq = ICP_QAT_FW_COMP_NO_CNV;
    Cpa8U cnvRecovery = ICP_QAT_FW_COMP_NO_CNV_RECOVERY;
    CpaBoolean cnvErrorInjection = ICP_QAT_FW_COMP_NO_CNV_DFX;
    CpaBoolean integrityCrcCheck = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcFlush flush = CPA_DC_FLUSH_NONE;
    Cpa32U initial_adler = 1;
    Cpa32U initial_xxhash = 0;
    Cpa32U initial_crc32 = 0;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean errorInjectionSupported = CPA_FALSE;
    Cpa32U errorInjectionCode = ICP_QAT_FW_COMP_CNV_ERROR_NONE;
    Cpa16U numInterBuffs = 0;
    dc_hw_gen_types_t hw_gen;

    LAC_ASSERT_NOT_NULL(pService);

    pMsg = &pCookie->request;

    status = dcNsCreateBaseRequest(pMsg, pService, pSetupData);

    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    /* Write the buffer descriptors */
    status = LacBuffDesc_BufferListDescWriteAndGetSize(
        pSrcBuff,
        &srcAddrPhys,
        CPA_FALSE,
        &srcTotalDataLenInBytes,
        &(pService->generic_service_info));
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    status = LacBuffDesc_BufferListDescWriteAndGetSize(
        pDestBuff,
        &dstAddrPhys,
        CPA_FALSE,
        &dstTotalDataLenInBytes,
        &(pService->generic_service_info));
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    pDcCapabilities = &pService->dc_capabilities;
    errorInjectionSupported = pDcCapabilities->cnv.errorInjection;
    numInterBuffs = pDcCapabilities->numInterBuffs;
    hw_gen = pDcCapabilities->deviceData.hw_gen;

    /* Populate the compression cookie */
    pCookie->dcInstance = pService;
    pCookie->pSessionHandle = (CpaDcSessionHandle)DCNS;
    pCookie->callbackTag = callbackTag;
    pCookie->pSessionDesc = NULL;
    pCookie->pDcOpData = pOpData;
    pCookie->pResults = pResults;
    pCookie->compDecomp = compDecomp;
    pCookie->checksumType = pSetupData->checksum;

#ifdef ICP_DC_ERROR_SIMULATION
    /* Inject DC error in cookie if simulation is active */
    if (dcErrorSimEnabled())
    {
        pCookie->dcErrorToSimulate = dcGetErrors();
    }
    else
    {
        pCookie->dcErrorToSimulate = 0;
    }
#endif
    pCookie->pUserSrcBuff = NULL;
    pCookie->pUserDestBuff = NULL;

    /* Extract flush flag from either the opData or from the
     * parameter. Opdata have been introduce with APIs
     * cpaDcCompressData2 and cpaDcDecompressData2 */
    if (pOpData != NULL)
    {
        flush = pOpData->flushFlag;
        integrityCrcCheck = pOpData->integrityCrcCheck;
    }
    else
    {
        flush = flushFlag;
    }
    pCookie->flushFlag = flush;

    pCookie->srcTotalDataLenInBytes = (Cpa32U)srcTotalDataLenInBytes;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
    /* In order to avoid (as opposed to prevent) overflow, the sizes of the
     * destination buffer and the intermediate buffer are synchronised. They
     * share the same field in the request message, and it is set to the
     * smaller of the two sizes. */
    if ((numInterBuffs > 0) && (compDecomp == DC_COMPRESSION_REQUEST) &&
        (pSetupData->huffType == CPA_DC_HT_FULL_DYNAMIC) &&
        ((Cpa32U)dstTotalDataLenInBytes > pService->minInterBuffSizeInBytes))
    {
        pCookie->dstTotalDataLenInBytes =
            (Cpa32U)pService->minInterBuffSizeInBytes;
    }
    else
    {
        pCookie->dstTotalDataLenInBytes = (Cpa32U)dstTotalDataLenInBytes;
    }
#else
    pCookie->dstTotalDataLenInBytes = (Cpa32U)dstTotalDataLenInBytes;
#endif

    if (pSetupData->checksum == CPA_DC_ADLER32)
    {
        initial_adler = pResults->checksum;
    }
    else if (pSetupData->checksum == CPA_DC_XXHASH32)
    {
        /* There is no seeding with xxHash. */
        initial_xxhash = 0;
    }
    else
    {
        initial_crc32 = pResults->checksum;
    }

    /* Backup source and destination buffer addresses,
     * CRC calculations both for CNV and translator overflow
     * will be performed on them in the callback function.
     */
    pCookie->pUserSrcBuff = pSrcBuff;
    pCookie->pUserDestBuff = pDestBuff;

    if ((CPA_TRUE == integrityCrcCheck) &&
        (CPA_TRUE == pDcCapabilities->crcIntegrity.supported))
    {
        /* Get physical address of E2E CRC buffer */
        pMsg->comp_pars.crc.crc_data_addr =
            (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_INTERNAL(
                &pService->generic_service_info, &pCookie->dataIntegrityCrcs);

        if (!pMsg->comp_pars.crc.crc_data_addr)
        {
            LAC_LOG_ERROR("Unable to get the physical address of "
                          "Data Integrity buffer.\n");
            return CPA_STATUS_FAIL;
        }

        pCookie->dataIntegrityCrcs.crc32 = initial_crc32;
        if (pSetupData->checksum == CPA_DC_XXHASH32)
        {
            pCookie->dataIntegrityCrcs.xxhash32 = initial_xxhash;
        }
        else
        {
            pCookie->dataIntegrityCrcs.adler32 = initial_adler;
        }

        if (hw_gen < DC_CAPS_GEN4_HW)
        {
            pCookie->dataIntegrityCrcs.oCrc32Cpr = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.iCrc32Cpr = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.oCrc32Xlt = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.iCrc32Xlt = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.xorFlags = DC_XOR_FLAGS_DEFAULT;
            pCookie->dataIntegrityCrcs.crcPoly = DC_CRC_POLY_DEFAULT;
            pCookie->dataIntegrityCrcs.xorOut = DC_XOR_OUT_DEFAULT;
            pCookie->dataIntegrityCrcs.deflateBlockType = DC_STATIC_TYPE;
        }
        else
        {
            pCookie->dataIntegrityCrcs.iCrc64Cpr = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.oCrc64Cpr = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.reflectIn = DC_REFLECT_IN_DEFAULT;
            pCookie->dataIntegrityCrcs.reflectOut = DC_REFLECT_OUT_DEFAULT;
            pCookie->dataIntegrityCrcs.oCrc64Xlt = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.crc64Poly = DC_CRC64_POLY_DEFAULT;
            pCookie->dataIntegrityCrcs.xor64Out = DC_XOR64_OUT_DEFAULT;
        }

        crcMode = ICP_QAT_FW_COMP_CRC_MODE_E2E;
    }
    else
    {
        /* Legacy request structure */
        if (pSetupData->checksum == CPA_DC_XXHASH32)
        {
            /* initial_adler field is also used for initializing xxhash */
            pMsg->comp_pars.crc.legacy.initial_adler = initial_xxhash;
        }
        else
        {
            pMsg->comp_pars.crc.legacy.initial_adler = initial_adler;
        }
        pMsg->comp_pars.crc.legacy.initial_crc32 = initial_crc32;
        crcMode = ICP_QAT_FW_COMP_CRC_MODE_LEGACY;
    }

    /* Populate the cmdFlags */

    /* (LW 14 - 15) */
    pCompReqParams = &(pMsg->comp_pars);
    dcCompRequestParamsPopulate(pCompReqParams, pCookie);
    if (flush == CPA_DC_FLUSH_FINAL)
    {
        bFinal = ICP_QAT_FW_COMP_BFINAL;
    }

    switch (cnvMode)
    {
        case DC_CNVNR:
            cnvRecovery = ICP_QAT_FW_COMP_CNV_RECOVERY;
        /* Fall through is intended here, because for CNVNR
         * cnvDecompReq also needs to be set */
        case DC_CNV:
            cnvDecompReq = ICP_QAT_FW_COMP_CNV;
            if (CPA_TRUE == errorInjectionSupported)
            {
                cnvErrorInjection =
                    pService->generic_service_info.ns_isCnvErrorInjection;
            }
            break;
        case DC_NO_CNV:
            cnvDecompReq = ICP_QAT_FW_COMP_NO_CNV;
            cnvRecovery = ICP_QAT_FW_COMP_NO_CNV_RECOVERY;
            break;
    }

    /* LW 18 */
    rpCmdFlags = ICP_QAT_FW_COMP_REQ_PARAM_FLAGS_BUILD(
        sop,
        eop,
        bFinal,
        cnvDecompReq,
        cnvRecovery,
        cnvErrorInjection,
        crcMode,
        ICP_QAT_FW_COMP_NO_XXHASH_ACC,
        errorInjectionCode,
        ICP_QAT_FW_COMP_NO_APPEND_CRC,
        ICP_QAT_FW_COMP_NO_DROP_DATA,
        ICP_QAT_FW_COMP_NO_PARTIAL_DECOMPRESS);

    /* Clear the xxHash accumulator flag, as a rolling checksum isn't supported
     * in the NS API. */
    ICP_QAT_FW_COMP_XXHASH_ACC_MODE_SET(rpCmdFlags, CPA_FALSE);

    pMsg->comp_pars.req_par_flags = rpCmdFlags;

    /* Populates the QAT common request middle part of the message
     * (LW 6 to 11) */
    SalQatMsg_CmnMidWrite((icp_qat_fw_la_bulk_req_t *)pMsg,
                          pCookie,
                          DC_DEFAULT_QAT_PTR_TYPE,
                          srcAddrPhys,
                          dstAddrPhys,
                          0,
                          0);

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus dcNsCompDecompData(sal_compression_service_t *pService,
                                    CpaDcNsSetupData *pSetupData,
                                    CpaDcCallbackFn callbackFn,
                                    CpaInstanceHandle dcInstance,
                                    CpaBufferList *pSrcBuff,
                                    CpaBufferList *pDestBuff,
                                    CpaDcRqResults *pResults,
                                    CpaDcFlush flushFlag,
                                    CpaDcOpData *pOpData,
                                    void *callbackTag,
                                    dc_request_dir_t compDecomp,
                                    dc_cnv_mode_t cnvMode)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus syncStatus = CPA_STATUS_SUCCESS;
    dc_compression_cookie_t *pCookie = NULL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    CpaBoolean syncMode = CPA_FALSE;
    icp_comms_trans_handle trans_handle = NULL;

    if (pService->generic_service_info.type == SAL_SERVICE_TYPE_COMPRESSION)
    {
        trans_handle = pService->trans_handle_compression_tx;
    }
    else
    {
        trans_handle = pService->trans_handle_decompression_tx;
    }

    if (!callbackFn)
    {
        syncMode = CPA_TRUE;
    }

    /* Allocate the compression cookie
     * The memory is freed in callback or in sendRequest if an error occurs
     */
    do
    {
        if (pService->generic_service_info.type == SAL_SERVICE_TYPE_COMPRESSION)
        {
            pCookie = (dc_compression_cookie_t *)Lac_MemPoolEntryAlloc(
                pService->compression_mem_pool);
        }
        else
        {
            pCookie = (dc_compression_cookie_t *)Lac_MemPoolEntryAlloc(
                pService->decompression_mem_pool);
        }
        if (pCookie == NULL)
        {
            if (pService->generic_service_info.type ==
                SAL_SERVICE_TYPE_COMPRESSION)
            {
                LAC_LOG_ERROR("Cannot get mem pool entry for compression");
            }
            else
            {
                LAC_LOG_ERROR("Cannot get mem pool entry for decompression");
            }
            status = CPA_STATUS_RESOURCE;
            return status;
        }
        else if (pCookie == (void *)CPA_STATUS_RETRY)
        {
            /* Give back the control to the OS */
            osalYield();
        }
    } while (pCookie == (void *)CPA_STATUS_RETRY);

    if (syncMode == CPA_TRUE)
    {
        if (status == CPA_STATUS_SUCCESS)
        {
            status = LacSync_CreateSyncCookie(&pSyncCallbackData);
            if (NULL == pSyncCallbackData)
            {
                LAC_LOG_ERROR("cannot create a sync cookie for compression.");
                status = CPA_STATUS_RESOURCE;

                /* Free the memory pool */
                if (pCookie != NULL)
                {
                    Lac_MemPoolEntryFree(pCookie);
                    pCookie = NULL;
                }

                return status;
            }

            callbackFn = LacSync_GenWakeupSyncCaller;

            callbackTag = pSyncCallbackData;
        }
    }

    if (status == CPA_STATUS_SUCCESS)
    {
        /* For asynchronous - use the user supplied callback
         * for synchronous - use the internal synchronous callback */
        pCookie->pCbFunc = callbackFn;

        status = dcNsCreateRequest(pCookie,
                                   pService,
                                   pSetupData,
                                   pSrcBuff,
                                   pDestBuff,
                                   pResults,
                                   flushFlag,
                                   pOpData,
                                   callbackTag,
                                   compDecomp,
                                   cnvMode);
    }

    if (status == CPA_STATUS_SUCCESS)
    {
        /* Send to QAT */
        status = SalQatMsg_transPutMsg(trans_handle,
                                       (void *)&(pCookie->request),
                                       LAC_QAT_DC_REQ_SZ_LW,
                                       LAC_LOG_MSG_DC,
                                       NULL);
    }

    if (status == CPA_STATUS_SUCCESS)
    {
        if (compDecomp == DC_COMPRESSION_REQUEST)
        {
            COMPRESSION_STAT_INC(numCompRequests, pService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompRequests, pService);
        }
    }
    else
    {
        if (compDecomp == DC_COMPRESSION_REQUEST)
        {
            COMPRESSION_STAT_INC(numCompRequestsErrors, pService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompRequestsErrors, pService);
        }

        /* Free the memory pool */
        if (pCookie != NULL)
        {
            Lac_MemPoolEntryFree(pCookie);
            pCookie = NULL;
        }
    }

    if (syncMode == CPA_TRUE)
    {
        if (status == CPA_STATUS_SUCCESS)
        {
            syncStatus = LacSync_WaitForCallback(
                pSyncCallbackData, DC_SYNC_CALLBACK_TIMEOUT, &status, NULL);

            /* If callback doesn't come back */
            if (syncStatus != CPA_STATUS_SUCCESS)
            {
                if (compDecomp == DC_COMPRESSION_REQUEST)
                {
                    COMPRESSION_STAT_INC(numCompCompletedErrors, pService);
                }
                else
                {
                    COMPRESSION_STAT_INC(numDecompCompletedErrors, pService);
                }
                /* Free the memory pool */
                if (pCookie != NULL)
                {
                    Lac_MemPoolEntryFree(pCookie);
                    pCookie = NULL;
                }
                LAC_LOG_ERROR("Callback timed out");
                status = syncStatus;
            }
        }
        else
        {
            /* As the Request was not sent the Callback will never
             * be called, so need to indicate that we're finished
             * with cookie so it can be destroyed. */
            LacSync_SetSyncCookieComplete(pSyncCallbackData);
        }

        LacSync_DestroySyncCookie(&pSyncCallbackData);
    }

    return status;
}

CpaStatus cpaDcNsDecompressData(CpaInstanceHandle dcInstance,
                                CpaDcNsSetupData *pSetupData,
                                CpaBufferList *pSrcBuff,
                                CpaBufferList *pDestBuff,
                                CpaDcOpData *pOpData,
                                CpaDcRqResults *pResults,
                                CpaDcCallbackFn callbackFn,
                                void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa64U srcBuffSize = 0;
#endif

#ifdef ICP_TRACE
    LAC_LOG8("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSetupData,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pOpData,
             (LAC_ARCH_UINT)pResults,
             (LAC_ARCH_UINT)callbackFn,
             (LAC_ARCH_UINT)callbackTag);
#endif

    if (dcInstance == CPA_INSTANCE_HANDLE_SINGLE)
    {
        dcInstance = dcGetFirstHandle();
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(dcInstance);
    LAC_CHECK_NULL_PARAM(pSetupData);
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pResults);
#endif

    pService = (sal_compression_service_t *)dcInstance;

#ifdef ICP_PARAM_CHECK
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(
        dcInstance,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));

    SAL_CHECK_ADDR_TRANS_SETUP(dcInstance);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(dcInstance);

#ifdef ICP_PARAM_CHECK
    /* Check that the parameters defined in pSetupData are valid for the
     * device */
    if (dcCheckSessionData((CpaDcSessionSetupData *)pSetupData, dcInstance) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSetupData->sessDirection != CPA_DC_DIR_DECOMPRESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSetupData->sessState == CPA_DC_STATEFUL)
    {
        LAC_INVALID_PARAM_LOG("Stateful mode of operation not available");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (dcCheckOpData(pService, pOpData, pSetupData->sessDirection) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->flushFlag == CPA_DC_FLUSH_NONE ||
        pOpData->flushFlag == CPA_DC_FLUSH_SYNC)
    {
        LAC_INVALID_PARAM_LOG(
            "Flush flags specific to stateful mode of operation not allowed");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (LacBuffDesc_BufferListVerifyNull(
            pSrcBuff, &srcBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
        CPA_STATUS_SUCCESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid source buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (dcNsCheckSourceData(srcBuffSize) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (dcNsCheckDestinationData(
            pService, pSetupData, pDestBuff, DC_DECOMPRESSION_REQUEST) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSrcBuff == pDestBuff)
    {
        LAC_INVALID_PARAM_LOG("In place operation not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    return dcNsCompDecompData(pService,
                              pSetupData,
                              callbackFn,
                              dcInstance,
                              pSrcBuff,
                              pDestBuff,
                              pResults,
                              pOpData->flushFlag,
                              pOpData,
                              callbackTag,
                              DC_DECOMPRESSION_REQUEST,
                              DC_NO_CNV);
}

CpaStatus cpaDcNsCompressData(CpaInstanceHandle dcInstance,
                              CpaDcNsSetupData *pSetupData,
                              CpaBufferList *pSrcBuff,
                              CpaBufferList *pDestBuff,
                              CpaDcOpData *pOpData,
                              CpaDcRqResults *pResults,
                              CpaDcCallbackFn callbackFn,
                              void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
    dc_cnv_mode_t cnvMode = DC_CNV;

    LAC_CHECK_NULL_PARAM(pOpData);

    if (pOpData->compressAndVerify != CPA_TRUE)
    {
        LAC_INVALID_PARAM_LOG(
            "Data compression without verification not allowed");
        return CPA_STATUS_UNSUPPORTED;
    }

#ifdef ICP_TRACE
    LAC_LOG8("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSetupData,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pOpData,
             (LAC_ARCH_UINT)pResults,
             (LAC_ARCH_UINT)callbackFn,
             (LAC_ARCH_UINT)callbackTag);
#endif

    if (dcInstance == CPA_INSTANCE_HANDLE_SINGLE)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pSetupData);
    LAC_CHECK_NULL_PARAM(pResults);
#endif

    pService = (sal_compression_service_t *)insHandle;

#ifdef ICP_PARAM_CHECK
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);

    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

#ifdef ICP_PARAM_CHECK
    /* Check that the parameters defined in pSetupData are valid for the
     * device */
    if (dcCheckSessionData((CpaDcSessionSetupData *)pSetupData, insHandle) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSetupData->sessDirection != CPA_DC_DIR_COMPRESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSetupData->sessState == CPA_DC_STATEFUL)
    {
        LAC_INVALID_PARAM_LOG("Stateful mode of operation not available");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_LZ4 == pSetupData->compType &&
        CPA_TRUE == pSetupData->accumulateXXHash)
    {
        LAC_INVALID_PARAM_LOG("Invalid accumulateXXHash value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((CPA_DC_LZ4 == pSetupData->compType) &&
        (CPA_TRUE == pOpData->integrityCrcCheck))
    {
        LAC_INVALID_PARAM_LOG("LZ4 with integrityCrcCheck is not supported"
                              " in the compression direction");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (dcCheckOpData(pService, pOpData, pSetupData->sessDirection) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->compressAndVerifyAndRecover != CPA_TRUE &&
        pOpData->compressAndVerifyAndRecover != CPA_FALSE)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->compressAndVerify == CPA_FALSE &&
        pOpData->compressAndVerifyAndRecover == CPA_TRUE)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->flushFlag == CPA_DC_FLUSH_NONE ||
        pOpData->flushFlag == CPA_DC_FLUSH_SYNC)
    {
        LAC_INVALID_PARAM_LOG(
            "Flush flags specific to stateful mode of operation not allowed");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    /* This check is outside the parameter checking as it is needed to manage
     * zero length requests */
    if (LacBuffDesc_BufferListVerifyNull(
            pSrcBuff, &srcBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
        CPA_STATUS_SUCCESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid source buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

#ifdef ICP_PARAM_CHECK
    if (dcNsCheckSourceData(srcBuffSize) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (dcNsCheckDestinationData(
            pService, pSetupData, pDestBuff, DC_COMPRESSION_REQUEST) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSrcBuff == pDestBuff)
    {
        LAC_INVALID_PARAM_LOG("In place operation not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (pSetupData->huffType == CPA_DC_HT_FULL_DYNAMIC)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic compression "
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (!(pService->dc_capabilities.cnv.supported) &&
        (CPA_TRUE == pOpData->compressAndVerify))
    {
        LAC_INVALID_PARAM_LOG("CompressAndVerify feature not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (!(pService->dc_capabilities.cnv.recovery) &&
        (CPA_TRUE == pOpData->compressAndVerifyAndRecover))
    {
        LAC_INVALID_PARAM_LOG("CompressAndVerify feature not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_TRUE == pOpData->compressAndVerifyAndRecover)
    {
        cnvMode = DC_CNVNR;
    }

    return dcNsCompDecompData(pService,
                              pSetupData,
                              callbackFn,
                              insHandle,
                              pSrcBuff,
                              pDestBuff,
                              pResults,
                              pOpData->flushFlag,
                              pOpData,
                              callbackTag,
                              DC_COMPRESSION_REQUEST,
                              cnvMode);
}

CpaStatus dcNsSetCnvErrorInj(CpaInstanceHandle dcInstance,
                             CpaBoolean enableCnvErrInj)
{

    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean errorInjectionSupported = CPA_FALSE;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;
    pDcCapabilities = &pService->dc_capabilities;
    errorInjectionSupported = pDcCapabilities->cnv.errorInjection;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pService);
#endif

    if (CPA_FALSE == errorInjectionSupported)
    {
        LAC_ENSURE(CPA_FALSE, "Unsupported compression feature.\n");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_TRUE == enableCnvErrInj)
    {
        pService->generic_service_info.ns_isCnvErrorInjection =
            ICP_QAT_FW_COMP_CNV_DFX;
    }
    else
    {
        pService->generic_service_info.ns_isCnvErrorInjection =
            ICP_QAT_FW_COMP_NO_CNV_DFX;
    }

    return CPA_STATUS_SUCCESS;
}
