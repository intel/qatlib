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
 * @file dc_datapath.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the Data Compression datapath operations.
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_dc_dp.h"
#ifndef ICP_DC_ONLY
#include "dc_chain.h"
#endif

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "dc_session.h"
#include "dc_datapath.h"
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
#ifndef KERNEL_SPACE
#include <stdlib.h>
#include "dc_crc32.h"
#include "dc_crc64.h"
#endif
#include "sal_misc_error_stats.h"
#define DC_COMP_MAX_BUFF_SIZE (1024 * 64)

STATIC OsalAtomic dcErrorCount[MAX_DC_ERROR_TYPE];

void dcErrorLog(CpaDcReqStatus dcError)
{
    Cpa32U absError = 0;

    absError = abs(dcError);
    if ((dcError < CPA_DC_OK) && (absError < MAX_DC_ERROR_TYPE))
    {
        osalAtomicInc(&(dcErrorCount[absError]));
    }
}

/* Reset xxhash state */
STATIC void dcResetXxhashState(dc_session_desc_t *pSessionDesc,
                               dc_compression_cookie_t *pCookie)
{
    if ((NULL == pSessionDesc) || (NULL == pCookie))
        return;
    if ((CPA_DC_LZ4 == pSessionDesc->compType) &&
        (CPA_DC_XXHASH32 == pSessionDesc->checksumType) &&
        (CPA_DC_FLUSH_FINAL == pCookie->flushFlag))
    {
        dcXxhash32SetState(pSessionDesc, 0);
    }
}

Cpa64U getDcErrorCounter(CpaDcReqStatus dcError)
{
    Cpa32U absError = 0;

    absError = abs(dcError);
    if (!(dcError >= CPA_DC_OK || dcError < CPA_DC_EMPTY_DYM_BLK))
    {
        return (Cpa64U)osalAtomicGet(&dcErrorCount[absError]);
    }

    return 0;
}

#ifndef KERNEL_SPACE
STATIC void dcUpdateCompStateCrc(dc_compression_cookie_t *pCookie,
                                 const Cpa32U offset,
                                 const Cpa32U newCrcValue)
{
    Cpa8U *pStateAddr = NULL;
    Cpa8U i = 0;
    dc_session_desc_t *pSessionDesc =
        DC_SESSION_DESC_FROM_CTX_GET(pCookie->pSessionHandle);

    /* Update state register with new CRC32 value */
    pStateAddr = &pSessionDesc->stateRegistersComp[offset];

    for (i = 0; i < DC_CHECKSUM_SIZE_IN_BYTES; i++)
    {
        *(pStateAddr++) =
            (newCrcValue >> (i * DC_8_BIT_SHIFT_POS)) & DC_8_BIT_MASK;
    }
}

STATIC void dcHandleIntegrityChecksums(dc_compression_cookie_t *pCookie,
                                       CpaCrcData *crc_external,
                                       CpaDcRqResults *pDcResults)
{
    dc_integrity_crc_fw_t *crc_internal = &pCookie->dataIntegrityCrcs;
    dc_session_desc_t *pSessionDesc =
        DC_SESSION_DESC_FROM_CTX_GET(pCookie->pSessionHandle);
    CpaBoolean integrityErrorOccurred = CPA_FALSE;
    dc_request_dir_t compDecomp = pCookie->compDecomp;
    Cpa32U swCrcI = DC_DEFAULT_CRC, swCrcO = DC_DEFAULT_CRC;
    CpaBoolean verifyHwIntegrityCrcs =
        pCookie->pDcOpData->verifyHwIntegrityCrcs;
    dc_sw_checksums_t seedSwCrc;

    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        seedSwCrc.swCrc32I = crc_external->integrityCrc.iCrc;
        seedSwCrc.swCrc32O = crc_external->integrityCrc.oCrc;
    }
    else
    {
        seedSwCrc.swCrc32I = DC_DEFAULT_CRC;
        seedSwCrc.swCrc32O = DC_DEFAULT_CRC;
    }

    /* Move results from internal firmware buffer (opaque to user)
     * into structure fields visible to user
     */
    crc_external->crc32 = crc_internal->crc32;
    crc_external->adler32 = crc_internal->adler32;

    /* Copy compression input CRC to iCrc field of
     * CpaIntegrityCrc structure
     */
    crc_external->integrityCrc.iCrc = crc_internal->iCrc32Cpr;

    if ((CPA_TRUE == verifyHwIntegrityCrcs) ||
        (DC_CLEARTEXT_TYPE == (dc_block_type_t)crc_internal->deflateBlockType))
    {
        /* Calculate checksum on input data */
        swCrcI = dcCalculateCrc32(
            pCookie->pUserSrcBuff, pDcResults->consumed, seedSwCrc.swCrc32I);
        /* Calculate checksum on output data */
        swCrcO = dcCalculateCrc32(
            pCookie->pUserDestBuff, pDcResults->produced, seedSwCrc.swCrc32O);
    }

    if (DC_STATIC_TYPE == (dc_block_type_t)crc_internal->deflateBlockType ||
        CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        crc_external->integrityCrc.oCrc = crc_internal->oCrc32Cpr;
    }
    else if (DC_DYNAMIC_TYPE == (dc_block_type_t)crc_internal->deflateBlockType)
    {
        /* Copy translator output CRC to oCrc field of
         * CpaIntegrityCrc structure
         */
        crc_external->integrityCrc.oCrc = crc_internal->oCrc32Xlt;

        /* Verify data integrity between compression and translator slices. */
        if (crc_internal->oCrc32Cpr != crc_internal->iCrc32Xlt)
        {
            integrityErrorOccurred = CPA_TRUE;
        }
    }
    else if (DC_CLEARTEXT_TYPE ==
             (dc_block_type_t)crc_internal->deflateBlockType)
    {
        crc_external->integrityCrc.iCrc = swCrcI;
        crc_external->integrityCrc.oCrc = swCrcO;

        /* Update State register 5 "CRC32" */
        dcUpdateCompStateCrc(pCookie, DC_STATE_CRC32_OFFSET, swCrcI);

        /* Update State register 6 "Input CRC32" */
        dcUpdateCompStateCrc(pCookie, DC_STATE_INPUT_CRC32_OFFSET, swCrcI);

        /* Update State register 6 "Input CRC32" */
        dcUpdateCompStateCrc(pCookie, DC_STATE_OUTPUT_CRC32_OFFSET, swCrcO);
    }

    /* Compare H/W CRCs against software ones if required */
    if (CPA_TRUE == verifyHwIntegrityCrcs)
    {
        if (crc_external->integrityCrc.iCrc != swCrcI ||
            crc_external->integrityCrc.oCrc != swCrcO)
        {
            integrityErrorOccurred = CPA_TRUE;
        }
    }

    if (CPA_TRUE == integrityErrorOccurred)
    {
        LAC_LOG_ERROR("CRC Data integrity failure detected.");
        LAC_LOG_ERROR1("\tsoftware input  buffer CRC = 0x%08x", swCrcI);
        LAC_LOG_ERROR1("\tsoftware output buffer CRC = 0x%08x", swCrcO);

        LAC_LOG_ERROR1("\tinternal compression input CRC = 0x%08x",
                       crc_internal->iCrc32Cpr);
        LAC_LOG_ERROR1("\tinternal compression output CRC = 0x%08x",
                       crc_internal->oCrc32Cpr);

        /* Report extra CRCs for dynamic compression */
        if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
        {
            LAC_LOG_ERROR1("\tinternal translator input CRC = 0x%08x",
                           crc_internal->iCrc32Xlt);
            LAC_LOG_ERROR1("\tinternal translator output CRC = 0x%08x",
                           crc_internal->oCrc32Xlt);
        }

        /* IA should indicate CRC integrity error, but does not
         * override hardware error code if one was already set
         */
        if (CPA_DC_OK == pDcResults->status ||
            CPA_DC_OVERFLOW == pDcResults->status)
        {
            pDcResults->status = CPA_DC_CRC_INTEG_ERR;
        }
    }
    else if (DC_DYNAMIC_TYPE == (dc_block_type_t)crc_internal->deflateBlockType)
    {
        /* Update the state registers in case of Stateful compression */
        if (DC_COMPRESSION_REQUEST == compDecomp)
        {
            /* Update State register 6 "Output CRC32" */
            dcUpdateCompStateCrc(pCookie,
                                 DC_STATE_OUTPUT_CRC32_OFFSET,
                                 crc_external->integrityCrc.oCrc);
        }
    }
    else if (DC_STATIC_TYPE == (dc_block_type_t)crc_internal->deflateBlockType)
    {
        if (DC_COMPRESSION_REQUEST == compDecomp)
        {
            /* Update State register 6 "Output CRC32" */
            dcUpdateCompStateCrc(pCookie,
                                 DC_STATE_OUTPUT_CRC32_OFFSET,
                                 crc_external->integrityCrc.oCrc);
        }
    }

    if (CPA_DC_CRC32 == pSessionDesc->checksumType)
    {
        pDcResults->checksum = crc_external->crc32;
    }
    else if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
    {
        pDcResults->checksum = crc_external->adler32;
    }
}

STATIC void dcHandleIntegrityChecksumsGen4(dc_compression_cookie_t *pCookie,
                                           CpaCrcData *crc_external,
                                           CpaDcRqResults *pDcResults)
{
    dc_integrity_crc_fw_t *crc_internal = &pCookie->dataIntegrityCrcs;
    dc_session_desc_t *pSessionDesc =
        DC_SESSION_DESC_FROM_CTX_GET(pCookie->pSessionHandle);
    CpaBoolean integrityErrorOccurred = CPA_FALSE;
    Cpa64U swCrc64I = DC_DEFAULT_CRC, swCrc64O = DC_DEFAULT_CRC;
    dc_block_type_t blockType = DC_STATIC_TYPE;
    CpaBoolean verifyHwIntegrityCrcs =
        pCookie->pDcOpData->verifyHwIntegrityCrcs;

    /* Simply set block type as per huffman type */
    if (CPA_DC_DEFLATE == pSessionDesc->compType &&
        CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType &&
        DC_COMPRESSION_REQUEST == pCookie->compDecomp)
    {
        blockType = DC_DYNAMIC_TYPE;
    }

    /* Move results from internal firmware buffer (opaque to user)
     * into structure fields visible to user
     */
    crc_external->crc32 = crc_internal->crc32;
    crc_external->adler32 = crc_internal->adler32;

    /* Copy compression input CRC to iCrc field of
     * CpaIntegrityCrc64b structure
     */
    crc_external->integrityCrc64b.iCrc = crc_internal->iCrc64Cpr;
    if (DC_DYNAMIC_TYPE == blockType)
    {
        /* Copy translator output CRC to oCrc field of
         * CpaIntegrityCrc64b structure
         */
        crc_external->integrityCrc64b.oCrc = crc_internal->oCrc64Xlt;
    }
    else
    {
        /* Copy compression output CRC to oCrc field of
         * CpaIntegrityCrc64b structure
         */
        crc_external->integrityCrc64b.oCrc = crc_internal->oCrc64Cpr;
    }

    /* Compare H/W CRCs against software ones if required */
    if (CPA_TRUE == verifyHwIntegrityCrcs)
    {
        /* Calculate checksum on input data */
        swCrc64I = dcCalculateCrc64(
            pCookie->pUserSrcBuff, pDcResults->consumed, DC_DEFAULT_CRC);
        /* Calculate checksum on output data */
        swCrc64O = dcCalculateCrc64(
            pCookie->pUserDestBuff, pDcResults->produced, DC_DEFAULT_CRC);

        if (crc_external->integrityCrc64b.iCrc != swCrc64I ||
            crc_external->integrityCrc64b.oCrc != swCrc64O)
        {
            integrityErrorOccurred = CPA_TRUE;
        }
    }

    if (CPA_TRUE == integrityErrorOccurred)
    {
        LAC_LOG_ERROR("CRC Data integrity failure detected.");
        LAC_LOG_ERROR_PARAMS("\tsoftware input  buffer CRC64 = 0x%016lx",
                             swCrc64I);

        LAC_LOG_ERROR_PARAMS("\tsoftware output buffer CRC64 = 0x%016lx",
                             swCrc64O);

        LAC_LOG_ERROR_PARAMS("\tinternal compression input CRC64 = 0x%016lx",
                             crc_internal->iCrc64Cpr);
        LAC_LOG_ERROR_PARAMS("\tinternal compression output CRC64 = 0x%016lx",
                             crc_internal->oCrc64Cpr);

        /* Report extra CRCs for dynamic compression */
        if (DC_DYNAMIC_TYPE == blockType)
        {
            LAC_LOG_ERROR_PARAMS(
                "\tinternal translator output CRC64 = 0x%016lx",
                crc_internal->oCrc64Xlt);
        }

        /* IA should indicate CRC integrity error, but does not
         * override hardware error code if one was already set
         */
        if (CPA_DC_OK == pDcResults->status ||
            CPA_DC_OVERFLOW == pDcResults->status)
        {
            pDcResults->status = CPA_DC_CRC_INTEG_ERR;
        }
    }

    if (CPA_DC_CRC32 == pSessionDesc->checksumType)
    {
        pDcResults->checksum = crc_external->crc32;
    }
    else if (CPA_DC_ADLER32 == pSessionDesc->checksumType ||
             CPA_DC_XXHASH32 == pSessionDesc->checksumType)
    {
        /* XXHASH32 and Adler share the same member */
        pDcResults->checksum = crc_external->adler32;
    }
}
#endif

void dcCompression_ProcessCallback(void *pRespMsg)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_comp_resp_t *pCompRespMsg = NULL;
    void *callbackTag = NULL;
    Cpa64U *pReqData = NULL;
    CpaDcDpOpData *pResponse = NULL;
    CpaDcRqResults *pResults = NULL;
    CpaDcCallbackFn pCbFunc = NULL;
    dc_session_desc_t *pSessionDesc = NULL;

    sal_compression_service_t *pService = NULL;
    dc_compression_cookie_t *pCookie = NULL;
    CpaDcOpData *pOpData = NULL;
    CpaBoolean cmpPass = CPA_TRUE, xlatPass = CPA_TRUE;
    CpaBoolean isDcDp = CPA_FALSE;
    Cpa8U cmpErr = ERR_CODE_NO_ERROR, xlatErr = ERR_CODE_NO_ERROR;
    dc_request_dir_t compDecomp = DC_COMPRESSION_REQUEST;
    Cpa8U opStatus = ICP_QAT_FW_COMN_STATUS_FLAG_OK;
    Cpa8U hdrFlags = 0;

    /* Cast response message to compression response message type */
    pCompRespMsg = (icp_qat_fw_comp_resp_t *)pRespMsg;
#ifdef ICP_PARAM_CHECK
    LAC_ASSERT_NOT_NULL(pCompRespMsg);
#endif

#ifndef ICP_DC_ONLY
#ifndef KERNEL_SPACE
    if (pCompRespMsg->comn_resp.response_type ==
        ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN)
    {
        dcChainProcessResults(pRespMsg);
        return;
    }
#endif
#endif

    /* Extract request data pointer from the opaque data */
    LAC_MEM_SHARED_READ_TO_PTR(pCompRespMsg->opaque_data, pReqData);
#ifdef ICP_PARAM_CHECK
    LAC_ASSERT_NOT_NULL(pReqData);
#endif

    /* Extract fields from the request data structure */
    pCookie = (dc_compression_cookie_t *)pReqData;
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pCookie->pSessionHandle);
    pService = (sal_compression_service_t *)(pCookie->dcInstance);

    isDcDp = pSessionDesc->isDcDp;
    if (CPA_TRUE == isDcDp)
    {
        pResponse = (CpaDcDpOpData *)pReqData;
        if (NULL != pResponse)
        {
            pResults = &(pResponse->results);
        }
        if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
        {
            compDecomp = DC_DECOMPRESSION_REQUEST;
        }
        pCookie = NULL;
    }
    else
    {
        pSessionDesc = pCookie->pSessionDesc;
        pResults = pCookie->pResults;
        callbackTag = pCookie->callbackTag;
        pCbFunc = pCookie->pSessionDesc->pCompressionCb;
        compDecomp = pCookie->compDecomp;
        pOpData = pCookie->pDcOpData;
    }
    isDcDp = pSessionDesc->isDcDp;

    opStatus = pCompRespMsg->comn_resp.comn_status;

    hdrFlags = pCompRespMsg->comn_resp.hdr_flags;

    /* Get the cmp error code */
    cmpErr = pCompRespMsg->comn_resp.comn_error.s1.cmp_err_code;
#ifdef ICP_DC_ERROR_SIMULATION
    if ((CPA_FALSE == isDcDp) && (0 != pCookie->dcErrorToSimulate))
    {
        cmpErr = pCookie->dcErrorToSimulate;
    }
#endif
    if (ICP_QAT_FW_COMN_RESP_UNSUPPORTED_REQUEST_STAT_GET(opStatus))
    {
        /* Compression not supported by firmware, set produced/consumed to zero
           and call the cb function with status CPA_STATUS_UNSUPPORTED */
        LAC_LOG_ERROR("Compression feature not supported");
        status = CPA_STATUS_UNSUPPORTED;
        if (NULL != pResults)
        {
            pResults->status = (Cpa8S)cmpErr;
            pResults->consumed = 0;
            pResults->produced = 0;
        }
        if (CPA_TRUE == isDcDp)
        {
            if (NULL != pResponse)
            {
                /* Decrement number of stateless pending callbacks for session
                 */
                pSessionDesc->pendingDpStatelessCbCount--;
                pResponse->responseStatus = CPA_STATUS_UNSUPPORTED;
                (pService->pDcDpCb)(pResponse);
            }
        }
        else
        {
            if (pCookie != NULL)
            {
                /* Decrement number of pending callbacks for session */
                if (CPA_DC_STATELESS == pSessionDesc->sessState)
                {
                    osalAtomicDec(
                        &(pCookie->pSessionDesc->pendingStatelessCbCount));
                }
                else if (0 !=
                         osalAtomicGet(
                             &pCookie->pSessionDesc->pendingStatefulCbCount))
                {
                    osalAtomicDec(
                        &(pCookie->pSessionDesc->pendingStatefulCbCount));
                }
                /* Free the memory pool */
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
        cmpPass = (CpaBoolean)(ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                               ICP_QAT_FW_COMN_RESP_CMP_STAT_GET(opStatus));

        SAL_MISC_ERR_STATS_INC(cmpErr, &pService->generic_service_info);
    }

    if (!pService->generic_service_info.isGen4)
    {
        /* QAT1.7 and QAT 1.8 hardware */
        if (CPA_DC_INCOMPLETE_FILE_ERR == (Cpa8S)cmpErr)
        {
            cmpPass = CPA_TRUE;
            cmpErr = ERR_CODE_NO_ERROR;
        }
    }
    else
    {
        /* QAT2.0 hardware cancels the incomplete file errors
         * only for DEFLATE algorithm.
         */
        if ((pSessionDesc->compType == CPA_DC_DEFLATE) &&
            (CPA_DC_INCOMPLETE_FILE_ERR == (Cpa8S)cmpErr))
        {
            cmpPass = CPA_TRUE;
            cmpErr = ERR_CODE_NO_ERROR;
        }
    }
    /* log the slice hang and endpoint push/pull error inside the response */
    if (ERR_CODE_SSM_ERROR == (Cpa8S)cmpErr)
    {
        LAC_LOG_ERROR("The slice hang is detected on the compression slice");
    }
    else if (ERR_CODE_ENDPOINT_ERROR == (Cpa8S)cmpErr)
    {
        LAC_LOG_ERROR(
            "The PCIe End Point Push/Pull or TI/RI Parity error detected.");
    }

    /* We return the compression error code for now. We would need to update
     * the API if we decide to return both error codes */
    if (NULL != pResults)
        pResults->status = (Cpa8S)cmpErr;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
    /* Check the translator status */
    if ((DC_COMPRESSION_REQUEST == compDecomp) &&
        (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType))
    {
        /* Check translator response status */
        xlatPass = (CpaBoolean)(ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                                ICP_QAT_FW_COMN_RESP_XLAT_STAT_GET(opStatus));

        /* Get the translator error code */
        xlatErr = pCompRespMsg->comn_resp.comn_error.s1.xlat_err_code;

        /* Return a fatal error or a potential error in the translator slice
         * if the compression slice did not return any error */
        if (pResults && ((CPA_DC_OK == pResults->status) ||
                         (CPA_DC_FATALERR == (Cpa8S)xlatErr)))
        {
            pResults->status = (Cpa8S)xlatErr;
        }
    }
#endif
    /* Update dc error counter */
    if (pResults)
        dcErrorLog(pResults->status);

    if (CPA_FALSE == isDcDp)
    {
        /* In case of any error for an end of packet request, we need to update
         * the request type for the following request */
        if (CPA_DC_FLUSH_FINAL == pCookie->flushFlag && cmpPass && xlatPass)
        {
            pSessionDesc->requestType = DC_REQUEST_FIRST;
        }
        else
        {
            pSessionDesc->requestType = DC_REQUEST_SUBSEQUENT;
        }
        if ((CPA_DC_STATEFUL == pSessionDesc->sessState) ||
            ((CPA_DC_STATELESS == pSessionDesc->sessState) &&
             (DC_COMPRESSION_REQUEST == compDecomp)))
        {
            /* Overflow is a valid use case for Traditional API only.
             * Stateful Overflow is supported in both compression and
             * decompression direction.
             * Stateless Overflow is supported only in compression direction.
             */
            if (CPA_DC_OVERFLOW == (Cpa8S)cmpErr)
                cmpPass = CPA_TRUE;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
            if (CPA_DC_OVERFLOW == (Cpa8S)xlatErr)
            {
                xlatPass = CPA_TRUE;
            }
#endif
        }
    }
    else
    {
        if (CPA_DC_OVERFLOW == (Cpa8S)cmpErr)
        {
            cmpPass = CPA_FALSE;
        }
#ifndef ICP_DC_DYN_NOT_SUPPORTED
        if (CPA_DC_OVERFLOW == (Cpa8S)xlatErr)
        {
            /* XLT overflow is not valid for Data Plane requests */
            xlatPass = CPA_FALSE;
        }
#endif
    }

    if (pResults && (CPA_TRUE == cmpPass) && (CPA_TRUE == xlatPass))
    {
        /* Extract the response from the firmware */
        pResults->consumed = pCompRespMsg->comp_resp_pars.input_byte_counter;
        pResults->produced = pCompRespMsg->comp_resp_pars.output_byte_counter;
        pSessionDesc->cumulativeConsumedBytes += pResults->consumed;

        /* Handle Checksum for end to end data integrity. */
        if (CPA_TRUE != isDcDp &&
            CPA_TRUE == pService->generic_service_info.integrityCrcCheck &&
            CPA_TRUE == pCookie->integrityCrcCheck && NULL != pOpData &&
            NULL != pOpData->pCrcData)
        {
            if (!pService->generic_service_info.isGen4)
            {
                dcHandleIntegrityChecksums(
                    pCookie, pOpData->pCrcData, pResults);
            }
            else
            {
                dcHandleIntegrityChecksumsGen4(
                    pCookie, pOpData->pCrcData, pResults);
            }

            if (pResults->status == CPA_DC_CRC_INTEG_ERR)
            {
                cmpPass = CPA_FALSE;
            }
        }
        else
        {
            if (CPA_DC_CRC32 == pSessionDesc->checksumType)
            {
                pResults->checksum =
                    pCompRespMsg->comp_resp_pars.crc.legacy.curr_crc32;
            }
            else if ((CPA_DC_ADLER32 == pSessionDesc->checksumType) ||
                     (CPA_DC_XXHASH32 == pSessionDesc->checksumType))
            {
                pResults->checksum =
                    pCompRespMsg->comp_resp_pars.crc.legacy.curr_adler_32;
            }
        }
    }

    if ((CPA_TRUE == cmpPass) && (CPA_TRUE == xlatPass))
    {
        if ((DC_COMPRESSION_REQUEST == compDecomp) &&
            (pService->generic_service_info.isGen4))
        {
            /* Check if returned data is a stored block
             * in compression direction
             */
            if (pResults)
                pResults->dataUncompressed =
                    ICP_QAT_FW_COMN_HDR_ST_BLK_FLAG_GET(hdrFlags);

            /* Check for reset of xxhash state */
            if (CPA_DC_OVERFLOW != (Cpa8S)cmpErr)
                dcResetXxhashState(pSessionDesc, pCookie);
        }

        if (pResults && (DC_DECOMPRESSION_REQUEST == compDecomp))
        {
            pResults->endOfLastBlock =
                (ICP_QAT_FW_COMN_STATUS_CMP_END_OF_LAST_BLK_FLAG_SET ==
                 ICP_QAT_FW_COMN_RESP_CMP_END_OF_LAST_BLK_FLAG_GET(opStatus));
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

        if (CPA_TRUE == isDcDp && NULL != pResponse)
        {
            pResponse->responseStatus = CPA_STATUS_SUCCESS;
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
        if (pResults)
        {
#ifdef ICP_DC_RETURN_COUNTERS_ON_ERROR
            /* Extract the response from the firmware */
            pResults->consumed =
                pCompRespMsg->comp_resp_pars.input_byte_counter;
            pResults->produced =
                pCompRespMsg->comp_resp_pars.output_byte_counter;

            if (CPA_DC_STATEFUL == pSessionDesc->sessState)
            {
                pSessionDesc->cumulativeConsumedBytes += pResults->consumed;
            }
            else
            {
                /* In the stateless case all requests have both SOP and EOP set
                 */
                pSessionDesc->cumulativeConsumedBytes = pResults->consumed;
            }
#else
            pResults->consumed = 0;
            pResults->produced = 0;
#endif
            if (CPA_DC_OVERFLOW == pResults->status &&
                CPA_DC_STATELESS == pSessionDesc->sessState)
            {
                /* This error message will be returned by Data Plane API in both
                 * compression and decompression direction. With Traditional API
                 * this error message will be returned only in stateless
                 * decompression direction */
                LAC_LOG_ERROR(
                    "Unrecoverable error: stateless overflow. You may "
                    "need to increase the size of your destination buffer");
            }
        }

        if (CPA_TRUE == isDcDp && NULL != pResponse)
        {
            pResponse->responseStatus = CPA_STATUS_FAIL;
        }
        else
        {
            if (pResults == NULL ||
                (CPA_DC_OK != pResults->status &&
                 CPA_DC_INCOMPLETE_FILE_ERR != pResults->status))
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

    if (CPA_TRUE == isDcDp)
    {
        if (pResponse)
        {
            /* Decrement number of stateless pending callbacks for session */
            pSessionDesc->pendingDpStatelessCbCount--;
            (pService->pDcDpCb)(pResponse);
        }
    }
    else
    {
        /* Decrement number of pending callbacks for session */
        if (CPA_DC_STATELESS == pSessionDesc->sessState)
        {
            osalAtomicDec(&(pCookie->pSessionDesc->pendingStatelessCbCount));
        }
        else if (0 !=
                 osalAtomicGet(&pCookie->pSessionDesc->pendingStatefulCbCount))
        {
            osalAtomicDec(&(pCookie->pSessionDesc->pendingStatefulCbCount));
        }

        /* Free the memory pool */
        Lac_MemPoolEntryFree(pCookie);
        pCookie = NULL;

        if (NULL != pCbFunc)
        {
            pCbFunc(callbackTag, status);
        }
    }
}

#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check that all the parameters in the pOpData structure are valid
 *
 * @description
 *      Check that all the parameters in the pOpData structure are valid
 *
 * @param[in]   pService              Pointer to the compression service
 * @param[in]   pOpData               Pointer to request information structure
 *                                    holding parameters for cpaDcCompress2 and
 *                                    CpaDcDecompressData2
 * @retval CPA_STATUS_SUCCESS         Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 *
 *****************************************************************************/
#ifndef KERNEL_SPACE
STATIC CpaStatus dcCheckOpData(sal_compression_service_t *pService,
                               CpaDcOpData *pOpData)
{
    CpaDcSkipMode skipMode = 0;

    if ((pOpData->flushFlag < CPA_DC_FLUSH_NONE) ||
        (pOpData->flushFlag > CPA_DC_FLUSH_FULL))
    {
        LAC_INVALID_PARAM_LOG("Invalid flushFlag value");
        return CPA_STATUS_INVALID_PARAM;
    }

    skipMode = pOpData->inputSkipData.skipMode;
    if ((skipMode < CPA_DC_SKIP_DISABLED) || (skipMode > CPA_DC_SKIP_STRIDE))
    {
        LAC_INVALID_PARAM_LOG("Invalid input skip mode value");
        return CPA_STATUS_INVALID_PARAM;
    }

    skipMode = pOpData->outputSkipData.skipMode;
    if ((skipMode < CPA_DC_SKIP_DISABLED) || (skipMode > CPA_DC_SKIP_STRIDE))
    {
        LAC_INVALID_PARAM_LOG("Invalid output skip mode value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->integrityCrcCheck == CPA_FALSE &&
        pOpData->verifyHwIntegrityCrcs == CPA_TRUE)
    {
        LAC_INVALID_PARAM_LOG("integrityCrcCheck must be set to true"
                              "in order to enable verifyHwIntegrityCrcs");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->integrityCrcCheck != CPA_TRUE &&
        pOpData->integrityCrcCheck != CPA_FALSE)
    {
        LAC_INVALID_PARAM_LOG("Invalid integrityCrcCheck value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->verifyHwIntegrityCrcs != CPA_TRUE &&
        pOpData->verifyHwIntegrityCrcs != CPA_FALSE)
    {
        LAC_INVALID_PARAM_LOG("Invalid verifyHwIntegrityCrcs value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->compressAndVerify != CPA_TRUE &&
        pOpData->compressAndVerify != CPA_FALSE)
    {
        LAC_INVALID_PARAM_LOG("Invalid cnv decompress check value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_TRUE == pOpData->integrityCrcCheck &&
        CPA_FALSE == pService->generic_service_info.integrityCrcCheck)
    {
        LAC_INVALID_PARAM_LOG("Integrity CRC check is not "
                              "supported on this device");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_TRUE == pOpData->integrityCrcCheck && NULL == pOpData->pCrcData)
    {
        LAC_INVALID_PARAM_LOG("Integrity CRC data structure "
                              "not intialized in CpaDcOpData");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check the compression source buffer for Batch and Pack API.
 *
 * @description
 *      Check that all the parameters used for a Batch and Pack compression
 *      request are valid. This function essentially checks the source buffer
 *      parameters and results structure parameters.
 *
 * @param[in]   pSessionHandle        Session handle
 * @param[in]   pSrcBuff              Pointer to data buffer for compression
 * @param[in]   pDestBuff             Pointer to buffer space allocated for
 *                                    output data
 * @param[in]   pResults              Pointer to results structure
 * @param[in]   flushFlag             Indicates the type of flush to be
 *                                    performed
 * @param[in]   srcBuffSize           Size of the source buffer
 *
 * @retval CPA_STATUS_SUCCESS         Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus dcCheckSourceData(CpaDcSessionHandle pSessionHandle,
                                   CpaBufferList *pSrcBuff,
                                   CpaBufferList *pDestBuff,
                                   CpaDcRqResults *pResults,
                                   CpaDcFlush flushFlag,
                                   Cpa64U srcBuffSize,
                                   CpaDcSkipData *skipData)
{
    dc_session_desc_t *pSessionDesc = NULL;

    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pSrcBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pResults);

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
    if (NULL == pSessionDesc)
    {
        LAC_INVALID_PARAM_LOG("Session handle not as expected");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((flushFlag < CPA_DC_FLUSH_NONE) || (flushFlag > CPA_DC_FLUSH_FULL))
    {
        LAC_INVALID_PARAM_LOG("Invalid flushFlag value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSrcBuff == pDestBuff)
    {
        LAC_INVALID_PARAM_LOG("In place operation not supported");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Compressing zero bytes is not supported for stateless sessions
     * for non Batch and Pack requests */
    if ((CPA_DC_STATELESS == pSessionDesc->sessState) && (0 == srcBuffSize) &&
        (NULL == skipData))
    {
        LAC_INVALID_PARAM_LOG("The source buffer size needs to be greater than "
                              "zero bytes for stateless sessions");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (srcBuffSize > DC_BUFFER_MAX_SIZE)
    {
        LAC_INVALID_PARAM_LOG("The source buffer size needs to be less than or "
                              "equal to 2^32-1 bytes");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check the compression or decompression function parameters.
 *
 * @description
 *      Check that all the parameters used for a Batch and Pack compression
 *      request are valid. This function essentially checks the destination
 *      buffer parameters and intermediate buffer parameters.
 *
 * @param[in]   pService              Pointer to the compression service
 * @param[in]   pSessionHandle        Session handle
 * @param[in]   pDestBuff             Pointer to buffer space allocated for
 *                                    output data
 * @param[in]   compDecomp            Direction of the operation
 *
 * @retval CPA_STATUS_SUCCESS         Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus dcCheckDestinationData(sal_compression_service_t *pService,
                                        CpaDcSessionHandle pSessionHandle,
                                        CpaBufferList *pDestBuff,
                                        dc_request_dir_t compDecomp)
{
    dc_session_desc_t *pSessionDesc = NULL;
    Cpa64U destBuffSize = 0;

    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pDestBuff);

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
    if (NULL == pSessionDesc)
    {
        LAC_INVALID_PARAM_LOG("Session handle not as expected");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (LacBuffDesc_BufferListVerify(
            pDestBuff, &destBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
        CPA_STATUS_SUCCESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid destination buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (destBuffSize > DC_BUFFER_MAX_SIZE)
    {
        LAC_INVALID_PARAM_LOG("The destination buffer size needs to be less "
                              "than or equal to 2^32-1 bytes");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        LAC_INVALID_PARAM_LOG("The session type should not be data plane");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
#ifndef ICP_DC_DYN_NOT_SUPPORTED
        if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
        {

            /* Check if intermediate buffers are supported */
            if ((!pService->generic_service_info.isGen4) &&
                ((0 == pService->pInterBuffPtrsArrayPhyAddr) ||
                 (NULL == pService->pInterBuffPtrsArray)))
            {
                LAC_LOG_ERROR(
                    "No intermediate buffer defined for this instance "
                    "- see cpaDcStartInstance");
                return CPA_STATUS_INVALID_PARAM;
            }

            /* Ensure that the destination buffer size is greater or equal
             * to devices min output buff size for dynamic compression */
            if (destBuffSize <
                pService->comp_device_data.minOutputBuffSizeDynamic)
            {
                LAC_INVALID_PARAM_LOG1(
                    "Destination buffer size should be "
                    "greater or equal to %d bytes",
                    pService->comp_device_data.minOutputBuffSizeDynamic);
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        else
#else
        if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
        {
            LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions "
                                  "not supported");
            return CPA_STATUS_INVALID_PARAM;
        }
        else
#endif
        {
            /* Ensure that the destination buffer size is greater or equal
             * to devices min output buff size for static compression */
            if (destBuffSize < pService->comp_device_data.minOutputBuffSize)
            {
                LAC_INVALID_PARAM_LOG1(
                    "Destination buffer size should be "
                    "greater or equal to %d bytes",
                    pService->comp_device_data.minOutputBuffSize);
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

    return CPA_STATUS_SUCCESS;
}
#endif

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
STATIC void dcCompRequestParamsPopulate(
    icp_qat_fw_comp_req_params_t *pCompReqParams,
    dc_compression_cookie_t *pCookie)
{
    LAC_ENSURE_NOT_NULL(pCompReqParams);
    LAC_ENSURE_NOT_NULL(pCookie);

    pCompReqParams->comp_len = pCookie->srcTotalDataLenInBytes;
    pCompReqParams->out_buffer_sz = pCookie->dstTotalDataLenInBytes;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Create the requests for compression or decompression
 *
 * @description
 *      Create the requests for compression or decompression. This function
 *      will update the cookie will all required information.
 *
 * @param{out]  pCookie             Pointer to the compression cookie
 * @param[in]   pService            Pointer to the compression service
 * @param[in]   pSessionDesc        Pointer to the session descriptor
 * @param[in    pSessionHandle      Session handle
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
 * @param[in]   compressAndVerify   Compress and Verify
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus dcCreateRequest(dc_compression_cookie_t *pCookie,
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
                                 dc_cnv_mode_t cnvMode)
{
    icp_qat_fw_comp_req_t *pMsg = NULL;
    icp_qat_fw_comp_req_params_t *pCompReqParams = NULL;
    Cpa64U srcAddrPhys = 0, dstAddrPhys = 0;
    Cpa64U srcTotalDataLenInBytes = 0, dstTotalDataLenInBytes = 0;

    Cpa32U rpCmdFlags = 0;
    Cpa8U sop = ICP_QAT_FW_COMP_SOP;
    Cpa8U eop = ICP_QAT_FW_COMP_EOP;
    Cpa8U crcMode = ICP_QAT_FW_COMP_CRC_MODE_LEGACY;
    Cpa8U bFinal = ICP_QAT_FW_COMP_NOT_BFINAL;
    Cpa8U cnvDecompReq = ICP_QAT_FW_COMP_NO_CNV;
    Cpa8U cnvRecovery = ICP_QAT_FW_COMP_NO_CNV_RECOVERY;
    Cpa8U cnvErrorInjection = ICP_QAT_FW_COMP_NO_CNV_DFX;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcFlush flush = CPA_DC_FLUSH_NONE;
    Cpa32U initial_adler = DC_DEFAULT_ADLER32;
    Cpa32U initial_crc32 = DC_DEFAULT_CRC;
    icp_qat_fw_comp_req_t *pReqCache = NULL;

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

    /* Populate the compression cookie */
    pCookie->dcInstance = pService;
    pCookie->pSessionHandle = pSessionHandle;
    pCookie->callbackTag = callbackTag;
    pCookie->pSessionDesc = pSessionDesc;
    pCookie->pDcOpData = pOpData;
    pCookie->pResults = pResults;
    pCookie->compDecomp = compDecomp;
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
    pCookie->integrityCrcCheck = CPA_FALSE;
    pCookie->verifyHwIntegrityCrcs = CPA_FALSE;

    /* Extract flush flag from either the opData or from the
     * parameter. Opdata have been introduced with APIs
     * cpaDcCompressData2 and cpaDcDecompressData2 */
    if (NULL != pOpData)
    {
        flush = pOpData->flushFlag;
#ifndef KERNEL_SPACE
        pCookie->integrityCrcCheck = pOpData->integrityCrcCheck;
        pCookie->verifyHwIntegrityCrcs = pOpData->verifyHwIntegrityCrcs;
#endif
    }
    else
    {
        flush = flushFlag;
    }

    pCookie->flushFlag = flush;

    /* The firmware expects the length in bytes for source and destination to be
     * Cpa32U parameters. However the total data length could be bigger as
     * allocated by the user. We ensure that this is not the case in
     * dcCheckSourceData and cast the values to Cpa32U here */
    pCookie->srcTotalDataLenInBytes = (Cpa32U)srcTotalDataLenInBytes;
#ifndef ICP_DC_DYN_NOT_SUPPORTED
    if ((!pService->generic_service_info.isGen4) &&
        (DC_COMPRESSION_REQUEST == compDecomp) &&
        (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType))
    {
        if (pService->minInterBuffSizeInBytes < (Cpa32U)dstTotalDataLenInBytes)
        {
            pCookie->dstTotalDataLenInBytes =
                (Cpa32U)(pService->minInterBuffSizeInBytes);
        }
        else
        {
            pCookie->dstTotalDataLenInBytes = (Cpa32U)dstTotalDataLenInBytes;
        }
    }
    else
#endif
    {
        pCookie->dstTotalDataLenInBytes = (Cpa32U)dstTotalDataLenInBytes;
    }

    /* Device can not decompress an odd byte decompression request
     * if bFinal is not set
     */
    if (CPA_TRUE != pService->comp_device_data.oddByteDecompNobFinal)
    {
        if ((CPA_DC_STATEFUL == pSessionDesc->sessState) &&
            (CPA_DC_FLUSH_FINAL != flushFlag) &&
            (DC_DECOMPRESSION_REQUEST == compDecomp) &&
            (pCookie->srcTotalDataLenInBytes & 0x1))
        {
            pCookie->srcTotalDataLenInBytes--;
        }
    }
    /* Device can not decompress odd byte interim requests */
    if (CPA_TRUE != pService->comp_device_data.oddByteDecompInterim)
    {
        if ((CPA_DC_STATEFUL == pSessionDesc->sessState) &&
            (CPA_DC_FLUSH_FINAL != flushFlag) &&
            (CPA_DC_FLUSH_FULL != flushFlag) &&
            (DC_DECOMPRESSION_REQUEST == compDecomp) &&
            (pCookie->srcTotalDataLenInBytes & 0x1))
        {
            pCookie->srcTotalDataLenInBytes--;
        }
    }

    pMsg = (icp_qat_fw_comp_req_t *)&pCookie->request;

    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
        pReqCache = &(pSessionDesc->reqCacheComp);
    }
    else
    {
        pReqCache = &(pSessionDesc->reqCacheDecomp);
    }

    /* Fills the msg from the template cached in the session descriptor */
    if (CPA_DC_STATELESS == pSessionDesc->sessState &&
        DC_COMPRESSION_REQUEST == compDecomp)
    {
        LAC_SPINLOCK(&(pSessionDesc->updateLock));
        osalMemCopy((void *)pMsg,
                    (void *)(pReqCache),
                    LAC_QAT_DC_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES);
        LAC_SPINUNLOCK(&(pSessionDesc->updateLock));
    }
    else
    {
        osalMemCopy((void *)pMsg,
                    (void *)(pReqCache),
                    LAC_QAT_DC_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES);
    }

    if (CPA_DC_STATELESS == pSessionDesc->sessState &&
        DC_REQUEST_SUBSEQUENT == pSessionDesc->requestType)
    {
        switch (pSessionDesc->checksumType)
        {
            case CPA_DC_ADLER32:
                initial_adler = pResults->checksum;
                break;
            case CPA_DC_CRC32:
                initial_crc32 = pResults->checksum;
                break;
            default:
                break;
                /* XXHASH32 uses a different implementation and does not need
                   initialising here. */
        }
    }
#ifndef KERNEL_SPACE
    /* Backup source and destination buffer addresses,
     * CRC calculations both for CNV and translator overflow
     * will be performed on them in the callback function.
     */
    pCookie->pUserSrcBuff = pSrcBuff;
    pCookie->pUserDestBuff = pDestBuff;

    /*
     * Due to implementation of CNV support and need for backwards compatibility
     * certain fields in the request and response structs had been
     * changed, moved or placed in unions
     * cnvMode flag signifies fields to be selected from req/res
     *
     * Doing extended crc checks makes sense only when we want to do the actual
     * CNV
     */
    if (CPA_TRUE == pService->generic_service_info.integrityCrcCheck &&
        CPA_TRUE == pCookie->integrityCrcCheck)
    {
        /* Get physical address of E2E CRC buffer */
        pMsg->comp_pars.crc.crc_data_addr =
            (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_EXTERNAL(
                pService->generic_service_info, &pCookie->dataIntegrityCrcs);

        if (!pMsg->comp_pars.crc.crc_data_addr)
        {
            LAC_LOG_ERROR("Unable to get the physical address of "
                          "Data Integrity buffer.\n");
            return CPA_STATUS_FAIL;
        }

        /* XXHASH32 uses a different initialisation mechanism */
        pCookie->dataIntegrityCrcs.crc32 = initial_crc32;
        pCookie->dataIntegrityCrcs.adler32 = initial_adler;

        if (!pService->generic_service_info.isGen4)
        {
            if (CPA_DC_STATEFUL == pSessionDesc->sessState)
            {
                pCookie->dataIntegrityCrcs.iCrc32Cpr =
                    pOpData->pCrcData->integrityCrc.iCrc;
                pCookie->dataIntegrityCrcs.oCrc32Cpr =
                    pOpData->pCrcData->integrityCrc.oCrc;
                pCookie->dataIntegrityCrcs.iCrc32Xlt =
                    pOpData->pCrcData->integrityCrc.oCrc;
                pCookie->dataIntegrityCrcs.oCrc32Xlt =
                    pOpData->pCrcData->integrityCrc.oCrc;
            }
            else
            {
                pCookie->dataIntegrityCrcs.iCrc32Cpr = DC_DEFAULT_CRC;
                pCookie->dataIntegrityCrcs.oCrc32Cpr = DC_DEFAULT_CRC;
                pCookie->dataIntegrityCrcs.iCrc32Xlt = DC_DEFAULT_CRC;
                pCookie->dataIntegrityCrcs.oCrc32Xlt = DC_DEFAULT_CRC;
            }
            pCookie->dataIntegrityCrcs.xorFlags = DC_XOR_FLAGS_DEFAULT;
            pCookie->dataIntegrityCrcs.crcPoly = DC_CRC_POLY_DEFAULT;
            pCookie->dataIntegrityCrcs.xorOut = DC_XOR_OUT_DEFAULT;
            pCookie->dataIntegrityCrcs.deflateBlockType = DC_STATIC_TYPE;
        }
        else
        {
            pCookie->dataIntegrityCrcs.iCrc64Cpr = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.oCrc64Cpr = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.iCrc64Xlt = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.oCrc64Xlt = DC_DEFAULT_CRC;
            pCookie->dataIntegrityCrcs.crc64Poly = DC_CRC64_POLY_DEFAULT;
            pCookie->dataIntegrityCrcs.xor64Out = DC_XOR64_OUT_DEFAULT;
        }

        crcMode = ICP_QAT_FW_COMP_CRC_MODE_E2E;
    }
    else
    {
        /* Legacy request structure */
        /* XXHASH32 uses a different initialisation mechanism */
        pMsg->comp_pars.crc.legacy.initial_crc32 = initial_crc32;
        pMsg->comp_pars.crc.legacy.initial_adler = initial_adler;

        crcMode = ICP_QAT_FW_COMP_CRC_MODE_LEGACY;
    }
#endif
    /* Populate the cmdFlags */
    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        pSessionDesc->previousRequestType = pSessionDesc->requestType;

        if (DC_REQUEST_FIRST == pSessionDesc->requestType)
        {
            /* Update the request type for following requests */
            pSessionDesc->requestType = DC_REQUEST_SUBSEQUENT;

            /* Reinitialise the cumulative amount of consumed bytes */
            pSessionDesc->cumulativeConsumedBytes = 0;

            if (DC_COMPRESSION_REQUEST == compDecomp)
            {
                pSessionDesc->isSopForCompressionProcessed = CPA_TRUE;
            }
            else if (DC_DECOMPRESSION_REQUEST == compDecomp)
            {
                pSessionDesc->isSopForDecompressionProcessed = CPA_TRUE;
            }
        }
        else
        {
            if (DC_COMPRESSION_REQUEST == compDecomp)
            {
                if (CPA_TRUE == pSessionDesc->isSopForCompressionProcessed)
                {
                    sop = ICP_QAT_FW_COMP_NOT_SOP;
                }
                else
                {
                    pSessionDesc->isSopForCompressionProcessed = CPA_TRUE;
                }
            }
            else if (DC_DECOMPRESSION_REQUEST == compDecomp)
            {
                if (CPA_TRUE == pSessionDesc->isSopForDecompressionProcessed)
                {
                    sop = ICP_QAT_FW_COMP_NOT_SOP;
                }
                else
                {
                    pSessionDesc->isSopForDecompressionProcessed = CPA_TRUE;
                }
            }
        }

        if ((CPA_DC_FLUSH_FINAL == flush) || (CPA_DC_FLUSH_FULL == flush))
        {
            /* Update the request type for following requests */
            pSessionDesc->requestType = DC_REQUEST_FIRST;
        }
        else
        {
            eop = ICP_QAT_FW_COMP_NOT_EOP;
        }
    }
    else
    {
        if (DC_REQUEST_FIRST == pSessionDesc->requestType)
        {
            /* Reinitialise the cumulative amount of consumed bytes */
            pSessionDesc->cumulativeConsumedBytes = 0;
        }
    }

    pCompReqParams = &(pMsg->comp_pars);
    /* Comp requests param populate
     * (LW 14 - 15)*/
    dcCompRequestParamsPopulate(pCompReqParams, pCookie);
    if (CPA_DC_FLUSH_FINAL == flush)
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
            if (pService->generic_service_info.isGen4)
            {
                cnvErrorInjection = pSessionDesc->cnvErrorInjection;
            }
            break;
        case DC_NO_CNV:
            cnvDecompReq = ICP_QAT_FW_COMP_NO_CNV;
            cnvRecovery = ICP_QAT_FW_COMP_NO_CNV_RECOVERY;
            break;
    }

    rpCmdFlags = ICP_QAT_FW_COMP_REQ_PARAM_FLAGS_BUILD(sop,
                                                       eop,
                                                       bFinal,
                                                       cnvDecompReq,
                                                       cnvRecovery,
                                                       cnvErrorInjection,
                                                       crcMode);

    /* Extract xxhash accumulator flag from sessionDesc */
    ICP_QAT_FW_COMP_XXHASH_ACC_MODE_SET(rpCmdFlags,
                                        pSessionDesc->accumulateXXHash);

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

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Send a compression request to QAT
 *
 * @description
 *      Send the requests for compression or decompression to QAT
 *
 * @param{in]   pCookie               Pointer to the compression cookie
 * @param[in]   pService              Pointer to the compression service
 * @param[in]   pSessionDesc          Pointer to the session descriptor
 * @param[in]   compDecomp            Direction of the operation
 *
 * @retval CPA_STATUS_SUCCESS         Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus dcSendRequest(dc_compression_cookie_t *pCookie,
                               sal_compression_service_t *pService,
                               dc_session_desc_t *pSessionDesc,
                               dc_request_dir_t compDecomp)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Send to QAT */
    status = SalQatMsg_transPutMsg(pService->trans_handle_compression_tx,
                                   (void *)&(pCookie->request),
                                   LAC_QAT_DC_REQ_SZ_LW,
                                   LAC_LOG_MSG_DC,
                                   NULL);

    if ((CPA_DC_STATEFUL == pSessionDesc->sessState) &&
        (CPA_STATUS_RETRY == status))
    {
        /* reset requestType after receiving an retry on
         * the stateful request */
        pSessionDesc->requestType = pSessionDesc->previousRequestType;
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Process the synchronous and asynchronous case for compression or
 *      decompression
 *
 * @description
 *      Process the synchronous and asynchronous case for compression or
 *      decompression. This function will then create and send the request to
 *      the firmware.
 *
 * @param[in]   pService            Pointer to the compression service
 * @param[in]   pSessionDesc        Pointer to the session descriptor
 * @param[in]   dcInstance          Instance handle derived from discovery
 *                                  functions
 * @param[in]   pSessionHandle      Session handle
 * @param[in]   pSrcBuff            Pointer to data buffer for compression
 * @param[in]   pDestBuff           Pointer to buffer space for data after
 *                                  compression
 * @param[in]   pResults            Pointer to results structure
 * @param[in]   flushFlag           Indicates the type of flush to be
 *                                  performed
 * @param[in]   pOpData             Pointer to request information structure
 *                                  holding parameters for cpaDcCompress2 and
 *                                  CpaDcDecompressData2
 * @param[in]   callbackTag         Pointer to the callback tag
 * @param[in]   compDecomp          Direction of the operation
 * @param[in]   isAsyncMode         Used to know if synchronous or asynchronous
 *                                  mode
 * @param[in]   compressAndVerify   Compress and Verify mode
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully
 * @retval CPA_STATUS_FAIL          Function failed
 * @retval CPA_STATUS_RESOURCE      Resource error
 *
 *****************************************************************************/
STATIC CpaStatus dcCompDecompData(sal_compression_service_t *pService,
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
                                  dc_cnv_mode_t cnvMode)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    dc_compression_cookie_t *pCookie = NULL;

    if ((LacSync_GenWakeupSyncCaller == pSessionDesc->pCompressionCb) &&
        isAsyncMode == CPA_TRUE)
    {
        lac_sync_op_data_t *pSyncCallbackData = NULL;

        status = LacSync_CreateSyncCookie(&pSyncCallbackData);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = dcCompDecompData(pService,
                                      pSessionDesc,
                                      dcInstance,
                                      pSessionHandle,
                                      pSrcBuff,
                                      pDestBuff,
                                      pResults,
                                      flushFlag,
                                      pOpData,
                                      pSyncCallbackData,
                                      compDecomp,
                                      CPA_FALSE,
                                      cnvMode);
        }
        else
        {
            return status;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            CpaStatus syncStatus = CPA_STATUS_SUCCESS;

            syncStatus = LacSync_WaitForCallback(
                pSyncCallbackData, DC_SYNC_CALLBACK_TIMEOUT, &status, NULL);

            /* If callback doesn't come back */
            if (CPA_STATUS_SUCCESS != syncStatus)
            {
                if (DC_COMPRESSION_REQUEST == compDecomp)
                {
                    COMPRESSION_STAT_INC(numCompCompletedErrors, pService);
                }
                else
                {
                    COMPRESSION_STAT_INC(numDecompCompletedErrors, pService);
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
        return status;
    }

    /* Allocate the compression cookie
     * The memory is freed in callback or in sendRequest if an error occurs
     */
    do
    {
        pCookie = (dc_compression_cookie_t *)Lac_MemPoolEntryAlloc(
            pService->compression_mem_pool);
        if (NULL == pCookie)
        {
            LAC_LOG_ERROR("Cannot get mem pool entry for compression");
            status = CPA_STATUS_RESOURCE;
        }
        else if ((void *)CPA_STATUS_RETRY == pCookie)
        {
            /* Give back the control to the OS */
            osalYield();
        }
    } while ((void *)CPA_STATUS_RETRY == pCookie);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcCreateRequest(pCookie,
                                 pService,
                                 pSessionDesc,
                                 pSessionHandle,
                                 pSrcBuff,
                                 pDestBuff,
                                 pResults,
                                 flushFlag,
                                 pOpData,
                                 callbackTag,
                                 compDecomp,
                                 cnvMode);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Increment number of pending callbacks for session */
        if (CPA_DC_STATELESS == pSessionDesc->sessState)
        {
            osalAtomicInc(&(pSessionDesc->pendingStatelessCbCount));
        }
        status = dcSendRequest(pCookie, pService, pSessionDesc, compDecomp);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (DC_COMPRESSION_REQUEST == compDecomp)
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
        if (DC_COMPRESSION_REQUEST == compDecomp)
        {
            COMPRESSION_STAT_INC(numCompRequestsErrors, pService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompRequestsErrors, pService);
        }

        /* Decrement number of pending callbacks for session */
        if (CPA_DC_STATELESS == pSessionDesc->sessState)
        {
            osalAtomicDec(&(pSessionDesc->pendingStatelessCbCount));
        }
        else
        {
            osalAtomicDec(&(pSessionDesc->pendingStatefulCbCount));
        }
        /* Free the memory pool */
        if (NULL != pCookie)
        {
            Lac_MemPoolEntryFree(pCookie);
            pCookie = NULL;
        }
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Handle zero length compression or decompression requests
 *
 * @description
 *      Handle zero length compression or decompression requests.
 *      Note: This function uses the state registers stored in the
 *      session for reading the previous checksum.
 *      This function should only be called for stateful requests and
 *      is not considered threadsafe.
 *
 * @param[in]   pService              Pointer to the compression service
 * @param[in]   pSessionDesc          Pointer to the session descriptor
 * @param[in]   pResults              Pointer to results structure
 * @param[in]   flushFlag             Indicates the type of flush to be
 *                                    performed
 * @param[in]   callbackTag           User supplied value to help correlate
 *                                    the callback with its associated request
 * @param[in]   compDecomp            Direction of the operation
 *
 * @retval CPA_TRUE                   Zero length SOP or MOP processed
 * @retval CPA_FALSE                  Zero length EOP
 *
 *****************************************************************************/
STATIC CpaBoolean dcZeroLengthRequests(sal_compression_service_t *pService,
                                       dc_session_desc_t *pSessionDesc,
                                       CpaDcRqResults *pResults,
                                       CpaDcFlush flushFlag,
                                       void *callbackTag,
                                       dc_request_dir_t compDecomp)
{
    CpaBoolean status = CPA_FALSE;
    CpaDcCallbackFn pCbFunc = pSessionDesc->pCompressionCb;
    Cpa8U *pStateAddr = NULL;
    Cpa8U i = 0;

    if (DC_REQUEST_FIRST == pSessionDesc->requestType)
    {
        /* Reinitialise the cumulative amount of consumed bytes */
        pSessionDesc->cumulativeConsumedBytes = 0;

        /* Zero length SOP */
        if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
        {
            pResults->checksum = 1;
        }
        else
        {
            pResults->checksum = 0;
        }

        status = CPA_TRUE;
    }
    else if ((CPA_DC_FLUSH_NONE == flushFlag) ||
             (CPA_DC_FLUSH_SYNC == flushFlag))
    {
        /* Zero length MOP */
        if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
        {
            if (DC_COMPRESSION_REQUEST == compDecomp)
            {
                pStateAddr =
                    &pSessionDesc->stateRegistersComp[DC_STATE_ADLER32_OFFSET];
            }
            else
            {
                pStateAddr =
                    &pSessionDesc
                         ->stateRegistersDecomp[DC_STATE_ADLER32_OFFSET];
            }
        }
        else
        {
            if (DC_COMPRESSION_REQUEST == compDecomp)
            {
                pStateAddr =
                    &pSessionDesc->stateRegistersComp[DC_STATE_CRC32_OFFSET];
            }
            else
            {
                pStateAddr =
                    &pSessionDesc->stateRegistersDecomp[DC_STATE_CRC32_OFFSET];
            }
        }

        pResults->checksum = 0;
        for (i = 0; i < DC_CHECKSUM_SIZE_IN_BYTES; i++)
        {
            pResults->checksum |=
                ((Cpa32U) * (pStateAddr++) << (i * DC_8_BIT_SHIFT_POS));
        }

        status = CPA_TRUE;
    }

    if (CPA_TRUE == status)
    {
        pResults->status = CPA_DC_OK;
        pResults->produced = 0;
        pResults->consumed = 0;

        /* Increment statistics */
        if (DC_COMPRESSION_REQUEST == compDecomp)
        {
            COMPRESSION_STAT_INC(numCompRequests, pService);
            COMPRESSION_STAT_INC(numCompCompleted, pService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompRequests, pService);
            COMPRESSION_STAT_INC(numDecompCompleted, pService);
        }

        LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));

        if ((NULL != pCbFunc) && (LacSync_GenWakeupSyncCaller != pCbFunc))
        {
            pCbFunc(callbackTag, CPA_STATUS_SUCCESS);
        }

        return CPA_TRUE;
    }

    return CPA_FALSE;
}

#ifdef ICP_PARAM_CHECK
STATIC CpaStatus dcParamCheck(const CpaInstanceHandle dcInstance,
                              const CpaDcSessionHandle pSessionHandle,
                              const sal_compression_service_t *pService,
                              const CpaBufferList *pSrcBuff,
                              const CpaBufferList *pDestBuff,
                              const CpaDcRqResults *pResults,
                              const dc_session_desc_t *pSessionDesc,
                              const CpaDcFlush flushFlag,
                              const Cpa64U srcBuffSize)
{

    if (dcCheckSourceData(pSessionHandle,
                          (CpaBufferList *)pSrcBuff,
                          (CpaBufferList *)pDestBuff,
                          (CpaDcRqResults *)pResults,
                          flushFlag,
                          srcBuffSize,
                          NULL) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (dcCheckDestinationData((sal_compression_service_t *)pService,
                               pSessionHandle,
                               (CpaBufferList *)pDestBuff,
                               DC_COMPRESSION_REQUEST) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }
    return CPA_STATUS_SUCCESS;
}
#endif

CpaStatus cpaDcCompressData(CpaInstanceHandle dcInstance,
                            CpaDcSessionHandle pSessionHandle,
                            CpaBufferList *pSrcBuff,
                            CpaBufferList *pDestBuff,
                            CpaDcRqResults *pResults,
                            CpaDcFlush flushFlag,
                            void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;

#ifdef ICP_TRACE
    LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%x, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pResults,
             flushFlag,
             (LAC_ARCH_UINT)callbackTag);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

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
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
#ifdef ICP_PARAM_CHECK
    if (CPA_STATUS_SUCCESS != dcParamCheck(insHandle,
                                           pSessionHandle,
                                           pService,
                                           pSrcBuff,
                                           pDestBuff,
                                           pResults,
                                           pSessionDesc,
                                           flushFlag,
                                           srcBuffSize))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions "
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        LAC_INVALID_PARAM_LOG("Invalid session state, stateful sessions "
                              "not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (!(pService->generic_service_info.dcExtendedFeatures &
          DC_CNV_EXTENDED_CAPABILITY))
    {
        LAC_INVALID_PARAM_LOG("CompressAndVerify feature not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (!(pService->generic_service_info.dcExtendedFeatures &
          DC_CNVNR_EXTENDED_CAPABILITY))
    {
        LAC_INVALID_PARAM_LOG(
            "CompressAndVerifyAndRecovery feature not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    return dcCompDecompData(pService,
                            pSessionDesc,
                            dcInstance,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            pResults,
                            flushFlag,
                            NULL,
                            callbackTag,
                            DC_COMPRESSION_REQUEST,
                            CPA_TRUE,
                            DC_CNVNR);
}

/* Note: cpaDcCompressData2 would be thread unsafe if it is using
 * E2E functionality */
CpaStatus cpaDcCompressData2(CpaInstanceHandle dcInstance,
                             CpaDcSessionHandle pSessionHandle,
                             CpaBufferList *pSrcBuff,
                             CpaBufferList *pDestBuff,
                             CpaDcOpData *pOpData,
                             CpaDcRqResults *pResults,
                             void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
    dc_cnv_mode_t cnvMode = DC_NO_CNV;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pOpData);

    if (((CPA_TRUE != pOpData->compressAndVerify) &&
         (CPA_FALSE != pOpData->compressAndVerify)) ||
        ((CPA_FALSE != pOpData->compressAndVerifyAndRecover) &&
         (CPA_TRUE != pOpData->compressAndVerifyAndRecover)))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((CPA_FALSE == pOpData->compressAndVerify) &&
        (CPA_TRUE == pOpData->compressAndVerifyAndRecover))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

#endif

    if ((CPA_TRUE == pOpData->compressAndVerify) &&
        (CPA_TRUE == pOpData->compressAndVerifyAndRecover) &&
        (CPA_FALSE == pOpData->integrityCrcCheck))
    {
        return cpaDcCompressData(dcInstance,
                                 pSessionHandle,
                                 pSrcBuff,
                                 pDestBuff,
                                 pResults,
                                 pOpData->flushFlag,
                                 callbackTag);
    }

    if (CPA_FALSE == pOpData->compressAndVerify)
    {
        LAC_INVALID_PARAM_LOG(
            "Data compression without verification not allowed");
        return CPA_STATUS_UNSUPPORTED;
    }

#ifdef ICP_TRACE
    LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pOpData,
             (LAC_ARCH_UINT)pResults,
             (LAC_ARCH_UINT)callbackTag);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

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
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

    if (CPA_TRUE == pOpData->compressAndVerify &&
        CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        LAC_INVALID_PARAM_LOG("Invalid session state, stateful sessions "
                              "not supported with CNV");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (!(pService->generic_service_info.dcExtendedFeatures &
          DC_CNV_EXTENDED_CAPABILITY) &&
        (CPA_TRUE == pOpData->compressAndVerify))
    {
        LAC_INVALID_PARAM_LOG("CompressAndVerify feature not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_DC_LZ4 == pSessionDesc->compType &&
        CPA_TRUE == pOpData->integrityCrcCheck)
    {
        LAC_INVALID_PARAM_LOG("LZ4 with integrityCrcCheck is not supported"
                              " for compression direction requests");
        return CPA_STATUS_UNSUPPORTED;
    }

#ifdef ICP_PARAM_CHECK
    if (CPA_STATUS_SUCCESS != dcParamCheck(insHandle,
                                           pSessionHandle,
                                           pService,
                                           pSrcBuff,
                                           pDestBuff,
                                           pResults,
                                           pSessionDesc,
                                           pOpData->flushFlag,
                                           srcBuffSize))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#ifndef KERNEL_SPACE
    if (CPA_STATUS_SUCCESS != dcCheckOpData(pService, pOpData))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
#endif
#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions "
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
    if (CPA_TRUE != pOpData->compressAndVerify)
    {
        if (srcBuffSize > DC_COMP_MAX_BUFF_SIZE)
        {
            LAC_LOG_ERROR("Compression payload greater than 64KB is "
                          "unsupported, when CnV is disabled\n");
            return CPA_STATUS_UNSUPPORTED;
        }
    }

    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        /* Lock the session to check if there are in-flight stateful requests */
        LAC_SPINLOCK(&(pSessionDesc->sessionLock));

        /* Check if there is already one in-flight stateful request */
        if (0 != osalAtomicGet(&(pSessionDesc->pendingStatefulCbCount)))
        {
            LAC_LOG_ERROR("Only one in-flight stateful request supported");
            LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));
            return CPA_STATUS_RETRY;
        }

        if (0 == srcBuffSize)
        {
            if (CPA_TRUE == dcZeroLengthRequests(pService,
                                                 pSessionDesc,
                                                 pResults,
                                                 pOpData->flushFlag,
                                                 callbackTag,
                                                 DC_COMPRESSION_REQUEST))
            {
                return CPA_STATUS_SUCCESS;
            }
        }

        osalAtomicInc(&(pSessionDesc->pendingStatefulCbCount));
        LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));
    }

    if (CPA_TRUE == pOpData->compressAndVerifyAndRecover)
    {
        cnvMode = DC_CNVNR;
    }
    else if (CPA_TRUE == pOpData->compressAndVerify)
    {
        cnvMode = DC_CNV;
    }

    return dcCompDecompData(pService,
                            pSessionDesc,
                            dcInstance,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            pResults,
                            pOpData->flushFlag,
                            pOpData,
                            callbackTag,
                            DC_COMPRESSION_REQUEST,
                            CPA_TRUE,
                            cnvMode);
}

CpaStatus cpaDcDecompressData(CpaInstanceHandle dcInstance,
                              CpaDcSessionHandle pSessionHandle,
                              CpaBufferList *pSrcBuff,
                              CpaBufferList *pDestBuff,
                              CpaDcRqResults *pResults,
                              CpaDcFlush flushFlag,
                              void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;

#ifdef ICP_TRACE
    LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%x, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pResults,
             flushFlag,
             (LAC_ARCH_UINT)callbackTag);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

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
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);

    if (dcCheckSourceData(pSessionHandle,
                          pSrcBuff,
                          pDestBuff,
                          pResults,
                          flushFlag,
                          srcBuffSize,
                          NULL) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (dcCheckDestinationData(pService,
                               pSessionHandle,
                               pDestBuff,
                               DC_DECOMPRESSION_REQUEST) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    if (CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions "
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        /* Lock the session to check if there are in-flight stateful requests */
        LAC_SPINLOCK(&(pSessionDesc->sessionLock));

        /* Check if there is already one in-flight stateful request */
        if (0 != osalAtomicGet(&(pSessionDesc->pendingStatefulCbCount)))
        {
            LAC_LOG_ERROR("Only one in-flight stateful request supported");
            LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));
            return CPA_STATUS_RETRY;
        }

        if ((0 == srcBuffSize) ||
            ((1 == srcBuffSize) && (CPA_DC_FLUSH_FINAL != flushFlag) &&
             (CPA_DC_FLUSH_FULL != flushFlag) &&
             (!pService->generic_service_info.isGen4)))
        {
            if (CPA_TRUE == dcZeroLengthRequests(pService,
                                                 pSessionDesc,
                                                 pResults,
                                                 flushFlag,
                                                 callbackTag,
                                                 DC_DECOMPRESSION_REQUEST))
            {
                return CPA_STATUS_SUCCESS;
            }
        }

        osalAtomicInc(&(pSessionDesc->pendingStatefulCbCount));
        LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));
    }
    return dcCompDecompData(pService,
                            pSessionDesc,
                            dcInstance,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            pResults,
                            flushFlag,
                            NULL,
                            callbackTag,
                            DC_DECOMPRESSION_REQUEST,
                            CPA_TRUE,
                            DC_NO_CNV);
}

CpaStatus cpaDcDecompressData2(CpaInstanceHandle dcInstance,
                               CpaDcSessionHandle pSessionHandle,
                               CpaBufferList *pSrcBuff,
                               CpaBufferList *pDestBuff,
                               CpaDcOpData *pOpData,
                               CpaDcRqResults *pResults,
                               void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
#ifdef ICP_TRACE
    LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%x, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pResults,
             pOpData->flushFlag,
             (LAC_ARCH_UINT)callbackTag);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
    LAC_CHECK_NULL_PARAM(pOpData);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    /* This check is outside the parameter checking as it is needed to manage
     * zero length requests */
    if (CPA_STATUS_SUCCESS !=
        LacBuffDesc_BufferListVerifyNull(
            pSrcBuff, &srcBuffSize, LAC_NO_ALIGNMENT_SHIFT))
    {
        LAC_INVALID_PARAM_LOG("Invalid source buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

#ifdef ICP_PARAM_CHECK
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);

    if (CPA_STATUS_SUCCESS != dcCheckSourceData(pSessionHandle,
                                                pSrcBuff,
                                                pDestBuff,
                                                pResults,
                                                CPA_DC_FLUSH_NONE,
                                                srcBuffSize,
                                                NULL))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (CPA_STATUS_SUCCESS != dcCheckDestinationData(pService,
                                                     pSessionHandle,
                                                     pDestBuff,
                                                     DC_DECOMPRESSION_REQUEST))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_STATUS_SUCCESS != dcCheckOpData(pService, pOpData))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    if (CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions "
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        /* Lock the session to check if there are in-flight stateful requests */
        LAC_SPINLOCK(&(pSessionDesc->sessionLock));

        /* Check if there is already one in-flight stateful request */
        if (0 != osalAtomicGet(&(pSessionDesc->pendingStatefulCbCount)))
        {
            LAC_LOG_ERROR("Only one in-flight stateful request supported");
            LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));
            return CPA_STATUS_RETRY;
        }

        /* Gen 4 handle 0 len requests in FW */
        if (!pService->generic_service_info.isGen4)
        {
            if ((0 == srcBuffSize) ||
                ((1 == srcBuffSize) &&
                 (CPA_DC_FLUSH_FINAL != pOpData->flushFlag) &&
                 (CPA_DC_FLUSH_FULL != pOpData->flushFlag)))
            {
                if (CPA_TRUE == dcZeroLengthRequests(pService,
                                                     pSessionDesc,
                                                     pResults,
                                                     pOpData->flushFlag,
                                                     callbackTag,
                                                     DC_DECOMPRESSION_REQUEST))
                {
                    return CPA_STATUS_SUCCESS;
                }
            }
        }

        osalAtomicInc(&(pSessionDesc->pendingStatefulCbCount));
        LAC_SPINUNLOCK(&(pSessionDesc->sessionLock));
    }

    return dcCompDecompData(pService,
                            pSessionDesc,
                            insHandle,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            pResults,
                            pOpData->flushFlag,
                            pOpData,
                            callbackTag,
                            DC_DECOMPRESSION_REQUEST,
                            CPA_TRUE,
                            DC_NO_CNV);
}
