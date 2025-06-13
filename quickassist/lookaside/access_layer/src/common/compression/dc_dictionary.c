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
 * @file dc_dictionary.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of dictionary to compress a data buffer
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "dc_datapath.h"
#include "sal_service_state.h"
#include "lac_buffer_desc.h"

CpaStatus cpaDcCompressDataWithDict(CpaInstanceHandle dcInstance,
                                    CpaDcSessionHandle pSessionHandle,
                                    CpaBufferList *pSrcBuff,
                                    CpaBufferList *pDestBuff,
                                    CpaDcDictionaryData *pDictionaryData,
                                    CpaDcOpData *pOpData,
                                    CpaDcRqResults *pResults,
                                    void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
    dc_cnv_mode_t cnvMode = DC_NO_CNV;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG8("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pDictionaryData,
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

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    if (CPA_FALSE == pOpData->compressAndVerify)
    {
        LAC_UNSUPPORTED_PARAM_LOG(
            "Data compression without verification are not allowed");
        return CPA_STATUS_UNSUPPORTED;
    }

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

#ifdef ICP_PARAM_CHECK
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pService = (sal_compression_service_t *)insHandle;
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

    /* This check is outside the parameter checking as it is needed to manage
     * zero length requests. For dictionary compression there is an
     * expectation that a buffer list that includes metadata is supplied. */
    if (LacBuffDesc_BufferListVerifyNull(
            pSrcBuff, &srcBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
        CPA_STATUS_SUCCESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid source buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
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
    LAC_CHECK_NULL_PARAM(pOpData);
    if (CPA_STATUS_SUCCESS !=
        dcCheckOpData(pService, pOpData, pSessionDesc->sessDirection))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
#endif

    retStatus = dcCheckDictData(pDictionaryData, pService, pSessionDesc);
    if (CPA_STATUS_SUCCESS != retStatus)
    {
        return retStatus;
    }

    if (!(pService->dc_capabilities.cnv.supported) &&
        (CPA_TRUE == pOpData->compressAndVerify))
    {
        LAC_UNSUPPORTED_PARAM_LOG("CompressAndVerify feature is not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if ((CPA_TRUE == pOpData->compressAndVerifyAndRecover) &&
        (CPA_FALSE == pService->dc_capabilities.cnv.recovery))
    {
        LAC_UNSUPPORTED_PARAM_LOG("CompressAndVerifyAndRecover feature is not"
                                  " supported for dictionary requests");
        return CPA_STATUS_UNSUPPORTED;
    }

#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions are"
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (CPA_TRUE == pOpData->compressAndVerify)
    {
        cnvMode = DC_CNV;
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
                            DC_COMPRESSION_REQUEST,
                            CPA_TRUE,
                            cnvMode,
                            pDictionaryData);
}

CpaStatus cpaDcDecompressDataWithDict(CpaInstanceHandle dcInstance,
                                      CpaDcSessionHandle pSessionHandle,
                                      CpaBufferList *pSrcBuff,
                                      CpaBufferList *pDestBuff,
                                      CpaDcDictionaryData *pDictionaryData,
                                      CpaDcOpData *pOpData,
                                      CpaDcRqResults *pResults,
                                      void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG8("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%x, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pDictionaryData,
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

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    /* Ensure this is a compression or decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pOpData);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pService = (sal_compression_service_t *)insHandle;
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

    retStatus = dcCheckDictData(pDictionaryData, pService, pSessionDesc);
    if (CPA_STATUS_SUCCESS != retStatus)
    {
        return retStatus;
    }

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
    if (CPA_STATUS_SUCCESS != dcCheckSourceData(pService,
                                                pSessionHandle,
                                                pSrcBuff,
                                                pDestBuff,
                                                pResults,
                                                CPA_DC_FLUSH_NONE,
                                                srcBuffSize,
                                                NULL))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (CPA_STATUS_SUCCESS !=
        dcCheckDestinationData(
            pService, pSessionHandle, pDestBuff, DC_DECOMPRESSION_REQUEST))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_STATUS_SUCCESS !=
        dcCheckOpData(pService, pOpData, pSessionDesc->sessDirection))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

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
                              "are not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

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
                            DC_NO_CNV,
                            pDictionaryData);
}
