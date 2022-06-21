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
 * @file dc_dp.c
 *
 * @defgroup cpaDcDp Data Compression Data Plane API
 *
 * @ingroup cpaDcDp
 *
 * @description
 *      Implementation of the Data Compression DP operations.
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

#include "icp_qat_fw_comp.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "dc_session.h"
#include "dc_datapath.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_log.h"
#include "sal_types_compression.h"
#include "lac_sal.h"
#include "lac_sync.h"
#include "sal_service_state.h"
#include "sal_qat_cmn_msg.h"
#include "icp_sal_poll.h"

#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup cpaDcDp
 *      Check that pOpData is valid
 *
 * @description
 *      Check that all the parameters defined in the pOpData are valid
 *
 * @param[in]       pOpData          Pointer to a structure containing the
 *                                   request parameters
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus dcDataPlaneParamCheck(const CpaDcDpOpData *pOpData)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;

    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pOpData->dcInstance);
    LAC_CHECK_NULL_PARAM(pOpData->pSessionHandle);

    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(pOpData->dcInstance, SAL_SERVICE_TYPE_COMPRESSION);

    pService = (sal_compression_service_t *)(pOpData->dcInstance);

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pOpData->pSessionHandle);
    if (NULL == pSessionDesc)
    {
        LAC_INVALID_PARAM_LOG("Session handle not as expected");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_FALSE == pSessionDesc->isDcDp)
    {
        LAC_INVALID_PARAM_LOG("The session type should be data plane");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Compressing zero byte is not supported */
    if ((CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection) &&
        (0 == pOpData->bufferLenToCompress))
    {
        LAC_INVALID_PARAM_LOG("The source buffer length to compress needs to "
                              "be greater than zero byte");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pOpData->sessDirection > CPA_DC_DIR_DECOMPRESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid direction of operation");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (0 == pOpData->srcBuffer)
    {
        LAC_INVALID_PARAM_LOG("Invalid srcBuffer");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (0 == pOpData->destBuffer)
    {
        LAC_INVALID_PARAM_LOG("Invalid destBuffer");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (pOpData->srcBuffer == pOpData->destBuffer)
    {
        LAC_INVALID_PARAM_LOG("In place operation is not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (0 == pOpData->thisPhys)
    {
        LAC_INVALID_PARAM_LOG("Invalid thisPhys");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((CPA_TRUE != pOpData->compressAndVerify) &&
        (CPA_FALSE != pOpData->compressAndVerify))
    {
        LAC_INVALID_PARAM_LOG("Invalid compressAndVerify");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((CPA_TRUE == pOpData->compressAndVerify) &&
        !(pService->generic_service_info.dcExtendedFeatures &
          DC_CNV_EXTENDED_CAPABILITY))
    {
        LAC_UNSUPPORTED_PARAM_LOG(
            "CompressAndVerify not set, no CNV capability");
        return CPA_STATUS_UNSUPPORTED;
    }
    if ((CPA_TRUE != pOpData->compressAndVerifyAndRecover) &&
        (CPA_FALSE != pOpData->compressAndVerifyAndRecover))
    {
        LAC_INVALID_PARAM_LOG("Invalid compressAndVerifyAndRecover");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((CPA_TRUE == pOpData->compressAndVerifyAndRecover) &&
        (CPA_FALSE == pOpData->compressAndVerify))
    {
        LAC_INVALID_PARAM_LOG("CnVnR option set, without setting CnV");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((CPA_TRUE == pOpData->compressAndVerifyAndRecover) &&
        !(pService->generic_service_info.dcExtendedFeatures &
          DC_CNVNR_EXTENDED_CAPABILITY))
    {
        LAC_UNSUPPORTED_PARAM_LOG("CnVnR not set, no CnVnR capability");
        return CPA_STATUS_UNSUPPORTED;
    }
    if ((CPA_DP_BUFLIST == pOpData->srcBufferLen) &&
        (CPA_DP_BUFLIST != pOpData->destBufferLen))
    {
        LAC_INVALID_PARAM_LOG(
            "The source and destination buffers need to be "
            "of the same type (both flat buffers or buffer lists)");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((CPA_DP_BUFLIST != pOpData->srcBufferLen) &&
        (CPA_DP_BUFLIST == pOpData->destBufferLen))
    {
        LAC_INVALID_PARAM_LOG(
            "The source and destination buffers need to be "
            "of the same type (both flat buffers or buffer lists)");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DP_BUFLIST != pOpData->srcBufferLen)
    {
        if (pOpData->srcBufferLen < pOpData->bufferLenToCompress)
        {
            LAC_INVALID_PARAM_LOG("srcBufferLen is smaller than "
                                  "bufferLenToCompress");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (pOpData->destBufferLen < pOpData->bufferLenForData)
        {
            LAC_INVALID_PARAM_LOG("destBufferLen is smaller than "
                                  "bufferLenForData");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        /* We are assuming that there is enough memory in the source and
         * destination buffer lists. We only receive physical addresses of the
         * buffers so we are unable to test it here */
        LAC_CHECK_8_BYTE_ALIGNMENT(pOpData->srcBuffer);
        LAC_CHECK_8_BYTE_ALIGNMENT(pOpData->destBuffer);
    }

    LAC_CHECK_8_BYTE_ALIGNMENT(pOpData->thisPhys);

    if ((CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection) ||
        (CPA_DC_DIR_COMBINED == pSessionDesc->sessDirection))
    {
#ifndef ICP_DC_DYN_NOT_SUPPORTED
        if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
        {
            /* Check if Intermediate Buffer Array pointer is NULL */
            if ((!pService->generic_service_info.isGen4) &&
                ((0 == pService->pInterBuffPtrsArrayPhyAddr) ||
                 (NULL == pService->pInterBuffPtrsArray)))
            {
                LAC_LOG_ERROR(
                    "No intermediate buffer defined for this instance "
                    "- see cpaDcStartInstance");
                return CPA_STATUS_INVALID_PARAM;
            }

            /* Ensure that the destination buffer length for data is greater
             * or equal to 128B */
            if (pOpData->bufferLenForData < DC_DEST_BUFFER_DYN_MIN_SIZE)
            {
                LAC_INVALID_PARAM_LOG("Destination buffer length for data "
                                      "should be greater or equal to 128B");
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
            /* Ensure that the destination buffer length for data is greater
             * or equal to min output buffsize */
            if (pOpData->bufferLenForData <
                pService->comp_device_data.minOutputBuffSize)
            {
                LAC_INVALID_PARAM_LOG1(
                    "Destination buffer size should be "
                    "greater or equal to %d bytes",
                    pService->comp_device_data.minOutputBuffSize);
                return CPA_STATUS_INVALID_PARAM;
            }
        }
    }

    return CPA_STATUS_SUCCESS;
}
#endif

CpaStatus cpaDcDpGetSessionSize(CpaInstanceHandle dcInstance,
                                CpaDcSessionSetupData *pSessionData,
                                Cpa32U *pSessionSize)
{
#ifdef ICP_TRACE
    CpaStatus status = CPA_STATUS_SUCCESS;
    status = dcGetSessionSize(dcInstance, pSessionData, pSessionSize, NULL);

    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionData,
             (LAC_ARCH_UINT)pSessionSize,
             *pSessionSize);

    return status;
#else
    return dcGetSessionSize(dcInstance, pSessionData, pSessionSize, NULL);
#endif
}

CpaStatus cpaDcDpInitSession(CpaInstanceHandle dcInstance,
                             CpaDcSessionHandle pSessionHandle,
                             CpaDcSessionSetupData *pSessionData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    dc_session_desc_t *pSessionDesc = NULL;
    sal_compression_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSessionData);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(dcInstance);
    SAL_CHECK_ADDR_TRANS_SETUP(dcInstance);
    SAL_CHECK_INSTANCE_TYPE(dcInstance, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pService = (sal_compression_service_t *)dcInstance;

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(pService);

#ifdef ICP_PARAM_CHECK
    /* Stateful is not supported */
    if (CPA_DC_STATELESS != pSessionData->sessState)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessState value");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    status =
        dcInitSession(dcInstance, pSessionHandle, pSessionData, NULL, NULL);
    if (CPA_STATUS_SUCCESS == status)
    {
        pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
        pSessionDesc->isDcDp = CPA_TRUE;

        ICP_QAT_FW_COMN_PTR_TYPE_SET(
            pSessionDesc->reqCacheDecomp.comn_hdr.comn_req_flags,
            DC_DP_QAT_PTR_TYPE);
        ICP_QAT_FW_COMN_PTR_TYPE_SET(
            pSessionDesc->reqCacheComp.comn_hdr.comn_req_flags,
            DC_DP_QAT_PTR_TYPE);
    }

    return status;
}

CpaStatus cpaDcDpRemoveSession(const CpaInstanceHandle dcInstance,
                               CpaDcSessionHandle pSessionHandle)
{
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle);
#endif
    return cpaDcRemoveSession(dcInstance, pSessionHandle);
}

CpaStatus cpaDcDpUpdateSession(const CpaInstanceHandle dcInstance,
                               CpaDcSessionHandle pSessionHandle,
                               CpaDcSessionUpdateData *pUpdateSessionData)
{
    return cpaDcUpdateSession(dcInstance, pSessionHandle, pUpdateSessionData);
}

CpaStatus cpaDcDpRegCbFunc(const CpaInstanceHandle dcInstance,
                           const CpaDcDpCallbackFn pNewCb)
{
    sal_compression_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pNewCb);
#endif

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(dcInstance);
    SAL_CHECK_INSTANCE_TYPE(dcInstance, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_NULL_PARAM(pNewCb);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(dcInstance);

    pService = (sal_compression_service_t *)dcInstance;
    pService->pDcDpCb = pNewCb;

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup cpaDcDp
 *
 * @description
 *      Writes the message to the ring
 *
 * @param[in]       pOpData          Pointer to a structure containing the
 *                                   request parameters
 * @param[in]       pCurrentQatMsg   Pointer to current QAT message on the ring
 *
 *****************************************************************************/
STATIC void dcDpWriteRingMsg(CpaDcDpOpData *pOpData,
                             icp_qat_fw_comp_req_t *pCurrentQatMsg)
{
    icp_qat_fw_comp_req_t *pReqCache = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    Cpa8U bufferFormat;
    Cpa8U cnv = ICP_QAT_FW_COMP_NO_CNV;
    Cpa8U cnvnr = ICP_QAT_FW_COMP_NO_CNV_RECOVERY;
    CpaBoolean cnvErrorInjection = ICP_QAT_FW_COMP_NO_CNV_DFX;
    sal_compression_service_t *pService = NULL;

    pService = (sal_compression_service_t *)(pOpData->dcInstance);
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pOpData->pSessionHandle);

    if (CPA_DC_DIR_COMPRESS == pOpData->sessDirection)
    {
        pReqCache = &(pSessionDesc->reqCacheComp);
        /* CNV check */
        if (CPA_TRUE == pOpData->compressAndVerify)
        {
            cnv = ICP_QAT_FW_COMP_CNV;
            if (pService->generic_service_info.isGen4)
            {
                cnvErrorInjection = pSessionDesc->cnvErrorInjection;
            }

            /* CNVNR check */
            if (CPA_TRUE == pOpData->compressAndVerifyAndRecover)
            {
                cnvnr = ICP_QAT_FW_COMP_CNV_RECOVERY;
            }
        }
    }
    else
    {
        pReqCache = &(pSessionDesc->reqCacheDecomp);
    }

    /* Fills in the template DC ET ring message - cached from the
     * session descriptor */
    osalMemCopy((void *)pCurrentQatMsg,
                (void *)(pReqCache),
                (LAC_QAT_DC_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES));

    if (CPA_DP_BUFLIST == pOpData->srcBufferLen)
    {
        bufferFormat = QAT_COMN_PTR_TYPE_SGL;
    }
    else
    {
        bufferFormat = QAT_COMN_PTR_TYPE_FLAT;
    }

    pCurrentQatMsg->comp_pars.req_par_flags |=
        ICP_QAT_FW_COMP_REQ_PARAM_FLAGS_BUILD(ICP_QAT_FW_COMP_NOT_SOP,
                                              ICP_QAT_FW_COMP_NOT_EOP,
                                              ICP_QAT_FW_COMP_NOT_BFINAL,
                                              cnv,
                                              cnvnr,
                                              cnvErrorInjection,
                                              ICP_QAT_FW_COMP_CRC_MODE_LEGACY);

    SalQatMsg_CmnMidWrite((icp_qat_fw_la_bulk_req_t *)pCurrentQatMsg,
                          pOpData,
                          bufferFormat,
                          pOpData->srcBuffer,
                          pOpData->destBuffer,
                          pOpData->srcBufferLen,
                          pOpData->destBufferLen);

    pCurrentQatMsg->comp_pars.comp_len = pOpData->bufferLenToCompress;
    pCurrentQatMsg->comp_pars.out_buffer_sz = pOpData->bufferLenForData;
}

CpaStatus cpaDcDpEnqueueOp(CpaDcDpOpData *pOpData,
                           const CpaBoolean performOpNow)
{
    icp_qat_fw_comp_req_t *pCurrentQatMsg = NULL;
    icp_comms_trans_handle trans_handle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
#ifdef ICP_PARAM_CHECK
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = dcDataPlaneParamCheck(pOpData);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
#endif

    if ((CPA_FALSE == pOpData->compressAndVerify) &&
        (CPA_DC_DIR_COMPRESS == pOpData->sessDirection))
    {
        return CPA_STATUS_UNSUPPORTED;
    }

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, %d)\n",
             (LAC_ARCH_UINT)pOpData,
             performOpNow);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(pOpData->dcInstance);

    trans_handle = ((sal_compression_service_t *)pOpData->dcInstance)
                       ->trans_handle_compression_tx;
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pOpData->pSessionHandle);

#ifdef ICP_PARAM_CHECK
    if ((CPA_DC_DIR_COMPRESS == pOpData->sessDirection) &&
        (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection))
    {
        LAC_INVALID_PARAM_LOG("The session does not support this direction of "
                              "operation");
        return CPA_STATUS_INVALID_PARAM;
    }
    else if ((CPA_DC_DIR_DECOMPRESS == pOpData->sessDirection) &&
             (CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection))
    {
        LAC_INVALID_PARAM_LOG("The session does not support this direction of"
                              " operation");
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

    icp_adf_getSingleQueueAddr(trans_handle, (void **)&pCurrentQatMsg);
    if (NULL == pCurrentQatMsg)
    {
        return CPA_STATUS_RETRY;
    }

    dcDpWriteRingMsg(pOpData, pCurrentQatMsg);

    pSessionDesc->pendingDpStatelessCbCount++;

    if (CPA_TRUE == performOpNow)
    {
        icp_adf_updateQueueTail(trans_handle);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcDpEnqueueOpBatch(const Cpa32U numberRequests,
                                CpaDcDpOpData *pOpData[],
                                const CpaBoolean performOpNow)
{
    icp_qat_fw_comp_req_t *pCurrentQatMsg = NULL;
    icp_comms_trans_handle trans_handle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    Cpa32U i = 0;
#ifdef ICP_PARAM_CHECK
    CpaStatus status = CPA_STATUS_SUCCESS;

    sal_compression_service_t *pService = NULL;

    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pOpData[0]);
    LAC_CHECK_NULL_PARAM(pOpData[0]->dcInstance);

    pService = (sal_compression_service_t *)(pOpData[0]->dcInstance);
    if ((numberRequests == 0) ||
        (numberRequests > pService->maxNumCompConcurrentReq))
    {
        LAC_INVALID_PARAM_LOG1("The number of requests needs to be between 1 "
                               "and %d",
                               pService->maxNumCompConcurrentReq);
        return CPA_STATUS_INVALID_PARAM;
    }

    for (i = 0; i < numberRequests; i++)
    {
        status = dcDataPlaneParamCheck(pOpData[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }

        /* Check that all instance handles and session handles are the same */
        if (pOpData[i]->dcInstance != pOpData[0]->dcInstance)
        {
            LAC_INVALID_PARAM_LOG("All instance handles should be the same "
                                  "in the pOpData");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (pOpData[i]->pSessionHandle != pOpData[0]->pSessionHandle)
        {
            LAC_INVALID_PARAM_LOG("All session handles should be the same "
                                  "in the pOpData");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (%d, 0x%lx, %d)\n",
             numberRequests,
             (LAC_ARCH_UINT)pOpData,
             performOpNow);
#endif

    for (i = 0; i < numberRequests; i++)
    {
        if ((CPA_FALSE == pOpData[i]->compressAndVerify) &&
            (CPA_DC_DIR_COMPRESS == pOpData[i]->sessDirection))
        {
            return CPA_STATUS_UNSUPPORTED;
        }
    }

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(pOpData[0]->dcInstance);

    trans_handle = ((sal_compression_service_t *)pOpData[0]->dcInstance)
                       ->trans_handle_compression_tx;

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pOpData[0]->pSessionHandle);

#ifdef ICP_PARAM_CHECK
    for (i = 0; i < numberRequests; i++)
    {
        if ((CPA_DC_DIR_COMPRESS == pOpData[i]->sessDirection) &&
            (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection))
        {
            LAC_INVALID_PARAM_LOG("The session does not support this "
                                  "direction of operation");
            return CPA_STATUS_INVALID_PARAM;
        }
        else if ((CPA_DC_DIR_DECOMPRESS == pOpData[i]->sessDirection) &&
                 (CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection))
        {
            LAC_INVALID_PARAM_LOG("The session does not support this "
                                  "direction of operation");
            return CPA_STATUS_INVALID_PARAM;
        }
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

    icp_adf_getQueueMemory(
        trans_handle, numberRequests, (void **)&pCurrentQatMsg);
    if (NULL == pCurrentQatMsg)
    {
        return CPA_STATUS_RETRY;
    }

    for (i = 0; i < numberRequests; i++)
    {
        dcDpWriteRingMsg(pOpData[i], pCurrentQatMsg);
        icp_adf_getQueueNext(trans_handle, (void **)&pCurrentQatMsg);
    }

    pSessionDesc->pendingDpStatelessCbCount += numberRequests;

    if (CPA_TRUE == performOpNow)
    {
        icp_adf_updateQueueTail(trans_handle);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_sal_DcPollDpInstance(CpaInstanceHandle dcInstance,
                                   Cpa32U responseQuota)
{
    icp_comms_trans_handle trans_handle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, %d)\n",
             (LAC_ARCH_UINT)dcInstance,
             responseQuota);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(dcInstance);
    SAL_CHECK_INSTANCE_TYPE(dcInstance, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(dcInstance);

    trans_handle =
        ((sal_compression_service_t *)dcInstance)->trans_handle_compression_rx;

    return icp_adf_pollQueue(trans_handle, responseQuota);
}

CpaStatus cpaDcDpPerformOpNow(CpaInstanceHandle dcInstance)
{
    icp_comms_trans_handle trans_handle = NULL;

#ifdef ICP_TRACE
    LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)dcInstance);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(dcInstance);
    SAL_CHECK_INSTANCE_TYPE(dcInstance, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(dcInstance);

    trans_handle =
        ((sal_compression_service_t *)dcInstance)->trans_handle_compression_tx;

    if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
    {
        icp_adf_updateQueueTail(trans_handle);
    }

    return CPA_STATUS_SUCCESS;
}
