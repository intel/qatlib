/******************************************************************************
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

/**
 ***************************************************************************
 * @file lac_sym_cb.c      Callback handler functions for symmetric components
 *
 * @ingroup LacSym
 *
 ***************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_sym.h"

#include "Osal.h"
#include "icp_accel_devices.h"
#include "icp_adf_init.h"
#include "icp_qat_fw_la.h"
#include "icp_adf_transport.h"
#include "icp_adf_debug.h"

#include "lac_sym.h"
#include "lac_sym_cipher.h"
#include "lac_common.h"
#include "lac_list.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "lac_session.h"
#include "lac_sym_stats.h"
#include "lac_log.h"
#include "lac_sym_cb.h"
#include "lac_sym_hash.h"
#include "lac_sym_qat_cipher.h"
#include "lac_sym_qat.h"

#define DEQUEUE_MSGPUT_MAX_RETRIES 10000

/*
*******************************************************************************
* Define static function definitions
*******************************************************************************
*/

/**
 *****************************************************************************
 * @ingroup LacSymCb
 *      Function to clean computed data.
 *
 * @description
 *      This function cleans GCM or CCM data in the case of a failure.
 *
 * @param[in]  pSessionDesc pointer to the session descriptor
 * @param[out] pBufferList  pointer to the bufferlist to clean
 * @param[in]  pOpData      pointer to operation data
 * @param[in]  isCCM        is it a CCM operation boolean
 *
 * @return  None
 *****************************************************************************/
STATIC void LacSymCb_CleanUserData(const lac_session_desc_t *pSessionDesc,
                                   CpaBufferList *pBufferList,
                                   const CpaCySymOpData *pOpData,
                                   CpaBoolean isCCM)
{
    Cpa32U authTagLen = 0;

    /* Retrieve authTagLen */
    authTagLen = pSessionDesc->hashResultSize;

    /* Cleaning */
    if (isCCM)
    {
        /* for CCM the digest is inside the buffer list */
        LacBuffDesc_BufferListZeroFromOffset(
            pBufferList,
            pOpData->cryptoStartSrcOffsetInBytes,
            pOpData->messageLenToCipherInBytes + authTagLen);
    }
    else
    {
        /* clean buffer list */
        LacBuffDesc_BufferListZeroFromOffset(
            pBufferList,
            pOpData->cryptoStartSrcOffsetInBytes,
            pOpData->messageLenToCipherInBytes);
    }
    if ((CPA_TRUE != pSessionDesc->digestIsAppended) &&
        (NULL != pOpData->pDigestResult))
    {
        /* clean digest */
        osalMemSet(pOpData->pDigestResult, 0, authTagLen);
    }
}

/**
 *****************************************************************************
 * @ingroup LacSymCb
 *      Definition of callback function for processing symmetric responses
 *
 * @description
 *      This callback is invoked to process symmetric response messages from
 *      the QAT.  It will extract some details from the message and invoke
 *      the user's callback to complete a symmetric operation.
 *
 * @param[in] pCookie             Pointer to cookie associated with this request
 * @param[in] qatRespStatusOkFlag Boolean indicating ok/fail status from QAT
 * @param[in] status              Status variable indicating an error occurred
 *                                in sending the message (e.g. when dequeueing)
 * @param[in] pSessionDesc        Session descriptor
 *
 * @return  None
 *****************************************************************************/
STATIC void LacSymCb_ProcessCallbackInternal(lac_sym_bulk_cookie_t *pCookie,
                                             CpaBoolean qatRespStatusOkFlag,
                                             CpaStatus status,
                                             lac_session_desc_t *pSessionDesc)
{
    CpaCySymCbFunc pSymCb = NULL;
    void *pCallbackTag = NULL;
    CpaCySymOpData *pOpData = NULL;
    CpaBufferList *pDstBuffer = NULL;
    CpaCySymOp operationType = CPA_CY_SYM_OP_NONE;
    CpaStatus dequeueStatus = CPA_STATUS_SUCCESS;

#ifndef DISABLE_STATS
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    /* NOTE: cookie pointer validated in previous function */
    instanceHandle = pCookie->instanceHandle;
    LAC_ENSURE(instanceHandle != NULL,
               "LacSymCb_ProcessCallbackInternal - instanceHandle NULL\n");
#endif

    pOpData = (CpaCySymOpData *)LAC_CONST_PTR_CAST(pCookie->pOpData);
    operationType = pSessionDesc->symOperation;

    /* Set the destination pointer to the one supplied in the cookie. */
    pDstBuffer = pCookie->pDstBuffer;

    /* For a digest verify operation - for full packet and final partial
     * only, perform a comparison with the digest generated and with the one
     * supplied in the packet. In case of AES_GCM in SPC mode, destination
     * buffer needs to be cleared if digest verify operation fails */

    if (((SPC_YES == pSessionDesc->singlePassState) ||
         (CPA_CY_SYM_OP_CIPHER != operationType)) &&
        (CPA_TRUE == pSessionDesc->digestVerify) &&
        ((CPA_CY_SYM_PACKET_TYPE_FULL == pOpData->packetType) ||
         (CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL == pOpData->packetType)))
    {
        if (CPA_FALSE == qatRespStatusOkFlag)
        {
            LAC_SYM_STAT_INC(numSymOpVerifyFailures, instanceHandle);

            /* The comparison has failed at this point (status is fail),
             * need to clean any sensitive calculated data up to this point.
             * The data calculated is no longer useful to the end result and
             * does not need to be returned to the user so setting buffers to
             * zero.
             */
            if (pSessionDesc->cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CCM)
            {
                LacSymCb_CleanUserData(
                    pSessionDesc, pDstBuffer, pOpData, CPA_TRUE);
            }
            else if (pSessionDesc->cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_GCM)
            {
                LacSymCb_CleanUserData(
                    pSessionDesc, pDstBuffer, pOpData, CPA_FALSE);
            }
        }
    }
    else
    {
        /* Most commands have no point of failure and always return
         * success. This is the default response from the QAT.
         * If status is already set to an error value, don't overwrite it
         */
        if ((CPA_STATUS_SUCCESS == status) && (CPA_TRUE != qatRespStatusOkFlag))
        {
            LAC_LOG_ERROR("Response status value not as expected");
            status = CPA_STATUS_FAIL;
        }
    }

    pSymCb = pSessionDesc->pSymCb;
    pCallbackTag = pCookie->pCallbackTag;

    /* State returned to the client for intermediate partials packets
     * for hash only and cipher only partial packets. Cipher update
     * allow next partial through */
    if (CPA_CY_SYM_PACKET_TYPE_PARTIAL == pOpData->packetType)
    {
        if ((CPA_CY_SYM_OP_CIPHER == operationType) ||
            (CPA_CY_SYM_OP_ALGORITHM_CHAINING == operationType))
        {
            if (CPA_TRUE == pCookie->updateUserIvOnRecieve)
            {
                /* Update the user's IV buffer
                 * Very important to do this BEFORE dequeuing
                 * subsequent partial requests, as the state buffer
                 * may get overwritten
                 */
                memcpy(pCookie->pOpData->pIv,
                       pSessionDesc->cipherPartialOpState,
                       pCookie->pOpData->ivLenInBytes);
            }
            if (CPA_TRUE == pCookie->updateKeySizeOnRecieve &&
                LAC_CIPHER_IS_XTS_MODE(pSessionDesc->cipherAlgorithm))
            {
                LacSymQat_CipherXTSModeUpdateKeyLen(
                    pSessionDesc, pSessionDesc->cipherKeyLenInBytes / 2);
            }
        }
    }
    else if (CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL == pOpData->packetType)
    {
        if ((CPA_CY_SYM_OP_CIPHER == operationType) ||
            (CPA_CY_SYM_OP_ALGORITHM_CHAINING == operationType))
        {
            if (CPA_TRUE ==
                LAC_CIPHER_IS_XTS_MODE(pSessionDesc->cipherAlgorithm))
            {
                /*
                 * For XTS mode, we replace the updated key with
                 * the original key - for subsequent partial requests
                 *
                 */
                LacSymQat_CipherXTSModeUpdateKeyLen(
                    pSessionDesc, pSessionDesc->cipherKeyLenInBytes);
            }
        }
    }

    if ((CPA_CY_SYM_PACKET_TYPE_FULL != pOpData->packetType) &&
        (qatRespStatusOkFlag != CPA_FALSE))
    {
        /* There may be requests blocked pending the completion of this
         * operation
         */

        dequeueStatus = LacSymCb_PendingReqsDequeue(pSessionDesc);
        if (CPA_STATUS_SUCCESS != dequeueStatus)
        {
            LAC_SYM_STAT_INC(numSymOpCompletedErrors, instanceHandle);
            qatRespStatusOkFlag = CPA_FALSE;
            if (CPA_STATUS_SUCCESS == status)
            {
                status = dequeueStatus;
            }
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* update stats */
        if (pSessionDesc->internalSession == CPA_FALSE)
        {
            LAC_SYM_STAT_INC(numSymOpCompleted, instanceHandle);
            if (CPA_STATUS_SUCCESS != status)
            {
                LAC_SYM_STAT_INC(numSymOpCompletedErrors, instanceHandle);
            }
        }
    }

    /* deallocate the memory for the internal callback cookie */
    Lac_MemPoolEntryFree(pCookie);

    /* user callback function is the last thing to be called */

    LAC_ASSERT_NOT_NULL(pSymCb);

    pSymCb(pCallbackTag,
           status,
           operationType,
           pOpData,
           pDstBuffer,
           qatRespStatusOkFlag);

    osalAtomicDec(&(pSessionDesc->u.pendingCbCount));
}

/**
 ******************************************************************************
 * @ingroup LacSymCb
 *      Definition of callback function for processing symmetric Data Plane
 *       responses
 *
 * @description
 *      This callback checks the status, decrements the number of operations
 *      pending and calls the user callback
 *
 * @param[in/out] pResponse          pointer to the response structure
 * @param[in] qatRespStatusOkFlag    status
 * @param[in] pSessionDesc           pointer to the session descriptor
 *
 * @return  None
 ******************************************************************************/
STATIC void LacSymCb_ProcessDpCallback(CpaCySymDpOpData *pResponse,
                                       CpaBoolean qatRespStatusOkFlag,
                                       CpaStatus status,
                                       lac_session_desc_t *pSessionDesc)
{
    CpaCySymDpCbFunc pSymDpCb = NULL;

    /* For CCM and GCM, if qatRespStatusOkFlag is false, the data has to be
     * cleaned as stated in RFC 3610; in DP mode, it is the user responsability
     * to do so */

    if (((CPA_CY_SYM_OP_CIPHER == pSessionDesc->symOperation &&
          (SPC_NO == pSessionDesc->singlePassState)) ||
         (CPA_FALSE == pSessionDesc->digestVerify)))
    {
        /* If not doing digest compare and qatRespStatusOkFlag != CPA_TRUE
           then there is something very wrong */
        if ((CPA_FALSE == qatRespStatusOkFlag) &&
            (status != CPA_STATUS_UNSUPPORTED))
        {
            LAC_LOG_ERROR("Response status value not as expected");
            status = CPA_STATUS_FAIL;
        }
    }

    pSymDpCb = ((sal_crypto_service_t *)pResponse->instanceHandle)->pSymDpCb;

    LAC_ASSERT_NOT_NULL(pSymDpCb);

    pSymDpCb(pResponse, status, qatRespStatusOkFlag);

    /*
     * Decrement the number of pending CB.
     *
     * If the @pendingDpCbCount becomes zero, we may remove the session, please
     * read more information in the cpaCySymRemoveSession().
     *
     * But there is a field in the @pResponse to store the session,
     * the "sessionCtx". In another word, in the above @->pSymDpCb() callback,
     * it may use the session again. If we decrease the @pendingDpCbCount before
     * the @->pSymDpCb(), there is a _risk_ the @->pSymDpCb() may reference to
     * a deleted session.
     *
     * So in order to avoid the risk, we decrease the @pendingDpCbCount after
     * the @->pSymDpCb() callback.
     */
    --pSessionDesc->u.pendingDpCbCount;
}

/**
 ******************************************************************************
 * @ingroup LacSymCb
 *      Definition of callback function for processing symmetric responses
 *
 * @description
 *      This callback, which is registered with the common symmetric response
 *      message handler,  is invoked to process symmetric response messages from
 *      the QAT.  It will extract the response status from the cmnRespFlags set
 *      by the QAT, and then will pass it to @ref
 *      LacSymCb_ProcessCallbackInternal to complete the response processing.
 *
 * @param[in] lacCmdId          ID of the symmetric QAT command of the request
 *                              message
 * @param[in] pOpaqueData       pointer to opaque data in the request message
 * @param[in] cmnRespFlags      Flags set by QAT to indicate response status
 *
 * @return  None
 ******************************************************************************/
STATIC void LacSymCb_ProcessCallback(icp_qat_fw_la_cmd_id_t lacCmdId,
                                     void *pOpaqueData,
                                     icp_qat_fw_comn_flags cmnRespFlags)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymDpOpData *pDpOpData = (CpaCySymDpOpData *)pOpaqueData;
    lac_session_desc_t *pSessionDesc =
        LAC_SYM_SESSION_DESC_FROM_CTX_GET(pDpOpData->sessionCtx);
    CpaBoolean qatRespStatusOkFlag =
        (CpaBoolean)(ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                     ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(cmnRespFlags));

    if (CPA_TRUE == pSessionDesc->isDPSession)
    {
        /* DP session */
        if (ICP_QAT_FW_COMN_RESP_UNSUPPORTED_REQUEST_STAT_GET(cmnRespFlags))
        {
            status = CPA_STATUS_UNSUPPORTED;
        }
        LacSymCb_ProcessDpCallback(
            pDpOpData, qatRespStatusOkFlag, status, pSessionDesc);
    }
    else
    {
        /* Trad session */
        LacSymCb_ProcessCallbackInternal((lac_sym_bulk_cookie_t *)pOpaqueData,
                                         qatRespStatusOkFlag,
                                         CPA_STATUS_SUCCESS,
                                         pSessionDesc);
    }
}

/*
*******************************************************************************
* Define public/global function definitions
*******************************************************************************
*/

/**
 * @ingroup LacSymCb
 *
 * @return CpaStatus
 *      value returned will be the result of icp_adf_transPutMsg
 */
CpaStatus LacSymCb_PendingReqsDequeue(lac_session_desc_t *pSessionDesc)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pService = NULL;
    Cpa32U retries = 0;

    LAC_ENSURE(pSessionDesc != NULL,
               "LacSymCb_PendingReqsDequeue - pSessionDesc NULL\n");

    pService = (sal_crypto_service_t *)pSessionDesc->pInstance;

    /* Need to protect access to queue head and tail pointers, which may
     * be accessed by multiple contexts simultaneously for enqueue and
     * dequeue operations
     */
    LAC_SPINLOCK(&pSessionDesc->requestQueueLock);

    /* Clear the blocking flag in the session descriptor */
    pSessionDesc->nonBlockingOpsInProgress = CPA_TRUE;

    while ((NULL != pSessionDesc->pRequestQueueHead) &&
           (CPA_TRUE == pSessionDesc->nonBlockingOpsInProgress))
    {

        /* If we send a partial packet request, set the blockingOpsInProgress
         * flag for the session to indicate that subsequent requests must be
         * queued up until this request completes
         */
        if (CPA_CY_SYM_PACKET_TYPE_FULL !=
            pSessionDesc->pRequestQueueHead->pOpData->packetType)
        {
            pSessionDesc->nonBlockingOpsInProgress = CPA_FALSE;
        }

        /* At this point, we're clear to send the request.  For cipher requests,
         * we need to check if the session IV needs to be updated.  This can
         * only be done when no other partials are in flight for this session,
         * to ensure the cipherPartialOpState buffer in the session descriptor
         * is not currently in use
         */
        if (CPA_TRUE == pSessionDesc->pRequestQueueHead->updateSessionIvOnSend)
        {
            if (LAC_CIPHER_IS_ARC4(pSessionDesc->cipherAlgorithm))
            {
                memcpy(pSessionDesc->cipherPartialOpState,
                       pSessionDesc->cipherARC4InitialState,
                       LAC_CIPHER_ARC4_STATE_LEN_BYTES);
            }
            else
            {
                memcpy(pSessionDesc->cipherPartialOpState,
                       pSessionDesc->pRequestQueueHead->pOpData->pIv,
                       pSessionDesc->pRequestQueueHead->pOpData->ivLenInBytes);
            }
        }

        /*
         * Now we'll attempt to send the message directly to QAT. We'll keep
         * looing until it succeeds (or at least a very high number of retries),
         * as the failure only happens when the ring is full, and this is only
         * a temporary situation. After a few retries, space will become
         * availble, allowing the putMsg to succeed.
         */
        retries = 0;
        do
        {
            /* Send directly to QAT */
            status = icp_adf_transPutMsg(
                pService->trans_handle_sym_tx,
                (void *)&(pSessionDesc->pRequestQueueHead->qatMsg),
                LAC_QAT_SYM_REQ_SZ_LW,
                NULL);

            retries++;
            /*
             * Yield to allow other threads that may be on this session to poll
             * and make some space on the ring
             */
            if (CPA_STATUS_SUCCESS != status)
            {
                osalYield();
            }
        } while ((CPA_STATUS_SUCCESS != status) &&
                 (retries < DEQUEUE_MSGPUT_MAX_RETRIES));

        if ((CPA_STATUS_SUCCESS != status) ||
            (retries >= DEQUEUE_MSGPUT_MAX_RETRIES))
        {
            LAC_LOG_ERROR(
                "Failed to icp_adf_transPutMsg, maximum retries exceeded.");
            goto cleanup;
        }

        pSessionDesc->pRequestQueueHead =
            pSessionDesc->pRequestQueueHead->pNext;
    }

    /* If we've drained the queue, ensure the tail pointer is set to NULL */
    if (NULL == pSessionDesc->pRequestQueueHead)
    {
        pSessionDesc->pRequestQueueTail = NULL;
    }

cleanup:
    LAC_SPINUNLOCK(&pSessionDesc->requestQueueLock);
    return status;
}

/**
 * @ingroup LacSymCb
 */
void LacSymCb_CallbacksRegister()
{
    /*** HASH ***/
    LacSymQat_RespHandlerRegister(ICP_QAT_FW_LA_CMD_AUTH,
                                  LacSymCb_ProcessCallback);

    /*** ALGORITHM-CHAINING CIPHER_HASH***/
    LacSymQat_RespHandlerRegister(ICP_QAT_FW_LA_CMD_CIPHER_HASH,
                                  LacSymCb_ProcessCallback);

    /*** ALGORITHM-CHAINING HASH_CIPHER***/
    LacSymQat_RespHandlerRegister(ICP_QAT_FW_LA_CMD_HASH_CIPHER,
                                  LacSymCb_ProcessCallback);

    /*** CIPHER ***/
    LacSymQat_RespHandlerRegister(ICP_QAT_FW_LA_CMD_CIPHER,
                                  LacSymCb_ProcessCallback);

    /* Call compile time param check function to ensure it is included
       in the build by the compiler - this compile time check
       ensures callbacks run as expected */
    LacSym_CompileTimeAssertions();
}
