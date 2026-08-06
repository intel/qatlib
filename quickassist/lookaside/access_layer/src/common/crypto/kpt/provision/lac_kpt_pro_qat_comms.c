/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 ***************************************************************************
 *
 * @file lac_kpt_pro_qat_comms.c
 *
 * @ingroup LacKptProQatComms
 *
 * This file implements the API for creating KPT key provision messages and
 * sending these to the QAT device. It implements an API for creating a KPT
 * provision request, and for sending a message to the QAT device.
 *
 ***************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/
#include "cpa.h"

/*
****************************************************************************
* Include private header files
****************************************************************************
*/
/* SAL includes  */
#include "lac_log.h"
#include "lac_common.h"
#include "lac_kpt_pro_qat_comms.h"
#include "lac_mem.h"
#include "lac_sal_types_crypto.h"
#include "sal_qat_cmn_msg.h"

#define LAC_KPT_PRO_SYNC_CALLBACK_TIMEOUT (2000) /* 2000ms */

#define LAC_KPT_DEV_CREDENTIAL_SIZE_IN_BYTE (776)
/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/

/**
***************************************************************************
* @ingroup LacKptProQatComms
*      KPT provision client callback function
***************************************************************************/
STATIC
void LacKpt_ProcessProCb(CpaStatus status,
                         CpaInstanceHandle instanceHandle,
                         lac_kpt_pro_op_cb_data_t *pCbData)
{
    lac_kpt_pro_sync_cb pCb = NULL;
    void *pCallbackTag = NULL;

    /* Extracts info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = (void *)pCbData->pCallbackTag;
    pCb = (lac_kpt_pro_sync_cb)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    LAC_ASSERT_NOT_NULL(pCb);

    /* Invokes the user callback */
    pCb(pCallbackTag, status);
}

/**
***************************************************************************
* @ingroup LacKptProQatComms
*      KPT provision sync mode client callback function
***************************************************************************/
STATIC
void LacKpt_Pro_SyncClientCb(void *pCallbackTag, CpaStatus status)
{
    LacSync_GenWakeupSyncCaller(pCallbackTag, status);
}

/**
***************************************************************************
* @ingroup LacKptProQatComms
*      KPT provision sync mode client callback function
***************************************************************************/
STATIC
CpaStatus LacKpt_Pro_CreateRequest(lac_kpt_pro_req_handle_t *pReqHandle,
                                   CpaInstanceHandle instanceHandle,
                                   Cpa8U cmdID,
                                   CpaCyKptHandle *pKeyHandle,
                                   CpaFlatBuffer *pSrc,
                                   lac_kpt_pro_op_cb_data_t *pCbData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_kpt_pro_qat_req_data_t *pReqData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&pReqData, sizeof(lac_kpt_pro_qat_req_data_t));
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_OS_BZERO(pReqData, sizeof(lac_kpt_pro_qat_req_data_t));
        pReqData->cbinfo.cbFunc = LacKpt_ProcessProCb;
        pReqData->cbinfo.pcbData = pCbData;
        pReqData->cbinfo.instanceHandle = instanceHandle;
        pReqData->u1.request.cmd_id = cmdID;
        pReqData->u1.request.service_type = LAC_KPT_PRO_SERVICE_TYPE;
        pReqData->u1.request.opaque_data = (LAC_ARCH_UINT)pReqData;
        pReqData->u1.request.valid = ICP_QAT_FW_COMN_VALID_FLAG_MASK;

        if (cmdID == KPT_PRO_DEL_SWK_CMD)
            pReqData->u1.request.key_handle = *pKeyHandle;

        if (cmdID == KPT_PRO_LOAD_SWK_CMD)
            pReqData->u1.request.src_addr = LAC_OS_VIRT_TO_PHYS_EXTERNAL(
                pCryptoService->generic_service_info, pSrc->pData);

        if (NULL != pCbData->pVirtAddr)
            pReqData->u1.request.dst_addr = LAC_OS_VIRT_TO_PHYS_INTERNAL(
                &pCryptoService->generic_service_info, pCbData->pVirtAddr);

        *pReqHandle = (lac_kpt_pro_req_handle_t)pReqData;
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup LacKptProQatComms
 *      Destroy KPT provision requests
 ***************************************************************************/
STATIC
void LacKpt_Pro_DestroyRequest(lac_kpt_pro_req_handle_t *pReqHandle)
{
    if (NULL != pReqHandle)
        LAC_OS_FREE(*pReqHandle);
}

/**
 ***************************************************************************
 * @ingroup LacKptProQatComms
 *      KPT Provision single request creation and sending function
 ***************************************************************************/
STATIC
CpaStatus LacKpt_Pro_SendSingleRequest(CpaInstanceHandle instanceHandle,
                                       Cpa8U cmdID,
                                       CpaCyKptHandle *pKeyHandle,
                                       CpaFlatBuffer *pSrc,
                                       lac_kpt_pro_op_cb_data_t *pCbData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
    lac_kpt_pro_req_handle_t reqHandle = LAC_KPT_PRO_INVALID_HANDLE;
    lac_kpt_pro_qat_req_data_t *pReqData = NULL;
    Cpa32U size = 0;
    void *pMsg = NULL;

    status = LacKpt_Pro_CreateRequest(
        &reqHandle, instanceHandle, cmdID, pKeyHandle, pSrc, pCbData);
    if (CPA_STATUS_SUCCESS == status)
    {
        pReqData = (lac_kpt_pro_qat_req_data_t *)reqHandle;
        {
            pMsg = (void *)&(pReqData->u1.request);
            size = LAC_QAT_KPT_PRO_REQ_SZ_LW;
        }

        status = SalQatMsg_transPutMsg(pCryptoService->trans_handle_asym_tx,
                                       pMsg,
                                       size,
                                       LAC_LOG_MSG_KPT_PRO,
                                       NULL);

        if (CPA_STATUS_SUCCESS != status)
        {
            LacKpt_Pro_DestroyRequest(&reqHandle);
        }
    }
    return status;
}

#ifdef ICP_PARAM_CHECK
/**
***************************************************************************
* @ingroup LacKptProQatComms
*      KPT Provision packet sending function input parameters check
***************************************************************************/
STATIC
CpaStatus LacKpt_Pro_SendRequestParamCheck(
    CpaInstanceHandle instanceHandle,
    Cpa8U cmdID,
    CpaCyKptHandle *pKeyHandle,
    CpaFlatBuffer *pSrc,
    CpaCyKptValidationKey *pDevCredential,
    CpaCyKptKeyManagementStatus *pKptStatus)
{
    /* Ensure the instance is not NULL */
    LAC_CHECK_NULL_PARAM(instanceHandle);
    LAC_CHECK_NULL_PARAM(pKptStatus);

    switch (cmdID)
    {
        case KPT_PRO_QUERY_DEV_CREDENTIAL_CMD:
            LAC_CHECK_NULL_PARAM(pDevCredential);
            break;
        case KPT_PRO_LOAD_SWK_CMD:
            LAC_CHECK_NULL_PARAM(pKeyHandle);
            LAC_CHECK_NULL_PARAM(pSrc);
            LAC_CHECK_NULL_PARAM(pSrc->pData);
            break;
        case KPT_PRO_DEL_SWK_CMD:
            LAC_CHECK_NULL_PARAM(pKeyHandle);
            break;
        default:
            LAC_LOG_ERROR("Unknown KPT provision command id");
            return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}
#endif

/**
***************************************************************************
* @ingroup LacKptProQatComms
*      KPT Provision sync mode packet sending function
***************************************************************************/
CpaStatus LacKpt_Pro_SendRequest(CpaInstanceHandle instanceHandle,
                                 Cpa8U cmdID,
                                 CpaCyKptHandle *pKeyHandle,
                                 CpaFlatBuffer *pSrc,
                                 CpaCyKptValidationKey *pDevCredential,
                                 CpaCyKptKeyManagementStatus *pKptStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_kpt_pro_op_cb_data_t cbData = { 0 };
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    Cpa8U *pVirt_addr = NULL;

#ifdef ICP_PARAM_CHECK
    status = LacKpt_Pro_SendRequestParamCheck(
        instanceHandle, cmdID, pKeyHandle, pSrc, pDevCredential, pKptStatus);
    LAC_CHECK_STATUS(status);
#endif

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to create sync cookie");
        return status;
    }

    cbData.cmdID = cmdID;
    cbData.pCallbackTag = (void *)pSyncCallbackData;
    cbData.pClientCb = (void *)LacKpt_Pro_SyncClientCb;
    cbData.pVirtAddr = NULL;
    if (NULL != pDevCredential)
    {
        sal_crypto_service_t *pCryptoService =
            (sal_crypto_service_t *)instanceHandle;

        status = LAC_OS_CAMALLOC(&pVirt_addr,
                                 LAC_KPT_DEV_CREDENTIAL_SIZE_IN_BYTE,
                                 LAC_64BYTE_ALIGNMENT,
                                 pCryptoService->nodeAffinity);

        if (CPA_STATUS_SUCCESS == status)
            cbData.pVirtAddr = pVirt_addr;
        else
        {
            LAC_LOG_ERROR(
                "Failed to allocate memory for KPT provision response");
            LacSync_SetSyncCookieComplete(pSyncCallbackData);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacKpt_Pro_SendSingleRequest(
            instanceHandle, cmdID, pKeyHandle, pSrc, &cbData);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to send KPT provision request");
            LacSync_SetSyncCookieComplete(pSyncCallbackData);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacSync_WaitForCallback(pSyncCallbackData,
                                         LAC_KPT_PRO_SYNC_CALLBACK_TIMEOUT,
                                         &status,
                                         NULL);
        if (CPA_STATUS_SUCCESS != status)
        {
            LacSync_SetSyncCookieComplete(pSyncCallbackData);
            LAC_LOG_ERROR("Failed to wait for KPT provision response");
        }
    }

    if ((CPA_STATUS_SUCCESS == status) && (cmdID != cbData.cmdID))
    {
        status = CPA_STATUS_FAIL;
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
        LAC_LOG_ERROR("Get a different command id from kpt provision response");
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        *pKptStatus = cbData.rspStatus;

        if (NULL != pDevCredential &&
            NULL != pDevCredential->publicKey.modulusN.pData &&
            NULL != pDevCredential->publicKey.publicExponentE.pData)
        {
            osalMemCopy(pDevCredential->publicKey.modulusN.pData,
                        cbData.pVirtAddr,
                        KPT_DEV_IPUB_N_SIZE_IN_BYTE);
            osalMemCopy(pDevCredential->publicKey.publicExponentE.pData,
                        cbData.pVirtAddr + KPT_DEV_IPUB_N_SIZE_IN_BYTE,
                        KPT_DEV_IPUB_E_SIZE_IN_BYTE);
            osalMemCopy(pDevCredential->signature,
                        cbData.pVirtAddr + KPT_DEV_IPUB_N_SIZE_IN_BYTE +
                            KPT_DEV_IPUB_E_SIZE_IN_BYTE,
                        CPA_CY_RSA3K_SIG_SIZE_INBYTES);
        }

        if (NULL != pKeyHandle)
            *pKeyHandle = cbData.keyHandle;
    }

    LAC_OS_CAFREE(cbData.pVirtAddr);
    LacSync_DestroySyncCookie(&pSyncCallbackData);

    return status;
}

/**
***************************************************************************
* @ingroup LacKptProQatComms
*      KPT Provision response handler
***************************************************************************/
void LacKpt_Pro_RspHandler(void *pRespMsg)
{
    lac_kpt_pro_qat_req_data_t *pReqData = NULL;
    lac_kpt_pro_op_cb_data_t *pCbData = NULL;
    lac_kpt_pro_op_cb_func_t pCbFunc = NULL;
    icp_qat_fw_kpt_pro_resp_data_t *pKptProRespMsg = NULL;
    lac_kpt_pro_req_handle_t requestHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U pkeRespFlags = 0;

    /* If the response message is NULL, this function should return
     * earlier and the client callback function will not be invoked.
     * The calling stack is expected to detect this kind of error
     * and report corresponding error code. */
    if (NULL == pRespMsg)
        return;

    pKptProRespMsg = (icp_qat_fw_kpt_pro_resp_data_t *)pRespMsg;
    pkeRespFlags = pKptProRespMsg->rsp_status.pke_resp_flags;

    LAC_MEM_SHARED_READ_TO_PTR(pKptProRespMsg->opaque_data, pReqData);

    requestHandle = (lac_kpt_pro_req_handle_t)pReqData;
    pCbFunc = pReqData->cbinfo.cbFunc;
    pCbData = pReqData->cbinfo.pcbData;
    instanceHandle = pReqData->cbinfo.instanceHandle;
    pCbData->cmdID = pKptProRespMsg->cmd_id;
    pCbData->keyHandle = pKptProRespMsg->key_handle;

    /* Detect early FW response status */
    if (ICP_QAT_FW_COMN_STATUS_FLAG_OK == pkeRespFlags)
        pCbData->rspStatus = CPA_CY_KPT_SUCCESS;
    else if (ICP_QAT_FW_PKE_RESP_PKE_STAT_GET(pkeRespFlags))
        pCbData->rspStatus = pKptProRespMsg->rsp_status.comn_err_code;
    else
        pCbData->rspStatus = CPA_CY_KPT_FAILED;

    LacKpt_Pro_DestroyRequest(&requestHandle);
    (*pCbFunc)(status, instanceHandle, pCbData);

    return;
}
