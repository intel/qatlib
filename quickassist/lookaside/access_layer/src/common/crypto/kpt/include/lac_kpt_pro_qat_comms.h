/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 ***************************************************************************
 * @file lac_kpt_pro_qat_comms.h
 *
 * @ingroup LacKptProQatComms
 *
 * Common definition that are KPT provision specific
 *
 ******************************************************************************/

/******************************************************************************/

#ifndef _LAC_KPT_PRO_QAT_COMMS_H_
#define _LAC_KPT_PRO_QAT_COMMS_H_

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_kpt.h"

/* QAT include */
#include "icp_qat_fw_kpt_pro.h"

#define LAC_QAT_KPT_PRO_REQ_SZ_LW (16)
#define LAC_KPT_PRO_SERVICE_TYPE (0xC)

#define KPT_DEV_IPUB_N_SIZE_IN_BYTE (384)
#define KPT_DEV_IPUB_E_SIZE_IN_BYTE (8)

#define KPT_LOAD_SWK_SIZE_IN_BYTE (384)

#define KPT_PRO_LOAD_SWK_CMD (1)
/* Load an encrypted SWK to device */
#define KPT_PRO_DEL_SWK_CMD (2)
/* Delete a SWK */
#define KPT_PRO_QUERY_DEV_CREDENTIAL_CMD (3)
/* Query device credential (public key and signature) */

typedef void *lac_kpt_pro_req_handle_t;

#define LAC_KPT_PRO_INVALID_HANDLE ((lac_kpt_pro_req_handle_t)0)

/**
 *******************************************************************************
 * @ingroup LacKptProvision
 *      This macro verifies that the KPT Instance Handle is valid.
 *
 * @description
 *      Check KPT Instance's value, type and running state.
 *
 ******************************************************************************/
#define LAC_CHECK_KPT_INSTANCE_HANDLE(instanceHandle)                          \
    do                                                                         \
    {                                                                          \
        LAC_CHECK_INSTANCE_HANDLE(instanceHandle);                             \
        /* Test if instance supports asymmetric crypto */                      \
        SAL_CHECK_INSTANCE_TYPE(                                               \
            instanceHandle,                                                    \
            (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));         \
    } while (0)

/**
 ******************************************************************************
 * @ingroup LacKptProQatComms
 *
 * @description
 *      KPT provision response client callback opdata
 *
 *****************************************************************************/
typedef struct lac_kpt_pro_op_cb_data_s
{
    const void *pClientCb;
    void *pCallbackTag;
    Cpa8U *pVirtAddr;
    Cpa64U keyHandle;
    Cpa16U rspStatus;
    Cpa8U cmdID;
} lac_kpt_pro_op_cb_data_t;

/**
 ******************************************************************************
 * @ingroup LacKptProQatComms
 *
 * @description
 *      KPT provision response client callback function
 *
 *****************************************************************************/
typedef void (*lac_kpt_pro_op_cb_func_t)(CpaStatus status,
                                         CpaInstanceHandle instanceHandle,
                                         lac_kpt_pro_op_cb_data_t *pCbData);
/**
 *****************************************************************************
 * @ingroup LacKptProQatComms
 *
 * @description
 *      KPT provision sync mode callback function definition
 *
 *****************************************************************************/
typedef void (*lac_kpt_pro_sync_cb)(void *pCallbackTag, CpaStatus status);

/**
 *****************************************************************************
 * @ingroup LacKptProQatComms
 *
 * @description
 *      Contains the data for a KPT provision operation callback
 *****************************************************************************/
typedef struct lac_kpt_pro_cb_info_s
{
    lac_kpt_pro_op_cb_func_t cbFunc;
    lac_kpt_pro_op_cb_data_t *pcbData;
    CpaInstanceHandle instanceHandle;
} lac_kpt_pro_cb_info_t;

/**
 ******************************************************************************
 * @ingroup LacKptProQatComms
 *      Request data of KPT provision for QAT messages
 *
 * @description
 *      This structure defines data format of KPT provision request which is
 *      issued along with a crypto instances. This structure is used to store
 *      data which is known when the message is sent and which we wish to
 *      retrieve when the response message is processed.
 *****************************************************************************/
typedef struct lac_kpt_pro_qat_req_data_s
{
    union lac_kpt_pro_qat_req_data_request_u {
        icp_qat_fw_kpt_pro_request_t request;
        Cpa8U padding[LAC_QAT_KPT_PRO_REQ_SZ_LW * 4];
    } u1;
    /* KPT only supports asymmetric service, the size of request is 64 bytes. */

    lac_kpt_pro_cb_info_t cbinfo;
} lac_kpt_pro_qat_req_data_t;

/**
 *******************************************************************************
 * @ingroup LacKptProQatComms
 *
 * @description
 *      This function sends a single (unchained) KPT provision request to the
 *      QAT. It takes the parameters for a KPT provision request, creates the
 *      request, fills in the KPT provision fields, and sends it to the QAT.
 *      This function will block, waiting for a response until the callback
 *      function is invoked when the response from the QAT has been processed.
 *
 * @param[in] instanceHandle        Instance handle
 * @param[in] cmdID                 KPT provision command ID
 * @param[in] pKeyHandle            A pointer referring to the SWK's identity
 * @param[in] pSrc                  A flat buffer pointer referring to input
 *                                  data for the QAT
 * @param[in] pDevCredential        A pointer referring to the KPT device
 *                                  credential
 * @param[out] pKptStatus           The return code
 *
 * @retval CPA_STATUS_SUCCESS       No error
 * @retval CPA_STATUS_RESOURCE      Resource error (e.g., failed memory
 *                                  allocation)
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter
 * @retval CPA_STATUS_RETRY         Ring full
 * @retval CPA_STATUS_FAIL          Failed to send the request
 *
 *****************************************************************************/
CpaStatus LacKpt_Pro_SendRequest(CpaInstanceHandle instanceHandle,
                                 Cpa8U cmdID,
                                 CpaCyKptHandle *pKeyHandle,
                                 CpaFlatBuffer *pSrc,
                                 CpaCyKptValidationKey *pDevCredential,
                                 CpaCyKptKeyManagementStatus *pKptStatus);

/**
 ******************************************************************************
 * @ingroup LacKptProQatComms
 *
 * @description
 *      This function will handle KPT provision response, it should be called
 *      in response callback function.
 *
 * @param[in] pRespMsg          Pointer to the KPT provision response
 *
 * @retval NULL
 *
 *****************************************************************************/
void LacKpt_Pro_RspHandler(void *pRespMsg);
#endif /* _LAC_KPT_PRO_QAT_COMMS_H_ */
