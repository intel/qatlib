/***************************************************************************
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
 ***************************************************************************/

/**
 *****************************************************************************
 * @file lac_rsa_encrypt.c
 *
 * @ingroup LacRsa
 *
 * This file implements encrypt functions for RSA.
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

/* Include API files */
#include "cpa.h"
#include "cpa_cy_rsa.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Osal include */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp_ids.h"

/* Include LAC files */
#include "lac_common.h"
#include "lac_pke_qat_comms.h"
#include "lac_pke_utils.h"
#include "lac_pke_mmp.h"
#include "lac_sym.h"
#include "lac_list.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "lac_rsa_p.h"
#include "lac_rsa_stats_p.h"

/*
********************************************************************************
* Static Variables
********************************************************************************
*/

static const Cpa32U lacRsaEncSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_512_BITS, PKE_RSA_EP_512},
    {LAC_1024_BITS, PKE_RSA_EP_1024},
    {LAC_1536_BITS, PKE_RSA_EP_1536},
    {LAC_2048_BITS, PKE_RSA_EP_2048},
    {LAC_3072_BITS, PKE_RSA_EP_3072},
    {LAC_4096_BITS, PKE_RSA_EP_4096},
    {LAC_8192_BITS, PKE_RSA_EP_8192}};
/**<
 *  Maps between operation sizes and PKE function ids */

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
 * This function performs synchronious version of the RSA Encrypt.
 */
STATIC CpaStatus LacRsa_EncryptSynch(const CpaInstanceHandle instanceHandle,
                                     const CpaCyRsaEncryptOpData *pEncryptData,
                                     CpaFlatBuffer *pOutputData);

/*
 * Based on the bit length of the modulus this function sets opSizeInBytes
 * used to select the correct MMP service.
 * This function also checks the parameters for an RSA encrypt operation. It
 * returns the appropriate error in the case of null and invalid params and also
 * unsupported operations.
 */
STATIC CpaStatus
LacRsa_EncGetOpSizeAndCheck(const CpaInstanceHandle instanceHandle,
                            const CpaCyGenFlatBufCbFunc pRsaEncryptCb,
                            const CpaCyRsaEncryptOpData *pEncryptData,
                            CpaFlatBuffer *pOutputData,
                            Cpa32U *pOpSizeInBytes);

/*
 * This function is called by the pke comms module after an RSA Encrypt
 * message has been received from the QAT.
 */
STATIC void LacRsa_ProcessEncCb(CpaStatus status,
                                CpaBoolean pass,
                                CpaInstanceHandle instanceHandle,
                                lac_pke_op_cb_data_t *pCbData);

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

/**
 *****************************************************************************
 * @ingroup LacRsa
 *
 *****************************************************************************/
CpaStatus cpaCyRsaEncrypt(const CpaInstanceHandle instanceHandle_in,
                          const CpaCyGenFlatBufCbFunc pRsaEncryptCb,
                          void *pCallbackTag,
                          const CpaCyRsaEncryptOpData *pEncryptData,
                          CpaFlatBuffer *pOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    Cpa32U opSizeInBytes = 0;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pRsaEncryptCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pEncryptData,
             (LAC_ARCH_UINT)pOutputData);
#endif
    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pRsaEncryptCb)
    {
        return LacRsa_EncryptSynch(instanceHandle, pEncryptData, pOutputData);
    }

    /* Get the opSize and check RSA Encrypt params and
       return an error if invalid */
    status = LacRsa_EncGetOpSizeAndCheck(instanceHandle,
                                         pRsaEncryptCb,
                                         pEncryptData,
                                         pOutputData,
                                         &opSizeInBytes);

    if (CPA_STATUS_SUCCESS == status)
    {
        functionalityId = LacPke_GetMmpId(opSizeInBytes * LAC_NUM_BITS_IN_BYTE,
                                          lacRsaEncSizeIdMap,
                                          LAC_ARRAY_LEN(lacRsaEncSizeIdMap));
        if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
        {
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* Zero ms bytes of output buffer
           (Note: verified in LacRsa_EncGetOpSizeAndCheck() that
                  buffer size >= opSizeInBytes) */
        osalMemSet(pOutputData->pData,
                   0,
                   (pOutputData->dataLenInBytes - opSizeInBytes));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_ep_1024.m,
                                      &(pEncryptData->inputData));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_input_t, m)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_input_t, m)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            in.mmp_rsa_ep_1024.e, &(pEncryptData->pPublicKey->publicExponentE));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_input_t, e)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_input_t, e)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_ep_1024.n,
                                      &(pEncryptData->pPublicKey->modulusN));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_input_t, n)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_input_t, n)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_rsa_ep_1024.c, pOutputData);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_output_t, c)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_output_t, c)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pRsaEncryptCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pEncryptData;
        cbData.pOutputData1 = pOutputData;
        /* send a PKE request to the QAT */
        status =
            LacPke_SendSingleRequest(functionalityId,
                                     pInArgSizeList,
                                     pOutArgSizeList,
                                     &in,
                                     &out,
                                     internalMemInList,
                                     internalMemOutList,
                                     (lac_pke_op_cb_func_t)LacRsa_ProcessEncCb,
                                     &cbData,
                                     instanceHandle);
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_RSA_STAT_INC(numRsaEncryptRequests, instanceHandle);
    }
    else
    {
        LAC_RSA_STAT_INC(numRsaEncryptRequestErrors, instanceHandle);
    }

    return status;
}

STATIC CpaStatus LacRsa_EncryptSynch(const CpaInstanceHandle instanceHandle,
                                     const CpaCyRsaEncryptOpData *pEncryptData,
                                     CpaFlatBuffer *pOutputData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyRsaEncrypt(instanceHandle,
                                 LacSync_GenFlatBufCb,
                                 pSyncCallbackData,
                                 pEncryptData,
                                 pOutputData);
    }
    else
    {
        LAC_RSA_STAT_INC(numRsaEncryptRequestErrors, instanceHandle);
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_RSA_STAT_INC(numRsaEncryptCompletedErrors, instanceHandle);
            status = wCbStatus;
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

CpaStatus LacRsa_EncGetOpSizeAndCheck(const CpaInstanceHandle instanceHandle,
                                      const CpaCyGenFlatBufCbFunc pRsaEncryptCb,
                                      const CpaCyRsaEncryptOpData *pEncryptData,
                                      CpaFlatBuffer *pOutputData,
                                      Cpa32U *pOpSizeInBytes)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pRsaEncryptCb);

    /* Check user parameters */
    LAC_CHECK_NULL_PARAM(pEncryptData);
    LAC_CHECK_NULL_PARAM(pEncryptData->pPublicKey);
    LAC_CHECK_NULL_PARAM(pOutputData);

    LAC_CHECK_FLAT_BUFFER(&pEncryptData->pPublicKey->modulusN);
#endif
    /* Check sizes. Operation size is the public key modulus length.
     * Message and cipher buffers must be able to accomodate messages of
     * this length */
    *pOpSizeInBytes = LacPke_GetMinBytes(&(pEncryptData->pPublicKey->modulusN));
#ifdef ICP_PARAM_CHECK
    if (CPA_FALSE == LacRsa_IsValidRsaSize((*pOpSizeInBytes)))
    {
        LAC_INVALID_PARAM_LOG("Invalid data length for pPublicKey->modulusN");
        return CPA_STATUS_INVALID_PARAM;
    }

    LAC_CHECK_RSA_BUFFER_MSB_LSB(&(pEncryptData->pPublicKey->modulusN),
                                 (*pOpSizeInBytes),
                                 CPA_TRUE,
                                 CPA_TRUE);
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(
        &(pEncryptData->pPublicKey->publicExponentE),
        CHECK_LESS_EQUALS,
        (*pOpSizeInBytes),
        CPA_TRUE);
    /* Check message and ciphertext buffers */
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(&(pEncryptData->inputData),
                                    CHECK_LESS_EQUALS,
                                    (*pOpSizeInBytes),
                                    CPA_FALSE);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        pOutputData, CHECK_GREATER_EQUALS, (*pOpSizeInBytes));

    /* Standards based check: 0 < m < n */
    LAC_CHECK_NON_ZERO_PARAM(&(pEncryptData->inputData));
    if (LacPke_Compare(&(pEncryptData->inputData),
                       0,
                       &(pEncryptData->pPublicKey->modulusN),
                       0) >= 0)
    {
        LAC_INVALID_PARAM_LOG("inputData must be < modulusN");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Note PKE will check e is within range */

#endif
    return status;
}

void LacRsa_ProcessEncCb(CpaStatus status,
                         CpaBoolean pass,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyRsaEncryptOpData *pOpData = NULL;
    CpaFlatBuffer *pOutputData = NULL;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;

    pOpData =
        (CpaCyRsaEncryptOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    LAC_ASSERT_NOT_NULL(pOpData);

    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    LAC_ASSERT_NOT_NULL(pCb);

    pOutputData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutputData);

    /* increment stats */
    LAC_RSA_STAT_INC(numRsaEncryptCompleted, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_RSA_STAT_INC(numRsaEncryptCompletedErrors, instanceHandle);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pOutputData);
}
