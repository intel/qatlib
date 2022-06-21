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
 * @file lac_rsa_decrypt.c
 *
 * @ingroup LacRsa
 *
 * This file implements decrypt functions for RSA.
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

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

static const Cpa32U lacRsaDp1SizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_512_BITS, PKE_RSA_DP1_512},
    {LAC_1024_BITS, PKE_RSA_DP1_1024},
    {LAC_1536_BITS, PKE_RSA_DP1_1536},
    {LAC_2048_BITS, PKE_RSA_DP1_2048},
    {LAC_3072_BITS, PKE_RSA_DP1_3072},
    {LAC_4096_BITS, PKE_RSA_DP1_4096},
    {LAC_8192_BITS, PKE_RSA_DP1_8192}};
/**<
 *  Maps between operation sizes and PKE function ids */

static const Cpa32U lacRsaDp2SizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_512_BITS, PKE_RSA_DP2_512},
    {LAC_1024_BITS, PKE_RSA_DP2_1024},
    {LAC_1536_BITS, PKE_RSA_DP2_1536},
    {LAC_2048_BITS, PKE_RSA_DP2_2048},
    {LAC_3072_BITS, PKE_RSA_DP2_3072},
    {LAC_4096_BITS, PKE_RSA_DP2_4096},
    {LAC_8192_BITS, PKE_RSA_DP2_8192}};
/**<
 *  Maps between operation sizes and PKE function ids */

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
 * This function checks the parameters for an RSA decrypt operation. It returns
 * the appropriate error in the case of null and invalid params and also
 * unsupported operations.
 */
#ifdef ICP_PARAM_CHECK
STATIC CpaStatus
LacRsa_DecryptParamsCheck(const CpaInstanceHandle instanceHandle,
                          const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                          const CpaCyRsaDecryptOpData *pDecryptData,
                          CpaFlatBuffer *pOutputData);
#endif

/*
 * This function is called by the pke comms module after an RSA Encrypt
 * message has been received from the QAT.
 */
STATIC void LacRsa_ProcessDecCb(CpaStatus status,
                                CpaBoolean pass,
                                CpaInstanceHandle instanceHandle,
                                lac_pke_op_cb_data_t *pCbData);

/*
 * This function performs RSA Decrypt for type 1 private keys.
 */
STATIC CpaStatus LacRsa_Type1Decrypt(const CpaInstanceHandle instanceHandle,
                                     const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                                     void *pCallbackTag,
                                     const CpaCyRsaDecryptOpData *pDecryptData,
                                     CpaFlatBuffer *pOutputData);

/*
 * This function performs RSA Decrypt for type 2 private keys.
 */
STATIC CpaStatus LacRsa_Type2Decrypt(const CpaInstanceHandle instanceHandle,
                                     const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                                     void *pCallbackTag,
                                     const CpaCyRsaDecryptOpData *pDecryptData,
                                     CpaFlatBuffer *pOutputData);

/*
 * This is the LAC RSA Decrypt synchronous function.
 */
STATIC CpaStatus LacRsa_DecryptSynch(const CpaInstanceHandle instanceHandle,
                                     const CpaCyRsaDecryptOpData *pDecryptData,
                                     CpaFlatBuffer *pOutputData);

/**
 *****************************************************************************
 * @ingroup LacRsa
 *
 *****************************************************************************/
CpaStatus cpaCyRsaDecrypt(const CpaInstanceHandle instanceHandle_in,
                          const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                          void *pCallbackTag,
                          const CpaCyRsaDecryptOpData *pDecryptData,
                          CpaFlatBuffer *pOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pRsaDecryptCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pDecryptData,
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
    if (NULL == pRsaDecryptCb)
    {
        return LacRsa_DecryptSynch(instanceHandle, pDecryptData, pOutputData);
    }
#ifdef ICP_PARAM_CHECK
    /* Check RSA Decrypt params and return an error if invalid */
    status = LacRsa_DecryptParamsCheck(
        instanceHandle, pRsaDecryptCb, pDecryptData, pOutputData);
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 ==
            pDecryptData->pRecipientPrivateKey->privateKeyRepType)
        {
            status = LacRsa_Type1Decrypt(instanceHandle,
                                         pRsaDecryptCb,
                                         pCallbackTag,
                                         pDecryptData,
                                         pOutputData);
        }
        else /* Must be type2 key as param check has passed */
        {
            status = LacRsa_Type2Decrypt(instanceHandle,
                                         pRsaDecryptCb,
                                         pCallbackTag,
                                         pDecryptData,
                                         pOutputData);
        }
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_RSA_STAT_INC(numRsaDecryptRequests, instanceHandle);
    }
    else
    {
        LAC_RSA_STAT_INC(numRsaDecryptRequestErrors, instanceHandle);
    }

    return status;
}

STATIC CpaStatus LacRsa_DecryptSynch(const CpaInstanceHandle instanceHandle,
                                     const CpaCyRsaDecryptOpData *pDecryptData,
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
        status = cpaCyRsaDecrypt(instanceHandle,
                                 LacSync_GenFlatBufCb,
                                 pSyncCallbackData,
                                 pDecryptData,
                                 pOutputData);
    }
    else
    {
        LAC_RSA_STAT_INC(numRsaDecryptRequestErrors, instanceHandle);
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
            LAC_RSA_STAT_INC(numRsaDecryptCompletedErrors, instanceHandle);
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

#ifdef ICP_PARAM_CHECK
STATIC CpaStatus
LacRsa_DecryptParamsCheck(const CpaInstanceHandle instanceHandle,
                          const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                          const CpaCyRsaDecryptOpData *pDecryptData,
                          CpaFlatBuffer *pOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U opSizeInBytes = 0;

    LAC_CHECK_NULL_PARAM(pRsaDecryptCb);

    /* Check user parameters */
    LAC_CHECK_NULL_PARAM(pDecryptData);

    /* Check the Private Key is correct version, type and for NULL params */
    status = LacRsa_CheckPrivateKeyParam(pDecryptData->pRecipientPrivateKey);
    LAC_CHECK_STATUS(status);

    /* Get the opSize */
    opSizeInBytes =
        LacRsa_GetPrivateKeyOpSize(pDecryptData->pRecipientPrivateKey);
    if (CPA_FALSE == LacRsa_IsValidRsaSize(opSizeInBytes))
    {
        LAC_INVALID_PARAM_LOG(
            "Invalid Private Key Size - pDecryptData->pRecipientPrivateKey");
        return CPA_STATUS_INVALID_PARAM;
    }
    /* Check message and ciphertext buffers */
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(&(pDecryptData->inputData),
                                    CHECK_LESS_EQUALS,
                                    opSizeInBytes,
                                    CPA_FALSE);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        pOutputData, CHECK_GREATER_EQUALS, opSizeInBytes);

    if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 ==
        pDecryptData->pRecipientPrivateKey->privateKeyRepType)
    {
        /* Check MSB and LSB of the modulus */
        LAC_CHECK_RSA_BUFFER_MSB_LSB(
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep1.modulusN),
            opSizeInBytes,
            CPA_TRUE,
            CPA_TRUE);

        /* Standards based check: 0 < inputData < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pDecryptData->inputData));
        if (LacPke_Compare(
                &(pDecryptData->inputData),
                0,
                &(pDecryptData->pRecipientPrivateKey->privateKeyRep1.modulusN),
                0) >= 0)
        {
            LAC_INVALID_PARAM_LOG("inputData must be < modulusN");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        /* Check MSB and LSB of the modulus */
        LAC_CHECK_FLAT_BUFFER_MSB_LSB(
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2.prime1P),
            (opSizeInBytes >> 1),
            CPA_TRUE,
            CPA_TRUE);

        LAC_CHECK_FLAT_BUFFER_MSB_LSB(
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2.prime2Q),
            (opSizeInBytes >> 1),
            CPA_TRUE,
            CPA_TRUE);

        status = LacRsa_Type2StdsCheck(
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2));
        LAC_CHECK_STATUS(status);
    }

    return status;
}
#endif

CpaStatus LacRsa_Type1Decrypt(const CpaInstanceHandle instanceHandle,
                              const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                              void *pCallbackTag,
                              const CpaCyRsaDecryptOpData *pDecryptData,
                              CpaFlatBuffer *pOutputData)
{
    Cpa32U opSizeInBytes = 0;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    CpaStatus status = CPA_STATUS_FAIL;
    lac_pke_op_cb_data_t cbData = {0};
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};

    LAC_ASSERT_NOT_NULL(pDecryptData);
    LAC_ASSERT_NOT_NULL(pOutputData);

    opSizeInBytes =
        LacRsa_GetPrivateKeyOpSize(pDecryptData->pRecipientPrivateKey);

    functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                      lacRsaDp1SizeIdMap,
                                      LAC_ARRAY_LEN(lacRsaDp1SizeIdMap));
    if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
    {
        LAC_INVALID_PARAM_LOG(
            "Invalid Private Key Size - pDecryptData->pRecipientPrivateKey");
        status = CPA_STATUS_INVALID_PARAM;
    }
    else
    {

        /* Zero ms bytes of output buffer */
        osalMemSet(pOutputData->pData,
                   0,
                   (pOutputData->dataLenInBytes - opSizeInBytes));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_dp1_1024.c,
                                      &(pDecryptData->inputData));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_input_t, c)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_input_t, c)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_dp1_1024.d,
                                      &(pDecryptData->pRecipientPrivateKey
                                            ->privateKeyRep1.privateExponentD));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_input_t, d)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_input_t, d)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            in.mmp_rsa_dp1_1024.n,
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep1.modulusN));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_input_t, n)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_input_t, n)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_rsa_dp1_1024.m, pOutputData);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_output_t, m)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_output_t, m)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pRsaDecryptCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pDecryptData;
        cbData.pOutputData1 = pOutputData;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &in,
                                          &out,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacRsa_ProcessDecCb,
                                          &cbData,
                                          instanceHandle);
    }

    return status;
}

CpaStatus LacRsa_Type2Decrypt(const CpaInstanceHandle instanceHandle,
                              const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                              void *pCallbackTag,
                              const CpaCyRsaDecryptOpData *pDecryptData,
                              CpaFlatBuffer *pOutputData)
{
    Cpa32U opSizeInBytes = 0;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};

    LAC_ASSERT_NOT_NULL(pDecryptData);
    LAC_ASSERT_NOT_NULL(pOutputData);

    opSizeInBytes =
        LacRsa_GetPrivateKeyOpSize(pDecryptData->pRecipientPrivateKey);

    functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                      lacRsaDp2SizeIdMap,
                                      LAC_ARRAY_LEN(lacRsaDp2SizeIdMap));
    if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
    {
        LAC_INVALID_PARAM_LOG(
            "Invalid Private Key Size - pDecryptData->pRecipientPrivateKey");
        status = CPA_STATUS_INVALID_PARAM;
    }
    else
    {
        /* Zero ms bytes of output buffer */
        osalMemSet(pOutputData->pData,
                   0,
                   (pOutputData->dataLenInBytes - opSizeInBytes));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_dp2_1024.c,
                                      &(pDecryptData->inputData));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, c)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, c)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            in.mmp_rsa_dp2_1024.p,
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2.prime1P));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, p)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            in.mmp_rsa_dp2_1024.q,
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2.prime2Q));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, q)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            in.mmp_rsa_dp2_1024.dp,
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2.exponent1Dp));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, dp)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, dp)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            in.mmp_rsa_dp2_1024.dq,
            &(pDecryptData->pRecipientPrivateKey->privateKeyRep2.exponent2Dq));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, dq)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, dq)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_dp2_1024.qinv,
                                      &(pDecryptData->pRecipientPrivateKey
                                            ->privateKeyRep2.coefficientQInv));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, qinv)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_input_t, qinv)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_rsa_dp2_1024.m, pOutputData);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_output_t, m)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_output_t, m)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pRsaDecryptCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pDecryptData;
        cbData.pOutputData1 = pOutputData;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &in,
                                          &out,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacRsa_ProcessDecCb,
                                          &cbData,
                                          instanceHandle);
    }

    return status;
}

void LacRsa_ProcessDecCb(CpaStatus status,
                         CpaBoolean pass,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyRsaDecryptOpData *pOpData = NULL;
    CpaFlatBuffer *pOutputData = NULL;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = (void *)pCbData->pCallbackTag;

    pOpData =
        (CpaCyRsaDecryptOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    LAC_ASSERT_NOT_NULL(pOpData);

    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    LAC_ASSERT_NOT_NULL(pCb);

    pOutputData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutputData);

    /* increment stats */
    LAC_RSA_STAT_INC(numRsaDecryptCompleted, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_RSA_STAT_INC(numRsaDecryptCompletedErrors, instanceHandle);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pOutputData);
}
