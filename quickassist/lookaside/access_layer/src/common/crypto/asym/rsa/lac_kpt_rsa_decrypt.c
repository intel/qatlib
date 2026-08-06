/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file lac_kpt_rsa_decrypt.c
 *
 * @ingroup Lac_KptRsa
 *
 * This file implements data decryption function for KPT RSA.
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_kpt.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Osal includes */
#include "Osal.h"

/* FW includes */
#include "icp_qat_fw_mmp_ids.h"

/* SAL includes */
#include "lac_common.h"
#include "lac_pke_qat_comms.h"
#include "lac_pke_utils.h"
#include "lac_pke_mmp.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "lac_rsa_stats_p.h"
#include "lac_mem.h"
#include "lac_kpt_crypto_qat_comms.h"
#include "lac_kpt_pro_qat_comms.h"

/*
*******************************************************************************
* Intel KPT RSA Wrapped Private Key(WPK) type1 has a fix format as:
* (d||n)'||AuthTag.
* The size of WPK is:  sizeof(d) + sizeof(n) + sizeof(AuthTag).
* E.g. Size of RSA512 WPK is: 64 + 64 + 16 = 144
*******************************************************************************
*/
#define LAC_KPT_RSA_512_DP1_KEY_SIZE_IN_BYTES (144)
#define LAC_KPT_RSA_1024_DP1_KEY_SIZE_IN_BYTES (272)
#define LAC_KPT_RSA_1536_DP1_KEY_SIZE_IN_BYTES (400)
#define LAC_KPT_RSA_2048_DP1_KEY_SIZE_IN_BYTES (528)
#define LAC_KPT_RSA_3072_DP1_KEY_SIZE_IN_BYTES (784)
#define LAC_KPT_RSA_4096_DP1_KEY_SIZE_IN_BYTES (1040)
#define LAC_KPT_RSA_8192_DP1_KEY_SIZE_IN_BYTES (2064)

/*
*******************************************************************************
* Intel KPT RSA Wrapped Private Key(WPK) type2 has a fix format as:
* (p||q||dp||dq||qinv||e)'||AuthTag.
* The size of WPK is:  sizeof(p) * 5 + sizeof(e) + sizeof(AuthTag).
* E.g. Size of RSA512 WPK is: 32 * 5 + 64 + 16 = 240
*******************************************************************************
*/
#define LAC_KPT_RSA_512_DP2_KEY_SIZE_IN_BYTES (240)
#define LAC_KPT_RSA_1024_DP2_KEY_SIZE_IN_BYTES (464)
#define LAC_KPT_RSA_1536_DP2_KEY_SIZE_IN_BYTES (688)
#define LAC_KPT_RSA_2048_DP2_KEY_SIZE_IN_BYTES (912)
#define LAC_KPT_RSA_3072_DP2_KEY_SIZE_IN_BYTES (1360)
#define LAC_KPT_RSA_4096_DP2_KEY_SIZE_IN_BYTES (1808)
#define LAC_KPT_RSA_8192_DP2_KEY_SIZE_IN_BYTES (3600)

/*
********************************************************************************
* Static Variables
********************************************************************************
*/
/**<
 *  Maps between operation sizes and PKE function ids */
static const Cpa32U lacKptRsaSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    { LAC_KPT_RSA_512_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_512 },
    { LAC_KPT_RSA_1024_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_1024 },
    { LAC_KPT_RSA_1536_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_1536 },
    { LAC_KPT_RSA_2048_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_2048 },
    { LAC_KPT_RSA_3072_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_3072 },
    { LAC_KPT_RSA_4096_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_4096 },
    { LAC_KPT_RSA_8192_DP1_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP1_8192 },
    { LAC_KPT_RSA_512_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_512 },
    { LAC_KPT_RSA_1024_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_1024 },
    { LAC_KPT_RSA_1536_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_1536 },
    { LAC_KPT_RSA_2048_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_2048 },
    { LAC_KPT_RSA_3072_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_3072 },
    { LAC_KPT_RSA_4096_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_4096 },
    { LAC_KPT_RSA_8192_DP2_KEY_SIZE_IN_BYTES, PKE_KPT_RSA_DP2_8192 }
};

/**<
 *  Maps between operation sizes and clear private key sizes */
static const Cpa32U lacKptRsaSizeMap[][LAC_PKE_NUM_COLUMNS] = {
    { LAC_KPT_RSA_512_DP1_KEY_SIZE_IN_BYTES,
      LAC_512_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_1024_DP1_KEY_SIZE_IN_BYTES,
      LAC_1024_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_1536_DP1_KEY_SIZE_IN_BYTES,
      LAC_1536_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_2048_DP1_KEY_SIZE_IN_BYTES,
      LAC_2048_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_3072_DP1_KEY_SIZE_IN_BYTES,
      LAC_3072_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_4096_DP1_KEY_SIZE_IN_BYTES,
      LAC_4096_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_8192_DP1_KEY_SIZE_IN_BYTES,
      LAC_8192_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_512_DP2_KEY_SIZE_IN_BYTES,
      LAC_512_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_1024_DP2_KEY_SIZE_IN_BYTES,
      LAC_1024_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_1536_DP2_KEY_SIZE_IN_BYTES,
      LAC_1536_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_2048_DP2_KEY_SIZE_IN_BYTES,
      LAC_2048_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_3072_DP2_KEY_SIZE_IN_BYTES,
      LAC_3072_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_4096_DP2_KEY_SIZE_IN_BYTES,
      LAC_4096_BITS / LAC_NUM_BITS_IN_BYTE },
    { LAC_KPT_RSA_8192_DP2_KEY_SIZE_IN_BYTES,
      LAC_8192_BITS / LAC_NUM_BITS_IN_BYTE }
};

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     Get the size of RSA Wrapped Private Key (WPK).
 *
 *****************************************************************************/
STATIC
Cpa32U LacKptRsa_GetPrivateKeyOpSize(const CpaCyKptRsaPrivateKey *pPrivateKey)
{
    LAC_ASSERT_NOT_NULL(pPrivateKey);

    switch (pPrivateKey->privateKeyRepType)
    {
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1:
            return pPrivateKey->privateKeyRep1.privateKey.dataLenInBytes;
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2:
            return pPrivateKey->privateKeyRep2.privateKey.dataLenInBytes;
        default:
        {
            LAC_LOG_ERROR("Invalid Private Key Type.");
            return LAC_KPT_PKE_INVALID_KEY_SIZE;
        }
    }
}

#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     Check KPT RSA Wrapped Private Key (WPK) parameters.
 *
 *****************************************************************************/
STATIC
CpaStatus LacKptRsa_CheckPrivateKeyParam(CpaCyKptRsaPrivateKey *pPrivateKey)
{
    LAC_CHECK_NULL_PARAM(pPrivateKey);

    if (CPA_CY_RSA_VERSION_TWO_PRIME != pPrivateKey->version)
    {
        LAC_INVALID_PARAM_LOG("Invalid pPrivateKey->version");
        return CPA_STATUS_INVALID_PARAM;
    }

    switch (pPrivateKey->privateKeyRepType)
    {
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1:
        {
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep1.privateKey), CHECK_NONE, 0);
        }
        break;

        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2:
        {
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep2.privateKey), CHECK_NONE, 0);
        }
        break;

        default:
        {
            LAC_INVALID_PARAM_LOG("Invalid pPrivateKey->privateKeyRepType");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *      Check KPT RSA decryption parameters.
 *
 *****************************************************************************/
STATIC
CpaStatus LacKptRsa_DecryptParamsCheck(
    const CpaCyKptRsaDecryptOpData *pDecryptOpData,
    CpaFlatBuffer *pOutputData,
    CpaCyKptUnwrapContext *pKptUnwrapContext)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U wpkSizeInBytes = 0;
    Cpa32U cpkSizeInBytes = 0;

    /* Check user parameters */
    LAC_CHECK_NULL_PARAM(pDecryptOpData);
    LAC_CHECK_NULL_PARAM(pKptUnwrapContext);

    /* Check the WPK is of correct version, type and NULL params */
    status =
        LacKptRsa_CheckPrivateKeyParam(pDecryptOpData->pRecipientPrivateKey);
    LAC_CHECK_STATUS(status);

    /* Get the WPK size */
    wpkSizeInBytes =
        LacKptRsa_GetPrivateKeyOpSize(pDecryptOpData->pRecipientPrivateKey);

    /* Get the size of Clear Private Key (CPK) */
    cpkSizeInBytes = LacKpt_GetCpkSize(
        wpkSizeInBytes, lacKptRsaSizeMap, LAC_ARRAY_LEN(lacKptRsaSizeMap));
    if (LAC_KPT_PKE_INVALID_KEY_SIZE == cpkSizeInBytes)
    {
        LAC_INVALID_PARAM_LOG("Invalid Private Key Size - "
                              "pDecryptOpData->pRecipientPrivateKey");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check message and ciphertext buffers */
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(&(pDecryptOpData->inputData),
                                    CHECK_LESS_EQUALS,
                                    cpkSizeInBytes,
                                    CPA_FALSE);

    /* Standards based check: inputData > 0 */
    if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 ==
        pDecryptOpData->pRecipientPrivateKey->privateKeyRepType)
        LAC_CHECK_NON_ZERO_PARAM(&(pDecryptOpData->inputData));

    LAC_CHECK_FLAT_BUFFER_PARAM(
        pOutputData, CHECK_GREATER_EQUALS, cpkSizeInBytes);

    return status;
}
#endif

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     Get RSA Wrapped Private Key(WPK) flat buffer.
 *
 *****************************************************************************/
STATIC
CpaFlatBuffer *getWpkFlatBuf(CpaCyKptRsaPrivateKey *pPrivateKey)
{
    switch (pPrivateKey->privateKeyRepType)
    {
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1:
            return &(pPrivateKey->privateKeyRep1.privateKey);
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2:
            return &(pPrivateKey->privateKeyRep2.privateKey);
        default:
        {
            LAC_LOG_ERROR("Invalid private key type.");
            return NULL;
        }
    }
}

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     KPT RSA decryption internal callback.
 *
 *****************************************************************************/
STATIC
void LacKptRsa_ProcessDecCb(CpaStatus status,
                            CpaBoolean pass,
                            CpaInstanceHandle instanceHandle,
                            lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyKptRsaDecryptOpData *pOpData = NULL;
    CpaFlatBuffer *pOutputData = NULL;
    Cpa8U *pMemPool = NULL;

    /* Extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = (void *)pCbData->pCallbackTag;

    pOpData =
        (CpaCyKptRsaDecryptOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    LAC_ASSERT_NOT_NULL(pOpData);

    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    LAC_ASSERT_NOT_NULL(pCb);

    pOutputData = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOutputData);

    pMemPool = (Cpa8U *)(pCbData->pOpaqueData);
    /* Free memory pool entry */
    if (pMemPool)
        LacKpt_MemPoolFree(pMemPool);

    /* Increment stats */
    LAC_RSA_STAT_INC(numKptRsaDecryptCompleted, instanceHandle);
    if ((CPA_STATUS_SUCCESS != status) || (CPA_FALSE == pass))
    {
        LAC_RSA_STAT_INC(numKptRsaDecryptCompletedErrors, instanceHandle);
    }

    if ((CPA_FALSE == pass) && ((CPA_STATUS_SUCCESS) == status))
    {
        status = CPA_STATUS_FAIL;
    }

    /* Invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pOutputData);
}

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     KPT RSA decryption synchronous function.
 *
 *****************************************************************************/
STATIC
CpaStatus LacKptRsa_DecryptSync(const CpaInstanceHandle instanceHandle,
                                const CpaCyKptRsaDecryptOpData *pDecryptOpData,
                                CpaFlatBuffer *pOutputData,
                                CpaCyKptUnwrapContext *pKptUnwrapContext)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    CpaStatus wCbStatus = CPA_STATUS_FAIL;
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyKptRsaDecrypt(instanceHandle,
                                    LacSync_GenFlatBufCb,
                                    pSyncCallbackData,
                                    pDecryptOpData,
                                    pOutputData,
                                    pKptUnwrapContext);
    }
    else
    {
        LAC_RSA_STAT_INC(numKptRsaDecryptRequestErrors, instanceHandle);
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(
            pSyncCallbackData, LAC_PKE_SYNC_CALLBACK_TIMEOUT, &status, NULL);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            /*
             * Increment stats only if the wait for callback failed.
             */
            LAC_RSA_STAT_INC(numKptRsaDecryptCompletedErrors, instanceHandle);
            LacSync_SetSyncCookieComplete(pSyncCallbackData);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the request was not sent the callback will never
         * be called, so need to indicate that we are finished
         * with cookie so that it can be destroyed. */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }
    LacSync_DestroySyncCookie(&pSyncCallbackData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     Internal KPT RSA decryption function.
 *
 *****************************************************************************/
STATIC
CpaStatus LacKptRsa_Decrypt(const CpaInstanceHandle instanceHandle,
                            const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                            void *pCallbackTag,
                            const CpaCyKptRsaDecryptOpData *pDecryptOpData,
                            CpaFlatBuffer *pOutputData,
                            CpaCyKptUnwrapContext *pKptUnwrapContext)
{
    Cpa32U wpkSizeInBytes = 0;
    Cpa32U cpkSizeInBytes = 0;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = { 0 };
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = { 0 };
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = { CPA_FALSE };
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = { CPA_FALSE };
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_pke_op_cb_data_t cbData = { 0 };
    icp_qat_fw_mmp_input_param_t in = { .flat_array = { 0 } };
    icp_qat_fw_mmp_output_param_t out = { .flat_array = { 0 } };
    CpaFlatBuffer *pUnwrapCtxBuf = NULL;
    CpaFlatBuffer *pWpkBuf = NULL;
    Cpa8U *pMemPool = NULL;
    sal_crypto_service_t *pCryptoService = NULL;

    LAC_ASSERT_NOT_NULL(pDecryptOpData);
    LAC_ASSERT_NOT_NULL(pOutputData);
    LAC_ASSERT_NOT_NULL(pKptUnwrapContext);

    pWpkBuf = getWpkFlatBuf(pDecryptOpData->pRecipientPrivateKey);
    if (NULL == pWpkBuf)
    {
        LAC_INVALID_PARAM_LOG("Invalid KPT Private Key Buffer - "
                              "pDecryptOpData->pRecipientPrivateKey");
        return CPA_STATUS_INVALID_PARAM;
    }

    wpkSizeInBytes =
        LacKptRsa_GetPrivateKeyOpSize(pDecryptOpData->pRecipientPrivateKey);
    if (LAC_KPT_PKE_INVALID_KEY_SIZE == wpkSizeInBytes)
    {
        LAC_INVALID_PARAM_LOG("Invalid KPT Wrapped Private Key Size - "
                              "pDecryptOpData->pRecipientPrivateKey");
        return CPA_STATUS_INVALID_PARAM;
    }

    functionalityId = LacPke_GetMmpId(
        wpkSizeInBytes, lacKptRsaSizeIdMap, LAC_ARRAY_LEN(lacKptRsaSizeIdMap));
    if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
    {
        LAC_INVALID_PARAM_LOG("Invalid KPT Private Key Size - "
                              "pDecryptOpData->pRecipientPrivateKey");
        return CPA_STATUS_INVALID_PARAM;
    }

    cpkSizeInBytes = LacKpt_GetCpkSize(
        wpkSizeInBytes, lacKptRsaSizeMap, LAC_ARRAY_LEN(lacKptRsaSizeMap));
    if (LAC_KPT_PKE_INVALID_KEY_SIZE == cpkSizeInBytes)
    {
        LAC_INVALID_PARAM_LOG("Invalid KPT Clear Private Key Size");
        return CPA_STATUS_INVALID_PARAM;
    }

    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    status = LacKpt_MemPoolAlloc(&pMemPool, pCryptoService->lac_pke_kpt_pool);
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Zero MSB bytes of output buffer */
        osalMemSet(pOutputData->pData,
                   0,
                   (pOutputData->dataLenInBytes - cpkSizeInBytes));

        /* Populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_kpt_rsa_dp1_512.c,
                                      &(pDecryptOpData->inputData));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_kpt_rsa_dp1_512_input_t, c)] =
            cpkSizeInBytes;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_kpt_rsa_dp1_512.kpt_wrapped,
                                      pWpkBuf);
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_kpt_rsa_dp1_512_input_t,
                                  kpt_wrapped)] = wpkSizeInBytes;

        LacKpt_BuildUnwrapCtxMemBuffer(pMemPool, pKptUnwrapContext);

        pUnwrapCtxBuf =
            (CpaFlatBuffer *)(pMemPool + LAC_KPT_UNWRAP_CTX_SIZE_IN_BYTES);
        pUnwrapCtxBuf->dataLenInBytes = LAC_KPT_UNWRAP_CTX_SIZE_IN_BYTES;
        pUnwrapCtxBuf->pData = pMemPool;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_kpt_rsa_dp1_512.kpt_unwrap_context,
                                      pUnwrapCtxBuf);
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_kpt_rsa_dp1_512_input_t,
                                  kpt_unwrap_context)] =
            LAC_KPT_UNWRAP_CTX_SIZE_IN_BYTES;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_kpt_rsa_dp1_512_input_t,
                                     kpt_unwrap_context)] = CPA_TRUE;

        /* Populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_kpt_rsa_dp1_512.m, pOutputData);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_kpt_rsa_dp1_512_output_t,
                                   m)] = cpkSizeInBytes;

        /* Populate callback data */
        cbData.pClientCb = pRsaDecryptCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pDecryptOpData;
        cbData.pOutputData1 = pOutputData;
        cbData.pOpaqueData = pMemPool;

        /* Send a PKE KPT request to the QAT */
        status = LacPkeKpt_SendSingleRequest(functionalityId,
                                             pInArgSizeList,
                                             pOutArgSizeList,
                                             &in,
                                             &out,
                                             internalMemInList,
                                             internalMemOutList,
                                             LacKptRsa_ProcessDecCb,
                                             &cbData,
                                             instanceHandle);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        /* Free memory pool entry */
        LacKpt_MemPoolFree(pMemPool);
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup Lac_KptRsa
 *     This function performs KPT RSA decryption.
 *
 *****************************************************************************/
CpaStatus cpaCyKptRsaDecrypt(const CpaInstanceHandle instanceHandle,
                             const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                             void *pCallbackTag,
                             const CpaCyKptRsaDecryptOpData *pDecryptOpData,
                             CpaFlatBuffer *pOutputData,
                             CpaCyKptUnwrapContext *pKptUnwrapContext)

{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pRsaDecryptCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pDecryptOpData,
             (LAC_ARCH_UINT)pOutputData,
             (LAC_ARCH_UINT)pKptUnwrapContext);
#endif
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_KPT_INSTANCE_HANDLE(instanceHandle);
#endif
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* Check RSA Decrypt params and return an error if invalid */
    status = LacKptRsa_DecryptParamsCheck(
        pDecryptOpData, pOutputData, pKptUnwrapContext);
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check if KPT is enabled on the service instance */
        SAL_GET_INSTANCE_CRYPTO_CAPABILITY_STATUS(status, instanceHandle, kpt);
        if (CPA_STATUS_SUCCESS != status)
            LAC_LOG_ERROR("KPT is not supported on this instance.");
    }
    /* Check if the API has been called in sync mode */
    if ((CPA_STATUS_SUCCESS == status) && (NULL == pRsaDecryptCb))
    {
        return LacKptRsa_DecryptSync(
            instanceHandle, pDecryptOpData, pOutputData, pKptUnwrapContext);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacKptRsa_Decrypt(instanceHandle,
                                   pRsaDecryptCb,
                                   pCallbackTag,
                                   pDecryptOpData,
                                   pOutputData,
                                   pKptUnwrapContext);
    }

    /* Increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_RSA_STAT_INC(numKptRsaDecryptRequests, instanceHandle);
    }
    else
    {
        LAC_RSA_STAT_INC(numKptRsaDecryptRequestErrors, instanceHandle);
    }

    return status;
}
