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
 * @file lac_rsa_keygen.c
 *
 * @ingroup LacRsa
 *
 * This file implements keygen functions for RSA.
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

#define LAC_RSA_KEYGEN_MIN_EXP -3
/**<
 *  Exponenent for key gen ops must be >= 3 */

static const Cpa32U lacRsaKp1SizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_512_BITS, PKE_RSA_KP1_512},
    {LAC_1024_BITS, PKE_RSA_KP1_1024},
    {LAC_1536_BITS, PKE_RSA_KP1_1536},
    {LAC_2048_BITS, PKE_RSA_KP1_2048},
    {LAC_3072_BITS, PKE_RSA_KP1_3072},
    {LAC_4096_BITS, PKE_RSA_KP1_4096}};
/**<
 *  Maps between operation sizes and PKE function ids */

static const Cpa32U lacRsaKp2SizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_512_BITS, PKE_RSA_KP2_512},
    {LAC_1024_BITS, PKE_RSA_KP2_1024},
    {LAC_1536_BITS, PKE_RSA_KP2_1536},
    {LAC_2048_BITS, PKE_RSA_KP2_2048},
    {LAC_3072_BITS, PKE_RSA_KP2_3072},
    {LAC_4096_BITS, PKE_RSA_KP2_4096}};
/**<
 *  Maps between operation sizes and PKE function ids */

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
 * This function performs synchronious version of the RSA Key Gen.
 */
STATIC CpaStatus LacRsa_KeyGenSync(const CpaInstanceHandle instanceHandle,
                                   const CpaCyRsaKeyGenOpData *pKeyGenData,
                                   CpaCyRsaPrivateKey *pPrivateKey,
                                   CpaCyRsaPublicKey *pPublicKey);

/*
 * This function is the synchronious callback function.
 */
STATIC
void LacRsa_KeyGenSyncCb(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey);

/*
 * This function checks the parameters for an RSA encrypt operation. It returns
 * the appropriate error in the case of null and invalid params and also
 * unsupported operations.
 */
#ifdef ICP_PARAM_CHECK
STATIC CpaStatus
LacRsa_KeyGenParamsCheck(const CpaInstanceHandle instanceHandle,
                         const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                         const CpaCyRsaKeyGenOpData *pKeyGenData,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey);
#endif

/*
 * This function is called by the pke comms module after an RSA Encrypt
 * message has been received from the QAT.
 */
STATIC void LacRsa_ProcessKeyCb(CpaStatus status,
                                CpaBoolean pass,
                                CpaInstanceHandle instanceHandle,
                                lac_pke_op_cb_data_t *pCbData);

/*
 * This function performs RSA Decrypt for type 1 private keys.
 */
STATIC CpaStatus LacRsa_Type1KeyGen(const CpaInstanceHandle instanceHandle,
                                    const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                                    void *pCallbackTag,
                                    const CpaCyRsaKeyGenOpData *pKeyGenData,
                                    CpaCyRsaPrivateKey *pPrivateKey,
                                    CpaCyRsaPublicKey *pPublicKey);

/*
 * This function performs RSA Decrypt for type 2 private keys.
 */
STATIC CpaStatus LacRsa_Type2KeyGen(const CpaInstanceHandle instanceHandle,
                                    const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                                    void *pCallbackTag,
                                    const CpaCyRsaKeyGenOpData *pKeyGenData,
                                    CpaCyRsaPrivateKey *pPrivateKey,
                                    CpaCyRsaPublicKey *pPublicKey);

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/*
********************************************************************************
* Define static function definitions
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
CpaStatus cpaCyRsaGenKey(const CpaInstanceHandle instanceHandle_in,
                         const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                         void *pCallbackTag,
                         const CpaCyRsaKeyGenOpData *pKeyGenData,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pRsaKeyGenCb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pKeyGenData,
             (LAC_ARCH_UINT)pPrivateKey,
             (LAC_ARCH_UINT)pPublicKey);
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
    if (NULL == pRsaKeyGenCb)
    {
        return LacRsa_KeyGenSync(
            instanceHandle, pKeyGenData, pPrivateKey, pPublicKey);
    }
#ifdef ICP_PARAM_CHECK
    /* Check RSA KeyGen params and return an error if invalid */
    status = LacRsa_KeyGenParamsCheck(
        instanceHandle, pRsaKeyGenCb, pKeyGenData, pPrivateKey, pPublicKey);
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 == pKeyGenData->privateKeyRepType)
        {
            status = LacRsa_Type1KeyGen(instanceHandle,
                                        pRsaKeyGenCb,
                                        pCallbackTag,
                                        pKeyGenData,
                                        pPrivateKey,
                                        pPublicKey);
        }
        else /* Must be type2 key as param check has passed */
        {
            status = LacRsa_Type2KeyGen(instanceHandle,
                                        pRsaKeyGenCb,
                                        pCallbackTag,
                                        pKeyGenData,
                                        pPrivateKey,
                                        pPublicKey);
        }
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_RSA_STAT_INC(numRsaKeyGenRequests, instanceHandle);
    }
    else
    {
        LAC_RSA_STAT_INC(numRsaKeyGenRequestErrors, instanceHandle);
    }

    return status;
}

STATIC
void LacRsa_KeyGenSyncCb(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey)
{
    LacSync_GenWakeupSyncCaller(pCallbackTag, status);
}

STATIC CpaStatus LacRsa_KeyGenSync(const CpaInstanceHandle instanceHandle,
                                   const CpaCyRsaKeyGenOpData *pKeyGenData,
                                   CpaCyRsaPrivateKey *pPrivateKey,
                                   CpaCyRsaPublicKey *pPublicKey)
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
        status = cpaCyRsaGenKey(instanceHandle,
                                LacRsa_KeyGenSyncCb,
                                pSyncCallbackData,
                                pKeyGenData,
                                pPrivateKey,
                                pPublicKey);
    }
    else
    {
        LAC_RSA_STAT_INC(numRsaKeyGenRequestErrors, instanceHandle);
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
            LAC_RSA_STAT_INC(numRsaKeyGenCompletedErrors, instanceHandle);
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
CpaStatus LacRsa_KeyGenParamsCheck(const CpaInstanceHandle instanceHandle,
                                   const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                                   const CpaCyRsaKeyGenOpData *pKeyGenData,
                                   CpaCyRsaPrivateKey *pPrivateKey,
                                   CpaCyRsaPublicKey *pPublicKey)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U opSizeInBytes = 0;
    Cpa32U byteLenP = 0;
    Cpa32U byteLenQ = 0;

    LAC_CHECK_NULL_PARAM(pRsaKeyGenCb);

    /* Check user parameters */
    LAC_CHECK_NULL_PARAM(pKeyGenData);
    LAC_CHECK_NULL_PARAM(pPrivateKey);
    LAC_CHECK_NULL_PARAM(pPublicKey);
    LAC_CHECK_FLAT_BUFFER(&pKeyGenData->prime1P);
    LAC_CHECK_FLAT_BUFFER(&pKeyGenData->prime2Q);

    /* Get size in bytes based on MS byte - msb validated later */
    byteLenP = LacPke_GetMinBytes(&(pKeyGenData->prime1P));
    byteLenQ = LacPke_GetMinBytes(&(pKeyGenData->prime2Q));
    if (byteLenP != byteLenQ)
    {
        LAC_INVALID_PARAM_LOG("Invalid (p,q) pair");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* opSize = byteLenP + byteLenQ */
    opSizeInBytes = byteLenP << 1;
    if (pKeyGenData->modulusLenInBytes != opSizeInBytes)
    {
        LAC_INVALID_PARAM_LOG("Invalid (n,p,q) set");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_FALSE == LacRsa_IsValidRsaSize(opSizeInBytes))
    {
        LAC_INVALID_PARAM_LOG("Invalid pKeyGenData->modulusLenInBytes Size. ");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Complete check of p and q buffers - msb and lsb check */
    LAC_CHECK_FLAT_BUFFER_MSB_LSB(
        &(pKeyGenData->prime1P), byteLenP, CPA_TRUE, CPA_TRUE);
    LAC_CHECK_FLAT_BUFFER_MSB_LSB(
        &(pKeyGenData->prime2Q), byteLenQ, CPA_TRUE, CPA_TRUE);

    if ((CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 != pKeyGenData->privateKeyRepType) &&
        (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2 != pKeyGenData->privateKeyRepType))
    {
        LAC_INVALID_PARAM_LOG("Invalid pKeyGenData->privateKeyRepType. ");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check input buffers */
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(&(pKeyGenData->publicExponentE),
                                    CHECK_LESS_EQUALS,
                                    opSizeInBytes,
                                    CPA_TRUE);

    /* Check the output buffers - ensure they are valid and large enough */
    /* Check public key */
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pPublicKey->modulusN), CHECK_GREATER_EQUALS, opSizeInBytes);

    /* Check private key */
    if (CPA_CY_RSA_VERSION_TWO_PRIME != pPrivateKey->version)
    {
        LAC_INVALID_PARAM_LOG("Invalid pPrivateKey->version");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pPrivateKey->privateKeyRepType != pKeyGenData->privateKeyRepType)
    {
        LAC_INVALID_PARAM_LOG("Invalid pPrivateKey->privateKeyRepType. ");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* For both key representations modulusN and ExponentD are generated */
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pPrivateKey->privateKeyRep1.modulusN),
                                CHECK_GREATER_EQUALS,
                                opSizeInBytes);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pPrivateKey->privateKeyRep1.privateExponentD),
                                CHECK_GREATER_EQUALS,
                                opSizeInBytes);

    /* For type 2 key additional output buffers to check */
    if (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2 == pKeyGenData->privateKeyRepType)
    {
        /* For KeyGen we do not output P and Q so no need to check these
           buffers */
        LAC_CHECK_FLAT_BUFFER_PARAM(&(pPrivateKey->privateKeyRep2.exponent1Dp),
                                    CHECK_GREATER_EQUALS,
                                    byteLenP);
        LAC_CHECK_FLAT_BUFFER_PARAM(&(pPrivateKey->privateKeyRep2.exponent2Dq),
                                    CHECK_GREATER_EQUALS,
                                    byteLenP);
        LAC_CHECK_FLAT_BUFFER_PARAM(
            &(pPrivateKey->privateKeyRep2.coefficientQInv),
            CHECK_GREATER_EQUALS,
            byteLenP);
    }

    /* Standards based check: e >= 3 */
    if (LacPke_CompareZero(&(pKeyGenData->publicExponentE),
                           LAC_RSA_KEYGEN_MIN_EXP) < 0)
    {
        LAC_INVALID_PARAM_LOG("publicExponentE must be >= 3");
        return CPA_STATUS_INVALID_PARAM;
    }

    return status;
}
#endif

CpaStatus LacRsa_Type1KeyGen(const CpaInstanceHandle instanceHandle,
                             const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                             void *pCallbackTag,
                             const CpaCyRsaKeyGenOpData *pKeyGenData,
                             CpaCyRsaPrivateKey *pPrivateKey,
                             CpaCyRsaPublicKey *pPublicKey)
{
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    Cpa32U opSizeInBytes = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_pke_op_cb_data_t cbData = {0};
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};

    LAC_ASSERT_NOT_NULL(pKeyGenData);
    LAC_CHECK_FLAT_BUFFER(&pKeyGenData->prime1P);
    LAC_CHECK_FLAT_BUFFER(&pKeyGenData->prime2Q);

    /* Get size in bytes based on MS byte */
    opSizeInBytes = LacPke_GetMinBytes(&(pKeyGenData->prime1P));
    /* Byte length of P and Q are equal therefore we can double */
    opSizeInBytes = opSizeInBytes << 1;

    functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                      lacRsaKp1SizeIdMap,
                                      LAC_ARRAY_LEN(lacRsaKp1SizeIdMap));
    if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
    {
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Zero ms bytes of output buffers */
        osalMemSet(pPublicKey->modulusN.pData,
                   0,
                   (pPublicKey->modulusN.dataLenInBytes - opSizeInBytes));

        osalMemSet(
            pPrivateKey->privateKeyRep1.privateExponentD.pData,
            0,
            (pPrivateKey->privateKeyRep1.privateExponentD.dataLenInBytes -
             opSizeInBytes));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_kp1_1024.p,
                                      &(pKeyGenData->prime1P));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_input_t, p)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_kp1_1024.q,
                                      &(pKeyGenData->prime2Q));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_input_t, q)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_kp1_1024.e,
                                      &(pPublicKey->publicExponentE));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_input_t, e)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_input_t, e)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_rsa_kp1_1024.n,
                                      &(pPublicKey->modulusN));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_output_t, n)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_output_t, n)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            out.mmp_rsa_kp1_1024.d,
            &(pPrivateKey->privateKeyRep1.privateExponentD));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_output_t, d)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_output_t, d)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pRsaKeyGenCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pKeyGenData;
        cbData.pOutputData1 = pPrivateKey;
        cbData.pOutputData2 = pPublicKey;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &in,
                                          &out,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacRsa_ProcessKeyCb,
                                          &cbData,
                                          instanceHandle);

        /* @performance
         * the in and out structures are allocated on the stack. This forces #
         * the underlying function to allocate and copy. why not allocate
         * nicely aligned in and out structures ? (this is a general comment
         * for all functions)*/
    }

    return status;
}

CpaStatus LacRsa_Type2KeyGen(const CpaInstanceHandle instanceHandle,
                             const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                             void *pCallbackTag,
                             const CpaCyRsaKeyGenOpData *pKeyGenData,
                             CpaCyRsaPrivateKey *pPrivateKey,
                             CpaCyRsaPublicKey *pPublicKey)
{
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    Cpa32U opSizeInBytes = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_pke_op_cb_data_t cbData = {0};
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};

    LAC_ASSERT_NOT_NULL(pKeyGenData);
    LAC_CHECK_FLAT_BUFFER(&pKeyGenData->prime1P);
    LAC_CHECK_FLAT_BUFFER(&pKeyGenData->prime2Q);

    /* Get size in bytes based on MSB */
    opSizeInBytes = LacPke_GetMinBytes(&(pKeyGenData->prime1P));
    /* Byte length of P and Q are equal therefore we can double */
    opSizeInBytes = opSizeInBytes << 1;

    functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                      lacRsaKp2SizeIdMap,
                                      LAC_ARRAY_LEN(lacRsaKp2SizeIdMap));
    if (LAC_PKE_INVALID_FUNC_ID == functionalityId)
    {
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* Zero ms bytes of output buffers */
        osalMemSet(pPublicKey->modulusN.pData,
                   0,
                   (pPublicKey->modulusN.dataLenInBytes - opSizeInBytes));
        osalMemSet(
            pPrivateKey->privateKeyRep1.privateExponentD.pData,
            0,
            (pPrivateKey->privateKeyRep1.privateExponentD.dataLenInBytes -
             opSizeInBytes));
        osalMemSet(pPrivateKey->privateKeyRep2.exponent1Dp.pData,
                   0,
                   (pPrivateKey->privateKeyRep2.exponent1Dp.dataLenInBytes -
                    LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes)));
        osalMemSet(pPrivateKey->privateKeyRep2.exponent2Dq.pData,
                   0,
                   (pPrivateKey->privateKeyRep2.exponent2Dq.dataLenInBytes -
                    LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes)));
        osalMemSet(pPrivateKey->privateKeyRep2.coefficientQInv.pData,
                   0,
                   (pPrivateKey->privateKeyRep2.coefficientQInv.dataLenInBytes -
                    LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes)));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_kp2_1024.p,
                                      &(pKeyGenData->prime1P));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_input_t, p)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_kp2_1024.q,
                                      &(pKeyGenData->prime2Q));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_input_t, q)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_rsa_kp2_1024.e,
                                      &(pPublicKey->publicExponentE));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_input_t, e)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_input_t, e)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_rsa_kp2_1024.n,
                                      &(pPublicKey->modulusN));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, n)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, n)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            out.mmp_rsa_kp2_1024.d,
            &(pPrivateKey->privateKeyRep1.privateExponentD));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, d)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, d)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            out.mmp_rsa_kp2_1024.dp,
            &(pPrivateKey->privateKeyRep2.exponent1Dp));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, dp)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, dp)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            out.mmp_rsa_kp2_1024.dq,
            &(pPrivateKey->privateKeyRep2.exponent2Dq));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, dq)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, dq)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(
            out.mmp_rsa_kp2_1024.qinv,
            &(pPrivateKey->privateKeyRep2.coefficientQInv));
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, qinv)] =
            LAC_RSA_TYPE_2_BUF_SIZE_GET(opSizeInBytes);
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_output_t, qinv)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pRsaKeyGenCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pKeyGenData;
        cbData.pOutputData1 = pPrivateKey;
        cbData.pOutputData2 = pPublicKey;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &in,
                                          &out,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacRsa_ProcessKeyCb,
                                          &cbData,
                                          instanceHandle);
    }

    return status;
}

void LacRsa_ProcessKeyCb(CpaStatus status,
                         CpaBoolean pass,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyRsaKeyGenCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyRsaKeyGenOpData *pOpData = NULL;
    CpaCyRsaPrivateKey *pPrivateKey = NULL;
    CpaCyRsaPublicKey *pPublicKey = NULL;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;

    pOpData =
        (CpaCyRsaKeyGenOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    LAC_ASSERT_NOT_NULL(pOpData);

    pCb = (CpaCyRsaKeyGenCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);

    pPrivateKey = (CpaCyRsaPrivateKey *)pCbData->pOutputData1;
    pPublicKey = (CpaCyRsaPublicKey *)pCbData->pOutputData2;
    LAC_ASSERT_NOT_NULL(pPrivateKey);
    LAC_ASSERT_NOT_NULL(pPublicKey);

    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_FALSE == pass)
        {
            LAC_LOG_ERROR(
                "Cannot generate a valid RSA public key from provided "
                "e, p, and q input parameters");
            status = CPA_STATUS_FAIL;
        }
    }

    /* Standards based checks on the public key */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* n must have one of the two most sig bits set and e < n */
        if (!(pPublicKey->modulusN.pData[pPublicKey->modulusN.dataLenInBytes -
                                         pOpData->modulusLenInBytes] &
              0xC0))
        {
            LAC_LOG_ERROR("The number n = p * q is out of range or invalid");
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (LacPke_Compare(
                &(pOpData->publicExponentE), 0, &(pPublicKey->modulusN), 0) >=
            0)
        {
            LAC_INVALID_PARAM_LOG("(e,n) is not a valid RSA public key n <= e");
            status = CPA_STATUS_FAIL;
        }
    }

    /* Private key - need to copy modulusN */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pPrivateKey->privateKeyRep1.modulusN.pData,
               pPublicKey->modulusN.pData,
               pPublicKey->modulusN.dataLenInBytes);
    }

    /* increment stats */
    LAC_RSA_STAT_INC(numRsaKeyGenCompleted, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_RSA_STAT_INC(numRsaKeyGenCompletedErrors, instanceHandle);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pPrivateKey, pPublicKey);
}
