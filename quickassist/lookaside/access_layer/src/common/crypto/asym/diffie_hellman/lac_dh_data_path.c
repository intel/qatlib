/******************************************************************************
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
 *****************************************************************************/

/**
 *****************************************************************************
 *
 * @file lac_dh_data_path.c
 *
 * @defgroup LacDh Diffie Hellman
 *
 * @ingroup LacAsym
 *
 * diffie hellman data path functions
 *
 * @lld_start
 *
 * @lld_overview
 * This is the Diffie Hellman feature implementation.  It implements 2 DH API
 * services: phase 1 and phase 2.  Statistics are maintained for each service.
 * For each service the parameters supplied by the client are checked, and then
 * input/output argument lists are constructed before calling the pke comms
 * layer.
 *
 * The service implementations are a straightforward
 * marshalling of client-supplied parameters for the QAT. I.e. there is
 * minimal logic handled by this component.  Buffer alignment is handled by
 * the PKE QAT Comms layer.
 *
 * The user's input buffers are checked for null params, correct length, msb
 * and lsb set where necessary. The following parameter checks based on the
 * standard are also performed for Diffie Hellman
 *
 *
 * Diffie Hellman:
 * Phase 1:    y = g^x mod p   (PKCS #3)
 *
 *           Test: P must have msb set
 *           Test: P must be odd
 *           Test:  0  < g < p
 *           Test:  0  < x < p-1
 *
 * Phase 2:   z = y^x mod p  (PKCS #3)
 *
 *           Test: P must have msb set
 *           Test: P must be odd
 *           Test:  0  <  x  < p-1
 *
 * @lld_dependencies
 * - @ref LacAsymCommonQatComms "PKE QAT Comms" : For creating and sending
 * messages to the QAT
 * - @ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @lld_initialisation
 * On instance initialization this component clears the stats.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

/* API Includes */
#include "cpa.h"
#include "cpa_cy_dh.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/

/* OSAL Includes */
#include "Osal.h"

/* FW includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"

/* ADF includes */
#include "icp_accel_devices.h"
#include "icp_adf_init.h"
#include "icp_adf_debug.h"
#include "icp_adf_transport.h"

/* Look Aside Includes */
#include "lac_log.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_sync.h"
#include "lac_sym.h"
#include "lac_list.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "lac_dh_stats_p.h"

/**
 ******************************************************************************
 * @ingroup LacDh
 * @description
 *      This enum lists the types of diffie hellman operation.
 *****************************************************************************/
typedef enum
{
    LAC_DH_OP = 0,
    /**< Diffie Hellman operation */
    LAC_DH_G2_OP
    /**< Diffie Hellman operation when exp = 2 */
} lac_dh_op_type_t;

/*
*******************************************************************************
* Static Variables
*******************************************************************************
*/

#define LAC_G2_DELTA (-2)
/**< @ingroup LacDh
 *  the delta to be subtracted from the exponent when testing for
 *  g2 type operation */

/* Maps between operation sizes and PKE function ids */
static const Cpa32U lacDHSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_768_BITS, PKE_DH_768},
    {LAC_1024_BITS, PKE_DH_1024},
    {LAC_1536_BITS, PKE_DH_1536},
    {LAC_2048_BITS, PKE_DH_2048},
    {LAC_3072_BITS, PKE_DH_3072},
    {LAC_4096_BITS, PKE_DH_4096},
    {LAC_8192_BITS, PKE_DH_8192}};

/* Maps between operation sizes and PKE function ids */
static const Cpa32U lacDHG2SizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_768_BITS, PKE_DH_G2_768},
    {LAC_1024_BITS, PKE_DH_G2_1024},
    {LAC_1536_BITS, PKE_DH_G2_1536},
    {LAC_2048_BITS, PKE_DH_G2_2048},
    {LAC_3072_BITS, PKE_DH_G2_3072},
    {LAC_4096_BITS, PKE_DH_G2_4096},
    {LAC_8192_BITS, PKE_DH_G2_8192}};
/*
*******************************************************************************
* Define static function definitions
*******************************************************************************
*/

/*
 * This function verifies that all the input parameters for the Diffie Hellman
 * Phase 1 operation are valid and also returns the opSize in bytes
 */
STATIC CpaStatus LacDh_Phase1GetOpSizeAndCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyGenFlatBufCbFunc pDhPhase1Cb,
    const CpaCyDhPhase1KeyGenOpData *pPhase1KeyGenData,
    CpaFlatBuffer *pLocalOctetStringPV,
    Cpa32U *pOpSizeInBytes);

/*
 * This function verifies that all the input parameters for the Diffie Hellman
 * Phase 2 operation are valid and also returns the opSize in Bytes
 */
STATIC CpaStatus LacDh_Phase2GetOpSizeAndCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyGenFlatBufCbFunc pDhPhase2Cb,
    const CpaCyDhPhase2SecretKeyGenOpData *pPhase2SecretKeyGenData,
    CpaFlatBuffer *pOctetStringSecretKey,
    Cpa32U *pOpSizeInBytes);

/*
 * This function is called after a Diffie Hellman
 * Phase1 message has been received from the QAT.
 */
STATIC void LacDh_ProcessPhase1Cb(CpaStatus status,
                                  CpaBoolean pass,
                                  CpaInstanceHandle instanceHandle,
                                  lac_pke_op_cb_data_t *pCbData);

/*
 * This function is called after a Diffie Hellman
 * Phase2 message has been received from the QAT.
 */
STATIC void LacDh_ProcessPhase2Cb(CpaStatus status,
                                  CpaBoolean pass,
                                  CpaInstanceHandle instanceHandle,
                                  lac_pke_op_cb_data_t *pCbData);

/*
 * This function is the synchronous version of cpaCyDhKeyGenPhase1
 */
STATIC CpaStatus
LacDh_SynKeyGenPhase1(const CpaInstanceHandle instanceHandle,
                      const CpaCyDhPhase1KeyGenOpData *pPhase1KeyGenData,
                      CpaFlatBuffer *pLocalOctetStringPV);

/*
 * This function is the synchronous version of cpaCyDhKeyGenPhase2Secret
 */
STATIC CpaStatus LacDh_SynKeyGenPhase2Secret(
    const CpaInstanceHandle instanceHandle,
    const CpaCyDhPhase2SecretKeyGenOpData *pPhase2SecretKeyGenData,
    CpaFlatBuffer *pOctetStringSecretKey);

/*
*******************************************************************************
* Global Variables
*******************************************************************************
*/

/*
*******************************************************************************
* Define public/global function definitions
*******************************************************************************
*/

#ifdef ICP_PARAM_CHECK
STATIC CpaBoolean LacDh_IsValidDhSize(Cpa32U opSizeInBytes)
{
    Cpa32U opSizeInBits = LAC_BYTES_TO_BITS(opSizeInBytes);

    if ((LAC_768_BITS != opSizeInBits) && (LAC_1024_BITS != opSizeInBits) &&
        (LAC_1536_BITS != opSizeInBits) && (LAC_2048_BITS != opSizeInBits) &&
        (LAC_3072_BITS != opSizeInBits) && (LAC_4096_BITS != opSizeInBits) &&
        (LAC_8192_BITS != opSizeInBits))
    {
        LAC_INVALID_PARAM_LOG(
            "Invalid operation size. Valid op sizes for "
            "DH are 768, 1024, 1536, 2048, 3072, 4096 and 8192 bits.");
        return CPA_FALSE;
    }

    return CPA_TRUE;
}
#endif

STATIC lac_dh_op_type_t LacDh_GetDhOpType(const CpaFlatBuffer *pExp)
{
    LAC_ASSERT_NOT_NULL(pExp);

    /* if exp is equal to 2 then return op type G2, otherwise normal DH op */
    if (0 == LacPke_CompareZero(pExp, LAC_G2_DELTA))
    {
        return LAC_DH_G2_OP;
    }
    return LAC_DH_OP;
}

STATIC CpaStatus
LacDh_SynKeyGenPhase1(const CpaInstanceHandle instanceHandle,
                      const CpaCyDhPhase1KeyGenOpData *pPhase1KeyGenData,
                      CpaFlatBuffer *pLocalOctetStringPV)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDhKeyGenPhase1(instanceHandle,
                                     LacSync_GenFlatBufCb,
                                     pSyncCallbackData,
                                     pPhase1KeyGenData,
                                     pLocalOctetStringPV);
    }
    else
    {
        LAC_DH_STAT_INC(numDhPhase1KeyGenRequestErrors, instanceHandle);
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
            LAC_DH_STAT_INC(numDhPhase1KeyGenCompletedErrors, instanceHandle);
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

STATIC CpaStatus LacDh_SynKeyGenPhase2Secret(
    const CpaInstanceHandle instanceHandle,
    const CpaCyDhPhase2SecretKeyGenOpData *pPhase2SecretKeyGenData,
    CpaFlatBuffer *pOctetStringSecretKey)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDhKeyGenPhase2Secret(instanceHandle,
                                           LacSync_GenFlatBufCb,
                                           pSyncCallbackData,
                                           pPhase2SecretKeyGenData,
                                           pOctetStringSecretKey);
    }
    else
    {
        LAC_DH_STAT_INC(numDhPhase2KeyGenRequestErrors, instanceHandle);
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
            LAC_DH_STAT_INC(numDhPhase2KeyGenCompletedErrors, instanceHandle);
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

/**
 *****************************************************************************
 * @ingroup LacDh
 *
 *****************************************************************************/
CpaStatus cpaCyDhKeyGenPhase1(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyGenFlatBufCbFunc pDhPhase1Cb,
    void *pCallbackTag,
    const CpaCyDhPhase1KeyGenOpData *pPhase1KeyGenData,
    CpaFlatBuffer *pLocalOctetStringPV)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U opSizeInBytes = 0;
    lac_pke_op_cb_data_t cbData = {0};
    lac_dh_op_type_t opType = LAC_DH_OP;

#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pDhPhase1Cb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pPhase1KeyGenData,
             (LAC_ARCH_UINT)pLocalOctetStringPV);
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in synchronous mode */
    if (NULL == pDhPhase1Cb)
    {
        return LacDh_SynKeyGenPhase1(
            instanceHandle, pPhase1KeyGenData, pLocalOctetStringPV);
    }

    /* Get the opSize and check the members of the key gen data struct */
    status = LacDh_Phase1GetOpSizeAndCheck(instanceHandle,
                                           pDhPhase1Cb,
                                           pPhase1KeyGenData,
                                           pLocalOctetStringPV,
                                           &opSizeInBytes);

    if (CPA_STATUS_SUCCESS == status)
    {
        opType = LacDh_GetDhOpType(
            (const CpaFlatBuffer *)&(pPhase1KeyGenData->baseG));

        /* Zero ms bytes of the output buffer - assumes size of output buffer is
           greater or equal to sizeInBytes */
        osalMemSet(pLocalOctetStringPV->pData,
                   0,
                   (pLocalOctetStringPV->dataLenInBytes - opSizeInBytes));

        if (LAC_DH_OP == opType)
        {
            functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                              lacDHSizeIdMap,
                                              LAC_ARRAY_LEN(lacDHSizeIdMap));

            /* Fill out input lists - we use mmp_dh_768 for all
               functionalityIds - checked at compile time (see
               lac_dh_intereface_check.c) that this is a valid assumption */
            LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_dh_768.g,
                                          &(pPhase1KeyGenData->baseG));
            pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, g)] =
                opSizeInBytes;
            internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, g)] =
                CPA_FALSE;
            LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_dh_768.e,
                                          &(pPhase1KeyGenData->privateValueX));
            pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, e)] =
                opSizeInBytes;
            internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, e)] =
                CPA_FALSE;

            LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_dh_768.m,
                                          &(pPhase1KeyGenData->primeP));
            pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, m)] =
                opSizeInBytes;
            internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, m)] =
                CPA_FALSE;
            /* Fill out output lists */
            LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_dh_768.r,
                                          pLocalOctetStringPV);
            pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_output_t, r)] =
                opSizeInBytes;
            internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_dh_output_t, r)] =
                CPA_FALSE;
        }
        else
        {
            /* opType == LAC_DH_G2_OP */
            functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                              lacDHG2SizeIdMap,
                                              LAC_ARRAY_LEN(lacDHG2SizeIdMap));

            /* Fill out input lists */
            LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_dh_g2_768.e,
                                          &(pPhase1KeyGenData->privateValueX));
            pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_input_t, e)] =
                opSizeInBytes;
            internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_input_t, e)] =
                CPA_FALSE;
            LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_dh_g2_768.m,
                                          &(pPhase1KeyGenData->primeP));
            pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_input_t, m)] =
                opSizeInBytes;
            internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_input_t, m)] =
                CPA_FALSE;

            /* Fill out Output List */
            LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_dh_g2_768.r,
                                          pLocalOctetStringPV);
            pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_output_t, r)] =
                opSizeInBytes;
            internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_output_t, r)] =
                CPA_FALSE;
        }

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pPhase1KeyGenData;
        cbData.pClientCb = pDhPhase1Cb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pLocalOctetStringPV;
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacDh_ProcessPhase1Cb,
                                          &cbData,
                                          instanceHandle);
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_DH_STAT_INC(numDhPhase1KeyGenRequestErrors, instanceHandle);
    }
    else
    {
        LAC_DH_STAT_INC(numDhPhase1KeyGenRequests, instanceHandle);
    }
    return status;
}

CpaStatus LacDh_Phase1GetOpSizeAndCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyGenFlatBufCbFunc pDhPhase1Cb,
    const CpaCyDhPhase1KeyGenOpData *pPhase1KeyGenData,
    CpaFlatBuffer *pLocalOctetStringPV,
    Cpa32U *pOpSizeInBytes)
{

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDhPhase1Cb);

    /* Check members of pPhase1KeyGenData are valid. Check pPrimeP, pBaseG,
     * pLocalOctetStringPV and pPrivateValueX */
    LAC_CHECK_NULL_PARAM(pPhase1KeyGenData);
    LAC_CHECK_NULL_PARAM(pLocalOctetStringPV);
    LAC_CHECK_FLAT_BUFFER(&pPhase1KeyGenData->primeP);
#endif

    /* Set the opSizeInBytes */
    *pOpSizeInBytes = LacPke_GetMinBytes(&(pPhase1KeyGenData->primeP));

#ifdef ICP_PARAM_CHECK
    if (CPA_FALSE == LacDh_IsValidDhSize((*pOpSizeInBytes)))
    {
        LAC_INVALID_PARAM_LOG("Invalid size for opSizeInBytes");
        return CPA_STATUS_INVALID_PARAM;
    }
    /* Check that the MSB and LSB of the prime buffer is set */
    LAC_CHECK_FLAT_BUFFER_MSB_LSB(
        &(pPhase1KeyGenData->primeP), (*pOpSizeInBytes), CPA_TRUE, CPA_TRUE);

    /* Check other input buffers for NULL and zero-len */
    LAC_CHECK_FLAT_BUFFER_PARAM(&pPhase1KeyGenData->baseG, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &pPhase1KeyGenData->privateValueX, CHECK_NONE, 0);

    /* output params  - based on buffer size */
    LAC_CHECK_FLAT_BUFFER_PARAM(
        pLocalOctetStringPV, CHECK_GREATER_EQUALS, (*pOpSizeInBytes));

    /* Standards based checks */
    /* 0 < g < p */
    LAC_CHECK_NON_ZERO_PARAM(&(pPhase1KeyGenData->baseG));
    if (LacPke_Compare(
            &(pPhase1KeyGenData->baseG), 0, &(pPhase1KeyGenData->primeP), 0) >=
        0)
    {
        LAC_INVALID_PARAM_LOG("baseG must be < primeP");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* 0 < x < p-1 */
    LAC_CHECK_NON_ZERO_PARAM(&(pPhase1KeyGenData->privateValueX));
    if (LacPke_Compare(&(pPhase1KeyGenData->privateValueX),
                       0,
                       &(pPhase1KeyGenData->primeP),
                       -1) >= 0)
    {
        LAC_INVALID_PARAM_LOG("privateValueX must be < primeP - 1");
        return CPA_STATUS_INVALID_PARAM;
    }

#endif
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup LacDh
 *
 *****************************************************************************/
CpaStatus cpaCyDhKeyGenPhase2Secret(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyGenFlatBufCbFunc pDhPhase2Cb,
    void *pCallbackTag,
    const CpaCyDhPhase2SecretKeyGenOpData *pPhase2SecretKeyGenData,
    CpaFlatBuffer *pOctetStringSecretKey)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    Cpa32U pInArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U pOutArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    icp_qat_fw_mmp_input_param_t inArgList = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outArgList = {.flat_array = {0}};
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    lac_pke_op_cb_data_t cbData = {0};
    Cpa32U opSizeInBytes = 0;

#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pDhPhase2Cb,
             (LAC_ARCH_UINT)pCallbackTag,
             (LAC_ARCH_UINT)pPhase2SecretKeyGenData,
             (LAC_ARCH_UINT)pOctetStringSecretKey);
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

    /* Check if the API has been called in synchronous mode */
    if (NULL == pDhPhase2Cb)
    {
        return LacDh_SynKeyGenPhase2Secret(
            instanceHandle, pPhase2SecretKeyGenData, pOctetStringSecretKey);
    }

    /* Get the opSize and check the members of the key gen data struct */
    status = LacDh_Phase2GetOpSizeAndCheck(instanceHandle,
                                           pDhPhase2Cb,
                                           pPhase2SecretKeyGenData,
                                           pOctetStringSecretKey,
                                           &opSizeInBytes);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Always use LAC_DH_OP service for Phase2 */
        functionalityId = LacPke_GetMmpId(LAC_BYTES_TO_BITS(opSizeInBytes),
                                          lacDHSizeIdMap,
                                          LAC_ARRAY_LEN(lacDHSizeIdMap));

        /* Fill out input lists */
        LAC_MEM_SHARED_WRITE_FROM_PTR(
            inArgList.mmp_dh_768.g,
            &(pPhase2SecretKeyGenData->remoteOctetStringPV));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, g)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, g)] = CPA_FALSE;
        LAC_MEM_SHARED_WRITE_FROM_PTR(
            inArgList.mmp_dh_768.e, &(pPhase2SecretKeyGenData->privateValueX));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, e)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, e)] = CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(inArgList.mmp_dh_768.m,
                                      &(pPhase2SecretKeyGenData->primeP));
        pInArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, m)] =
            opSizeInBytes;
        internalMemInList[LAC_IDX_OF(icp_qat_fw_mmp_dh_input_t, m)] = CPA_FALSE;
        /* Fill out output lists */
        LAC_MEM_SHARED_WRITE_FROM_PTR(outArgList.mmp_dh_768.r,
                                      pOctetStringSecretKey);
        pOutArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dh_output_t, r)] =
            opSizeInBytes;
        internalMemOutList[LAC_IDX_OF(icp_qat_fw_mmp_dh_output_t, r)] =
            CPA_FALSE;

        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pPhase2SecretKeyGenData;
        cbData.pClientCb = pDhPhase2Cb;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pOctetStringSecretKey;
        status = LacPke_SendSingleRequest(functionalityId,
                                          pInArgSizeList,
                                          pOutArgSizeList,
                                          &inArgList,
                                          &outArgList,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacDh_ProcessPhase2Cb,
                                          &cbData,
                                          instanceHandle);
    }

    /* if any of the preceding steps failed then we need to perform clean up */
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_DH_STAT_INC(numDhPhase2KeyGenRequestErrors, instanceHandle);
    }
    else
    {
        LAC_DH_STAT_INC(numDhPhase2KeyGenRequests, instanceHandle);
    }
    return status;
}

STATIC CpaStatus LacDh_Phase2GetOpSizeAndCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyGenFlatBufCbFunc pDhPhase2Cb,
    const CpaCyDhPhase2SecretKeyGenOpData *pPhase2SecretKeyGenData,
    CpaFlatBuffer *pOctetStringSecretKey,
    Cpa32U *pOpSizeInBytes)
{

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDhPhase2Cb);

    LAC_CHECK_NULL_PARAM(pPhase2SecretKeyGenData);
    LAC_CHECK_NULL_PARAM(pOctetStringSecretKey);
    LAC_CHECK_FLAT_BUFFER(&pPhase2SecretKeyGenData->primeP);
#endif

    *pOpSizeInBytes = LacPke_GetMinBytes(&(pPhase2SecretKeyGenData->primeP));

#ifdef ICP_PARAM_CHECK
    if (CPA_FALSE == LacDh_IsValidDhSize((*pOpSizeInBytes)))
    {
        LAC_INVALID_PARAM_LOG("Invalid size for opSizeInBytes");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that the MSB and LSB of the prime buffer is set */
    LAC_CHECK_FLAT_BUFFER_MSB_LSB(&(pPhase2SecretKeyGenData->primeP),
                                  (*pOpSizeInBytes),
                                  CPA_TRUE,
                                  CPA_TRUE);

    /* Check remoteOctetStringPV */
    LAC_CHECK_FLAT_BUFFER_PARAM_PKE(
        &(pPhase2SecretKeyGenData->remoteOctetStringPV),
        CHECK_LESS_EQUALS,
        (*pOpSizeInBytes),
        CPA_FALSE);

    /* Check privateValueX for NULL and zero-len */
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &pPhase2SecretKeyGenData->privateValueX, CHECK_NONE, 0);

    /* output params */
    LAC_CHECK_FLAT_BUFFER_PARAM(
        pOctetStringSecretKey, CHECK_GREATER_EQUALS, (*pOpSizeInBytes));

    /* Standards based checks */
    /* 0 < x < p-1 */
    LAC_CHECK_NON_ZERO_PARAM(&(pPhase2SecretKeyGenData->privateValueX));
    if (LacPke_Compare(&(pPhase2SecretKeyGenData->privateValueX),
                       0,
                       &(pPhase2SecretKeyGenData->primeP),
                       -1) >= 0)
    {
        LAC_INVALID_PARAM_LOG("privateValueX must be < primeP - 1");
        return CPA_STATUS_INVALID_PARAM;
    }

#endif
    return CPA_STATUS_SUCCESS;
}

void LacDh_ProcessPhase1Cb(CpaStatus status,
                           CpaBoolean pass,
                           CpaInstanceHandle instanceHandle,
                           lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDhPhase1KeyGenOpData *pOpData = NULL;
    CpaFlatBuffer *pLocalOctetStringPV = NULL;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData =
        (CpaCyDhPhase1KeyGenOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pLocalOctetStringPV = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pLocalOctetStringPV);

    /* increment stats */
    LAC_DH_STAT_INC(numDhPhase1KeyGenCompleted, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_DH_STAT_INC(numDhPhase1KeyGenCompletedErrors, instanceHandle);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pLocalOctetStringPV);
}

void LacDh_ProcessPhase2Cb(CpaStatus status,
                           CpaBoolean pass,
                           CpaInstanceHandle instanceHandle,
                           lac_pke_op_cb_data_t *pCbData)
{
    CpaCyGenFlatBufCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDhPhase2SecretKeyGenOpData *pOpData = NULL;
    CpaFlatBuffer *pOctetStringSecretKey = NULL;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyDhPhase2SecretKeyGenOpData *)LAC_CONST_PTR_CAST(
        pCbData->pClientOpData);
    pCb = (CpaCyGenFlatBufCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pOctetStringSecretKey = pCbData->pOutputData1;
    LAC_ASSERT_NOT_NULL(pOctetStringSecretKey);

    /* increment stats */
    LAC_DH_STAT_INC(numDhPhase2KeyGenCompleted, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_DH_STAT_INC(numDhPhase2KeyGenCompletedErrors, instanceHandle);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pOctetStringSecretKey);
}
