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
 ***************************************************************************
 *
 * @file lac_ec_montedwds.c
 *
 * @ingroup Lac_Ec_MontEdwds
 *
 * Elliptic Curve Montgomery and Edwards functions
 *
 * @lld_start
 *
 * @lld_overview
 * This file implements Elliptic Curve Montgomery and Edwards api funcitons.
 * @lld_dependencies
 * - \ref LacAsymCommonQatComms "PKE QAT Comms" : For creating and sending
 * messages to the QAT
 * - \ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @lld_initialisation
 * On initialization this component clears the stats.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 ***************************************************************************/

/*
****************************************************************************
* Include public/global header files
****************************************************************************
*/

/* API Includes */
#include "cpa.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_im.h"

/* QAT FW includes */
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"

/* Look Aside Includes */
#include "lac_common.h"
#include "lac_mem_pools.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_ec.h"
#include "lac_sal_types.h"
#include "lac_sal.h"
#include "lac_sync.h"
#include "lac_sal_types_crypto.h"
#include "sal_service_state.h"

#define LAC_EC_MONTEDWDS_DATA_LEN_IN_BYTES 32

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/
#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup LacEcMontEdwds
 *
 * @description
 *      This function is used to perform basic checks on the
 *      input parameters (eg., checks data buffers for NULL and 0 dataLen)
 *
 * @param[in]  instanceHandle   Instance handle
 * @param[in]  pOpData          Structure containing all the data needed to
 *                              perform the operation. The client code
 *                              allocates the memory for this structure. This
 *                              component takes ownership of the memory until
 *                              it is returned in the callback.
 * @param[in] pMultiplyStatus   Multiply status.
 * @param[in] pXk               Pointer to xk flat buffer.
 * @param[in] pYk               Pointer to yk flat buffer.
 *
 * @retval CPA_STATUS_SUCCESS       No error
 * @retval CPA_STATUS_INVALID_PARAM Invalid curve type
 *
 ****************************************************************************/
STATIC CpaStatus LacEcMontEdwds_PointMultiplyParamCheck(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcMontEdwdsPointMultiplyOpData *pOpData,
    const CpaBoolean *pMultiplyStatus,
    const CpaFlatBuffer *pXk,
    const CpaFlatBuffer *pYk)
{
    Cpa32U dataLen = LAC_EC_MONTEDWDS_DATA_LEN_IN_BYTES;

    /* Check for null parameters */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);

    if (CPA_CY_EC_MONTEDWDS_CURVE448_TYPE == pOpData->curveType ||
        CPA_CY_EC_MONTEDWDS_ED448_TYPE == pOpData->curveType)
    {
        dataLen = 2 * LAC_EC_MONTEDWDS_DATA_LEN_IN_BYTES;
    }

    switch (pOpData->curveType)
    {
        case CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE:
        case CPA_CY_EC_MONTEDWDS_CURVE448_TYPE:
            LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->k, CHECK_EQUALS, dataLen);
            LAC_CHECK_FLAT_BUFFER_PARAM(pXk, CHECK_EQUALS, dataLen);
            if (CPA_FALSE == pOpData->generator)
                LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->x, CHECK_EQUALS, dataLen);
            break;
        case CPA_CY_EC_MONTEDWDS_ED25519_TYPE:
        case CPA_CY_EC_MONTEDWDS_ED448_TYPE:
            LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->k, CHECK_EQUALS, dataLen);
            LAC_CHECK_FLAT_BUFFER_PARAM(pXk, CHECK_EQUALS, dataLen);
            LAC_CHECK_FLAT_BUFFER_PARAM(pYk, CHECK_EQUALS, dataLen);
            if (CPA_FALSE == pOpData->generator)
            {
                LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->x, CHECK_EQUALS, dataLen);
                LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->y, CHECK_EQUALS, dataLen);
            }
            break;
        default:
            return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 *****************************************************************************
 * @ingroup LacEcMontEdwds
 *
 * @description
 *      This function is used to perform the point multiply synchronous
 *
 * @param[in]  instanceHandle   Instance handle
 * @param[in]  pOpData          Structure containing all the data needed to
 *                              perform the operation. The client code
 *                              allocates the memory for this structure. This
 *                              component takes ownership of the memory until
 *                              it is returned in the callback.
 * @param[in] pMultiplyStatus   Multiply status.
 * @param[in] pXk               Pointer to xk flat buffer.
 * @param[in] pYk               Pointer to yk flat buffer.
 *
 * @retval CPA_STATUS_SUCCESS       No error
 * @retval CPA_STATUS_INVALID_PARAM Invalid curve type
 *
 ****************************************************************************/
STATIC CpaStatus LacEcMontEdwds_PointMultiplySyn(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcMontEdwdsPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_FAIL, wCbStatus = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
        return status;
    }

    /* Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    status = cpaCyEcMontEdwdsPointMultiply(instanceHandle,
                                           LacSync_GenDualFlatBufVerifyCb,
                                           pSyncCallbackData,
                                           pOpData,
                                           pMultiplyStatus,
                                           pXk,
                                           pYk);
    if (CPA_STATUS_SUCCESS == status)
    {
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_EC_STAT_INC(numEcPointMultiplyCompletedError, pCryptoService);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the Request was not sent the Callback will never
         * be called, so need to indicate that we're finished
         * with cookie so it can be destroyed.
         */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }

    LacSync_DestroySyncCookie(&pSyncCallbackData);

    return status;
}

/**
 *****************************************************************************
 * @ingroup Lac_Ec_MontEdwds
 *      Creates a PKE EC_MONTEDWDS request for the QAT.
 *
 * @description
 *      This function takes the parameters for a PKE EC_ED QAT request, create
 *      the request, and fills in the per request PKE fields. The request can
 *      subsequently be sent to the QAT using LacPke_SendRequest(). In the
 *      event of an error this function will tidy up any resources associated
 *      with the request handle and set it to PKE_INVALID_HANDLE.
 *
 * @pre
 *      The requests in the request pool have been initialised using
 *      Lac_MemPoolInitAsymRequest().
 *
 * @param[in,out] pRequestHandle Pointer to hold the handle for the request
 *                               created by this call.  If the incoming value
 *                               is non-zero then the new request is appended
 *                               to the request (chain) already associated
 *                               with the handle.  For a single request, or
 *                               the first request in a chain, the passed in
 *                               handle value must be zero
 *                               i.e. PKE_INVALID_HANDLE).
 * @param[in] functionalityId    The PKE functionality id.
 * @param[in] pInArgList         Pointer to the list of input params. This
 *                               should contain the client-provided flat
 *                               buffer pointers. Any entries in the list
 *                               which are not used must be set to 0.
 * @param[in] pOutArgList        Pointer to the list of output params. This
 *                               should contain the client-provided flat
 *                               buffer pointers. Any entries in the list
 *                               which are not used must be set to 0.
 * @param[in] pPkeOpCbFunc       This function is invoked when the response is
 *                               received from the QAT
 * @param[in] pCbData            Callback data to be returned (by copy)
 *                               unchanged in the callback.
 * @param[in] instanceHandle     InstanceHandle
 *
 * @retval CPA_STATUS_SUCCESS    No error
 * @retval CPA_STATUS_RESOURCE   Resource error (e.g. failed memory allocation)
 *
 ******************************************************************************/
STATIC CpaStatus
LacEcMontEdwds_CreateRequest(lac_pke_request_handle_t *pRequestHandle,
                             Cpa32U functionalityId,
                             icp_qat_fw_mmp_input_param_t *pInArgList,
                             icp_qat_fw_mmp_output_param_t *pOutArgList,
                             lac_pke_op_cb_func_t pPkeOpCbFunc,
                             lac_pke_op_cb_data_t *pCbData,
                             CpaInstanceHandle instanceHandle)
{
    lac_pke_qat_req_data_t *pReqData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;
    CpaFlatBuffer *pParam = NULL;
    Cpa8U idx = 0;

    /* Allocate request data */
    do
    {
        pReqData = Lac_MemPoolEntryAlloc(pCryptoService->lac_pke_req_pool);
        if (NULL == pReqData)
        {
            LAC_LOG_ERROR("Cannot get a mem pool entry");
            return CPA_STATUS_RESOURCE;
        }
        else if ((void *)CPA_STATUS_RETRY == pReqData)
        {
            osalYield();
        }
    } while ((void *)CPA_STATUS_RETRY == pReqData);

    /* Ensure correct request structure alignment */
    LAC_ASSERT(
        LAC_ADDRESS_ALIGNED(&pReqData->u1.request, LAC_OPTIMAL_ALIGNMENT_SHIFT),
        "request structure not correctly aligned");

    /* Ensure correct input argument list structure alignment */
    LAC_ASSERT(LAC_ADDRESS_ALIGNED(&pReqData->u2.inArgList,
                                   LAC_OPTIMAL_ALIGNMENT_SHIFT),
               "inArgList structure not correctly aligned");

    /* Ensure correct output argument list structure alignment */
    LAC_ASSERT(LAC_ADDRESS_ALIGNED(&pReqData->u3.outArgList,
                                   LAC_OPTIMAL_ALIGNMENT_SHIFT),
               "outArgList structure not correctly aligned");


    /* Clear the previous param info */
    LAC_OS_BZERO(&pReqData->paramInfo, sizeof(pReqData->paramInfo));

    /* Store request data pointer in the request handle */
    *pRequestHandle = (lac_pke_request_handle_t)pReqData;

    /* Initialize next, head, and tail request data pointers */
    pReqData->pNextReqData = NULL;
    pReqData->pHeadReqData = pReqData;

    /* Note: tail pointer is only valid in head request data struct */
    pReqData->pTailReqData = pReqData;

    /* Populate request data structure */
    pReqData->cbInfo.cbFunc = pPkeOpCbFunc;
    pReqData->cbInfo.cbData = *pCbData;
    pReqData->cbInfo.instanceHandle = instanceHandle;
    pReqData->pNextReqData = NULL;

    /* Set functionality ID */
    pReqData->u1.request.pke_hdr.cd_pars.func_id = functionalityId;

    /* LWs 14 and 15 set to zero for this request for now */
    pReqData->u1.request.next_req_adr = 0;

    /* Store correctly sized in parameters in QAT structure*/
    for (idx = 0; 0 != pInArgList->flat_array[idx]; idx++)
    {
        /* Get user input data */
        pParam = (CpaFlatBuffer *)(UARCH_INT)pInArgList->flat_array[idx];

        LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
            pCryptoService->generic_service_info,
            pReqData->u2.inArgList.flat_array[idx],
            pParam->pData);
    }
    /* Set number in inputs */
    pReqData->u1.request.input_param_count = idx;

    /* Store correctly sized out parameters in QAT structure */
    for (idx = 0; 0 != pOutArgList->flat_array[idx]; idx++)
    {
        /* Get user input data */
        pParam = (CpaFlatBuffer *)(UARCH_INT)pOutArgList->flat_array[idx];

        LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
            pCryptoService->generic_service_info,
            pReqData->u3.outArgList.flat_array[idx],
            pParam->pData);
    }
    /* Set number in outputs */
    pReqData->u1.request.output_param_count = idx;

    LAC_ASSERT(
        ((pReqData->u1.request.input_param_count +
          pReqData->u1.request.output_param_count) <= LAC_MAX_MMP_PARAMS),
        "number of input/output parameters exceeds maximum allowed");

    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup LacEcMontEdwds
 *      Sends a single (unchained) PKE Ec_MontEdwds request to the QAT.
 *
 * @description
 *      This function takes the parameters for a PKE Ec_MontEdwds QAT request,
 *      creates the request, fills in the PKE fields and sends it to the QAT.
 *      It does not block waiting for a response. Instead the callback function
 *      is invoked when the response from the QAT has been processed.
 *
 * @param[in] functionalityId   The PKE functionality id.
 * @param[in] pInArgList        Pointer to the list of input params. This
 *                              should contain the client-provided flat buffer
 *                              pointers. Any entries in the list which are not
 *                              used must be set to 0.
 * @param[in] pOutArgList       Pointer to the list of output params. This
 *                              should contain the client-provided flat buffer
 *                              pointers. Any entries in the list which are not
 *                              used must be set to 0.
 * @param[in] pPkeOpCbFunc      This function is invoked when the response is
 *                              received from the QAT
 * @param[in] pCbData           Callback data to be returned in the callback.
 * @param[in] instanceHandle    InstanceHandle
 *
 * @retval CPA_STATUS_SUCCESS   No error
 * @retval CPA_STATUS_RESOURCE  Resource error (e.g. failed memory allocation)
 * @retval CPA_STATUS_RETRY     Ring full
 *
 *****************************************************************************/
CpaStatus LacEcMontEdwds_SendSingleRequest(
    Cpa32U functionalityId,
    icp_qat_fw_mmp_input_param_t *pInArgList,
    icp_qat_fw_mmp_output_param_t *pOutArgList,
    lac_pke_op_cb_func_t pPkeOpCbFunc,
    lac_pke_op_cb_data_t *pCbData,
    CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_pke_request_handle_t requestHandle = LAC_PKE_INVALID_HANDLE;

    /* Prepare the Ec_MontEdwds request */
    status = LacEcMontEdwds_CreateRequest(&requestHandle,
                                          functionalityId,
                                          pInArgList,
                                          pOutArgList,
                                          pPkeOpCbFunc,
                                          pCbData,
                                          instanceHandle);

    /* Send the request */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_SendRequest(&requestHandle, instanceHandle);
    }

    return status;
}

/**
 ******************************************************************************
 * @ingroup LacEcMontEdwds
 *
 * @description
 *      This function is used to perform point multiply internal callback
 *
 * @param[in] status           Status to be checked
 * @param[in] pMultiplyStatus  Multiply status.
 * @param[in] instanceHandle   Instance handle
 * @param[in] pCbData          Callback data
 *
 *****************************************************************************/
STATIC void LacEcMontEdwds_PointMultiplyCallback(
    CpaStatus status,
    CpaBoolean multiplyStatus,
    CpaInstanceHandle instanceHandle,
    lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcPointMultiplyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcPointMultiplyOpData *pOpData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* Extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcPointMultiplyCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcPointMultiplyOpData *)pCbData->pClientOpData;
    pXk = pCbData->pOutputData1;
    pYk = pCbData->pOutputData2;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pXk);
    LAC_ASSERT_NOT_NULL(pYk);

    /* Increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyCompleted, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyCompletedError, pCryptoService);
    }

    /* For Montgomery & Edwards curves multiplyStatus is always true,
     * so no effect on statistics.
     */

    /* Invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pXk, pYk);
}

/**
 ******************************************************************************
 * @ingroup LacEcMontEdwds
 *      Map user data for ec curve to QAT.
 *
 * @description
 *      This function takes the parameters for a PKE Ec_MontEdwds QAT request,
 *      creates the request, fills in the PKE fields and sends it to the QAT.
 *      It does not block waiting for a response. Instead the callback function
 *      is invoked when the response from the QAT has been processed.
 *
 * @param[in] pXk               Pointer to xk flat buffer.
 * @param[in] pYk               Pointer to yk flat buffer.
 * @param[in] pOpData           Structure containing all the data needed to
 *                              perform the operation. The client code
 *                              allocates the memory for this structure. This
 *                              component takes ownership of the memory until
 *                              it is returned in the callback.
 * @param[in] pIn               Pointer to icp_qat_fw_mmp_input_param_t
 * @param[in] pOut              Pointer to icp_qat_fw_mmp_output_param_t
 * @param[out] functionalityId  The PKE functionality id.
 *
 * @retval CPA_STATUS_SUCCESS       No error
 * @retval CPA_STATUS_INVALID_PARAM Invalid curve type
 *
 *****************************************************************************/
STATIC CpaStatus LacEcMontEdwds_MapEcCruvesDataToQat(
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk,
    const CpaCyEcMontEdwdsPointMultiplyOpData *pOpData,
    icp_qat_fw_mmp_input_param_t *pIn,
    icp_qat_fw_mmp_output_param_t *pOut,
    Cpa32U *functionID)
{
    switch (pOpData->curveType)
    {
        case CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE:
            if (pOpData->generator)
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->generator_multiplication_c25519.k, &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->generator_multiplication_c25519.xr, pXk);
                *functionID = GENERATOR_MULTIPLICATION_C25519;
            }
            else
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_c25519.k, &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_c25519.xp, &pOpData->x);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->point_multiplication_c25519.xr, pXk);
                *functionID = POINT_MULTIPLICATION_C25519;
            }
            break;
        case CPA_CY_EC_MONTEDWDS_ED25519_TYPE:
            if (pOpData->generator)
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->generator_multiplication_ed25519.k, &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->generator_multiplication_ed25519.xr, pXk);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->generator_multiplication_ed25519.yr, pYk);

                *functionID = GENERATOR_MULTIPLICATION_ED25519;
            }
            else
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_ed25519.k, &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_ed25519.xp, &pOpData->x);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_ed25519.yp, &pOpData->y);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->point_multiplication_ed25519.xr, pXk);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->point_multiplication_ed25519.yr, pYk);
                *functionID = POINT_MULTIPLICATION_ED25519;
            }
            break;
        case CPA_CY_EC_MONTEDWDS_CURVE448_TYPE:
            if (pOpData->generator)
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->generator_multiplication_c448.k, &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->generator_multiplication_c448.xr, pXk);
                *functionID = GENERATOR_MULTIPLICATION_C448;
            }
            else
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->point_multiplication_c448.k,
                                              &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->point_multiplication_c448.xp,
                                              &pOpData->x);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->point_multiplication_c448.xr, pXk);
                *functionID = POINT_MULTIPLICATION_C448;
            }
            break;
        case CPA_CY_EC_MONTEDWDS_ED448_TYPE:
            if (pOpData->generator)
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->generator_multiplication_ed448.k, &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->generator_multiplication_ed448.xr, pXk);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->generator_multiplication_ed448.yr, pYk);
                *functionID = GENERATOR_MULTIPLICATION_ED448;
            }
            else
            {
                LAC_MEM_SHARED_WRITE_FROM_PTR(pIn->point_multiplication_ed448.k,
                                              &pOpData->k);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_ed448.xp, &pOpData->x);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pIn->point_multiplication_ed448.yp, &pOpData->y);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->point_multiplication_ed448.xr, pXk);
                LAC_MEM_SHARED_WRITE_FROM_PTR(
                    pOut->point_multiplication_ed448.yr, pYk);
                *functionID = POINT_MULTIPLICATION_ED448;
            }
            break;
        default:
        {
            LAC_LOG_ERROR("Invalid Curve Type");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup LacEc
 *      Perform EC Point Multiplication on an Edwards or Montgomery curve as
 *      defined in RFC#7748.
 *
 * @description
 *      This function performs Elliptic Curve Point Multiplication as per
 *      RFC#7748
 *
 * @param[in] instanceHandle    Instance handle.
 * @param[in] pCb               Callback function pointer. If this is set to
 *                              a NULL value the function will operate
 *                              synchronously.
 * @param[in] pCallbackTag      User-supplied value to help identify request.
 * @param[in] pOpData           Structure containing all the data needed to
 *                              perform the operation. The client code
 *                              allocates the memory for this structure. This
 *                              component takes ownership of the memory until
 *                              it is returned in the callback.
 * @param[out] pMultiplyStatus  In synchronous mode, the multiply output is
 *                              valid (CPA_TRUE) or the output is invalid
 *                              (CPA_FALSE).
 * @param[out] pXk              Pointer to xk flat buffer.
 * @param[out] pYk              Pointer to yk flat buffer.
 *
 *****************************************************************************/
CpaStatus cpaCyEcMontEdwdsPointMultiply(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcMontEdwdsPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaCyCapabilitiesInfo cyCapInfo;
    Cpa32U functionID = 0;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    /* Populate callback data */
    lac_pke_op_cb_data_t cbData = {.pClientCb = pCb,
                                   .pCallbackTag = pCallbackTag,
                                   .pClientOpData = pOpData,
                                   .pOpaqueData = NULL,
                                   .pOutputData1 = pXk,
                                   .pOutputData2 = pYk};

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* Check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif

    /* Ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);

#ifdef ICP_PARAM_CHECK
    /* Ensure this is a crypto instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    SalCtrl_CyQueryCapabilities(instanceHandle, &cyCapInfo);
    if (!cyCapInfo.ecEdMontSupported)
    {
        LAC_LOG_ERROR("The device does not support ECEDMONT");
        return CPA_STATUS_UNSUPPORTED;
    }

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {
        /* Call synchronous mode function */
        status = LacEcMontEdwds_PointMultiplySyn(
            instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);

#ifdef ICP_TRACE
        LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                 "%d, 0x%lx, 0x%lx)\n",
                 (LAC_ARCH_UINT)instanceHandle,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 (NULL == pMultiplyStatus) ? 0 : *pMultiplyStatus,
                 (LAC_ARCH_UINT)pXk,
                 (LAC_ARCH_UINT)pYk);

#endif

        return status;
    }

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

#ifdef ICP_PARAM_CHECK
    /* Basic NULL Param Checking  */
    status = LacEcMontEdwds_PointMultiplyParamCheck(
        instanceHandle, pOpData, pMultiplyStatus, pXk, pYk);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
        return status;
    }
#endif

    /* Zero the output buffers */
    osalMemSet(pXk->pData, 0, pXk->dataLenInBytes);
    if (CPA_CY_EC_MONTEDWDS_ED25519_TYPE == pOpData->curveType ||
        CPA_CY_EC_MONTEDWDS_ED448_TYPE == pOpData->curveType)
    {
        osalMemSet(pYk->pData, 0, pYk->dataLenInBytes);
    }

    status = LacEcMontEdwds_MapEcCruvesDataToQat(
        pXk, pYk, pOpData, &in, &out, &functionID);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
        return status;
    }

    /* Send the PKE request to the QAT */
    status =
        LacEcMontEdwds_SendSingleRequest(functionID,
                                         &in,
                                         &out,
                                         LacEcMontEdwds_PointMultiplyCallback,
                                         &cbData,
                                         instanceHandle);

    /* Increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequests, pCryptoService);
    }
    else
    {
        LAC_EC_STAT_INC(numEcPointMultiplyRequestErrors, pCryptoService);
    }

    return status;
}
