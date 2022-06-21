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
 * @defgroup LacAsym Asymmetric
 *
 * @ingroup Lac
 *
 * Asymmetric component includes Diffie Hellman, Rsa, Dsa, ECC and Prime.
 **************************************************************************/

/**
 ***************************************************************************
 * @defgroup LacAsymCommon Asymmetric Common
 *
 * @ingroup LacAsym
 *
 * Asymmetric common includes pke utils, mmp and qat communication layer
 **************************************************************************/

/**
 ***************************************************************************
 * @file lac_pke_qat_comms.h
 *
 * @defgroup LacAsymCommonQatComms QAT Communication Layer
 *
 * @ingroup LacAsymCommon
 *
 * Asymmetric QAT Communication Layer
 *
 * @lld_start
 *
 * @lld_overview
 * This is the LAC PKE QAT Comms component.  It takes care of the creation
 * of PKE messages in the format the QAT expects, and also the sending of
 * these messages to the QAT.  As part of PKE message creation, flat buffers
 * are internally resized by this component if necessary.  Also PKE request
 * chaining, where multiple requests are linked together and just the head
 * request is sent to the QAT, is supported by this component.  This component
 * also takes care of the allocation and freeing of request data structures
 * to minimize the work required by calling code.
 *
 * The expected usage is that clients will create input/output parameter
 * lists, with flat buffer pointers stored in the correct order and location
 * within these lists.  They will then call the function to create and send
 * a PKE request to the QAT.  If the client wishes to chain requests, then
 * they will create multiple requests using the same handle, and then send
 * the request chain as a normal request.
 *
 * The clients call the asynchronous function to send the message to the QAT.
 * They pass in a callback function and callback data when creating the
 * message. When the response is received from the QAT the callback function
 * is invoked with the LAC status, the QAT pass/fail status, and the callback
 * data as params.
 *
 * In the case of request chaining, the QAT will abort the execution of
 * requests in the chain if any request fails.  The response message will
 * correspond to the last executed request in the chain.  As each request
 * has its own (potentially unique) callback data, a client could in theory
 * determine which request in the chain failed if this info is needed.
 *
 * @lld_dependencies
 * - @ref QatComms "ADF" : For sending messages to the QAT, and for
 *   setting the response callback
 * - @ref LacMem "Mem" : For memory allocation and freeing, virtual/physical
 *   address translation, and translating between scalar and pointer types
 *
 * @lld_initialisation
 * On initialization this component sets the response callback for messages
 * of type PKE, so that they can be handled by this component.
 *
 * @lld_module_algorithms
 * To support request chaining, this component builds up a linked list of
 * requests, and maintains the head of the list in the handle that gets
 * returned to the caller.  Each element of the list has a pointer to the
 * head of the list so that the entire list can be freed by knowing any
 * element of the list.  Each element of the list maintains a next pointer
 * to facilitate list traversal.  Only the head element of the list maintains
 * a tail pointer, to facilitate adding to the end of the list.  The head
 * element is static, so can readily be stored in each element, but as the
 * tail element is dynamic (it changes as the list grows) its not convenient
 * to store and maintain it in each element.  Instead to get the tail of the
 * list you must first get the head of the list to get the tail pointer.
 *
 * @lld_process_context
 *
 * @lld_end
 ****************************************************************************/

/******************************************************************************/

#ifndef _LAC_PKE_QAT_COMMS_H_
#define _LAC_PKE_QAT_COMMS_H_

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_common.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/
/* ADF include */
#include "icp_adf_transport.h"

/* QAT include */
#include "icp_qat_fw_pke.h"
#include "icp_qat_fw_mmp.h"

/* SAL include */
#include "lac_pke_mmp.h"
#include "lac_sync.h"
#include "lac_mem_pools.h"

/**
 *****************************************************************************
 * @ingroup LacAsymCommonQatComms
 *
 * @description
 *      PKE request callback data structure
 *
 *****************************************************************************/
typedef struct lac_pke_op_cb_data_s
{
    const void *pClientCb;
    /**< client callback function pointer */
    void *pCallbackTag;
    /**< client callback correlator */
    const void *pClientOpData;
    /**< client callback operation data pointer */
    void *pOpaqueData;
    /**< generic opaque data pointer */
    /* Output data */
    void *pOutputData1;
    /**< Output data pointer 1 */
    void *pOutputData2;
    /**< Output data pointer 2 */
    lac_sync_op_data_t *pSyncCookie;
    /**< synchronous cookie */
#ifdef COUNTERS
    Cpa64U timeStamp;
#endif
} lac_pke_op_cb_data_t;

/**
 *****************************************************************************
 * @ingroup LacAsymCommonQatComms
 *
 * @description
 * This is the callback prototype for the non-blocking PKE operations. It
 * takes a status, pass flag, acceleration handle, and callback data pointer
 * as parameters and returns void. This function will be invoked when a
 * PKE response is received from the QAT to a previously issued PKE request.
 *
 * @param[in] status            status of the operation
 * @param[in] pass              result of the operation. For operations such as
 *                              verify which require the QAT to perform a test
 *                              then this parameter shall be set to CPA_TRUE if
 *                              the test succeeds or CPA_FALSE if the test
 *                              fails.
 *                              For messages which do not perform a test e.g.
 *                              encrypt, decrypt then this parameter shall
 *                              always be CPA_TRUE.
 * @param[in] instanceHandle    Acceleration engine to which the message was
 *                              sent.
 * @param[in] pCbData           this field contains a copy of the callback data
 *                              passed when the request was created.
 *****************************************************************************/
typedef void (*lac_pke_op_cb_func_t)(CpaStatus status,
                                     CpaBoolean pass,
                                     CpaInstanceHandle instanceHandle,
                                     lac_pke_op_cb_data_t *pCbData);

/**
 *****************************************************************************
 * @ingroup LacAsymCommonQatComms
 *
 * @description
 *     Contains the data for a pke op callback
 *
 *****************************************************************************/
typedef struct lac_pke_qat_req_data_cb_info_s
{
    lac_pke_op_cb_func_t cbFunc;      /**< Callback function */
    lac_pke_op_cb_data_t cbData;      /**< Callback function data */
    CpaInstanceHandle instanceHandle; /**< Acceleration engine for request */
} lac_pke_qat_req_data_cb_info_t;

/**
 *****************************************************************************
 * @ingroup LacAsymCommonQatComms
 *
 * @description
 *     Contains the input and output buffer data
 *
 *****************************************************************************/
typedef struct lac_pke_qat_req_data_param_info_s
{
    CpaFlatBuffer *clientInputParams[LAC_MAX_MMP_INPUT_PARAMS];
    /**< the client input parameters (unaligned flat buffers) */
    CpaFlatBuffer *clientOutputParams[LAC_MAX_MMP_OUTPUT_PARAMS];
    /**< the client output parameters (unaligned flat buffers) */

    Cpa8U *pkeInputParams[LAC_MAX_MMP_INPUT_PARAMS];
    /* the PKE input parameters (aligned data pointers) */
    Cpa8U *pkeOutputParams[LAC_MAX_MMP_OUTPUT_PARAMS];
    /* the PKE output parameters (aligned data pointers) */

    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS];
    /* Array of input arguments sizes */
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS];
    /* Array of output arguments sizes */

} lac_pke_qat_req_data_param_info_t;

/**
 ***************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Request data for QAT messages
 *
 * @description
 *      This structure defines the request data for PKE QAT messages. This is
 * used to store data which is known when the message is sent and which we wish
 * to retrieve when the response message is processed.
 **************************************************************************/
typedef struct lac_pke_qat_req_data_s
{

    /* use union to ensure optimal alignment */
    union lac_pke_qat_req_data_request_u {
        icp_qat_fw_pke_request_t request; /**< the PKE request */
        Cpa8U padding[1 << LAC_OPTIMAL_ALIGNMENT_SHIFT];
    } u1;

    /* use union to ensure optimal alignment */
    union lac_pke_qat_req_data_in_args_u {
        icp_qat_fw_mmp_input_param_t inArgList; /**< msg input arg list */
        Cpa8U padding[1 << LAC_OPTIMAL_ALIGNMENT_SHIFT];
    } u2;

    /* use union to ensure optimal alignment */
    union lac_pke_qat_req_data_out_args_u {
        icp_qat_fw_mmp_output_param_t outArgList; /**< msg output arg list */
        Cpa8U padding[1 << LAC_OPTIMAL_ALIGNMENT_SHIFT];
    } u3;

    lac_pke_qat_req_data_cb_info_t cbInfo;       /**< Callback info */
    lac_pke_qat_req_data_param_info_t paramInfo; /**< Parameter info */

    struct lac_pke_qat_req_data_s *pNextReqData; /**< next req data ptr */
    struct lac_pke_qat_req_data_s *pHeadReqData; /**< head req data ptr */
    struct lac_pke_qat_req_data_s *pTailReqData; /**< tail req data ptr */

} lac_pke_qat_req_data_t;

typedef void *lac_pke_request_handle_t;
/**< @ingroup LacAsymCommonQatComms
 * Handle to a PKE request. The handle is created using  LacPke_CreateRequest()
 * and is subsequently used to send the request using LacPke_SendRequest(). */

#define LAC_PKE_INVALID_HANDLE ((lac_pke_request_handle_t)0)
/**< @ingroup LacAsymCommonQatComms
 * Invalid PKE request handle. */

/**
 ***************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Handles a PKE response
 *
 * @description
 *      This function is called by ADF when a response is
 * received from the QAT to a PKE request. The pPkeRespMsg is the message read
 * off the ring.
 *
 * @param[in] pRespMsg       pointer to the response message
 *
 ***************************************************************************/
void LacPke_MsgCallback(void *pRespMsg);

/**
 ***************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Generates pke dummy response
 *
 * @description
 *      This function is called during the error state of the device to
 * generate dummy responses from the pke request memory pool.
 *
 * @param[in] pBucket       pointer to the bucket of memblks
 *
 * @retval CPA_STATUS_SUCCESS       Successfully polled a memory pool with data
 *                                  that generate dummy responses.
 * @retval CPA_STATUS_RETRY         There are no inflight requests in the
 *                                  memory pool associated with the instance
 *
 ***************************************************************************/
CpaStatus LacPke_SwRespMsgCallback(lac_memblk_bucket_t *pBucket);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Inits a PKE request in the request pool.
 *
 * @description
 *      This function inits a PKE request with all information constant
 *      for the instance.
 *
 * @pre
 *      All the instance information (mmplib, flowid, etc. ) is set
 *      before this function is called.
 *
 * @param[in,out] pData             pointer to the request
 * @param[in] instanceHandle        instanceHandle
 *
 * @retval none
 *
 ******************************************************************************/
void LacPke_InitAsymRequest(Cpa8U *pData, CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Creates a PKE request for the QAT.
 *
 * @description
 *      This function takes the parameters for a PKE QAT request, creates the
 * request, resizes the input & output buffer parameters, and fills in the per
 * request PKE fields.  The request can subsequently be sent to the QAT using
 * LacPke_SendRequest(). In the event of an error this function will tidy up
 * any resources associated with the request handle and set it to
 * PKE_INVALID_HANDLE.
 *
 * @pre
 *      The requests in the request pool have been initialised using
 *      Lac_MemPoolInitAsymRequest().
 *
 * @param[in,out] pRequestHandle    Pointer to hold the handle for the request
 *                                  created by this call.  If the incoming value
 *                                  is non-zero then the new request is appended
 *                                  to the request (chain) already associated
 *                                  with the handle.  For a single request, or
 *                                  the first request in a chain, the passed in
 *                                  handle value must be zero
 *                                  (i.e. PKE_INVALID_HANDLE).
 *
 * @param[in] functionalityId   the PKE functionality id.
 * @param[in] pInArgSizeList    pointer to a list of input sizes required by
 *                              QAT. The client-provided input flat buffers
 *                              greater than or equal to their corresponding
 *                              size will be passed to QAT. Buffers that are
 *                              less than the required size will be copied into
 *                              internal driver buffers before being passed to
 *                              QAT.
 * @param[in] pOutArgSizeList   pointer to a list of output sizes required by
 *                              QAT.
 * @param[in] pInArgList        pointer to the list of input params. This
 *                              should contain the client-provided flat buffer
 *                              pointers. Any entries in the list which are not
 *                              used must be set to 0.
 * @param[in] pOutArgList       pointer to the list of output params. This
 *                              should contain the client-provided flat buffer
 *                              pointers. Any entries in the list which are not
 *                              used must be set to 0.
 * @param[in] pInternalInMemList pointer to a list of Booleans that indicate if
 *                              input data buffers passed to QAT are internally
 *                              or externally allocated. This information needs
 *                              to be tracked to ensure we use the corect
 *                              virt2phys function.
 * @param[in] pInternalInMemList pointer to a list of Booleans that indicate if
 *                              output data buffers passed to QAT are internally
 *                              or externally allocated.
 * @param[in] pPkeOpCbFunc      this function is invoked when the response is
 *                              received from the QAT
 * @param[in] pCbData           callback data to be returned (by copy)
 *                              unchanged in the callback.
 * @param[in] instanceHandle    instanceHandle
 *
 * @retval CPA_STATUS_SUCCESS   No error
 * @retval CPA_STATUS_RESOURCE  Resource error (e.g. failed memory allocation)
 *
 ******************************************************************************/
CpaStatus LacPke_CreateRequest(lac_pke_request_handle_t *pRequestHandle,
                               Cpa32U functionalityId,
                               Cpa32U *pInArgSizeList,
                               Cpa32U *pOutArgSizeList,
                               icp_qat_fw_mmp_input_param_t *pInArgList,
                               icp_qat_fw_mmp_output_param_t *pOutArgList,
                               CpaBoolean *pInternalInMemList,
                               CpaBoolean *pInternalOutMemList,
                               lac_pke_op_cb_func_t pPkeOpCbFunc,
                               lac_pke_op_cb_data_t *pCbData,
                               CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Sends a PKE request to the QAT.
 *
 * @description
 *      This function sends a PKE request, previously created using
 * LacPke_CreateRequest(), to the QAT. It does not block waiting for a
 * response. Instead the callback function is invoked when the response from
 * the QAT has been processed.
 *
 * @param[in,out] pRequestHandle    the handle of the PKE request (chain) to be
 *                                  sent.  Will be set to CPA_INVALID_HANDLE in
 *                                  the case of any error.
 * @param[in] instanceHandle        Acceleration engine to which the message
 *                                  will be sent.
 *
 * @retval CPA_STATUS_SUCCESS       No error
 * @retval CPA_STATUS_RETRY         Ring full
 *
 ******************************************************************************/
CpaStatus LacPke_SendRequest(lac_pke_request_handle_t *pRequestHandle,
                             CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonQatComms
 *      Sends a single (unchained) PKE request to the QAT.
 *
 * @description
 *      This function takes the parameters for a PKE QAT request, creates the
 * request, fills in the PKE fields and sends it to the QAT. It does not block
 * waiting for a response. Instead the callback function is invoked when the
 * response from the QAT has been processed.
 *
 * @param[in] functionalityId   the PKE functionality id.
 * @param[in] pInArgSizeList    pointer to a list of input sizes required by
 *                              QAT. The client-provided input flat buffers
 *                              greater than or equal to their corresponding
 *                              size will be passed to QAT. Buffers that are
 *                              less than the required size will be copied into
 *                              internal driver buffers before being passed to
 *                              QAT.
 * @param[in] pOutArgSizeList   pointer to a list of output sizes required by
 *                              QAT.
 * @param[in] pInArgList        pointer to the list of input params. This
 *                              should contain the client-provided flat buffer
 *                              pointers. Any entries in the list which are not
 *                              used must be set to 0.
 * @param[in] pOutArgList       pointer to the list of output params. This
 *                              should contain the client-provided flat buffer
 *                              pointers. Any entries in the list which are not
 *                              used must be set to 0.
 * @param[in] pInternalInMemList pointer to a list of Booleans that indicate if
 *                              input data buffers passed to QAT are internally
 *                              or externally allocated. This information needs
 *                              to be tracked to ensure we use the corect
 *                              virt2phys function.
 * @param[in] pInternalInMemList pointer to a list of Booleans that indicate if
 *                              output data buffers passed to QAT are internally
 *                              or externally allocated.
 * @param[in] pPkeOpCbFunc      this function is invoked when the response is
 *                              received from the QAT
 * @param[in] pCbData           callback data to be returned (by copy)
 *                              unchanged in the callback.
 * @param[in] instanceHandle    instanceHandle
 *
 * @retval CPA_STATUS_SUCCESS   No error
 * @retval CPA_STATUS_RESOURCE  Resource error (e.g. failed memory allocation)
 * @retval CPA_STATUS_RETRY         Ring full
 *
 ******************************************************************************/
CpaStatus LacPke_SendSingleRequest(Cpa32U functionalityId,
                                   Cpa32U *pInArgSizeList,
                                   Cpa32U *pOutArgSizeList,
                                   icp_qat_fw_mmp_input_param_t *pInArgList,
                                   icp_qat_fw_mmp_output_param_t *pOutArgList,
                                   CpaBoolean *pInternalInMemList,
                                   CpaBoolean *pInternalOutMemList,
                                   lac_pke_op_cb_func_t pPkeOpCbFunc,
                                   lac_pke_op_cb_data_t *pCbData,
                                   CpaInstanceHandle instanceHandle);

#endif /* _LAC_PKE_QAT_COMMS_H_ */
