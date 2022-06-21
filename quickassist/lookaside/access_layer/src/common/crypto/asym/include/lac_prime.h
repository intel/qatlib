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
 ***************************************************************************
 * @file lac_prime.h
 *
 * @defgroup Lac_Prime     Prime
 *
 * @ingroup LacAsym
 *
 * Interfaces exposed by the Prime Component
 *
 * @lld_start
 *
 * @lld_overview
 * This is the Prime feature implementation. It implements four methods for
 * primality test: GCD, Fermat test, Miller-Rabin and Lucas test. The client may
 * require combined testing, i.e. up to one GCD + up to one Fermat + up to
 * 50 Miller-Rabin rounds + up to one Lucas.
 *
 * For Miller-Rabin test the client supplies the array of random numbers.
 * Further processing requires a flat buffer to be associated with each random
 * number. The memory for these flat buffers is assigned internally, as needed,
 * from the pre-allocated memory pool.
 *
 * In addition to the standard check on the parameters supplied by the client,
 * the prime candidate of the acceptable length is tested for MSB and LSB (non-
 * -even number). For Miller-Rabin method, the number of requested rounds must
 * not exceed 50, the supplied random numbers must match the prime candidate in
 * length and have to fall in within 1 and prime-1 (1 < random < prime-1)
 * boundaries.
 *
 * The requests for service are created and chained as necessary for multiple
 * tests in the increasing complexity order: GCD->Fermat->Miller-Rabin->Lucas.
 * The internal functions are called to calculate the function ID for each
 * method and to construct the input/output argument lists before calling the
 * PKE QAT Comms layer to create the request. After all requests have been
 * created, the PKE QAT Comms layer is called to propagate the requests to the
 * QAT.
 *
 * Buffer alignment is handled by the PKE QAT Comms layer.
 *
 * @lld_dependencies
 * - @ref LacPkeQatComms "PKE QAT Comms" : For creating and sending messages
 * to the QAT
 * - @ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @lld_module_algorithms
 * LacPke_CreateRequest() function takes the parameters for a PKE QAT request,
 * creates the request, aligns the input & output buffer parameters, and fills
 * in the PKE fields.  The request can subsequently be sent to the QAT using
 * LacPke_SendRequest(). In the event of an error this function will tidy up any
 * resources associated with request handle and set it to PKE_INVALID_HANDLE.
 * When the chain of requests is formed (with the same requestHandle) each
 * request structure gets a pointer filled in to point to the next structure
 * (PKE request).
 *
 * LacPke_SendRequest() function sends a PKE request, previously created using
 * LacPke_CreateRequest(), to the QAT. It does NOT block waiting for a response.
 * In the case of synchronous mode the blocking is done elsewhere in the code
 * using wait-queues, and the callback method is handled internally. The
 * callback function is invoked when the response from the QAT has been
 * processed. When a chain of requests is formed, this function sends the
 * request - head of the chain to the QAT. The QAT performs the required
 * operation, in this case the flavour of Prime test. In the event of a
 * successful operation (positive result) the QAT checks if there is a pointer
 * to point to the next request structure, automatically invokes the next
 * request, performs the operation and so on.
 *
 * If any operation returns a negative result then the QAT sends a negative
 * respond back regardless of reaching the end request or not. Similarly,
 * only when all operations result in a positive outcome and the QAT reaches
 * the end of the chain and only then is able to send a positive response.
 *
 * @note
 * The Prime feature may be called in Asynchronous or Synchronous modes.
 * In Asynchronous mode the user supplies a Callback function to the API.
 * Control returns to the client after the message has been sent to the QAT and
 * the Callback gets invoked when the QAT completes the operation. There is NO
 * BLOCKING. This mode is preferred for maximum performance.
 * In Synchronous mode the client supplies no Callback function pointer (NULL)
 * and the point of execution is placed on a wait-queue internally, and this is
 * de-queued once the QAT completes the operation. Hence, Synchronous mode is
 * BLOCKING. So avoid using in an interrupt context. To achieve maximum
 * performance from the API Asynchronous mode is preferred.
 *
 * @lld_process_context
 *
 * @lld_end
 *
 ***************************************************************************/

/*****************************************************************************/

#ifndef LAC_PRIME_H
#define LAC_PRIME_H

#include "cpa.h"

/* Include Osal files */
#include "Osal.h"

/* Include QAT files */
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"

/*** Types definitions ***/
typedef enum
{
    LAC_PRIME_TEST_START_DELIMITER,
    LAC_PRIME_GCD,
    LAC_PRIME_FERMAT,
    LAC_PRIME_MILLER_RABIN,
    LAC_PRIME_LUCAS,
    LAC_PRIME_TEST_END_DELIMITER
} lac_prime_test_t;

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      print the Prime stats to standard output
 *
 * @description
 *      For each Instance this function copies the stats using the function
 *      cpaCyPrimeQueryStats. It then prints contents of this structure to
 *      standard output.
 *
 * @param[in]  instanceHandle       instanceHandle
 *
 * @see cpaCyPrimeQueryStats()
 *
 *****************************************************************************/
void LacPrime_StatsShow(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Get Function ID function
 *
 * @description
 *      Given the opLenInBits this function selects the appropriate PKE
 *      functionID
 *
 * @param[in] testId        prime test to be carried out
 * @param[in] opLenInBits   pointer to length in bits of the prime candidate
 *                          to be tested. This value may be updated by this
 *                          function to the PKE interface requires data of
 *                          a larger length
 * @retval   FunctionID     functionID to be used
 *
 *****************************************************************************/
Cpa32U LacPrimeGetFuncID(lac_prime_test_t testId, Cpa32U *opLenInBits);

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Populate Prime Input and Output Parameter function
 *
 * @description
 *      Given the testId this function fills out the lists describing the
 *      input and output parameters to PKE
 *
 * @param[in] testId        prime test to be carried out
 * @param[in] opSizeInBytes length in bytes of the prime candidate
 * @param[in] pIn           pointer to icp_qat_fw_mmp_input_param_t
 *                          structure to be filled out by this function
 * @param[in] pOut          pointer to icp_qat_fw_mmp_output_param_t
 *                          structure to be filled out by this function
 * @param[in] pInSize       pointer to array of input buffer sizes to be
 *                          filled out by this function
 * @param[in] pInternalMemInList  pointer to array of booleans describing if
 *                          memory is internally or externally allocated.
 *                          Elements of this array will be modified by this
 *                          function
 * @param[in] internalPrimeMem    boolean to indicate if the prime is in
 *                          internally or externally allocated memory.
 * @param[in] pPrimeBuff    pointer to flatbuffer holding the prime. It can
 *                          either be the user supplied buffer or an internal
 *                          buffer in the case where the prime has been
 *                          previously resized.
 * @param[in] pInputMillerRabinBuffer if testId == MILLER_RABIN then this
 *                                    contains the pointer the the flatbuffer
 *                                    describing the Miller Rabin input data
 *                                    otherwise can be NULL
 *
 *****************************************************************************/
void LacPrimePopulateParam(lac_prime_test_t testId,
                           Cpa32U opSizeInBytes,
                           icp_qat_fw_mmp_input_param_t *pIn,
                           icp_qat_fw_mmp_output_param_t *pOut,
                           Cpa32U *pInSize,
                           CpaBoolean *pInternalMemInList,
                           CpaBoolean internalPrimeMem,
                           CpaFlatBuffer *pPrimeBuff,
                           const CpaFlatBuffer *pInputMillerRabinBuffer);

#ifdef ICP_PARAM_CHECK
/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Test Parameter Check
 *
 * @description
 *     Performs basic validation of the client's input parameters.
 *     Checks for NULL pointers etc.
 *
 * @param[in] pCb           user supplied callback function or in the sync
 *                          case our internal callback function
 * @param[in] pOpData       pointer to user supplied CpaCyPrimeTestOpData
 *                          structure
 * @param[in] pTestPassed   pointer to memory to write the result of the
 *                          prime check
 *
 * @retval CPA_STATUS_SUCCESS        Validation passed
 * @retval CPA_STATUS_INVALID_PARAM  Validation failed
 *
 *****************************************************************************/
CpaStatus LacPrimeParameterCheck(CpaCyPrimeTestCbFunc pCb,
                                 CpaCyPrimeTestOpData *pOpData,
                                 CpaBoolean *pTestPassed);
#endif

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Prime Test Callback Function
 *
 * @description
 *     Called by PKE QAT COMMS when a response to a prime message is recevied
 *     from the QAT. This function increments stats and frees resources where
 *     appropriate before calling the client's callback.
 *
 * @param[in] status        status of the response message received from QAT
 * @param[in] pass          result of prime test from PKE. If CPA_FALSE prime
 *                          candidate is composite. If CPA_TRUE there is a
 *                          possibility the prime candidate is prime
 * @param[in] instanceHandle  Identifies the instance processing this request
 * @param[in] pCbData         pointer to callback data
 *
 *****************************************************************************/

void LacPrimeTestCallback(CpaStatus status,
                          CpaBoolean pass,
                          CpaInstanceHandle instanceHandle,
                          lac_pke_op_cb_data_t *pCbData);

/**
 *******************************************************************************
 * @ingroup Lac_Prime
 *      Compile time check of FW interface
 *
 * @description
 *      Performs a compile time check of PKE interface to ensure IA assumptions
 *      about the interface are valid.
 *
 *****************************************************************************/
void LacPrime_CompileTimeAssertions(void);

#endif /* LAC_PRIME_H */
