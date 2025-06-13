/****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
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
 *
 ***************************************************************************/

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file cpa_dc_chain.h
 *
 * @defgroup cpaDcChain Data Compression Chaining API
 *
 * @ingroup cpaDc
 *
 * @description
 *      These functions specify the API for Data Compression Chaining
 *      operations.
 *
 * @remarks
 *
 *
 *****************************************************************************/

#ifndef CPA_DC_CHAIN_H
#define CPA_DC_CHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa_dc.h"
#include "cpa_cy_sym.h"

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Supported operations for compression chaining
 *
 * @description
 *      This enumeration lists the supported operations for compression chaining
 *
 *****************************************************************************/
typedef enum _CpaDcChainOperations
{
    CPA_DC_CHAIN_COMPRESS_THEN_HASH = 0,
    /**< 2 operations for chaining:
     * 1st operation is to perform compression on plain text
     * 2nd operation is to perform hash on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for compression setup data
     * 2nd entry is for hash setup data
     */
    CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT = 1,
    /**< 2 operations for chaining:
     * 1st operation is to perform compression on plain text
     * 2nd operation is to perform encryption on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for compression setup data
     * 2nd entry is for encryption setup data
     */
    CPA_DC_CHAIN_COMPRESS_THEN_HASH_ENCRYPT = 2,
    /**< 2 operations for chaining:
     * 1st operation is to perform compression on plain text
     * 2nd operation is to perform hash on compressed text and
     * encryption on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for compression setup data
     * 2nd entry is for hash and encryption setup data
     */
    CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT_HASH = 3,
    /**< 2 operations for chaining:
     * 1st operation is to perform compression on plain text
     * 2nd operation is to perform encryption on compressed text and
     * hash on compressed & encrypted text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for compression setup data
     * 2nd entry is for encryption and hash setup data
     */
    CPA_DC_CHAIN_COMPRESS_THEN_AEAD = 4,
    /**< 2 operations for chaining:
     * 1st operation is to perform compression on plain text
     * 2nd operation is to perform AEAD encryption on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for compression setup data
     * 2nd entry is for AEAD encryption setup data
     */
    CPA_DC_CHAIN_HASH_THEN_COMPRESS = 5,
    /**< 2 operations for chaining:
     * 1st operation is to perform hash on plain text
     * 2nd operation is to perform compression on plain text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for hash setup data
     * 2nd entry is for compression setup data
     */
    CPA_DC_CHAIN_HASH_VERIFY_THEN_DECOMPRESS = 6,
    /**< 2 operations for chaining:
     * 1st operation is to perform hash verify on compressed text
     * 2nd operation is to perform decompression on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for hash setup data
     * 2nd entry is for decompression setup data
     */
    CPA_DC_CHAIN_DECRYPT_THEN_DECOMPRESS = 7,
    /**< 2 operations for chaining:
     * 1st operation is to perform decryption on compressed & encrypted text
     * 2nd operation is to perform decompression on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for decryption setup data
     * 2nd entry is for decompression setup data
     */
    CPA_DC_CHAIN_HASH_VERIFY_DECRYPT_THEN_DECOMPRESS = 8,
    /**< 2 operations for chaining:
     * 1st operation is to perform hash verify on compressed & encrypted text
     * and decryption on compressed & encrypted text
     * 2nd operation is to perform decompression on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for hash and decryption setup data
     * 2nd entry is for decompression setup data
     */
    CPA_DC_CHAIN_DECRYPT_HASH_VERIFY_THEN_DECOMPRESS = 9,
    /**< 2 operations for chaining:
     * 1st operation is to perform decryption on compressed & encrypted text
     * and hash verify on compressed text
     * 2nd operation is to perform decompression on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for decryption and hash setup data
     * 2nd entry is for decompression setup data
     */
    CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS = 10,
    /**< 2 operations for chaining:
     * 1st operation is to perform AEAD decryption on compressed & encrypted
     * text
     * 2nd operation is to perform decompression on compressed text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for AEAD decryption setup data
     * 2nd entry is for decompression setup data
     */
    CPA_DC_CHAIN_DECOMPRESS_THEN_HASH_VERIFY = 11,
    /**< 2 operations for chaining:
     * 1st operation is to perform decompression on compressed text
     * 2nd operation is to perform hash verify on plain text
     * 2 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for decompression setup data
     * 2nd entry is for hash setup data
     */
    CPA_DC_CHAIN_COMPRESS_THEN_AEAD_THEN_HASH = 12,
    /**< 3 operations for chaining:
     * 1st operation is to perform compression on plain text
     * 2nd operation is to perform AEAD encryption on compressed text
     * 3rd operation is to perform hash on compressed & encrypted text
     * 3 entries in CpaDcChainSessionSetupData array:
     * 1st entry is for compression setup data
     * 2nd entry is for AEAD encryption setup data
     * 3rd entry is for hash setup data
     */
} CpaDcChainOperations;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Supported session types for data compression chaining.
 *
 * @description
 *      This enumeration lists the supported session types
 *      for data compression chaining.
 *****************************************************************************/
typedef enum _CpaDcChainSessionType
{
    CPA_DC_CHAIN_COMPRESS_DECOMPRESS = 0,
    /**< Indicate the session is for compression or decompression */
    CPA_DC_CHAIN_SYMMETRIC_CRYPTO
    /**< Indicate the session is for symmetric crypto */
} CpaDcChainSessionType;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Chaining Session Setup Data.
 * @description
 *      This structure contains data relating to the setup of a chaining
 *      session.
 *      This structure can comprise either compression or crypto session data
 *      determined by the sessType.
 *      The client needs to complete the information in this structure in order
 *      to setup a chaining session.
 *      This structure contains settings for use with the
 *      cpaDcChainInitSession API.
 *
 ****************************************************************************/
typedef struct _CpaDcChainSessionSetupData
{
    CpaDcChainSessionType sessType;
    /**< Indicate the type for this session */
    union {
        CpaDcSessionSetupData *pDcSetupData;
        /**< Pointer to compression session setup data */
        CpaCySymSessionSetupData *pCySetupData;
        /**< Pointer to symmetric crypto session setup data */
    };
} CpaDcChainSessionSetupData;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Compression chaining request input parameters.
 * @description
 *      This structure contains the request information to use with
 *      compression chaining operations.
 *      This structure contains settings for use with the
 *      cpaDcChainPerformOp API.
 *
 ****************************************************************************/
typedef struct _CpaDcChainOpData
{
    CpaDcChainSessionType opType;
    /**< Indicate the type for this operation */
    union {
        CpaDcOpData *pDcOp;
        /**< Pointer to compression operation data */
        CpaCySymOpData *pCySymOp;
        /**< Pointer to symmetric crypto operation data with
         * append crc64 option
         */
    };
} CpaDcChainOpData;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Compression chaining request input parameters.
 * @description
 *      This structure contains the request information to use with
 *      compression chaining sub-request operations.
 *      This structure contains settings for use with the
 *      cpaDcChainPerformOp2 API.
 *
 ****************************************************************************/
typedef struct _CpaDcChainSubOpData2
{
    CpaDcChainSessionType opType;
    /**< Indicate the type for this operation */
    union {
        CpaDcOpData2 *pDcOp2;
        /**< Pointer to compression operation data */
        CpaCySymOpData2 *pCySymOp2;
        /**< Pointer to symmetric crypto operation data with
         * additional options.
         */
    };
} CpaDcChainSubOpData2;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Chaining request result data
 * @description
 *      This structure contains the request results.
 *      This result structure is used with the cpaDcChainPerformOp API.
 *
 ****************************************************************************/
typedef struct _CpaDcChainRqResults
{
    CpaDcReqStatus dcStatus;
    /**< Additional status details from compression accelerator */
    CpaStatus cyStatus;
    /**< Additional status details from symmetric crypto accelerator */
    CpaBoolean verifyResult;
    /**< This parameter is valid when the verifyDigest option is set in the
     * CpaCySymSessionSetupData structure. A value of CPA_TRUE indicates
     * that the compare succeeded. A value of CPA_FALSE indicates that the
     * compare failed
     */
    Cpa32U produced;
    /**< Octets produced to the output buffer */
    Cpa32U consumed;
    /**< Octets consumed from the input buffer */
    Cpa32U crc32;
    /**< Crc32 checksum produced by chaining operations */
    Cpa32U adler32;
    /**< Adler32 checksum produced by chaining operations */
} CpaDcChainRqResults;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Chaining request result data for chained operations with optional
 *      verification step.
 * @description
 *      This structure contains the request results.
 *      This result structure is used with the cpaDcChainPerformOp2 API.
 *
 ****************************************************************************/
typedef struct _CpaDcChainRqVResults
{
    CpaDcChainRqResults chainRqResults;
    /**< Chain result structure. */
    Cpa64U ctxCrc64;
    /**< Crc64 of context structure.
     * Applicable to store2 flow.
     */
    Cpa64U iDcCrc64;
    /**< Input crc of DC operation */
    Cpa64U oDcCrc64;
    /**< Output crc of DC operation */
    Cpa64U storedCrc64;
    /**< Crc64 that was appended to compressed data.
     * Only valid if decrypt and decompress operations
     * were performed successfully and appendCrc was requested.
     */
    CpaBoolean reserved1;
    /**< Reserved for future use */
    CpaStatus chainStatus;
    /**< Status of chain command. In the event the request is invalid,
     * a value of CPA_STATUS_INVALID_PARAM or CPA_STATUS_UNSUPPORTED may
     * be returned. If the request has been successfully sent to the
     * accelerator and has been processed, this value will be set to
     * CPA_STATUS_SUCCESS. To verify the success of the entire chain
     * operation, the return status of each operation must be examined.
     */
} CpaDcChainRqVResults;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Chaining request data for chained operations with optional
 *      verification step.
 * @description
 *      This structure contains arguments for the cpaDcChainPerformOp2 API.
 *
 ****************************************************************************/
typedef struct _CpaDcChainOpData2
{
    CpaBoolean testIntegrity;
    /**< True if integrity check is required */
    CpaDcChainOperations operation;
    /**< Description of operations */
    Cpa8U numOpDatas;
    /**< Number of elements in pChainOpData, which define the chain
     * operation.
     */
    CpaDcChainSubOpData2 *pChainOpData;
    /**< Array of operations for chaining */
} CpaDcChainOpData2;

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Get the size of the memory required to hold the chaining session
 *      information.
 *
 * @description
 *      The client of the Data Compression API is responsible for
 *      allocating sufficient memory to hold chaining session information.
 *      This function provides a way for determining the size of a chaining
 *      session.
 *
 * @context
 *      No restrictions
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] dcInstance             Instance handle.
 * @param[in] operation              The operation for chaining
 * @param[in] numSessions            Number of sessions for the chaining
 * @param[in] pSessionData           Pointer to an array of
 *                                   CpaDcChainSessionSetupData structures.
 *                                   There should be numSessions entries in
 *                                   the array.
 * @param[out] pSessionSize          On return, this parameter will be the size
 *                                   of the memory that will be required
 *                                   to be allocated for the session handle.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      dcInstance has been started using cpaDcStartInstance.
 * @post
 *      pSessionSize will contain the size in bytes to be allocated for the
 *      session handle.
 * @note
 *      Only a synchronous version of this function is provided.
 *
 * @see
 *      cpaDcChainInitSession()
 *
 *****************************************************************************/
CpaStatus cpaDcChainGetSessionSize(CpaInstanceHandle dcInstance,
                                   CpaDcChainOperations operation,
                                   Cpa8U numSessions,
                                   CpaDcChainSessionSetupData *pSessionData,
                                   Cpa32U *pSessionSize);

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Initialize data compression chaining session
 *
 * @description
 *      This function is used to initialize a compression/decompression
 *      chaining session.
 *      This function returns a unique session handle each time this function
 *      is invoked.
 *      If the session has been configured with a callback function, then
 *      the order of the callbacks are guaranteed to be in the same order the
 *      compression or decompression requests were submitted for each session,
 *      so long as a single thread of execution is used for job submission.
 *      For data integrity computations the default CRC algorithm parameters
 *      are used.
 *
 * @context
 *      This is a synchronous function and it cannot sleep. It can be executed
 *      in a context that does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]     dcInstance        Instance handle derived from discovery
 *                                  functions.
 * @param[in,out] pSessionHandle    Pointer to a session handle.
 * @param[in]     operation         The operations for chaining
 * @param[in]     numSessions       Number of sessions for chaining
 * @param[in,out] pSessionData      Pointer to an array of
 *                                  CpaDcChainSessionSetupData structures.
 *                                  There should be numSessions entries in
 *                                  the array.
 * @param[in]     callbackFn        For synchronous operation this callback
 *                                  shall be a null pointer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      dcInstance has been started using cpaDcStartInstance.
 *      Before the session is initialized with this function,
 *      cpaDcChainGetSessionSize() function should be used to determine the
 *      size of the session handle. Memory needs to be allocated of the
 *      required size and passed in as the pSessionHandle.
 * @post
 *      Internal state and session parameters will be stored within the
 *      session handle.
 * @note
 *      Only a synchronous version of this function is provided.
 *
 *  pSessionData Setup Rules
 *  -# Each element in CpaDcChainSessionSetupData structure array provides
 *     (de)compression or a symmetric crypto session setup data.
 *
 *  -# The supported chaining operations are listed in CpaDcChainOperations.
 *     This enum indicates the number of operations in a chain and the order
 *     in which they are performed.
 *
 *  -# The order of entries in pSessionData[] should be consistent with the
 *     CpaDcChainOperations perform order.
 *     As an example, for CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT, pSessionData[0]
 *     holds the compression setup data and pSessionData[1] holds the
 *     encryption setup data..
 *
 *  -# The numSessions for each chaining operation are provided in
 *     the documentation of enum CpaDcChainOperations.
 *
 *  -# For a (de)compression session, the corresponding
 *     pSessionData[]->sessType should be set to
 *     CPA_DC_CHAIN_COMPRESS_DECOMPRESS and pSessionData[]->pDcSetupData
 *     should point to a CpaDcSessionSetupData structure.
 *
 *  -# For a symmetric crypto session, the corresponding
 *     pSessionData[]->sessType should be set to CPA_DC_CHAIN_SYMMETRIC_CRYPTO
 *     and pSessionData[]->pCySetupData should point to a
 *     CpaCySymSessionSetupData structure.
 *
 *  -# Combined compression sessions are not supported for chaining.
 *
 *  -# Stateful compression/decompression is not supported for chaining.
 *
 *  -# Simultaneous CRC32 and Adler32 over the input data are supported for
 *     chaining.
 *
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus cpaDcChainInitSession(CpaInstanceHandle dcInstance,
                                CpaDcSessionHandle pSessionHandle,
                                CpaDcChainOperations operation,
                                Cpa8U numSessions,
                                CpaDcChainSessionSetupData *pSessionData,
                                CpaDcCallbackFn callbackFn);

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Initialize CRC parameters for a DC Chaining session
 *
 * @description
 *      This function is used to initialize E2E programmable CRC parameters.
 *
 * @context
 *      This is a synchronous function and it cannot sleep. It can be executed
 *      in a context that does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]       dcInstance      Instance handle derived from discovery
 *                                  functions.
 * @param[in,out]   pSessionHandle  Pointer to a session handle.
 * @param[in]       pCrcControlData Pointer to a user instantiated structure
 *                                  containing the CRC parameters.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_FAIL          Operation failed.
 * @retval CPA_STATUS_UNSUPPORTED   Unsupported feature.
 *
 * @pre
 *      dcInstance has been started using cpaDcStartInstance.
 *      cpaDcInitSession has been called to initialize session parameters.
 * @post
 *      None
 * @note
 *      Only a synchronous version of this function is provided.
 *
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus cpaDcChainSetCrcControlData(CpaInstanceHandle dcInstance,
                                      CpaDcSessionHandle pSessionHandle,
                                      CpaCrcControlData *pCrcControlData);

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *       Reset a compression chaining session.
 *
 * @description
 *      This function will reset a previously initialized session handle.
 *      Reset will return CPA_STATUS_RETRY if outstanding calls still exist
 *      for the initialized session handle. In that case the client needs to
 *      retry the reset function at a later time.
 *
 * @context
 *      This is a synchronous function that cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]      dcInstance      Instance handle.
 * @param[in,out]  pSessionHandle  Session handle.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_RETRY          Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaDcStartInstance function.
 *      The session has been initialized via cpaDcChainInitSession.
 *      This function will work with either standard or extended chained
 *      requests.
 * @post
 *      Internal state within the chained session will be cleared allowing
 *      the session to be reused again without calling either
 *      cpaDcChainRemoveSession or cpaDcChainInitSession.
 * @note
 *      This is a synchronous function and has no completion callback
 *      associated with it.
 *      cpaDcChainResetSession() API will have the capability to reset a
 *      session previously initialized with cpaDcChainInitSession().
 *
 * @see
 *      cpaDcChainInitSession()
 *
 *****************************************************************************/
CpaStatus cpaDcChainResetSession(const CpaInstanceHandle dcInstance,
                                 CpaDcSessionHandle pSessionHandle);

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Remove a compression chaining session.
 *
 * @description
 *      This function will remove a previously initialized session handle
 *      and the installed callback handler function. Removal will fail if
 *      outstanding calls still exist for the initialized session handle.
 *      The client needs to retry the remove function at a later time.
 *      The memory for the session handle MUST not be freed until this call
 *      has completed successfully.
 *
 * @context
 *      This is a synchronous function that cannot sleep. It can be executed
 *      in a context that does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]      dcInstance      Instance handle.
 * @param[in,out]  pSessionHandle  Session handle.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_RETRY          Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting. Resubmit
 *                                   the request.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaDcStartInstance function.
 *      pSessionHandle has been setup using cpaDcChainInitSession().
 *      This function will work with either standard or extended chained
 *      requests.
 * @post
 *      Following a retval of CPA_STATUS_SUCCESS it is safe to free the
 *      memory allocated for the session handle.
 * @note
 *      This is a synchronous function and has no completion callback
 *      associated with it.
 *      cpaDcChainRemoveSession() API will have the capability to remove a
 *      session initialized with cpaDcChainInitSession().
 *
 * @see
 *      cpaDcChainInitSession()
 *
 *****************************************************************************/
CpaStatus cpaDcChainRemoveSession(const CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle);

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Submit a request to perform chaining operations.
 *
 * @description
 *      This function is used to perform chaining operations over data from
 *      the source buffer.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]     dcInstance        Target service instance.
 * @param[in,out] pSessionHandle    Session handle.
 * @param[in]     pSrcBuff          Pointer to input data buffer.
 * @param[out]    pDestBuff         Pointer to output data buffer.
 * @param[in]     operation         Operation for the chaining request
 * @param[in]     numOpData         The number of CpaDcChainOpData array items
 * @param[in]     pChainOpData      Pointer to an array of CpaDcChainOpData
 *                                  structures. There should be numOpData
 *                                  items in the array.
 * @param[in,out] pResults          Pointer to CpaDcChainRqResults
 * @param[in]     callbackTag       User supplied value to help correlate
 *                                  the callback with its associated request.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_DC_BAD_DATA          The input data was not properly formed.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *     pSessionHandle has been setup using cpaDcChainInitSession()
 * @post
 *     Following synchronous operation:
 *     The pSessionHandle will contain updated session related state
 *     information.
 *     The pDestBuff will contain processed data following the chained
 *     operation.
 *     The pResults will contain the status/checksums/additional outputs
 *     from the completed chained operation.
 *     Following asynchronous operation:
 *     The call has been submitted and the data dependent structures will
 *     only be safe to use once the asynchronous callback is called.
 * @note
 *     This function passes control to the compression service for chaining
 *     processing, the supported chaining operations are described in
 *     CpaDcChainOperations.
 *     This function does not support the additional integrity checking
 *     chaining features supported in cpaDcChainPerformOp2() and should only
 *     be used if these features are not required.
 *
 *  pChainOpData Setup Rules
 *  -# Each element in CpaDcChainOpData structure array holds either a
 *     (de)compression or a symmetric crypto operation data.
 *
 *  -# The order of entries in pChainOpData[] must be consistent with the
 *     order of operations described for the chaining operation in
 *     CpaDcChainOperations.
 *     As an example, for CPA_DC_CHAIN_HASH_THEN_COMPRESS, pChainOpData[0]
 *     must contain the hash operation data and pChainOpData[1] must
 *     contain the compress operation data.
 *
 *  -# The numOpData for each chaining operation are specified in the
 *     documentation for the operation in CpaDcChainOperations.
 *
 *  -# For a (de)compression operation, the corresponding
 *     pChainOpData[]->opType should be set to
 *     CPA_DC_CHAIN_COMPRESS_DECOMPRESS and pChainOpData[]->pDcOp should
 *     point to a CpaDcOpData structure.
 *
 *  -# For a symmetric crypto operation,  the corresponding
 *     pChainOpData[]->opType should be set to
 *     CPA_DC_CHAIN_SYMMETRIC_CRYPTO and pChainOpData[]->pCySymOp should
 *     point to a CpaCySymOpData structure.
 *
 *   -# Partial packet processing is not supported.
 *
 *   This function has identical buffer processing rules as
 *   cpaDcCompressData().
 *
 *   This function has identical checksum processing rules as
 *   cpaDcCompressData(), except:
 *   -# pResults->crc32 is available to the application if
 *      CpaDcSessionSetupData->checksum is set to CPA_DC_CRC32
 *      and will contain a crc32 checksum.
 *
 *   -# pResults->adler32 is available to the application if
 *      CpaDcSessionSetupData->checksum is set to CPA_DC_ADLER32
 *      and will contain an adler32 checksum.
 *
 *   -# pResults->adler32 is available to the application if
 *      CpaDcSessionSetupData->checksum is set to CPA_DC_XXHASH32
 *      and will contain an xxhash32 checksum.
 *
 *   -# Both pResults->crc32 and pResults->adler32 are available if
 *      CpaDcSessionSetupData->checksum is set to CPA_DC_CRC32_ADLER32
 *      and will contain crc32 and adler32 checksums respectively.
 *
 *  Synchronous or asynchronous operation of the API is determined by
 *  the value of the callbackFn parameter passed to cpaDcChainInitSession()
 *  when the sessionHandle was setup. If a non-NULL value was specified
 *  then the supplied callback function will be invoked asynchronously
 *  with the response of this request.
 *
 *  This function has identical response ordering rules as
 *  cpaDcCompressData().
 *
 * @see
 *      cpaDcCompressData
 *
 *****************************************************************************/
CpaStatus cpaDcChainPerformOp(CpaInstanceHandle dcInstance,
                              CpaDcSessionHandle pSessionHandle,
                              CpaBufferList *pSrcBuff,
                              CpaBufferList *pDestBuff,
                              CpaDcChainOperations operation,
                              Cpa8U numOpData,
                              CpaDcChainOpData *pChainOpData,
                              CpaDcChainRqResults *pResults,
                              void *callbackTag);

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Submit a request to perform chaining with integrity operations.
 *
 * @description
 *      This function is used to perform chaining operations over data from
 *      the source buffer with optional integrity checking.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]     dcInstance        Target service instance.
 * @param[in,out] pSessionHandle    Session handle.
 * @param[in]     pSrcBuff          Pointer to input data buffer.
 * @param[out]    pDestBuff         Pointer to output data buffer.
 * @param[in]     pInterBuff        Pointer to intermediate buffer to be used
 *                                  as internal staging area for chaining
 *                                  operations.
 * @param[in]     opData            User supplied CpaDcChainOpData2
 *                                  structure.
 * @param[in,out] pResults          Pointer to CpaDcChainRqVResults
 *                                  structure.
 * @param[in]     callbackTag       User supplied value to help correlate
 *                                  the callback with its associated request.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_DC_BAD_DATA          The input data was not properly formed.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *     pSessionHandle has been setup using cpaDcChainInitSession()
 * @post
 *     Following synchronous operation:
 *     The pSessionHandle will contain updated session related state
 *     information.
 *     The pDestBuff will contain processed data following the chained
 *     operation.
 *     The pResults will contain the status/checksums/additional outputs
 *     from the completed chained operation.
 *     Following asynchronous operation:
 *     The call has been submitted only and the data structures above will
 *     only be safe to use once the asynchronous callback is called.
 * @note
 *     This function passes control to the compression service for chaining
 *     processing, the supported chaining operations are described in
 *     CpaDcChainOperations.
 *     This function is a replacement for cpaDcChainPerformOp() supporting
 *     additional integrity chaining features and should be used if these
 *     additional features are required.
 *
 *  User supplied opData contains pChainOpData
 *  -# Refer to cpaDcChainPerformOp for pChainOpData Setup Rules
 *
 *  This function has identical buffer processing rules as
 *  cpaDcCompressData().
 *
 *  Synchronous or asynchronous operation of the API is determined by
 *  the value of the callbackFn parameter passed to cpaDcChainInitSession()
 *  when the sessionHandle was setup. If a non-NULL value was specified
 *  then the supplied callback function will be invoked asynchronously
 *  with the response of this request.
 *
 *  This function has identical response ordering rules as
 *  cpaDcCompressData().
 *
 * @see
 *      cpaDcCompressData
 *
 *****************************************************************************/
CpaStatus cpaDcChainPerformOp2(CpaInstanceHandle dcInstance,
                               CpaDcSessionHandle pSessionHandle,
                               CpaBufferList *pSrcBuff,
                               CpaBufferList *pDestBuff,
                               CpaBufferList *pInterBuff,
                               CpaDcChainOpData2 opData,
                               CpaDcChainRqVResults *pResults,
                               void *callbackTag);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_DC_CHAIN_H */
