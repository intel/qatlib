/***************************************************************************
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
 * @file cpa_cy_drbg.h
 *
 * @defgroup cpaCyDrbg Deterministic Random Bit Generation API
 *
 * @ingroup cpaCy
 *
 * @description
 *      These functions specify the API for a Deterministic Random Bit
 *      Generation (DRBG), compliant with NIST SP 800-90, March 2007,
 *      "Recommendation for Random Number Generation Using Deterministic
 *      Random Bit Generators (Revised)".
 *
 *      The functions @ref cpaCyDrbgInitSession, @ref
 *      cpaCyDrbgGen, @ref cpaCyDrbgReseed and @ref
 *      cpaCyDrbgRemoveSession are used to instantiate, generate,
 *      reseed and uninstantiate a DRBG mechanism.
 *
 * @note
 *         These functions supersede the random number generation functions
 *      in API group @ref cpaCyRand, which are now deprecated.
 *
 *****************************************************************************/

#ifndef CPA_CY_DRBG_H
#define CPA_CY_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa_cy_common.h"

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Security Strength
 * @description
 *      This enum defines the security strength.  NIST SP 800-90 defines
 *      security strength as "A number associated with the amount of work
 *      (that is, the number of operations) that is required to break a
 *      cryptographic algorithm or system; a security strength is specified
 *      in bits and is a specific value from the set (112, 128, 192, 256)
 *      for this Recommendation. The amount of work needed is
 *      2^(security_strength)."
 ****************************************************************************/
typedef enum _CpaCyDrbgSecStrength {
  CPA_CY_RBG_SEC_STRENGTH_112 = 1,
  CPA_CY_RBG_SEC_STRENGTH_128,
  CPA_CY_RBG_SEC_STRENGTH_192,
  CPA_CY_RBG_SEC_STRENGTH_256
} CpaCyDrbgSecStrength;

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      DRBG Session (Instance) Setup Data
 * @description
 *      This structure contains data relating to instantiation of a
 *      DRBG session, or instance.
 *****************************************************************************/
typedef struct _CpaCyDrbgSessionSetupData {
    CpaCyDrbgSecStrength secStrength;
    /**< Requested security strength */

    CpaBoolean predictionResistanceRequired;
    /**< Prediction resistance flag.
     * Indicates whether or not prediction resistance may be required by the
     * consuming application during one or more requests for pseudorandom
     * bits.
     */
    CpaFlatBuffer personalizationString;
    /**< Personalization string.
     * String that should be used to derive the seed.
     */
} CpaCyDrbgSessionSetupData;


/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Handle to a DRBG session (or instance).
 * @description
 *      This is what NIST SP 800-90 refers to as the "state_handle".
 *      That document also refers to the process of creating such a handle
 *      as "instantiation", or instance creation.  On this API, we use the
 *      term "session" to refer to such an instance, to avoid confusion with
 *      the crypto instance handle, and for consistency with the similar
 *      concept of sessions in symmetric crypto (see @ref cpaCySym) and
 *      elsewhere on the API.
 *
 *      Note that there can be multiple sessions, or DRBG instances, created
 *      within a single instance of a CpaInstanceHandle.
 *
 * @note
 *      The memory for this handle is allocated by the client. The size
 *      of the memory that the client needs to allocate is determined
 *      by a call to the @ref cpaCyDrbgSessionGetSize function. The
 *      session memory is initialized with a call to the @ref
 *      cpaCyDrbgInitSession function.  This memory MUST not be
 *      freed until a call to @ref cpaCyDrbgRemoveSession has
 *      completed successfully.
 *****************************************************************************/
typedef void* CpaCyDrbgSessionHandle;

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      DRBG Data Generation Operation Data
 * @description
 *      This structure contains data relating to generation of random bits
 *      using a DRBG.
 * @see
 *         cpaCyDrbgGen()
 * @note
 *      If the client modifies or frees the memory referenced in this structure
 *      after it has been submitted to the @ref cpaCyDrbgGen() function, and
 *      before it has been returned in the callback, undefined behavior will
 *      result.
 *****************************************************************************/
typedef struct _CpaCyDrbgGenOpData {
  CpaCyDrbgSessionHandle sessionHandle;
  /**< Session handle, also known as the state handle or instance handle */
  Cpa32U lengthInBytes;
  /**< Requested number of bytes to be generated */
    CpaCyDrbgSecStrength secStrength;
    /**< Requested security strength */
    CpaBoolean predictionResistanceRequired;
    /**< Requested prediction resistance flag.
     * Indicates whether or not prediction resistance is to be
     * provided prior to the generation of the requested pseudorandom
     * bits to be generated.
     */
    CpaFlatBuffer additionalInput;
    /**< Additional input */
} CpaCyDrbgGenOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      DRBG Reseed Operation Data
 * @description
 *      This structure contains data relating to reseeding a DRBG session,
 *      or instance.
 * @see
 *         cpaCyDrbgReseed()
 * @note
 *      If the client modifies or frees the memory referenced in this structure
 *      after it has been submitted to the @ref cpaCyDrbgReseed() function,
 *      and before it has been returned in the callback, undefined behavior will
 *      result.
 *****************************************************************************/
typedef struct _CpaCyDrbgReseedOpData {
    CpaCyDrbgSessionHandle sessionHandle;
    /**< Session handle, also known as a state handle or instance handle. */
    CpaFlatBuffer additionalInput;
    /**< An "optional" input to the reseeding.  The length should be
     * less than or equal to the seed length, which is returned by the
     * function @ref cpaCyDrbgInitSession().  A length of 0 can be
     * specified to indicate no additional input. */
} CpaCyDrbgReseedOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      DRBG Statistics
 * @description
 *      This structure contains statistics (counters) related to the
 *      random bit generation API.
 * @see
 *         CpaCyDrbgQueryStats64()
 *****************************************************************************/
typedef struct _CpaCyDrbgStats64 {
    Cpa64U numSessionsInitialized;
    /**<  Number of session initialized */
    Cpa64U numSessionsRemoved;
    /**<  Number of sessions removed */
    Cpa64U numSessionErrors;
    /**<  Total number of errors returned when initializing and removing
     * sessions
     */

    Cpa64U numGenRequests;
    /**<  Number of successful calls to @ref cpaCyDrbgGen. */
    Cpa64U numGenRequestErrors;
    /**<  Number of calls to @ref cpaCyDrbgGen that returned an error and
     * could not be processed.
     */
    Cpa64U numGenCompleted;
    /**<  Number of calls to @ref cpaCyDrbgGen that completed
     * successfully.
     */
    Cpa64U numGenCompletedErrors;
    /**<  Number of calls to @ref cpaCyDrbgGen that completed with an error
     * status.
     */

    Cpa64U numReseedRequests;
    /**<  Number of successful calls to @ref cpaCyDrbgReseed.
     *
     * Note that this does NOT include implicit reseeds due to calls to @ref
     * cpaCyDrbgGen with prediction resistance, or due to seed
     * lifetime expiry.
     */
    Cpa64U numReseedRequestErrors;
    /**<  Number of calls to @ref cpaCyDrbgReseed that returned an error and
     * could not be processed.
     */
    Cpa64U numReseedCompleted;
    /**<  Number of calls to @ref cpaCyDrbgReseed that completed
     * successfully.
     */
    Cpa64U numReseedCompletedErrors;
    /**<  Number of calls to @ref cpaCyDrbgReseed that completed with an
     * error status.
     */
} CpaCyDrbgStats64;



/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Returns the size (in bytes) of a DRBG session handle.
 *
 * @description
 *      This function is used by the client to determine the size of the memory
 *      it must allocate in order to store the DRBG session.  This MUST be
 *      called before the client allocates the memory for the session
 *      and before the client calls the @ref cpaCyDrbgInitSession function.
 *
 * @context
 *      This is a synchronous function and it can sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
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
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  pSetupData            Pointer to session setup data which
 *                                   contains parameters which are static
 *                                   for a given DRBG session, such
 *                                   as security strength, etc.
 * @param[out] pSize                 The amount of memory in bytes required
 *                                   to hold the session.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      The component has been initialized via the @ref cpaCyStartInstance
 *      function.
 * @post
 *      None
 *****************************************************************************/
CpaStatus
cpaCyDrbgSessionGetSize(const CpaInstanceHandle instanceHandle,
        const CpaCyDrbgSessionSetupData *pSetupData,
        Cpa32U *pSize);


/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Instantiates and seeds a DRBG session, or instance.
 *
 * @description
 *      This function is used by the client to initialize a DRBG session,
 *      or instance.
 * @note
 *      On some implementations, the client may have to register an entropy
 *      source, nonce source, and/or a function which specifies whether a
 *      derivation function is required.  See the Programmer's Guide for your
 *      implementation for more details.
 *
 * @context
 *      This is a synchronous function and it can sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
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
 * @param[in]  instanceHandle       Instance handle.
 * @param[in]  pGenCb               Pointer to callback function to be
 *                                  registered.  This is the function that will
 *                                  be called back to indicate completion of
 *                                  the asynchronous @ref cpaCyDrbgGen
 *                                  function.  Set this field to NULL if this
 *                                  function is to operate in a synchronous
 *                                  manner.
 * @param[in]  pReseedCb            Pointer to callback function to be
 *                                  registered.  This is the function that will
 *                                  be called back to indicate completion of
 *                                  the asynchronous @ref cpaCyDrbgReseed
 *                                  function.  Set this field to NULL if this
 *                                  function is to operate in a synchronous
 *                                  manner.
 * @param[in]  pSetupData            Pointer to setup data.
 * @param[out] sessionHandle        Pointer to the memory allocated by the
 *                                  client to store the instance handle. This
 *                                  will be initialized with this function. This
 *                                  handle needs to be passed to subsequent
 *                                  processing calls.
 * @param[out] pSeedLen             Seed length for the supported DRBG
 *                                     mechanism and security strength.
 *                                     The value of this is dependent on the
 *                                     DRBG mechanism implemented by the instance,
 *                                  which is implementation-dependent.
 *                                  This seed length may be used by the
 *                                  client when reseeding.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *      The component has been initialized via the @ref cpaCyStartInstance
 *      function.
 * @post
 *      None
 *****************************************************************************/
CpaStatus
cpaCyDrbgInitSession(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pGenCb,
        const CpaCyGenericCbFunc pReseedCb,
        const CpaCyDrbgSessionSetupData *pSetupData,
        CpaCyDrbgSessionHandle sessionHandle,
        Cpa32U* pSeedLen);

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Reseeds a DRBG session, or instance.
 *
 * @description
 *      Reseeding inserts additional entropy into the generation of
 *      pseudorandom bits.

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
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  pCallbackTag         Opaque User Data for this specific call. Will
 *                                  be returned unchanged in the callback.
 * @param[in]  pOpData                Structure containing all the data needed
 *                                   to perform the operation. The client code
 *                                   allocates the memory for this structure.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *      The component has been initialized via the @ref cpaCyStartInstance
 *      function.
 * @post
 *      None
 ******************************************************************************/
CpaStatus
cpaCyDrbgReseed(const CpaInstanceHandle instanceHandle,
        void *pCallbackTag,
        CpaCyDrbgReseedOpData *pOpData);

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Generates pseudorandom bits.
 *
 * @description
 *      This function is used to request the generation of random bits.
 *      The generated data and the length of the data will be
 *      returned to the caller in an asynchronous callback function.
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
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  pCallbackTag          Opaque User Data for this specific call. Will
 *                                   be returned unchanged in the callback.
 * @param[in]  pOpData                Structure containing all the data needed
 *                                   to perform the operation. The client code
 *                                   allocates the memory for this structure.
 *                                   This component takes ownership of the
 *                                   memory until it is returned in the
 *                                   callback.
 * @param[out] pPseudoRandomBits    Pointer to the memory allocated by the client
 *                                   where the random data will be written to. For
 *                                   optimal performance, the data pointed to SHOULD
 *                                   be 8-byte aligned. There is no endianness
 *                                   associated with the random data.
 *                                   On invocation the callback function will
 *                                   contain this parameter in its pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources. One
 *                                  reason may be for an entropy test failing.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *      The component has been initialized via the @ref cpaCyStartInstance
 *      function.
 *      The DRBG session, or instance, has been initialized via the @ref
 *      cpaCyDrbgInitSession function.
 * @post
 *      None
 ******************************************************************************/
CpaStatus
cpaCyDrbgGen(const CpaInstanceHandle instanceHandle,
        void *pCallbackTag,
        CpaCyDrbgGenOpData *pOpData,
        CpaFlatBuffer *pPseudoRandomBits);


/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Removes a previously instantiated DRBG session, or instance.
 *
 * @description
 *      This function will remove a previously initialized DRBG session,
 *      or instance, and the installed callback handler function.
 *      Removal will fail if outstanding calls still exist for the
 *      initialized session.  In this case, the client needs to retry
 *      the remove function at a later time.  The memory for the session
 *      handle MUST not be freed until this call has completed successfully.
 *
 * @context
 *      This is a synchronous function and it can sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
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
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  sessionHandle        DRBG session handle to be removed.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *      The component has been initialized via the @ref cpaCyStartInstance
 *      function.
 *      The DRBG session, or instance, has been initialized via the @ref
 *      cpaCyDrbgInitSession function.
 * @post
 *      None
 *****************************************************************************/
CpaStatus
cpaCyDrbgRemoveSession(const CpaInstanceHandle instanceHandle,
        CpaCyDrbgSessionHandle sessionHandle);

/**
 *****************************************************************************
 * @ingroup cpaCyDrbg
 *      Returns statistics specific to a session, or instance, of the
 *      RBG API.
 *
 * @description
 *      This function will query a specific session for RBG statistics.
 *      The user MUST allocate the CpaCyDrbgStats64 structure and pass the
 *      reference to that into this function call. This function writes
 *      the statistic results into the passed in CpaCyDrbgStats64 structure.
 *
 *      Note: statistics returned by this function do not interrupt current
 *      data processing and as such can be slightly out of sync with
 *      operations that are in progress during the statistics retrieval
 *      process.
 *
 * @context
 *      This is a synchronous function and it can sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle        Instance handle.
 * @param[out] pStats                 Pointer to memory into which the statistics
 *                                   will be written.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting. Resubmit
 *                                   the request.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 *****************************************************************************/
CpaStatus
cpaCyDrbgQueryStats64(const CpaInstanceHandle instanceHandle,
        CpaCyDrbgStats64 *pStats);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_CY_DRBG_H */
