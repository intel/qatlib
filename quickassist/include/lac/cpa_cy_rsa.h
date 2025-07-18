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
 * @file cpa_cy_rsa.h
 *
 * @defgroup cpaCyRsa RSA API
 *
 * @ingroup cpaCy
 *
 * @description
 *      These functions specify the API for Public Key Encryption
 *      (Cryptography) RSA operations. The PKCS #1 V2.1 specification is
 *      supported, however the support is limited to "two-prime" mode. RSA
 *      multi-prime is not supported.
 *
 * @note
 *     These functions implement RSA cryptographic primitives. RSA padding
 *     schemes are not implemented. For padding schemes that require the mgf
 *     function see @ref cpaCyKeyGen.
 *
 * @note
 *      Large numbers are represented on the QuickAssist API as described
 *      in the Large Number API (@ref cpaCyLn).
 *****************************************************************************/

#ifndef CPA_CY_RSA_H
#define CPA_CY_RSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa_cy_common.h"

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Version.
 * @description
 *      This enumeration lists the version identifier for the PKCS #1 V2.1
 *      standard.
 * @note
 *      Multi-prime (more than two primes) is not supported.
 *
 *****************************************************************************/
typedef enum _CpaCyRsaVersion
{
    CPA_CY_RSA_VERSION_TWO_PRIME = 1
    /**< The version supported is "two-prime". */
} CpaCyRsaVersion;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Public Key Structure.
 * @description
 *      This structure contains the two components which comprise the RSA
 *      public key as defined in the PKCS #1 V2.1 standard.
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. modulusN.pData[0] = MSB.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaPublicKey
{
    CpaFlatBuffer modulusN;
    /**< The modulus (n).
     * For key generation operations, the client MUST allocate the memory
     * for this parameter; its value is generated.
     * For encrypt operations this parameter is an input. */
    CpaFlatBuffer publicExponentE;
    /**< The public exponent (e).
     * For key generation operations, this field is unused.  It is NOT
     * generated by the interface; it is the responsibility of the client
     * to set this to the same value as the corresponding parameter on
     * the CpaCyRsaKeyGenOpData structure before using the key for
     * encryption.
     * For encrypt operations this parameter is an input. */
} CpaCyRsaPublicKey;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Private Key Structure For Representation 1.
 * @description
 *      This structure contains the first representation that can be used for
 *      describing the RSA private key, represented by the tuple of the
 *      modulus (n) and the private exponent (d).
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. modulusN.pData[0] = MSB.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaPrivateKeyRep1
{
    CpaFlatBuffer modulusN;
    /**< The modulus (n). For key generation operations the memory MUST
     * be allocated by the client and the value is generated. For other
     * operations this is an input. Permitted lengths are:
     *
     * - 512 bits (64 bytes),
     * - 1024 bits (128 bytes),
     * - 1536 bits (192 bytes),
     * - 2048 bits (256 bytes),
     * - 3072 bits (384 bytes),
     * - 4096 bits (512 bytes), or
     * - 8192 bits (1024 bytes).
     */
    CpaFlatBuffer privateExponentD;
    /**< The private exponent (d). For key generation operations the
     * memory MUST be allocated by the client and the value is generated. For
     * other operations this is an input.
     * NOTE: It is important that the value D is big enough. It is STRONGLY
     * recommended that this value is at least half the length of the modulus
     * N to protect against the Wiener attack. */
} CpaCyRsaPrivateKeyRep1;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Private Key Structure For Representation 2.
 * @description
 *      This structure contains the second representation that can be used for
 *      describing the RSA private key. The quintuple of p, q, dP, dQ, and qInv
 *      (explained below and in the spec) are required for the second
 *      representation. The optional sequence of triplets are not included.
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. prime1P.pData[0] = MSB.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaPrivateKeyRep2
{
    CpaFlatBuffer prime1P;
    /**< The first large prime (p).
     * For key generation operations, this field is unused. */
    CpaFlatBuffer prime2Q;
    /**< The second large prime (q).
     * For key generation operations, this field is unused. */
    CpaFlatBuffer exponent1Dp;
    /**< The first factor CRT exponent (dP). d mod (p-1). */
    CpaFlatBuffer exponent2Dq;
    /**< The second factor CRT exponent (dQ). d mod (q-1). */
    CpaFlatBuffer coefficientQInv;
    /**< The (first) Chinese Remainder Theorem (CRT) coefficient (qInv).
     * (inverse of q) mod p. */
} CpaCyRsaPrivateKeyRep2;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA DPA Opdata.
 * @description
 *      This structure contains data needed to perform RSA DPA decrypt.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaDpaOpData
{
    CpaFlatBuffer *pRsaPrimeP;
    /**< Pointer to RSA prime P data buffer. */
    CpaFlatBuffer *pRsaPrimeQ;
    /**< Pointer to RSA prime Q data buffer. */
    CpaFlatBuffer *pRsaPublicE;
    /**< Pointer to an RSA Public key exponent. */
    CpaFlatBuffer *pRandom;
    /**< Pointer to buffer containing cryptographically secure random data. */
    CpaBoolean createRandomData;
    /**< Control parameter to delegate the random data generation to QAT. If
     * set to CPA_TRUE, input parameter pRandom is ignored. */
} CpaCyRsaDpaOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA private key representation type.
 * @description
 *      This enumeration lists which PKCS V2.1 representation of the private
 *      key is being used.
 *
 *****************************************************************************/
typedef enum _CpaCyRsaPrivateKeyRepType
{
    CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 = 1,
    /**< The first representation of the RSA private key. */
    CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2
    /**< The second representation of the RSA private key. */
} CpaCyRsaPrivateKeyRepType;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Private Key Structure.
 * @description
 *      This structure contains the two representations that can be used for
 *      describing the RSA private key. The privateKeyRepType will be used to
 *      identify which representation is to be used. Typically, using the
 *      second representation results in faster decryption operations.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaPrivateKey
{
    CpaCyRsaVersion version;
    /**< Indicates the version of the PKCS #1 specification that is
     * supported.
     * Note that this applies to both representations. */
    CpaCyRsaPrivateKeyRepType privateKeyRepType;
    /**< This value is used to identify which of the private key
     * representation types in this structure is relevant.
     * When performing key generation operations for Type 2 representations,
     * memory must also be allocated for the type 1 representations, and values
     * for both will be returned. */
    CpaCyRsaPrivateKeyRep1 privateKeyRep1;
    /**< This is the first representation of the RSA private key as
     * defined in the PKCS #1 V2.1 specification. For key generation operations
     * the memory for this structure is allocated by the client and the
     * specific values are generated. For other operations this is an input
     * parameter. */
    CpaCyRsaPrivateKeyRep2 privateKeyRep2;
    /**< This is the second representation of the RSA private key as
     * defined in the PKCS #1 V2.1 specification. For key generation operations
     * the memory for this structure is allocated by the client and the
     * specific values are generated. For other operations this is an input
     * parameter. */
} CpaCyRsaPrivateKey;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Key Generation Data.
 * @description
 *      This structure lists the different items that are required in the
 *      cpaCyRsaGenKey function. The client MUST allocate the memory for this
 *      structure. When the structure is passed into the function, ownership of
 *      the memory passes to the function. Ownership of the memory returns to
 *      the client when this structure is returned in the
 *      CpaCyRsaKeyGenCbFunc callback function.
 *
 * @note
 *      If the client modifies or frees the memory referenced in this structure
 *      after it has been submitted to the cpaCyRsaGenKey function, and
 *      before it has been returned in the callback, undefined behavior will
 *      result.
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. prime1P.pData[0] = MSB.
 *
 *      The following limitations on the permutations of the supported bit
 *      lengths of p, q and n (written as {p, q, n}) apply:
 *
 *      - {256, 256, 512} or
 *      - {512, 512, 1024} or
 *      - {768, 768, 1536} or
 *      - {1024, 1024, 2048} or
 *      - {1536, 1536, 3072} or
 *      - {2048, 2048, 4096}.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaKeyGenOpData
{
    CpaFlatBuffer prime1P;
    /**< A large random prime number (p). This MUST be created by the
     * client. Permitted bit lengths are: 256, 512, 768, 1024, 1536 or 2048.
     * Limitations apply - refer to the description above for details. */
    CpaFlatBuffer prime2Q;
    /**<  A large random prime number (q). This MUST be created by the
     * client. Permitted bit lengths are: 256, 512, 768, 1024, 1536 or 2048.
     * Limitations apply - refer to the description above for details. If the
     * private key representation type is 2, then this pointer will be assigned
     * to the relevant structure member of the representation 2 private key. */
    Cpa32U modulusLenInBytes;
    /**<  The bit length of the modulus (n). This is the modulus length for
     * both the private and public keys. The length of the modulus N parameter
     * for the private key representation 1 structure and the public key
     * structures will be assigned to this value. References to the strength of
     * RSA actually refer to this bit length. Recommended minimum is 1024 bits.
     * Permitted lengths are:
     * - 512 bits (64 bytes),
     * - 1024 bits (128 bytes),
     * - 1536 bits (192 bytes),
     * - 2048 bits (256 bytes),
     * - 3072 bits (384 bytes), or
     * - 4096 bits (512 bytes).
     * Limitations apply - refer to description above for details. */
    CpaCyRsaVersion version;
    /**< Indicates the version of the PKCS #1 specification that is
     * supported.
     * Note that this applies to both representations. */
    CpaCyRsaPrivateKeyRepType privateKeyRepType;
    /**< This value is used to identify which of the private key
     * representation types is required to be generated. */
    CpaFlatBuffer publicExponentE;
    /**< The public exponent (e). */
} CpaCyRsaKeyGenOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Encryption Primitive Operation Data
 * @description
 *      This structure lists the different items that are required in the
 *      cpaCyRsaEncrypt function.  As the RSA encryption primitive and
 *      verification primitive operations are mathematically identical this
 *      structure may also be used to perform an RSA verification primitive
 *      operation.
 *      When performing an RSA encryption primitive operation, the input data
 *      is the message and the output data is the cipher text.
 *      When performing an RSA verification primitive operation, the input data
 *      is the signature and the output data is the message.
 *      The client MUST allocate the memory for this structure. When the
 *      structure is passed into the function, ownership of the memory passes
 *      to the function. Ownership of the memory returns to the client when
 *      this structure is returned in the CpaCyRsaEncryptCbFunc
 *      callback function.
 *
 * @note
 *      If the client modifies or frees the memory referenced in this structure
 *      after it has been submitted to the cpaCyRsaEncrypt function, and
 *      before it has been returned in the callback, undefined behavior will
 *      result.
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. inputData.pData[0] = MSB.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaEncryptOpData
{
    CpaCyRsaPublicKey *pPublicKey;
    /**< Pointer to the public key. */
    CpaFlatBuffer inputData;
    /**< The input data that the RSA encryption primitive operation is
     * performed on. The data pointed to is an integer that MUST be in big-
     * endian order. The value MUST be between 0 and the modulus n - 1. */
} CpaCyRsaEncryptOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Decryption Primitive Operation Data
 * @description
 *      This structure lists the different items that are required in the
 *      cpaCyRsaDecrypt function.  As the RSA decryption primitive and
 *      signature primitive operations are mathematically identical this
 *      structure may also be used to perform an RSA signature primitive
 *      operation.
 *      When performing an RSA decryption primitive operation, the input data
 *      is the cipher text and the output data is the message text.
 *      When performing an RSA signature primitive operation, the input data
 *      is the message and the output data is the signature.
 *      The client MUST allocate the memory for this structure. When the
 *      structure is passed into the function, ownership of the memory passes
 *      to he function. Ownership of the memory returns to the client when
 *      this structure is returned in the CpaCyRsaDecryptCbFunc
 *      callback function.
 *
 * @note
 *      If the client modifies or frees the memory referenced in this structure
 *      after it has been submitted to the cpaCyRsaDecrypt function, and
 *      before it has been returned in the callback, undefined behavior will
 *      result.
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. inputData.pData[0] = MSB.
 *
 *****************************************************************************/
typedef struct _CpaCyRsaDecryptOpData
{
    CpaCyRsaPrivateKey *pRecipientPrivateKey;
    /**< Pointer to the recipient's RSA private key. */
    CpaFlatBuffer inputData;
    /**< The input data that the RSA decryption primitive operation is
     * performed on. The data pointed to is an integer that MUST be in big-
     * endian order. The value MUST be between 0 and the modulus n - 1. */
} CpaCyRsaDecryptOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Statistics.
 * @deprecated
 *      As of v1.3 of the Crypto API, this structure has been deprecated,
 *      replaced by @ref CpaCyRsaStats64.
 * @description
 *      This structure contains statistics on the RSA operations.
 *      Statistics are set to zero when the component is initialized, and are
 *      collected per instance.
 ****************************************************************************/
typedef struct _CpaCyRsaStats
{
    Cpa32U numRsaKeyGenRequests;
    /**<  Total number of successful RSA key generation requests. */
    Cpa32U numRsaKeyGenRequestErrors;
    /**<  Total number of RSA key generation requests that had an error and
     * could not be processed. */
    Cpa32U numRsaKeyGenCompleted;
    /**<  Total number of RSA key generation operations that completed
     * successfully. */
    Cpa32U numRsaKeyGenCompletedErrors;
    /**<  Total number of RSA key generation operations that could not be
     * completed successfully due to errors. */
    Cpa32U numRsaEncryptRequests;
    /**<  Total number of successful RSA encrypt operation requests. */
    Cpa32U numRsaEncryptRequestErrors;
    /**<  Total number of RSA encrypt requests that had an error and could
     * not be processed. */
    Cpa32U numRsaEncryptCompleted;
    /**<  Total number of RSA encrypt operations that completed
     * successfully. */
    Cpa32U numRsaEncryptCompletedErrors;
    /**<  Total number of RSA encrypt operations that could not be
     * completed successfully due to errors. */
    Cpa32U numRsaDecryptRequests;
    /**<  Total number of successful RSA decrypt operation requests. */
    Cpa32U numRsaDecryptRequestErrors;
    /**<  Total number of RSA decrypt requests that had an error and could
     * not be processed. */
    Cpa32U numRsaDecryptCompleted;
    /**<  Total number of RSA decrypt operations that completed
     * successfully. */
    Cpa32U numRsaDecryptCompletedErrors;
    /**<  Total number of RSA decrypt operations that could not be
     * completed successfully due to errors. */
} CpaCyRsaStats CPA_DEPRECATED;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      RSA Statistics (64-bit version).
 * @description
 *      This structure contains 64-bit version of the statistics on the RSA
 *      operations.
 *      Statistics are set to zero when the component is initialized, and are
 *      collected per instance.
 ****************************************************************************/
typedef struct _CpaCyRsaStats64
{
    Cpa64U numRsaKeyGenRequests;
    /**<  Total number of successful RSA key generation requests. */
    Cpa64U numRsaKeyGenRequestErrors;
    /**<  Total number of RSA key generation requests that had an error and
     * could not be processed. */
    Cpa64U numRsaKeyGenCompleted;
    /**<  Total number of RSA key generation operations that completed
     * successfully. */
    Cpa64U numRsaKeyGenCompletedErrors;
    /**<  Total number of RSA key generation operations that could not be
     * completed successfully due to errors. */
    Cpa64U numRsaEncryptRequests;
    /**<  Total number of successful RSA encrypt operation requests. */
    Cpa64U numRsaEncryptRequestErrors;
    /**<  Total number of RSA encrypt requests that had an error and could
     * not be processed. */
    Cpa64U numRsaEncryptCompleted;
    /**<  Total number of RSA encrypt operations that completed
     * successfully. */
    Cpa64U numRsaEncryptCompletedErrors;
    /**<  Total number of RSA encrypt operations that could not be
     * completed successfully due to errors. */
    Cpa64U numRsaDecryptRequests;
    /**<  Total number of successful RSA decrypt operation requests. */
    Cpa64U numRsaDecryptRequestErrors;
    /**<  Total number of RSA decrypt requests that had an error and could
     * not be processed. */
    Cpa64U numRsaDecryptCompleted;
    /**<  Total number of RSA decrypt operations that completed
     * successfully. */
    Cpa64U numRsaDecryptCompletedErrors;
    /**<  Total number of RSA decrypt operations that could not be
     * completed successfully due to errors. */
    Cpa64U numKptRsaDecryptRequests;
    /**<  Total number of successful KPT RSA decrypt operation requests. */
    Cpa64U numKptRsaDecryptRequestErrors;
    /**<  Total number of KPT RSA decrypt requests that had an error and could
     * not be processed. */
    Cpa64U numKptRsaDecryptCompleted;
    /**<  Total number of KPT RSA decrypt operations that completed
     * successfully. */
    Cpa64U numKptRsaDecryptCompletedErrors;
    /**<  Total number of KPT RSA decrypt operations that could not be
     * completed successfully due to errors. */
} CpaCyRsaStats64;

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Definition of the RSA key generation callback function.
 *
 * @description
 *      This is the prototype for the RSA key generation callback function. The
 *      callback function pointer is passed in as a parameter to the
 *      cpaCyRsaGenKey function. It will be invoked once the request has
 *      completed.
 *
 * @context
 *      This callback function can be executed in a context that DOES NOT
 *      permit sleeping to occur.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] pCallbackTag    Opaque value provided by user while making
 *                            individual function calls.
 * @param[in] status          Status of the operation. Valid values are
 *                            CPA_STATUS_SUCCESS, CPA_STATUS_FAIL and
 *                            CPA_STATUS_UNSUPPORTED.
 * @param[in] pKeyGenOpData   Structure with output params for callback.
 * @param[in] pPrivateKey     Structure which contains pointers to the memory
 *                            into which the generated private key will be
 *                            written.
 * @param[in] pPublicKey      Structure which contains pointers to the memory
 *                            into which the generated public key will be
 *                            written. The pointer to the public exponent (e)
 *                            that is returned in this structure is equal to
 *                            the input public exponent.
 * @retval
 *      None
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 * @note
 *      None
 * @see
 *      CpaCyRsaPrivateKey,
 *      CpaCyRsaPublicKey,
 *      cpaCyRsaGenKey()
 *
 *****************************************************************************/
typedef void (*CpaCyRsaKeyGenCbFunc)(void *pCallbackTag,
                                     CpaStatus status,
                                     void *pKeyGenOpData,
                                     CpaCyRsaPrivateKey *pPrivateKey,
                                     CpaCyRsaPublicKey *pPublicKey);

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Generate RSA keys.
 *
 * @description
 *      This function will generate private and public keys for RSA as specified
 *      in the PKCS #1 V2.1 standard. Both representation types of the private
 *      key may be generated.
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
 * @param[in]  instanceHandle    Instance handle.
 * @param[in]  pRsaKeyGenCb      Pointer to the callback function to be invoked
 *                               when the operation is complete. If this is
 *                               set to a NULL value the function will operate
 *                               synchronously.
 * @param[in]  pCallbackTag      Opaque User Data for this specific call. Will
 *                               be returned unchanged in the callback.
 * @param[in]  pKeyGenOpData     Structure containing all the data needed to
 *                               perform the RSA key generation operation. The
 *                               client code allocates the memory for this
 *                               structure. This component takes ownership of
 *                               the memory until it is returned in the
 *                               callback.
 * @param[out] pPrivateKey       Structure which contains pointers to the memory
 *                               into which the generated private key will be
 *                               written.  The client MUST allocate memory
 *                               for this structure, and for the pointers
 *                               within it, recursively; on return, these will
 *                               be populated.
 * @param[out] pPublicKey        Structure which contains pointers to the memory
 *                               into which the generated public key will be
 *                               written.  The memory for this structure and
 *                               for the modulusN parameter MUST be allocated
 *                               by the client, and will be populated on return
 *                               from the call.  The field publicExponentE
 *                               is not modified or touched in any way; it is
 *                               the responsibility of the client to set this
 *                               to the same value as the corresponding
 *                               parameter on the CpaCyRsaKeyGenOpData
 *                               structure before using the key for encryption.
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
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      When pRsaKeyGenCb is non-NULL, an asynchronous callback of type is
 *      generated in response to this function call.
 *      Any errors generated during processing are reported as part of the
 *      callback status code. For optimal performance, data pointers SHOULD be
 *      8-byte aligned.
 * @see
 *      CpaCyRsaKeyGenOpData,
 *      CpaCyRsaKeyGenCbFunc,
 *      cpaCyRsaEncrypt(),
 *      cpaCyRsaDecrypt()
 *
 *****************************************************************************/
CpaStatus cpaCyRsaGenKey(const CpaInstanceHandle instanceHandle,
                         const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                         void *pCallbackTag,
                         const CpaCyRsaKeyGenOpData *pKeyGenOpData,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey);

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Perform the RSA encrypt (or verify) primitive operation on the input
 *      data.
 *
 * @description
 *      This function will perform an RSA encryption primitive operation on the
 *      input data using the specified RSA public key.  As the RSA encryption
 *      primitive and verification primitive operations are mathematically
 *      identical this function may also be used to perform an RSA verification
 *      primitive operation.
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
 * @param[in]  instanceHandle    Instance handle.
 * @param[in]  pRsaEncryptCb     Pointer to callback function to be invoked
 *                               when the operation is complete. If this is
 *                               set to a NULL value the function will operate
 *                               synchronously.
 * @param[in]  pCallbackTag      Opaque User Data for this specific call. Will
 *                               be returned unchanged in the callback.
 * @param[in]  pEncryptOpData    Structure containing all the data needed to
 *                               perform the RSA encryption operation. The
 *                               client code allocates the memory for this
 *                               structure. This component takes ownership of
 *                               the memory until it is returned in the
 *                               callback.
 * @param[out] pOutputData       Pointer to structure into which the result of
 *                               the RSA encryption primitive is written. The
 *                               client MUST allocate this memory. The data
 *                               pointed to is an integer in big-endian order.
 *                               The value will be between 0 and the modulus
 *                               n - 1.
 *                               On invocation the callback function will
 *                               contain this parameter in the pOut parameter.
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
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      When pRsaEncryptCb is non-NULL an asynchronous callback of type is
 *      generated in response to this function call.
 *      Any errors generated during processing are reported as part of the
 *      callback status code. For optimal performance, data pointers SHOULD be
 *      8-byte aligned.
 * @see
 *      CpaCyGenFlatBufCbFunc
 *      CpaCyRsaEncryptOpData
 *      cpaCyRsaGenKey()
 *      cpaCyRsaDecrypt()
 *
 *****************************************************************************/
CpaStatus cpaCyRsaEncrypt(const CpaInstanceHandle instanceHandle,
                          const CpaCyGenFlatBufCbFunc pRsaEncryptCb,
                          void *pCallbackTag,
                          const CpaCyRsaEncryptOpData *pEncryptOpData,
                          CpaFlatBuffer *pOutputData);

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Perform the RSA decrypt (or sign) primitive operation on the input
 *      data.
 *
 * @description
 *      This function will perform an RSA decryption primitive operation on the
 *      input data using the specified RSA private key. As the RSA decryption
 *      primitive and signing primitive operations are mathematically identical
 *      this function may also be used to perform an RSA signing primitive
 *      operation.
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
 * @param[in]  instanceHandle   Instance handle.
 * @param[in]  pRsaDecryptCb    Pointer to callback function to be invoked
 *                              when the operation is complete. If this is
 *                              set to a NULL value the function will operate
 *                              synchronously.
 * @param[in]  pCallbackTag     Opaque User Data for this specific call.
 *                              Will be returned unchanged in the callback.
 * @param[in]  pDecryptOpData   Structure containing all the data needed to
 *                              perform the RSA decrypt operation. The
 *                              client code allocates the memory for this
 *                              structure. This component takes ownership
 *                              of the memory until it is returned in the
 *                              callback.
 * @param[out] pOutputData      Pointer to structure into which the result of
 *                              the RSA decryption primitive is written. The
 *                              client MUST allocate this memory. The data
 *                              pointed to is an integer in big-endian order.
 *                              The value will be between 0 and the modulus
 *                              n - 1.
 *                              On invocation the callback function will
 *                              contain this parameter in the pOut parameter.
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
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      When pRsaDecryptCb is non-NULL an asynchronous callback is generated in
 *      response to this function call.
 *      Any errors generated during processing are reported as part of the
 *      callback status code. For optimal performance, data pointers SHOULD be
 *      8-byte aligned.
 * @see
 *      CpaCyRsaDecryptOpData,
 *      CpaCyGenFlatBufCbFunc,
 *      cpaCyRsaGenKey(),
 *      cpaCyRsaEncrypt()
 *
 *****************************************************************************/
CpaStatus cpaCyRsaDecrypt(const CpaInstanceHandle instanceHandle,
                          const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                          void *pCallbackTag,
                          const CpaCyRsaDecryptOpData *pDecryptOpData,
                          CpaFlatBuffer *pOutputData);

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Perform Differential Power Analysis (DPA) resistant RSA decrypt
 *      (or sign) primitive operation on the input data. This is the DPA
 *      variation of cpaCyRsaDecrypt() API.
 *
 * @description
 *      This function will perform an RSA decryption primitive operation on the
 *      input data using the specified RSA private key. As the RSA decryption
 *      primitive and signing primitive operations are mathematically identical
 *      this function may also be used to perform an RSA signing primitive
 *      operation.
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
 * @param[in]  instanceHandle   Instance handle.
 * @param[in]  pRsaDecryptCb    Pointer to callback function to be invoked
 *                              when the operation is complete. If this is
 *                              set to a NULL value the function will operate
 *                              synchronously.
 * @param[in]  pCallbackTag     Opaque User Data for this specific call.
 *                              Will be returned unchanged in the callback.
 * @param[in]  pDecryptOpData   Structure containing all the data needed to
 *                              perform the RSA decrypt operation. The
 *                              client code allocates the memory for this
 *                              structure. This component takes ownership
 *                              of the memory until it is returned in the
 *                              callback.
 * @param[in]  pDpaOpData       Structure containing the additional
 *                              configuration settings to make the RSA decrypt
 *                              operations DPA resilient.
 * @param[out] pOutputData      Pointer to structure into which the result of
 *                              the RSA decryption primitive is written. The
 *                              client MUST allocate this memory. The data
 *                              pointed to is an integer in big-endian order.
 *                              The value will be between 0 and the modulus
 *                              n - 1.
 *                              On invocation the callback function will
 *                              contain this parameter in the pOut parameter.
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
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      When pRsaDecryptCb is non-NULL an asynchronous callback is generated in
 *      response to this function call.
 *      Any errors generated during processing are reported as part of the
 *      callback status code. For optimal performance, data pointers SHOULD be
 *      8-byte aligned.
 * @see
 *      CpaCyRsaDecryptOpData,
 *      CpaCyGenFlatBufCbFunc,
 *      cpaCyRsaGenKey(),
 *      cpaCyRsaEncrypt()
 *
 *****************************************************************************/
CpaStatus cpaCyRsaDpaDecrypt(const CpaInstanceHandle instanceHandle,
                             const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                             void *pCallbackTag,
                             const CpaCyRsaDecryptOpData *pDecryptOpData,
                             const CpaCyRsaDpaOpData *pDpaOpData,
                             CpaFlatBuffer *pOutputData);

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Query statistics for a specific RSA instance.
 *
 * @deprecated
 *      As of v1.3 of the Crypto API, this function has been deprecated,
 *      replaced by @ref cpaCyRsaQueryStats64().
 *
 * @description
 *      This function will query a specific instance for RSA statistics. The
 *      user MUST allocate the CpaCyRsaStats structure and pass the
 *      reference to that into this function call. This function will write the
 *      statistic results into the passed in CpaCyRsaStats structure.
 *
 *      Note: statistics returned by this function do not interrupt current data
 *      processing and as such can be slightly out of sync with operations that
 *      are in progress during the statistics retrieval process.
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
 * @param[in]  instanceHandle       Instance handle.
 * @param[out] pRsaStats            Pointer to memory into which the statistics
 *                                  will be written.
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
 * @note
 *      This function operates in a synchronous manner and no asynchronous
 *      callback will be generated.
 * @see
 *      CpaCyRsaStats
 *
 *****************************************************************************/
CpaStatus CPA_DEPRECATED
cpaCyRsaQueryStats(const CpaInstanceHandle instanceHandle,
                   struct _CpaCyRsaStats *pRsaStats);

/**
 *****************************************************************************
 * @ingroup cpaCyRsa
 *      Query statistics (64-bit version) for a specific RSA instance.
 *
 * @description
 *      This function will query a specific instance for RSA statistics. The
 *      user MUST allocate the CpaCyRsaStats64 structure and pass the
 *      reference to that into this function call. This function will write the
 *      statistic results into the passed in CpaCyRsaStats64 structure.
 *
 *      Note: statistics returned by this function do not interrupt current data
 *      processing and as such can be slightly out of sync with operations that
 *      are in progress during the statistics retrieval process.
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
 * @param[in]  instanceHandle       Instance handle.
 * @param[out] pRsaStats            Pointer to memory into which the statistics
 *                                  will be written.
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
 * @note
 *      This function operates in a synchronous manner and no asynchronous
 *      callback will be generated.
 * @see
 *      CpaCyRsaStats64
 *****************************************************************************/
CpaStatus cpaCyRsaQueryStats64(const CpaInstanceHandle instanceHandle,
                               CpaCyRsaStats64 *pRsaStats);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_CY_RSA_H */
