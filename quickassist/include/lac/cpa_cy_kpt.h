/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 * @file cpa_cy_kpt.h
 *
 * @defgroup cpaCyKpt Intel(R) Key Protection Technology (KPT) Cryptographic API
 *
 * @ingroup cpaCy
 *
 * @description
 *     These functions specify the APIs for Key Protection Technology (KPT)
 *     Cryptographic services.
 *
 * @note
 *     These functions implement the KPT Cryptographic API, In order to
 *     realize full KPT function, you need Intel(R) PTT (Platform Trust
 *     Technology) and Intel C62X PCH support, which provide
 *     1. QuickAssist Technology
 *     2. Trusted Platform Module (TPM2.0)
 *     3. Secure communication channel between QAT and PTT
 *****************************************************************************/

#ifndef __CPA_CY_KPT_H__
#define __CPA_CY_KPT_H__

#ifdef __cplusplus
extern "C" {
#endif
#include "cpa_cy_common.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_dsa.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_ec.h"

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      KPT wrapping key handle
 *
 * @description
 *      Handle to a unique wrapping key in wrapping key table. Application
 *      creates it in KPT key transfer phase and maintains it for KPT Crypto
 *      service. For each KPT Crypto service API invocation,this handle will
 *      be used to get a SWK(Symmetric Wrapping Key ) to unwrap
 *      WPK(Wrapped Private Key) before performing the requested crypto
 *      service.
 *
 *****************************************************************************/
typedef Cpa64U CpaCyKptHandle;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Cipher algorithms used to generate a wrapped private key (WPK) from
 *      the clear private key.
 *
 * @description
 *      This enumeration lists supported cipher algorithms and modes.
 *
 *****************************************************************************/
typedef enum CpaCyKptWrappingKeyType_t {
    CPA_CY_KPT_WRAPPING_KEY_TYPE_AES128_GCM = 0,
    CPA_CY_KPT_WRAPPING_KEY_TYPE_AES256_GCM,
    CPA_CY_KPT_WRAPPING_KEY_TYPE_AES128_CBC,
    CPA_CY_KPT_WRAPPING_KEY_TYPE_AES256_CBC
}CpaCyKptWrappingKeyType;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Hash algorithms used to generate WPK hash tag or used to do HMAC
 *      authentication in KPT crypto service.
 * @description
 *      This enumeration lists supported hash algorithms.
 *
 *****************************************************************************/
typedef enum CpaCyKptHMACType_t {
    CPA_CY_KPT_HMAC_TYPE_NULL = 0,
    /**< No HMAC required */
    CPA_CY_KPT_HMAC_TYPE_SHA1,
    CPA_CY_KPT_HMAC_TYPE_SHA224,
    CPA_CY_KPT_HMAC_TYPE_SHA256,
    CPA_CY_KPT_HMAC_TYPE_SHA384,
    CPA_CY_KPT_HMAC_TYPE_SHA512,
    CPA_CY_KPT_HMAC_TYPE_SHA3_224,
    CPA_CY_KPT_HMAC_TYPE_SHA3_256,
    CPA_CY_KPT_HMAC_TYPE_SHA3_384,
    CPA_CY_KPT_HMAC_TYPE_SHA3_512
}CpaCyKptHMACType;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Return Status
 * @description
 *      This enumeration lists all the possible return status after completing
 *      KPT APIs.
 *
 *****************************************************************************/
typedef enum CpaCyKptKeyManagementStatus_t{
    CPA_CY_KPT_SUCCESS = 0,
    /**< Generic success status for all KPT wrapping key handling functions*/
    CPA_CY_KPT_REGISTER_HANDLE_FAIL_RETRY,
    /**< WKT is busy, retry after some time*/
    CPA_CY_KPT_REGISTER_HANDLE_FAIL_DUPLICATE,
    /**<Handle is already present in WKT; this is attempt at duplication */
    CPA_CY_KPT_LOAD_KEYS_FAIL_INVALID_HANDLE,
    /**<LoadKey call does not provide a handle that was previously registered.
     * Either application error, or malicious application. Reject request to
     * load the key.*/
    CPA_CY_KPT_REGISTER_HANDLE_FAIL_WKT_FULL,
    /**< Failed to register wrapping key as WKT is full*/
    CPA_CY_KPT_WKT_ENTRY_NOT_FOUND,
    /**< Unable to find SWK entry by handle */
    CPA_CY_KPT_REGISTER_HANDLE_FAIL_INSTANCE_QUOTA_EXCEEDED,
    /**< This application has opened too many WKT entries. A Quota is enforced
     * to prevent DoS attacks*/
    CPA_CY_KPT_LOADKEYS_FAIL_CHECKSUM_ERROR,
    /**< Checksum error in key loading*/
    CPA_CY_KPT_LOADKEYS_FAIL_HANDLE_NOT_REGISTERED,
    /**< Key is not registered in key loading*/
    CPA_CY_KPT_LOADKEYS_FAIL_POSSIBLE_DOS_ATTACK,
    /**< Possible Dos attack happened in key loading*/
    CPA_CY_KPT_LOADKEYS_FAIL_INVALID_AC_SEND_HANDLE,
    /**< Invalid key handle got from PTT*/
    CPA_CY_KPT_LOADKEYS_FAIL_INVALID_DATA_OBJ,
    /**< Invalid data object got from PTT*/
    CPA_CY_KPT_FAILED,
}CpaCyKptKeyManagementStatus;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Key selection flag.
 * @description
 *      This enumeration lists possible actions to be performed  during
 *      cpaCyKptLoadKeys invocation.
 *****************************************************************************/
typedef enum CpaCyKptKeySelectionFlags_t {
    CPA_CY_KPT_SWK,
    /**<Symmetric wrapping key,only a SWK will be loaded from PTT to QAT*/
    CPA_CY_KPT_WPK,
    /**<Wrapped private key, a data blob including SWK and CPK will be loaded
    from PTT to QAT, and WPK will be return to application.*/
    CPA_CY_KPT_OPAQUE_DATA,
    /**<Opaque data,a opaque data will be loaded from PTT to QAT*/
    CPA_CY_KPT_HMAC_AUTH_PARAMS,
    /**<HMAC auth params,HMAC auth params will be loaded from PTT to QAT*/
    CPA_CY_KPT_RN_SEED
    /**<DRBG seed,A rondom data generated by PTT will be loaded from PTT
    to QAT*/
}CpaCyKptKeySelectionFlags;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Key action.
 * @description
 *      PTT architecture support a "per-use" HMAC authorization for accessing
 *      and using key objects stored in PTT. This HMAC check is based on the
 *      use of running nonces shared between the application and PTT. To
 *      stay compatible with PTT's security protocol, QAT implements HMAC
 *      authorization protocol. This flag, set first time in cpaCyKptLoadKeys,
 *      will be used to determine whether HMAC authorization must be processed
 *      when QAT decrypts WPKs using SWKs.
 *
 *****************************************************************************/
typedef enum CpaCyKptKeyAction_t {
    CPA_CY_KPT_NO_HMAC_AUTH_CHECK,
    /**<Do not need HMAC authentication check in KPT Crypto service */
    CPA_CY_KPT_HMAC_AUTH_CHECK
    /**< Need HMAC authentication check in KPT Crypto service */
}CpaCyKptKeyAction;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Max length of initialization vector
 * @description
 *      Defines the permitted max iv length in bytes that may be used in
 *      private key wrapping/unwrapping.For AEC-GCM,iv length is 12 bytes,for
 *      AES-CBC,iv length is 16 bytes.
 *@see  cpaCyKptWrappingFormat
 *
 *****************************************************************************/
#define CPA_CY_KPT_MAX_IV_LENGTH  (16)

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      KPT wrapping format structure.
 * @description
 *      This structure defines wrapping format which is used to wrap clear
 *      private keys using a symmetric wrapping key.Application sets these
 *      parameters through the cpaCyKptLoadKeys calls.
 *
 *****************************************************************************/
typedef struct CpaCyKptWrappingFormat_t {
    CpaCyKptWrappingKeyType   wrappingAlgorithm;
    /**< Symmetric wrapping algorithm*/
    Cpa8U               iv[CPA_CY_KPT_MAX_IV_LENGTH];
    /**< Initialization Vector */
    Cpa32U              iterationCount;
    /**< Iteration Count for Key Wrap Algorithms */
    CpaCyKptHMACType    hmacType;
    /**< Hash algorithm used in WPK tag generation*/
} CpaCyKptWrappingFormat;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      RSA wrapped private key size structure For Representation 2.
 * @description
 *      This structure contains byte length of wrapped quintuple of p,q,dP,dQ
 *      and qInv which are required for the second representation of RSA
 *      private key.
 *       PKCS #1 V2.1 specification defines the second representation of the
 *      RSA private key,The quintuple of p, q, dP, dQ, and qInv  are required
 *      for this representation.
 * @ref CpaCyRsaPrivateKeyRep2
 *
 *****************************************************************************/
typedef struct CpaCyKptRsaWpkSizeRep2_t {
    Cpa32U pLenInBytes;
    /**< The byte length of wrapped prime p */
    Cpa32U qLenInBytes;
    /**< The byte length of wrapped prime q */
    Cpa32U dpLenInBytes;
    /**< The byte length of wrapped factor CRT exponent (dP) */
    Cpa32U dqLenInBytes;
    /**< The byte length of wrapped factor CRT exponent (dQ) */
    Cpa32U qinvLenInBytes;
    /**< The byte length of wrapped coefficient (qInv) */
} CpaCyKptRsaWpkSizeRep2;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Wrapped private key size union.
 * @description
 *      A wrapped private key size union, either wrapped quintuple of RSA
 *      representation 2 private key,or byte length of wrapped ECC/RSA Rep1/DSA/
 *      ECDSA private key.
 *
 *****************************************************************************/
typedef union CpaCyKptWpkSize_t
{
   Cpa32U  wpkLenInBytes;
   /**< The byte length of wrapped private key for Rsa rep1,ECC,DSA
    *and  ECDSA case*/
   CpaCyKptRsaWpkSizeRep2 rsaWpkSizeRep2;
   /**< The byte length of wrapped private key for RSA rep2 case*/
}CpaCyKptWpkSize;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Max length of HMAC value in HMAC authentication during KPT crypto
 *      service.
 * @description
 *      Defines the permitted max HMAC value length in bytes that may be used
 *      to do HMAC verification in KPT crypto service.
 *@see  cpaCyKptUnwrapContext
 *
 *****************************************************************************/
#define CPA_CY_KPT_HMAC_LENGTH  (64)

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Length of nonce generated by application in HMAC authentication during
 *      KPT crypto service.
 * @description
 *      Defines the caller nonce length in bytes that will be used to do HMAC
 *      authentication in KPT crypto service.
 *@see  cpaCyKptUnwrapContext
 *
 *****************************************************************************/
#define CPA_CY_KPT_CALLER_NONCE_LENGTH  (64)

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Length of nonce generated by QAT in HMAC authentication during KPT
 *      crypto service.
 * @description
 *      Defines the device nonce length in bytes that will be used to do HMAC
 *      authentication in KPT crypto service.
 *@see  cpaCyKptUnwrapContext
 *
 *****************************************************************************/
#define CPA_CY_KPT_DEVICE_NONCE_LENGTH  (64)

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Structure of KPT unwrapping context.
 * @description
 *      This structure is a parameter of KPT crypto APIs, it contains data
 *      relating to KPT WPK unwrapping and HMAC authentication,application
 *      should complete those information in structure.
 *
 *****************************************************************************/
typedef struct CpaCyKptUnwrapContext_t{
    CpaCyKptHandle   kptHandle;
    /**< This is application's unique handle that identifies its
     * (symmetric) wrapping key*/
    CpaCyKptWpkSize  wpkSize;
    /**< WPK's key size*/
    CpaCyKptHMACType  hmacAlg;
    /**< HMAC algorithm used in HMAC authentication in KPT crypto service*/
    Cpa8U          hmacAuthValue[CPA_CY_KPT_HMAC_LENGTH];
    /**< HMAC authentication value input by the application in KPT crypto
     * service;*/
    Cpa8U          callerNonce[CPA_CY_KPT_CALLER_NONCE_LENGTH];
    /**< Caller(app) nonce generated by app in KPT crypto service*/
    Cpa8U          deviceNonce[CPA_CY_KPT_DEVICE_NONCE_LENGTH];
    /**< Device nonce generated by device in KPT crypto service*/
} CpaCyKptUnwrapContext;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      KPTECDSA Sign R & S Operation Data.
 *
 * @description
 *      This structure contains the operation data for the cpaCyKptEcdsaSignRS
 *      function. The client MUST allocate the memory for this structure and the
 *      items pointed to by this structure. When the structure is passed into
 *      the function, ownership of the memory passes to the function. Ownership
 *      of the memory returns to the client when this structure is returned in
 *      the callback function.
 *
 *      For optimal performance all data buffers SHOULD be 8-byte aligned.
 *
 *      All values in this structure are required to be in Most Significant Byte
 *      first order, e.g. a.pData[0] = MSB.
 *
 * @note
 *      If the client modifies or frees the memory referenced in this
 *      structure after it has been submitted to the cpaCyKptEcdsaSignRS
 *      function, and before it has been returned in the callback, undefined
 *      behavior will result.
 *
 * @see
 *      cpaCyEcdsaSignRS()
 *
 *****************************************************************************/
typedef struct _CpaCyKptEcdsaSignRSOpData {
    CpaFlatBuffer xg;
    /**< x coordinate of base point G */
    CpaFlatBuffer yg;
    /**< y coordinate of base point G */
    CpaFlatBuffer n;
    /**< order of the base point G, which shall be prime */
    CpaFlatBuffer q;
    /**< prime modulus or irreducible polynomial over GF(2^r) */
    CpaFlatBuffer a;
    /**< a elliptic curve coefficient */
    CpaFlatBuffer b;
    /**< b elliptic curve coefficient */
    CpaFlatBuffer m;
    /**< digest of the message to be signed */
    CpaFlatBuffer d;
    /**< private key */
    CpaCyEcFieldType fieldType;
    /**< field type for the operation */
} CpaCyKptEcdsaSignRSOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Perform KPT key handle register function.
 *
 * @description
 *      Used for loading an application's wrapping key from PTT to QAT.
 *      An application first precomputes/initializes a 64 bit handle value
 *      using CPU based RDRAND instruction or other means and passes it to
 *      QAT. This will signal to QAT that a KPT key transfer operation is
 *      about to begin
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
 * @param[in]  instanceHandle       QAT service instance handle.
 * @param[in]  keyHandle            A 64-bit handle value
 * @param[out] pKptStatus           One of the status codes denoted in the
 *                                  enumerate type of
 *                                  cpaCyKptKeyManagementStatus
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting.
 *                                   Resubmit the request.
 *
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 * @note
 *     This function operates in a synchronous manner and no asynchronous
 *     callback will be generated.
 * @see
 *      None
 *****************************************************************************/
CpaStatus cpaCyKptRegisterKeyHandle(CpaInstanceHandle instanceHandle,
                                  CpaCyKptHandle keyHandle,
                                  CpaCyKptKeyManagementStatus *pKptStatus);

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Perform KPT key loading function.
 *
 * @description
 *      This function is invoked by QAT application after instructing PTT to
 *      send its wrapping key to QAT.
 *      After PTT returns a TPM_SUCCESS, the wrapping key structure is placed
 *      in QAT. The Application completes the 3-way handshake by invoking this
 *      API and requesting QAT to store the wrapping key, along with its
 *      handle.
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
 * @param[in]  instanceHandle      QAT service instance handle.
 * @param[in]  keyHandle           A 64-bit handle value
 * @param[in]  keySelFlag          Flag to indicate which kind of mode
 *                                 (SWK or WPK) should be loaded.
 * @param[in]  keyAction           Whether HAMC authentication is needed
 * @param[in]  pKptWrappingFormat  Pointer to CpaCyKptWrappingFormat whose
 *                                 fields will be written to WKT.
 * @param[out] pOutputData         FlatBuffer pointer, which contains the
 *                                 wrapped private key structure used by
 *                                 application.
 * @param[out] pKptStatus          One of the status codes denoted in the
 *                                 enumerate type CpaCyKptKeyManagementStatus
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting.
 *                                  Resubmit the request.
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 * @note
 *      None
 * @see
 *      None
 *****************************************************************************/
CpaStatus cpaCyKptLoadKeys(CpaInstanceHandle instanceHandle,
                         CpaCyKptHandle keyHandle,
                         CpaCyKptWrappingFormat *pKptWrappingFormat,
                         CpaCyKptKeySelectionFlags keySelFlag,
                         CpaCyKptKeyAction keyAction,
                         CpaFlatBuffer *pOutputData,
                         CpaCyKptKeyManagementStatus *pKptStatus);

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Perform KPT delete keys function according to key handle
 *
 * @description
 *      Before closing a QAT session(instance), an application that has
 *      previously stored its wrapping key in QAT using the KPT framework
 *      executes this call to delete its wrapping key in QAT.
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
 * @param[in]  instanceHandle       QAT service instance handle.
 * @param[in]  keyHandle            A 64-bit handle value
 * @param[out] pkptstatus           One of the status codes denoted in the
 *                                  enumerate type CpaCyKptKeyManagementStatus
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting.
 *                                   Resubmit the request.
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 * @note
 *      None
 * @see
 *      None
 *****************************************************************************/
CpaStatus cpaCyKptDeleteKey(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle keyHandle,
                            CpaCyKptKeyManagementStatus * pkptstatus);

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Perform KPT mode RSA decrypt primitive operation on the input data.
 *
 * @description
 *      This function is variant of cpaCyRsaDecrypt, which  will perform
 *      an RSA decryption primitive operation on the input data using the
 *      specified RSA private key which are encrypted. As the RSA decryption
 *      primitive and signing primitive operations are mathematically
 *      identical this function may also be used to perform an RSA signing
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
 * @param[in]  instanceHandle     Instance handle.
 * @param[in]  pRsaDecryptCb      Pointer to callback function to be invoked
 *                                when the operation is complete. If this is
 *                                set to a NULL value the function will operate
 *                                synchronously.
 * @param[in]  pCallbackTag       Opaque User Data for this specific call.
 *                                Will be returned unchanged in the callback.
 * @param[in]  pDecryptOpData     Structure containing all the data needed to
 *                                perform the RSA decrypt operation. The
 *                                client code allocates the memory for this
 *                                structure. This component takes ownership
 *                                of the memory until it is returned in the
 *                                callback.
 * @param[out] pOutputData        Pointer to structure into which the result of
 *                                the RSA decryption primitive is written. The
 *                                client MUST allocate this memory. The data
 *                                pointed to is an integer in big-endian order.
 *                                The value will be between 0 and the modulus
 *                                n - 1.
 *                                On invocation the callback function will
 *                                contain this parameter in the pOut parameter.
 * @param[in]  pKptUnwrapContext  Pointer of structure into which the content
 *                                of KptUnwrapContext is kept,The client MUST
 *                                allocate this memory and copy structure
 *                                KptUnwrapContext into this flat buffer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_RETRY          Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting.Resubmit
 *                                   the request.
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      By virtue of invoking cpaSyKptRsaDecrypt, the implementation understands
 *      that pDecryptOpData contains an encrypted private key that requires
 *      unwrapping. KptUnwrapContext contains an 'KptHandle' field that points
 *      to the unwrapping key in the WKT.
 *      When pRsaDecryptCb is non-NULL an asynchronous callback is generated in
 *      response to this function call.
 *      Any errors generated during processing are reported as part of the
 *      callback status code. For optimal performance, data pointers SHOULD be
 *      8-byte aligned.
 *      In KPT release,private key field in CpaCyRsaDecryptOpData is a
 *      concatenation of cipher text and hash tag.
 *      For optimal performance, data pointers SHOULD be 8-byte aligned.
 * @see
 *      CpaCyRsaDecryptOpData,
 *      CpaCyGenFlatBufCbFunc,
 *      cpaCyRsaGenKey(),
 *      cpaCyRsaEncrypt()
 *
 *****************************************************************************/
CpaStatus cpaCyKptRsaDecrypt(const CpaInstanceHandle       instanceHandle,
                             const CpaCyGenFlatBufCbFunc   pRsaDecryptCb,
                             void                          *pCallbackTag,
                             const CpaCyRsaDecryptOpData   *pDecryptOpData,
                             CpaFlatBuffer                 *pOutputData,
                             CpaFlatBuffer                 *pKptUnwrapContext);

/**
 *****************************************************************************
 * @ingroup cpaCyEc
 *      Perform KPT mode EC Point Multiplication.
 *
 * @description
 *      This function is variant of cpaCyEcPointMultiply, which will
 *      perform Elliptic Curve Point Multiplication as per
 *      ANSI X9.63 Annex D.3.2.
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
 * @param[in]  instanceHandle     Instance handle.
 * @param[in]  pCb                Callback function pointer. If this is set to
 *                                a NULL value the function will operate
 *                                synchronously.
 * @param[in]  pCallbackTag       User-supplied value to help identify request.
 * @param[in]  pOpData            Structure containing all the data needed to
 *                                perform the operation. The client code
 *                                allocates the memory for this structure. This
 *                                component takes ownership of the memory until
 *                                it is returned in the callback.
 * @param[out] pMultiplyStatus    In synchronous mode, the multiply output is
 *                                valid (CPA_TRUE) or the output is invalid
 *                                (CPA_FALSE).
 * @param[out] pXk                Pointer to xk flat buffer.
 * @param[out] pYk                Pointer to yk flat buffer.
 * @param[in]  pKptUnwrapContext  Pointer of structure into which the content
 *                                of KptUnwrapContext is kept,The client MUST
 *                                allocate this memory and copy structure
 *                                KptUnwrapContext into this flat buffer.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 *
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      By virtue of invoking the cpaCyKptEcPointMultiply, the implementation
 *      understands that CpaCyEcPointMultiplyOpData contains an encrypted 
 *      private key that requires unwrapping. KptUnwrapContext contains an 
 *      'KptHandle' field that points to the unwrapping key in the WKT.
 *      When pCb is non-NULL an asynchronous callback of type
 *      CpaCyEcPointMultiplyCbFunc is generated in response to this function
 *      call.
 *      In KPT release,private key field in cpaCyKptEcPointMultiply is a
 *      concatenation of cipher text and hash tag.
 *      For optimal performance, data pointers SHOULD be 8-byte aligned.
 * @see
 *      CpaCyEcPointMultiplyOpData,
 *      CpaCyEcPointMultiplyCbFunc
 *
 *****************************************************************************/
CpaStatus cpaCyKptEcPointMultiply(const   CpaInstanceHandle    instanceHandle,
                                  const   CpaCyEcPointMultiplyCbFunc  pCb,
                                  void*                           pCallbackTag,
                                  const   CpaCyEcPointMultiplyOpData* pOpData,
                                  CpaBoolean                  *pMultiplyStatus,
                                  CpaFlatBuffer               *pXk,
                                  CpaFlatBuffer               *pYk,
                                  CpaFlatBuffer               *pKptUnwrapContext);

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      Generate ECDSA Signature R & S.
 * @description
 *      This function is a varient of cpaCyEcdsaSignRS, it generates ECDSA
 *      Signature R & S as per ANSI X9.62 2005 section 7.3.
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
 * @param[in]  instanceHandle     Instance handle.
 * @param[in]  pCb                Callback function pointer. If this is set to
 *                                a NULL value the function will operate
 *                                synchronously.
 * @param[in]  pCallbackTag       User-supplied value to help identify request.
 * @param[in]  pOpData            Structure containing all the data needed to
 *                                perform the operation. The client code
 *                                allocates the memory for this structure. This
 *                                component takes ownership of the memory until
 *                                it is returned in the callback.
 * @param[out] pSignStatus        In synchronous mode, the multiply output is
 *                                valid (CPA_TRUE) or the output is invalid
 *                                (CPA_FALSE).
 * @param[out] pR                 ECDSA message signature r.
 * @param[out] pS                 ECDSA message signature s.
 * @param[in]  pKptUnwrapContext  Pointer of structure into which the content
 *                                of KptUnwrapContext is kept,The client MUST
 *                                allocate this memory and copy structure
 *                                KptUnwrapContext into this flat buffer.
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
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      By virtue of invoking the cpaCyKptEcdsaSignRS, the implementation
 *      understands CpaCyEcdsaSignRSOpData contains an encrypted private key that
 *      requires unwrapping. KptUnwrapContext contains an 'KptHandle' field
 *      that points to the unwrapping key in the WKT.
 *      When pCb is non-NULL an asynchronous callback of type
 *      CpaCyEcdsaSignRSCbFunc generated in response to this function
 *      call.
 *      In KPT release,private key field in CpaCyEcdsaSignRSOpData is a
 *      concatenation of cipher text and hash tag.
 * @see
 *      None
 *****************************************************************************/
CpaStatus
cpaCyKptEcdsaSignRS(const CpaInstanceHandle instanceHandle,
        const CpaCyEcdsaSignRSCbFunc pCb,
        void *pCallbackTag,
        const CpaCyKptEcdsaSignRSOpData *pOpData,
        CpaBoolean *pSignStatus,
        CpaFlatBuffer *pR,
        CpaFlatBuffer *pS,
        CpaFlatBuffer *pKptUnwrapContext);

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *      This function is varient of cpaCyDsaSignS,which generate DSA S
 *      Signature.
 * @description
 *      This function generates the DSA S signature as described in FIPS 186-3
 *      Section 4.6:
 *          s = (k^-1(z + xr)) mod q
 *
 *      Here, z = the leftmost min(N, outlen) bits of Hash(M).  This function
 *      does not perform the SHA digest; z is computed by the caller and
 *      passed as a parameter in the pOpData field.
 *
 *      The protocol status, returned in the callback function as parameter
 *      protocolStatus (or, in the case of synchronous invocation, in the
 *      parameter *pProtocolStatus) is used to indicate whether the value
 *      s == 0.
 *
 *      Specifically, (protocolStatus == CPA_TRUE) means s != 0, while
 *      (protocolStatus == CPA_FALSE) means s == 0.
 *
 *      If signature r has been generated in advance, then this function can
 *      be used to generate the signature s once the message becomes available.
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
 * @param[in]  pCb               Callback function pointer. If this is set to a
 *                               NULL value the function will operate
 *                               synchronously.
 * @param[in]  pCallbackTag      User-supplied value to help identify request.
 * @param[in]  pOpData           Structure containing all the data needed to
 *                               perform the operation. The client code
 *                               allocates the memory for this structure. This
 *                               component takes ownership of the memory until
 *                               it is returned in the callback.
 * @param[out] pProtocolStatus   The result passes/fails the DSA protocol
 *                               related checks.
 * @param[out] pS                DSA message signature s.
 *                               On invocation the callback function will
 *                               contain this parameter in the pOut parameter.
 * @param[in]  pKptUnwrapContext  Pointer of structure into which the content
 *                                of KptUnwrapContext is kept,The client MUST
 *                                allocate this memory and copy structure
 *                                KptUnwrapContext into this flat buffer.
 *
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
 *      When pCb is non-NULL an asynchronous callback of type
 *      CpaCyDsaSSignCbFunc is generated in response to this function
 *      call.
 *      For optimal performance, data pointers SHOULD be 8-byte aligned.
 *
 *      By virtue of invoking cpaCyKptDsaSignS, the implementation understands
 *      CpaCyDsaSSignOpData contains an encrypted private key that
 *      requires unwrapping. KptUnwrapContext contains an 'KptHandle' field
 *      that points to the unwrapping key in the WKT.
 *      In KPT,private key field in CpaCyDsaSSignOpData is a concatenation
 *      of cipher text and hash tag.
 *      For optimal performance, data pointers SHOULD be 8-byte aligned.
 * @see
 *      CpaCyDsaSSignOpData,
 *      CpaCyDsaGenCbFunc,
 *      cpaCyDsaSignR(),
 *      cpaCyDsaSignRS()
 *
 *****************************************************************************/
CpaStatus
cpaCyKptDsaSignS(const CpaInstanceHandle instanceHandle,
        const CpaCyDsaGenCbFunc pCb,
        void *pCallbackTag,
        const CpaCyDsaSSignOpData *pOpData,
        CpaBoolean *pProtocolStatus,
        CpaFlatBuffer *pS,
        CpaFlatBuffer *pKptUnwrapContext);

/**
 *****************************************************************************
 * @ingroup cpaCyKpt
 *     This function is a varient of cpaCyDsaSignRS,which generate DSA R and
 *     S Signature
 * @description
 *     This function generates the DSA R and S signatures as described in
 *     FIPS 186-3 Section 4.6:
 *
 *         r = (g^k mod p) mod q
 *         s = (k^-1(z + xr)) mod q
 *
 *     Here, z = the leftmost min(N, outlen) bits of Hash(M).  This function
 *     does not perform the SHA digest; z is computed by the caller and
 *     passed as a parameter in the pOpData field.
 *
 *     The protocol status, returned in the callback function as parameter
 *     protocolStatus (or, in the case of synchronous invocation, in the
 *     parameter *pProtocolStatus) is used to indicate whether either of
 *     the values r or s are zero.
 *
 *     Specifically, (protocolStatus == CPA_TRUE) means neither is zero (i.e.
 *     (r != 0) && (s != 0)), while (protocolStatus == CPA_FALSE) means that at
 *     least one of r or s is zero (i.e. (r == 0) || (s == 0)).
 *
 * @context
 *     When called as an asynchronous function it cannot sleep. It can be
 *     executed in a context that does not permit sleeping.
 *     When called as a synchronous function it may sleep. It MUST NOT be
 *     executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *     None
 * @sideEffects
 *     None
 * @blocking
 *     Yes when configured to operate in synchronous mode.
 * @reentrant
 *     No
 * @threadSafe
 *     Yes
 *
 * @param[in]  instanceHandle    Instance handle.
 * @param[in]  pCb               Callback function pointer. If this is  set to
 *                               a NULL value the function will operate
 *                               synchronously.
 * @param[in]  pCallbackTag      User-supplied value to help identify request.
 * @param[in]  pOpData           Structure containing all the data needed to
 *                               perform the operation. The client code
 *                               allocates the memory for this structure. This
 *                               component takes ownership of the memory until
 *                               it is returned in the callback.
 * @param[out] pProtocolStatus   The result passes/fails the DSA protocol
 *                               related checks.
 * @param[out] pR                DSA message signature r.
 * @param[out] pS                DSA message signature s.
 * @param[in]  pKptUnwrapContext  Pointer of structure into which the content
 *                                of KptUnwrapContext is kept,The client MUST
 *                                allocate this memory and copy structure
 *                                KptUnwrapContext into this flat buffer.
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
 *      When pCb is non-NULL an asynchronous callback of type
 *      CpaCyDsaRSSignCbFunc is generated in response to this function
 *      call.
 *      For optimal performance, data pointers SHOULD be 8-byte aligned.
 *      By virtue of invoking CyKptDsaSignRS, the implementation understands
 *      CpaCyDsaRSSignOpData contains an enrypted private key that requires
 *      unwrapping. KptUnwrapContext contains an 'KptHandle' field that points
 *      to the unwrapping key in the WKT.
 *      In KPT,private key field in CpaCyDsaRSSignOpData is a concatenation
 *      of cipher text and hash tag.
 *      For optimal performance, data pointers SHOULD be 8-byte aligned.
 * @see
 *      CpaCyDsaRSSignOpData,
 *      CpaCyDsaRSSignCbFunc,
 *      cpaCyDsaSignR(),
 *      cpaCyDsaSignS()
 *
 *****************************************************************************/
CpaStatus
cpaCyKptDsaSignRS(const CpaInstanceHandle instanceHandle,
        const CpaCyDsaRSSignCbFunc pCb,
        void *pCallbackTag,
        const CpaCyDsaRSSignOpData *pOpData,
        CpaBoolean *pProtocolStatus,
        CpaFlatBuffer *pR,
        CpaFlatBuffer *pS,
        CpaFlatBuffer *pKptUnwrapContext);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif
#endif
