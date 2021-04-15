/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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

/**
 ******************************************************************************
 * @file cpa_fips_sample_rsa.c
 *
 * @ingroup fipsSampleRsa
 *
 * This file contains function prototypes and structure definitions for
 * running the FIPS Cy RSA implementation functions
 *
 *****************************************************************************/

#include "cpa_fips_sample.h"
#include "cpa_fips_sample_utils.h"
#include "cpa_fips_sample_rsa.h"
#include "cpa_fips_sample_aes_gcm.h"

/**
 ******************************************************************************
 * @ingroup fipsSampleRsa
 *      EXPORT_SYMBOLs
 *
 * Functions which are exported for the kernel module interface
 *****************************************************************************/

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      checkRsaData
 *
 * @description
 *      Check inputs for the different FIPS functions based on expected input
 *      and output buffers.
 *
 * @param[in]  pRsaData            Structure containing the input parameters
 *                                 and output buffers
 * @param[in]  rsaOp               Which RSA operation is being performed
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus checkRsaData(const usr_rsa_data_t *restrict pRsaData,
                              rsa_operation_t rsaOp)
{
    Cpa32U hashBytes = 0;
    Cpa32U eNumStartOffset = 0;
    const Cpa32U nLenBytes =
        (NULL == pRsaData) ? 0 : (pRsaData->rsaModulusSizeInBits / BYTE_SIZE);
    CpaFlatBuffer E = {.dataLenInBytes = 0, .pData = NULL};

    /*Check common input values*/
    if (NULL == pRsaData)
    {
        PRINT_ERR("RSA Data is NULL \n");
        return CPA_STATUS_FAIL;
    }

    /*Check length of 'n' is 1024, 2048, or 3072*/
    if ((RSA_N_LEN_1024 != pRsaData->rsaModulusSizeInBits) &&
        (RSA_N_LEN_2048 != pRsaData->rsaModulusSizeInBits) &&
        (RSA_N_LEN_3072 != pRsaData->rsaModulusSizeInBits))
    {
        PRINT_ERR("Modulus length (%u) not supported by FIPS 186-3 \n",
                  pRsaData->rsaModulusSizeInBits);
        return CPA_STATUS_FAIL;
    }

    /*Check an approved hash function is being used
      (SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512)*/
    switch (pRsaData->shaAlg)
    {
        case CPA_CY_SYM_HASH_SHA1:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA1\n");
            break;
        case CPA_CY_SYM_HASH_SHA224:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA224\n");
            break;
        case CPA_CY_SYM_HASH_SHA256:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA256\n");
            break;
        case CPA_CY_SYM_HASH_SHA384:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA384\n");
            break;
        case CPA_CY_SYM_HASH_SHA512:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA512\n");
            break;
        default:
            PRINT_ERR("ERROR - SHA operation supported\n");
            return CPA_STATUS_FAIL;
    }

    if (RSA_KEYGEN == rsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaN = ", &pRsaData->rsaN));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaD = ", &pRsaData->rsaD));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaE = ", &pRsaData->rsaE));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaP = ", &pRsaData->rsaP));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaP1 = ", &pRsaData->rsaP1));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaP2 = ", &pRsaData->rsaP2));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaQ = ", &pRsaData->rsaQ));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaQ1 = ", &pRsaData->rsaQ1));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaQ2 = ", &pRsaData->rsaQ2));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaXP = ", &pRsaData->rsaXP));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaXP1 = ", &pRsaData->rsaXP1));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaXP2 = ", &pRsaData->rsaXP2));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaXQ = ", &pRsaData->rsaXQ));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaXQ1 = ", &pRsaData->rsaXQ1));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaXQ2 = ", &pRsaData->rsaXQ2));

        /*FIPS 186-3 section 5.4 - check that 'e' is odd*/
        if (0 == (1 & pRsaData->rsaE.pData[pRsaData->rsaE.dataLenInBytes - 1]))
        {
            PRINT_ERR("Rabin-Williams is not supported by FIPS"
                      " (e is an even number)\n");
            return CPA_STATUS_FAIL;
        }

        /*Check public exponent value 'e' is correct*/
        eNumStartOffset = getOffsetToBufferedData(&pRsaData->rsaE);
        E.dataLenInBytes = pRsaData->rsaE.dataLenInBytes;
        E.pData = pRsaData->rsaE.pData;
        switch (pRsaData->rsaKeyGenType)
        {
            case FIPS_186_3_KEYGEN:
                /*FIPS 186-3 B.3.6, part 2. Check e > 2^16, e < 2^256*/
                if ((E.dataLenInBytes - eNumStartOffset) <=
                    FIPS_186_3_MIN_E_SIZE_IN_BYTES)
                {
                    PRINT_ERR("E is too small (<= %u bytes), size = %u\n",
                              FIPS_186_3_MIN_E_SIZE_IN_BYTES,
                              pRsaData->rsaModulusSizeInBits);
                    return CPA_STATUS_FAIL;
                }
                else if ((E.dataLenInBytes - eNumStartOffset) >
                         FIPS_186_3_MAX_E_SIZE_IN_BYTES)
                {
                    PRINT_ERR("E is too large (> %u bytes), size = %u\n",
                              FIPS_186_3_MAX_E_SIZE_IN_BYTES,
                              pRsaData->rsaModulusSizeInBits);
                    return CPA_STATUS_FAIL;
                }
                break;
            case ANS_X9_31_KEYGEN:
                /*ANS X9.31, Check e > 2, e < 2^(k - 160). Where k = modulus
                 * length in bytes*/
                /*supported modulus sizes are 1024, 2048, 3072*/
                if (0x01 == (E.dataLenInBytes - eNumStartOffset))
                {
                    if (E.pData[eNumStartOffset] < ANS_X9_31_MIN_E_VALUE)
                    {
                        PRINT_ERR("E value is too small (%u < %u)\n",
                                  E.pData[eNumStartOffset],
                                  ANS_X9_31_MIN_E_VALUE);
                        return CPA_STATUS_FAIL;
                    }
                }
                else
                {
                    if ((nLenBytes - ANS_X9_31_E_MAX_SIZE_CONSTANT_BYTES) <=
                        (E.dataLenInBytes - eNumStartOffset))
                    {
                        PRINT_ERR(
                            "E value size is too large (%u >= %u)\n",
                            (E.dataLenInBytes - eNumStartOffset),
                            (nLenBytes - ANS_X9_31_E_MAX_SIZE_CONSTANT_BYTES));
                        return CPA_STATUS_FAIL;
                    }
                }
                break;
            default:
                PRINT_ERR("Specified key generation method not supported\n");
                return CPA_STATUS_FAIL;
        }
    }
    else if ((RSA_SIGN == rsaOp) || (RSA_VERIFY == rsaOp))
    {
        /*Public/Private keys*/
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaN = ", &pRsaData->rsaN));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaD = ", &pRsaData->rsaD));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaE = ", &pRsaData->rsaE));

        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("rsaM = ", &pRsaData->rsaM));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("rsaEM = ", &pRsaData->rsaEM));
        /*FIPS 186-3 section 5.5 -
           check salt length is between zero and 'h', the hash output block
           length*/
        if (CPA_STATUS_SUCCESS != getHashBytes(pRsaData->shaAlg, &hashBytes))
        {
            PRINT_ERR("Could not get output length of SHA algorithm\n");
            return CPA_STATUS_FAIL;
        }
        if (pRsaData->rsaSalt.dataLenInBytes > hashBytes)
        {
            PRINT_ERR("Error - Salt Len (%u) is greater than the "
                      " input hash function result length (%u)\n",
                      pRsaData->rsaSalt.dataLenInBytes,
                      hashBytes);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        PRINT_ERR("RSA operation not supported");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaCheckNLen
 *
 * @description
 *      check the input value is equal to one of the supported Modulus Lengths
 *
 * @param[in]  nLen        Length to check for conformance with supported RSA
 *                         Modulus Lengths
 *
 * @retval CPA_TRUE        nLen is a supported modulus length
 * @retval CPA_FALSE       nLen is not a supported modulus length
 *
 *****************************************************************************/
static inline CpaBoolean rsaCheckNLen(Cpa32U nLen)
{
    if ((RSA_N_LEN_1024 != nLen) && (RSA_N_LEN_2048 != nLen) &&
        (RSA_N_LEN_3072 != nLen))
    {
        return CPA_FALSE;
    }
    return CPA_TRUE;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      checkPrimalityFipsC3
 *
 * @description
 *      Check small or large value for primeness based on FIPS 186-3 appendix
 *      C.3, table C.3
 *
 * @param[in]  pRsaData          Structure giving the operation size
 * @param[in]  pCandidate        Prime Candidate for checking
 * @param[in]  primeCheckType    Is a large or small prime value being checked
 * @param[out] pIsPrime          Set to true if the value being checked is
 *                               found to be prime
 * @param[in]  instanceHandle    Quick Assist API instance handle
 * @param[in]  securityStrength  Required DRNG security strength for (L, N)
 *
 * @retval CPA_STATUS_SUCCESS
 * @retval CPA_STATUS_FAIL
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus checkPrimalityFipsC3(Cpa32U nLenBits,
                                      const CpaFlatBuffer *restrict pCandidate,
                                      rsa_prime_check_type_t primeCheckType,
                                      CpaBoolean *pIsPrime,
                                      const CpaInstanceHandle instanceHandle,
                                      Cpa32U securityStrength)
{
    Cpa32U numMillerRabin = 0;
    *pIsPrime = CPA_FALSE;

    /*Check whether a small value has the correct length. It is assumed
      large values to be checked have the correct length, as they must
      be the same as the supported RSA modulus sizes*/
    if (((FIPS_RSA_MAX_RANDOM_LEN_SMALL_PRIME_BYTES <
          pCandidate->dataLenInBytes) &&
         (XP1_LEN_FOR_SEC_STRENGTH_128_IN_BYTES ==
          pCandidate->dataLenInBytes)) &&
        (FIPS_RSA_PRIME_SMALL == primeCheckType))
    {
        PRINT_ERR("Quick Assist API only supports prime checking for\n"
                  "values of length up to 512 bits, or equal to 768,\n"
                  "1024, 2048, 3072, 4096 bits. Input value is %u bytes\n",
                  pCandidate->dataLenInBytes);
        PRINT_ERR("FIPS compliant probable primes are possible with\n"
                  "values less than 512 bits in length. See Table B.1\n"
                  "of FIPS 186-3 for available sizes.\n");

        return CPA_STATUS_FAIL;
    }

    switch (nLenBits)
    {
        case RSA_N_LEN_1024:
            if (FIPS_RSA_PRIME_SMALL == primeCheckType)
            {
                numMillerRabin = FIPS_RSA_MILLER_RABIN_1024_SMALL;
            }
            else
            {
                numMillerRabin = FIPS_RSA_MILLER_RABIN_1024_LARGE;
            }
            break;
        case RSA_N_LEN_2048:
            if (FIPS_RSA_PRIME_SMALL == primeCheckType)
            {
                numMillerRabin = FIPS_RSA_MILLER_RABIN_2048_SMALL;
            }
            else
            {
                numMillerRabin = FIPS_RSA_MILLER_RABIN_2048_LARGE;
            }
            break;
        case RSA_N_LEN_3072:
            if (FIPS_RSA_PRIME_SMALL == primeCheckType)
            {
                numMillerRabin = FIPS_RSA_MILLER_RABIN_3072_SMALL;
            }
            else
            {
                numMillerRabin = FIPS_RSA_MILLER_RABIN_3072_LARGE;
            }
            break;
        default:
            PRINT_ERR("Modulus value (%u) invalid\n", nLenBits);
            return CPA_STATUS_FAIL;
            break;
    }

    if (CPA_STATUS_SUCCESS !=
        checkPrimality(pCandidate,
                       numMillerRabin,
                       CPA_FALSE, /*Perform 0 Lucas tests*/
                       pIsPrime,
                       instanceHandle,
                       securityStrength))
    {
        PRINT_ERR("Primality check Fail \n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}
/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      getRsaHash
 *
 * @description
 *      Create a hash based on the SHA operation currently required for the
 *      algorithm. The pMesg input is overwritten by the hash value if the
 *      pMesgResult pointer is NULL
 *
 * @param[in,out] pRsaData         Structure containing SHA algorithm
 *                                 information
 * @param[in,out] pMesg            message to be hashed
 * @param[in,out] pMesgResult      If this is not NULL, the hash result is
 *                                 is stored here
 * @param[in]     instanceHandle   Quick Assist instance handle
 *
 * @retval CPA_STATUS_SUCCESS      The operation succeeded
 * @retval CPA_STATUS_FAIL         The operation failed
 *
 * @pre
 *      Enough memory has been allocated for 'mesg' buffer to store the
 *      digest result.
 * @post
 *      none
 *****************************************************************************/
static inline CpaStatus getRsaHash(const usr_rsa_data_t *restrict pRsaData,
                                   CpaFlatBuffer *pMesg,
                                   CpaFlatBuffer *pMesgResult,
                                   const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /* Set input data */
    CpaCySymSessionSetupData sessionSetupData = {
        .sessionPriority = CPA_CY_PRIORITY_NORMAL,
        .symOperation = CPA_CY_SYM_OP_HASH,
        .cipherSetupData =
            {
                0,
            }, /*not used*/
        .hashSetupData = {.hashAlgorithm = pRsaData->shaAlg,
                          .hashMode = CPA_CY_SYM_HASH_MODE_PLAIN,
                          .digestResultLenInBytes = 0,
                          .authModeSetupData =
                              {
                                  0,
                              },
                          .nestedModeSetupData =
                              {
                                  0,
                              }},
        .algChainOrder = 0, /*ignored*/
        .digestIsAppended = CPA_FALSE,
        .verifyDigest = CPA_FALSE};

    /*Get the length of the SHA digest result*/
    status =
        getHashBytes(pRsaData->shaAlg,
                     &sessionSetupData.hashSetupData.digestResultLenInBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("HASH operation not supported for RSA\n");
        return CPA_STATUS_FAIL;
    }
    status =
        getMesgDigest(pMesg, pMesgResult, &sessionSetupData, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Mesg Digest Fail \n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaKeygenCpaGenerate
 *
 * @description
 *      Does the RSA keygen operation parts accelerated by the QA API.
 *
 * @param[in,out] pRsaData      Structure containing RSA E, modulus size, P
 *                              and Q input parameters and the output N and
 *                              D storage buffers
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaKeygenCpaGenerate(usr_rsa_data_t *pRsaData,
                                      const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };

    CpaCyRsaKeyGenOpData keyGenOpData = {
        .prime1P = {.pData = pRsaData->rsaP.pData,
                    .dataLenInBytes = pRsaData->rsaP.dataLenInBytes},
        .prime2Q = {.pData = pRsaData->rsaQ.pData,
                    .dataLenInBytes = pRsaData->rsaQ.dataLenInBytes},
        .modulusLenInBytes = pRsaData->rsaModulusSizeInBits / BYTE_SIZE,
        .version = CPA_CY_RSA_VERSION_TWO_PRIME,
        .privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1,
        .publicExponentE = {.pData = pRsaData->rsaE.pData,
                            .dataLenInBytes = pRsaData->rsaE.dataLenInBytes}};

    CpaCyRsaPrivateKey privateKey = {
        .version = CPA_CY_RSA_VERSION_TWO_PRIME,
        .privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1,
        .privateKeyRep1 =
            {
                .modulusN = {.pData = pRsaData->rsaN.pData,
                             .dataLenInBytes = pRsaData->rsaN.dataLenInBytes},
                .privateExponentD = {.pData = pRsaData->rsaD.pData,
                                     .dataLenInBytes =
                                         pRsaData->rsaD.dataLenInBytes},
            },
        /*.privateKeyRep2 not used*/
    };
    CpaCyRsaPublicKey publicKey = {
        .modulusN = {.pData = pRsaData->rsaN.pData,
                     .dataLenInBytes = pRsaData->rsaN.dataLenInBytes},
        .publicExponentE = {.pData = pRsaData->rsaE.pData,
                            .dataLenInBytes = pRsaData->rsaE.dataLenInBytes}};

    /*Generate the public/private keys as specified in PKCS #1 v2.1*/
    do
    {
        status = cpaCyRsaGenKey(instanceHandle,
                                NULL, /*callback function not required*/
                                NULL, /*opaque data not required*/
                                &keyGenOpData,
                                &privateKey,
                                &publicKey);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        if (CPA_STATUS_SUCCESS !=
            cpaCyGetStatusText(instanceHandle, status, statusErrorString))
        {
            PRINT_ERR("Error retrieving status string.\n");
        }
        PRINT_ERR("CPA RSA Key Gen Failed -- %s\n", statusErrorString);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaGenerateSmallPrime
 *
 * @description
 *      Calculate a small prime value used in generating the large
 *      primes P and Q (used when calculating the 'N' key value).
 *      This implements FIPS 186-3 B.3.6, parts 4.1 and 4.2 or 5.1 and 5.2.
 *
 * @param[in,out]  pSmallXP             This is an empty buffer unless
 *                                      haveFipsTestXValues is set. In
 *                                      that case, a NIST test vector is
 *                                      stored there.
 * @param[out] pSmallP                  Small prime number
 * @param[in]  nlenBits                 Size of the operation
 * @param[in]  securityStrength         Security strength to be used for the
 *                                      Random Bit Generator called in this
 *                                      function.
 * @param[in]  haveFipsTestXValues      If this is true, the caller has
 *                                      stored a NIST test vector in pSmallXP
 * @param[in]  instanceHandle           QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      The pSmallXP value should be cleared.
 *****************************************************************************/
static CpaStatus rsaGenerateSmallPrime(CpaFlatBuffer *pSmallXP,
                                       CpaFlatBuffer *pSmallP,
                                       Cpa32U nlenBits,
                                       Cpa32U securityStrength,
                                       CpaBoolean haveFipsTestXValues,
                                       const CpaInstanceHandle instanceHandle)
{

    Cpa32U xpBitLenInBytes = 0, i = 0;
    static const Cpa8U increment = ADD_2_TO_KEEP_ODD;
    CpaBoolean isPrime = CPA_FALSE;
    CpaFlatBuffer randomP = {.dataLenInBytes = 0, .pData = NULL};

    PRINT_DBG("Original security strength was %d\n", (int)securityStrength);
    if (CPA_FALSE == haveFipsTestXValues)
    {
        /*Need to generate xp value based on security strength*/
        /*Check Table B.1 for max/min sizes.*/
        switch (nlenBits)
        {
            case RSA_N_LEN_1024:
                xpBitLenInBytes = XP1_LEN_FOR_SEC_STRENGTH_80_IN_BYTES;
                securityStrength =
                    CPA_CY_RBG_SEC_STRENGTH_112; /* Only need 80 bits */
                break;
            case RSA_N_LEN_2048:
                xpBitLenInBytes = XP1_LEN_FOR_SEC_STRENGTH_112_IN_BYTES;
                securityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
                break;
            case RSA_N_LEN_3072:
                xpBitLenInBytes =
                    XP1_LEN_FOR_SEC_STRENGTH_112_IN_BYTES; // 128 Bytes was not
                                                           // supported for 3072
                securityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
                break;
            default:
                PRINT_ERR("Operation size not supported\n");
                return CPA_STATUS_FAIL;
        }
        PRINT_DBG("Not using test values, %u\n", xpBitLenInBytes);
        PRINT_DBG("New security strength is %d\n", (int)securityStrength);

        randomP.dataLenInBytes = xpBitLenInBytes;
        randomP.pData = osZalloc(xpBitLenInBytes, instanceHandle);
        if (NULL == randomP.pData)
        {
            PRINT_ERR("P value Alloc Fail\n");
            return CPA_STATUS_FAIL;
        }

        /*generate random bits for xp - bitlen is a multiple of 8*/
        if (CPA_STATUS_SUCCESS !=
            generateRandomBytes(
                &randomP, xpBitLenInBytes, securityStrength, instanceHandle))
        {
            PRINT_ERR("Could not gen random XP value\n");
            goto finish;
        }
        /*set top bit, bottom bit*/
        FIPS_SAMPLE_SET_TOP_BIT(randomP.pData[0]);
        FIPS_SAMPLE_SET_BOTTOM_BIT(randomP.pData[randomP.dataLenInBytes - 1]);

        memcpy(pSmallXP->pData, randomP.pData, randomP.dataLenInBytes);
        pSmallXP->dataLenInBytes = randomP.dataLenInBytes;
    }

    COPY_FLATBUFF(pSmallP, pSmallXP);

    /*if not odd, set as odd*/
    FIPS_SAMPLE_SET_BOTTOM_BIT(pSmallP->pData[pSmallXP->dataLenInBytes - 1]);

    /*Will be able to find a prime number in the interval of the current
      number and double it's size*/
    for (i = 0; i < ((pSmallP->dataLenInBytes * BYTE_SIZE) << 1); i++)
    {
        if (CPA_STATUS_SUCCESS != checkPrimalityFipsC3(nlenBits,
                                                       pSmallP,
                                                       FIPS_RSA_PRIME_SMALL,
                                                       &isPrime,
                                                       instanceHandle,
                                                       securityStrength))
        {
            PRINT_ERR("Prime Check Process Fail\n");
            goto finish;
        }

        if (CPA_TRUE == isPrime)
        {
            osFree(&randomP.pData);
            return CPA_STATUS_SUCCESS;
        }
        /*here NULL means the result will be stored in pSmallP*/
        if (CPA_STATUS_SUCCESS !=
            incrementFlatBuffer32U(NULL, pSmallP, increment))
        {
            PRINT_ERR("Buffer increment overflow\n");
            goto finish;
        }
    }
    PRINT_ERR("Could not find a prime value within an interval of the Prime\n"
              "Candidate length in bits and double the Prime Candidate\n"
              "length in bits\n");

finish:
    osFree(&randomP.pData);
    return CPA_STATUS_FAIL;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      findAndSetLargestSmallestBuffer
 *
 * @description
 *      Check which buffer stores the largest value and set the input flat
 *      buffer pointers accordingly
 *
 * @param[in]  pInputBuffer1           Buffer containing a value to be checked
 * @param[in]  pInputBuffer2           Buffer containing a value to be checked
 * @param[out] pLargerResultTarget     The buffer with the largest stored
 *                                     value is referenced by this structure
 * @param[out] pSmallerResultTarget    The buffer with the smallest stored
 *                                     value is referenced by this structure
 *
 * @retval  None
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static inline void findAndSetLargestSmallestBuffer(
    const CpaFlatBuffer *restrict pInputBuffer1,
    const CpaFlatBuffer *restrict pInputBuffer2,
    CpaFlatBuffer *pLargerResultTarget,
    CpaFlatBuffer *pSmallerResultTarget)
{
    /*Note, if buffers contain the same number, this returns false*/
    if (CPA_TRUE == isFbALessThanFbB(pInputBuffer1, pInputBuffer2))
    {
        pLargerResultTarget->pData = pInputBuffer2->pData;
        pLargerResultTarget->dataLenInBytes = pInputBuffer2->dataLenInBytes;
        pSmallerResultTarget->pData = pInputBuffer1->pData;
        pSmallerResultTarget->dataLenInBytes = pInputBuffer1->dataLenInBytes;
    }
    else
    {
        pLargerResultTarget->pData = pInputBuffer1->pData;
        pLargerResultTarget->dataLenInBytes = pInputBuffer1->dataLenInBytes;
        pSmallerResultTarget->pData = pInputBuffer2->pData;
        pSmallerResultTarget->dataLenInBytes = pInputBuffer2->dataLenInBytes;
    }
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      validateD
 *
 * @description
 *      Check that the generated private signature exponent 'd' is correct in
 *      accordance with FIPS 186-3 B.3.1 part 3
 *
 * @param[in]  rsaModulusSizeInBits  RSA modulus size 'n' value
 * @param[in]  pD                    Private Signature exponent 'd' value
 *
 *
 * @retval CPA_STATUS_SUCCESS
 * @retval CPA_STATUS_FAIL
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static inline CpaStatus validateD(Cpa32U rsaModulusSizeInBits,
                                  const CpaFlatBuffer *restrict pD)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U i = FIPS_SAMPLE_TOP_BIT;
    Cpa32U nlenHalved =
        FIPS_SAMPLE_UNSIGNED_DIVIDE_BY_TWO(rsaModulusSizeInBits);

    Cpa32U dNumStartOffset = getOffsetToBufferedData(pD);
    Cpa32U dDataLenBits = 0;

    dDataLenBits = (pD->dataLenInBytes - dNumStartOffset) * BYTE_SIZE;
    while ((0 == (pD->pData[dNumStartOffset] & i)) && (0 < i))
    {
        i >>= 1;
        dDataLenBits--;
    }

    /*Firmware ensures that d is generated correctly. We just need to check
      that the result of the calculation is not too small*/
    if (dDataLenBits <= nlenHalved)
    {
        PRINT_ERR("Generated private signature exponent 'd' bit length (%u) "
                  "is less than (%u) (2^(nlen /2))\n",
                  dDataLenBits,
                  FIPS_SAMPLE_UNSIGNED_DIVIDE_BY_TWO(rsaModulusSizeInBits));
        return CPA_STATUS_FAIL;
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      checkCoprime
 *
 * @description
 *      Check whether two numbers are co-prime (their only common factor is 1)
 *
 * @param[in]  pInputBuffer1         Value to be checked for co-primality
 * @param[in]  pInputBuffer2         Value to be checked for co-primality
 * @param[out] isCoprime             This value is set to CPA_TRUE if the
 *                                   two input buffers are coprime
 * @param[in]  instanceHandle        QA API instance handle
 *
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus checkCoprime(const CpaFlatBuffer *restrict pInputBuffer1,
                              const CpaFlatBuffer *restrict pInputBuffer2,
                              CpaBoolean *isCoprime,
                              const CpaInstanceHandle instanceHandle)
{
    Cpa8U *pCoprimeVals = NULL;
    CpaFlatBuffer coprimeValA = {.dataLenInBytes =
                                     pInputBuffer1->dataLenInBytes,
                                 .pData = pInputBuffer1->pData};
    CpaFlatBuffer coprimeValB = {.dataLenInBytes =
                                     pInputBuffer2->dataLenInBytes,
                                 .pData = pInputBuffer2->pData};
    CpaFlatBuffer tmpBuf = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer tmpBuf1 = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer coprimeModResult = {.dataLenInBytes = 0, .pData = NULL};

    /*initialize result false*/
    *isCoprime = CPA_FALSE;

    while (0 == *(coprimeValB.pData))
    {
        coprimeValB.pData++;
        coprimeValB.dataLenInBytes--;
    }
    while (0 == *(coprimeValA.pData))
    {
        coprimeValA.pData++;
        coprimeValA.dataLenInBytes--;
    }

    pCoprimeVals =
        osZalloc(coprimeValA.dataLenInBytes + FIPS_SAMPLE_UNSIGNED_MULT_BY_TWO(
                                                  coprimeValB.dataLenInBytes),
                 instanceHandle);
    if (NULL == pCoprimeVals)
    {
        PRINT_ERR("Could not allocate data for check\n");
        return CPA_STATUS_FAIL;
    }
    (void)memcpy(pCoprimeVals, coprimeValA.pData, coprimeValA.dataLenInBytes);
    (void)memcpy(pCoprimeVals + coprimeValA.dataLenInBytes,
                 coprimeValB.pData,
                 coprimeValB.dataLenInBytes);

    coprimeValA.pData = pCoprimeVals;
    coprimeValB.pData = pCoprimeVals + coprimeValA.dataLenInBytes;
    coprimeModResult.pData = coprimeValB.pData + coprimeValB.dataLenInBytes;

    coprimeModResult.dataLenInBytes = coprimeValB.dataLenInBytes;

    /*Get the GCD, store the result in 'coprimeValB'*/
    do
    {
        if (CPA_TRUE == checkZero(&coprimeValB))
        {
            *isCoprime = checkOne(&coprimeValA);
            break;
        }
        if (CPA_STATUS_SUCCESS != doModExp(&coprimeValA,
                                           NULL,
                                           &coprimeValB,
                                           &coprimeModResult,
                                           instanceHandle))
        {
            PRINT_ERR("Modulus operation Fail\n");
            osFree(&pCoprimeVals);
            return CPA_STATUS_FAIL;
        }

        tmpBuf.pData = coprimeValB.pData;
        tmpBuf.dataLenInBytes = coprimeValB.dataLenInBytes;

        tmpBuf1.pData = coprimeValA.pData;
        tmpBuf1.dataLenInBytes = coprimeValA.dataLenInBytes;

        /*Recursive Mod Exp -> second modulus is result of first operation*/
        coprimeValB.pData = coprimeModResult.pData;
        coprimeValB.dataLenInBytes = coprimeModResult.dataLenInBytes;

        /*Recursive Mod Exp -> second base is equal to the first modulus*/
        coprimeValA.pData = tmpBuf.pData;
        coprimeValA.dataLenInBytes = tmpBuf.dataLenInBytes;

        /*Recursive Mod Exp -> second result buffer is equal to the first
                               base buffer*/
        coprimeModResult.pData = tmpBuf1.pData;
        coprimeModResult.dataLenInBytes = tmpBuf1.dataLenInBytes;
    } while (CPA_TRUE);

    osFree(&pCoprimeVals);
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      generateRxValue
 *
 * @description
 *      Calculate Rx = ((mult^-1) modulus (mod)) * mult
 *      This is part of the FIPS 186-3 C.9 algorithm (step 2).
 *
 * @param[out] pResult                  Result of the above calculation
 * @param[in]  pMod                     The value to be used as the modulus
 *                                      size in the inverse modulus operation
 * @param[in]  pMult                    This value is multiplied by the
 *                                      inverse modulus
 * @param[in]  instanceHandle           QA API instance handle
 *
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus generateRxValue(CpaFlatBuffer *pResult,
                                 const CpaFlatBuffer *restrict pMod,
                                 const CpaFlatBuffer *restrict pMult,
                                 const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer invResult = {.dataLenInBytes = 0, .pData = NULL};

    invResult.pData = osZalloc(pMod->dataLenInBytes, instanceHandle);
    if (NULL == invResult.pData)
    {
        PRINT_ERR("Data alloc fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    invResult.dataLenInBytes = pMod->dataLenInBytes;
    (void)memset(pResult->pData, 0, pResult->dataLenInBytes);

    status = doModInv(pMult, pMod, &invResult, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Modular inversion fail\n");
        goto finish;
    }
    status = mulFlatBuffer(pResult, pMult, &invResult);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Rx multiply fail\n");
        goto finish;
    }

finish:
    osFree(&invResult.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      generateRValue
 *
 * @description
 *      Calculate :
 *      {
 *          R1 = ((r2^-1) mod (2r1)) * r2
 *          R2 = ((2r1)^-1 mod r2) * 2r1
 *          R  = R1 - R2
 *      }
 *      This implements FIPS 186-3 C.9 algorithm (step 2).
 *      For the B.3.6 algorithm, the inputs r1 and r2 are small prime values.
 *
 * @param[out] pResult                  Result (R) of the above calculation
 * @param[out] pRIsNegative             Result is a negative number
 * @param[in]  pMult2P1                 '2r1' of the above calculation
 * @param[in]  pP2                      'r2' of the above calculation
 * @param[in]  nlenBits                 modulus size of the RSA operation
 * @param[in]  instanceHandle           QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaGenerateRValue(CpaFlatBuffer *pResult,
                                   CpaBoolean *pRIsNegative,
                                   CpaFlatBuffer *pMult2P1,
                                   CpaFlatBuffer *pP2,
                                   Cpa32U nlenBits,
                                   const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer R2 = {.dataLenInBytes = 0, .pData = NULL};

    *pRIsNegative = CPA_FALSE;

    R2.dataLenInBytes = pResult->dataLenInBytes;
    R2.pData = osZalloc(R2.dataLenInBytes, instanceHandle);
    if (NULL == R2.pData)
    {
        PRINT_ERR("Data alloc fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*pResult = R1 = ((r2^-1) mod (2r1)) * r2*/
    status = generateRxValue(pResult, pMult2P1, pP2, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Gen R1 fail\n");
        goto finish;
    }

    /*R2 = ((2r1)^-1 mod r2) * 2r1*/
    status = generateRxValue(&R2, pP2, pMult2P1, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Gen R2 fail\n");
        goto finish;
    }

    /*R = R1 - R2*/
    if (CPA_TRUE == isFbALessThanFbB(pResult, &R2))
    {
        /*subtraction has negative result*/
        PRINT_DBG("R is negative\n");
        *pRIsNegative = CPA_TRUE;

        /*NULL here means the result is stored in 'R2'*/
        status = subFlatBuffer(NULL, &R2, pResult);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("R subtract fail\n");
            goto finish;
        }
        /*pResult is the return value, so R2 must be copied to it.*/
        (void)memcpy(pResult->pData, R2.pData, R2.dataLenInBytes);
        pResult->dataLenInBytes = R2.dataLenInBytes;
    }
    else
    {
        /*subtraction has positive result*/
        *pRIsNegative = CPA_FALSE;
        /*NULL here means the result is stored in 'pResult'*/
        status = subFlatBuffer(NULL, pResult, &R2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("R subtract fail\n");
            goto finish;
        }
    }

    if (CPA_TRUE != isFbOdd(pResult))
    {
        PRINT_ERR("Calculated R is not odd!\n");
        status = CPA_STATUS_FAIL;
    }

finish:
    osFree(&R2.pData);

    if (CPA_STATUS_SUCCESS != status)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaGeneratePValue
 *
 * @description
 *      This implements FIPS 186-3 C.9 algorithm parts 3 to 11.
 *
 * @param[out]     pResult          Result prime P
 * @param[in,out]  pXp              An empty buffer or (if haveFipsTestXValues)
 *                                  is CPA_TRUE) a buffer containing a
 *                                  NIST test vector. The random number that
 *                                  was used to generate the prime P is stored
 *                                  here as a result value.
 * @param[in]  pMult2P1             '2*P1' as calculated in the B.3.6 alg
 * @param[in]  pP2                  'P2' as calculated in the B.3.6 alg
 * @param[in]  pR                   R value from C.9, step 2
 * @param[in]  pRIsNegative         R value is a negative number
 * @param[in]  pE                   Public Key Exponent E
 * @param[in]  nlenBits             modulus size of the RSA operation
 * @param[in]  securityStrength     Security strength to be used for the
 *                                  Random Bit Generator called in this
 *                                  function.
 * @param[in]  haveFipsTestXValues  If this is true, the caller has
 *                                  stored NIST test vectors in the Xp
 *                                  parameters
 * @param[in]  instanceHandle       QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS       The operation succeeded
 * @retval CPA_STATUS_FAIL          The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaGeneratePValue(CpaFlatBuffer *pResult,
                                   CpaFlatBuffer *pXp,
                                   CpaFlatBuffer *pMult2P1,
                                   CpaFlatBuffer *pP2,
                                   CpaFlatBuffer *pR,
                                   CpaBoolean rIsNegative,
                                   CpaFlatBuffer *pE,
                                   Cpa32U nlenBits,
                                   Cpa32U securityStrength,
                                   CpaBoolean *pYTooLarge,
                                   CpaBoolean haveFipsTestXValues,
                                   const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    CpaFlatBuffer mult2P1P2 = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer modExpResultBuff = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer randomXp = {.dataLenInBytes = 0, .pData = NULL};
    CpaBoolean isCoprime = CPA_FALSE;
    Cpa32U i = 0;
    Cpa32U imax = FIPS_RSA_MAX_I_VALUE(nlenBits);

    *pYTooLarge = CPA_TRUE;

    /*We need space for the mult2P1P2 buffer and the Modular exponentiation
      result.*/
    mult2P1P2.pData =
        osZalloc(FIPS_SAMPLE_UNSIGNED_MULT_BY_TWO(pMult2P1->dataLenInBytes) +
                     FIPS_SAMPLE_UNSIGNED_MULT_BY_TWO(pP2->dataLenInBytes),
                 instanceHandle);
    if (NULL == mult2P1P2.pData)
    {
        PRINT_ERR("Could not allocate data\n");
        return CPA_STATUS_FAIL;
    }
    mult2P1P2.dataLenInBytes = pMult2P1->dataLenInBytes + pP2->dataLenInBytes;

    modExpResultBuff.pData = mult2P1P2.pData + mult2P1P2.dataLenInBytes;
    modExpResultBuff.dataLenInBytes = mult2P1P2.dataLenInBytes;

    if (CPA_FALSE == haveFipsTestXValues)
    {
        /*FIPS 186-3, section C.9, part 3:
         generate X, max len = nlen / 2  -1 bits (top bit shall be subtracted
         later)*/
        const Cpa32U xpLenBytes =
            FIPS_SAMPLE_UNSIGNED_DIVIDE_BY_TWO(nlenBits) / BYTE_SIZE;
        PRINT_ERR("Not using test values, %u\n", xpLenBytes);

        randomXp.dataLenInBytes = xpLenBytes;
        randomXp.pData = osZalloc(randomXp.dataLenInBytes, instanceHandle);
        if (NULL == randomXp.pData)
        {
            PRINT_ERR("Xp value Alloc Fail\n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }

        /*generate random bits for xp - bitlen is a multiple of 8*/
        if (CPA_STATUS_SUCCESS !=
            generateRandomBytes(
                &randomXp, xpLenBytes, securityStrength, instanceHandle))
        {
            status = CPA_STATUS_FAIL;
            PRINT_ERR("Could not gen random XP value\n");
            goto finish;
        }
        /*make sure the result is (2^(1/2))(2^(nlen/2 -1) < Xp)*/
        FIPS_SAMPLE_SET_TOP_BIT(randomXp.pData[0]);
        /*R is odd ==> X should be even for odd Y value*/
        FIPS_SAMPLE_UNSET_BOTTOM_BIT(
            randomXp.pData[randomXp.dataLenInBytes - 1]);

        memcpy(pXp->pData, randomXp.pData, randomXp.dataLenInBytes);
        pXp->dataLenInBytes = randomXp.dataLenInBytes;
    }

    /*FIPS 186-3, section C.9, part 4: Y = X + ((R - X) mod 2r1.r2).*/
    /*Calculate 2r1.r2*/
    status = mulFlatBuffer(&mult2P1P2, pMult2P1, pP2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("2r1.r2 multiply Fail\n");
        goto finish;
    }

    if (CPA_TRUE == rIsNegative)
    {
        /*if R is negative then this operation is equivalent to:
        Y = X + 2r1.r2 - (R + X) mod 2r1.r2*/
        PRINT_DBG("R is negative\n");
        status = addFlatBuffer(pResult, pR, pXp);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("R plus X fail\n");
            goto finish;
        }
    }
    else if (CPA_TRUE == isFbALessThanFbB(pR, pXp))
    {
        /*if (R - X) is negative, then:
        Y = X + 2r1.r2 - (X - R) mod 2r1.r2*/
        PRINT_DBG("R - X is negative\n");
        status = subFlatBuffer(pResult, pXp, pR);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("X - R subtract fail\n");
            goto finish;
        }
        /*re-use this variable to state that the modular exponentiation
          result must be subtracted from 2r1.r2*/
        rIsNegative = CPA_TRUE;
    }
    else
    {
        /*else R > X, then:
        Y = X + (R - X) mod 2r1.r2*/
        PRINT_DBG("R - X is positive\n");
        status = subFlatBuffer(pResult, pR, pXp);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("pXp subtract fail\n");
            goto finish;
        }
    }

    /*calculate (R - X)mod2r1.r2.
      In this case, NULL means the exponent = 1.
      The result of this operation is stored in modExpResultBuff*/
    status =
        doModExp(pResult, NULL, &mult2P1P2, &modExpResultBuff, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("C.9, part 4: Modexp Fail\n");
        goto finish;
    }

    if (CPA_TRUE == rIsNegative)
    {
        /*Must subtract the modExpResult from 2r1.r2*/
        /*Re-use 'pR' value buffer*/
        status = subFlatBuffer(pR, &mult2P1P2, &modExpResultBuff);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Generate Y Fail - subtraction underflow\n");
            goto finish;
        }
        /*Add to X to obtain Y = X + 2r1.r2 - (modExpResult)*/
        status = addFlatBuffer(pResult, pR, pXp);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Generate Y Fail - addition of X and 2r1.r2\n");
            goto finish;
        }
    }
    else
    {
        /*obtain Y = X + (modExpResult)*/
        status = addFlatBuffer(pResult, &modExpResultBuff, pXp);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Generate Y Fail - addition of X and modExp result\n");
            goto finish;
        }
    }

    /*FIPS 186-3, section C.9, part 5. and 8*/
    for (i = 0; i < imax; i++)
    {
        CpaFlatBuffer resultTarget = {.dataLenInBytes = pResult->dataLenInBytes,
                                      .pData = pResult->pData};
        const Cpa32U maxYSize =
            FIPS_SAMPLE_UNSIGNED_DIVIDE_BY_TWO(nlenBits) / BYTE_SIZE;
        /*FIPS 186-3, section C.9, part 6. check length of Y*/
        const Cpa32U yDataOffset = getOffsetToBufferedData(&resultTarget);

        if ((resultTarget.dataLenInBytes - yDataOffset) > maxYSize)
        {
            /*restart calculation process*/
            PRINT_DBG("Y value is too large (%u)>(%u), restart calculation\n",
                      resultTarget.dataLenInBytes - yDataOffset,
                      maxYSize);
            *pYTooLarge = CPA_TRUE;
            status = CPA_STATUS_SUCCESS;
            break;
        }

        /*FIPS 186-3, section C.9, part 7. Y is odd, checkCoprime(Y-1, e)*/
        FIPS_SAMPLE_UNSET_BOTTOM_BIT(
            resultTarget.pData[pResult->dataLenInBytes - 1]);
        status = checkCoprime(pResult, pE, &isCoprime, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Co-primality check fail\n");
            break;
        }
        FIPS_SAMPLE_SET_BOTTOM_BIT(
            resultTarget.pData[pResult->dataLenInBytes - 1]);
        resultTarget.pData += yDataOffset;
        resultTarget.dataLenInBytes -= yDataOffset;
        if (CPA_TRUE != isCoprime)
        {
            /*PRINT_DBG("Y and E are not coprime\n");*/
        }
        else
        {
            CpaBoolean isPrime = CPA_FALSE;

            if (CPA_STATUS_SUCCESS != checkPrimalityFipsC3(nlenBits,
                                                           &resultTarget,
                                                           FIPS_RSA_PRIME_LARGE,
                                                           &isPrime,
                                                           instanceHandle,
                                                           securityStrength))
            {
                PRINT_ERR("Prime Check Process Fail\n");
                status = CPA_STATUS_FAIL;
                break;
            }

            if (CPA_TRUE == isPrime)
            {
                /*FIPS 186-3, section C.9, part 7.1 - 7.3*/
                /*'Y' result is the computed large prime number*/
                PRINT_DBG("Large Prime found.\n");
                *pYTooLarge = CPA_FALSE;
                status = CPA_STATUS_SUCCESS;
                break;
            }
        }

        /*FIPS 186-3, section C.9, part 10. Y = Y + 2(r1r2)*/
        /*add to pResult instead of resultTarget and reset result target size
          and pData pointer at the start of this loop. The NULL input here
          means the result is stored in 'pResult'*/
        status = addFlatBuffer(NULL, pResult, &mult2P1P2);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Y + 2r1r2 overflow (step 6)\n");
            break;
        }
        /*FIPS 186-3, section C.9, part 11. goto 6*/
    }

    /*FIPS 186-3, section C.9, part 9. Too many iterations?*/
    if (i == imax)
    {
        status = CPA_STATUS_FAIL;
    }

finish:
    osFree(&mult2P1P2.pData);
    osFree(&randomXp.pData);

    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaGenerateLargePrime
 *
 * @description
 *      Implementation of FIPS 186-3, C.9 algorithm (for generating a large
 *      prime number based on two smaller primes).
 *
 * @param[in,out]  pXp              An empty buffer or(if haveFipsTestXValues)
 *                                  is CPA_TRUE) a buffer containing a
 *                                  NIST test vector. The random number that
 *                                  was used to generate the prime P is stored
 *                                  here as a result value.
 * @param[in]  pP1                  Small prime used to generate large prime
 * @param[in]  pP2                  Small prime used to generate large prime
 * @param[in]  pE                   RSA algorithm Public Key Exponent value
 * @param[in]  nlenBits             Modulus length
 * @param[in]  securityStrength     Security strength associated with the
 *                                  Modulus length
 * @param[in]  haveFipsTestXValues  If this is set to CPA_TRUE, then the
 *                                  Xp input value is a NIST test vector
 * @param[in]  instanceHandle       QA API instance handle
 *
 * @param[out] P                    A large prime number which may be
 *                                  used to generate N
 * @param[out] Xp                   A large random number used to generate P
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      The pXp value should be cleared before returning to the module.
 *      It is stored only for FIPS audit reasons.
 *****************************************************************************/
static CpaStatus rsaGenerateLargePrime(CpaFlatBuffer *pXp,
                                       CpaFlatBuffer *pP1,
                                       CpaFlatBuffer *pP2,
                                       CpaFlatBuffer *pP,
                                       CpaFlatBuffer *pE,
                                       Cpa32U nlenBits,
                                       Cpa32U securityStrength,
                                       CpaBoolean haveFipsTestXValues,
                                       const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U yDataOffset = 0;
    CpaBoolean isCoprime = CPA_FALSE;
    CpaBoolean rIsNegative = CPA_FALSE;
    CpaBoolean yTooLarge = CPA_FALSE;

    CpaFlatBuffer mult2P1 = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer R = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer Y = {.dataLenInBytes = 0, .pData = NULL};

    /*Max R length < nlen (e.g. if nlen = 1024, max R = 498 bits)*/
    /*Using a large 'R' buffer in case of calculation overflow later*/
    R.dataLenInBytes = (nlenBits / BYTE_SIZE);
    R.pData = osZalloc(R.dataLenInBytes, instanceHandle);
    if (NULL == R.pData)
    {
        PRINT_ERR("Data alloc fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    mult2P1.pData = osZalloc(R.dataLenInBytes, instanceHandle);
    if (NULL == mult2P1.pData)
    {
        PRINT_ERR("Data alloc fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    mult2P1.dataLenInBytes = R.dataLenInBytes;

    /*Allocate a large amount of space for this buffer as some
      intermediate calculates can result in a value greater than the
      result prime value*/
    Y.dataLenInBytes = FIPS_SAMPLE_UNSIGNED_MULT_BY_TWO(R.dataLenInBytes);
    Y.pData = osZalloc(Y.dataLenInBytes, instanceHandle);
    if (NULL == Y.pData)
    {
        PRINT_ERR("Data alloc fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*Copy P1 value to 'mult2P1' buffer*/
    (void)memcpy(
        (mult2P1.pData + (mult2P1.dataLenInBytes - (pP1->dataLenInBytes))),
        pP1->pData,
        pP1->dataLenInBytes);

    /*Calculate (2 * P1), 'NULL' argument means the result is stored in
      'mult2P1' buffer*/
    status = addFlatBuffer(NULL, &mult2P1, pP1);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("mult2P1 gen fail\n");
        goto finish;
    }

    /*FIPS 186-3, section C.9, part 1 - check coprime(2.P1, P2)*/
    status = checkCoprime(&mult2P1, pP2, &isCoprime, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Co-prime check fail\n");
        goto finish;
    }
    if (CPA_TRUE != isCoprime)
    {
        status = CPA_STATUS_FAIL;
        PRINT_ERR("2*P1, P2 are not coprime\n");
        goto finish;
    }
    /*FIPS 186-3, section C.9, part 2*/
    status = rsaGenerateRValue(
        &R, &rIsNegative, &mult2P1, pP2, nlenBits, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Generate R fail\n");
        goto finish;
    }
    do
    {
        /*FIPS 186-3 C.9 algorithm parts 3 to 11. If Y becomes too large
          during the calculation of the prime value, regenerate the 'X'
          intitial value*/
        status = rsaGeneratePValue(&Y,
                                   pXp,
                                   &mult2P1,
                                   pP2,
                                   &R,
                                   rIsNegative,
                                   pE,
                                   nlenBits,
                                   securityStrength,
                                   &yTooLarge,
                                   haveFipsTestXValues,
                                   instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Generate large prime Fail\n");
            goto finish;
        }

        if (haveFipsTestXValues && (CPA_TRUE == yTooLarge))
        {
            PRINT_ERR("NIST test vector failed to result in prime number\n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }
    }
    /*check Y is not too large*/
    while (CPA_TRUE == yTooLarge);

    /*Large Prime has been generated!*/
    yDataOffset = getOffsetToBufferedData(&Y);
    (void)memcpy(
        pP->pData, Y.pData + yDataOffset, Y.dataLenInBytes - yDataOffset);
    pP->dataLenInBytes = Y.dataLenInBytes - yDataOffset;

finish:
    osFree(&Y.pData);
    osFree(&R.pData);
    osFree(&mult2P1.pData);
    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaGeneratePrime1Prime2AndPrime
 *
 * @description
 *      FIPS 186-3 B.3.6 alg, parts 4, 5 (parts 4 and 5 are the same with
 *      different inputs). This function may be used to generate 'P' or 'Q'
 *      large prime values for RSA key generation.
 *
 * @param[in,out]  pXp1             An empty buffer or (if haveFipsTestXValues)
 *                                  is CPA_TRUE) a buffer containing a
 *                                  NIST test vector. The random number that
 *                                  was used to generate the prime P1 is stored
 *                                  here as a result value.
 * @param[in,out]  pXp2             An empty buffer or (if haveFipsTestXValues)
 *                                  is CPA_TRUE) a buffer containing a
 *                                  NIST test vector. The random number that
 *                                  was used to generate the prime P2 is stored
 *                                  here as a result value.
 * @param[in,out]  pXp              An empty buffer or (if haveFipsTestXValues)
 *                                  is CPA_TRUE) a buffer containing a
 *                                  NIST test vector. The random number that
 *                                  was used to generate the prime P is stored
 *                                  here as a result value.
 * @param[out] pP                   Large Prime P
 * @param[out] pP1                  Small prime value used to generate P
 * @param[out] pP2                  Small prime value used to generate P
 * @param[in]  pE                   Public Key Exponent E
 * @param[in]  nlenBits             Size of the operation
 * @param[in]  securityStrength     Security strength to be used for the
 *                                  Random Bit Generator called in this
 *                                  function.
 * @param[in]  haveFipsTestXValues  If this is true, the caller has
 *                                  stored NIST test vectors in the Xp
 *                                  parameters
 * @param[in]  instanceHandle       QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS       The operation succeeded
 * @retval CPA_STATUS_FAIL          The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      The Xp values should be cleared before returning to the module.
 *      It is stored only for FIPS audit reasons.
 *****************************************************************************/
static CpaStatus rsaGeneratePrime1Prime2AndPrime(
    CpaFlatBuffer *pXp1,
    CpaFlatBuffer *pXp2,
    CpaFlatBuffer *pXp,
    CpaFlatBuffer *pP1,
    CpaFlatBuffer *pP2,
    CpaFlatBuffer *pP,
    CpaFlatBuffer *pE,
    Cpa32U nlenBits,
    Cpa32U securityStrength,
    CpaBoolean haveFipsTestXValues,
    const CpaInstanceHandle instanceHandle)
{
    /*get first small prime*/
    if (CPA_STATUS_SUCCESS != rsaGenerateSmallPrime(pXp1,
                                                    pP1,
                                                    nlenBits,
                                                    securityStrength,
                                                    haveFipsTestXValues,
                                                    instanceHandle))
    {
        PRINT_ERR("Could not generate first prime\n");
        return CPA_STATUS_FAIL;
    }
    /*get second small prime*/
    if (CPA_STATUS_SUCCESS != rsaGenerateSmallPrime(pXp2,
                                                    pP2,
                                                    nlenBits,
                                                    securityStrength,
                                                    haveFipsTestXValues,
                                                    instanceHandle))
    {
        PRINT_ERR("Could not generate second prime\n");
        return CPA_STATUS_FAIL;
    }

    /*3 - get large prime and XP*/
    if (CPA_STATUS_SUCCESS != rsaGenerateLargePrime(pXp,
                                                    pP1,
                                                    pP2,
                                                    pP,
                                                    pE,
                                                    nlenBits,
                                                    securityStrength,
                                                    haveFipsTestXValues,
                                                    instanceHandle))
    {
        PRINT_ERR("Could not generate large prime\n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      getFlatBuffNumberSizeDifference
 *
 * @description
 *      Get the size in bits of the difference of two numbers stored in the
 *      input buffers
 *
 * @param[in]  pInputBuffer1         Buffer to compare numbers with
 * @param[in]  pInputBuffer2         Buffer to compare numbers with
 * @param[in]  instanceHandle        QA API instance handle
 *
 * @retval Cpa32U                    Number of bits difference between A and
 *                                   B stored numbers
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static Cpa32U getFlatBuffNumberSizeDifference(
    const CpaFlatBuffer *restrict pInputBuffer1,
    const CpaFlatBuffer *restrict pInputBuffer2,
    const CpaInstanceHandle instanceHandle)
{

    Cpa32U sizeDifference = 0;
    Cpa32U dataOffsetBytes = 0;
    Cpa8U bitOffset = 0;
    Cpa8U topByte = 0;
    CpaFlatBuffer larger = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer smaller = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer result = {.dataLenInBytes = 0, .pData = NULL};

    findAndSetLargestSmallestBuffer(
        pInputBuffer1, pInputBuffer2, &larger, &smaller);

    result.pData = osZalloc(larger.dataLenInBytes, instanceHandle);
    if (NULL == result.pData)
    {
        PRINT_ERR("Could not allocate buffer\n");
        return 0;
    }
    result.dataLenInBytes = larger.dataLenInBytes;

    if (CPA_STATUS_SUCCESS != subFlatBuffer(&result, &larger, &smaller))
    {
        PRINT_ERR("Subtract error\n");
        osFree(&result.pData);
        return 0;
    }

    dataOffsetBytes = getOffsetToBufferedData(&result);
    if (dataOffsetBytes == result.dataLenInBytes)
    {
        PRINT_DBG("Numbers are equal\n");
        osFree(&result.pData);
        return 0;
    }

    topByte = result.pData[dataOffsetBytes];
    if (0 == topByte)
    {
        PRINT_ERR("Error calculating size difference\n");
        osFree(&result.pData);
        return 0;
    }

    sizeDifference = (result.dataLenInBytes - dataOffsetBytes) * BYTE_SIZE;

    bitOffset = FIPS_SAMPLE_TOP_BIT;
    while (0 == (topByte & bitOffset))
    {
        bitOffset >>= 1;
        /*remove extra zero bits*/
        sizeDifference--;
    }

    osFree(&result.pData);
    return sizeDifference;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      checkXPXQandPQValuesBitLengthDifference
 *
 * @description
 *      Ensure the input values are sufficiently close together
 *      on the number line
 *      FIPS 186-3 B.3.6 alg, part 6:
 *      |Xp - Xq| <= 2^(nlen/2 - 100) OR |p -q| <= 2^(nlen/2 - 100)
 *
 * @param[in]  pXp                Random value used to generate P value
 * @param[in]  pXq                Random value used to generate Q value
 * @param[in]  pP                 Prime P value
 * @param[in]  pQ                 Prime Q value
 * @param[in]  instanceHandle     QA API instance handle
 *
 * @retval CPA_TRUE            The numbers are far enough apart
 * @retval CPA_FALSE           The numbers must be re-generated
 *
 * @pre
 *      All memory has been allocated for the inputs.
 * @post
 *      If this function returns CPA_FALSE, the input parameters must be
 *      re-generated
 *****************************************************************************/
static CpaBoolean checkXPXQandPQValuesBitLengthDifference(
    const CpaFlatBuffer *restrict pXp,
    const CpaFlatBuffer *restrict pXq,
    const CpaFlatBuffer *restrict pP,
    const CpaFlatBuffer *restrict pQ,
    Cpa32U nlenBits,
    const CpaInstanceHandle instanceHandle)
{

    const Cpa32S minBits =
        FIPS_RSA_CALCULATE_MIN_BIT_DIFFERENCE_ALG_B_3_6(nlenBits);
    Cpa32U sizeDifferenceBits = 0;

    PRINT_DBG("nlen == %d \n", nlenBits);
    if (0 > minBits)
    {
        PRINT_ERR("nlen(%u) results in too small min bits (%d)! \n",
                  nlenBits,
                  minBits);
    }
    sizeDifferenceBits =
        getFlatBuffNumberSizeDifference(pXp, pXq, instanceHandle);
    if (sizeDifferenceBits <= minBits)
    {
        PRINT_DBG("Size difference too small for Xp, Xq\n");
        PRINT_DBG("Xp - Xq = %u bits\n", sizeDifferenceBits);
        return CPA_FALSE;
    }
    sizeDifferenceBits =
        getFlatBuffNumberSizeDifference(pP, pQ, instanceHandle);
    if (sizeDifferenceBits <= minBits)
    {
        PRINT_DBG("Size difference too small for P, Q\n");
        PRINT_DBG("P - Q = %u bits\n", sizeDifferenceBits);
        return CPA_FALSE;
    }
    PRINT_DBG("Xp, Xq, P, Q sizes OK!\n");

    return CPA_TRUE;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaKeygen
 *
 * @description
 *      Generate RSA keys as specified in FIPS 186-3 section B.3.1.
 *      The algorithm used to generate 'p' and 'q' is B.3.6.
 *
 * @param[in,out]  pRsaData         Structure containing input parameters and
 *                                  output buffers for RSA keygen
 * @param[in] haveFipsTestXValues   If this is true, the caller has supplied
 *                                  key generation values. These are used to
 *                                  test that the key generation algorithm is
 *                                  working correctly and results in an
 *                                  expected set of values.
 * @param[in]  instanceHandle       QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS       The operation succeeded
 * @retval CPA_STATUS_RETRY         The operation should be attempted again
 * @retval CPA_STATUS_FAIL          The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaKeygen(usr_rsa_data_t *pRsaData,
                           CpaBoolean haveFipsTestXValues,
                           const CpaInstanceHandle instanceHandle)
{

    CpaCyDrbgSecStrength securityStrength = CPA_CY_RBG_SEC_STRENGTH_128;
    CpaFlatBuffer *E = &pRsaData->rsaE;

    /*FIPS 186-3 B.3.6, part 1. Check nlen is a FIPS supported length*/
    if (CPA_TRUE != rsaCheckNLen(pRsaData->rsaModulusSizeInBits))
    {
        PRINT_ERR("N len is incorrect value - %d \n",
                  pRsaData->rsaModulusSizeInBits);
        return CPA_STATUS_FAIL;
    }

    /*FIPS 186-3 B.3.6, part 2. Check e > 2^16, e < 2^256, this check is done in
      the 'checkRsaData' function. This algorithm may also be used for X9.31
      Key Generation, however the size of 'e' allowed is different.*/
    if (CPA_TRUE != isFbOdd(E))
    {
        PRINT_ERR("E is not ODD - Rabin Williams mode is not supported by "
                  "FIPS 186-3\n");
        return CPA_STATUS_FAIL;
    }

    /*FIPS 186-3 B.3.6, part 3. set security strength*/
    if (RSA_N_LEN_1024 == pRsaData->rsaModulusSizeInBits)
    {
        /*Min supported security strength for QA is 112*/
        securityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
    }
    else if (RSA_N_LEN_2048 == pRsaData->rsaModulusSizeInBits)
    {
        securityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
    }
    else if (RSA_N_LEN_3072 == pRsaData->rsaModulusSizeInBits)
    {
        securityStrength = CPA_CY_RBG_SEC_STRENGTH_128;
    }
    else
    {
        PRINT_ERR("Modulus size (%d) not supported\n",
                  pRsaData->rsaModulusSizeInBits);
        return CPA_STATUS_FAIL;
    }

    /*FIPS 186-3 B.3.6, part 4. Generate p*/
    /*4.1 - 4.3*/
    if (CPA_STATUS_SUCCESS !=
        rsaGeneratePrime1Prime2AndPrime(&(pRsaData->rsaXP1),
                                        &(pRsaData->rsaXP2),
                                        &(pRsaData->rsaXP),
                                        &(pRsaData->rsaP1),
                                        &(pRsaData->rsaP2),
                                        &(pRsaData->rsaP),
                                        &(pRsaData->rsaE),
                                        pRsaData->rsaModulusSizeInBits,
                                        securityStrength,
                                        haveFipsTestXValues,
                                        instanceHandle))
    {
        PRINT_ERR("Could not generate p1, p2, p \n");
        return CPA_STATUS_FAIL;
    }

    do
    {
        /*FIPS 186-3 B.3.6, part 5. Generate q*/
        /*5.1 - 5.3*/
        if (CPA_STATUS_SUCCESS !=
            rsaGeneratePrime1Prime2AndPrime(&(pRsaData->rsaXQ1),
                                            &(pRsaData->rsaXQ2),
                                            &(pRsaData->rsaXQ),
                                            &(pRsaData->rsaQ1),
                                            &(pRsaData->rsaQ2),
                                            &(pRsaData->rsaQ),
                                            &(pRsaData->rsaE),
                                            pRsaData->rsaModulusSizeInBits,
                                            securityStrength,
                                            haveFipsTestXValues,
                                            instanceHandle))
        {
            PRINT_ERR("Could not generate q1, q2, q \n");
            return CPA_STATUS_FAIL;
        }
        /*FIPS 186-3 B.3.6, part 6.
          If:
            |Xp - Xq| <= 2^(2/nlen - 100) OR |p - q| <= 2^(2/nlen - 100),
          then regenerate the 'Q' value*/
    } while (CPA_FALSE == checkXPXQandPQValuesBitLengthDifference(
                              &(pRsaData->rsaXP),
                              &(pRsaData->rsaXQ),
                              &(pRsaData->rsaP),
                              &(pRsaData->rsaQ),
                              pRsaData->rsaModulusSizeInBits,
                              instanceHandle));

    /*Check if P and Q values are equal - this is not in the FIPS standard,
      but is a (small) possibility as we are basing their generation on
      random numbers*/
    if (0 == memcmp(pRsaData->rsaP.pData,
                    pRsaData->rsaQ.pData,
                    pRsaData->rsaP.dataLenInBytes))
    {
        PRINT_ERR("Generated P and Q values are equal\n");
        return CPA_STATUS_RETRY;
    }

/*FIPS 186-3 B.3.6, part 7. Zero internal buffers*/
    /*End of FIPS B.3.6 prime gen function*/

    /*Generate the public/private keys as specified in PKCS #1 v2.1*/
    if (CPA_STATUS_SUCCESS != rsaKeygenCpaGenerate(pRsaData, instanceHandle))
    {
        PRINT_ERR("Private/Public Key generation Fail\n");
        return CPA_STATUS_FAIL;
    }

    /*FIPS 186-3 B.3.1 part 3- check 'd' value is valid*/
    if (CPA_STATUS_SUCCESS !=
        validateD(pRsaData->rsaModulusSizeInBits, &(pRsaData->rsaD)))
    {
        /*Should restart key generation*/
        return CPA_STATUS_RETRY;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      fipsSample_rsaKeygen
 *
 * @description
 *      Generate RSA keys. See section B.3.1 of FIPS 186-3 for information on
 *      key generation algorithms. The algorithm used in this sample code is
 *      described in section B.3.6 of the standard.
 *
 * @param[in,out]  pRsaData          Structure containing input parameters and
 *                                   output buffers for RSA keygen
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none.
 *****************************************************************************/
CpaStatus fipsSample_rsaKeygen(usr_rsa_data_t *pRsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    Cpa32U keyGenRetryAttempts = 0;

    if (CPA_STATUS_SUCCESS != checkRsaData(pRsaData, RSA_KEYGEN))
    {
        PRINT_ERR("RSA Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        goto finish;
    }
    do
    {
        status = rsaKeygen(pRsaData, pRsaData->useXPinput, instanceHandle);
        keyGenRetryAttempts++;
    } while ((CPA_STATUS_RETRY == status) &&
             (keyGenRetryAttempts < MAX_KEYGEN_RETRY_ATTEMPTS));

    if (MAX_KEYGEN_RETRY_ATTEMPTS == keyGenRetryAttempts)
    {
        PRINT_ERR("RSA keygen Fail, too many retries (%u)\n",
                  keyGenRetryAttempts);
        status = CPA_STATUS_FAIL;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaVerCpa
 *
 * @description
 *      Do the modulus operation to retrieve the message signature for
 *      verification as specified in PKCS#1 v2.1 Section 8.1.2, part 1.
 *      Internally, the Quick Assist API function call also checks the length
 *      of the message signature as specified in part 2 of the same standard.
 *
 * @param[in]  pRsaData           Structure containing input parameters
 *                                for the RSA verify operation.
 * @param[out] pPssMesg           Structure containing input parameters
 * @param[in]  instanceHandle     QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaVerCpa(usr_rsa_data_t *pRsaData,
                           CpaFlatBuffer *pPssMesg,
                           const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaCyRsaPublicKey rsaPublicKey = {
        .modulusN = {.dataLenInBytes = pRsaData->rsaN.dataLenInBytes,
                     .pData = pRsaData->rsaN.pData},
        .publicExponentE = {.dataLenInBytes = pRsaData->rsaE.dataLenInBytes,
                            .pData = pRsaData->rsaE.pData}};
    CpaCyRsaEncryptOpData encryptOpData = {
        .pPublicKey = &rsaPublicKey,
        .inputData = {.pData = pRsaData->rsaEM.pData,
                      .dataLenInBytes = pRsaData->rsaEM.dataLenInBytes}};
    CpaFlatBuffer outputData = {.pData = pPssMesg->pData,
                                .dataLenInBytes = pPssMesg->dataLenInBytes};

    do
    {
        status = cpaCyRsaEncrypt(instanceHandle,
                                 NULL, /*callback function not required*/
                                 NULL, /*opaque data not required*/
                                 &encryptOpData,
                                 &outputData);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        if (CPA_STATUS_SUCCESS !=
            cpaCyGetStatusText(instanceHandle, status, statusErrorString))
        {
            PRINT_ERR("Error retrieving status string.\n");
        }
        PRINT_ERR("RSA Encrypt Fail -- %s\n", statusErrorString);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaSignCpa
 *
 * @description
 *      Sign a message after it has been encoded using a RSA signing scheme
 *
 * @param[in]  pRsaData                 Structure containing input parameters
 *                                      for the RSA sign operation
 * @param[in]  pInputMesg               Message to be used in generating the
 *                                      signature
 * @param[out] pOutputMesg              Signed message
 * @param[in]  instanceHandle           QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaSignCpa(usr_rsa_data_t *pRsaData,
                            CpaFlatBuffer *pInputMesg,
                            CpaFlatBuffer *pOutputMesg,
                            const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };

    CpaFlatBuffer outputData = {.dataLenInBytes = pOutputMesg->dataLenInBytes,
                                .pData = pOutputMesg->pData};
    CpaCyRsaPrivateKey rsaPrivateKey = {
        .version = CPA_CY_RSA_VERSION_TWO_PRIME,
        .privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1,
        .privateKeyRep1 = {
            .modulusN = {.pData = pRsaData->rsaN.pData,
                         .dataLenInBytes = pRsaData->rsaN.dataLenInBytes},
            .privateExponentD = {.pData = pRsaData->rsaD.pData,
                                 .dataLenInBytes =
                                     pRsaData->rsaD.dataLenInBytes}}};
    CpaCyRsaDecryptOpData decryptOpData = {
        .pRecipientPrivateKey = &rsaPrivateKey,
        .inputData = {.dataLenInBytes = pInputMesg->dataLenInBytes,
                      .pData = pInputMesg->pData}};

    do
    {
        status = cpaCyRsaDecrypt(instanceHandle,
                                 NULL, /*callback function not required*/
                                 NULL, /*opaque data not required*/
                                 &decryptOpData,
                                 &outputData);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        if (CPA_STATUS_SUCCESS !=
            cpaCyGetStatusText(instanceHandle, status, statusErrorString))
        {
            PRINT_ERR("Error retrieving status string.\n");
        }
        PRINT_ERR("RSA Decrypt Fail -- %s\n", statusErrorString);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaApplyMGF
 *
 * @description
 *      Use the QA Extended Mask Generation Function to get a PKCS #1 v2.1
 *      mask, based on the input hash algorithm.
 *
 * @param[in]  pMesg             Message to apply the mask to
 * @param[out] pEncodedMesg      Result mask is stored here
 * @param[in]  hashAlgorithm     SHA algorithm to use
 * @param[in]  instanceHandle    QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS    The operation succeeded
 * @retval CPA_STATUS_FAIL       The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaApplyMGF(CpaFlatBuffer *pMesg,
                             CpaFlatBuffer *pEncodedMesg,
                             CpaCySymHashAlgorithm hashAlgorithm,
                             const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaCyKeyGenMgfOpDataExt keyGenMgfOpDataExt = {
        .hashAlgorithm = hashAlgorithm,
        .baseOpData = {
            .maskLenInBytes = pEncodedMesg->dataLenInBytes,
            .seedBuffer = {.pData = pMesg->pData,
                           .dataLenInBytes = pMesg->dataLenInBytes}}};
    CpaFlatBuffer generatedMaskBuffer = {.pData = pEncodedMesg->pData,
                                         .dataLenInBytes =
                                             pEncodedMesg->dataLenInBytes};

    do
    {
        status = cpaCyKeyGenMgfExt(instanceHandle,
                                   NULL, /*callback function not required*/
                                   NULL, /*opaque data not required*/
                                   &keyGenMgfOpDataExt,
                                   &generatedMaskBuffer);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        if (CPA_STATUS_SUCCESS !=
            cpaCyGetStatusText(instanceHandle, status, statusErrorString))
        {
            PRINT_ERR("Error retrieving status string.\n");
        }
        PRINT_ERR("MGF generation Fail -- %s\n", statusErrorString);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaSignPSS
 *
 * @description
 *      RSA PSS signature generation function implementing PKCS#1 v2.1
 *      Section 8.1.1. It uses the Quick Assist API for modulus related
 *      functionality and also implements EMSA-PSS-Encode (Section 9.1.1)
 *
 * @param[in,out] pRsaData           Structure containing input parameters
 *                                   and output buffers for the RSA PSS sign
 *                                   operation.
 * @param[in]     instanceHandle     QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaSignPSS(usr_rsa_data_t *pRsaData,
                            const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer h = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer EM = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer DB = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer dbMask = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer randomSalt = {
        .dataLenInBytes = pRsaData->rsaSalt.dataLenInBytes, .pData = NULL};

    /*PKCS#1 v2.1 section 8.1.1, part 1 - EM len = (nlenBits) / 8 for supported
      sizes of nlenBits*/
    Cpa32U emLenBytes = (pRsaData->rsaModulusSizeInBits) / BYTE_SIZE;
    Cpa32U modulusInBytes = (pRsaData->rsaModulusSizeInBits) / BYTE_SIZE;

    Cpa32U osZallocSize = pRsaData->rsaM.dataLenInBytes +
                          (modulusInBytes * NUM_PSS_REQUIRED_BUFFERS);
    Cpa32U saltlen = pRsaData->rsaSalt.dataLenInBytes;
    Cpa32U hlen = 0;
    Cpa32U pslen = 0;
    Cpa32U securityStrength = CPA_CY_RBG_SEC_STRENGTH_128;

    /*PKCS#1 v2.1 section 9.1.2, part 1 -
      Check if M is less than the Hash function max input size*/
    /*Max message size for SHA1 is 61 bits, max supported input size for
      Quick Assist API is 32 bits, so we don't need to do this check.*/


    status = getHashBytes(pRsaData->shaAlg, &hlen);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not get output length of SHA algorithm\n");
        return CPA_STATUS_FAIL;
    }

    EM.pData = osZalloc(osZallocSize, instanceHandle);
    if (NULL == EM.pData)
    {
        PRINT_ERR("Could not allocate PSS calculation buffers\n");
        return CPA_STATUS_FAIL;
    }

    DB.pData = EM.pData + pRsaData->rsaM.dataLenInBytes;
    h.pData = DB.pData + modulusInBytes;
    dbMask.pData = h.pData + modulusInBytes;

    (void)memcpy(EM.pData, pRsaData->rsaM.pData, pRsaData->rsaM.dataLenInBytes);
    EM.dataLenInBytes = pRsaData->rsaM.dataLenInBytes;

    /*PKCS#1 v2.1 section 9.1.1, part 2 - get message hash*/
    status = getRsaHash(pRsaData,
                        &EM,
                        NULL, /*This means the result overwrites the
                                value in the 'EM' buffer*/
                        instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Mesg Digest Fail\n");
        goto finish;
    }
    EM.dataLenInBytes = hlen;

    pslen = hlen + saltlen + RSA_PSS_TRAILER_LENGTH;
    /*PKCS#1 v2.1 section 9.1.1, part 3 -
      Check emLen >= hash len + salt len + 2 bytes*/
    if (emLenBytes < pslen)
    {
        PRINT_ERR("Encoding Error\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    randomSalt.pData = osZalloc(randomSalt.dataLenInBytes, instanceHandle);
    if (NULL == randomSalt.pData)
    {
        PRINT_ERR("Salt value Alloc Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    PRINT_DBG("Original security strength is %d\n", (int)securityStrength);

    switch (pRsaData->rsaModulusSizeInBits)
    {
        case RSA_N_LEN_1024:
            securityStrength =
                CPA_CY_RBG_SEC_STRENGTH_112; /* Only 80 bits needed */
            break;
        case RSA_N_LEN_2048:
            securityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
            break;
        case RSA_N_LEN_3072:
            securityStrength = CPA_CY_RBG_SEC_STRENGTH_128;
            break;
        default:
        {
            PRINT_ERR("Modulus length (%u) not supported by FIPS 186-3 \n",
                      pRsaData->rsaModulusSizeInBits);
            return CPA_STATUS_FAIL;
        }
    }

    PRINT_DBG("New security strength is %d\n", (int)securityStrength);
    /*PKCS#1 v2.1 section 9.1.1, part 4 -
      Generate Salt (if slen is 0, generate no salt)*/
    if (0 != saltlen)
    {
        /*Using max security strength as it is not specified.*/
        status = generateRandomBytes(
            &(randomSalt), saltlen, securityStrength, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("generateRandomBytes Fail \n");
            goto finish;
        }
    }
    memcpy(
        pRsaData->rsaSalt.pData, randomSalt.pData, randomSalt.dataLenInBytes);
    pRsaData->rsaSalt.dataLenInBytes = randomSalt.dataLenInBytes;

    /*PKCS#1 v2.1 section 9.1.1, part 5, 6 -
      Generate h = HASH(8 zero bytes || message hash || salt)*/
    (void)memset(h.pData, 0, RSA_PAD_8_BYTES);
    (void)memcpy((h.pData + RSA_PAD_8_BYTES), EM.pData, EM.dataLenInBytes);
    (void)memcpy((h.pData + RSA_PAD_8_BYTES + EM.dataLenInBytes),
                 pRsaData->rsaSalt.pData,
                 saltlen);

    h.dataLenInBytes = RSA_PAD_8_BYTES + EM.dataLenInBytes + saltlen;

    status = getRsaHash(pRsaData, &h, NULL, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("getRsaHash Fail \n");
        goto finish;
    }
    h.dataLenInBytes = hlen;

    /*PKCS#1 v2.1 section 9.1.1, part 7 -
      PS_len = nlen - (hash len + salt len + 2) <= 0 (checked at 3)*/
    pslen = emLenBytes - pslen;

    /*PKCS#1 v2.1 section 9.1.1, part 8 - DB = PS_len zero bytes || 0x01 ||
     * salt*/
    (void)memset(DB.pData, 0, pslen);
    DB.pData[pslen] = 0x01;
    (void)memcpy(&(DB.pData[pslen + 1]), pRsaData->rsaSalt.pData, saltlen);
    DB.dataLenInBytes = pslen + 1 + saltlen;

    dbMask.dataLenInBytes = emLenBytes - hlen - 1;

    /*PKCS#1 v2.1 section 9.1.1, part 9 - get dbMask = MGF(H, DBlen)*/
    if (CPA_STATUS_SUCCESS !=
        rsaApplyMGF(&h, &dbMask, pRsaData->shaAlg, instanceHandle))
    {
        PRINT_ERR("MGF generation Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*PKCS#1 v2.1 section 9.1.1, part 10 - maskedDB = DB XOR dbMask*/
    fipsSampleBufXOR(DB.pData, dbMask.pData, dbMask.dataLenInBytes);

    /*PKCS#1 v2.1 section 9.1.1, part 11 -
      Set the leftmost (8emLen - emBits) bits of the leftmost octet
      in maskedDB to zero. Supported sizes = 1024, 2048, 3072 ==> 128, 256,
      384*/
    FIPS_SAMPLE_UNSET_TOP_BIT(DB.pData[0]);

    EM.dataLenInBytes = DB.dataLenInBytes + h.dataLenInBytes + 1;

    /*PKCS#1 v2.1 section 9.1.1, part 12 - EM = maskedDB || H || 0xbc*/
    (void)memcpy(EM.pData, DB.pData, DB.dataLenInBytes);
    (void)memcpy(EM.pData + DB.dataLenInBytes, h.pData, h.dataLenInBytes);
    EM.dataLenInBytes = DB.dataLenInBytes + h.dataLenInBytes + 1;
    EM.pData[EM.dataLenInBytes - 1] = RSA_PSS_ENCODED_MESSAGE_TERMINATOR;

    pRsaData->rsaEM.dataLenInBytes = EM.dataLenInBytes;

    if (CPA_STATUS_SUCCESS !=
        rsaSignCpa(pRsaData, &EM, &pRsaData->rsaEM, instanceHandle))
    {
        PRINT_ERR("RSA Sign Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

finish:
    osFree(&EM.pData);
    osFree(&randomSalt.pData);

    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      fipsSample_rsaSign
 *
 * @description
 *      Top level function for RSA PSS signature generation
 *
 * @param[in,out] pRsaData           Structure containing input parameters
 *                                   and output buffers for the RSA signature
 *                                   operation.
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_rsaSign(usr_rsa_data_t *pRsaData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkRsaData(pRsaData, RSA_SIGN))
    {
        PRINT_ERR("RSA Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != fipsSampleGetQaInstance(&instanceHandle))
    {
        PRINT_ERR("Get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        goto finish;
    }
    /*RSASSA-PSS signing scheme as specified in PKCS #1 v1.5*/
    if (CPA_STATUS_SUCCESS != rsaSignPSS(pRsaData, instanceHandle))
    {
        PRINT_ERR("RSA PSS sign fail\n");
        goto finish;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      rsaVerPSS
 *
 * @description
 *      RSA PSS signature verification function implementing PKCS#1 v2.1
 *      Section 8.1.2. It uses the Quick Assist API for modulus related
 *      functionality and also implements EMSA-PSS-Verify (Section 9.1.2)
 *
 * @param[in,out] pRsaData           Structure containing input parameters
 *                                   and output buffers for the RSA signature
 *                                   operation.
 * @param[in]     instanceHandle     QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus rsaVerPSS(usr_rsa_data_t *pRsaData,
                           const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer pssSig = {.dataLenInBytes =
                                pRsaData->rsaModulusSizeInBits / BYTE_SIZE,
                            .pData = NULL};
    CpaFlatBuffer dbMask = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer maskedDB = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer salt = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer mDash = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer mHash = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer h = {.dataLenInBytes = 0, .pData = NULL};
    Cpa32U modulusInBytes = pRsaData->rsaModulusSizeInBits / BYTE_SIZE;
    Cpa32U saltlen = pRsaData->rsaSalt.dataLenInBytes;
    Cpa32U pslen = 0;
    Cpa32U i = 0;

    /*default for signature check is 'inconsistent' result*/
    pRsaData->sigVerified = CPA_FALSE;

    /*PKCS#1 v2.1 section 9.1.2, part 1 -
      Check M is not greater than max hash length*/
    /*Max message size for SHA1 is 61 bits, max supported input size for
      Quick Assist API is 32 bits, so we don't need to do this check.*/


    status = getHashBytes(pRsaData->shaAlg, &mHash.dataLenInBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not get output length of SHA algorithm\n");
        return CPA_STATUS_FAIL;
    }

    mDash.dataLenInBytes = RSA_PAD_8_BYTES + mHash.dataLenInBytes + saltlen;

    /*Mask Generation function output buffer size*/
    dbMask.dataLenInBytes = pssSig.dataLenInBytes - mHash.dataLenInBytes - 1;
    pssSig.pData = osZalloc(modulusInBytes + mHash.dataLenInBytes +
                                mDash.dataLenInBytes + dbMask.dataLenInBytes,
                            instanceHandle);
    if (NULL == pssSig.pData)
    {
        PRINT_ERR("Could not allocate PSS calculation buffers\n");
        return CPA_STATUS_FAIL;
    }

    mHash.pData = pssSig.pData + modulusInBytes;
    mDash.pData = mHash.pData + mHash.dataLenInBytes;
    dbMask.pData = mDash.pData + mDash.dataLenInBytes;

    /*PKCS#1 v2.1 section 8.1.2, part 1 and 2*/
    status = rsaVerCpa(pRsaData, &pssSig, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("RSA PSS verification fail (QA fail)\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*PKCS#1 v2.1 section 9.1.2, part 2 - get message hash*/
    status = getRsaHash(pRsaData, &pRsaData->rsaM, &mHash, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Mesg Digest Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    PRINT_DBG("saltlen = %u\n", saltlen);
    pslen = mHash.dataLenInBytes + saltlen + RSA_PSS_TRAILER_LENGTH;
    /*PKCS#1 v2.1 section 9.1.2, part 3 - Check EM length >= hlen + slen + 2*/
    if (pRsaData->rsaEM.dataLenInBytes < pslen)
    {
        PRINT_ERR("Inconsistent\n");
        PRINT_DBG("Encoding Error - Signature len (%u)"
                  " is less than pslen (%u)\n",
                  pRsaData->rsaEM.dataLenInBytes,
                  pslen);
        status = CPA_STATUS_SUCCESS;
        pRsaData->sigVerified = CPA_FALSE;
        goto finish;
    }
    pslen = modulusInBytes - pslen;

    /*PKCS#1 v2.1 section 9.1.2, part 4 - Check EM has rightmost octet == 0xbc*/
    if (RSA_PSS_ENCODED_MESSAGE_TERMINATOR !=
        pssSig.pData[pssSig.dataLenInBytes - 1])
    {
        PRINT_ERR("Inconsistent\n");
        PRINT_DBG("Encoding Error - message terminator (0x%X) is set as 0x%X\n",
                  RSA_PSS_ENCODED_MESSAGE_TERMINATOR,
                  pssSig.pData[pssSig.dataLenInBytes - 1]);
        status = CPA_STATUS_SUCCESS;
        pRsaData->sigVerified = CPA_FALSE;
        goto finish;
    }

    /*PKCS#1 v2.1 section 9.1.2, part 5. Hash value must be found as per
      FIPS 186-3 section 5.4 (last two bytes, backwards)*/
    /* get maskedDB, 'h'*/
    maskedDB.pData = pssSig.pData;
    maskedDB.dataLenInBytes = pssSig.dataLenInBytes - mHash.dataLenInBytes - 1;

    /*'h' is the stored message hash from the signature*/
    h.pData = pssSig.pData + pssSig.dataLenInBytes - (mHash.dataLenInBytes + 1);
    h.dataLenInBytes = mHash.dataLenInBytes;

    /*PKCS#1 v2.1 section 9.1.2, part 6 -
      Check the 8emLen - emBits of the leftmost byte are zero*/
    if (0 != (maskedDB.pData[0] & FIPS_SAMPLE_TOP_BIT))
    {
        PRINT_ERR("Inconsistent\n");
        PRINT_DBG("Encoding Error - top bits of maskedDB are not zero\n");
        pRsaData->sigVerified = CPA_FALSE;
        status = CPA_STATUS_SUCCESS;
        goto finish;
    }

    /*PKCS#1 v2.1 section 9.1.2, part 7 - Let dbMask = MGF (h, emLen - hLen -
     * 1)*/
    if (CPA_STATUS_SUCCESS !=
        rsaApplyMGF(&h, &dbMask, pRsaData->shaAlg, instanceHandle))
    {
        PRINT_ERR("MGF generation Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*PKCS#1 v2.1 section 9.1.2, part 8 - maskedDB = DB XOR dbMask*/
    fipsSampleBufXOR(maskedDB.pData, dbMask.pData, dbMask.dataLenInBytes);

    /*PKCS#1 v2.1 section 9.1.2, part 9 - set 8Emlen - EmBits bits to zero*/
    FIPS_SAMPLE_UNSET_TOP_BIT(maskedDB.pData[0]);

    for (i = 0; i < pslen; i++)
    {
        if (0 != maskedDB.pData[i])
        {
            pRsaData->sigVerified = CPA_FALSE;
            status = CPA_STATUS_SUCCESS;
            PRINT_ERR("Inconsistent\n");
            PRINT_DBG("Encoding Error - non zero byte at top of maskedDB\n");
            goto finish;
        }
    }
    /*PKCS#1 v2.1 section 9.1.2, part 10 -
      If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero or
      if the octet at position emLen - hLen - sLen - 1 does not have hexadecimal
      value 0x01, output inconsistent and stop.*/
    if (0x01 != maskedDB.pData[pslen])
    {
        PRINT_ERR("Inconsistent\n");
        PRINT_DBG("Encoding Error, maskedDB byte = 0x%X \n",
                  maskedDB.pData[pslen]);
        pRsaData->sigVerified = CPA_FALSE;
        status = CPA_STATUS_SUCCESS;
        goto finish;
    }

    /*PKCS#1 v2.1 section 9.1.2, part 11 -
      Let salt be the last sLen octets of DB.
      slen is an input parameter == rsaData->rsaSalt.dataLenInBytes*/
    salt.pData = maskedDB.pData + maskedDB.dataLenInBytes -
                 pRsaData->rsaSalt.dataLenInBytes;
    salt.dataLenInBytes = pRsaData->rsaSalt.dataLenInBytes;
    /*PKCS#1 v2.1 section 9.1.2, part 12 - Let
      M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
      M' is an octet string of length 8 + hLen + sLen with
      eight initial zero octets.*/
    (void)memset(mDash.pData, 0, RSA_PAD_8_BYTES);
    (void)memcpy(
        (mDash.pData + RSA_PAD_8_BYTES), mHash.pData, mHash.dataLenInBytes);
    (void)memcpy((mDash.pData + RSA_PAD_8_BYTES + mHash.dataLenInBytes),
                 salt.pData,
                 salt.dataLenInBytes);

    mDash.dataLenInBytes =
        RSA_PAD_8_BYTES + mHash.dataLenInBytes + salt.dataLenInBytes;

    /*PKCS#1 v2.1 section 9.1.2, part 13 -
      Let H' = Hash (M'), an octet string of length hLen.*/
    status = getRsaHash(pRsaData, &mDash, NULL, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("getRsaHash Fail \n");
        goto finish;
    }
    mDash.dataLenInBytes = mHash.dataLenInBytes;

    /*PKCS#1 v2.1 section 9.1.2, part 14 -
      If h = h', output consistent. Otherwise, output inconsistent.*/
    if (0 != memcmp(mDash.pData, h.pData, h.dataLenInBytes))
    {
        PRINT_ERR("Inconsistent\n");
        PRINT_DBG("Hash contents are different \n");
        pRsaData->sigVerified = CPA_FALSE;
        status = CPA_STATUS_SUCCESS;
        goto finish;
    }
    pRsaData->sigVerified = CPA_TRUE;

finish:
    osFree(&pssSig.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      fipsSample_rsaVerify
 *
 * @description
 *      Verify a RSA signature using a RSA signature scheme
 *
 * @param[in,out] pRsaData           Structure containing input parameters
 *                                   and output buffers for the RSA signature
 *                                   operation.
 * @param[in]     instanceHandle     QA API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the inputs and outputs
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_rsaVerify(usr_rsa_data_t *pRsaData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkRsaData(pRsaData, RSA_VERIFY))
    {
        PRINT_ERR("RSA Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != fipsSampleGetQaInstance(&instanceHandle))
    {
        PRINT_ERR("Get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        goto finish;
    }
    /*RSASSA-PSS signature verification scheme as specified in PKCS #1 v1.5*/
    if (CPA_STATUS_SUCCESS != rsaVerPSS(pRsaData, instanceHandle))
    {
        PRINT_ERR("RSA PSS Verify fail\n");
        goto finish;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }

    return CPA_STATUS_SUCCESS;
}
