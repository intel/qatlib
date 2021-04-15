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
 *****************************************************************************
 * @file cpa_fips_sample_ecdsa.c
 *
 * @ingroup fipsSampleEcdsa
 *
 *      ECDSA functions implemented using the Quick Assist API to comply with
 *      FIPS 186-3 standard
 *
 *****************************************************************************/

#include "cpa_fips_sample.h"
#include "cpa_fips_sample_utils.h"
#include "cpa_fips_sample_ecdsa.h"
#include "cpa_fips_sample_aes_gcm.h"

/**
 ******************************************************************************
 * @ingroup fipsSampleCodeEcdsa
 *      EXPORT_SYMBOLs
 *
 * Functions which are exported for the kernel module interface
 *****************************************************************************/

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      checkEcdsaCofactorDomainParamSizeInBits
 *
 * @description
 *      As specified in FIPS 186-3 Section 6.1.1, Table 1, check whether the
 *      input cofactor 'h' value is the correct bit size.
 *
 * @param[in]  baseOrderBitLength  Bit length of 'n' the base point order.
 *                                 if this value is greater than or equal to
 *                                 512, the following defined value should
 *                                 be input:
 *                                 FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_512
 *                                 This is to avoid values that are not
 *                                 possible to store in 32 bits
 * @param[in]  hValueBitLength     Bit length of 'h' the cofactor
 *                                 if this value is greater than or equal to
 *                                 33, the following defined value should
 *                                 be input:
 *                                 FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_32_BITS
 *                                 This is to avoid values that are not
 *                                 possible to store in 32 bits
 *
 * @retval CPA_TRUE                h value is OK
 *         CPA_FALSE               h value does not conform to the spec
 *
 *****************************************************************************/
static inline CpaBoolean checkEcdsaCofactorDomainParamSizeInBits(
    Cpa32U baseOrderBitLength,
    Cpa32U hValueBitLength)
{

    /*if baseOrderBitLength < 224, h must be <= 2^10*/
    if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_223 >= baseOrderBitLength)
    {
        if (FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_10_BITS < hValueBitLength)
        {
            PRINT_ERR("h value is too large for the curve type\n");
            PRINT_ERR("h value is described in %u bits\n", hValueBitLength);
            return CPA_FALSE;
        }
        /*if baseOrderBitLength < 256, h must be <= 2^14*/
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_255 >= baseOrderBitLength)
    {
        if (FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_14_BITS < hValueBitLength)
        {
            PRINT_ERR("h value is too large for the curve type\n");
            return CPA_FALSE;
        }
        /*if baseOrderBitLength < 384, h must be <= 2^16*/
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_383 >= baseOrderBitLength)
    {
        if (FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_16_BITS < hValueBitLength)
        {
            PRINT_ERR("h value is too large for the curve type\n");
            return CPA_FALSE;
        }
        /*if baseOrderBitLength < 511, h must be <= 2^24*/
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_511 >= baseOrderBitLength)
    {
        if (FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_24_BITS < hValueBitLength)
        {
            PRINT_ERR("h value is too large for the curve type\n");
            return CPA_FALSE;
        }
        /*if baseOrderBitLength >= 512, h must be <= 2^32*/
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_512 <= baseOrderBitLength)
    {
        if (FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_32_BITS < hValueBitLength)
        {
            PRINT_ERR("h value is too small for the curve type\n");
            return CPA_FALSE;
        }
    }
    else
    {
        PRINT_DBG("ERROR - baseOrderBitLength not supported\n");
        return CPA_FALSE;
    }

    return CPA_TRUE;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      checkEcdsaData
 *
 * @description
 *      Check inputs for the different FIPS functions based on expected input
 *      and output buffers. This also checks that domain parameters are
 *      within the bounds specified in FIPS 186-3 Section 6
 *
 * @param[in]  pEcdsaData            structure to be checked per algorithm
 * @param[in]  ecdsaOp               Which algorithm is being checked
 *                                   (e.g. KeyGen, Sign, Verify)
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 *****************************************************************************/
static CpaStatus checkEcdsaData(const usr_ecdsa_data_t *restrict pEcdsaData,
                                ecdsa_operation_t ecdsaOp)
{
    Cpa32U baseOrderValueNumberOfBits = 0;
    Cpa32U i = FIPS_SAMPLE_TOP_BIT;
    Cpa32U hValueNumberOfBytes = 0, hValueNumberOfBits = 0, hByteOffset = 0;
    Cpa32U nValueNumberOfBytes = 0, nValueNumberOfBits = 0, nByteOffset = 0;

    /*Check common domain parameters*/
    switch (pEcdsaData->fieldType)
    {
        case CPA_CY_EC_FIELD_TYPE_PRIME:
            PRINT_DBG("field type prime\n");
            break;
        case CPA_CY_EC_FIELD_TYPE_BINARY:
            PRINT_DBG("field type binary\n");
            break;
        default:
            PRINT_DBG("ERROR - field type not supported\n");
            return CPA_STATUS_FAIL;
            break;
    }

    switch (pEcdsaData->curve)
    {
        case P192:
        case P224:
        case P256:
        case P384:
        case P521:
            PRINT_DBG("Prime curve\n");
            break;
        case K163:
        case K233:
        case K283:
        case K409:
        case K571:
            PRINT_DBG("Koblitz Binary curve\n");
            break;
        case B163:
        case B233:
        case B283:
        case B409:
        case B571:
            PRINT_DBG("Binary curve %d\n", pEcdsaData->curve);
            break;
        case CUSTOM:
            PRINT_DBG("Custom curve %d\n", pEcdsaData->curve);
        default:
            PRINT_ERR("ERROR - curve designation incorrect\n");
            return CPA_STATUS_FAIL;
    }

    /*FIPS 186-3 Section 6.1.1 - make sure cofactor (h) value is supplied*/
    RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("h = ", &pEcdsaData->h));

    /*FIPS 186-3 Section 6.1.1 - make sure cofactor (h) is the correct size*/
    hByteOffset = getOffsetToBufferedData(&(pEcdsaData->h));
    if (pEcdsaData->h.dataLenInBytes - hByteOffset > sizeof(Cpa32U))
    {
        PRINT_ERR("h value cannot be described in greater than"
                  " 32 bits for any curve\n");
        return CPA_STATUS_FAIL;
    }

    if (hByteOffset >= pEcdsaData->h.dataLenInBytes)
    {
        PRINT_ERR("h stored value is zero\n");
        return CPA_STATUS_FAIL;
    }

    i = FIPS_SAMPLE_TOP_BIT;
    hValueNumberOfBytes = pEcdsaData->h.dataLenInBytes - hByteOffset;
    hValueNumberOfBits = hValueNumberOfBytes * BYTE_SIZE;
    while (0 == (pEcdsaData->h.pData[hByteOffset] & i))
    {
        i >>= 1;
        hValueNumberOfBits--;
    }

    if (FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_32_BITS < hValueNumberOfBits)
    {
        PRINT_ERR("Cofactor 'h' value %u is too large"
                  " - greater than 32 bits)\n",
                  hValueNumberOfBits);
        return CPA_STATUS_FAIL;
    }

    /*Find which part of the table the bit length of the base order
      value 'n' fits into.*/
    nByteOffset = getOffsetToBufferedData(&(pEcdsaData->OrderOfG));
    if (nByteOffset >= pEcdsaData->OrderOfG.dataLenInBytes)
    {
        PRINT_ERR("Base Point Order value is zero\n");
        return CPA_STATUS_FAIL;
    }
    nValueNumberOfBytes = pEcdsaData->OrderOfG.dataLenInBytes - nByteOffset;
    nValueNumberOfBits = nValueNumberOfBytes * BYTE_SIZE;

    i = FIPS_SAMPLE_TOP_BIT;
    while (0 == (pEcdsaData->OrderOfG.pData[nByteOffset] & i))
    {
        i >>= 1;
        nValueNumberOfBits--;
    }

    /*n is described in less than 160 bits*/
    if (FIPS_SAMPLE_ECDSA_BASE_ORDER_MIN_BIT_LENGTH > nValueNumberOfBits)
    {
        PRINT_ERR("Base Point Order value is too small - (%u bits)\n",
                  nValueNumberOfBits);
        return CPA_STATUS_FAIL;
    }

    if (CPA_TRUE != checkEcdsaCofactorDomainParamSizeInBits(nValueNumberOfBits,
                                                            hValueNumberOfBits))
    {
        PRINT_ERR("h value is too large for the curve type\n");
        return CPA_STATUS_FAIL;
    }


    /*Check polynomial a,b values exist*/
    RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("a = ", &pEcdsaData->a));
    /*'a' can be zero, 1 or -3 for FIPS curves*/
    RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("b = ", &pEcdsaData->b));
    if (CPA_FALSE != checkZero(&pEcdsaData->b))
    {
        PRINT_DBG("b value is zero (invalid value)\n");
        return CPA_STATUS_FAIL;
    }

    /*Check polynomial G values exist*/
    RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("xg = ", &pEcdsaData->xg));
    RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("yg = ", &pEcdsaData->yg));
    if ((CPA_FALSE != checkZero(&pEcdsaData->xg)) &&
        (CPA_FALSE != checkZero(&pEcdsaData->yg)))
    {
        PRINT_DBG("Gx and Gy value is zero (invalid value)\n");
        return CPA_STATUS_FAIL;
    }

    /*Check values exist for PrimeOrPolynomial and OrderOfG*/
    RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("PrimeOrPolynomial = ",
                                              &pEcdsaData->PrimeOrPolynomial));
    RETURN_IF_CPA_STATUS_FAIL(
        checkFlatBuffer("OrderOfG = ", &pEcdsaData->OrderOfG));

    /*Check per algorithm parameters*/
    if ((ECDSA_SIGN == ecdsaOp) || (ECDSA_VERIFY == ecdsaOp))
    {
        /*Check it is a supported hash algorithm, and that the algorithm
          has the required security strength*/
        switch (pEcdsaData->hashAlgorithm)
        {
            case CPA_CY_SYM_HASH_SHA1:
                PRINT_DBG("CPA_CY_SYM_HASH_SHA1\n");
                if (baseOrderValueNumberOfBits >
                    FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_223)
                {
                    PRINT_ERR(
                        "SHA1 algorithm security strength is to "
                        "low to be used with the specified base point order\n");
                    PRINT_ERR("Base point order is greater than %u\n",
                              FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_223);
                }
                break;
            case CPA_CY_SYM_HASH_SHA224:
                PRINT_DBG("CPA_CY_SYM_HASH_SHA224\n");
                if (baseOrderValueNumberOfBits >
                    FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_255)
                {
                    PRINT_ERR(
                        "SHA224 algorithm security strength is to "
                        "low to be used with the specified base point order\n");
                    PRINT_ERR("Base point order is greater than %u\n",
                              FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_255);
                }
                break;
            case CPA_CY_SYM_HASH_SHA256:
                PRINT_DBG("CPA_CY_SYM_HASH_SHA256\n");
                if (baseOrderValueNumberOfBits >
                    FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_383)
                {
                    PRINT_ERR(
                        "SHA256 algorithm security strength is to "
                        "low to be used with the specified base point order\n");
                    PRINT_ERR("Base point order is greater than %u\n",
                              FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_383);
                }
                break;
            case CPA_CY_SYM_HASH_SHA384:
                PRINT_DBG("CPA_CY_SYM_HASH_SHA384\n");
                if (baseOrderValueNumberOfBits >
                    FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_511)
                {
                    PRINT_ERR(
                        "SHA384 algorithm security strength is to "
                        "low to be used with the specified base point order\n");
                    PRINT_ERR("Base point order is greater than %u\n",
                              FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_511);
                }
                break;
            case CPA_CY_SYM_HASH_SHA512:
                PRINT_DBG("CPA_CY_SYM_HASH_SHA512\n");
                break;
            default:
                PRINT_DBG("ERROR - Hash Algorithm not supported\n");
                return CPA_STATUS_FAIL;
        }

        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("mesg = ", &pEcdsaData->mesg));

        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("SignR = ", &pEcdsaData->SignR));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("SignS = ", &pEcdsaData->SignS));

        if (ECDSA_SIGN == ecdsaOp)
        {
            RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("D = ", &pEcdsaData->d));
            if (CPA_FALSE != checkZero(&pEcdsaData->d))
            {
                PRINT_ERR("Private Key value is zero (invalid value)\n");
                return CPA_STATUS_FAIL;
            }
            RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("k = ", &pEcdsaData->k));
            if (CPA_FALSE != checkZero(&pEcdsaData->k))
            {
                PRINT_ERR("Per mesg secret number is zero (invalid value)\n");
                return CPA_STATUS_FAIL;
            }
        }
        else /*Verify*/
        {
            RETURN_IF_CPA_STATUS_FAIL(
                checkFlatBuffer("xq = ", &pEcdsaData->xq));
            RETURN_IF_CPA_STATUS_FAIL(
                checkFlatBuffer("yq = ", &pEcdsaData->yq));
            if ((CPA_FALSE != checkZero(&pEcdsaData->yq)) &&
                (CPA_FALSE != checkZero(&pEcdsaData->xq)))
            {
                PRINT_ERR("Public Key value xq,yq is zero (invalid value)\n");
                return CPA_STATUS_FAIL;
            }
            if (CPA_FALSE != checkZero(&pEcdsaData->SignR))
            {
                PRINT_ERR("Signature value value SignR is zero"
                          " (invalid value)\n");
                return CPA_STATUS_FAIL;
            }
            if (CPA_FALSE != checkZero(&pEcdsaData->SignS))
            {
                PRINT_ERR("Signature value value SignS is zero"
                          " (invalid value)\n");
                return CPA_STATUS_FAIL;
            }
        }
    }
    else if (ECDSA_KEYGEN == ecdsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("D = ", &pEcdsaData->d));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("xq = ", &pEcdsaData->xq));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("yq = ", &pEcdsaData->yq));
    }
    else
    {
        PRINT_DBG("Operation not supported\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      getEcdsaMesgDigestSetupAndCall
 *
 * @description
 *      Compute the hash value H(M).
 *
 *      Note: the value to be used in a sign/verify operation is computed
 *            in a separate function.
 *
 * @param[in]  curve            The curve type
 * @param[in]  pMesg            Message to be Hashed
 * @param[in]  hashAlgorithm    Secure Hash Algorithm to be used
 * @param[in]  instanceHandle   QA instance handle
 *
 * @param[out] pMesgDigest      Hash of the input message
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated
 * @post
 *      none
 *****************************************************************************/
CpaStatus getEcdsaMesgDigestSetupAndCall(CpaFlatBuffer *pMesg,
                                         CpaFlatBuffer *pMesgDigest,
                                         CpaCySymHashAlgorithm hashAlgorithm,
                                         const CpaInstanceHandle instanceHandle)
{

    /* Set input data */
    CpaCySymSessionSetupData sessionSetupData = {
        .sessionPriority = CPA_CY_PRIORITY_NORMAL,
        .symOperation = CPA_CY_SYM_OP_HASH,
        .cipherSetupData =
            {
                0,
            }, /*not used*/
        .hashSetupData = {.hashAlgorithm = hashAlgorithm,
                          .hashMode = CPA_CY_SYM_HASH_MODE_PLAIN,
                          .digestResultLenInBytes = pMesgDigest->dataLenInBytes,
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

    sessionSetupData.hashSetupData.digestResultLenInBytes =
        pMesgDigest->dataLenInBytes;

    return getMesgDigest(pMesg, pMesgDigest, &sessionSetupData, instanceHandle);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      ecdsaKeyGen
 *
 * @description
 *      Generate ECDSA keys. The algorithm used is B.4.1 of FIPS 186-3
 *
 * @param[in,out] pEcdsaData   Domain Parameters (description in header file):
 *                             Curve, a, b, h, xg, yg, PrimeOrPolynomial,
 *                             OrderOfG, Public/Private ECDSA Keys d, xq, yq
 * @param[in]  instanceHandle  Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS       The operation succeeded
 * @retval CPA_STATUS_FAIL          The operation failed
 *
 * @pre
 *      All memory has been allocated
 * @post
 *      none
 *****************************************************************************/
CpaStatus ecdsaKeyGen(usr_ecdsa_data_t *pEcdsaData,
                      const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    Cpa32U orderOfGDataOffset = 0;
    CpaCyEcPointMultiplyOpData multOpData = {{0, NULL}, /*k*/
                                             {0, NULL}, /*xg*/
                                             {0, NULL}, /*yg*/
                                             {0, NULL}, /*a*/
                                             {0, NULL}, /*b*/
                                             {0, NULL}, /*q*/
                                             {0, NULL}, /*h*/
                                             pEcdsaData->fieldType};
    CpaBoolean MultiplyStatus = CPA_TRUE;
    Cpa32U maxDGenIterations = FIPS_SAMPLE_ECDSA_MAX_D_GEN_ITERATIONS;
    Cpa8U i = FIPS_SAMPLE_TOP_BIT;
    CpaCyDrbgSecStrength requestedSecurityStrength =
        CPA_CY_RBG_SEC_STRENGTH_128;
    CpaFlatBuffer randomD = {.dataLenInBytes = pEcdsaData->d.dataLenInBytes,
                             .pData = NULL};
    /*1. N = len(n)*/
    Cpa32U N = pEcdsaData->OrderOfG.dataLenInBytes * BYTE_SIZE;

    PRINT_DBG("Original security strength is %d\n",
              (int)requestedSecurityStrength);

    /*top bytes may be zero*/
    orderOfGDataOffset = getOffsetToBufferedData(&pEcdsaData->OrderOfG);

    N -= orderOfGDataOffset;

    /*counting the bit length of n - therefore subtract top bits*/
    while (0 == (pEcdsaData->OrderOfG.pData[orderOfGDataOffset] & i))
    {
        i >>= 1;
        N--;
    }

    /*2. Check the value of n is greater than or equal to 160 bits*/
    if (FIPS_SAMPLE_ECDSA_BASE_ORDER_MIN_BIT_LENGTH > N)
    {
        PRINT_ERR("Number of bits for N is too small\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*3. Find the requested security strength (associated with n).
      Guidance for this may be found in NIST SP 800-57 Part 1, Table 2*/
    if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_223 > N)
    {
        /*80 bits of security is a minimum. FIPS DRBG only supports 112 bits
          minimum*/
        requestedSecurityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_255 > N)
    {
        requestedSecurityStrength = CPA_CY_RBG_SEC_STRENGTH_112;
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_383 > N)
    {
        requestedSecurityStrength = CPA_CY_RBG_SEC_STRENGTH_128;
    }
    else if (FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_511 > N)
    {
        requestedSecurityStrength = CPA_CY_RBG_SEC_STRENGTH_192;
    }
    else
    {
        requestedSecurityStrength = CPA_CY_RBG_SEC_STRENGTH_256;
    }

    PRINT_DBG("New security strength is %d\n", (int)requestedSecurityStrength);

    randomD.pData = osZalloc(randomD.dataLenInBytes, instanceHandle);
    if (NULL == randomD.pData)
    {
        PRINT_ERR("D value Alloc Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*4,5,6 Spec allows for 'equivalent functionality'. Here, instead of
     adding 1 to the (possibly) zero value result, we check for zero and
     regenerate the random number if that is found. The limit of the result
     is now (n -1). */
    do
    {
        /*B.4.1, d = (c mod (n -1)) + 1 ==> max(d) = n -1 */
        /*Note: The possible number generation bias introduced by doing
                the modulus operation (and the modulus operation itself)
                are taken care of in this function.*/
        status = getRandomLessThanN((&randomD),
                                    &(pEcdsaData->OrderOfG),
                                    requestedSecurityStrength,
                                    instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Get Random Less Than N fail\n");
            goto finish;
        }
        maxDGenIterations--;
        if (0 == maxDGenIterations)
        {
            PRINT_ERR("Max D Generation attempts exceeded and status = %d \n",
                      status);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        /*Make sure d is > 0*/
    } while (CPA_TRUE == checkZero(&(randomD)));

    memcpy(pEcdsaData->d.pData, randomD.pData, randomD.dataLenInBytes);
    pEcdsaData->d.dataLenInBytes = randomD.dataLenInBytes;
    if (pEcdsaData->k.pData != NULL)
    {
        memcpy(pEcdsaData->k.pData, randomD.pData, randomD.dataLenInBytes);
        pEcdsaData->k.dataLenInBytes = randomD.dataLenInBytes;
    }

    /*7. Q = d.G*/
    multOpData.k.pData = pEcdsaData->d.pData;
    multOpData.k.dataLenInBytes = pEcdsaData->d.dataLenInBytes;
    multOpData.h.pData = NULL;
    multOpData.h.dataLenInBytes = 0;

    FIPS_SAMPLE_ECDSA_ECDSA_SET_ABGxGy(pEcdsaData, (&multOpData));

    multOpData.q.pData = pEcdsaData->PrimeOrPolynomial.pData;
    multOpData.q.dataLenInBytes = pEcdsaData->PrimeOrPolynomial.dataLenInBytes;
    do
    {
        status = cpaCyEcPointMultiply(
            instanceHandle,
            NULL, /*NULL callback function (synchronous exec mode)*/
            NULL, /*NULL callback data*/
            &multOpData,
            &MultiplyStatus,
            &pEcdsaData->xq,
            &pEcdsaData->yq);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);
    if (CPA_STATUS_FAIL == status)
    {
        PRINT_ERR("Point Multiply process fail\n");
        goto finish;
    }

    if (CPA_TRUE != MultiplyStatus)
    {
        PRINT_ERR("Point Multiply output invalid\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        if (CPA_STATUS_SUCCESS !=
            cpaCyGetStatusText(instanceHandle, status, statusErrorString))
        {
            PRINT_ERR("Error retrieving status string.\n");
        }
        PRINT_ERR("Point Multiply Fail -- %s\n", statusErrorString);
        goto finish;
    }
finish:
    osFree(&randomD.pData);
    if (CPA_STATUS_SUCCESS != status)
    {
        (void)memset(pEcdsaData->d.pData, 0, pEcdsaData->d.dataLenInBytes);
        (void)memset(pEcdsaData->xq.pData, 0, pEcdsaData->xq.dataLenInBytes);
        (void)memset(pEcdsaData->yq.pData, 0, pEcdsaData->yq.dataLenInBytes);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      fipsSample_ecdsaKeygen
 *
 * @description
 *      Generates the ECDSA public key Q and private key D from domain
 *      parameters passed in by the calling function. This is done in
 *      accordance with FIPS 186-3 Appendix B.4.1
 *      In the case of an error, D and Q values are set to an invalid value
 *      (zero).
 *
 *      Note: Domain parameter generation method is given in ANS X9.62.
 *      FIPS 186-3 also gives some domain parameters in Appendix D. The
 *      FIPS domain parameters are what is used for CAVP certification
 *      of ECDSA.
 *
 * @param[in,out]  pEcdsaData        Structure containing parameters for
 *                                   ECDSA keygen, result also stored here
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      The domain parameters have been loaded into the pEcdsaData structure.
 *      All input/output buffers/data must be allocated by the caller and
 *      given the correct buffer size.
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_ecdsaKeygen(usr_ecdsa_data_t *pEcdsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkEcdsaData(pEcdsaData, ECDSA_KEYGEN))
    {
        PRINT_ERR("ecdsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    status = ecdsaKeyGen(pEcdsaData, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("EC DSA keygen fail\n");
        goto finish;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      calculateEcdsaEValue
 *
 * @description
 *      Calculate e = H(mesg) and truncate the result if the bit length of
 *      the hash function is greater than the base order bit length.
 *
 * @param[in] pEcdsaData        Structure containing Domain Parameters
 *                              (description in header file):
 *                              Curve, a, b, h, xg, yg, PrimeOrPolynomial,
 *                              OrderOfG
 *                              Private Key D
 *                              Per message secret value: k
 *
 * @param[out] E                SignR and SignS signature values
 * @param[in]  instanceHandle   Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the input and outputs
 * @post
 *      none
 *****************************************************************************/
static CpaStatus calculateEcdsaEValue(usr_ecdsa_data_t *pEcdsaData,
                                      CpaFlatBuffer *E,
                                      const CpaInstanceHandle instanceHandle)
{
    Cpa32U hashLenBits = E->dataLenInBytes * BYTE_SIZE;
    Cpa32U baseOrderValueNumberOfBits = 0;
    Cpa32U nByteOffset = 0, i = 0;

    if (CPA_STATUS_SUCCESS !=
        getEcdsaMesgDigestSetupAndCall(
            &(pEcdsaData->mesg), E, pEcdsaData->hashAlgorithm, instanceHandle))
    {
        PRINT_ERR("Digest Setup and Call Fail \n");
        return CPA_STATUS_FAIL;
    }

    /*If 2^n < 2^hashlen, truncate result to the leftmost 2^n bits*/
    nByteOffset = getOffsetToBufferedData(&(pEcdsaData->OrderOfG));
    baseOrderValueNumberOfBits =
        (pEcdsaData->OrderOfG.dataLenInBytes - nByteOffset) * BYTE_SIZE;
    /*subtract number of zeros at the top of the 'OrderOfG'
      value to get the total number of bits for the base order*/
    for (i = FIPS_SAMPLE_TOP_BIT;
         0 == (i & pEcdsaData->OrderOfG.pData[nByteOffset]);
         i >>= 1)
    {
        baseOrderValueNumberOfBits--;
    }

    if (hashLenBits > baseOrderValueNumberOfBits)
    {
        Cpa8U remainder =
            (hashLenBits - baseOrderValueNumberOfBits) % BYTE_SIZE;
        /*get rid of least significant bytes*/
        E->dataLenInBytes -=
            ((hashLenBits - baseOrderValueNumberOfBits) / BYTE_SIZE);
        /*right shift by remaining bits
          (if remainder is zero, the loop is not executed)*/
        for (i = 0; i < remainder; i++)
        {
            /*function shifts the value by one bit*/
            rightShift(E->pData, E->dataLenInBytes);
        }
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      fipsSample_ecdsaSign
 *
 * @description
 *      Does a ECDSA signature generation as specified in section 7.3 ANSX9.62.
 *
 *      Inputs include the private key D and a per message secret number 'k'
 *      (as specified in FIPS 186-3 Section 6.3). The security strength, hash
 *      function and Key generation domain parameters must also be input.
 *
 * @param[in,out] pEcdsaData    Domain Parameters (description in header file):
 *                              Curve, a, b, h, xg, yg, PrimeOrPolynomial,
 *                              OrderOfG
 *                              Private Key D
 *                              Per message secret value: k
 *                              Message to be signed: mesg
 *
 * @param[out] pEcdsaData       SignR and SignS signature values
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_FAIL           The operation failed
 *
 * @pre
 *      All memory has been allocated for the input and outputs
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_ecdsaSign(usr_ecdsa_data_t *pEcdsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaBoolean signStatus = CPA_TRUE;
    CpaFlatBuffer ecdsaE = {.dataLenInBytes = 0, .pData = NULL};

    CpaCyEcdsaSignRSOpData ecSignData = {
        {0, NULL},            /*xg*/
        {0, NULL},            /*yg*/
        {0, NULL},            /*n*/
        {0, NULL},            /*q*/
        {0, NULL},            /*a*/
        {0, NULL},            /*b*/
        {0, NULL},            /*k*/
        {0, NULL},            /*m*/
        {0, NULL},            /*d*/
        pEcdsaData->fieldType /*fieldType*/
    };

    if (CPA_STATUS_SUCCESS != checkEcdsaData(pEcdsaData, ECDSA_SIGN))
    {
        PRINT_ERR("ecdsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    ecSignData.q.pData = pEcdsaData->PrimeOrPolynomial.pData;
    ecSignData.q.dataLenInBytes = pEcdsaData->PrimeOrPolynomial.dataLenInBytes;

    ecSignData.n.pData = pEcdsaData->OrderOfG.pData;
    ecSignData.n.dataLenInBytes = pEcdsaData->OrderOfG.dataLenInBytes;

    status = getHashBytes(pEcdsaData->hashAlgorithm, &(ecdsaE.dataLenInBytes));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Hash function not supported\n");
        goto finish;
    }

    ecdsaE.pData = osZalloc(ecdsaE.dataLenInBytes, instanceHandle);
    if (NULL == ecdsaE.pData)
    {
        PRINT_ERR("Could not get memory for message hash result\n");
        return CPA_STATUS_FAIL;
    }

    /*1. Compute the hash value e = H(M), len(e) is the smaller of 'n' bits and
         the hash function output length*/
    status = calculateEcdsaEValue(pEcdsaData, &ecdsaE, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Calculate 'e' Fail\n");
        goto finish;
    }

    ecSignData.fieldType = pEcdsaData->fieldType;
    /*'m' for Quick Assist API is 'e' for FIPS and 'E' for ANS X9.62*/
    ecSignData.m.pData = ecdsaE.pData;
    ecSignData.m.dataLenInBytes = ecdsaE.dataLenInBytes;

    FIPS_SAMPLE_ECDSA_ECDSA_SET_ABGxGy(pEcdsaData, (&ecSignData));

    /*Using the private key for the message signature*/
    ecSignData.d.pData = pEcdsaData->d.pData;
    ecSignData.d.dataLenInBytes = pEcdsaData->d.dataLenInBytes;

    ecSignData.k.pData = pEcdsaData->k.pData;
    ecSignData.k.dataLenInBytes = pEcdsaData->k.dataLenInBytes;

    /*2. ecdsa signing scheme as specified in ANS X9.62 7.3*/
    do
    {
        status = cpaCyEcdsaSignRS(
            instanceHandle,
            NULL, /*NULL callback function (synchronous exec mode)*/
            NULL, /*NULL callback data*/
            &ecSignData,
            &signStatus,
            &pEcdsaData->SignR,
            &pEcdsaData->SignS);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Signature generation process fail -- %s\n",
                      statusErrorString);
            goto finish;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);
    if (CPA_STATUS_FAIL == status)
    {
        PRINT_ERR("Signature generation process fail\n");
        goto finish;
    }

    if (CPA_TRUE != signStatus)
    {
        PRINT_ERR("Signature generation algorithm fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*if R == 0 or S == 0, this is a fail condition*/
    if (CPA_TRUE == checkZero(&(pEcdsaData->SignR)))
    {
        PRINT_ERR("Signature generation fail - R is zero\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    if (CPA_TRUE == checkZero(&(pEcdsaData->SignS)))
    {
        PRINT_ERR("Signature generation fail - S is zero\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

finish:
    osFree(&ecdsaE.pData);
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("stop QA instance Fail \n");
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      fipsSample_ecdsaVerify
 *
 * @description
 *      Execute ECDSA verify as specified in section 7.4 ANS X9.62.
 *
 *      Inputs include the public key Q and the security strength, hash
 *      function and Key generation domain parameters must also be input.
 *
 * @param[in,out] pEcdsaData    Domain Parameters (description in header file):
 *                              Curve, a, b, h, xg, yg, PrimeOrPolynomial,
 *                              OrderOfG
 *                              Public Key: xq, yq
 *                              Message that was signed: mesg
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      All memory has been allocated for input and output buffers
 * @post
 *     none
 *****************************************************************************/
CpaStatus fipsSample_ecdsaVerify(usr_ecdsa_data_t *pEcdsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaFlatBuffer ecdsaE = {.dataLenInBytes = 0, .pData = NULL};

    CpaCyEcdsaVerifyOpData ecVerData = {
        {0, NULL},            /*xg*/
        {0, NULL},            /*yg*/
        {0, NULL},            /*n*/
        {0, NULL},            /*q*/
        {0, NULL},            /*a*/
        {0, NULL},            /*b*/
        {0, NULL},            /*m*/
        {0, NULL},            /*r*/
        {0, NULL},            /*s*/
        {0, NULL},            /*xp*/
        {0, NULL},            /*yp*/
        pEcdsaData->fieldType /*fieldType*/
    };

    if (CPA_STATUS_SUCCESS != checkEcdsaData(pEcdsaData, ECDSA_VERIFY))
    {
        PRINT_ERR("ecdsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    ecVerData.xg.pData = pEcdsaData->xg.pData;
    ecVerData.xg.dataLenInBytes = pEcdsaData->xg.dataLenInBytes;
    ecVerData.yg.pData = pEcdsaData->yg.pData;
    ecVerData.yg.dataLenInBytes = pEcdsaData->yg.dataLenInBytes;

    ecVerData.xp.pData = pEcdsaData->xq.pData;
    ecVerData.xp.dataLenInBytes = pEcdsaData->xq.dataLenInBytes;
    ecVerData.yp.pData = pEcdsaData->yq.pData;
    ecVerData.yp.dataLenInBytes = pEcdsaData->yq.dataLenInBytes;

    ecVerData.q.pData = pEcdsaData->PrimeOrPolynomial.pData;
    ecVerData.q.dataLenInBytes = pEcdsaData->PrimeOrPolynomial.dataLenInBytes;

    ecVerData.n.pData = pEcdsaData->OrderOfG.pData;
    ecVerData.n.dataLenInBytes = pEcdsaData->OrderOfG.dataLenInBytes;

    displayHexArrayFB("R = ", &(pEcdsaData->SignR));
    displayHexArrayFB("S = ", &(pEcdsaData->SignS));
    displayHexArrayFB("N = ", &(pEcdsaData->OrderOfG));
    displayHexArrayFB("P = ", &(pEcdsaData->PrimeOrPolynomial));
    displayHexArrayFB("a = ", &(pEcdsaData->a));
    displayHexArrayFB("b = ", &(pEcdsaData->b));
    displayHexArrayFB("h = ", &(pEcdsaData->h));
    displayHexArrayFB("xq = ", &(pEcdsaData->xq));
    displayHexArrayFB("yq = ", &(pEcdsaData->yq));
    status = getHashBytes(pEcdsaData->hashAlgorithm, &(ecdsaE.dataLenInBytes));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Hash function not supported\n");
        goto finish;
    }

    ecdsaE.pData = osZalloc(ecdsaE.dataLenInBytes, instanceHandle);
    if (NULL == ecdsaE.pData)
    {
        PRINT_ERR("Could not get memory for message hash result\n");
        return CPA_STATUS_FAIL;
    }
    /*1. Compute the hash value e = H(M), len(e) is the smaller of 'n' bits and
         the hash function output length*/
    status = calculateEcdsaEValue(pEcdsaData, &ecdsaE, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Calculate 'e' Fail\n");
        goto finish;
    }

    ecVerData.fieldType = pEcdsaData->fieldType;
    /*'m' for Quick Assist API is 'e' for FIPS and 'E' for ANS X9.62*/
    ecVerData.m.pData = ecdsaE.pData;
    ecVerData.m.dataLenInBytes = ecdsaE.dataLenInBytes;

    FIPS_SAMPLE_ECDSA_ECDSA_SET_ABGxGy(pEcdsaData, (&ecVerData));

    ecVerData.r.pData = pEcdsaData->SignR.pData;
    ecVerData.r.dataLenInBytes = pEcdsaData->SignR.dataLenInBytes;
    ecVerData.s.pData = pEcdsaData->SignS.pData;
    ecVerData.s.dataLenInBytes = pEcdsaData->SignS.dataLenInBytes;

    do
    {
        /*2. ecdsa signing scheme as specified in ANS X9.62 7.4
             All steps are done apart from the generation of 'e'*/
        status = cpaCyEcdsaVerify(
            instanceHandle,
            NULL, /*NULL callback function (synchronous exec mode)*/
            NULL, /*NULL callback data*/
            &ecVerData,
            &pEcdsaData->verifyStatus);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("cpaCyEcdsaVerify Process FAIL -- %s\n",
                      statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);
    if (CPA_STATUS_FAIL == status)
    {
        PRINT_ERR("cpaCyEcdsaVerify process fail\n");
        goto finish;
    }

    if (CPA_TRUE != pEcdsaData->verifyStatus)
    {
        PRINT_DBG("Signature Invalid\n");
        /*validation process completed successfully*/
        status = CPA_STATUS_SUCCESS;
    }
    else
    {
        PRINT_DBG("Signature Valid\n");
        status = CPA_STATUS_SUCCESS;
    }

finish:
    osFree(&ecdsaE.pData);
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("stop QA instance Fail \n");
    }
    return status;
}
