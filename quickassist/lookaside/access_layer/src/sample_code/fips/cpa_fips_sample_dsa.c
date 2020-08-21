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
 * @file cpa_fips_sample_dsa.c
 *
 * @ingroup fipsSampleDsa
 *
 * @description
 *      This file contains function definitions for FIPS 186-3 compliant
 *      operations for the DSA algorithm. Functions implemented are
 *      Domain Parameter Generation, Domain Parameter Validation,
 *      Key Generation, Signature Generation and Signature Verification.
 *****************************************************************************/

#include "cpa_fips_sample.h"

#include "cpa_fips_sample_utils.h"
#include "cpa_fips_sample_dsa.h"

#include "cpa_fips_sample_aes_gcm.h"

/**
 ******************************************************************************
 * @ingroup fipsSampleCodeDsa
 *      EXPORT_SYMBOLs
 *
 * Functions which are exported for the kernel module interface
 *****************************************************************************/
#ifdef KERNEL_SPACE
EXPORT_SYMBOL(fipsSample_dsaPQgen);
EXPORT_SYMBOL(fipsSample_dsaGgen);
EXPORT_SYMBOL(fipsSample_dsaPQver);
EXPORT_SYMBOL(fipsSample_dsaGver);
EXPORT_SYMBOL(fipsSample_dsaKeyGen);
EXPORT_SYMBOL(fipsSample_dsaSign);
EXPORT_SYMBOL(fipsSample_dsaVerify);
#endif /*KERNEL_SPACE*/

static CpaStatus dsaVerCpa(usr_dsa_data_t *pDsaData,
                           const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      checkDsaData
 *
 * @description
 *      Check that the buffers and initial values for either domain parameter
 *      (P,Q,G) generation, Public/Private Key generation, Sign or Verify
 *      operation are correct
 *
 * @param[in] pDsaData          Structure containing the input parameters
 *                              and output buffers.
 * @param[in] dsaOp             enum describing which operation to check for
 *                              (Domain parameter generation/verification,
 *                              Key Generation, Sign/Verify operations)
 *
 * @retval CPA_STATUS_SUCCESS   Values of pDsaData to be used in the dsaOp
 *                              specified operation are correct.
 * @retval CPA_STATUS_FAIL      Values of pDsaData are not correct
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus checkDsaData(const usr_dsa_data_t *restrict pDsaData,
                              dsa_operation_t dsaOp)
{

    /*Common*/
    if (NULL == pDsaData)
    {
        PRINT_ERR("Dsa Data is NULL \n");
        return CPA_STATUS_FAIL;
    }

    /*Per Operation*/
    if (DSA_SIGN == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaX = ", &pDsaData->dsaX));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaK = ", &pDsaData->dsaK));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("dsaMsg = ", &pDsaData->dsaMsg));
    }
    else if (DSA_VERIFY == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaY = ", &pDsaData->dsaY));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaR = ", &pDsaData->dsaR));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaS = ", &pDsaData->dsaS));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("dsaMsg = ", &pDsaData->dsaMsg));
    }
    else if (DSA_KEYGEN == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaX = ", &pDsaData->dsaX));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaY = ", &pDsaData->dsaY));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaP = ", &pDsaData->dsaP));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaQ = ", &pDsaData->dsaQ));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaG = ", &pDsaData->dsaG));
    }
    else if (DSA_PQGEN == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaP = ", &pDsaData->dsaP));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaQ = ", &pDsaData->dsaQ));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaG = ", &pDsaData->dsaG));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("dsaSeed = ", &pDsaData->dsaSeed));
    }
    else if (DSA_GGEN == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaP = ", &pDsaData->dsaP));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaQ = ", &pDsaData->dsaQ));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaG = ", &pDsaData->dsaG));
    }
    else if (DSA_PQVER == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaP = ", &pDsaData->dsaP));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaQ = ", &pDsaData->dsaQ));
        RETURN_IF_CPA_STATUS_FAIL(
            checkFlatBuffer("dsaSeed = ", &pDsaData->dsaSeed));
        if (0 == pDsaData->dsaC)
        {
            PRINT_ERR("P generation count is zero\n");
        }
    }
    else if (DSA_GVER == dsaOp)
    {
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaP = ", &pDsaData->dsaP));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaQ = ", &pDsaData->dsaQ));
        RETURN_IF_CPA_STATUS_FAIL(checkFlatBuffer("dsaG = ", &pDsaData->dsaG));
    }
    else
    {
        PRINT_ERR("DSA operation not supported.\n");
    }

    if (CPA_TRUE == pDsaData->resultVerified)
    {
        PRINT_DBG("pDsaData resultVerified is set to CPA_TRUE\n");
    }
    else
    {
        PRINT_DBG("pDsaData resultVerified is set to CPA_FALSE\n");
    }
    PRINT_DBG("DSA modulus is %u\n", pDsaData->dsaL);
    switch (pDsaData->shaAlg)
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
            PRINT_DBG("ERROR - SHA operation supported\n");
            return CPA_STATUS_FAIL;
            break;
    }
    PRINT_DBG("DSA C is %u\n", pDsaData->dsaC);

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      getDsaHash
 *
 * @description
 *      Calculate the message Hash based on pDsaData input values and the
 *      message buffer. If the mesgDigest pointer is NULL, the result is
 *      stored in 'mesg' buffer.
 *
 * @param[in]  pDsaData         Structure containing the input parameters
 *                              and output buffers.
 * @param[in]  pMesg            message to be hashed
 * @param[in]  digestResultLen  Amount of bytes required from the digest
 *                              operation
 * @param[out] pMesgDigest      hash result is stored here. If this value
 *                              is NULL, the result will be stored in the
 *                              buffer associated with the pMesg parameter
 * @param[in] instanceHandle    Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      Buffer to store the digest result must be large enough for that.
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus getDsaHash(const usr_dsa_data_t *restrict pDsaData,
                            CpaFlatBuffer *pMesg,
                            CpaFlatBuffer *pMesgDigest,
                            Cpa32U digestResultLen,
                            const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /*Set input data */
    CpaCySymSessionSetupData sessionSetupData = {
        .sessionPriority = CPA_CY_PRIORITY_NORMAL,
        .symOperation = CPA_CY_SYM_OP_HASH,
        .cipherSetupData =
            {
                0,
            }, /*not used*/
        .hashSetupData = {.hashAlgorithm = pDsaData->shaAlg,
                          .hashMode = CPA_CY_SYM_HASH_MODE_PLAIN,
                          .digestResultLenInBytes = digestResultLen,
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

    status =
        getMesgDigest(pMesg, pMesgDigest, &sessionSetupData, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Mesg Digest Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      checkLN
 *
 * @description
 *      Check L and N are correct in accordance with FIPS 186-3 section 4.2.
 *      And calculate required DRBG security strength based on Table 2 of NIST
 *      PUB SP800-57 part 1 rev 3.
 *      Acceleration devices that use an internal DRBG provide 256 bit security
 *      strength whereas those that rely on the external Intel Secure Key
 *      Technology (i.e. RDRAND) provide 128 bits.
 *
 * @param[in]  L                L value as seen in part 4.2
 * @param[in]  N                N value as seen in part 4.2
 * @param[out] secStrength      Security strength needed for DRNG
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus checkLN(Cpa32U L, Cpa32U N, Cpa32U *secStrength)
{
    switch (L)
    {
        case FIPS_DSA_L_SIZE_1024:
            if (FIPS_DSA_N_SIZE_160 != N)
            {
                PRINT_ERR("'N' value (%u) not valid for keysize %u\n",
                          N,
                          FIPS_DSA_L_SIZE_1024);
                return CPA_STATUS_FAIL;
            }
            *secStrength = CPA_CY_RBG_SEC_STRENGTH_112; /* Only need 80 bits */
            break;
        case FIPS_DSA_L_SIZE_2048:
            if ((FIPS_DSA_N_SIZE_224 != N) && (FIPS_DSA_N_SIZE_256 != N))
            {
                PRINT_ERR("'N' value (%u) not valid for keysize %u\n",
                          N,
                          FIPS_DSA_L_SIZE_2048);
                return CPA_STATUS_FAIL;
            }
            if (FIPS_DSA_N_SIZE_224 == N)
                *secStrength = CPA_CY_RBG_SEC_STRENGTH_112; /* Need 112 bits */
            if (FIPS_DSA_N_SIZE_256 == N)
                *secStrength =
                    CPA_CY_RBG_SEC_STRENGTH_128; /* Assuming 128 bits */
            break;
        case FIPS_DSA_L_SIZE_3072:
            if (FIPS_DSA_N_SIZE_256 != N)
            {
                PRINT_ERR("'N' value (%u) not valid for keysize %u\n",
                          N,
                          FIPS_DSA_L_SIZE_3072);
                return CPA_STATUS_FAIL;
            }
            *secStrength = CPA_CY_RBG_SEC_STRENGTH_128; /* Need 128 bits */
            break;
        default:
            PRINT_ERR("'L' value (%u) invalid\n", L);
            return CPA_STATUS_FAIL;
            break;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      checkPorQPrimalityFipsC1
 *
 * @description
 *      Check P or Q value for primeness based on FIPS 186-3 appendix C.3,
 *      table C.1
 *
 * @param[in]  pDsaData          Structure giving the operation N and L values
 * @param[in]  pCandidate        Prime Candidate for checking
 * @param[in]  primeCheckType    Is a P or Q value being checked
 * @param[out] pIsPrime          Set to true if the value being checked is
 *                               found to be prime
 * @param[in]  instanceHandle    Quick Assist API instance handle
 * @param[in]  securityStrength         Required DRNG security strength for (L,
 *N)
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
static CpaStatus
checkPorQPrimalityFipsC1(const usr_dsa_data_t *restrict pDsaData,
                         const CpaFlatBuffer *restrict pCandidate,
                         dsa_prime_check_type_t primeCheckType,
                         CpaBoolean *pIsPrime,
                         const CpaInstanceHandle instanceHandle,
                         Cpa32U securityStrength)
{
    Cpa32U numMillerRabin = 0;
    *pIsPrime = CPA_FALSE;

    switch (pDsaData->dsaL)
    {
        case FIPS_DSA_L_SIZE_1024:
            if (FIPS_DSA_PRIME_Q == primeCheckType)
            {
                numMillerRabin = FIPS_DSA_MILLER_RABIN_1024_160_Q;
            }
            else
            {
                numMillerRabin = FIPS_DSA_MILLER_RABIN_1024_160_P;
            }
            break;
        case FIPS_DSA_L_SIZE_2048:
            if (FIPS_DSA_PRIME_Q == primeCheckType)
            {
                if (FIPS_DSA_N_SIZE_224 == pDsaData->dsaN)
                {
                    numMillerRabin = FIPS_DSA_MILLER_RABIN_2048_224_Q;
                }
                else
                {
                    numMillerRabin = FIPS_DSA_MILLER_RABIN_2048_256_Q;
                }
            }
            else
            {
                numMillerRabin = FIPS_DSA_MILLER_RABIN_2048_P;
            }
            break;
        case FIPS_DSA_L_SIZE_3072:
            if (FIPS_DSA_PRIME_Q == primeCheckType)
            {
                numMillerRabin = FIPS_DSA_MILLER_RABIN_3072_256_Q;
            }
            else
            {
                numMillerRabin = FIPS_DSA_MILLER_RABIN_3072_256_P;
            }
            break;
        default:
            PRINT_ERR("'L' value (%u) invalid\n", pDsaData->dsaL);
            return CPA_STATUS_FAIL;
            break;
    }

    if (CPA_STATUS_SUCCESS != checkPrimality(pCandidate,
                                             numMillerRabin,
                                             CPA_TRUE, /*Perform 1 Lucas test*/
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
 * @ingroup fipsSampleDsa
 *      generateQ
 *
 * @description
 *      Implementation of FIPS 186-3 section A.1.1.2, parts 5 to 9
 *
 * @param[in,out] pDsaData      Structure containing the following values:
 *                              dsaQ - result prime value
 *                              dsaSeed - value used to generate Q
 * @param[in] seedLenBytes      Required Seed Length
 * @param[in] outLenBytes       Hash output length
 * @param[in] instanceHandle    Quick Assist API instance handle
 * @param[in] securityStrength  Required DRNG security strength for (L, N)
 *
 * @retval CPA_STATUS_SUCCESS   Q has been generated successfully
 * @retval CPA_STATUS_FAIL      The operation failed, or the domain
 *                              parameters were invalid
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus generateQ(usr_dsa_data_t *pDsaData,
                           Cpa32U seedLenBytes,
                           Cpa32U outLenBytes,
                           const CpaInstanceHandle instanceHandle,
                           Cpa32U securityStrength)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus primeGenStatus = CPA_STATUS_FAIL;
    CpaBoolean isPrime = CPA_FALSE;
    Cpa32U qCounter = 0;
    CpaFlatBuffer nModulus = {.dataLenInBytes = (pDsaData->dsaN / BYTE_SIZE),
                              .pData = NULL};
    CpaFlatBuffer modulusTarget = {
        .dataLenInBytes = (pDsaData->dsaN / BYTE_SIZE), .pData = NULL};
    CpaFlatBuffer localSeedValue = {.dataLenInBytes = seedLenBytes,
                                    .pData = NULL};

    CpaFlatBuffer localHashValue = {.dataLenInBytes = outLenBytes,
                                    .pData = NULL};

    /*allocate a local seed value to be used in verifying Q*/
    localSeedValue.dataLenInBytes = seedLenBytes;
    localSeedValue.pData =
        osZalloc(localSeedValue.dataLenInBytes +   /*Hash function result*/
                     nModulus.dataLenInBytes +     /*base value of modulus*/
                     modulusTarget.dataLenInBytes, /*Modulus result value*/
                 instanceHandle);
    if (NULL == localSeedValue.pData)
    {
        PRINT_ERR("Seed alloc Fail \n");
        return CPA_STATUS_FAIL;
    }

    localHashValue.pData =
        osZalloc(localHashValue.dataLenInBytes, instanceHandle);
    if (NULL == localHashValue.pData)
    {
        PRINT_ERR("Hash alloc Fail \n");
        return CPA_STATUS_FAIL;
    }

    nModulus.pData = localSeedValue.pData + localSeedValue.dataLenInBytes;
    modulusTarget.pData =
        localSeedValue.pData +
        (localSeedValue.dataLenInBytes + nModulus.dataLenInBytes);

    /*Calculate 2^(N -1) for Hash result truncation*/
    /*Assume the value of N is always a multiple of BYTE_SIZE*/
    nModulus.pData[0] |= FIPS_SAMPLE_TOP_BIT;

    for (qCounter = 0; qCounter < FIPS_DSA_MAX_Q_TRIES; qCounter++)
    {
        /*Arbitrary set of bits is only required here,
                 but use max sec strength anyway*/
        status = generateRandomBytes(
            &localSeedValue, seedLenBytes, securityStrength, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Get DSA Seed value Fail \n");
            goto finish;
        }

        /*Store domain parameter 'seed'*/
        (void)memcpy(
            pDsaData->dsaSeed.pData, localSeedValue.pData, seedLenBytes);
        pDsaData->dsaSeed.dataLenInBytes = seedLenBytes;

        /*A.1.1.2 part 6*/
        status = getDsaHash(pDsaData,
                            &localSeedValue,
                            &localHashValue,
                            outLenBytes,
                            instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("GetDsaHash Fail (seedLen = %u)\n", seedLenBytes);
            goto finish;
        }

        /*get result mod(2^N-1) -- this gives the 'U' value*/
        status = doModExp(
            &localHashValue, NULL, &nModulus, &modulusTarget, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Generate Q prime candidate (mod exp) Fail \n");
            goto finish;
        }

        /*A.1.1.2 part 7 - set bit at 2^(N -1) and 2^(0)*/
        modulusTarget.pData[0] |= nModulus.pData[0];
        /*A.1.1.2 part 7, xor(U, 0x01) ==  1 - ( U mod 2).*/
        modulusTarget.pData[modulusTarget.dataLenInBytes - 1] |= 0x01;

        /*A.1.1.2 part 8*/
        /*Check primality of Q*/
        status = checkPorQPrimalityFipsC1(pDsaData,
                                          &modulusTarget,
                                          FIPS_DSA_PRIME_Q,
                                          &isPrime,
                                          instanceHandle,
                                          securityStrength);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Q primality check Fail \n");
            goto finish;
        }
        if (CPA_TRUE == isPrime)
        {
            primeGenStatus = CPA_STATUS_SUCCESS;
            break;
        }
        /*if not prime, return to step 5*/
    }
/*END A.1.1.2 part 5 to 9*/
finish:
    osFree(&localSeedValue.pData);
    if (CPA_STATUS_SUCCESS == primeGenStatus)
    {
        (void)memcpy(pDsaData->dsaQ.pData,
                     modulusTarget.pData,
                     pDsaData->dsaQ.dataLenInBytes);
    }
    else
    {
        PRINT_ERR("Prime generation Fail, possibly breaking from"
                  " A.1.1.2 specified infinit loop");
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      generatePfromQ
 *
 * @description
 *      This function is used to generate a prime 'P' value from a smaller
 *      prime 'Q' value. It is an implementation of FIPS 186-3 section A.1.1.2,
 *      parts 11.1 to 11.5. This code is also equivalent to section A.1.1.3,
 *      parts 13.1 to 13.5 (for validating P and Q values).
 *      This function also does A.1.1.2 part 4 as the variable calculated
 *      is only used here.
 *
 * @param[in]  pDsaData          Parameters for generating P
 * @param[out] pTargetP          Calculation result is stored here
 * @param[in]  seedLenBytes      Prime generation seed length
 * @param[in]  outLenBytes       Hash output length
 * @param[in]  offset            Current value for 'offset', a value used to
 *                               update the Hash of the domain parameter seed
 *                               for each generation attempt
 * @param[in]  n                 Value calculated in A.1.1.2, part 3
 * @param[out] pPrimePGenerated  Boolean value set to CPA_TRUE if the
 *                               generated P value passes the robust prime
 *                               test
 * @param[in] instanceHandle     Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      All buffers allocated, instanceHandle has been initialized
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus generatePfromQ(usr_dsa_data_t *pDsaData,
                                CpaFlatBuffer *pTargetP,
                                Cpa32U seedLenBytes,
                                Cpa32U outLenBytes,
                                Cpa32U offset,
                                Cpa32U n,
                                CpaBoolean *pPrimePGenerated,
                                const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    Cpa32U b = 0, j = 0;
    Cpa32U bitLengthOfL = 0, bitLengthOfN = 0;
    Cpa32U xMsb = 0, calcTopByte = 0;
    Cpa8U *pWDataPointer = NULL;

    CpaFlatBuffer resultVn = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer seedModulus = {.dataLenInBytes = seedLenBytes + 1,
                                 .pData = NULL};
    CpaFlatBuffer bModulus = {/*calculate the buffer length later*/
                              .dataLenInBytes = 0,
                              .pData = NULL};
    CpaFlatBuffer modulusTarget = {.dataLenInBytes = seedLenBytes + 1,
                                   .pData = NULL};
    /*Temporary buffer used in 'W' calculation (A.1.1.2, part 11)*/
    CpaFlatBuffer tmpBuf = {.dataLenInBytes = 0, .pData = NULL};

    CpaFlatBuffer localHashValue = {.dataLenInBytes = outLenBytes,
                                    .pData = NULL};
    CpaFlatBuffer lastValue = {.dataLenInBytes = outLenBytes + 1,
                               .pData = NULL};

    CpaCyDsaPParamGenOpData dsaPParamGenOpData = {
        .X = {.dataLenInBytes = 0, .pData = NULL},
        .Q = {.dataLenInBytes = 0, .pData = NULL}};
    /*Prime variables*/
    CpaFlatBuffer W = {/*Len W = outLenBytes * (n + 1)*/
                       .dataLenInBytes = (outLenBytes) * (n + 1),
                       .pData = NULL};
    CpaFlatBuffer X = {.dataLenInBytes = W.dataLenInBytes, .pData = NULL};
    CpaBoolean protocolStatus = CPA_FALSE;

    /* This is calculated later by checkLN() based on L & N */
    Cpa32U securityStrength;

    /*P not generated is the default case*/
    *pPrimePGenerated = CPA_FALSE;

    bitLengthOfL = pDsaData->dsaL;
    bitLengthOfN = pDsaData->dsaN;

    /*B.1.1 part 2. Check valid L, N values*/
    status = checkLN(bitLengthOfL, bitLengthOfN, &securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("L or N value invalid\n");
        goto finish;
    }
    PRINT_DBG("Using security strength of %d\n", (int)securityStrength);

    /*A.1.1.2 part 4. calculate small 'b' value*/
    b = bitLengthOfL - 1 - (n * (outLenBytes * BYTE_SIZE));

    W.pData = osZalloc(W.dataLenInBytes, instanceHandle);
    if (NULL == W.pData)
    {
        PRINT_ERR("W alloc Fail \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    /*move pointer to last block of 'outlenBytes'*/
    pWDataPointer = W.pData + (W.dataLenInBytes - outLenBytes);

    /*allocate the temporary buffers used in calculating W
       -- Need addition result, ModExp result, second ModExp result.
          result buffers need extra space for overflow (seedlen + 1)
    */
    tmpBuf.dataLenInBytes =
        (seedLenBytes + 1) * (FIPS_DSA_W_CALC_NUM_TMP_BUFFERS_REQUIRED - 1) +
        /*bytes for the final mod exp operation*/
        ((b / BYTE_SIZE) + 1);
    tmpBuf.pData = osZalloc(tmpBuf.dataLenInBytes, instanceHandle);
    if (NULL == tmpBuf.pData)
    {
        PRINT_ERR("W tmpBuf alloc Fail \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    /*buff size to be used in calculations*/
    tmpBuf.dataLenInBytes = seedLenBytes;

    localHashValue.pData =
        osZalloc(localHashValue.dataLenInBytes, instanceHandle);
    if (NULL == localHashValue.pData)
    {
        PRINT_ERR("Hash alloc Fail \n");
        return CPA_STATUS_FAIL;
    }
    lastValue.pData = osZalloc(lastValue.dataLenInBytes, instanceHandle);
    if (NULL == lastValue.pData)
    {
        PRINT_ERR("lastValue alloc Fail \n");
        return CPA_STATUS_FAIL;
    }

    /*if outLen < seedlen, there are some overflow
                                        calculations to be done*/
    if (outLenBytes > seedLenBytes)
    {
        PRINT_DBG("'outlen' (%u) greater then 'seedlen' (%u)\n",
                  outLenBytes,
                  seedLenBytes);
    }

    /*Buffer for setting the modulus base*/
    seedModulus.pData =
        tmpBuf.pData + (seedLenBytes + 1) * FIPS_DSA_SEED_MODULUS_BUFFER_OFFSET;
    /*Set Seed Modulus LSB*/

    // seedModulus.pData[seedModulus.dataLenInBytes - 1] = 1;
    seedModulus.pData[0] = 1;

    /*Buffer for setting the modulus result*/
    modulusTarget.pData =
        tmpBuf.pData +
        (seedLenBytes + 1) * FIPS_DSA_MODULUS_TARGET_BUFFER_OFFSET;

    /*Buffer for the final modulus operation (using 'b' value)*/
    bModulus.pData =
        tmpBuf.pData + ((seedLenBytes + 1) * FIPS_DSA_B_BUFFER_OFFSET);
    bModulus.dataLenInBytes = b / BYTE_SIZE + 1;

    /*calculate 2^b for the final Vn calculation*/
    bModulus.pData[0] = 1;
    bModulus.pData[0] <<= (b % BYTE_SIZE);

    displayHexArray(
        "seedModulus", seedModulus.pData, seedModulus.dataLenInBytes);
    displayHexArray("bModulus", bModulus.pData, bModulus.dataLenInBytes);

    /*A.1.1.2 part 11 (Corresponds to part 13 of A.1.1.3)*/
    for (j = 0; j <= n; j++)
    {
        /*A.1.1.2 part 11.1*/
        (void)memset(tmpBuf.pData, 0, tmpBuf.dataLenInBytes);
        /*add increment*/
        status =
            incrementFlatBuffer32U(&tmpBuf, &pDsaData->dsaSeed, offset + j);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error incrementing Flat Buffer\n");
            goto finish;
        }
// displayHexArray("tmpBuf", tmpBuf.pData, tmpBuf.dataLenInBytes);
        status = doModExp(
            &tmpBuf, NULL, &seedModulus, &modulusTarget, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Generate V%u (mod exp) Fail \n", j);
            goto finish;
        }
        resultVn.pData = modulusTarget.pData + 1;
        resultVn.dataLenInBytes = modulusTarget.dataLenInBytes - 1;
        // displayHexArray(" modulusTarget",  modulusTarget.pData,
        // modulusTarget.dataLenInBytes);
        // displayHexArray("resultVn", resultVn.pData, resultVn.dataLenInBytes);

        status = getDsaHash(
            pDsaData, &resultVn, &localHashValue, outLenBytes, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error getting Hash value \n");
            goto finish;
        }
        // displayHexArray("localHashValue1", localHashValue.pData,
        // localHashValue.dataLenInBytes);

        resultVn.pData = localHashValue.pData;
        resultVn.dataLenInBytes = outLenBytes;

        /*If calculating the last part of the 'W' variable,
             do a second modulus on the result (mod b)*/
        if (j == n)
        {
            status = doModExp(&localHashValue,
                              /*&tmpBuf,*/ NULL,
                              &bModulus,
                              &lastValue, //&modulusTarget,
                              instanceHandle);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Generate V%u (mod exp) Fail \n", j);
                goto finish;
            }

            resultVn.pData = lastValue.pData; // modulusTarget.pData;
            resultVn.dataLenInBytes =
                lastValue.dataLenInBytes; // modulusTarget.dataLenInBytes;
            displayHexArray(
                "resultVn last", resultVn.pData, resultVn.dataLenInBytes);
            /*target buffer is larger than seedlen*/
            for (; (0 == *(resultVn.pData)) &&
                   (resultVn.dataLenInBytes > outLenBytes);
                 resultVn.dataLenInBytes--)
            {
                resultVn.pData++;
            }
            if (resultVn.dataLenInBytes != outLenBytes)
            {
                PRINT_ERR("P generation process error\n");
                status = CPA_STATUS_FAIL;
                goto finish;
            }
        }
        /*A.1.1.2 part 11.2*/
        /*No overlap, just copy bytes to W*/
        (void)memcpy(
            pWDataPointer - (outLenBytes * j), resultVn.pData, outLenBytes);
    }

    /*A.1.1.2 part 11.3 (Add 2^(L - 1)) == 2^(n * outlen + b)*/
    /*have W, calculate the 'X' value*/
    /*NB: the top part of the 'W' buffer is filled with zero at the moment.
          need to have the most significant byte of the value a the top of
          the buffer before passing the value to the Quick Assist API.*/
    X.pData = W.pData;
    X.dataLenInBytes = W.dataLenInBytes;

    calcTopByte = n * outLenBytes;
    calcTopByte += b / BYTE_SIZE;

    /*Move X data pointer so MSB value is the top byte of the buffer*/
    xMsb = X.dataLenInBytes - (calcTopByte + 1);
    X.pData += xMsb;
    X.dataLenInBytes -= xMsb;

    /*X = W + 2^(L - 1)*/
    X.pData[0] |= (1 << (b % BYTE_SIZE));

    dsaPParamGenOpData.X.pData = X.pData;
    dsaPParamGenOpData.X.dataLenInBytes = X.dataLenInBytes;
    dsaPParamGenOpData.Q.pData = pDsaData->dsaQ.pData;
    dsaPParamGenOpData.Q.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes;

    dsaPParamGenOpData.Q.pData[0] |= (0x80);
    dsaPParamGenOpData.Q.pData[pDsaData->dsaQ.dataLenInBytes - 1] |= (0x01);
    do
    {
        /*A.1.1.2 11.4, 11.5*/
        status =
            cpaCyDsaGenPParam(instanceHandle,
                              NULL, /*callback function not required*/
                              NULL, /*opaque data not required*/
                              &dsaPParamGenOpData,
                              &protocolStatus,
                              /*A.1.1.2 11.6  - note: length is already set*/
                              pTargetP);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("P calc function FAIL -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if ((CPA_FALSE == protocolStatus) || (CPA_STATUS_SUCCESS != status))
    {
        /*A.1.1.2 part 11.6 --  if not prime or P < 2^(L-1), goto step 11.9*/
        PRINT_ERR("P robust prime check Fail \n");
        goto finish;
    }
    /*A.1.1.2 11.7, Check primality of P*/
    status = checkPorQPrimalityFipsC1(pDsaData,
                                      pTargetP,
                                      FIPS_DSA_PRIME_P,
                                      pPrimePGenerated,
                                      instanceHandle,
                                      securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("P primality check Fail \n");
        goto finish;
    }

finish:
    osFree(&W.pData);
    osFree(&tmpBuf.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      generateQP
 *
 * @description
 *      Generate P and Q domain parameters. This conforms to FIPS 186-3
 *      Section A.1.1.2. If the 'validateParams' boolean is set, this function
 *      validates the domain parameters (FIPS 186-3 Section A.1.1.3)
 *
 * @param[in,out] pDsaData       Structure containing values used for
 *                               generating P/Q primes and buffers for storing
 *                               dsaP, dsaQ, dsaC and dsaSeed.
 * @param[in]  validateParams    Validate the P and Q parameters instead of
 *                               generating them (i.e. execute A.1.1.3
 *                               algorithm instead of A.1.1.2).
 * @param[in] instanceHandle     Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded, or the domain
 *                                   parameters were valid
 * @retval CPA_STATUS_FAIL           The operation failed
 * @retval CPA_STATUS_INVALID_PARAM  The calculated P, Q or C
 *                                   parameters were invalid (for A.1.1.3)
 *
 * @pre
 *      pDsaData.dsaSeed.dataLenInBytes must be set by the calling
 *      function (this is equivalent to seedlen input value given in the
 *      standard).
 * @post
 *      none
 *****************************************************************************/
static CpaStatus generateQP(usr_dsa_data_t *pDsaData,
                            CpaBoolean validateParams,
                            const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /*offset is an incremented value used in the standard to change the result
      of the Hash operation when generating prime value P*/
    Cpa32U bitLengthOfL = pDsaData->dsaL, bitLengthOfN = pDsaData->dsaN,
           offset = 0, seedLenBytes = 0, qCounter = 0, outLenBytes = 0, n = 0,
           generationAttempts = 0;
    /*Counter value for P generation/validation*/
    Cpa32U counter = (CPA_TRUE == validateParams)
                         ? pDsaData->dsaC
                         : (FIPS_DSA_COUNTER_MULTIPLIER * pDsaData->dsaL) - 1;
    CpaBoolean primePGenerated = CPA_FALSE;

    CpaFlatBuffer localSeedValue = {.dataLenInBytes = 0, .pData = NULL};
    CpaFlatBuffer localPValue = {.dataLenInBytes = 0, .pData = NULL};

    /* This is calculated later by checkLN() based on L & N */
    Cpa32U securityStrength;

    if ((pDsaData->dsaL / BYTE_SIZE) > pDsaData->dsaP.dataLenInBytes)
    {
        PRINT_ERR("P buffer byte size too small:\n"
                  "P = (%u),\n"
                  "L value = (%u) bits\n",
                  pDsaData->dsaP.dataLenInBytes,
                  pDsaData->dsaL);
        return CPA_STATUS_FAIL;
    }
    else
    {
        localPValue.dataLenInBytes = (pDsaData->dsaL / BYTE_SIZE);
        /*truncate buffer size to output P size*/
        pDsaData->dsaP.dataLenInBytes = (pDsaData->dsaL / BYTE_SIZE);
    }

    if ((pDsaData->dsaN / BYTE_SIZE) > pDsaData->dsaQ.dataLenInBytes)
    {
        PRINT_ERR("Q buffer size (%u) less than required size (%u)\n",
                  pDsaData->dsaQ.dataLenInBytes,
                  pDsaData->dsaN / BYTE_SIZE);
        return CPA_STATUS_FAIL;
    }
    else
    {
        pDsaData->dsaQ.dataLenInBytes = (pDsaData->dsaN / BYTE_SIZE);
    }

    if (0 == pDsaData->dsaSeed.dataLenInBytes)
    {
        PRINT_ERR("Seed Length not set\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    seedLenBytes = pDsaData->dsaSeed.dataLenInBytes;

    if (CPA_TRUE == validateParams)
    {
        PRINT_DBG("Validating P, Q\n");
        localSeedValue.dataLenInBytes = seedLenBytes;
        localPValue.pData =
            osZalloc(localPValue.dataLenInBytes + localSeedValue.dataLenInBytes,
                     instanceHandle);
        if (NULL == localPValue.pData)
        {
            PRINT_ERR("Could not allocate buffers for P,Q validation\n");
            return CPA_STATUS_FAIL;
        }

        localSeedValue.pData = localPValue.pData + localPValue.dataLenInBytes;
    }
    else
    {
        localPValue.pData = pDsaData->dsaP.pData;
    }

    /*seedLen is the length of the random number used to
      generate P and Q. It must be greater than or equal
      to the value of N*/
    if (seedLenBytes < (pDsaData->dsaN / BYTE_SIZE))
    {
        PRINT_ERR("'seedlen' (%u) is less than 'N' (%u)\n",
                  seedLenBytes,
                  (pDsaData->dsaN / BYTE_SIZE));
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*outlen is the length of the output of the HASH function
      It must be greater than or equal to the value of N*/
    status = getHashBytes(pDsaData->shaAlg, &outLenBytes);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Hash output length\n");
        goto finish;
    }
    PRINT_DBG("'outlen' value is %u\n", outLenBytes);
    PRINT_DBG("L value is %u\n", pDsaData->dsaL);
    PRINT_DBG("N value is %u\n", pDsaData->dsaN);

    /*A.1.1.2 part 1. Check the L, N pair is acceptable*/
    status = checkLN(pDsaData->dsaL, pDsaData->dsaN, &securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("L or N value invalid\n");
        goto finish;
    }
    PRINT_DBG("Using security strength of %d\n", (int)securityStrength);

    /*A.1.1.3 difference, part 4 - check counter is less than (4L -1)*/
    if (CPA_TRUE == validateParams)
    {
        if (((pDsaData->dsaL * FIPS_DSA_COUNTER_MULTIPLIER) - 1) <
            pDsaData->dsaC)
        {
            PRINT_ERR("Counter domain parameter invalid\n");
            status = CPA_STATUS_INVALID_PARAM;
            goto finish;
        }
    }

    /*A.1.1.2 part 2. if seed length < N,  return fail
      -- works for A.1.1.3 algorithm also*/
    if ((seedLenBytes * BYTE_SIZE) < bitLengthOfN)
    {
        PRINT_ERR("Seed length (%u) is less than 'N' (%u),"
                  " the output data length of Q\n",
                  (seedLenBytes * BYTE_SIZE),
                  bitLengthOfN);
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*A.1.1.2 part 3. calculate small 'n' value*/
    if ((bitLengthOfL % (outLenBytes * BYTE_SIZE)) != 0)
    {
        /*Divide truncates the value (opposite of FIPS ceiling function),
          so no need to subtract 1*/
        n = bitLengthOfL / (outLenBytes * BYTE_SIZE);
    }
    else
    {
        /*No rounding, so need to subtract 1*/
        n = (bitLengthOfL / (outLenBytes * BYTE_SIZE)) - 1;
    }

    PRINT_DBG("'n' value is %u\n", n);

    /*A.1.1.2 part 4. calculate small 'b' value -
      This step is done in generatePfromQ function (as it is only used there).*/

    for (qCounter = 0; qCounter < FIPS_DSA_MAX_PQ_TRIES; qCounter++)
    {
        if (CPA_TRUE == validateParams)
        {
            CpaBoolean isQPrime = CPA_FALSE;

            /*If validateParams is true, this loop should only execute once*/
            if (0 < qCounter)
            {
                PRINT_ERR("Parameter validation should only happen once for"
                          "Q!\n");
                status = CPA_STATUS_INVALID_PARAM;
                goto finish;
            }

            (void)memcpy(
                localSeedValue.pData, pDsaData->dsaSeed.pData, seedLenBytes);
            /*A.1.1.3 part 7 - Hash the seed*/
            status = getDsaHash(pDsaData,
                                &localSeedValue,
                                NULL, /*NULL value means the result shall be
                                        written to 'localSeedValue buffer*/
                                outLenBytes,
                                instanceHandle);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Seed Domain parameter check Fail!\n");
                goto finish;
            }
            /*A.1.1.3 part 8*/
            localSeedValue.pData[0] |= FIPS_SAMPLE_TOP_BIT;
            localSeedValue.pData[localSeedValue.dataLenInBytes - 1] |= 0x01;
            /*A.1.1.3 part 9. check the primality of Q*/
            status = checkPorQPrimalityFipsC1(pDsaData,
                                              &localSeedValue,
                                              FIPS_DSA_PRIME_Q,
                                              &isQPrime,
                                              instanceHandle,
                                              securityStrength);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Q primality check Fail \n");
                goto finish;
            }
            if (CPA_TRUE == isQPrime)
            {
                PRINT_ERR("Domain Parameter Q Check FAIL - not prime\n");
                status = CPA_STATUS_INVALID_PARAM;
                goto finish;
            }

            /*A.1.1.3 part 9. check generated Q is == input Q*/
            if (0 != memcmp(localSeedValue.pData,
                            pDsaData->dsaQ.pData,
                            pDsaData->dsaQ.dataLenInBytes))
            {
                PRINT_ERR("Q Check FAIL - not the same as input Q value\n");
                status = CPA_STATUS_INVALID_PARAM;
                goto finish;
            }
        }
        else /*else we are generating P,Q*/
        {
            /*A.1.1.2 part 5 to 9 -- standard loops from this point if P < 2
             * ^(L-1)*/
            status = generateQ(pDsaData,
                               seedLenBytes,
                               outLenBytes,
                               instanceHandle,
                               securityStrength);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Generate Q Fail!\n");
                status = CPA_STATUS_INVALID_PARAM;
                goto finish;
            }
        }

        /*A.1.1.2 part 10*/
        offset = 1;

        for (generationAttempts = 0; generationAttempts <= counter;
             generationAttempts++)
        {
            /*A.1.1.2 part 11.1 to 11.7*/
            /*A.1.1.3 part 13.1 to 13.7*/
            status = generatePfromQ(pDsaData,
                                    &localPValue,
                                    seedLenBytes,
                                    outLenBytes,
                                    offset,
                                    n,
                                    &primePGenerated,
                                    instanceHandle);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Generate P, process Fail!\n");
                goto finish;
            }
            if (CPA_TRUE == primePGenerated)
            {
                PRINT_DBG("Count = %u \n", generationAttempts);
                if (CPA_TRUE != validateParams)
                {
                    pDsaData->dsaC = generationAttempts;
                }
                else
                {
                    /*A.1.1.3 part 14. return invalid if CTR != i, P != comp_P,
                     * P not prime*/
                    if (generationAttempts != pDsaData->dsaC)
                    {
                        PRINT_ERR("Local count not equal to input P gen count:"
                                  "Local = %u, Input = %u",
                                  generationAttempts,
                                  pDsaData->dsaC);
                        status = CPA_STATUS_INVALID_PARAM;
                        goto finish;
                    }
                    if (0 != memcmp(pDsaData->dsaP.pData,
                                    localPValue.pData,
                                    localPValue.dataLenInBytes))
                    {
                        PRINT_ERR("Calculated P not equal to input P \n");
                        status = CPA_STATUS_INVALID_PARAM;
                        goto finish;
                    }
                }
                /*break from 'for' loop*/
                break;
            }
            /*A.1.1.2 part 11.9*/
            offset += n + 1;
        }
        /*A.1.1.2 part 12 - loop back to part 5*/
        if (CPA_TRUE == primePGenerated)
        {
            /*break from top level 'for' loop*/
            break;
        }
    }

    /*qCounter < FIPS_DSA_MAX_PQ_TRIES;*/
    if (FIPS_DSA_MAX_PQ_TRIES == qCounter)
    {
        PRINT_ERR("No P value found after %u tries \n", qCounter);
        status = CPA_STATUS_FAIL;
    }

finish:

    if (CPA_TRUE == validateParams)
    {
        osFree(&localPValue.pData);
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      generateG
 *
 * @description
 *      Calculate the 'G' domain parameter, this uses FIPS 186-3 Section
 *      A.2.1.
 *
 * @param[in,out] pDsaData       Structure containing P and Q values used
 *                               in generating G. The result is stored the
 *                               referenced 'dsaG' structure element.
 * @param[in] instanceHandle     Quick Assist API instance handle
 * @param[in] securityStrength   Required DRNG security strength based on (L,N)
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      P and Q primes must be generated before calling this function.
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus generateG(usr_dsa_data_t *pDsaData,
                           const CpaInstanceHandle instanceHandle,
                           Cpa32U securityStrength)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };

    CpaCyDsaGParamGenOpData genGOpData = {
        .P = {.dataLenInBytes = pDsaData->dsaP.dataLenInBytes,
              .pData = pDsaData->dsaP.pData},
        .Q = {.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes,
              .pData = pDsaData->dsaQ.pData},
        .H = {.dataLenInBytes = 0, .pData = NULL}};
    CpaFlatBuffer H = {.dataLenInBytes = 0, .pData = NULL};
    CpaBoolean protocolStatus = CPA_FALSE;
    Cpa32U numGenGTries = FIPS_DSA_NUM_GEN_G_TRIES;
    /*Gen H*/
    H.pData = osZalloc(pDsaData->dsaP.dataLenInBytes, instanceHandle);
    if (NULL == H.pData)
    {
        PRINT_ERR("H alloc Fail \n");
        return CPA_STATUS_FAIL;
    }
    /*A.2.1 part 2. 0 < H < p-1 - just an arbitrary number*/
    H.dataLenInBytes = pDsaData->dsaP.dataLenInBytes - 1;
    pDsaData->dsaG.dataLenInBytes = pDsaData->dsaP.dataLenInBytes;

    for (; 0 < numGenGTries; numGenGTries--)
    {

        status = generateRandomBytes(
            &H, H.dataLenInBytes, securityStrength, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Get DSA H value Fail\n");
            goto finish;
        }
        /*Copy and overwrite the random number from kat file*/
        if (0 == pDsaData->dsaH.dataLenInBytes)
        {
            PRINT_ERR("Get DSA H value from Kat Fail\n");
            goto finish;
        }
        else
        {
            (void)memcpy(
                H.pData, pDsaData->dsaH.pData, pDsaData->dsaH.dataLenInBytes);
            H.dataLenInBytes = pDsaData->dsaH.dataLenInBytes;
        }
        (void)memcpy(pDsaData->dsaH.pData, H.pData, H.dataLenInBytes);
        pDsaData->dsaH.dataLenInBytes = H.dataLenInBytes;

        genGOpData.P.pData = pDsaData->dsaP.pData;
        genGOpData.P.dataLenInBytes = pDsaData->dsaP.dataLenInBytes;

        genGOpData.Q.pData = pDsaData->dsaQ.pData;
        genGOpData.Q.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes;

        genGOpData.H.pData = H.pData;
        genGOpData.H.dataLenInBytes = H.dataLenInBytes;

        /*A.2.1 parts 1,3 and part of step 4*/
        /*A.2.1 part 3. g = h^e mod p*/
        do
        {
            status = cpaCyDsaGenGParam(instanceHandle,
                                       NULL, /*callback function not required*/
                                       NULL, /*opaque data not required*/
                                       &genGOpData,
                                       &protocolStatus,
                                       &pDsaData->dsaG);
            if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
            {
                if (CPA_STATUS_SUCCESS != cpaCyGetStatusText(instanceHandle,
                                                             status,
                                                             statusErrorString))
                {
                    PRINT_ERR("Error retrieving status string.\n");
                }
                PRINT_ERR("G calc function FAIL \n -- %s", statusErrorString);
                status = CPA_STATUS_FAIL;
                goto finish;
            }
            maxCyRetries++;
            if (FIPS_MAX_CY_RETRIES == maxCyRetries)
            {
                PRINT_ERR("Too many retries (%u) from QA API\n",
                          FIPS_MAX_CY_RETRIES);
                status = CPA_STATUS_FAIL;
                goto finish;
            }
        } while (CPA_STATUS_RETRY == status);

        if (CPA_FALSE == protocolStatus)
        {
            /*A.2.1 part 4. if G == 1, re-calculate using a different H value*/
            PRINT_ERR("G calc calculation FAIL \n");
            status = CPA_STATUS_FAIL;
            continue;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = CPA_STATUS_SUCCESS;
            goto finish;
        }
    }
finish:
    osFree(&H.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      generateXY
 *
 * @description
 *      Calculate Public (Y) and Private (X) Keys using FIPS 186-3
 *      Section B.1.1
 *
 * @param[in,out] pDsaData      Structure containing the P,Q and G domain
 *                              parameters used for generating the
 *                              public/private keys. The result values are
 *                              stored in dsaX and dsaY buffers
 * @param[in] instanceHandle    Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus generateXY(usr_dsa_data_t *pDsaData,
                            const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    /*B.1.1 part 1.*/
    const Cpa32U bitLenL = pDsaData->dsaL;
    const Cpa32U bitLenN = pDsaData->dsaN;
    CpaBoolean protocolStatus = CPA_FALSE;
    Cpa8U *temp = NULL;
    CpaFlatBuffer randomC = {.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes +
                                               FIPS_DSA_EXTRA_8_BYTES,
                             .pData = NULL};

    CpaCyDsaYParamGenOpData genYOpData = {
        .P = {.dataLenInBytes = pDsaData->dsaP.dataLenInBytes,
              .pData = pDsaData->dsaP.pData},
        .G = {.dataLenInBytes = pDsaData->dsaG.dataLenInBytes,
              .pData = pDsaData->dsaG.pData},
        .X = {.dataLenInBytes = 0, .pData = NULL}};

    /* This is calculated later by checkLN() based on L & N */
    Cpa32U securityStrength;

    /*B.1.1 part 2. Check valid L, N values*/
    status = checkLN(bitLenL, bitLenN, &securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("L or N value invalid\n");
        goto finish;
    }
    PRINT_DBG("Using security strength of %d\n", (int)securityStrength);

    randomC.pData = osZalloc(randomC.dataLenInBytes, instanceHandle);
    if (NULL == randomC.pData)
    {
        PRINT_ERR("C value Alloc Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*B.1.1 part 3. Since max security strength is always used in
      part 4, this step is not required.*/
    /*B.1.1 parts 4,5. Generate 'c' using max security strength.*/
    status = generateRandomBytes(
        &(randomC), randomC.dataLenInBytes, securityStrength, instanceHandle);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Generate C Fail \n");
        goto finish;
    }
    (void)memcpy(
        pDsaData->dsaRandomC.pData, randomC.pData, randomC.dataLenInBytes);
    pDsaData->dsaRandomC.dataLenInBytes = randomC.dataLenInBytes;

    temp = (Cpa8U *)pDsaData->dsaQ.pData + pDsaData->dsaQ.dataLenInBytes - 1;
    *temp -= 1;
    do
    {
        pDsaData->dsaX.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes;

        /*B.1.1 part 6. x = c mod (q - 1) + 1 ==> ans OK as long as 0 < x < q*/
        status = doModExp(&(randomC),
                          NULL, /*NULL sets exponent to '0x01'*/
                          &(pDsaData->dsaQ),
                          &(pDsaData->dsaX),
                          instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Generate X (mod exp) Fail \n");
            goto finish;
        }
    } while (checkZero(&(pDsaData->dsaX)));
    temp = (Cpa8U *)pDsaData->dsaQ.pData + pDsaData->dsaQ.dataLenInBytes - 1;
    *temp += 1;
    temp = (Cpa8U *)pDsaData->dsaX.pData + pDsaData->dsaX.dataLenInBytes - 1;
    *temp += 1;

    pDsaData->dsaY.dataLenInBytes = pDsaData->dsaP.dataLenInBytes;

    genYOpData.X.dataLenInBytes = pDsaData->dsaX.dataLenInBytes;
    genYOpData.X.pData = pDsaData->dsaX.pData;

    do
    {
        /*B.1.1 part 7. y = g^x mod p*/
        status = cpaCyDsaGenYParam(instanceHandle,
                                   NULL, /*callback function not required*/
                                   NULL, /*opaque data not required*/
                                   &genYOpData,
                                   &protocolStatus,
                                   &pDsaData->dsaY);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Y calc function FAIL -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if ((CPA_FALSE == protocolStatus) || (CPA_STATUS_SUCCESS != status))
    {
        PRINT_ERR("Y calc calculation FAIL \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

finish:
    osFree(&randomC.pData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Keygen Fail\n");
        /*return invalid X and Y*/
        (void)memset(pDsaData->dsaX.pData, 0, pDsaData->dsaX.dataLenInBytes);
        (void)memset(pDsaData->dsaY.pData, 0, pDsaData->dsaY.dataLenInBytes);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaPQgen
 *
 * @description
 *      Top level function for generating P and Q domain parameters. This
 *      conforms to FIPS 186-3 Section A.1.1.2.
 *      Note: pDsaData.dsaSeed.dataLenInBytes must be set by the calling
 *      function (this is equivalent to seedlen input value given in the
 *      standard).
 *
 * @param[in,out] pDsaData       Structure containing values used for
 *                               generating P/Q primes and buffers for storing
 *                               dsaP, dsaQ, dsaC and dsaSeed.
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      Buffers associated with P, Q and Seed output values must be allocated.
 * @post
 *      none
 *
 *****************************************************************************/
CpaStatus fipsSample_dsaPQgen(usr_dsa_data_t *pDsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_PQGEN))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }
    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    /*generate Q and P values in accordance with FIPS 186-3 section A.1.1.2*/
    status = generateQP(pDsaData, CPA_FALSE, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Generate Q,P func Fail\n");
        goto finish;
    }
finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaGgen
 *
 * @description
 *      Top level function to calculate the 'G' domain parameter,
 *      this uses FIPS 186-3 Section A.2.1.
 *
 * @param[in,out] pDsaData      Structure containing P and Q values used
 *                              in generating G. The result is stored the
 *                              referenced 'dsaG' structure element.
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      P and Q primes must be generated before calling this function.
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_dsaGgen(usr_dsa_data_t *pDsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    /* This is calculated later by checkLN() based on L & N */
    Cpa32U securityStrength;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_GGEN))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    /*B.1.1 part 2. Check valid L, N values*/
    status = checkLN(pDsaData->dsaL, pDsaData->dsaN, &securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("L or N value invalid\n");
        goto finish;
    }
    PRINT_DBG("Using security strength of %d\n", (int)securityStrength);

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    status = generateG(pDsaData, instanceHandle, securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Generate G func Fail\n");
        goto finish;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      checkGUsingPQ
 *
 * @description
 *      Check that there is a valid G value using the input P and Q values.
 *      This is in accordance with NIST SP 800-89 Section 4.1 and FIPS 186-3
 *      Appendix A.2.2, part 2
 *
 * @param[in] pDsaG             G value to be checked
 * @param[in] pDsaP             P domain parameter
 * @param[in] pDsaQ             Q domain parameter
 * @param[in] instanceHandle    Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded,
 *                              G is 'PARTIALLY VALID'
 * @retval CPA_STATUS_FAIL      G is not valid
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus checkGUsingPQ(const CpaFlatBuffer *restrict pDsaG,
                               const CpaFlatBuffer *restrict pDsaP,
                               const CpaFlatBuffer *restrict pDsaQ,
                               const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer result = {.dataLenInBytes = pDsaP->dataLenInBytes,
                            .pData = NULL};

    result.pData = osZalloc(result.dataLenInBytes, instanceHandle);
    if (NULL == result.pData)
    {
        PRINT_ERR("Result Alloc Fail\n");
        return CPA_STATUS_FAIL;
    }

    /*A.2.2 part 2. if G^Q = 1 mod p, then 1 = (G^Q) mod p*/
    status = doModExp(pDsaG, pDsaQ, pDsaP, &result, instanceHandle);
    if (CPA_STATUS_FAIL == status)
    {
        PRINT_ERR("Do ModExp Fail\n");
        goto finish;
    }
    /*else PARTIALLY VALID*/
    if (CPA_TRUE != checkOne(&result))
    {
        PRINT_ERR("G^Q != 1 mod P!!!\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
finish:
    osFree(&result.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      validateG
 *
 * @description
 *      Validate G value using FIPS 186-3 Section A.2.2 algorithm
 *
 * @param[in] pDsaData      Structure containing P,Q and G domain
 *                              parameter values
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded,
 *                              G is 'PARTIALLY VALID'
 * @retval CPA_STATUS_FAIL      G is not valid
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static CpaStatus validateG(usr_dsa_data_t *pDsaData,
                           const CpaInstanceHandle instanceHandle)
{
    /*A.2.2 part 1. Verify that 2 <= g <= (p-1). If not true, return INVALID.*/
    /*P -= 1*/
    pDsaData->dsaP.pData[pDsaData->dsaP.dataLenInBytes - 1] -= 1;
    if (CPA_TRUE != isFbALessThanFbB(&(pDsaData->dsaG), &(pDsaData->dsaP)))
    {
        PRINT_ERR("G not less than P\n");
        /*reset P*/
        pDsaData->dsaP.pData[pDsaData->dsaP.dataLenInBytes - 1] += 1;
        return CPA_STATUS_FAIL;
    }
    /*reset P*/
    pDsaData->dsaP.pData[pDsaData->dsaP.dataLenInBytes - 1] += 1;
    if (CPA_TRUE != isFlatBufValGreaterThanOrEqualTo32UVal(
                        &(pDsaData->dsaG), (Cpa32U)FIPS_DSA_G_LOWER_BOUNDRY))
    {
        PRINT_ERR("G not greater than %u\n", FIPS_DSA_G_LOWER_BOUNDRY);
        return CPA_STATUS_FAIL;
    }

    /*A.2.2 part 2. If (g^q = 1 mod p), then return PARTIALLY VALID.*/
    if (CPA_STATUS_SUCCESS == checkGUsingPQ(&(pDsaData->dsaG),
                                            &(pDsaData->dsaP),
                                            &(pDsaData->dsaQ),
                                            instanceHandle))
    {
        PRINT_DBG("G is Partially Valid(ated)\n");
        return CPA_STATUS_SUCCESS;
    }

    /*A.2.2 part 3. Return INVALID.*/
    PRINT_ERR("Failed G validation");
    return CPA_STATUS_FAIL;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaGver
 *
 * @description
 *      Verify domain parameter G using FIPS 186-3 section A.2.2.
 *      N.B. This function returns 'partially valid' for G. This is in
 *      accordance with the validation algorithm.
 *
 * @param[in] pDsaData          Structure containing P,Q and G domain
 *                              parameter values
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded,
 *                              G is 'PARTIALLY VALID'
 * @retval CPA_STATUS_FAIL      G is not valid
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_dsaGver(usr_dsa_data_t *pDsaData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_GVER))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }
    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    /* Algo A.2.1 was used for generateing G (unverifiable generation),
       Therefore go to step 4.
       It is possible to extend the current algorithm to do 'verifiable G' by
       doing some extra processing on the QA API 'H' parameter.
       However there doesn't seem to be a need for the extra complexity.*/

    /* Perform partial validation of G using A.2.2, return INVALID or Partially
       Validated.*/

    /*NB: Since this program only does partial validation, a return of
          Success means although P and Q may have been validated, G was only
          partially validated.*/
    status = validateG(pDsaData, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Validate G Fail\n");
        goto finish;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaPQver
 *
 * @description
 *      Verify domain parameters P and Q using FIPS 186-3 section A.1.1.3.
 *
 * @param[in]  pDsaData         structure containing the domain parameters to
 *                              be validated
 *
 * @retval CPA_STATUS_SUCCESS   The parameters are valid
 * @retval CPA_STATUS_FAIL      The parameters are invalid
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_dsaPQver(usr_dsa_data_t *pDsaData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_PQVER))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    /*Assume FIPS 186-3 function was used to generate PQ, execute appropriate
         validation algorithm (A.1.1.3)*/
    status = generateQP(pDsaData,
                        CPA_TRUE, /*When this is set to CPA_TRUE,
                                    P and Q are validated*/
                        instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Validate QP Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaKeyGen
 *
 * @description
 *      Top level function to calculate Public (Y) and Private (X) Keys
 *      using FIPS 186-3 Section B.1.1
 *
 * @param[in,out] pDsaData      Structure containing the P,Q and G domain
 *                              parameters used for generating the
 *                              public/private keys. The result values are
 *                              stored in dsaX and dsaY buffers
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      Domain parameters for the operation have already been calculated
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_dsaKeyGen(usr_dsa_data_t *pDsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_KEYGEN))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    status = generateXY(pDsaData, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Generate X,Y Fail\n");
    }

    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      dsaSignCpa
 *
 * @description
 *      Calculate a message signature using FIPS 186-3 Section 4.6
 *
 * @param[in,out] pDsaData      Structure containing the input message
 *                              and other algorithm information for
 *                              generating the message signature.
 *                              The result R and S values are stored in
 *                              dsaR and dsaS structure elements.
 * @param[in] instanceHandle    Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      dsaR and dsaS associated buffers must be allocated
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus dsaSignCpa(usr_dsa_data_t *pDsaData,
                            const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaBoolean protocolStatus = CPA_FALSE;
    CpaCyDsaRSSignOpData dsaRSSignOpData = {
        .P = {.dataLenInBytes = pDsaData->dsaP.dataLenInBytes,
              .pData = pDsaData->dsaP.pData},
        .Q = {.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes,
              .pData = pDsaData->dsaQ.pData},
        .G = {.dataLenInBytes = pDsaData->dsaG.dataLenInBytes,
              .pData = pDsaData->dsaG.pData},
        .X = {.dataLenInBytes = pDsaData->dsaX.dataLenInBytes,
              .pData = pDsaData->dsaX.pData},
        .K = {.dataLenInBytes = pDsaData->dsaK.dataLenInBytes,
              .pData = pDsaData->dsaK.pData},
        .Z = {.dataLenInBytes = 0, .pData = NULL}};

    /*Get the message digest*/
    status =
        getHashBytes(pDsaData->shaAlg, &(dsaRSSignOpData.Z.dataLenInBytes));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Hash output length\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    /*len(Z) = min(hashLenbits, N)*/
    if (dsaRSSignOpData.Z.dataLenInBytes > pDsaData->dsaN / BYTE_SIZE)
    {
        dsaRSSignOpData.Z.dataLenInBytes = pDsaData->dsaN / BYTE_SIZE;
    }

    /*Allocate maximum buffer size*/
    dsaRSSignOpData.Z.pData =
        osZalloc(dsaRSSignOpData.Z.dataLenInBytes, instanceHandle);
    if (NULL == dsaRSSignOpData.Z.pData)
    {
        PRINT_ERR("Digest buffer allocation Fail \n");
        return CPA_STATUS_FAIL;
    }

    status = getDsaHash(pDsaData,
                        &(pDsaData->dsaMsg),
                        &(dsaRSSignOpData.Z),
                        dsaRSSignOpData.Z.dataLenInBytes,
                        instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error getting message digest \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    pDsaData->dsaR.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes;
    pDsaData->dsaS.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes;

    do
    {
        status = cpaCyDsaSignRS(instanceHandle,
                                NULL, /*callback function not required*/
                                NULL, /*opaque data not required*/
                                &dsaRSSignOpData,
                                &protocolStatus,
                                &pDsaData->dsaR,
                                &pDsaData->dsaS);

        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("RS calculation FAIL -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_FALSE == protocolStatus)
    {
        PRINT_ERR("RS calculation protocol FAIL \n");
        status = CPA_STATUS_FAIL;
    }

finish:

    osFree(&dsaRSSignOpData.Z.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaSign
 *
 * @description
 *      Top level function to calculate a message signature using FIPS 186-3
 *      Section 4.6. This also stores the per message secret number K.
 *
 * @param[in,out] pDsaData      Structure containing the input message
 *                              and other algorithm information for
 *                              checking the message signature.
 *                              The result R and S values are stored in
 *                              dsaR and dsaS structure elements.
 *                              The per message secret number is stored in
 *                              dsaK structure element.
 *
 * @retval CPA_STATUS_SUCCESS   The operation succeeded
 * @retval CPA_STATUS_FAIL      The operation failed
 *
 * @pre
 *      dsaX, dsaR, dsaS , dsaMsg and dsaK associated buffers must be
 *      allocated before calling this function
 * @post
 *      In accordance with FIPS 186-3 section 4.5, the per message secret
 *      number shall be protected from unorthorised disclosure or modification
 *****************************************************************************/
CpaStatus fipsSample_dsaSign(usr_dsa_data_t *pDsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxRSRetries = 0;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaFlatBuffer dsaK = {.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes,
                          .pData = NULL};
    /* This is calculated later by checkLN() based on L & N */
    Cpa32U securityStrength;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_SIGN))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    /*A.1.1.2 part 1. Check the L, N pair is acceptable*/
    status = checkLN(pDsaData->dsaL, pDsaData->dsaN, &securityStrength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("L or N value invalid\n");
        goto finish;
    }
    PRINT_DBG("Using security strength of %d\n", (int)securityStrength);

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    dsaK.pData = osZalloc(pDsaData->dsaQ.dataLenInBytes, instanceHandle);
    if (NULL == dsaK.pData)
    {
        PRINT_ERR("K value Alloc Fail\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    do
    {
        /*Gen K*/
        status = generateRandomBytes(&dsaK,
                                     pDsaData->dsaQ.dataLenInBytes,
                                     securityStrength,
                                     instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Get DSA K value Fail \n");
            goto finish;
        }
        dsaK.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes;
        dsaK.pData[0] = 0;
        dsaK.pData[1] |= FIPS_SAMPLE_TOP_BIT;
        memcpy(pDsaData->dsaK.pData, dsaK.pData, dsaK.dataLenInBytes);
        pDsaData->dsaK.dataLenInBytes = dsaK.dataLenInBytes;

        status = dsaSignCpa(pDsaData, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("RS sign Fail\n");
            goto finish;
        }

        maxRSRetries++;
        if (FIPS_MAX_CY_RETRIES == maxRSRetries)
        {
            PRINT_ERR("Too many retries (%u) while generating R, S values\n",
                      FIPS_MAX_CY_RETRIES);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
    }
    /*if R or S values are zero, new values must be calculated with a new per
      message secret number K*/
    while ((CPA_TRUE == checkZero(&pDsaData->dsaR)) ||
           (CPA_TRUE == checkZero(&pDsaData->dsaS)));

finish:
    osFree(&dsaK.pData);
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      dsaVerCpa
 *
 * @description
 *      Validate a message signature in accordance with FIPS 186-3 section
 *      4.7
 *
 * @param[in,out] pDsaData      Structure containing the message, the
 *                              message signature R,S values, the
 *                              domain parameters (P, Q, G) and the public
 *                              key Y.
 * @param[in] instanceHandle    Quick Assist API instance handle
 *
 * @retval CPA_STATUS_SUCCESS   The signature is verified
 * @retval CPA_STATUS_FAIL      The signature is not verified
 *
 * @pre
 *      dsaR, dsaS, dsaP, dsaQ, dsaG, dsaY, dsaMsg associated buffers have
 *      been allocated
 * @post
 *      none
 *****************************************************************************/
static CpaStatus dsaVerCpa(usr_dsa_data_t *pDsaData,
                           const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaBoolean protocolStatus = CPA_FALSE;
    CpaCyDsaVerifyOpData dsaVerifyOpData = {
        .P = {.dataLenInBytes = pDsaData->dsaP.dataLenInBytes,
              .pData = pDsaData->dsaP.pData},
        .Q = {.dataLenInBytes = pDsaData->dsaQ.dataLenInBytes,
              .pData = pDsaData->dsaQ.pData},
        .G = {.dataLenInBytes = pDsaData->dsaG.dataLenInBytes,
              .pData = pDsaData->dsaG.pData},
        .Y = {.dataLenInBytes = pDsaData->dsaY.dataLenInBytes,
              .pData = pDsaData->dsaY.pData},
        .Z = {.dataLenInBytes = 0, .pData = NULL},
        .R = {.dataLenInBytes = pDsaData->dsaR.dataLenInBytes,
              .pData = pDsaData->dsaR.pData},
        .S = {.dataLenInBytes = pDsaData->dsaS.dataLenInBytes,
              .pData = pDsaData->dsaS.pData}};

    /*Get the message digest*/
    status =
        getHashBytes(pDsaData->shaAlg, &(dsaVerifyOpData.Z.dataLenInBytes));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get Hash output length\n");
        goto finish;
    }
    /*Z = min(hashLenbits, N)*/
    if (dsaVerifyOpData.Z.dataLenInBytes > (pDsaData->dsaN / BYTE_SIZE))
    {
        dsaVerifyOpData.Z.dataLenInBytes = (pDsaData->dsaN / BYTE_SIZE);
    }
    /*Allocate maximum buffer size*/
    dsaVerifyOpData.Z.pData =
        osZalloc(dsaVerifyOpData.Z.dataLenInBytes, instanceHandle);
    if (NULL == dsaVerifyOpData.Z.pData)
    {
        PRINT_ERR("Digest buffer allocation Fail \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    status = getDsaHash(pDsaData,
                        &(pDsaData->dsaMsg),
                        &(dsaVerifyOpData.Z),
                        dsaVerifyOpData.Z.dataLenInBytes,
                        instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error getting message digest \n");
        goto finish;
    }
    do
    {
        status = cpaCyDsaVerify(instanceHandle,
                                NULL, /*callback function not required*/
                                NULL, /*opaque data not required*/
                                &dsaVerifyOpData,
                                &protocolStatus);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("RS verification process FAIL -- %s\n",
                      statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    pDsaData->resultVerified = protocolStatus;

finish:
    osFree(&dsaVerifyOpData.Z.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleDsa
 *      fipsSample_dsaVerify
 *
 * @description
 *      Top level function to validate a message signature in accordance
 *      with FIPS 186-3 section 4.7
 *
 * @param[in]  pDsaData         Structure containing the message, the
 *                              message signature R,S values, the
 *                              domain parameters (P, Q, G) and the public
 *                              key Y.
 *
 * @retval CPA_STATUS_SUCCESS   The signature is verified
 * @retval CPA_STATUS_FAIL      The signature is not verified
 *
 * @pre
 *      dsaR, dsaS, dsaP, dsaQ, dsaG, dsaY, dsaMsg associated buffers have
 *      been allocated
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_dsaVerify(usr_dsa_data_t *pDsaData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (CPA_STATUS_SUCCESS != checkDsaData(pDsaData, DSA_VERIFY))
    {
        PRINT_ERR("Dsa Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get QA instance Fail\n");
        return CPA_STATUS_FAIL;
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling failed \n");
        return CPA_STATUS_FAIL;
    }
    status = dsaVerCpa(pDsaData, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("RS verification func Fail\n");
        goto finish;
    }

finish:
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }
    return status;
}
