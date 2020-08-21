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
 * @file cpa_fips_sample_rsa.h
 *
 * @defgroup fipsSampleRsa FIPS sample RSA code
 *
 * @ingroup fipsSample
 *
 * This header file contains function prototypes and structure definitions for
 * running the FIPS Cy RSA implementation functions
 *
 *****************************************************************************/

#ifndef _CPA_FIPS_SAMPLE_RSA_H_
#define _CPA_FIPS_SAMPLE_RSA_H_

#include "cpa_cy_rsa.h"

/**
 *****************************************************************************
 * RSA definitions, enums and structures
 *****************************************************************************/

/**
 * FIPS 186-3 supported RSA modulus lengths
 **/
#define RSA_N_LEN_1024 (1024)
#define RSA_N_LEN_2048 (2048)
#define RSA_N_LEN_3072 (3072)

/**
 * FIPS 186-3 Appendix C.3, Table C.3 based numbers for the amount of
 * Miller Rabin rounds to do when checking a prime candidate
 **/
#define FIPS_RSA_MILLER_RABIN_1024_SMALL (38)
#define FIPS_RSA_MILLER_RABIN_1024_LARGE (7)
#define FIPS_RSA_MILLER_RABIN_2048_SMALL (32)
#define FIPS_RSA_MILLER_RABIN_2048_LARGE (4)
#define FIPS_RSA_MILLER_RABIN_3072_SMALL (27)
#define FIPS_RSA_MILLER_RABIN_3072_LARGE (3)

/**
 * Quick Assist API only supports prime checking for values of length up to
 * 512 bits, or equal to 768, 1024, 2048, 3072, 4096 bits. This is the
 * size limit placed on the smaller values to be checked for primality during
 * RSA key generation. See Table B.1 FIPS 186-3 for more information on
 * possible prime sizes.
 **/
#define FIPS_RSA_MAX_RANDOM_LEN_SMALL_PRIME_BYTES (64)

/**
 * Max and Min sizes for RSA key generation parameter 'e'
 **/
#define FIPS_186_3_MIN_E_SIZE_IN_BYTES (2)
#define FIPS_186_3_MAX_E_SIZE_IN_BYTES (32)
#define ANS_X9_31_MIN_E_VALUE (2)
/**
 * E must be less than modulus size in bits - 160 for ANS X9.31
 **/
#define ANS_X9_31_E_MAX_SIZE_CONSTANT_BYTES (20)

/**
 * Number of times to retry generating a RSA key. This only occurs when the
 * Result P == Q, or the private signature exponent 'd' value fails the checks
 * in FIPS 186-3 section B.3.1, part 3
 **/
#define MAX_KEYGEN_RETRY_ATTEMPTS (10)

/**
 * Definitions used in RSA-PSS encoding
 **/
#define NUM_PSS_REQUIRED_BUFFERS (5)
#define RSA_PSS_TRAILER_LENGTH (2)
#define RSA_PAD_8_BYTES (8)
#define RSA_PSS_ENCODED_MESSAGE_TERMINATOR (0xBC)

/**
 * XP1, XP2, XQ1, XQ2 max lengths based on security strength
 **/
#define XP1_LEN_FOR_SEC_STRENGTH_80_IN_BYTES (31)
#define XP1_LEN_FOR_SEC_STRENGTH_112_IN_BYTES (62)
#define XP1_LEN_FOR_SEC_STRENGTH_128_IN_BYTES (93)

/**
 * FIPS 186-3 section C.9 part 3 - random value byte length calculation
 **/
#define FIPS_RSA_CALC_XP_MAX_LENGTH_BYTES(xpLen, modulusLengthBits)            \
    do                                                                         \
    {                                                                          \
        xpLen = ((modulusLengthBits / 2)) / BYTE_SIZE;                         \
    } while (0)

/**
 * FIPS 186-3 section C.9 part 9 compares the number of iterations with this
 * number
 **/
#define FIPS_RSA_MAX_I_VALUE(modulusLengthBits) (5 * (modulusLengthBits / 2))

/**
 * FIPS 186-3 section B.3.6, part 6 - the difference between 'P' and 'Q', and
 * 'Xp' and 'Xq' must be at least this calculated size
 **/
#define FIPS_RSA_CALCULATE_MIN_BIT_DIFFERENCE_ALG_B_3_6(modulusLengthBits)     \
    ((modulusLengthBits / 2) - 100)

#define FIPS_RSA_FIPS_186_3_FIND_LAST_TWO_BYTES(storedEm, Em)                  \
    (storedEm - (Em + 2))

/**
 * Only RSA PSS is supported in the FIPS sample code
 **/
typedef enum {
    RSA_PSS = 0,
} rsa_mode_t;

/**
 * Different RSA operations
 **/
typedef enum { RSA_KEYGEN = 0, RSA_SIGN, RSA_VERIFY } rsa_operation_t;

/**
 * Different Key Generation modes. These only effect the size of the 'e'
 * public key exponent value allowed. 'e' must be odd in both cases.
 * FIPS 186-3 allows (e > 2^16) OR (e < 2^256) ANS X9.31 allows (e > 2) OR
 * (e < 2^(k -160)), where k is the modulus size in bits
 **/
typedef enum { FIPS_186_3_KEYGEN = 0, ANS_X9_31_KEYGEN } rsa_prime_gen_type_t;

/**
 * Different RSA prime check types
 **/
typedef enum {
    FIPS_RSA_PRIME_SMALL = 0,
    FIPS_RSA_PRIME_LARGE
} rsa_prime_check_type_t;

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      usr_rsa_data_t
 *
 * @description
 *      Structure for all RSA operations.
 *****************************************************************************/
typedef struct usr_rsa_data_s
{
    Cpa32U rsaModulusSizeInBits;
    /*Modulus Length in bits*/
    CpaFlatBuffer rsaM;
    /*Plaintext buffer for input message*/
    CpaFlatBuffer rsaEM;
    /*Buffer for encoded message signature. In all cases, a buffer of the
      modulus size of the operation must be allocated*/
    CpaFlatBuffer rsaE;
    /*RSA public key exponent.
     This must be odd and between 2 and 64 bytes in length for FIPS 186-3*/
    CpaFlatBuffer rsaXP;
    /*This parameter is used for generating RSA keys.
      This buffer MUST be allocated for KeyGen operations with
      size = modulus size. It may be unused or filled with a NIST test
      vector used for Key Generation*/
    CpaFlatBuffer rsaXP1;
    CpaFlatBuffer rsaXP2;
    /*rsaXP1 and rsaXP2 are used for running FIPS tests. These buffers MUST be
      allocated for KeyGen operations with a size = modulus size and
      may be empty or contain an NIST test vector used in Key Generation*/
    CpaFlatBuffer rsaXQ;
    /*This parameter is used for generating RSA keys.
      This buffer MUST be allocated for KeyGen operations with
      size = modulus size. It may be unused or filled with a NIST test
      vector used for Key Generation*/
    CpaFlatBuffer rsaXQ1;
    CpaFlatBuffer rsaXQ2;
    /*rsaXQ1 and rsaXQ2 are used for running FIPS tests. These buffers MUST be
      allocated for KeyGen operations with a size = modulus size and
      may be empty or contain an NIST test vector used in Key Generation*/
    CpaBoolean useXPinput;
    /*If the user sets this value to CPA_TRUE, all XP and XQ buffers have been
      filled with NIST test vectors, else the buffers are only allocated */
    rsa_operation_t rsaOperation;
    /*This gives which RSA operation should be used*/
    rsa_prime_gen_type_t rsaKeyGenType;
    /*This gives what type of key generation method should be used - FIPS 186-3,
      section B.3.6, or ANS X9.31 keygen method (this effects the available
      choice of values for public key exponent 'e')*/
    rsa_mode_t rsaMode;
    /*This gives which Sign/Verify mode should be used*/
    CpaFlatBuffer rsaN;
    /*Modulus N = P * Q (part of the public/private RSA key pairs)*/
    CpaFlatBuffer rsaD;
    /*Private Key Exponent D*/
    CpaFlatBuffer rsaP;
    /*Prime P, output value from the Key Generation Operation*/
    CpaFlatBuffer rsaP1;
    /*Prime P1, output value from the Key Generation Operation (this value
      was used to generate P)*/
    CpaFlatBuffer rsaP2;
    /*Prime P2, output value from the Key Generation Operation (this value
      was used to generate P)*/
    CpaFlatBuffer rsaQ;
    /*Prime Q, output value from the Key Generation Operation*/
    CpaFlatBuffer rsaQ1;
    /*Prime Q1, output value from the Key Generation Operation (this value
      was used to generate Q)*/
    CpaFlatBuffer rsaQ2;
    /*Prime Q2, output value from the Key Generation Operation (this value
      was used to generate Q)*/
    CpaCySymHashAlgorithm shaAlg;
    /*Sha Algorithm associated with the processing request
      (Key Gen/Sign/Verify)*/
    CpaCyDrbgSecStrength securityStrength;
    /*Random Number Generator security strength associated with the
      processing request (Key Gen/Sign/Verify)*/
    CpaFlatBuffer rsaSalt;
    /*Salt value to be used for RSA PSS encode/decode operation*/
    CpaBoolean sigVerified;
    /*This value is set to CPA_TRUE if the signature being checked by the RSA
      verification operation is 'consistent'. If it is set to CPA_FALSE, the
      input signature is 'inconsistent'*/
} usr_rsa_data_t;

/**
 *****************************************************************************
 * RSA function prototypes
 *****************************************************************************/

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
CpaStatus fipsSample_rsaKeygen(usr_rsa_data_t *rsaData);

/**
 *****************************************************************************
 * @ingroup fipsSampleRsa
 *      fipsSample_rsaSign
 *
 * @description
 *      Top level function for RSA signature generation
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
CpaStatus fipsSample_rsaSign(usr_rsa_data_t *rsaData);

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
CpaStatus fipsSample_rsaVerify(usr_rsa_data_t *rsaData);

#endif /*_CPA_FIPS_SAMPLE_RSA_H_*/
