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
 * @file cpa_fips_sample_dsa.h
 *
 * @defgroup fipsSampleDsa FIPS sample DSA code
 *
 * @ingroup fipsSample
 *
 * @description
 * This header file contains function prototypes and structure definitions for
 * running the FIPS Cy DSA implementation functions
 *
 *****************************************************************************/

#ifndef _CPA_FIPS_SAMPLE_DSA_H_
#define _CPA_FIPS_SAMPLE_DSA_H_

#include "cpa_cy_dsa.h"

/**
 *****************************************************************************
 * DSA definitions, enums and structures
 *****************************************************************************/
/**
 * This is the multiplier from FIPS 186-3, A.1.1.2, step 11
 **/
#define FIPS_DSA_COUNTER_MULTIPLIER (4)

/**
 * FIPS 186-3 does not specify a maximum number of algorithm iterations. These
 * give the maximum in case of program error.
 **/
#define FIPS_DSA_MAX_PQ_TRIES (1000)
#define FIPS_DSA_MAX_Q_TRIES (1000)
#define FIPS_DSA_NUM_GEN_G_TRIES (100)

/**
 * G domain parameter must be less than P and greater than 2
 **/
#define FIPS_DSA_G_LOWER_BOUNDRY (2)

/**
 * FIPS 186-3, B.1.1, section 4 requires an extra 64 bits of random data to
 * ensure any bias introduced by the modulus function is negligible.
 **/
#define FIPS_DSA_EXTRA_8_BYTES (8)

/**
 * Definitions for FIPS 186-3 A.1.1.2, part 11 'W' calculations
 **/
#define FIPS_DSA_W_CALC_NUM_TMP_BUFFERS_REQUIRED (4)
#define FIPS_DSA_B_BUFFER_OFFSET (3)
#define FIPS_DSA_MODULUS_TARGET_BUFFER_OFFSET (2)
#define FIPS_DSA_SEED_MODULUS_BUFFER_OFFSET (1)

/**
 * Number of Miller Rabin Rounds required (based on FIPS 186-3, Appendix C.3,
 * Table C.1 when including 1 Lucas test
 **/
#define FIPS_DSA_MILLER_RABIN_1024_160_Q (19)
#define FIPS_DSA_MILLER_RABIN_1024_160_P (3)
#define FIPS_DSA_MILLER_RABIN_2048_224_Q (24)
#define FIPS_DSA_MILLER_RABIN_2048_256_Q (27)
#define FIPS_DSA_MILLER_RABIN_2048_P (3)
#define FIPS_DSA_MILLER_RABIN_3072_256_Q (27)
#define FIPS_DSA_MILLER_RABIN_3072_256_P (2)

/**
 * Valid DSA 'L' values from NIST SP 800-57 (Part 1, Table 4)
 **/
#define FIPS_DSA_L_SIZE_1024 (1024)
#define FIPS_DSA_L_SIZE_2048 (2048)
#define FIPS_DSA_L_SIZE_3072 (3072)

/**
 * Valid DSA 'N' values from NIST SP 800-57 (Part 1, Table 4)
 **/
#define FIPS_DSA_N_SIZE_160 (160)
#define FIPS_DSA_N_SIZE_224 (224)
#define FIPS_DSA_N_SIZE_256 (256)

/**
 * Different supported DSA operations
 **/
typedef enum
{
    DSA_SIGN = 0,
    DSA_VERIFY,
    DSA_KEYGEN,
    DSA_PQGEN,
    DSA_GGEN,
    DSA_PQVER,
    DSA_GVER,
} dsa_operation_t;

/**
 * Different prime check candidate types
 **/
typedef enum
{
    FIPS_DSA_PRIME_Q = 0,
    FIPS_DSA_PRIME_P
} dsa_prime_check_type_t;

/**
 ****************************************************************************
 * @ingroup fipsSampleDsa
 *      usr_dsa_data_t
 *
 * @description
 *      Structure for all DSA operations. Memory required to store function
 *      outputs MUST be allocated before calling a fipsSample_xxx fuction.
 *      All function input values must be in MSB order.
 *
 *      Note FIPS 186-3 section 4.3 states that domain parameters P,Q,G,
 *      domain_parameter_seed, counter, may be made public, however
 *      assurance of their validity must be gained in accordance with
 *      FIPS 800-89. I.e. The one using the domain parameters must have been
 *      the one to generate them or have obtained the assurance of a trusted
 *      third party (TTP), e.g. a Certificate Authority (CA).
 *****************************************************************************/
typedef struct usr_dsa_data_s
{
    Cpa32U dsaL;
    /*Operation modulus size (L size). Note FIPS 800-57 (Part 1, Table 4)
      states the minimum for this value is 2048 bits from 2011 AD*/
    Cpa32U dsaN;
    /*Operation N size (corresponding to the operation L size).*/
    CpaCySymHashAlgorithm shaAlg;
    /*SHA algorithm to use for key generation*/
    Cpa32U dsaC;
    /*Domain Parameter Counter value for the number iterations to generate
      P,Q and G (this may be used to validate the values)*/
    CpaFlatBuffer dsaX;
    /*Private Key X (generated from P,Q,G)*/
    CpaFlatBuffer dsaY;
    /*Public Key Y (generated from P,Q,G)*/
    CpaFlatBuffer dsaK;
    /*Per message secret number (value set during 'sign' operation)*/
    CpaFlatBuffer dsaR;
    /*Signature R value*/
    CpaFlatBuffer dsaS;
    /*Signature S value*/
    CpaFlatBuffer dsaP;
    /*Domain parameter P (used in key generation)*/
    CpaFlatBuffer dsaQ;
    /*Domain parameter Q (used in key generation)*/
    CpaFlatBuffer dsaG;
    /*Domain parameter G (used in key generation)*/
    CpaFlatBuffer dsaSeed;
    /*Domain Parameter Seed, random value used for generating
      P,Q and G (this may be used to validate the values). The dataLenInBytes
      property of the CpaFlatBuffer must also be set when generating P and Q
      in order to give the A.1.1.2 algorithm input 'seedlen' (however a byte
      length is used in this case)*/
    CpaFlatBuffer dsaMsg;
    /*Message to be signed or corresponding to a signature that must be
      verified*/
    CpaFlatBuffer dsaH;
    /*Domain parameter H*/
    CpaFlatBuffer dsaRandomC;
    /*Domain parameter C*/
    CpaBoolean resultVerified;
    /*This boolean is set after checking whether a signature is correct.
      A value of CPA_TRUE means the signature was verified.*/
} usr_dsa_data_t;

/**
 *****************************************************************************
 * DSA function prototypes
 *****************************************************************************/
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
CpaStatus fipsSample_dsaPQgen(usr_dsa_data_t *pDsaData);

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
CpaStatus fipsSample_dsaGgen(usr_dsa_data_t *pDsaData);

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
CpaStatus fipsSample_dsaGver(usr_dsa_data_t *pDsaData);

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
CpaStatus fipsSample_dsaPQver(usr_dsa_data_t *pDsaData);

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
CpaStatus fipsSample_dsaKeyGen(usr_dsa_data_t *pDsaData);

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
CpaStatus fipsSample_dsaSign(usr_dsa_data_t *pDsaData);

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
CpaStatus fipsSample_dsaVerify(usr_dsa_data_t *pDsaData);

#endif /*_CPA_FIPS_SAMPLE_DSA_H_*/
