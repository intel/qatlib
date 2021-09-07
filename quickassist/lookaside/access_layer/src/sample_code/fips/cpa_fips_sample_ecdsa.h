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

/**
 ******************************************************************************
 * @file cpa_fips_sample_ecdsa.h
 *
 * @defgroup fipsSampleEcdsa FIPS sample ECDSA code
 *
 * @ingroup fipsSample
 *
 * This header file contains function prototypes and structure definitions for
 * running the FIPS Cy ECDSA implementation functions
 *
 *****************************************************************************/

#ifndef _CPA_FIPS_SAMPLE_ECDSA_H_
#define _CPA_FIPS_SAMPLE_ECDSA_H_

#include "cpa_cy_ec.h"
#include "cpa_cy_ecdsa.h"

/**
 *****************************************************************************
 * ECDSA definitions, enums and structures
 *****************************************************************************/
#define FIPS_SAMPLE_ECDSA_MAX_D_GEN_ITERATIONS (5)
#define FIPS_SAMPLE_ECDSA_TOP_NIBBLE (0xF0)
/**
 * G (Base Point) Order bit length
 **/
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_MIN_BIT_LENGTH (160)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_223 (223)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_255 (255)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_383 (383)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_511 (511)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BIT_LENGTH_512 (512)

/**
 * Byte space for storing base order value area. Number of bits
 * to store 2^X = X + 1
 **/
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_MIN_BYTE_SPACE (20)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BYTE_SPACE_233 (30)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BYTE_SPACE_255 (32)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BYTE_SPACE_383 (48)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BYTE_SPACE_511 (54)
#define FIPS_SAMPLE_ECDSA_BASE_ORDER_BYTE_SPACE_512 (55)

/**
 * Supported sizes for Cofactor H are (10, 14, 16 or 32) + 1 bits in length
 **/
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_10_BITS (11)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_14_BITS (15)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_16_BITS (17)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_24_BITS (25)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_32_BITS (33)

/**
 * Byte space for storing the cofactor value.
 * Number of bits to store 2^X = X + 1
 **/
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_10_BITS_NIBBLE_SPACE (3)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_14_BITS_NIBBLE_SPACE (4)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_16_BITS_NIBBLE_SPACE (6)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_24_BITS_NIBBLE_SPACE (10)
#define FIPS_SAMPLE_ECDSA_COFACTOR_SIZE_32_BITS_NIBBLE_SPACE (13)

/**
 * Many QA Operation Data structures need these parameters.
 * This macro allows setting the parameters in minimal code space.
 **/
#define FIPS_SAMPLE_ECDSA_ECDSA_SET_ABGxGy(ecdsaData, ecdsa_struct)            \
    do                                                                         \
    {                                                                          \
        ecdsa_struct->a.pData = ecdsaData->a.pData;                            \
        ecdsa_struct->a.dataLenInBytes = ecdsaData->a.dataLenInBytes;          \
        ecdsa_struct->b.pData = ecdsaData->b.pData;                            \
        ecdsa_struct->b.dataLenInBytes = ecdsaData->b.dataLenInBytes;          \
        ecdsa_struct->xg.pData = ecdsaData->xg.pData;                          \
        ecdsa_struct->xg.dataLenInBytes = ecdsaData->xg.dataLenInBytes;        \
        ecdsa_struct->yg.pData = ecdsaData->yg.pData;                          \
        ecdsa_struct->yg.dataLenInBytes = ecdsaData->yg.dataLenInBytes;        \
    } while (0)

/**
 * Different ECDSA operations
 **/
typedef enum
{
    ECDSA_SIGN = 0,
    ECDSA_VERIFY,
    ECDSA_KEYGEN,
} ecdsa_operation_t;

/**
 * ECDSA FIPS curves
 **/
typedef enum
{
    P192 = 0,
    P224,
    P256,
    P384,
    P521,
    K163,
    B163,
    K233,
    B233,
    K283,
    B283,
    K409,
    B409,
    K571,
    B571,
    CUSTOM,
} ecdsa_curve_t;

/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      usr_ecdsa_data_t
 *
 * @description
 *      Structure for all ECDSA operations. Memory required to store function
 *      outputs MUST be allocated before calling a fipsSample_xxx fuction.
 *      All function input values must be in MSB order
 *
 *      For the Key Generation, Sign and Verify functions it is required that
 *      the  domain parameters be passed as arguments.
 *      (Sec 6.1):
 *
 *      (q, FR, a, b {, domain_parameter_seed}, G, n, h)
 *
 *      q    = Field Size
 *      FR   = Basis indication
 *      a, b = part of the polynomial equation used for generating the field
 *      domain_parameter_seed
 *           = seed used in generating the elliptic curve
 *      G    = (Gx, Gy) Base point or Generator of Elliptic Curve parameters
 *      n    = The order of point G
 *      h    = The cofactor (order of the curve divided by n)
 *
 *      Other variables:
 *
 *      Hash = Hash function to be used (must be same or better security
 *             strength as specified in NIST SP 800-57 Part 1, Table 2).
 *      Q    = Public Key (co-ordinate xq, yq)
 *      d    = Private Key (such the Q = G.d)
 *      r,s  = Signature pair
 *
 *      Note, NIST recommended Curves were generated using SHA1
 *
 *      Please see this document for a discussion on generating curve
 *      parameters:
 *      http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
 *
 *****************************************************************************/
typedef struct usr_ecdsa_data_s
{
    ecdsa_curve_t curve;
    /*Which FIPS curve to used,
      if this is set to 'CUSTOM', then the user has generated the domain
      parameters for the requested operation.
      If this is not set to Custom, then the domain parameters are loaded
      from the array specified in cpa_fips_sample_ecdsa_params.h*/
    Cpa32U N;
    /*This is the order of point G (xg and yg below).
      This also specifies the security strength to used (Ref. NIST SP 800-57
      Part 1, Table 2*/
    Cpa32U fieldType;
    /*This specifies whether the Field is type Binary or Prime number.
      A Binary Field may be specified by a Binary or Koblitz style
      polynomial*/
    CpaCySymHashAlgorithm hashAlgorithm;
    /*Hash algorithm to be used in the sign/verify functions*/
    CpaFlatBuffer domainParameterSeed;
    /*Seed value used in generating domain parameters. See FIPS 186-3 section
      6.1 for more information*/
    CpaFlatBuffer h;
    /*Cofactor of the Curve Polynomial*/
    CpaFlatBuffer a;
    CpaFlatBuffer b;
    /*'a' and 'b' are constants used for generating the EC field*/
    CpaFlatBuffer xg;
    CpaFlatBuffer yg;
    /*'xg' and 'yg' are base point generator of EC parameters. i.e. all
      operations (add/divide/multiply) are done through this point*/
    CpaFlatBuffer PrimeOrPolynomial;
    /*Prime Modulus or Polynomial powers for Prime and Binary curves
      For the polynomial description, this is an array of power values,
      largest to smallest.
      Pseudo-random curves are those whose coefficients are generated from
      the output of a seeded cryptographic hash*/
    CpaFlatBuffer OrderOfG;
    /*This is the order (n) of the curve
      Note, NIST supply sample values for 'n', however any value may be
      used. This could help in separating cryptographic networks
      (see FIPS 186-3, Appendix D.1.1.5)*/
    CpaFlatBuffer d;
    /*Private Key, d*/
    CpaFlatBuffer xq;
    /*Public key X value (xq = xg.d*/
    CpaFlatBuffer yq;
    /*Public key Y value (yq = yg.d*/
    CpaFlatBuffer SignR;
    CpaFlatBuffer SignS;
    /*R and S are the signature pairs.
      These buffers must be allocated by the calling function*/
    CpaFlatBuffer k;
    /*Per message secret number for signature process
      This buffer must be allocated by the calling function*/
    CpaFlatBuffer mesg;
    /*A message to be signed or to be used to verify a signature*/
    CpaFlatBuffer mesgDigest;
    /*Digest of the message (computed during a sign or verify operation.
      This buffer must be allocated by the user and must be of a size large
      enough to hold the output of the associated HASH function*/
    CpaBoolean verifyStatus;
    /*When doing a message signature verification, this value is set to
      CPA_TRUE if the signature is valid or CPA_FALSE if the signature is
      invalid.*/
} usr_ecdsa_data_t;

/**
 *****************************************************************************
 * ECDSA function prototypes
 *****************************************************************************/
/**
 *****************************************************************************
 * @ingroup fipsSampleEcdsa
 *      fipsSample_ecdsaKeygen
 *
 * @description
 *      Generates the ECDSA public key Q and private key D from domain
 *      parameters passed in by the calling function. This is done in
 *      accordance with FIPS 186-3 Appendix B.4.1
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
 *      delete all data that is not required for further operations
 *****************************************************************************/
CpaStatus fipsSample_ecdsaKeygen(usr_ecdsa_data_t *pEcdsaData);

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
 * @param[in] pEcdsaData        Domain Parameters (description in header file):
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
CpaStatus fipsSample_ecdsaSign(usr_ecdsa_data_t *pEcdsaData);

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
CpaStatus fipsSample_ecdsaVerify(usr_ecdsa_data_t *pEcdsaData);

#endif /*_CPA_FIPS_SAMPLE_ECDSA_H_*/
