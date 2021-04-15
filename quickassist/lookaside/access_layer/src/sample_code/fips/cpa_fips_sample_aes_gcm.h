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
 * @file cpa_fips_sample_aes_gcm.h
 *
 * @defgroup fipsSampleGcm FIPS sample code for the GCM algorithm
 *
 * @ingroup fipsSample
 *
 * @description
 * This header file contains function prototypes and structure definitions for
 * running the FIPS Cy GCM implementation functions
 *
 *****************************************************************************/

#ifndef _CPA_FIPS_SAMPLE_AES_GCM_H_
#define _CPA_FIPS_SAMPLE_AES_GCM_H_

#include "cpa_cy_sym.h"

/**
 *****************************************************************************
 * GCM definitions, enums and structures
 *****************************************************************************/
/**
 * Galois Multiply 'R' value top byte (FIPS 800-38D, section 6.3)
 **/
#define FIPS_SAMPLE_GALOIS_MULTIPLY_CONSTANT_TOP_BYTE (0xE1)
/**
 * Maximum storage size for the GCM key
 **/
#define FIPS_SAMPLE_GCM_MAX_KEYLEN_BYTES (32)
/**
 * GHASH operates on buffers of 16 Bytes
 **/
#define FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE (16)
/**
 * Get the index of the last byte of a GHASH input buffer
 **/
#define FIPS_SAMPLE_GHASH_INPUT_BUFFER_LAST_BYTE_INDEX                         \
    (FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE - 1)
/**
 * Constant used for the 16 byte IV case
 **/
#define FIPS_SAMPLE_GCM_16_BYTE_IV_LENGTH (16)
/**
 * Constant used for the 12 byte IV case
 **/
#define FIPS_SAMPLE_GCM_12_BYTE_IV_LENGTH (12)
/**
 * FIPS 800-38D specifies at least 128 bits of padding for the initial value
 * of J0 (before the GHASH operation is applied)
 **/
#define FIPS_SAMPLE_J0_PADDING_LEN_IN_BYTES (16)

/**
 * Supported keylengths for GCM
 **/
#define FIPS_SAMPLE_KEYLEN_16_BYTES (16)
#define FIPS_SAMPLE_KEYLEN_24_BYTES (24)
#define FIPS_SAMPLE_KEYLEN_32_BYTES (32)

/**
 * Supported Tag lengths for GCM
 **/
#define FIPS_SAMPLE_GCM_SUPPORTED_TAG_LEN_8_BYTES (8)
#define FIPS_SAMPLE_GCM_SUPPORTED_TAG_LEN_12_BYTES (12)
#define FIPS_SAMPLE_GCM_SUPPORTED_TAG_LEN_16_BYTES (16)

/**
 * This enum defines the modes that this GCM implementation supports. GCM mode
 * gives full authentication/verification and encrypt/decrypt. GMAC mode gives
 * only authentication/verification based on Plain Text inputs.
 **/
typedef enum
{
    GCM_MODE = 0,
    GMAC_MODE
} gcm_mode_t;

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      usrGcmData
 *
 * @description
 *      Structure for all GCM operations. Memory required to store function
 *      outputs MUST be allocated before calling a fipsSample_xxx fuction.
 *****************************************************************************/
typedef struct usr_gcm_data_s
{
    Cpa8U cipherKey[FIPS_SAMPLE_GCM_MAX_KEYLEN_BYTES];
    /*Cipher Key to be used for the GCM algorithm. This must be stored in
      a contiguous data buffer.*/
    Cpa32U cipherKeyLength;
    /*Cipher Key Length
      Support sizes are 16, 24, 32 bytes*/
    CpaCySymCipherDirection cipherDirection;
    /*Specifies whether the operation is Encrypt or Decrypt*/
    Cpa32U digestResultLenInBytes;
    /*Expected Tag length for the GCM operation*/
    CpaFlatBuffer mesg;
    /*This is the input message (plaintext for encrypt,
      ciphertext for decrypt. If this buffer has zero length, the
      dataLenInBytes descriptor must be set to 0 and the pData pointer
      set to NULL.*/
    CpaFlatBuffer mesgResult;
    /*The result of the decrypt operation, must have equal length to the
      mesg buffer*/
    CpaFlatBuffer digestResult;
    /*Result GCM tag or value to verify*/
    CpaFlatBuffer additionalAuthData;
    /*Additional Auth Data for the GCM algorithm. This may have zero length.
      Max size is 240 bytes*/
    CpaFlatBuffer iV;
    /*Initialization Vector for GCM*/
    CpaBoolean resultVerified;
    /*When doing a message signature verification, this value is set to
      CPA_TRUE if the signature is valid or CPA_FALSE if the signature is
      invalid.*/
    gcm_mode_t gcmMode;
    /*GCM algorithm can be run in GMAC mode. In GMAC_MODE, in the encrypt
      path, only authentication data is generated (no cipher text). In the
      decrypt path, the authentication data is verified based on plaintext
      input.*/
} usr_gcm_data_t;

/**
 *****************************************************************************
 * GCM function prototypes
 *****************************************************************************/

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      fipsSample_aesGcm
 *
 * @description
 *      This function implemented GCM and GMAC modes of operation based on
 *      FIPS 800-38D standard. In GCM mode, full authentication/verification
 *      and encrypt/decrypt is performed. GMAC mode gives only
 *      authentication/verification based on Plain Text inputs.
 *
 * @param[in,out] pGcmData   Structure containing all the data needed to
 *                           perform the AES-GCM operations. The caller
 *                           must allocate all memory associated with this
 *                           structure.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_aesGcm(usr_gcm_data_t *pGcmData);

CpaStatus sampleCyStartPolling(CpaInstanceHandle cyInstHandle);

void sampleCyStopPolling(void);

#endif /*_CPA_FIPS_SAMPLE_AES_GCM_H_*/
