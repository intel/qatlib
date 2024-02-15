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

/**
 ***************************************************************************
 * @file lac_sym_qat_hash_defs_lookup.c      Hash Definitions Lookup
 *
 * @ingroup LacHashDefsLookup
 ***************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "lac_common.h"
#include "lac_log.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"
#include "icp_adf_transport.h"
#include "lac_sym.h"
#include "icp_qat_fw_la.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sal_types_crypto.h"
#include "lac_sym_hash_defs.h"
#include "sal_types_compression.h"

/* state size for xcbc mac consists of 3 * 16 byte keys */
#define LAC_SYM_QAT_XCBC_STATE_SIZE ((LAC_HASH_XCBC_MAC_BLOCK_SIZE)*3)

#define LAC_SYM_QAT_CMAC_STATE_SIZE ((LAC_HASH_CMAC_BLOCK_SIZE)*3)

/* This type is used for the mapping between the hash algorithm and
 * the corresponding hash definitions structure */
typedef struct lac_sym_qat_hash_def_map_s
{
    CpaCySymHashAlgorithm hashAlgorithm;
    /* hash algorithm */
    lac_sym_qat_hash_defs_t hashDefs;
    /* hash definitions pointers */
} lac_sym_qat_hash_def_map_t;

/*
*******************************************************************************
* Static Variables
*******************************************************************************
*/

/* initialisers as defined in FIPS and RFCS for digest operations */

/* md5 16 bytes - Initialiser state can be found in RFC 1321*/
STATIC Cpa8U md5InitialState[LAC_HASH_MD5_STATE_SIZE] = {
    0x01,
    0x23,
    0x45,
    0x67,
    0x89,
    0xab,
    0xcd,
    0xef,
    0xfe,
    0xdc,
    0xba,
    0x98,
    0x76,
    0x54,
    0x32,
    0x10,
};

/* SHA1 - 20 bytes - Initialiser state can be found in FIPS stds 180-2 */
STATIC Cpa8U sha1InitialState[LAC_HASH_SHA1_STATE_SIZE] = {
    0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba,
    0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0};

/* SHA 224 - 32 bytes - Initialiser state can be found in FIPS stds 180-2 */
STATIC Cpa8U sha224InitialState[LAC_HASH_SHA224_STATE_SIZE] = {
    0xc1, 0x05, 0x9e, 0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd,
    0x17, 0xf7, 0x0e, 0x59, 0x39, 0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58,
    0x15, 0x11, 0x64, 0xf9, 0x8f, 0xa7, 0xbe, 0xfa, 0x4f, 0xa4};

/* SHA 256 - 32 bytes - Initialiser state can be found in FIPS stds 180-2 */
STATIC Cpa8U sha256InitialState[LAC_HASH_SHA256_STATE_SIZE] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3,
    0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05,
    0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19};

/* SHA 384 - 64 bytes - Initialiser state can be found in FIPS stds 180-2 */
STATIC Cpa8U sha384InitialState[LAC_HASH_SHA384_STATE_SIZE] = {
    0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29,
    0x2a, 0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70,
    0xdd, 0x17, 0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67,
    0x33, 0x26, 0x67, 0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87,
    0x68, 0x58, 0x15, 0x11, 0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f,
    0xa7, 0x47, 0xb5, 0x48, 0x1d, 0xbe, 0xfa, 0x4f, 0xa4};

/* SHA 512 - 64 bytes - Initialiser state can be found in FIPS stds 180-2 */
STATIC Cpa8U sha512InitialState[LAC_HASH_SHA512_STATE_SIZE] = {
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
    0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
    0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
    0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
    0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
    0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

/* SHA3 224 - 28 bytes  */
STATIC Cpa8U sha3_224InitialState[LAC_HASH_SHA3_224_STATE_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* SHA3 256 - 32 bytes  */
STATIC Cpa8U sha3_256InitialState[LAC_HASH_SHA3_256_STATE_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* SHA3 384 - 48 bytes  */
STATIC Cpa8U sha3_384InitialState[LAC_HASH_SHA3_384_STATE_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* SHA3 512 - 64 bytes  */
STATIC Cpa8U sha3_512InitialState[LAC_HASH_SHA3_512_STATE_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* SM3 - 32 bytes */
STATIC Cpa8U sm3InitialState[LAC_HASH_SM3_STATE_SIZE] = {
    0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9, 0x17, 0x24, 0x42,
    0xd7, 0xda, 0x8a, 0x06, 0x00, 0xa9, 0x6f, 0x30, 0xbc, 0x16, 0x31,
    0x38, 0xaa, 0xe3, 0x8d, 0xee, 0x4d, 0xb0, 0xfb, 0x0e, 0x4e
};

/* Constants used in generating K1, K2, K3 from a Key for AES_XCBC_MAC
 * State defined in RFC 3566 */
STATIC Cpa8U aesXcbcKeySeed[LAC_SYM_QAT_XCBC_STATE_SIZE] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
};

STATIC Cpa8U aesCmacKeySeed[LAC_HASH_CMAC_BLOCK_SIZE] = {0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00,
                                                         0x00};

/* Hash Algorithm specific structure */

STATIC lac_sym_qat_hash_alg_info_t md5Info = {LAC_HASH_MD5_DIGEST_SIZE,
                                              LAC_HASH_MD5_BLOCK_SIZE,
                                              md5InitialState,
                                              LAC_HASH_MD5_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha1Info = {LAC_HASH_SHA1_DIGEST_SIZE,
                                               LAC_HASH_SHA1_BLOCK_SIZE,
                                               sha1InitialState,
                                               LAC_HASH_SHA1_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha224Info = {LAC_HASH_SHA224_DIGEST_SIZE,
                                                 LAC_HASH_SHA224_BLOCK_SIZE,
                                                 sha224InitialState,
                                                 LAC_HASH_SHA224_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha256Info = {LAC_HASH_SHA256_DIGEST_SIZE,
                                                 LAC_HASH_SHA256_BLOCK_SIZE,
                                                 sha256InitialState,
                                                 LAC_HASH_SHA256_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha384Info = {LAC_HASH_SHA384_DIGEST_SIZE,
                                                 LAC_HASH_SHA384_BLOCK_SIZE,
                                                 sha384InitialState,
                                                 LAC_HASH_SHA384_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha512Info = {LAC_HASH_SHA512_DIGEST_SIZE,
                                                 LAC_HASH_SHA512_BLOCK_SIZE,
                                                 sha512InitialState,
                                                 LAC_HASH_SHA512_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha3_224Info = {
    LAC_HASH_SHA3_224_DIGEST_SIZE,
    LAC_HASH_SHA3_224_BLOCK_SIZE,
    sha3_224InitialState,
    LAC_HASH_SHA3_224_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha3_256Info = {
    LAC_HASH_SHA3_256_DIGEST_SIZE,
    LAC_HASH_SHA3_256_BLOCK_SIZE,
    sha3_256InitialState,
    LAC_HASH_SHA3_256_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha3_384Info = {
    LAC_HASH_SHA3_384_DIGEST_SIZE,
    LAC_HASH_SHA3_384_BLOCK_SIZE,
    sha3_384InitialState,
    LAC_HASH_SHA3_384_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sha3_512Info = {
    LAC_HASH_SHA3_512_DIGEST_SIZE,
    LAC_HASH_SHA3_512_BLOCK_SIZE,
    sha3_512InitialState,
    LAC_HASH_SHA3_512_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t sm3Info = { LAC_HASH_SM3_DIGEST_SIZE,
                                               LAC_HASH_SM3_BLOCK_SIZE,
                                               sm3InitialState,
                                               LAC_HASH_SM3_STATE_SIZE };

STATIC lac_sym_qat_hash_alg_info_t polyInfo = { LAC_HASH_POLY_DIGEST_SIZE,
                                                LAC_HASH_POLY_BLOCK_SIZE,
                                                NULL, /* initial state */
                                                LAC_HASH_POLY_STATE_SIZE };

STATIC lac_sym_qat_hash_alg_info_t xcbcMacInfo = {
    LAC_HASH_XCBC_MAC_128_DIGEST_SIZE,
    LAC_HASH_XCBC_MAC_BLOCK_SIZE,
    aesXcbcKeySeed,
    LAC_SYM_QAT_XCBC_STATE_SIZE};

STATIC lac_sym_qat_hash_alg_info_t aesCmacInfo = {
    LAC_HASH_CMAC_DIGEST_SIZE,
    LAC_HASH_CMAC_BLOCK_SIZE,
    aesCmacKeySeed,
    LAC_SYM_QAT_CMAC_STATE_SIZE
};

STATIC lac_sym_qat_hash_alg_info_t aesCcmInfo = {
    LAC_HASH_AES_CCM_DIGEST_SIZE,
    LAC_HASH_AES_CCM_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t aesGcmInfo = {
    LAC_HASH_AES_GCM_DIGEST_SIZE,
    LAC_HASH_AES_GCM_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t kasumiF9Info = {
    LAC_HASH_KASUMI_F9_DIGEST_SIZE,
    LAC_HASH_KASUMI_F9_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t snow3gUia2Info = {
    LAC_HASH_SNOW3G_UIA2_DIGEST_SIZE,
    LAC_HASH_SNOW3G_UIA2_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t aesCbcMacInfo = {
    LAC_HASH_AES_CBC_MAC_DIGEST_SIZE,
    LAC_HASH_AES_CBC_MAC_BLOCK_SIZE,
    NULL,
    0};

STATIC lac_sym_qat_hash_alg_info_t zucEia3Info = {
    LAC_HASH_ZUC_EIA3_DIGEST_SIZE,
    LAC_HASH_ZUC_EIA3_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t zuc256mac32Info = {
    LAC_HASH_ZUC_256_MAC_32_DIGEST_SIZE,
    LAC_HASH_ZUC_256_MAC_32_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t zuc256mac64Info = {
    LAC_HASH_ZUC_256_MAC_64_DIGEST_SIZE,
    LAC_HASH_ZUC_256_MAC_64_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t zuc256mac128Info = {
    LAC_HASH_ZUC_256_MAC_128_DIGEST_SIZE,
    LAC_HASH_ZUC_256_MAC_128_BLOCK_SIZE,
    NULL, /* initial state */
    0     /* state size */
};

STATIC lac_sym_qat_hash_alg_info_t aesCmacWatInfo = {
    LAC_HASH_CMAC_BLOCK_SIZE,
    LAC_HASH_CMAC_DIGEST_SIZE,
    NULL, /* initial state */
    0     /* state size */
};
/* Hash QAT specific structures */

STATIC lac_sym_qat_hash_qat_info_t md5Config = {ICP_QAT_HW_AUTH_ALGO_MD5,
                                                LAC_HASH_MD5_BLOCK_SIZE,
                                                ICP_QAT_HW_MD5_STATE1_SZ,
                                                ICP_QAT_HW_MD5_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha1Config = {ICP_QAT_HW_AUTH_ALGO_SHA1,
                                                 LAC_HASH_SHA1_BLOCK_SIZE,
                                                 ICP_QAT_HW_SHA1_STATE1_SZ,
                                                 ICP_QAT_HW_SHA1_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha224Config = {ICP_QAT_HW_AUTH_ALGO_SHA224,
                                                   LAC_HASH_SHA224_BLOCK_SIZE,
                                                   ICP_QAT_HW_SHA224_STATE1_SZ,
                                                   ICP_QAT_HW_SHA224_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha256Config = {ICP_QAT_HW_AUTH_ALGO_SHA256,
                                                   LAC_HASH_SHA256_BLOCK_SIZE,
                                                   ICP_QAT_HW_SHA256_STATE1_SZ,
                                                   ICP_QAT_HW_SHA256_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha384Config = {ICP_QAT_HW_AUTH_ALGO_SHA384,
                                                   LAC_HASH_SHA384_BLOCK_SIZE,
                                                   ICP_QAT_HW_SHA384_STATE1_SZ,
                                                   ICP_QAT_HW_SHA384_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha512Config = {ICP_QAT_HW_AUTH_ALGO_SHA512,
                                                   LAC_HASH_SHA512_BLOCK_SIZE,
                                                   ICP_QAT_HW_SHA512_STATE1_SZ,
                                                   ICP_QAT_HW_SHA512_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha3_224Config = {
    ICP_QAT_HW_AUTH_ALGO_SHA3_224,
    LAC_HASH_SHA3_224_BLOCK_SIZE,
    ICP_QAT_HW_SHA3_224_STATE1_SZ,
    ICP_QAT_HW_SHA3_224_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha3_256Config = {
    ICP_QAT_HW_AUTH_ALGO_SHA3_256,
    LAC_HASH_SHA3_256_BLOCK_SIZE,
    ICP_QAT_HW_SHA3_256_STATE1_SZ,
    ICP_QAT_HW_SHA3_256_STATE2_SZ,
};

STATIC lac_sym_qat_hash_qat_info_t sha3_384Config = {
    ICP_QAT_HW_AUTH_ALGO_SHA3_384,
    LAC_HASH_SHA3_384_BLOCK_SIZE,
    ICP_QAT_HW_SHA3_384_STATE1_SZ,
    ICP_QAT_HW_SHA3_384_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sha3_512Config = {
    ICP_QAT_HW_AUTH_ALGO_SHA3_512,
    LAC_HASH_SHA3_512_BLOCK_SIZE,
    ICP_QAT_HW_SHA3_512_STATE1_SZ,
    ICP_QAT_HW_SHA3_512_STATE2_SZ};

STATIC lac_sym_qat_hash_qat_info_t sm3Config = { ICP_QAT_HW_AUTH_ALGO_SM3,
                                                 LAC_HASH_SM3_BLOCK_SIZE,
                                                 ICP_QAT_HW_SM3_STATE1_SZ,
                                                 ICP_QAT_HW_SM3_STATE2_SZ };

STATIC lac_sym_qat_hash_qat_info_t polyConfig = {ICP_QAT_HW_AUTH_ALGO_POLY,
                                                 LAC_HASH_POLY_BLOCK_SIZE,
                                                 0,
                                                 0};

STATIC lac_sym_qat_hash_qat_info_t xcbcMacConfig = {
    ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC,
    0,
    ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ,
    LAC_SYM_QAT_XCBC_STATE_SIZE
};

STATIC lac_sym_qat_hash_qat_info_t aesCmacConfig = {
    ICP_QAT_HW_AUTH_ALGO_AES_XCBC_MAC,
    0,
    ICP_QAT_HW_AES_XCBC_MAC_STATE1_SZ,
    LAC_SYM_QAT_CMAC_STATE_SIZE
};

STATIC lac_sym_qat_hash_qat_info_t aesCcmConfig = {
    ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC,
    0,
    ICP_QAT_HW_AES_CBC_MAC_STATE1_SZ,
    ICP_QAT_HW_AES_CBC_MAC_KEY_SZ + ICP_QAT_HW_AES_CCM_CBC_E_CTR0_SZ
};

STATIC lac_sym_qat_hash_qat_info_t aesGcmConfig = {
    ICP_QAT_HW_AUTH_ALGO_GALOIS_128,
    0,
    ICP_QAT_HW_GALOIS_128_STATE1_SZ,
    ICP_QAT_HW_GALOIS_H_SZ + ICP_QAT_HW_GALOIS_LEN_A_SZ +
        ICP_QAT_HW_GALOIS_E_CTR0_SZ
};

STATIC lac_sym_qat_hash_qat_info_t kasumiF9Config = {
    ICP_QAT_HW_AUTH_ALGO_KASUMI_F9,
    0,
    ICP_QAT_HW_KASUMI_F9_STATE1_SZ,
    ICP_QAT_HW_KASUMI_F9_STATE2_SZ
};

STATIC lac_sym_qat_hash_qat_info_t snow3gUia2Config = {
    ICP_QAT_HW_AUTH_ALGO_SNOW_3G_UIA2,
    0,
    ICP_QAT_HW_SNOW_3G_UIA2_STATE1_SZ,
    ICP_QAT_HW_SNOW_3G_UIA2_STATE2_SZ
};

STATIC lac_sym_qat_hash_qat_info_t aesCbcMacConfig = {
    ICP_QAT_HW_AUTH_ALGO_AES_CBC_MAC,
    0,
    ICP_QAT_HW_AES_CBC_MAC_STATE1_SZ,
    ICP_QAT_HW_AES_CBC_MAC_STATE1_SZ + ICP_QAT_HW_AES_CBC_MAC_STATE1_SZ
};

STATIC lac_sym_qat_hash_qat_info_t zucEia3Config = {
    ICP_QAT_HW_AUTH_ALGO_ZUC_3G_128_EIA3,
    0,
    ICP_QAT_HW_ZUC_3G_EIA3_STATE1_SZ,
    ICP_QAT_HW_ZUC_3G_EIA3_STATE2_SZ
};

STATIC lac_sym_qat_hash_qat_info_t zuc256mac32Config = {
    ICP_QAT_HW_AUTH_ALGO_ZUC_256_MAC_32,
    0,
    ICP_QAT_HW_ZUC_256_MAC_32_STATE1_SZ,
    ICP_QAT_HW_ZUC_256_STATE2_SZ
};

STATIC lac_sym_qat_hash_qat_info_t zuc256mac64Config = {
    ICP_QAT_HW_AUTH_ALGO_ZUC_256_MAC_64,
    0,
    ICP_QAT_HW_ZUC_256_MAC_64_STATE1_SZ,
    ICP_QAT_HW_ZUC_256_STATE2_SZ
};

STATIC lac_sym_qat_hash_qat_info_t zuc256mac128Config = {
    ICP_QAT_HW_AUTH_ALGO_ZUC_256_MAC_128,
    0,
    ICP_QAT_HW_ZUC_256_MAC_128_STATE1_SZ,
    ICP_QAT_HW_ZUC_256_STATE2_SZ
};

STATIC lac_sym_qat_hash_defs_t zuc256Mac32HashDefs = { &zuc256mac32Info,
                                                       &zuc256mac32Config };
STATIC lac_sym_qat_hash_defs_t zuc256Mac64HashDefs = { &zuc256mac64Info,
                                                       &zuc256mac64Config };
STATIC lac_sym_qat_hash_defs_t zuc256Mac128HashDefs = { &zuc256mac128Info,
                                                        &zuc256mac128Config };

STATIC lac_sym_qat_hash_qat_info_t aes192CmacConfig = {
    ICP_QAT_HW_AUTH_ALGO_AES_192_CMAC,
    0,
    ICP_QAT_HW_AES_CMAC_STATE1_SZ,
    ICP_QAT_HW_AES_192_CMAC_STATE2_SZ
};

STATIC lac_sym_qat_hash_qat_info_t aes256CmacConfig = {
    ICP_QAT_HW_AUTH_ALGO_AES_256_CMAC,
    0,
    ICP_QAT_HW_AES_CMAC_STATE1_SZ,
    ICP_QAT_HW_AES_256_CMAC_STATE2_SZ
};

STATIC lac_sym_qat_hash_defs_t aes192MacHashDefs = { &aesCmacWatInfo,
                                                     &aes192CmacConfig };
STATIC lac_sym_qat_hash_defs_t aes256MacHashDefs = { &aesCmacWatInfo,
                                                     &aes256CmacConfig };

/* Array of mappings between algorithm and info structure
 * This array is used to populate the lookup table */
STATIC lac_sym_qat_hash_def_map_t lacHashDefsMapping[] = {
    { CPA_CY_SYM_HASH_MD5, { &md5Info, &md5Config } },
    { CPA_CY_SYM_HASH_SHA1, { &sha1Info, &sha1Config } },
    { CPA_CY_SYM_HASH_SHA224, { &sha224Info, &sha224Config } },
    { CPA_CY_SYM_HASH_SHA256, { &sha256Info, &sha256Config } },
    { CPA_CY_SYM_HASH_SHA384, { &sha384Info, &sha384Config } },
    { CPA_CY_SYM_HASH_SHA512, { &sha512Info, &sha512Config } },
    { CPA_CY_SYM_HASH_SHA3_224, { &sha3_224Info, &sha3_224Config } },
    { CPA_CY_SYM_HASH_SHA3_256, { &sha3_256Info, &sha3_256Config } },
    { CPA_CY_SYM_HASH_SHA3_384, { &sha3_384Info, &sha3_384Config } },
    { CPA_CY_SYM_HASH_SHA3_512, { &sha3_512Info, &sha3_512Config } },
    { CPA_CY_SYM_HASH_POLY, { &polyInfo, &polyConfig } },
    { CPA_CY_SYM_HASH_SM3, { &sm3Info, &sm3Config } },
    { CPA_CY_SYM_HASH_AES_XCBC, { &xcbcMacInfo, &xcbcMacConfig } },
    { CPA_CY_SYM_HASH_AES_CMAC, { &aesCmacInfo, &aesCmacConfig } },
    { CPA_CY_SYM_HASH_AES_CCM, { &aesCcmInfo, &aesCcmConfig } },
    { CPA_CY_SYM_HASH_AES_GCM, { &aesGcmInfo, &aesGcmConfig } },
    { CPA_CY_SYM_HASH_KASUMI_F9, { &kasumiF9Info, &kasumiF9Config } },
    { CPA_CY_SYM_HASH_SNOW3G_UIA2, { &snow3gUia2Info, &snow3gUia2Config } },
    { CPA_CY_SYM_HASH_AES_GMAC, { &aesGcmInfo, &aesGcmConfig } },
    { CPA_CY_SYM_HASH_ZUC_EIA3, { &zucEia3Info, &zucEia3Config } },
    { CPA_CY_SYM_HASH_AES_CBC_MAC, { &aesCbcMacInfo, &aesCbcMacConfig } }
};

/*
 * LacSymQat_HashLookupInit
 */
CpaStatus LacSymQat_HashLookupInit(CpaInstanceHandle instanceHandle)
{
    Cpa32U entry = 0;
    Cpa32U numEntries = 0;
    Cpa32U arraySize = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymHashAlgorithm hashAlg = CPA_CY_SYM_HASH_NONE;
    sal_service_t *pService = (sal_service_t *)instanceHandle;
    lac_sym_qat_hash_defs_t **pLacHashLookupDefs;

    arraySize = (CPA_CY_HASH_ALG_END + 1) * sizeof(lac_sym_qat_hash_defs_t *);
    /* Size round up for performance */
    arraySize = LAC_ALIGN_POW2_ROUNDUP(arraySize, LAC_64BYTE_ALIGNMENT);

    status = LAC_OS_MALLOC(&pLacHashLookupDefs, arraySize);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    LAC_OS_BZERO(pLacHashLookupDefs, arraySize);
    numEntries =
        sizeof(lacHashDefsMapping) / sizeof(lac_sym_qat_hash_def_map_t);

    /* initialise the hash lookup definitions table so that the algorithm
     * can be used to index into the table */
    for (entry = 0; entry < numEntries; entry++)
    {
        hashAlg = lacHashDefsMapping[entry].hashAlgorithm;

        pLacHashLookupDefs[hashAlg] = &(lacHashDefsMapping[entry].hashDefs);
    }

    if (SAL_SERVICE_TYPE_COMPRESSION == pService->type)
    {
        ((sal_compression_service_t *)pService)
            ->pDcChainService->pLacHashLookupDefs = pLacHashLookupDefs;
    }
    else
    {
        ((sal_crypto_service_t *)pService)->pLacHashLookupDefs =
            pLacHashLookupDefs;
    }

    return status;
}

/*
 * LacSymQat_HashAlgLookupGet
 */
void LacSymQat_HashAlgLookupGet(CpaInstanceHandle instanceHandle,
                                CpaCySymHashAlgorithm hashAlgorithm,
                                lac_sym_qat_hash_alg_info_t **ppHashAlgInfo,
                                Cpa32U authKeyLenInBytes,
                                Cpa32U digestResultLenInBytes)
{
    sal_service_t *pService = (sal_service_t *)instanceHandle;
    lac_sym_qat_hash_defs_t **pLacHashLookupDefs;

    if (SAL_SERVICE_TYPE_COMPRESSION == pService->type)
    {
        pLacHashLookupDefs = ((sal_compression_service_t *)pService)
                                 ->pDcChainService->pLacHashLookupDefs;
    }
    else
    {
        pLacHashLookupDefs =
            ((sal_crypto_service_t *)pService)->pLacHashLookupDefs;
    }

    LAC_ENSURE_NOT_NULL(ppHashAlgInfo);
    LAC_ENSURE(pLacHashLookupDefs[hashAlgorithm] != NULL,
               "hashInfo entry should not be NULL\n");
    LAC_ENSURE(pLacHashLookupDefs[hashAlgorithm]->algInfo != NULL,
               "hash alg Info should not be NULL\n");

    *ppHashAlgInfo = pLacHashLookupDefs[hashAlgorithm]->algInfo;
    if ((hashAlgorithm == CPA_CY_SYM_HASH_ZUC_EIA3) &&
        (authKeyLenInBytes == ICP_QAT_HW_ZUC_256_KEY_SZ))
    {
        if (digestResultLenInBytes == LAC_HASH_ZUC_256_MAC_32_DIGEST_SIZE)
        {
            *ppHashAlgInfo = &zuc256mac32Info;
        }
        else if (digestResultLenInBytes == LAC_HASH_ZUC_256_MAC_64_DIGEST_SIZE)
        {
            *ppHashAlgInfo = &zuc256mac64Info;
        }
        else
        {
            *ppHashAlgInfo = &zuc256mac128Info;
        }
    }
    else if ((hashAlgorithm == CPA_CY_SYM_HASH_AES_CMAC) &&
             (authKeyLenInBytes != ICP_QAT_HW_AES_128_KEY_SZ))
    {
        *ppHashAlgInfo = &aesCmacWatInfo;
    }
}

/*
 * LacSymQat_HashDefsLookupGet
 */
void LacSymQat_HashDefsLookupGet(CpaInstanceHandle instanceHandle,
                                 CpaCySymHashAlgorithm hashAlgorithm,
                                 lac_sym_qat_hash_defs_t **ppHashDefsInfo,
                                 Cpa32U authKeyLenInBytes,
                                 Cpa32U digestResultLenInBytes)
{
    sal_service_t *pService = (sal_service_t *)instanceHandle;
    lac_sym_qat_hash_defs_t **pLacHashLookupDefs;

    if (SAL_SERVICE_TYPE_COMPRESSION == pService->type)
    {
        pLacHashLookupDefs = ((sal_compression_service_t *)pService)
                                 ->pDcChainService->pLacHashLookupDefs;
    }
    else
    {
        pLacHashLookupDefs =
            ((sal_crypto_service_t *)pService)->pLacHashLookupDefs;
    }

    LAC_ENSURE_NOT_NULL(ppHashDefsInfo);
    LAC_ENSURE(pLacHashLookupDefs[hashAlgorithm] != NULL,
               "hashInfo should not be NULL\n");
    LAC_ENSURE(pLacHashLookupDefs[hashAlgorithm]->algInfo != NULL,
               "hash algInfo should not be NULL\n");
    LAC_ENSURE(pLacHashLookupDefs[hashAlgorithm]->qatInfo != NULL,
               "hash qatInfo should not be NULL\n");
    *ppHashDefsInfo = pLacHashLookupDefs[hashAlgorithm];
    if ((hashAlgorithm == CPA_CY_SYM_HASH_ZUC_EIA3) &&
        (authKeyLenInBytes == ICP_QAT_HW_ZUC_256_KEY_SZ))
    {
        if (digestResultLenInBytes == LAC_HASH_ZUC_256_MAC_32_DIGEST_SIZE)
        {
            *ppHashDefsInfo = &zuc256Mac32HashDefs;
        }
        else if (digestResultLenInBytes == LAC_HASH_ZUC_256_MAC_64_DIGEST_SIZE)
        {
            *ppHashDefsInfo = &zuc256Mac64HashDefs;
        }
        else
        {
            *ppHashDefsInfo = &zuc256Mac128HashDefs;
        }
    }
    else if (hashAlgorithm == CPA_CY_SYM_HASH_AES_CMAC)
    {
        if (authKeyLenInBytes == ICP_QAT_HW_AES_192_KEY_SZ)
        {
            *ppHashDefsInfo = &aes192MacHashDefs;
        }
        else if (authKeyLenInBytes == ICP_QAT_HW_AES_256_KEY_SZ)
        {
            *ppHashDefsInfo = &aes256MacHashDefs;
        }
    }
}
