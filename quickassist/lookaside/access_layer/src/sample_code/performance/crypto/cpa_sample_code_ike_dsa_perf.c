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
 *****************************************************************************
 * @file cpa_sample_code_ike_dsa_perf.c
 *
 * @ingroup cryptoThreads
 *
 * @description
 *      This file contains code which chains QA API functions together to
 *      simulate IKE, over all flow of data is as follows:
 *
 * 1. Alice & Bob generate public & private DSA keys
 *    we generated a third DSA key set to act as a trusted third party
 * 2. Alice & Bob agree on a p & g and generate secret random x
 * 3. Alice & Bob Perform DH Phase1 to produce Public Value - PV = g^x mod p
 * 4. Bob Perform DH Phase2 to produce Secret Key SK = alicePV^x mod p
 * 5. Sign Bobs Public Value using peers public key -> DSA decrypt bobsPV
 * 6. Setup Alices Decrypt and Diffie Hellman Data for performance Loop
 * 7. IKE main mode Asymmetric steps
 *      7a Perform DH phase1 for Alice alicePV = g^x mod p
 *      7b Perform DSA verify of third party: bobsPV = DSA encrypt bobsSig
 *      7c Perform DSA verify of Bobs signed public values (same as 7b)
 *      7d Sign all of Alices public value buffers DSA decrypt alicesPV
 *      7e Perform the DH phase2 operation for Alice
 *          SK = bobsPV(from 7b)^x mod p
 *
 *****************************************************************************/
#include "cpa_cy_dsa.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_utils_common.h"

/*This is the number of DSA and Diffie Hellman QA APIs chained together in
 * which performance is measured against*/
#define NUMBER_OF_CHAINED_OPS (5)
#define ONE_LOOP (1)
#define ONE_BUFFER (1)
#define NUMBER_OF_RSA_VERIFIES (2)

#define IKEDSA_DEFAULT_H_VALUE (2)

extern void dsaGenRandom(CpaFlatBuffer *dsaRand, CpaFlatBuffer *dsaQ);
extern CpaStatus dsaGenG(CpaInstanceHandle instanceHandle,
                         CpaCyDsaGParamGenOpData *gOpData,
                         CpaFlatBuffer *dsaG);
extern CpaStatus dsaGenY(CpaInstanceHandle instanceHandle,
                         CpaCyDsaYParamGenOpData *yOpData,
                         CpaFlatBuffer *dsaY);
extern CpaStatus dsaGenRS(CpaInstanceHandle instanceHandle,
                          CpaCyDsaRSSignOpData *rsOpData,
                          CpaFlatBuffer *dsaR,
                          CpaFlatBuffer *dsaS);
CpaStatus dsaGenZ(CpaInstanceHandle instanceHandle,
                  CpaFlatBuffer *msg,
                  CpaCySymHashAlgorithm hashAlg,
                  CpaFlatBuffer *dsaZ);

/*****************************************************************
 * Declare a static 1024/160 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U ikedsa_1024_160_p[] = {
    0xEA, 0xE2, 0xE2, 0x08, 0xBC, 0x34, 0x79, 0xAF, 0x6C, 0xD9, 0x90, 0xC8,
    0xB6, 0x17, 0x0D, 0x33, 0x31, 0xDF, 0x22, 0xBB, 0x2D, 0x54, 0x64, 0x76,
    0x98, 0xD5, 0x5A, 0x53, 0xE1, 0x14, 0xBE, 0x73, 0xDA, 0x89, 0xC6, 0x2D,
    0x39, 0x00, 0x69, 0xA5, 0x42, 0x14, 0x90, 0x7E, 0x2F, 0x67, 0x31, 0xF0,
    0xC2, 0x4B, 0xAC, 0x7E, 0x4C, 0xCF, 0xE9, 0x48, 0xFD, 0x67, 0xD8, 0x5E,
    0x6B, 0x08, 0x65, 0x55, 0x56, 0xE0, 0xB3, 0xDE, 0x62, 0x23, 0xE2, 0xCF,
    0x85, 0x9E, 0x6E, 0x4D, 0x07, 0xC2, 0x95, 0xAA, 0x46, 0x1C, 0xE5, 0xE5,
    0x97, 0x1F, 0x97, 0x67, 0xAC, 0x6B, 0xAB, 0x39, 0x87, 0x17, 0x66, 0x92,
    0x67, 0xC1, 0x97, 0x13, 0x3F, 0xF1, 0xB3, 0x98, 0x1B, 0x73, 0x09, 0x6D,
    0x58, 0x25, 0xA5, 0xEF, 0x71, 0x93, 0x99, 0x8F, 0xB0, 0x81, 0x23, 0x48,
    0xAF, 0xD9, 0x3A, 0xDB, 0xDB, 0x03, 0x0E, 0xFB};

static Cpa8U ikedsa_1024_160_q[] = {0x9D, 0x6D, 0x96, 0xC4, 0xB8, 0x69, 0x37,
                                    0xC1, 0x60, 0x6D, 0x6E, 0xBA, 0x37, 0x5C,
                                    0x46, 0x25, 0x49, 0x3C, 0x50, 0x33};

/*****************************************************************
 * Declare a static 2048/224 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U ikedsa_2048_224_p[] = {
    0xb9, 0x8f, 0x24, 0x95, 0x41, 0x14, 0x86, 0x5f, 0xc2, 0xaf, 0xf1, 0x80,
    0x92, 0x2b, 0x33, 0x46, 0xaa, 0xcf, 0xec, 0x30, 0x90, 0x3c, 0x2b, 0xa8,
    0x87, 0xd6, 0x59, 0x15, 0x14, 0xfe, 0xa1, 0xff, 0x00, 0xe6, 0x95, 0xf4,
    0x7f, 0x3d, 0xa3, 0x37, 0x9e, 0x41, 0x1c, 0xd4, 0xf4, 0x00, 0x78, 0xb1,
    0x68, 0x88, 0x2e, 0x32, 0xa4, 0x8e, 0xc1, 0xb5, 0x05, 0x85, 0x22, 0x4c,
    0x83, 0x3a, 0x5e, 0x8e, 0x48, 0x9f, 0x62, 0x24, 0xa6, 0xb6, 0x95, 0xf1,
    0xb0, 0xe3, 0xa2, 0x18, 0xc6, 0x72, 0xf3, 0xcb, 0xe1, 0x42, 0x44, 0x16,
    0x3d, 0x29, 0x39, 0xb8, 0x7f, 0xf8, 0xe3, 0xe7, 0xb1, 0xd3, 0xc8, 0x06,
    0x6f, 0x6f, 0x1c, 0x84, 0x94, 0x90, 0x21, 0x75, 0xe6, 0x10, 0xda, 0x5b,
    0x45, 0xdf, 0xc2, 0xa2, 0xc0, 0x41, 0xb7, 0x07, 0xdf, 0x77, 0x37, 0xc5,
    0xe2, 0x4b, 0x99, 0x5b, 0x09, 0x37, 0xf5, 0xc5, 0xbc, 0x85, 0x2f, 0xde,
    0x6e, 0x71, 0xd6, 0xef, 0xaa, 0xc7, 0x4b, 0xbc, 0xe8, 0x5c, 0xe6, 0xcf,
    0x7b, 0x2a, 0x3c, 0x70, 0xd1, 0x67, 0xc2, 0x1d, 0xae, 0xde, 0x7e, 0x6c,
    0x9e, 0xfd, 0xf0, 0xee, 0x06, 0xbc, 0x29, 0xde, 0x68, 0xe1, 0xac, 0x52,
    0xe5, 0xdd, 0xa5, 0xd2, 0x76, 0x12, 0x62, 0x8a, 0x66, 0x90, 0xbe, 0xc7,
    0xc2, 0x42, 0xbc, 0xd0, 0xa6, 0x28, 0x47, 0xe2, 0x37, 0x86, 0xa6, 0x12,
    0x7f, 0x24, 0x83, 0x99, 0x51, 0xdf, 0xec, 0x51, 0x95, 0xc9, 0x2c, 0xb2,
    0x3e, 0x9c, 0x83, 0xa0, 0xd7, 0x5f, 0x18, 0xb7, 0xd9, 0x31, 0x55, 0xcb,
    0x05, 0x2f, 0xb5, 0xa8, 0x6f, 0x13, 0xf3, 0x31, 0x28, 0x5b, 0x55, 0x81,
    0x53, 0xc3, 0xdb, 0x06, 0x21, 0x13, 0x93, 0xd9, 0xef, 0x54, 0x36, 0x35,
    0x1b, 0x39, 0x0c, 0x94, 0x8f, 0x4f, 0x78, 0x68, 0x8f, 0xbf, 0x99, 0xfd,
    0x6c, 0x86, 0x71, 0xf9};

static Cpa8U ikedsa_2048_224_q[] = {0x8a, 0xad, 0x30, 0x8a, 0x52, 0x54, 0x0f,
                                    0x30, 0xf9, 0xe4, 0x8b, 0x0b, 0xe0, 0xfd,
                                    0x3e, 0x8d, 0xa1, 0xba, 0xd8, 0x07, 0x63,
                                    0x8b, 0x40, 0x38, 0x30, 0x25, 0x81, 0x93};

/*****************************************************************
 * Declare a static 2048/256 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U ikedsa_2048_256_p[] = {
    0x92, 0xf2, 0x30, 0x17, 0x69, 0x5c, 0x21, 0x41, 0x61, 0x53, 0xf9, 0x5f,
    0xbe, 0x0a, 0x7b, 0x78, 0x5d, 0xec, 0xea, 0x3b, 0x93, 0xd1, 0xf0, 0xd8,
    0xe8, 0x16, 0xb9, 0x47, 0x75, 0xca, 0xeb, 0xf6, 0x5a, 0x4a, 0xc9, 0x95,
    0x22, 0x80, 0x38, 0x13, 0x6a, 0xd7, 0xe6, 0x21, 0x3a, 0x44, 0xd3, 0x99,
    0xc0, 0xc7, 0x70, 0xf6, 0x28, 0xbe, 0x04, 0x99, 0x9b, 0xa1, 0x7d, 0x34,
    0x63, 0x70, 0x0e, 0xf2, 0x23, 0xbe, 0x7c, 0xe4, 0x79, 0xe4, 0x23, 0x70,
    0xdc, 0x5f, 0xd8, 0x79, 0x0e, 0x6c, 0xbf, 0x03, 0xee, 0xe4, 0x79, 0xd4,
    0xce, 0xf1, 0x3d, 0x93, 0xd6, 0xd2, 0xa4, 0x2e, 0xf2, 0x28, 0x3a, 0x82,
    0xb8, 0x63, 0xa5, 0xe6, 0x06, 0x99, 0xa1, 0x67, 0xc7, 0x82, 0xa9, 0x0d,
    0xfd, 0xbc, 0x67, 0xb5, 0x63, 0xd8, 0xd0, 0xd2, 0xf3, 0x51, 0xe7, 0x1d,
    0xfa, 0xb2, 0x9a, 0x62, 0xbf, 0x65, 0x98, 0x72, 0x28, 0x78, 0x0d, 0x3e,
    0x40, 0xb6, 0x88, 0x2e, 0x1d, 0x5d, 0xbb, 0x8c, 0x70, 0x79, 0x68, 0x9e,
    0x06, 0xda, 0xe9, 0xb0, 0x2f, 0xa1, 0x16, 0x83, 0x14, 0x93, 0xf9, 0x1f,
    0xcd, 0x79, 0x41, 0x07, 0x42, 0x56, 0x13, 0x05, 0x29, 0xaa, 0x99, 0x7d,
    0x2c, 0xad, 0xa4, 0xa8, 0xf0, 0xfb, 0x58, 0x23, 0x31, 0x89, 0xc0, 0xa0,
    0xda, 0x75, 0xb1, 0xe8, 0xcb, 0x4d, 0x18, 0x99, 0xfe, 0x86, 0x3b, 0x9b,
    0x2b, 0x64, 0xca, 0x79, 0xc0, 0x97, 0xd3, 0xfc, 0xb4, 0x95, 0xd2, 0x69,
    0xe1, 0xb9, 0xb4, 0xbd, 0xd1, 0xfa, 0x32, 0x3d, 0x98, 0x08, 0x87, 0x03,
    0x8b, 0x4c, 0x17, 0x78, 0x99, 0x73, 0xe3, 0x3d, 0x2d, 0xef, 0xe1, 0x93,
    0x39, 0xda, 0x21, 0xdc, 0x23, 0x1c, 0x98, 0x56, 0x3c, 0x70, 0x60, 0x5d,
    0x55, 0x17, 0x7a, 0x23, 0x35, 0x45, 0x42, 0xa6, 0x33, 0x90, 0xeb, 0x19,
    0x39, 0x18, 0xd6, 0x7b};

static Cpa8U ikedsa_2048_256_q[] = {
    0xa3, 0x4f, 0x3a, 0xaa, 0x84, 0x9b, 0x1e, 0x28, 0xd3, 0x82, 0x3b,
    0x89, 0x6f, 0xb6, 0xe2, 0x0f, 0xfe, 0x07, 0xdb, 0xe4, 0x85, 0xa5,
    0x81, 0x6c, 0xbb, 0x14, 0x3f, 0x97, 0xf1, 0x47, 0x6a, 0xf9};
/*****************************************************************
 * Declare a static 3072/256 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U ikedsa_3072_256_p[] = {
    0xa3, 0x78, 0x53, 0xcf, 0x35, 0x04, 0x0d, 0xb2, 0x07, 0x24, 0x2b, 0xab,
    0x21, 0xd0, 0xa3, 0x9a, 0xb5, 0xa5, 0x25, 0x22, 0xac, 0xb3, 0x06, 0xe4,
    0xdc, 0x04, 0x7b, 0xa5, 0xb9, 0xc3, 0xe5, 0x34, 0x4a, 0x23, 0x42, 0xfd,
    0x6c, 0x5d, 0x61, 0x28, 0x06, 0x90, 0xe3, 0x9a, 0x4a, 0xab, 0x7b, 0xd7,
    0x25, 0x84, 0x0d, 0x95, 0xe2, 0xda, 0x53, 0xb7, 0x49, 0xfc, 0xbf, 0xcf,
    0xa2, 0xd6, 0x9b, 0xf9, 0x17, 0x0b, 0x6e, 0xef, 0x65, 0xbf, 0xf7, 0xc2,
    0x42, 0x8d, 0x65, 0x9f, 0xe0, 0x0c, 0x47, 0x8c, 0xa1, 0xaf, 0xf4, 0x1b,
    0x10, 0x36, 0xe6, 0x8e, 0x95, 0x22, 0xaa, 0xc3, 0xee, 0xb7, 0x85, 0x15,
    0xf1, 0xaf, 0x29, 0xff, 0xc1, 0x38, 0xaa, 0x27, 0x48, 0x4e, 0x12, 0xad,
    0xf9, 0x2e, 0xec, 0x85, 0x1e, 0x54, 0x8f, 0x19, 0x21, 0x08, 0x14, 0xb3,
    0x16, 0x64, 0x06, 0x4c, 0x4d, 0x7e, 0x30, 0xe9, 0x45, 0x49, 0x13, 0x7a,
    0x0b, 0x7d, 0x06, 0x14, 0x92, 0xb6, 0xa8, 0x51, 0x7a, 0xe2, 0xed, 0xd9,
    0xae, 0x31, 0x06, 0xe3, 0x5b, 0xcf, 0xea, 0x28, 0xb7, 0x3f, 0xec, 0x34,
    0x16, 0xff, 0x40, 0x41, 0x65, 0x7e, 0x97, 0xad, 0x4a, 0xcb, 0x78, 0x87,
    0xea, 0xf2, 0xb7, 0xa0, 0x2b, 0xcd, 0x8e, 0xe1, 0xb0, 0x5d, 0x99, 0x1e,
    0x81, 0xca, 0xe7, 0x7d, 0xf2, 0xd1, 0x57, 0xdb, 0x95, 0x8f, 0xd4, 0x81,
    0xc6, 0xed, 0x00, 0x47, 0xe3, 0x84, 0xdf, 0x75, 0xf0, 0x9c, 0xec, 0xca,
    0x34, 0x1f, 0xb2, 0xe8, 0x38, 0xc7, 0x19, 0xaf, 0x4d, 0xd1, 0xe4, 0xf1,
    0x80, 0x83, 0xbd, 0x31, 0x48, 0x74, 0xd0, 0x97, 0x7c, 0xf6, 0x1b, 0x03,
    0xcc, 0xf3, 0x00, 0x2d, 0x90, 0x3f, 0x1d, 0x1f, 0x94, 0x6f, 0x47, 0x46,
    0xb3, 0x04, 0x6a, 0x14, 0x4a, 0xb0, 0x75, 0x9c, 0x3f, 0x40, 0x1e, 0x31,
    0x52, 0x26, 0xfe, 0x9a, 0x4e, 0x6f, 0xde, 0x00, 0xc4, 0x54, 0xe4, 0xf9,
    0x0e, 0x4a, 0x14, 0x87, 0x99, 0x81, 0xd9, 0x8f, 0x6e, 0xdc, 0xa2, 0xdd,
    0xab, 0xcf, 0xe0, 0x78, 0x3a, 0xe9, 0xfd, 0x84, 0xd0, 0xf2, 0xb0, 0xcb,
    0x74, 0xef, 0xa8, 0x27, 0x6f, 0xbf, 0xe4, 0xa1, 0x52, 0x5d, 0x39, 0xd1,
    0x28, 0x09, 0x76, 0x78, 0xa9, 0x32, 0x18, 0x9d, 0x57, 0xe1, 0x97, 0x29,
    0x29, 0x5c, 0xf3, 0xb9, 0x70, 0x3b, 0x4b, 0x2a, 0x2d, 0x5e, 0x98, 0x0d,
    0x90, 0xcb, 0xa7, 0xd1, 0xd1, 0x9f, 0x28, 0xea, 0xbe, 0x7a, 0x92, 0xfd,
    0xc4, 0xe8, 0x00, 0x4d, 0xef, 0x05, 0x45, 0x97, 0xc4, 0x2d, 0x2e, 0x94,
    0x80, 0x44, 0x90, 0xf8, 0x5a, 0xbd, 0xd1, 0x86, 0xa1, 0xef, 0x47, 0x93,
    0xe9, 0x1b, 0x98, 0x59, 0x1b, 0xbb, 0xb2, 0x66, 0xbd, 0x23, 0x23, 0x60,
    0x4d, 0xeb, 0x6f, 0x5a, 0xcd, 0xee, 0x43, 0xab, 0x02, 0x08, 0xa6, 0xc7};

static Cpa8U ikedsa_3072_256_q[] = {
    0xc4, 0x06, 0xcd, 0x06, 0x69, 0xd9, 0x82, 0x2f, 0x5e, 0x41, 0x91,
    0x3c, 0x9c, 0xb8, 0xa3, 0x06, 0xee, 0x25, 0x68, 0xdc, 0x22, 0x8c,
    0x4a, 0x39, 0x96, 0x01, 0xe3, 0x57, 0x93, 0xf4, 0x4e, 0x41};

/* this structure is used to store data required by each client in the ike-dsa
 * transaction */
typedef struct ike_dsa_client_data_s
{
    CpaFlatBuffer **ppPublicValues;
    CpaFlatBuffer **ppSecretKeys;
    CpaCyDhPhase2SecretKeyGenOpData **ppPhase2;
    CpaCyDhPhase1KeyGenOpData **ppPhase1;
    CpaCyDsaRSSignOpData **ppRSSignOpData;
    CpaCyDsaVerifyOpData **ppVerifyOpData;
    CpaCyDsaVerifyOpData **ppVerifyOpData2;
    CpaFlatBuffer **ppR;
    CpaFlatBuffer **ppS;
} ike_dsa_client_data_t;

/*****************************************************************************
 * @ingroup IKE_DSA Threads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * operation has been processed
 *****************************************************************************/
void ikeDsaCallback(void *pCallbackTag,
                    CpaStatus status,
                    void *pOpData,
                    CpaFlatBuffer *pOut)
{
    processCallback(pCallbackTag);
}

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * This function frees all Operation Data memory setup in this file.
 * The code checks for any unallocated memory before it attempts to free it.
 ******************************************************************************/
void dsaFreeDataMemory(dsa_test_params_t *setup,
                       CpaCyDsaRSSignOpData *pSignOpdata[],
                       CpaCyDsaVerifyOpData *pVerifyOpData[],
                       CpaCyDsaVerifyOpData *pVerifyOpData2[],
                       CpaFlatBuffer *pR[],
                       CpaFlatBuffer *pS[])
{
    Cpa32U bufferCount = 0;

    if (NULL != pSignOpdata)
    {
        if (NULL != pSignOpdata[0])
        {
            qaeMemFreeNUMA((void **)&pSignOpdata[bufferCount]->P.pData);
            qaeMemFreeNUMA((void **)&pSignOpdata[bufferCount]->Q.pData);
            qaeMemFreeNUMA((void **)&pSignOpdata[bufferCount]->G.pData);
        }
    }

    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        if (NULL != pSignOpdata)
        {
            if (NULL != pSignOpdata[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pSignOpdata[bufferCount]->X.pData);
                qaeMemFreeNUMA((void **)&pSignOpdata[bufferCount]->K.pData);
                qaeMemFreeNUMA((void **)&pSignOpdata[bufferCount]->Z.pData);
            }
        }
        if (NULL != pVerifyOpData)
        {
            if (NULL != pVerifyOpData[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pVerifyOpData[bufferCount]->Y.pData);
                qaeMemFreeNUMA((void **)&pVerifyOpData[bufferCount]->R.pData);
                qaeMemFreeNUMA((void **)&pVerifyOpData[bufferCount]->S.pData);
            }
        }
        if (NULL != pVerifyOpData2)
        {
            if (NULL != pVerifyOpData2[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pVerifyOpData2[bufferCount]->R.pData);
                qaeMemFreeNUMA((void **)&pVerifyOpData2[bufferCount]->S.pData);
            }
        }

        if (NULL != pR)
        {
            if (NULL != pR[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pR[bufferCount]->pData);
            }
        }
        if (NULL != pS)
        {
            if (NULL != pS[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pS[bufferCount]->pData);
            }
        }
    }
    return;
}
// EXPORT_SYMBOL(rsaFreeDataMemory);

/*****************************************************************************
 * @ingroup IKE_DSA
 *
 * @description
 * This function is free an array of operation data structures for
 * ikedsa operations, any memory allocation is freed in
 * ikeDsaPerform
 ******************************************************************************/
static void ikeDsaMemFreeDsaData(ike_dsa_client_data_t *client)
{
    if (NULL != client)
    {
        if (NULL != client->ppRSSignOpData)
        {
            qaeMemFreeNUMA((void **)&client->ppRSSignOpData);
        }
        if (NULL != client->ppVerifyOpData)
        {
            qaeMemFreeNUMA((void **)&client->ppVerifyOpData);
        }
        if (NULL != client->ppVerifyOpData2)
        {
            qaeMemFreeNUMA((void **)&client->ppVerifyOpData2);
        }
        if (NULL != client->ppR)
        {
            qaeMemFreeNUMA((void **)&client->ppR);
        }
        if (NULL != client->ppS)
        {
            qaeMemFreeNUMA((void **)&client->ppS);
        }
    }
    return;
}

/*****************************************************************************
 * @ingroup IKE_DSA
 *
 * @description
 *      This function allocates the client memory for an IKE-DSA
 *      transaction used in ikeDsaPerform
 ******************************************************************************/
CpaStatus allocDsaClientMem(dsa_test_params_t *setup,
                            ike_dsa_client_data_t *client)
{
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppRSSignOpData,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppRSSignOpData\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppVerifyOpData,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppVerifyOpData\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppVerifyOpData2,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppVerifyOpData2\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppPhase1, setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppPhase1\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppPhase2, setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppPhase2\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppPublicValues,
                                 setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppPublicValues\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppSecretKeys,
                                 setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppSecretKeys\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != allocArrayOfPointers(setup->cyInstanceHandle,
                                                   (void **)&client->ppR,
                                                   setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppR\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != allocArrayOfPointers(setup->cyInstanceHandle,
                                                   (void **)&client->ppS,
                                                   setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppS\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup sampleDSACode
 *
 * @description
 *      free all memory used in DSA IKE code in this file
 *
 *****************************************************************************/
void freeIkeDsaMem(dsa_test_params_t *setup,
                   CpaFlatBuffer *dsaX,
                   CpaFlatBuffer *dsaY,
                   CpaFlatBuffer *dsaK,
                   CpaFlatBuffer *dsaP,
                   CpaFlatBuffer *dsaQ,
                   CpaFlatBuffer *dsaG,
                   CpaFlatBuffer *dsaH)
{
    freeArrayFlatBufferNUMA(dsaX, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaY, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaK, setup->numBuffers);

    /*free the normal flatBuffer pData */
    if (NULL != dsaP)
    {
        qaeMemFreeNUMA((void **)dsaP->pData);
    }
    if (NULL != dsaQ)
    {
        qaeMemFreeNUMA((void **)dsaQ->pData);
    }
    if (NULL != dsaG)
    {
        qaeMemFreeNUMA((void **)dsaG->pData);
    }
    if (NULL != dsaH)
    {
        qaeMemFreeNUMA((void **)dsaH->pData);
    }
}

/**
 *****************************************************************************
 * @ingroup sampleDSACode
 *
 * @description
 *      Macro to free all memory used in DSA IKE code in this file
 *
 *****************************************************************************/
#define FREE_ikeDSA_MEM                                                        \
    freeIkeDsaMem(setup, pDsaX, pDsaY, pDsaK, pDsaP, pDsaQ, pDsaG, pDsaH)

/******************************************************************************
 * @ingroup sampleDSACode
 *
 * @description
 * this function allocates space and generates arrays of DSA keys, based on the
 * parameters within the setup
 * ****************************************************************************/
CpaStatus genDsaPara(dsa_test_params_t *setup,
                     CpaCyDsaRSSignOpData **ppSignOpData,
                     CpaCyDsaVerifyOpData **ppVerifyOpData,
                     CpaCyDsaVerifyOpData **ppVerifyOpData2,
                     CpaFlatBuffer **ppdsaR,
                     CpaFlatBuffer **ppdsaS)
{
    Cpa32U i = 0;
    Cpa32U status = 0;

    /*DSA parameters */
    /*DSA P parameter, this shall be populated by the hard coded P at the top
     * of this file */
    CpaFlatBuffer *pDsaP = NULL;
    /*DSA Q parameter, this shall be populated by the hard coded Q at the top
     * of this file */
    CpaFlatBuffer *pDsaQ = NULL;
    /* DSA G parameter used to generate Y, the signature R&S, and to verify */
    CpaFlatBuffer *pDsaG = NULL;
    /*H is used to generate G, H is hard coded to DEFAULT_H_VALUE */
    CpaFlatBuffer *pDsaH = NULL;
    /*random number X used to generate Y and Sign R&S */
    CpaFlatBuffer *pDsaX = NULL;
    /*DSA Y parameter is used in the verification stage */
    CpaFlatBuffer *pDsaY = NULL;
    /*K is a random number used in the generation of signature R&S */
    CpaFlatBuffer *pDsaK = NULL;
    CpaFlatBuffer *pDsaR1 = NULL;
    CpaFlatBuffer *pDsaS1 = NULL;
    CpaFlatBuffer *pDsaR2 = NULL;
    CpaFlatBuffer *pDsaS2 = NULL;

    /*GCC compiler complains without the double {{}} to init the following
     * structures*/
    CpaCyDsaGParamGenOpData gOpData = {{0, NULL}, {0, NULL}, {0, NULL}};
    CpaCyDsaYParamGenOpData yOpData = {{0}};

    Cpa8U *pDataPtr = NULL;
    Cpa32U sizeOfp = 0;
    Cpa8U *qDataPtr = NULL;
    Cpa32U sizeOfq = 0;

    Cpa32U node = 0;

#ifdef POLL_INLINE
    CpaInstanceInfo2 *instanceInfo2 = NULL;
#endif


#ifdef POLL_INLINE
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
    }
    qaeMemFree((void **)&instanceInfo2);
#endif

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not determine node for memory allocation\n");
        return status;
    }

    /*check the p and q input len and set the pointers to the data */
    if (MODULUS_1024_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
        EXPONENT_160_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = ikedsa_1024_160_p;
        qDataPtr = ikedsa_1024_160_q;
        sizeOfp = sizeof(ikedsa_1024_160_p);
        sizeOfq = sizeof(ikedsa_1024_160_q);
    }
    else if (MODULUS_2048_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_224_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = ikedsa_2048_224_p;
        qDataPtr = ikedsa_2048_224_q;
        sizeOfp = sizeof(ikedsa_2048_224_p);
        sizeOfq = sizeof(ikedsa_2048_224_q);
    }
    else if (MODULUS_2048_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_256_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = ikedsa_2048_256_p;
        qDataPtr = ikedsa_2048_256_q;
        sizeOfp = sizeof(ikedsa_2048_256_p);
        sizeOfq = sizeof(ikedsa_2048_256_q);
    }
    else if (MODULUS_3072_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_256_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = ikedsa_3072_256_p;
        qDataPtr = ikedsa_3072_256_q;
        sizeOfp = sizeof(ikedsa_3072_256_p);
        sizeOfq = sizeof(ikedsa_3072_256_q);
    }
    else
    {
        PRINT_ERR("P & Q len not supported\n");
        /*thread status is init to fail so just return fail here*/
        return CPA_STATUS_FAIL;
    }
    /* Completion used in callback */

    /*Allocate all the buffers */
    pDsaX = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == pDsaX)
    {
        PRINT_ERR("Could not allocate memory\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }
    pDsaY = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == pDsaY)
    {
        PRINT_ERR("Could not allocate memory\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }
    pDsaK = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == pDsaK)
    {
        PRINT_ERR("Could not allocate memory\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }

    /************************************************************************
     * STAGE 1 Setup up the DSA parameters, generate X, G, Y, K, Z,
     *          generate user defined number of messages to be signed
     *          calculate the digest of the messages
     *          sign all the messages
     *          setup the verification data structure
     **************************************************************************/
    /*set P */
    pDsaP = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    if (NULL == pDsaP)
    {
        PRINT_ERR("Could not allocate memory for pDsaP\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pDsaP,
                         setup->pLenInBytes,
                         pDataPtr,
                         sizeOfp,
                         FREE_ikeDSA_MEM);
    /*set Q */
    pDsaQ = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    if (NULL == pDsaQ)
    {
        PRINT_ERR("Could not allocate memory for pDsaQ\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pDsaQ,
                         setup->qLenInBytes,
                         qDataPtr,
                         sizeOfq,
                         FREE_ikeDSA_MEM);

    /*generate X for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*Choose X is generated by random method, where 0 < X < Q */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &pDsaX[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        dsaGenRandom(&pDsaX[i], pDsaQ);
    }

    /***************************************************************************
     * set genG opData and generate G
     *
     ************************************************************************/
    /*H is required to genG */
    pDsaH = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    if (NULL == pDsaH)
    {
        PRINT_ERR("Could not allocate memory for pDsaH\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pDsaH,
                         setup->pLenInBytes,
                         NULL,
                         0,
                         FREE_ikeDSA_MEM);
    memset(pDsaH->pData, 0, pDsaH->dataLenInBytes);
    pDsaH->pData[setup->pLenInBytes - 1] = IKEDSA_DEFAULT_H_VALUE;

    /*allocate space for G */
    pDsaG = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    if (NULL == pDsaG)
    {
        PRINT_ERR("Could not allocate memory for pDsaG\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pDsaG,
                         setup->pLenInBytes,
                         NULL,
                         0,
                         FREE_ikeDSA_MEM);

    /*set opData to generate G */
    gOpData.P.pData = pDsaP->pData;
    gOpData.P.dataLenInBytes = pDsaP->dataLenInBytes;
    gOpData.Q.pData = pDsaQ->pData;
    gOpData.Q.dataLenInBytes = pDsaQ->dataLenInBytes;
    gOpData.H.pData = pDsaH->pData;
    gOpData.H.dataLenInBytes = pDsaH->dataLenInBytes;
    status = dsaGenG(setup->cyInstanceHandle, &gOpData, pDsaG);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to generate IKE DSA parameter G\n");
        FREE_ikeDSA_MEM;
        return CPA_STATUS_FAIL;
    }

    /*generate a Y for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*set the opData to gen Y */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &pDsaY[i],
                             setup->pLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        yOpData.P.pData = pDsaP->pData;
        yOpData.P.dataLenInBytes = pDsaP->dataLenInBytes;
        yOpData.G.pData = pDsaG->pData;
        yOpData.G.dataLenInBytes = pDsaG->dataLenInBytes;
        yOpData.X.pData = pDsaX[i].pData;
        yOpData.X.dataLenInBytes = pDsaX[i].dataLenInBytes;
        status = dsaGenY(setup->cyInstanceHandle, &yOpData, &pDsaY[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating Y for buffer %d\n", i);
            /*free all the pData buffers allocated and Array of pointers
             * allocated */
            FREE_ikeDSA_MEM;
            return CPA_STATUS_FAIL;
        }

        /*Generate a random per-message value K, where 0 < K < Q. */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &pDsaK[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        dsaGenRandom(&pDsaK[i], pDsaQ);

        /* Allocate memory for the PublicValue buffer */
        ppdsaR[i] =
            qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == ppdsaR[i])
        {
            PRINT("ppdsaR[%d] is NULL \n", i);
            FREE_ikeDSA_MEM;
            return CPA_STATUS_FAIL;
        }
        ppdsaS[i] =
            qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == ppdsaS[i])
        {
            PRINT("ppdsaS[%d] is NULL \n", i);
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            return CPA_STATUS_FAIL;
        }
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             ppdsaR[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             ppdsaS[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);

        ppSignOpData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyDsaRSSignOpData), node, BYTE_ALIGNMENT_64);
        if (NULL == ppSignOpData[i])
        {
            PRINT_ERR("Failed to allocate mem for ppSignOpData input data\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            return CPA_STATUS_FAIL;
        }
        memset(ppSignOpData[i], 0, sizeof(CpaCyDsaRSSignOpData));

        /*Gen R & S signature */
        ppSignOpData[i]->P.pData = pDsaP->pData;
        ppSignOpData[i]->P.dataLenInBytes = pDsaP->dataLenInBytes;
        ppSignOpData[i]->Q.pData = pDsaQ->pData;
        ppSignOpData[i]->Q.dataLenInBytes = pDsaQ->dataLenInBytes;
        ppSignOpData[i]->G.pData = pDsaG->pData;
        ppSignOpData[i]->G.dataLenInBytes = pDsaG->dataLenInBytes;
        ppSignOpData[i]->X.pData = pDsaX[i].pData;
        ppSignOpData[i]->X.dataLenInBytes = pDsaX[i].dataLenInBytes;
        ppSignOpData[i]->K.pData = pDsaK[i].pData;
        ppSignOpData[i]->K.dataLenInBytes = pDsaK[i].dataLenInBytes;
        /*Verify signature */
        ppVerifyOpData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyDsaVerifyOpData), node, BYTE_ALIGNMENT_64);
        if (NULL == ppVerifyOpData[i])
        {
            PRINT_ERR("Failed to allocate mem for ppVerifyOpData input data\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            qaeMemFree((void **)&ppSignOpData);
            return CPA_STATUS_FAIL;
        }
        memset(ppVerifyOpData[i], 0, sizeof(CpaCyDsaVerifyOpData));
        pDsaR1 =
            qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == pDsaR1)
        {
            PRINT_ERR("Failed to allocate memory for pDsaR1\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            qaeMemFree((void **)&ppSignOpData);
            qaeMemFree((void **)&ppVerifyOpData);
            return CPA_STATUS_FAIL;
        }
        pDsaS1 =
            qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == pDsaS1)
        {
            PRINT_ERR("Failed to allocate memory for pDsaS1\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            qaeMemFree((void **)&ppSignOpData);
            qaeMemFree((void **)&ppVerifyOpData);
            qaeMemFree((void **)&pDsaR1);
            return CPA_STATUS_FAIL;
        }
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pDsaR1,
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pDsaS1,
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        ppVerifyOpData[i]->P.pData = pDsaP->pData;
        ppVerifyOpData[i]->P.dataLenInBytes = pDsaP->dataLenInBytes;
        ppVerifyOpData[i]->Q.pData = pDsaQ->pData;
        ppVerifyOpData[i]->Q.dataLenInBytes = pDsaQ->dataLenInBytes;
        ppVerifyOpData[i]->G.pData = pDsaG->pData;
        ppVerifyOpData[i]->G.dataLenInBytes = pDsaG->dataLenInBytes;
        ppVerifyOpData[i]->Y.pData = pDsaY[i].pData;
        ppVerifyOpData[i]->Y.dataLenInBytes = pDsaY[i].dataLenInBytes;
        ppVerifyOpData[i]->R.pData = pDsaR1->pData;
        ppVerifyOpData[i]->R.dataLenInBytes = pDsaR1->dataLenInBytes;
        ppVerifyOpData[i]->S.pData = pDsaS1->pData;
        ppVerifyOpData[i]->S.dataLenInBytes = pDsaS1->dataLenInBytes;

        ppVerifyOpData2[i] = qaeMemAllocNUMA(
            sizeof(CpaCyDsaVerifyOpData), node, BYTE_ALIGNMENT_64);
        if (NULL == ppVerifyOpData2[i])
        {
            PRINT_ERR("Failed to allocate mem for ppVerifyOpData input data\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            qaeMemFree((void **)&ppSignOpData);
            qaeMemFree((void **)&ppVerifyOpData);
            qaeMemFree((void **)&pDsaR1);
            qaeMemFree((void **)&pDsaS1);
            return CPA_STATUS_FAIL;
        }
        memset(ppVerifyOpData2[i], 0, sizeof(CpaCyDsaVerifyOpData));
        pDsaR2 =
            qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == pDsaR2)
        {
            PRINT_ERR("Failed to allocate mem for pDsaR2 input data\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            qaeMemFree((void **)&ppSignOpData);
            qaeMemFree((void **)&ppVerifyOpData);
            qaeMemFree((void **)&pDsaR1);
            qaeMemFree((void **)&pDsaS1);
            qaeMemFree((void **)&ppVerifyOpData2);
            return CPA_STATUS_FAIL;
        }
        pDsaS2 =
            qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == pDsaS2)
        {
            PRINT_ERR("Failed to allocate mem for pDsaS2 input data\n");
            FREE_ikeDSA_MEM;
            qaeMemFree((void **)&ppdsaR);
            qaeMemFree((void **)&ppdsaS);
            qaeMemFree((void **)&ppSignOpData);
            qaeMemFree((void **)&ppVerifyOpData);
            qaeMemFree((void **)&pDsaR1);
            qaeMemFree((void **)&pDsaS1);
            qaeMemFree((void **)&ppVerifyOpData2);
            qaeMemFree((void **)&pDsaR2);
            return CPA_STATUS_FAIL;
        }
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pDsaR2,
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pDsaS2,
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_ikeDSA_MEM);
        ppVerifyOpData2[i]->P.pData = pDsaP->pData;
        ppVerifyOpData2[i]->P.dataLenInBytes = pDsaP->dataLenInBytes;
        ppVerifyOpData2[i]->Q.pData = pDsaQ->pData;
        ppVerifyOpData2[i]->Q.dataLenInBytes = pDsaQ->dataLenInBytes;
        ppVerifyOpData2[i]->G.pData = pDsaG->pData;
        ppVerifyOpData2[i]->G.dataLenInBytes = pDsaG->dataLenInBytes;
        ppVerifyOpData2[i]->Y.pData = pDsaY[i].pData;
        ppVerifyOpData2[i]->Y.dataLenInBytes = pDsaY[i].dataLenInBytes;
        ppVerifyOpData2[i]->R.pData = pDsaR2->pData;
        ppVerifyOpData2[i]->R.dataLenInBytes = pDsaR2->dataLenInBytes;
        ppVerifyOpData2[i]->S.pData = pDsaS2->pData;
        ppVerifyOpData2[i]->S.dataLenInBytes = pDsaS2->dataLenInBytes;
    }

    return CPA_STATUS_SUCCESS;
}

/******************************************************************************
 * @ingroup sampleDSACode
 *
 * @description
 * this function measures the performance of DSA Encrypt operations
 * It is assumed all the encrypt data and keys have been been set using
 * functions defined in this file
 * ****************************************************************************/
CpaStatus sampleDsaSign(dsa_test_params_t *setup,
                        CpaCyDsaRSSignOpData *pRSSignOpData[],
                        CpaFlatBuffer *dsaR[],
                        CpaFlatBuffer *dsaS[],
                        Cpa32U numBuffers,
                        Cpa32U numLoops)
{
    Cpa32U outerLoop = 0;
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;


    for (outerLoop = 0; outerLoop < setup->numLoops; outerLoop++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            status = dsaGenRS(
                setup->cyInstanceHandle, pRSSignOpData[i], dsaR[i], dsaS[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Error Generating R&S for buffer %d\n", i);
                // FREE_DSA_MEM;
                return CPA_STATUS_FAIL;
            }
        }
    }

    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 * @ingroup IKE_DSA
 *
 * @description
 *      This function frees all the dynamically allocated memory used in the
 * ikeDsaPerform
 * Each pointer is checked to see if its null and if not it is free'd,
 * The underlying free function ensures that when freeing the pointer is reset
 * to NULL
 ******************************************************************************/
static void ikeDsaMemFree(dsa_test_params_t *setup,
                          ike_dsa_client_data_t *alice,
                          ike_dsa_client_data_t *bob)
{
    dsaFreeDataMemory(setup,
                      alice->ppRSSignOpData,
                      alice->ppVerifyOpData,
                      alice->ppVerifyOpData2,
                      alice->ppR,
                      alice->ppS);
    dsaFreeDataMemory(setup,
                      bob->ppRSSignOpData,
                      bob->ppVerifyOpData,
                      bob->ppVerifyOpData2,
                      bob->ppR,
                      bob->ppS);

    /*free the signature pointer arrays because in RSA code this is allocated
     * as a local variable*/
    ikeDsaMemFreeDsaData(alice);
    ikeDsaMemFreeDsaData(bob);
    dhMemFreePh1((asym_test_params_t *)setup,
                 alice->ppPhase1,
                 alice->ppPublicValues,
                 bob->ppPhase1,
                 bob->ppPublicValues);
    qaeMemFree((void **)&alice->ppPublicValues);
    qaeMemFree((void **)&bob->ppPublicValues);
    qaeMemFree((void **)&alice->ppPhase1);
    qaeMemFree((void **)&bob->ppPhase1);
    dhMemFreePh2((asym_test_params_t *)setup,
                 alice->ppSecretKeys,
                 alice->ppPhase2,
                 bob->ppSecretKeys,
                 bob->ppPhase2);
    qaeMemFree((void **)&alice->ppSecretKeys);
    qaeMemFree((void **)&bob->ppSecretKeys);
    qaeMemFree((void **)&alice->ppPhase2);
    qaeMemFree((void **)&bob->ppPhase2);

    return;
}
#define FREE_dsaSetup_MEM                                                      \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&dsaZ[i].pData);                               \
    } while (0)

/******************************************************************************
 * @ingroup sampleDSACode
 *
 * @description
 * this function sets up the data to be decrypted and allocates space to
 * store the output
 *
 ****************************************************************************/
CpaStatus dsaZSetup(CpaFlatBuffer **ppPublicValues,
                    CpaCyDsaRSSignOpData **ppSignatureOpData,
                    CpaCyDsaVerifyOpData **ppVerifyOpData,
                    CpaCyDsaVerifyOpData **ppVerifyOpData2,
                    dsa_test_params_t *setup)
{
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /*Z is the digest of the message in dsaM */
    CpaFlatBuffer *dsaZ = NULL;

    Cpa32U node = 0;

#ifdef POLL_INLINE
    CpaInstanceInfo2 instanceInfo2 = {0};
#endif


#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, &instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            return CPA_STATUS_FAIL;
        }
    }
#endif
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not determine node for memory allocation\n");
        return status;
    }

    dsaZ = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == dsaZ)
    {
        PRINT_ERR("Could not allocate memory\n");
        return CPA_STATUS_FAIL;
    }

    /*generate a Y for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*allocate space for digest of message */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaZ[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_dsaSetup_MEM);
        /*calculate digest of message */
        status = dsaGenZ(setup->cyInstanceHandle,
                         ppPublicValues[i],
                         setup->hashAlg,
                         &dsaZ[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating Z for buffer %d\n", i);
            FREE_dsaSetup_MEM;
            return CPA_STATUS_FAIL;
        }

        (*ppSignatureOpData[i]).Z.pData = dsaZ[i].pData;
        (*ppSignatureOpData[i]).Z.dataLenInBytes = dsaZ[i].dataLenInBytes;
        (*ppVerifyOpData[i]).Z.pData = dsaZ[i].pData;
        (*ppVerifyOpData[i]).Z.dataLenInBytes = dsaZ[i].dataLenInBytes;
        (*ppVerifyOpData2[i]).Z.pData = dsaZ[i].pData;
        (*ppVerifyOpData2[i]).Z.dataLenInBytes = dsaZ[i].dataLenInBytes;
    }

    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 * @ingroup IKE_DSA
 *
 * @description
 *      This function sets up the QA API asymmetric functions of an IKE
 *      transaction using DSA to sign/verify DH generated keys
 ******************************************************************************/
static CpaStatus ikeDsaPerform(dsa_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean verifyStatus = CPA_TRUE;
    Cpa32U i = 0;
    Cpa32U innerLoop = 0;
    CpaBoolean dsaSignprotocolStatus = CPA_FALSE;

    ike_dsa_client_data_t alice = {0};
    ike_dsa_client_data_t bob = {0};

    Cpa32U node = 0;
    /*functions called in this code over writes the performanceStats->response,
     * so we use a local counter to count responses */
    Cpa32U responses = 0;
    Cpa32U packageId = 0;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        qaeMemFree((void **)&instanceInfo2);
        return CPA_STATUS_FAIL;
    }
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        qaeMemFree((void **)&instanceInfo2);
        return status;
    }
    packageId = instanceInfo2->physInstId.packageId;
    qaeMemFree((void **)&instanceInfo2);
    /************************************************************************/
    /* Allocate all the memory for DH and DSA operations                    */
    /************************************************************************/
    /*Allocate for Alice*/
    if (CPA_STATUS_SUCCESS != allocDsaClientMem(setup, &alice))
    {
        PRINT_ERR("Alice allocClientMem error\n");
        ikeDsaMemFree(setup, &alice, &bob);
        return CPA_STATUS_FAIL;
    }
    /*Allocate for Bob*/
    if (CPA_STATUS_SUCCESS != allocDsaClientMem(setup, &bob))
    {
        PRINT_ERR("Bob allocClientMem error\n");
        ikeDsaMemFree(setup, &alice, &bob);
        return CPA_STATUS_FAIL;
    }

    /**************************************************************************
     * STEP 1. Alice & Bob generate public & private DSA keys
     * ************************************************************************/
    status = genDsaPara(setup,
                        alice.ppRSSignOpData,
                        alice.ppVerifyOpData,
                        alice.ppVerifyOpData2,
                        alice.ppR,
                        alice.ppS);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed Alice genDsaPara, status: %d\n", status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    status = genDsaPara(setup,
                        bob.ppRSSignOpData,
                        bob.ppVerifyOpData,
                        bob.ppVerifyOpData2,
                        bob.ppR,
                        bob.ppS);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed Bob genDsaPara, status: %d\n", status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /**************************************************************************
     * STEP 2. Alice & Bob agree on a p & g and generate secret random x
     **************************************************************************/
    status = dhPhase1Setup((asym_test_params_t *)setup,
                           alice.ppPhase1,
                           bob.ppPhase1,
                           alice.ppPublicValues,
                           bob.ppPublicValues,
                           NULL);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed dhPhase1Setup, status: %d\n", status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /**************************************************************************
     * STEP 3. Alice & Bob Perform DH Phase1 to produce Public Value -
     * PV = g^x mod p
     **************************************************************************/
    /**************************************************************************/
    /*Perform DH phase1 for Alice */
    /**************************************************************************/
    status = dhPhase1(alice.ppPhase1,
                      alice.ppPublicValues,
                      (asym_test_params_t *)setup,
                      setup->numBuffers,
                      ONE_LOOP);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed to complete dhPhase1 for Alice, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /**************************************************************************/
    /*Perform DH phase1 for Bob                                               */
    /**************************************************************************/
    status = dhPhase1(bob.ppPhase1,
                      bob.ppPublicValues,
                      (asym_test_params_t *)setup,
                      setup->numBuffers,
                      ONE_LOOP);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to complete dhPhase1 for Bob, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /**************************************************************************/
    /*Perform Phase2 setup for Bob                                            */
    /**************************************************************************/
    status = dhPhase2Setup(bob.ppSecretKeys,
                           bob.ppPhase1,
                           bob.ppPhase2,
                           alice.ppPublicValues,
                           (asym_test_params_t *)setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to setup phase2 for Bob, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /**************************************************************************/
    /*Calculate Bobs secret keys                                            */
    /**************************************************************************/
    status = dhPhase2Perform(bob.ppSecretKeys,
                             bob.ppPhase2,
                             (asym_test_params_t *)setup,
                             setup->numBuffers,
                             ONE_LOOP);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to perform phase2 for Bob, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /***************************************************************************
     * STEP 5. Sign Bobs Public Value using peers public key ->
     * Bobs Signature = DSA sign bobsPV
     *************************************************************************/
    status = dsaZSetup(bob.ppPublicValues,
                       bob.ppRSSignOpData,
                       bob.ppVerifyOpData,
                       bob.ppVerifyOpData2,
                       setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaDecryptDataSetup for Bob, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    status = dsaZSetup(alice.ppPublicValues,
                       alice.ppRSSignOpData,
                       alice.ppVerifyOpData2,
                       alice.ppVerifyOpData2,
                       setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaDecryptDataSetup for Bob, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }
    /**************************************************************************/
    /* Sign all of Bobs public value buffers, but loop only once              */
    /**************************************************************************/
    status = sampleDsaSign(setup,
                           bob.ppRSSignOpData,
                           bob.ppR,
                           bob.ppS,
                           setup->numBuffers,
                           ONE_LOOP);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed sampleDsaSign for Bob, status: %d\n", status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }
    /* Copy the DSA signature output into the verification structure
     * in the performance loop we verify bobs signature. Bobs signature is
     * the input the the verification operation*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*check that the signature is the expected length*/
        if (bob.ppVerifyOpData[i]->R.dataLenInBytes !=
            bob.ppR[i]->dataLenInBytes)
        {
            PRINT_ERR("Verify R data len does not match the signature len\n");
            ikeDsaMemFree(setup, &alice, &bob);
            return status;
        }
        memcpy(bob.ppVerifyOpData[i]->R.pData,
               bob.ppR[i]->pData,
               bob.ppVerifyOpData[i]->R.dataLenInBytes);

        if (bob.ppVerifyOpData[i]->S.dataLenInBytes !=
            bob.ppS[i]->dataLenInBytes)
        {
            PRINT_ERR("Verify S data len does not match the signature len\n");
            ikeDsaMemFree(setup, &alice, &bob);
            return status;
        }
        memcpy(bob.ppVerifyOpData[i]->S.pData,
               bob.ppS[i]->pData,
               bob.ppVerifyOpData[i]->S.dataLenInBytes);

        /*check that the signature is the expected length*/
        if (bob.ppVerifyOpData2[i]->R.dataLenInBytes !=
            bob.ppR[i]->dataLenInBytes)
        {
            PRINT_ERR("Verify 2 R data len does not match the signature len\n");
            ikeDsaMemFree(setup, &alice, &bob);
            return status;
        }
        memcpy(bob.ppVerifyOpData2[i]->R.pData,
               bob.ppR[i]->pData,
               bob.ppVerifyOpData2[i]->R.dataLenInBytes);

        if (bob.ppVerifyOpData2[i]->R.dataLenInBytes !=
            bob.ppS[i]->dataLenInBytes)
        {
            PRINT_ERR("Verify 2 S data len does not match the signature len\n");
            ikeDsaMemFree(setup, &alice, &bob);
            return status;
        }
        memcpy(bob.ppVerifyOpData2[i]->S.pData,
               bob.ppS[i]->pData,
               bob.ppVerifyOpData2[i]->S.dataLenInBytes);
    }
    /***************************************************************************
     * STEP 6. Setup Alices Decrypt and Diffie Hellman Data for performance
     *Loop
     *************************************************************************/
    /**************************************************************************/
    /* Perform Phase2 setup for Alice                                         */
    /**************************************************************************/
    status = dhPhase2Setup(alice.ppSecretKeys,
                           alice.ppPhase1,
                           alice.ppPhase2,
                           bob.ppPublicValues,
                           (asym_test_params_t *)setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to setup phase2 for Alice, status: %d\n",
                  status);
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    /***************************************************************************
     * STEP 7 IKE main mode Asymmetric steps
     **************************************************************************/
    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();
    memset(setup->performanceStats, 0, sizeof(perf_data_t));
    setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();
    setup->performanceStats->packageId = packageId;
    /*pre-set the number of ops we plan to submit*/
    /*number of responses equals the number of QA APIs we have chained together
     * multiplied by the number of buffers and how many times we have looped
     * over the buffers */
    setup->performanceStats->numOperations =
        NUMBER_OF_CHAINED_OPS * setup->numBuffers * setup->numLoops;
    setup->performanceStats->averagePacketSizeInBytes = setup->pLenInBytes;
    setup->performanceStats->responses = 0;
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);

    for (i = 0; i < setup->numLoops; i++)
    {
        for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
        {
            /******************************************************************/
            /* Step 7a Perform DH phase1 for Alice
             * This step, performs setup->NumBuffers DH Phase1
             * Operations to
             * Calculate setup->numBuffers Public Values for Alice*/
            /******************************************************************/
            do
            {
                /*****************************************************************/
                /* ikeRsaCallback  : used in asynchronous mode
                 * performanceStats: Opaque user data
                 * ppPhase1        : Structure containing p, g and x
                 * ppPublicValues  : Public value (output) */
                /******************************************************************/

                status = cpaCyDhKeyGenPhase1(setup->cyInstanceHandle,
                                             NULL /*ikeRsaCallback*/,
                                             setup->performanceStats,
                                             alice.ppPhase1[innerLoop],
                                             alice.ppPublicValues[innerLoop]);

                /*this is a back off mechanism to stop the code
                 * continually submitting requests. Without this the
                 * CPU
                 * can report a soft lockup if it continually loops
                 * on busy*/
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to complete dhPhase1 for Alice, status: %d\n",
                          status);
                break;
            }
            /******************************************************************/
            /* Step 7b Perform RSA verify of third party...normally this is done
             *  on at third party to verify that bob is who he says he
             * is, but
             *  here we are performing a second RSA encrypt on Bobs
             * signature to
             *  test the sequence of calls */
            /******************************************************************/
            do
            {
                status = cpaCyDsaVerify(setup->cyInstanceHandle,
                                        NULL,
                                        setup->performanceStats,
                                        bob.ppVerifyOpData[innerLoop],
                                        &verifyStatus);
                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
                    /*once we get to many retries, perform a context switch
                     * to give the acceleration engine a small
                     * break */
                    if (RETRY_LIMIT ==
                        (setup->performanceStats->retries % (RETRY_LIMIT + 1)))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed on DSAVerify for Bob using buffer=%d \n ",
                          innerLoop);
                break;
            }
            /***************************************************************
             * Step 7c Perform RSA verify of Bobs signed public values.
             * Bobs Public values and Bobs RSA Signature have been
             * pre-calculated Bobs signature is in the EncryptOpData
             * structure, the verified value should match bobsPublic value,
             * but in this code we don't check if they match
             **************************************************************/
            do
            {
                status = cpaCyDsaVerify(setup->cyInstanceHandle,
                                        NULL,
                                        setup->performanceStats,
                                        bob.ppVerifyOpData2[innerLoop],
                                        &verifyStatus);
                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
                    /*once we get to many retries, perform a context switch
                     * to give the acceleration engine a small
                     * break */
                    if (RETRY_LIMIT ==
                        (setup->performanceStats->retries % (RETRY_LIMIT + 1)))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed on DSAVerify for Bob using buffer=%d \n ",
                          innerLoop);
                break;
            }

            /******************************************************************
             * Step 7d Sign all of Alices public value buffers,
             * Alices Public Value is in the Decrypt opData setup, the signature
             *  is placed in alices signature
             ******************************************************************/
            /*status = sampleDsaSign(setup,
            alice.ppRSSignOpData,
            alice.ppR,
            alice.ppS,
            setup->numBuffers,
            ONE_LOOP);*/

            do
            {
                status = cpaCyDsaSignRS(setup->cyInstanceHandle,
                                        NULL,
                                        setup->performanceStats,
                                        alice.ppRSSignOpData[innerLoop],
                                        &dsaSignprotocolStatus,
                                        alice.ppR[innerLoop],
                                        alice.ppS[innerLoop]);
                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while ((CPA_STATUS_RETRY == status) &&
                     ((setup->performanceStats->retries % (RETRY_LIMIT + 1)) <=
                      RETRY_LIMIT));
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to complete RsaSign for Alice, status: %d\n",
                          status);
                ikeDsaMemFree(setup, &alice, &bob);
                return status;
            }

            /******************************************************************/
            /* Step 7e Perform the DH phase2 operation for Alice,
             * using Bobs verified Public values                              */

            do
            {
                status =
                    cpaCyDhKeyGenPhase2Secret(setup->cyInstanceHandle,
                                              NULL /*ikeRsaCallback*/,
                                              setup->performanceStats,
                                              alice.ppPhase2[innerLoop],
                                              alice.ppSecretKeys[innerLoop]);

                /*this is a back off mechanism to stop the code
                 * continually calling the Decrypt operation when the
                 * acceleration units are busy. Without this the CPU
                 * can report a soft lockup if it continually loops
                 * on busy*/
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Diffie Hellman Phase2 for Alice, status: %d\n",
                          status);
                break;
            }
            /*At this point Bob and Alice should have created the same shared
             * secret key*/
            responses++;
        } /*end innerLoop*/
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }

    } /*end numLoops*/
    setup->performanceStats->endCyclesTimestamp = sampleCodeTimestamp();
    /*if (CPA_STATUS_SUCCESS == status)
    {
        if(sampleCodeSemaphoreWait(&setup->performanceStats->comp,
                SAMPLE_CODE_WAIT_FOREVER) != CPA_STATUS_SUCCESS)
        {
           PRINT_ERR("interruption in ike rsa Loop\n");
           status = CPA_STATUS_FAIL;
        }
    }*/

    sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);

    if (CPA_STATUS_SUCCESS != status)
    {
        ikeDsaMemFree(setup, &alice, &bob);
        return status;
    }

    ikeDsaMemFree(setup, &alice, &bob);
    /*set the total number of responses and requests. */
    setup->performanceStats->numOperations = responses * NUMBER_OF_CHAINED_OPS;
    setup->performanceStats->responses = responses * NUMBER_OF_CHAINED_OPS;
    return status;
}

/*****************************************************************************
 * @ingroup IKE_DSA
 *
 * @description
 *      This function prints the IKE-DSA performance stats
 ******************************************************************************/
CpaStatus ikeDsaPrintStats(thread_creation_data_t *data)
{
    PRINT("IKE_DSA SIMULATION\n");
    PRINT("Modulus Size %17u\n", data->packetSize);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 *@ingroup cryptoThreads
 *
 * @description
 *      This function sets up an IKE-DSA thread
 ******************************************************************************/
void ikeDsaPerformance(single_thread_test_data_t *testSetup)
{
    dsa_test_params_t ikeDsaSetup;
    dsa_test_params_t *setup = (dsa_test_params_t *)testSetup->setupPtr;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    /* This barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*give our thread a unique memory location to store performance stats*/
    ikeDsaSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        ikeDsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }

    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (cyInstances == NULL)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        ikeDsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }

    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        ikeDsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        ikeDsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    /*give our thread a unique memory location to store performance stats */
    ikeDsaSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    ikeDsaSetup.hashAlg = setup->hashAlg;
    ikeDsaSetup.pLenInBytes = setup->pLenInBytes;
    ikeDsaSetup.qLenInBytes = setup->qLenInBytes;
    ikeDsaSetup.numBuffers = setup->numBuffers;
    ikeDsaSetup.numLoops = setup->numLoops;
    ikeDsaSetup.syncMode = setup->syncMode;

    /*launch function that does all the work*/
    status = ikeDsaPerform(&ikeDsaSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("ikeDsa Thread FAILED with status: %d\n", status);
        ikeDsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc = (stats_print_func_t)ikeDsaPrintStats;
    }
    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}

/*****************************************************************************
 *@ingroup cryptoThreads
 *
 * @description
 *      This function needs to be called first to setup an IKE test.
 * Then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupIkeDsaTest(Cpa32U pLenInBits,
                          Cpa32U qLenInBits,
                          sync_mode_t syncMode,
                          Cpa32U numBuffs,
                          Cpa32U numLoops)
{
    /*thread_setup_g is a multi-dimensional array that stores the setup for all
     * thread variations in an array of characters. we store our test setup at
     * the start of the second array ie index 0. There maybe multi thread types
     * (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * asymmetric structure*/
    dsa_test_params_t *ikeDsaSetup = NULL;
    if (MAX_THREAD_VARIATION <= testTypeCount_g)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }
    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Error starting Crypto Services\n");
        return CPA_STATUS_FAIL;
    }
    /* start polling threads if polling is enabled in the configuration file */
    if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
    {
        PRINT_ERR("Error creating polling threads\n");
        return CPA_STATUS_FAIL;
    }
    if (MAX_SETUP_STRUCT_SIZE_IN_BYTES <= sizeof(dsa_test_params_t))
    {
        PRINT_ERR("Test structure is to big for framework\n");
        PRINT_ERR("Size needed: %u, limit %u\n",
                  (Cpa32U)sizeof(dsa_test_params_t),
                  (Cpa32U)MAX_SETUP_STRUCT_SIZE_IN_BYTES);
        return CPA_STATUS_FAIL;
    }
    /*get the pre-allocated memory allocation to store the setup for IKE test*/
    ikeDsaSetup = (dsa_test_params_t *)&thread_setup_g[testTypeCount_g][0];

    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)ikeDsaPerformance;

    testSetupData_g[testTypeCount_g].packetSize = pLenInBits;
    /*then we store the test setup in the above location */
    if (MODULUS_1024_BIT == pLenInBits && EXPONENT_160_BIT == qLenInBits)
    {
        ikeDsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA1;
    }
    else if (MODULUS_2048_BIT == pLenInBits && EXPONENT_224_BIT == qLenInBits)
    {
        ikeDsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA224;
    }
    else if (MODULUS_2048_BIT == pLenInBits && EXPONENT_256_BIT == qLenInBits)
    {
        ikeDsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA256;
    }
    else if (MODULUS_3072_BIT == pLenInBits && EXPONENT_256_BIT == qLenInBits)
    {
        ikeDsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA256;
    }
    else
    {
        PRINT_ERR("pLen & qLen combination not supported, must be 1024/160 ");
        PRINT("2048/224, 2048/256 or 3072/256\n");
        return CPA_STATUS_FAIL;
    }
    ikeDsaSetup->pLenInBytes = pLenInBits / NUM_BITS_IN_BYTE;
    ikeDsaSetup->qLenInBytes = qLenInBits / NUM_BITS_IN_BYTE;
    ikeDsaSetup->numBuffers = numBuffs;
    ikeDsaSetup->numLoops = numLoops;
    ikeDsaSetup->syncMode = syncMode;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupIkeDsaTest);
