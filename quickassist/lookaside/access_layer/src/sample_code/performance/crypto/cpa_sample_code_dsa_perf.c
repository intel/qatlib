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
 * @file cpa_sample_code_dsa_perf.c
 *
 * @ingroup dsaPerformance
 *
 * @description
 *      This file contains the DSA performance functions
 *
 *****************************************************************************/

#include "cpa_cy_dsa.h"
#include "cpa_sample_code_crypto_utils.h"
#ifdef POLL_INLINE
#include "icp_sal_poll.h"
#endif
#ifdef SC_DEV_INFO_ENABLED
#include "cpa_dev.h"
#endif
#include "qat_perf_cycles.h"
#define DEFAULT_H_VALUE (2)

#define ALLOC_STRUCT(ptr, size, FREE_MEM_FUNC)                                 \
    do                                                                         \
    {                                                                          \
        ptr = qaeMemAlloc(size * setup->numBuffers);                           \
        if (NULL == ptr)                                                       \
        {                                                                      \
            PRINT_ERR("Could not allocate memory\n");                          \
            FREE_MEM_FUNC;                                                     \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
        memset(ptr, 0, size * setup->numBuffers);                              \
    } while (0)

CpaBoolean msgFlagSym = CPA_FALSE;
/*****************************************************************
 * Declare a static 1024/160 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U dsa_1024_160_p[] = {
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

static Cpa8U dsa_1024_160_q[] = {0x9D, 0x6D, 0x96, 0xC4, 0xB8, 0x69, 0x37,
                                 0xC1, 0x60, 0x6D, 0x6E, 0xBA, 0x37, 0x5C,
                                 0x46, 0x25, 0x49, 0x3C, 0x50, 0x33};

/*****************************************************************
 * Declare a static 2048/224 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U dsa_2048_224_p[] = {
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

static Cpa8U dsa_2048_224_q[] = {0x8a, 0xad, 0x30, 0x8a, 0x52, 0x54, 0x0f,
                                 0x30, 0xf9, 0xe4, 0x8b, 0x0b, 0xe0, 0xfd,
                                 0x3e, 0x8d, 0xa1, 0xba, 0xd8, 0x07, 0x63,
                                 0x8b, 0x40, 0x38, 0x30, 0x25, 0x81, 0x93};

/*****************************************************************
 * Declare a static 2048/256 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U dsa_2048_256_p[] = {
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

static Cpa8U dsa_2048_256_q[] = {
    0xa3, 0x4f, 0x3a, 0xaa, 0x84, 0x9b, 0x1e, 0x28, 0xd3, 0x82, 0x3b,
    0x89, 0x6f, 0xb6, 0xe2, 0x0f, 0xfe, 0x07, 0xdb, 0xe4, 0x85, 0xa5,
    0x81, 0x6c, 0xbb, 0x14, 0x3f, 0x97, 0xf1, 0x47, 0x6a, 0xf9};
/*****************************************************************
 * Declare a static 3072/256 bit P/Q pair that satisfies FIPS186-3
 * ***************************************************************/
static Cpa8U dsa_3072_256_p[] = {
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

static Cpa8U dsa_3072_256_q[] = {
    0xc4, 0x06, 0xcd, 0x06, 0x69, 0xd9, 0x82, 0x2f, 0x5e, 0x41, 0x91,
    0x3c, 0x9c, 0xb8, 0xa3, 0x06, 0xee, 0x25, 0x68, 0xdc, 0x22, 0x8c,
    0x4a, 0x39, 0x96, 0x01, 0xe3, 0x57, 0x93, 0xf4, 0x4e, 0x41};
extern Cpa32U packageIdCount_g;

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaVerifyCb
 *
 * @description
 *     handle callbacks due to asymmetric call of cpaDsaVerify
 *
 *****************************************************************************/
static void dsaVerifyCb(void *pCallbackTag,
                        CpaStatus status,
                        void *pOpData,
                        CpaBoolean verifyStatus)
{
    processCallback(pCallbackTag);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaSignRSCb
 *
 * @description
 *     handle callbacks due to asymmetric call of cpaCyDsaSignRS
 *
 *****************************************************************************/
static void dsaSignRSCb(void *pCallbackTag,
                        CpaStatus status,
                        void *pOpData,
                        CpaBoolean protocolStatus,
                        CpaFlatBuffer *pR,
                        CpaFlatBuffer *pS)
{
    processCallback(pCallbackTag);
}

#ifdef POLL_INLINE
/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaVerifyCb
 *
 * @description
 *     Generic callback for asynchronous Generation of G, Y and sign R & S.
 *
 *****************************************************************************/

static void processGenCB(void *pCallbackTag,
                         CpaStatus status,
                         CpaBoolean protocolStatus)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    /*check perf_data pointer is valid*/
    if (pPerfData == NULL)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    if (CPA_FALSE == protocolStatus)
    {
        PRINT_ERR("DSA protocol checks failed\n");
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DSA Gen callback failed\n");
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    /* response has been received */
    pPerfData->responses++;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaVerifyCb
 *
 * @description
 *     handle callbacks due to asymmetric call of cpaCyDsaGenGParam
 *
 *****************************************************************************/
static void dsaGenGCb(void *pCallbackTag,
                      CpaStatus status,
                      void *pOpData,
                      CpaBoolean protocolStatus,
                      CpaFlatBuffer *pOut)
{
    processGenCB(pCallbackTag, status, protocolStatus);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaVerifyCb
 *
 * @description
 *     handle callbacks due to asymmetric call of cpaDsaVerify
 *
 *****************************************************************************/
static void dsaGenYCb(void *pCallbackTag,
                      CpaStatus status,
                      void *pOpData,
                      CpaBoolean protocolStatus,
                      CpaFlatBuffer *pOut)
{
    processGenCB(pCallbackTag, status, protocolStatus);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaVerifyCb
 *
 * @description
 *     handle callbacks due to asymmetric call of cpaCyDsaSignRS
 *
 *****************************************************************************/
static void dsaGenRSCb(void *pCallbackTag,
                       CpaStatus status,
                       void *pOpData,
                       CpaBoolean protocolStatus,
                       CpaFlatBuffer *pR,
                       CpaFlatBuffer *pS)
{
    processGenCB(pCallbackTag, status, protocolStatus);
}
#endif

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaGenRandom
 *
 * @description
 *     Populate a CpaFlatBuffer with a random number which is less than Q
 *
 *****************************************************************************/
void dsaGenRandom(CpaFlatBuffer *dsaRand, CpaFlatBuffer *dsaQ)
{
    /*generate random data */
    generateRandomData(dsaRand->pData, dsaRand->dataLenInBytes);
    /*make sure MSB is set */
    setCpaFlatBufferMSB(dsaRand);
    /*make sure its < q */
    makeParam1SmallerThanParam2(
        dsaRand->pData, dsaQ->pData, dsaRand->dataLenInBytes, CPA_TRUE);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaGenG
 *
 * @description
 *     Generate the DSA G parameter
 *
 *****************************************************************************/
CpaStatus dsaGenG(CpaInstanceHandle instanceHandle,
                  CpaCyDsaGParamGenOpData *gOpData,
                  CpaFlatBuffer *dsaG)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean protocolStatus = CPA_FALSE;
    Cpa32U retries = 0;
    CpaCyDsaGenCbFunc cbFunc = NULL;
    perf_data_t *pPerfData = NULL;
#ifdef POLL_INLINE
    CpaInstanceInfo2 instanceInfo2 = {0};
    if (poll_inline_g)
    {
        cbFunc = dsaGenGCb;
        cbFunc = dsaGenGCb;
        pPerfData = qaeMemAlloc(sizeof(perf_data_t));
        if (NULL == pPerfData)
        {
            PRINT_ERR("Error: Allocating perf_data for calcDigest\n");
            return CPA_STATUS_FAIL;
        }
        pPerfData->numOperations = SINGLE_OPERATION;
        pPerfData->responses = 0;
    }
#endif

#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&pPerfData);
            return CPA_STATUS_FAIL;
        }
    }
#endif
    do
    {

        status = cpaCyDsaGenGParam(
            instanceHandle, cbFunc, pPerfData, gOpData, &protocolStatus, dsaG);
        if (CPA_STATUS_RETRY == status)
        {
            retries++;
            /*once we get to many retries, perform a context switch
             * to give the acceleration engine a small break */
            if (RETRY_LIMIT == (retries % (RETRY_LIMIT + 1)))
            {
                AVOID_SOFTLOCKUP;
            }
        }
    } while (CPA_STATUS_RETRY == status);
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2.isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, instanceHandle, pPerfData->numOperations);
        }
        if (CPA_STATUS_FAIL == pPerfData->threadReturnStatus)
        {
            PRINT_ERR("DSA protocol Status failed - for Gen \'G\'\n");
            qaeMemFree((void **)&pPerfData);
            return CPA_STATUS_FAIL;
        }
        qaeMemFree((void **)&pPerfData);
        return CPA_STATUS_SUCCESS;
    }
#endif
    if (CPA_FALSE == protocolStatus || CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DSA protocol Status failed - status: %d, "
                  "protocolStatus: %d \n",
                  status,
                  protocolStatus);
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaGenY
 *
 * @description
 *     Generate the DSA Y parameter
 *
 *****************************************************************************/
CpaStatus dsaGenY(CpaInstanceHandle instanceHandle,
                  CpaCyDsaYParamGenOpData *yOpData,
                  CpaFlatBuffer *dsaY)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean protocolStatus = CPA_FALSE;
    perf_data_t *pPerfData = NULL;
    Cpa32U retries = 0;
    CpaCyDsaGenCbFunc cbFunc = NULL;
#ifdef POLL_INLINE
    CpaInstanceInfo2 instanceInfo2 = {0};
    if (poll_inline_g)
    {
        cbFunc = dsaGenYCb;

        pPerfData = qaeMemAlloc(sizeof(perf_data_t));
        if (NULL == pPerfData)
        {
            PRINT_ERR("Error: Allocating perf_data for calcDigest\n");
            return CPA_STATUS_FAIL;
        }
        pPerfData->numOperations = SINGLE_OPERATION;
        pPerfData->responses = 0;
    }
#endif

#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&pPerfData);
            return CPA_STATUS_FAIL;
        }
    }
#endif
    do
    {

        status = cpaCyDsaGenYParam(
            instanceHandle, cbFunc, pPerfData, yOpData, &protocolStatus, dsaY);
        if (CPA_STATUS_RETRY == status)
        {
            retries++;
            /*once we get to many retries, perform a context switch
             * to give the acceleration engine a small break */
            if (RETRY_LIMIT == (retries % (RETRY_LIMIT + 1)))
            {
                AVOID_SOFTLOCKUP;
            }
        }
    } while (CPA_STATUS_RETRY == status);
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2.isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, instanceHandle, pPerfData->numOperations);
        }

        if (CPA_STATUS_FAIL == pPerfData->threadReturnStatus)
        {
            PRINT_ERR("DSA protocol Status failed - for Gen \'Y\'\n");
            qaeMemFree((void **)&pPerfData);
            return CPA_STATUS_FAIL;
        }
        qaeMemFree((void **)&pPerfData);
        return CPA_STATUS_SUCCESS;
    }
#endif

    if (CPA_FALSE == protocolStatus || CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DSA protocol Status failed - status: %d, "
                  "protocolStatus: %d \n",
                  status,
                  protocolStatus);
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaGenRS
 *
 * @description
 *     Generate the DSA Signature R&S
 *
 *****************************************************************************/
CpaStatus dsaGenRS(CpaInstanceHandle instanceHandle,
                   CpaCyDsaRSSignOpData *rsOpData,
                   CpaFlatBuffer *dsaR,
                   CpaFlatBuffer *dsaS)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean protocolStatus = CPA_FALSE;
    perf_data_t *pPerfData = NULL;
    CpaCyDsaRSSignCbFunc rsSignCb = NULL;
    Cpa32U retries = 0;
#ifdef POLL_INLINE
    CpaInstanceInfo2 instanceInfo2 = {0};
    if (poll_inline_g)
    {
        rsSignCb = dsaGenRSCb;
        pPerfData = qaeMemAlloc(sizeof(perf_data_t));
        if (NULL == pPerfData)
        {
            PRINT_ERR("Error: Allocating perf_data for calcDigest\n");
            return CPA_STATUS_FAIL;
        }
        pPerfData->numOperations = SINGLE_OPERATION;
        pPerfData->responses = 0;
    }
#endif

#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&pPerfData);
            return CPA_STATUS_FAIL;
        }
    }
#endif
    do
    {

        status = cpaCyDsaSignRS(instanceHandle,
                                rsSignCb,
                                pPerfData,
                                rsOpData,
                                &protocolStatus,
                                dsaR,
                                dsaS);
        if (CPA_STATUS_RETRY == status)
        {
            retries++;
            /*once we get to many retries, perform a context switch
             * to give the acceleration engine a small break */
            if (RETRY_LIMIT == (retries % (RETRY_LIMIT + 1)))
            {
                AVOID_SOFTLOCKUP;
            }
        }
    } while (CPA_STATUS_RETRY == status);
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2.isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, instanceHandle, pPerfData->numOperations);
        }

        if (CPA_STATUS_FAIL == pPerfData->threadReturnStatus)
        {
            PRINT_ERR("DSA protocol Status failed - for Sign \'RS\'\n");
            qaeMemFree((void **)&pPerfData);
            return CPA_STATUS_FAIL;
        }
        qaeMemFree((void **)&pPerfData);
        return CPA_STATUS_SUCCESS;
    }
#endif
    if (CPA_FALSE == protocolStatus || CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DSA protocol Status failed - status: %d, "
                  "protocolStatus: %d \n",
                  status,
                  protocolStatus);
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaGenZ
 *
 * @description
 *     Generate Z, Z is the digest of the message which is used in DSA
 *     Signature generation and also used to verify a message
 *
 *****************************************************************************/
CpaStatus dsaGenZ(CpaInstanceHandle instanceHandle,
                  CpaFlatBuffer *msg,
                  CpaCySymHashAlgorithm hashAlg,
                  CpaFlatBuffer *dsaZ)
{
    CpaStatus status = CPA_STATUS_FAIL;
    /* Z is:  The leftmost min(N, outlen) bits of Hash(M), where:
     * - N is the bit length of q
     * - outlen is the bit length of the hash function output block
     * - M is the message to be signed
     *
     * when q len = length of output of hash operation:
     *       N = outLen so Z = digest of msg
     */


    CpaCyCapabilitiesInfo cap = {0};

    status = getCySpecificInstanceCapabilities(instanceHandle, &cap);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("getCySpecificInstanceCapabilities failed with status: %d\n",
                  status);
        return status;
    }

    if (cap.symSupported == CPA_FALSE)
    {
        if (msgFlagSym == CPA_FALSE)
        {
            PRINT(
                "DSA Warning! SYMMETRIC operation is not supported on Instance.\
                   Using calcSWDigest instead.\n");
            msgFlagSym = CPA_TRUE;
        }
        status = calcSWDigest(msg, dsaZ, hashAlg);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("DSA Calc SW Digest Error hashAlg %u\n", hashAlg);
        }
    }
    else
    {
        status = calcDigest(instanceHandle, msg, dsaZ, hashAlg);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("DSA Calc Digest Error hashAlg %u\n", hashAlg);
        }
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *
 * @description
 *      free all memory used in DSA performance code in this file
 *
 *****************************************************************************/
void freeDsaMem(dsa_test_params_t *setup,
                CpaFlatBuffer *dsaX,
                CpaFlatBuffer *dsaY,
                CpaFlatBuffer *dsaK,
                CpaFlatBuffer *dsaM,
                CpaFlatBuffer *dsaZ,
                CpaFlatBuffer *dsaR,
                CpaFlatBuffer *dsaS,
                CpaCyDsaVerifyOpData *verifyOpData,
                CpaCyDsaRSSignOpData *rsOpData,
                CpaFlatBuffer dsaG,
                CpaFlatBuffer dsaP,
                CpaFlatBuffer dsaH,
                CpaFlatBuffer dsaQ)
{
    freeArrayFlatBufferNUMA(dsaX, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaY, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaK, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaM, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaZ, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaR, setup->numBuffers);
    freeArrayFlatBufferNUMA(dsaS, setup->numBuffers);
    if (NULL != verifyOpData)
        qaeMemFree((void **)&verifyOpData);
    if (NULL != rsOpData)
        qaeMemFree((void **)&rsOpData);
    /*free the normal flatBuffer pData */
    qaeMemFreeNUMA((void **)&dsaG.pData);
    qaeMemFreeNUMA((void **)&dsaP.pData);
    qaeMemFreeNUMA((void **)&dsaH.pData);
    qaeMemFreeNUMA((void **)&dsaQ.pData);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *
 * @description
 *      Macro to free all memory used in DSA performance code in this file
 *
 *****************************************************************************/
#define FREE_DSA_MEM                                                           \
    freeDsaMem(setup,                                                          \
               dsaX,                                                           \
               dsaY,                                                           \
               dsaK,                                                           \
               dsaM,                                                           \
               dsaZ,                                                           \
               dsaR,                                                           \
               dsaS,                                                           \
               verifyOpData,                                                   \
               NULL,                                                           \
               dsaG,                                                           \
               dsaP,                                                           \
               dsaH,                                                           \
               dsaQ)

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *
 * @description
 *      Macro to free all memory used in DSA sign performance code in this file
 *
 *****************************************************************************/
#define FREE_DSA_SIGN_MEM                                                      \
    freeDsaMem(setup,                                                          \
               dsaX,                                                           \
               dsaY,                                                           \
               dsaK,                                                           \
               dsaM,                                                           \
               dsaZ,                                                           \
               dsaR,                                                           \
               dsaS,                                                           \
               NULL,                                                           \
               rsOpData,                                                       \
               dsaG,                                                           \
               dsaP,                                                           \
               dsaH,                                                           \
               dsaQ)

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaPerform
 *
 * @description
 *     This function generates all the DSA parameters required to perform a DSA
 *     sign and DSA verify operation. A user defined number of random messages
 *     are generated and signed, then the signature is verified
 *
 *****************************************************************************/
CpaStatus dsaPerform(dsa_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U outerLoop = 0;
    CpaBoolean verifyStatus = CPA_TRUE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    /*DSA parameters */
    /*DSA Q parameter, this shall be populated by the hard coded Q at the top
     * of this file */
    CpaFlatBuffer dsaQ = {0};
    /*random number X used to generate Y and Sign R&S */
    CpaFlatBuffer *dsaX = NULL;
    /*DSA P parameter, this shall be populated by the hard coded P at the top
     * of this file */
    CpaFlatBuffer dsaP = {0};
    /*H is used to generate G, H is hard coded to DEFAULT_H_VALUE */
    CpaFlatBuffer dsaH = {0};
    /* DSA G parameter used to generate Y, the signature R&S, and to verify */
    CpaFlatBuffer dsaG = {0};
    /*DSA Y parameter is used in the verification stage */
    CpaFlatBuffer *dsaY = NULL;
    /*K is a random number used in the generation of signature R&S */
    CpaFlatBuffer *dsaK = NULL;
    /*M is the message to be signed */
    CpaFlatBuffer *dsaM = NULL;
    /*R&S is used to store the DSA Signature */
    CpaFlatBuffer *dsaR = NULL;
    CpaFlatBuffer *dsaS = NULL;
    /*Z is the digest of the message in dsaM */
    CpaFlatBuffer *dsaZ = NULL;
    perf_data_t *pDsaData = NULL;
    /*GCC compiler complains without the double {{}} to init the following
     * structures*/
    CpaCyDsaGParamGenOpData gOpData = {{0, NULL}, {0, NULL}, {0, NULL}};
    CpaCyDsaYParamGenOpData yOpData = {{0, NULL}, {0, NULL}, {0, NULL}};
    CpaCyDsaRSSignOpData rsOpData = {
        {0, NULL}, {0, NULL}, {0, NULL}, {0, NULL}, {0, NULL}, {0, NULL}};
    CpaCyDsaVerifyOpData *verifyOpData = NULL;
    Cpa8U *pDataPtr = NULL;
    Cpa32U sizeOfp = 0;
    Cpa8U *qDataPtr = NULL;
    Cpa32U sizeOfq = 0;
    Cpa32U node = 0;
    CpaCyDsaVerifyCbFunc cbFunc = NULL;
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    perf_data_t *pPerfData = setup->performanceStats;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
#endif
    DECLARE_IA_CYCLE_COUNT_VARIABLES();

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
            goto barrier;
        }
    }
#endif
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not determibne node for memory allocation\n");
        goto barrier;
    }
    pDsaData = setup->performanceStats;
    pDsaData->threadReturnStatus = CPA_STATUS_FAIL;
    pDsaData->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;
    coo_init(pDsaData, pDsaData->numOperations);

    /*check the p and q input len and set the pointers to the data */
    if (MODULUS_1024_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
        EXPONENT_160_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_1024_160_p;
        qDataPtr = dsa_1024_160_q;
        sizeOfp = sizeof(dsa_1024_160_p);
        sizeOfq = sizeof(dsa_1024_160_q);
    }
    else if (MODULUS_2048_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_224_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_2048_224_p;
        qDataPtr = dsa_2048_224_q;
        sizeOfp = sizeof(dsa_2048_224_p);
        sizeOfq = sizeof(dsa_2048_224_q);
    }
    else if (MODULUS_2048_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_256_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_2048_256_p;
        qDataPtr = dsa_2048_256_q;
        sizeOfp = sizeof(dsa_2048_256_p);
        sizeOfq = sizeof(dsa_2048_256_q);
    }
    else if (MODULUS_3072_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_256_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_3072_256_p;
        qDataPtr = dsa_3072_256_q;
        sizeOfp = sizeof(dsa_3072_256_p);
        sizeOfq = sizeof(dsa_3072_256_q);
    }
    else
    {
        PRINT_ERR("P & Q len not supported\n");
        /*thread status is init to fail so just return fail here*/
        goto barrier;
    }
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&pDsaData->comp, 0);

    /*Allocate all the buffers */
    ALLOC_STRUCT(dsaX, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(dsaY, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(dsaK, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(dsaM, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(dsaR, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(dsaS, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(dsaZ, sizeof(CpaFlatBuffer), FREE_DSA_MEM);
    ALLOC_STRUCT(verifyOpData, sizeof(CpaCyDsaVerifyOpData), FREE_DSA_MEM);
    /************************************************************************
     * STAGE 1 Setup up the DSA parameters, generate X, G, Y, K, Z,
     *          generate user defined number of messages to be signed
     *          calculate the digest of the messages
     *          sign all the messages
     *          setup the verification data structure
     **************************************************************************/
    /*set Q */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaQ,
                         setup->qLenInBytes,
                         qDataPtr,
                         sizeOfq,
                         FREE_DSA_MEM);

    /*generate X for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*Choose X is generated by random method, where 0 < X < Q */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaX[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);
        dsaGenRandom(&dsaX[i], &dsaQ);
    }

    /*set P */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaP,
                         setup->pLenInBytes,
                         pDataPtr,
                         sizeOfp,
                         FREE_DSA_MEM);

    /***************************************************************************
     * set genG opData and generate G
     * ************************************************************************/

    /*H is required to genG */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaH,
                         setup->pLenInBytes,
                         NULL,
                         0,
                         FREE_DSA_MEM);
    memset(dsaH.pData, 0, dsaH.dataLenInBytes);
    dsaH.pData[setup->pLenInBytes - 1] = DEFAULT_H_VALUE;

    /*allocate space for G */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaG,
                         setup->pLenInBytes,
                         NULL,
                         0,
                         FREE_DSA_MEM);

    /*set opData to generate G */
    gOpData.P.pData = dsaP.pData;
    gOpData.P.dataLenInBytes = dsaP.dataLenInBytes;
    gOpData.Q.pData = dsaQ.pData;
    gOpData.Q.dataLenInBytes = dsaQ.dataLenInBytes;
    gOpData.H.pData = dsaH.pData;
    gOpData.H.dataLenInBytes = dsaH.dataLenInBytes;
    status = dsaGenG(setup->cyInstanceHandle, &gOpData, &dsaG);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to generate DSA parameter G\n");
        FREE_DSA_MEM;
        goto barrier;
    }

    /*generate a Y for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*set the opData to gen Y */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaY[i],
                             setup->pLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);
        yOpData.P.pData = dsaP.pData;
        yOpData.P.dataLenInBytes = dsaP.dataLenInBytes;
        yOpData.G.pData = dsaG.pData;
        yOpData.G.dataLenInBytes = dsaG.dataLenInBytes;
        yOpData.X.pData = dsaX[i].pData;
        yOpData.X.dataLenInBytes = dsaX[i].dataLenInBytes;
        status = dsaGenY(setup->cyInstanceHandle, &yOpData, &dsaY[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating Y for buffer %d\n", i);
            /*free all the pData buffers allocated and Array of pointers
             * allocated */
            FREE_DSA_MEM;
            goto barrier;
        }

        /*Generate a random per-message value K, where 0 < K < Q. */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaK[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);
        dsaGenRandom(&dsaK[i], &dsaQ);

        /*generate a message to sign */
        /*allocate space for message */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaM[i],
                             setup->pLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);

        /*allocate space for digest of message */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaZ[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);

        /*generate random message */
        generateRandomData(dsaM[i].pData, dsaM[i].dataLenInBytes);

        /*calculate digest of message */
        status = dsaGenZ(
            setup->cyInstanceHandle, &dsaM[i], setup->hashAlg, &dsaZ[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating Z for buffer %d\n", i);
            FREE_DSA_MEM;
            goto barrier;
        }

        /*Gen R & S signature */
        rsOpData.G.pData = dsaG.pData;
        rsOpData.G.dataLenInBytes = dsaG.dataLenInBytes;
        rsOpData.K.pData = dsaK[i].pData;
        rsOpData.K.dataLenInBytes = dsaK[i].dataLenInBytes;
        rsOpData.P.pData = dsaP.pData;
        rsOpData.P.dataLenInBytes = dsaP.dataLenInBytes;
        rsOpData.Q.pData = dsaQ.pData;
        rsOpData.Q.dataLenInBytes = dsaQ.dataLenInBytes;
        rsOpData.X.pData = dsaX[i].pData;
        rsOpData.X.dataLenInBytes = dsaX[i].dataLenInBytes;
        rsOpData.Z.pData = dsaZ[i].pData;
        rsOpData.Z.dataLenInBytes = dsaZ[i].dataLenInBytes;
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaR[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaS[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_MEM);
        status =
            dsaGenRS(setup->cyInstanceHandle, &rsOpData, &dsaR[i], &dsaS[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating R&S for buffer %d\n", i);
            FREE_DSA_MEM;
            goto barrier;
        }

        /*Verify signature */

        verifyOpData[i].P.pData = dsaP.pData;
        verifyOpData[i].P.dataLenInBytes = dsaP.dataLenInBytes;
        verifyOpData[i].Q.pData = dsaQ.pData;
        verifyOpData[i].Q.dataLenInBytes = dsaQ.dataLenInBytes;
        verifyOpData[i].G.pData = dsaG.pData;
        verifyOpData[i].G.dataLenInBytes = dsaG.dataLenInBytes;
        verifyOpData[i].Y.pData = dsaY[i].pData;
        verifyOpData[i].Y.dataLenInBytes = dsaY[i].dataLenInBytes;
        verifyOpData[i].Z.pData = dsaZ[i].pData;
        verifyOpData[i].Z.dataLenInBytes = dsaZ[i].dataLenInBytes;
        verifyOpData[i].R.pData = dsaR[i].pData;
        verifyOpData[i].R.dataLenInBytes = dsaR[i].dataLenInBytes;
        verifyOpData[i].S.pData = dsaS[i].pData;
        verifyOpData[i].S.dataLenInBytes = dsaS[i].dataLenInBytes;
    }
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = dsaVerifyCb;
    }

    /************************************************************************
     * STAGE 2 repeatedly verify all the signatures and measure the performance
     *************************************************************************
     */

    /*this barrier will wait until all threads get to this point */
barrier:
    sampleCodeBarrier();
    /* exiting the function if any failure occurs in previous steps*/
    if (CPA_STATUS_SUCCESS != status)
    {
#ifdef POLL_INLINE
        qaeMemFree((void **)&instanceInfo2);
#endif
        return status;
    }
    /* get a timestamp before submitting any requests. After submitting
     * all requests a final timestamp is taken in the callback function.
     * These two times and the number of requests submitted are used  to
     * calculate operations per second  */
    pDsaData->startCyclesTimestamp = sampleCodeTimestamp();
    for (outerLoop = 0; outerLoop < setup->numLoops; outerLoop++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            do
            {
                coo_req_start(pDsaData);
                status = cpaCyDsaVerify(setup->cyInstanceHandle,
                                        cbFunc,
                                        pDsaData,
                                        &verifyOpData[i],
                                        &verifyStatus);
                coo_req_stop(pDsaData, status);
                if (CPA_STATUS_RETRY == status)
                {
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo2->isPolled)
                        {
                            sampleCodeAsymPollInstance(setup->cyInstanceHandle,
                                                       0);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    pDsaData->retries++;
                    /*once we get to many retries, perform a context switch
                     * to give the acceleration engine a small break */
                    if (RETRY_LIMIT == (pDsaData->retries % (RETRY_LIMIT + 1)))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);
            if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                BUSY_LOOP();
            }
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo2->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(
                            pDsaData, setup->cyInstanceHandle, &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif
            /*if for some reason the DSA verify returns fail, decrease the
             * numOperations expected in the callback so that the code does not
             * wait forever */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("DSA Verify function failed with status:%d\n",
                          status);
                break;
            }
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, setup->cyInstanceHandle, pPerfData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pDsaData, setup->syncMode, setup->numBuffers, setup->numLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Thread %u timeout.", setup->threadID);
        }
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        IA_CYCLE_COUNT_CALCULATION();
    }
    coo_average(pDsaData);
    coo_deinit(pDsaData);

    /*free Arrays of buffer pointers and pData */
    FREE_DSA_MEM;
    sampleCodeSemaphoreDestroy(&pDsaData->comp);
    pDsaData->threadReturnStatus = status;
#ifdef POLL_INLINE
    qaeMemFree((void **)&instanceInfo2);
#endif
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}
EXPORT_SYMBOL(dsaPerform);

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaSignPerform
 *
 * @description
 *     This function generates all the DSA parameters required to perform a DSA
 *     sign operation. A user defined number of random messages are generated
 *     and signed.
 *
 *****************************************************************************/
CpaStatus dsaSignPerform(dsa_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U outerLoop = 0;
    CpaBoolean protocolStatus = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;
    /*DSA parameters */
    /*DSA Q parameter, this shall be populated by the hard coded Q at the top
     * of this file */
    CpaFlatBuffer dsaQ = {0};
    /*random number X used to generate Y and Sign R&S */
    CpaFlatBuffer *dsaX = NULL;
    /*DSA P parameter, this shall be populated by the hard coded P at the top
     * of this file */
    CpaFlatBuffer dsaP = {0};
    /*H is used to generate G, H is hard coded to DEFAULT_H_VALUE */
    CpaFlatBuffer dsaH = {0};
    /* DSA G parameter used to generate Y, the signature R&S, and to verify */
    CpaFlatBuffer dsaG = {0};
    /*DSA Y parameter is used in the verification stage */
    CpaFlatBuffer *dsaY = NULL;
    /*K is a random number used in the generation of signature R&S */
    CpaFlatBuffer *dsaK = NULL;
    /*M is the message to be signed */
    CpaFlatBuffer *dsaM = NULL;
    /*R&S is used to store the DSA Signature */
    CpaFlatBuffer *dsaR = NULL;
    CpaFlatBuffer *dsaS = NULL;
    /*Z is the digest of the message in dsaM */
    CpaFlatBuffer *dsaZ = NULL;
    perf_data_t *pDsaData = NULL;
    /*GCC compiler complains without the double {{}} to init the following
     * structures*/
    CpaCyDsaGParamGenOpData gOpData = {{0, NULL}, {0, NULL}, {0, NULL}};
    CpaCyDsaYParamGenOpData yOpData = {{0}};
    CpaCyDsaRSSignOpData *rsOpData = NULL;
    Cpa8U *pDataPtr = NULL;
    Cpa32U sizeOfp = 0;
    Cpa8U *qDataPtr = NULL;
    Cpa32U sizeOfq = 0;
    Cpa32U node = 0;
    CpaCyDsaRSSignCbFunc cbFunc = NULL;
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    perf_data_t *pPerfData = setup->performanceStats;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
#endif
    DECLARE_IA_CYCLE_COUNT_VARIABLES();

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
            goto barrier;
        }
    }
#endif
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not determine node for memory allocation\n");
        goto barrier;
    }
    pDsaData = setup->performanceStats;
    pDsaData->threadReturnStatus = CPA_STATUS_FAIL;
    pDsaData->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;

    coo_init(pDsaData, pDsaData->numOperations);

    /*check the p and q input len and set the pointers to the data */
    if (MODULUS_1024_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
        EXPONENT_160_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_1024_160_p;
        qDataPtr = dsa_1024_160_q;
        sizeOfp = sizeof(dsa_1024_160_p);
        sizeOfq = sizeof(dsa_1024_160_q);
    }
    else if (MODULUS_2048_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_224_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_2048_224_p;
        qDataPtr = dsa_2048_224_q;
        sizeOfp = sizeof(dsa_2048_224_p);
        sizeOfq = sizeof(dsa_2048_224_q);
    }
    else if (MODULUS_2048_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_256_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_2048_256_p;
        qDataPtr = dsa_2048_256_q;
        sizeOfp = sizeof(dsa_2048_256_p);
        sizeOfq = sizeof(dsa_2048_256_q);
    }
    else if (MODULUS_3072_BIT / NUM_BITS_IN_BYTE == setup->pLenInBytes &&
             EXPONENT_256_BIT / NUM_BITS_IN_BYTE == setup->qLenInBytes)
    {
        pDataPtr = dsa_3072_256_p;
        qDataPtr = dsa_3072_256_q;
        sizeOfp = sizeof(dsa_3072_256_p);
        sizeOfq = sizeof(dsa_3072_256_q);
    }
    else
    {
        PRINT_ERR("P & Q len not supported\n");
        /*thread status is init to fail so just return fail here*/
        goto barrier;
    }
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&pDsaData->comp, 0);

    /*Allocate all the buffers */
    ALLOC_STRUCT(dsaX, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(dsaY, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(dsaK, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(dsaM, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(dsaR, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(dsaS, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(dsaZ, sizeof(CpaFlatBuffer), FREE_DSA_SIGN_MEM);
    ALLOC_STRUCT(rsOpData, sizeof(CpaCyDsaRSSignOpData), FREE_DSA_SIGN_MEM);
    /************************************************************************
     * STAGE 1 Setup up the DSA parameters, generate X, G, Y, K, Z,
     *          generate user defined number of messages to be signed
     *          calculate the digest of the messages
     **************************************************************************/
    /*set Q */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaQ,
                         setup->qLenInBytes,
                         qDataPtr,
                         sizeOfq,
                         FREE_DSA_SIGN_MEM);

    /*generate X for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*Choose X is generated by random method, where 0 < X < Q */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaX[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);
        dsaGenRandom(&dsaX[i], &dsaQ);
    }

    /*set P */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaP,
                         setup->pLenInBytes,
                         pDataPtr,
                         sizeOfp,
                         FREE_DSA_SIGN_MEM);

    /***************************************************************************
     * set genG opData and generate G
     * ************************************************************************/

    /*H is required to genG */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaH,
                         setup->pLenInBytes,
                         NULL,
                         0,
                         FREE_DSA_SIGN_MEM);
    memset(dsaH.pData, 0, dsaH.dataLenInBytes);
    dsaH.pData[setup->pLenInBytes - 1] = DEFAULT_H_VALUE;

    /*allocate space for G */
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &dsaG,
                         setup->pLenInBytes,
                         NULL,
                         0,
                         FREE_DSA_SIGN_MEM);

    /*set opData to generate G */
    gOpData.P.pData = dsaP.pData;
    gOpData.P.dataLenInBytes = dsaP.dataLenInBytes;
    gOpData.Q.pData = dsaQ.pData;
    gOpData.Q.dataLenInBytes = dsaQ.dataLenInBytes;
    gOpData.H.pData = dsaH.pData;
    gOpData.H.dataLenInBytes = dsaH.dataLenInBytes;
    status = dsaGenG(setup->cyInstanceHandle, &gOpData, &dsaG);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to generate DSA parameter G\n");
        FREE_DSA_SIGN_MEM;
        goto barrier;
    }

    /*generate a Y for each buffer */
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*set the opData to gen Y */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaY[i],
                             setup->pLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);
        yOpData.P.pData = dsaP.pData;
        yOpData.P.dataLenInBytes = dsaP.dataLenInBytes;
        yOpData.G.pData = dsaG.pData;
        yOpData.G.dataLenInBytes = dsaG.dataLenInBytes;
        yOpData.X.pData = dsaX[i].pData;
        yOpData.X.dataLenInBytes = dsaX[i].dataLenInBytes;
        status = dsaGenY(setup->cyInstanceHandle, &yOpData, &dsaY[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating Y for buffer %d\n", i);
            /*free all the pData buffers allocated and Array of pointers
             * allocated */
            FREE_DSA_SIGN_MEM;
            goto barrier;
        }

        /*Generate a random per-message value K, where 0 < K < Q. */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaK[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);
        dsaGenRandom(&dsaK[i], &dsaQ);

        /*generate a message to sign */
        /*allocate space for message */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaM[i],
                             setup->pLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);

        /*allocate space for digest of message */
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaZ[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);

        /*generate random message */
        generateRandomData(dsaM[i].pData, dsaM[i].dataLenInBytes);

        /*calculate digest of message */
        status = dsaGenZ(
            setup->cyInstanceHandle, &dsaM[i], setup->hashAlg, &dsaZ[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error Generating Z for buffer %d\n", i);
            FREE_DSA_SIGN_MEM;
            goto barrier;
        }

        /* Prepare data for R & S signature */
        rsOpData[i].G.pData = dsaG.pData;
        rsOpData[i].G.dataLenInBytes = dsaG.dataLenInBytes;
        rsOpData[i].K.pData = dsaK[i].pData;
        rsOpData[i].K.dataLenInBytes = dsaK[i].dataLenInBytes;
        rsOpData[i].P.pData = dsaP.pData;
        rsOpData[i].P.dataLenInBytes = dsaP.dataLenInBytes;
        rsOpData[i].Q.pData = dsaQ.pData;
        rsOpData[i].Q.dataLenInBytes = dsaQ.dataLenInBytes;
        rsOpData[i].X.pData = dsaX[i].pData;
        rsOpData[i].X.dataLenInBytes = dsaX[i].dataLenInBytes;
        rsOpData[i].Z.pData = dsaZ[i].pData;
        rsOpData[i].Z.dataLenInBytes = dsaZ[i].dataLenInBytes;
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaR[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &dsaS[i],
                             setup->qLenInBytes,
                             NULL,
                             0,
                             FREE_DSA_SIGN_MEM);
    }
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = dsaSignRSCb;
    }

    /************************************************************************
     * STAGE 2 repeatedly sign messages and measure the performance
     *************************************************************************
     */
    /*this barrier will wait until all threads get to this point */
barrier:
    sampleCodeBarrier();
    /* exiting the function if any failure occurs in previous steps*/
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
    /* get a timestamp before submitting any requests. After submitting
     * all requests a final timestamp is taken in the callback function.
     * These two times and the number of requests submitted are used  to
     * calculate operations per second  */
    pDsaData->startCyclesTimestamp = sampleCodeTimestamp();
    for (outerLoop = 0; outerLoop < setup->numLoops; outerLoop++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            do
            {
                coo_req_start(pDsaData);
                status = cpaCyDsaSignRS(setup->cyInstanceHandle,
                                        cbFunc,
                                        pDsaData,
                                        &rsOpData[i],
                                        &protocolStatus,
                                        &dsaR[i],
                                        &dsaS[i]);
                coo_req_stop(pDsaData, status);
                if (CPA_STATUS_RETRY == status)
                {
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo2->isPolled)
                        {
                            sampleCodeAsymPollInstance(setup->cyInstanceHandle,
                                                       0);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    pDsaData->retries++;
                    /*once we get to many retries, perform a context switch
                     * to give the acceleration engine a small break */
                    if (RETRY_LIMIT == (pDsaData->retries % (RETRY_LIMIT + 1)))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);
            if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                BUSY_LOOP();
            }
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo2->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(
                            pDsaData, setup->cyInstanceHandle, &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif
            /*if for some reason the DSA sign returns fail, decrease the
             * numOperations expected in the callback so that the code does not
             * wait forever */
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("DSA Sign function failed with status:%d\n", status);
                break;
            }
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, setup->cyInstanceHandle, pPerfData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pDsaData, setup->syncMode, setup->numBuffers, setup->numLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Thread %u timeout.", setup->threadID);
        }
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        IA_CYCLE_COUNT_CALCULATION();
    }
    coo_average(pDsaData);
    coo_deinit(pDsaData);
    /*free Arrays of buffer pointers and pData */
    FREE_DSA_SIGN_MEM;
    sampleCodeSemaphoreDestroy(&pDsaData->comp);
    pDsaData->threadReturnStatus = status;
#ifdef POLL_INLINE
    qaeMemFree((void **)&instanceInfo2);
#endif
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaPrintStats
 *
 * @description
 *     Print out the DSA perfomance
 *
 *****************************************************************************/
CpaStatus dsaPrintStats(thread_creation_data_t *data)
{
    PRINT("DSA VERIFY\n");
    PRINT("Modulus Size %19d\n", data->packetSize * NUM_BITS_IN_BYTE);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaSignPrintStats
 *
 * @description
 *     Print out the DSA sign only performance
 *
 *****************************************************************************/
CpaStatus dsaSignPrintStats(thread_creation_data_t *data)
{
    PRINT("DSA SIGN\n");
    PRINT("Modulus Size %19d\n", data->packetSize * NUM_BITS_IN_BYTE);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaPerformanceGen
 *
 * @description
 *     This function is called by the framework to execute the DSA performance
 *     thread. This is a generic function, which calls different performance
 *     functions based on passed argument.
 *
 *****************************************************************************/
static void dsaPerformanceGen(single_thread_test_data_t *testSetup,
                              dsa_step_t step)
{
    dsa_test_params_t dsaSetup = {0};
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    dsa_test_params_t *params = (dsa_test_params_t *)testSetup->setupPtr;
    CpaInstanceInfo2 instanceInfo = {0};
#ifdef SC_DEV_INFO_ENABLED
    CpaDeviceInfo deviceInfo = {0};
#endif

    testSetup->passCriteria = getPassCriteria();

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway */
    startBarrier();
    /*
     * In case of error scenario, the thread will exit early.
     * register the print function here itself to properly exit with statistics.
     */
    if (DSA_STEP_VERIFY == step)
    {
        testSetup->statsPrintFunc = (stats_print_func_t)dsaPrintStats;
    }
    else if (DSA_STEP_SIGNRS == step)
    {
        testSetup->statsPrintFunc = (stats_print_func_t)dsaSignPrintStats;
    }
    /*give our thread a unique memory location to store performance stats */
    dsaSetup.threadID = testSetup->threadID;
    dsaSetup.performanceStats = testSetup->performanceStats;
    dsaSetup.hashAlg = params->hashAlg;
    dsaSetup.pLenInBytes = params->pLenInBytes;
    dsaSetup.qLenInBytes = params->qLenInBytes;
    dsaSetup.numBuffers = params->numBuffers;
    dsaSetup.numLoops = params->numLoops;
    dsaSetup.syncMode = params->syncMode;
    /*get the instance handles so that we can start our thread on the selected
     * instance */
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("Could not get any instances\n");
        PRINT_ERR("DSA Thread FAILED\n");
        dsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Could not allocate memory for logical instances\n");
        dsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cpaCyGetInstances(numInstances, cyInstances);
    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances */
    dsaSetup.cyInstanceHandle =
        cyInstances[(testSetup->logicalQaInstance) % numInstances];

    status = cpaCyInstanceGetInfo2(dsaSetup.cyInstanceHandle, &instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        qaeMemFree((void **)&cyInstances);
        dsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }

#ifdef SC_DEV_INFO_ENABLED
    /* check whether asym service enabled or not for the instance */
    status = cpaGetDeviceInfo(instanceInfo.physInstId.packageId, &deviceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaGetDeviceInfo failed", __func__, __LINE__);
        dsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (CPA_FALSE == deviceInfo.cyAsymEnabled)
    {
        PRINT_ERR("%s::%d Error! cyAsymEnabled service not enabled for the "
                  "configured instance\n",
                  __func__,
                  __LINE__);
        dsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
#endif
    if (instanceInfo.physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo.physInstId.packageId;
    }
    dsaSetup.performanceStats->packageId = instanceInfo.physInstId.packageId;


    /*launch function that does all the work */
    if (DSA_STEP_VERIFY == step)
    {
        status = dsaPerform(&dsaSetup);
    }
    else if (DSA_STEP_SIGNRS == step)
    {
        status = dsaSignPerform(&dsaSetup);
    }
    else
    {
        PRINT_ERR("Incorrect step");
        status = CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("DSA Thread %u FAILED\n", testSetup->threadID);
        dsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaPerformance
 *
 * @description
 *     This function is called by the framework to execute the dsaPerform
 *     thread
 *
 *****************************************************************************/
void dsaPerformance(single_thread_test_data_t *testSetup)
{
    dsaPerformanceGen(testSetup, DSA_STEP_VERIFY);
}
EXPORT_SYMBOL(dsaPerformance);

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      dsaSignPerformance
 *
 * @description
 *     This function is called by the framework to execute the dsaSignPerform
 *     thread
 *
 *****************************************************************************/
void dsaSignPerformance(single_thread_test_data_t *testSetup)
{
    dsaPerformanceGen(testSetup, DSA_STEP_SIGNRS);
}
EXPORT_SYMBOL(dsaSignPerformance);

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      setupDsaTestGen
 *
 * @description
 *     This function setups up a DSA thread. Once called the user then calls the
 *      createThreads function which replicates this setup in threads across
 *      several cores, each using a separate acceleration engine instances.
 *      This is a generic function for setting up test, which defines different
 *      performance functions based on passed argument.
 *
 *****************************************************************************/
static CpaStatus setupDsaTestGen(Cpa32U pLenInBits,
                                 Cpa32U qLenInBits,
                                 sync_mode_t syncMode,
                                 Cpa32U numBuffers,
                                 Cpa32U numLoops,
                                 dsa_step_t step)
{
    /*setup is a multi-dimensional array that stores the setup for all thread
     * variations in an array of characters. We store our test setup at the
     * start of the second array ie index 0, [][0].
     * There may be multi thread types(setups) running as counted by
     * testTypeCount_g */

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure */
    dsa_test_params_t *dsaSetup = NULL;

    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    /*start crypto service if not already started */
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Error starting Crypto Services\n");
        return CPA_STATUS_FAIL;
    }
    if (iaCycleCount_g)
    {
#ifdef POLL_INLINE
        enablePollInline();
#endif
        timeStampTime_g = getTimeStampTime();
        PRINT("timeStampTime_g %llu\n", timeStampTime_g);
    }
    if (!poll_inline_g)
    {
        /* start polling threads if polling is enabled in the configuration file
         */
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }

    if (DSA_STEP_VERIFY == step)
    {
        testSetupData_g[testTypeCount_g].performance_function =
            (performance_func_t)dsaPerformance;
    }
    else if (DSA_STEP_SIGNRS == step)
    {
        testSetupData_g[testTypeCount_g].performance_function =
            (performance_func_t)dsaSignPerformance;
    }
    else
    {
        PRINT_ERR("Incorrect step");
        return CPA_STATUS_FAIL;
    }

    testSetupData_g[testTypeCount_g].packetSize = pLenInBits / NUM_BITS_IN_BYTE;
    dsaSetup = (dsa_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    /*then we store the test setup in the above location */
    if (MODULUS_1024_BIT == pLenInBits && EXPONENT_160_BIT == qLenInBits)
    {
        dsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA1;
    }
    else if (MODULUS_2048_BIT == pLenInBits && EXPONENT_224_BIT == qLenInBits)
    {
        dsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA224;
    }
    else if (MODULUS_2048_BIT == pLenInBits && EXPONENT_256_BIT == qLenInBits)
    {
        dsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA256;
    }
    else if (MODULUS_3072_BIT == pLenInBits && EXPONENT_256_BIT == qLenInBits)
    {
        dsaSetup->hashAlg = CPA_CY_SYM_HASH_SHA256;
    }
    else
    {
        PRINT_ERR("pLen & qLen combination not supported, must be 1024/160 ");
        PRINT("2048/224, 2048/256 or 3072/256\n");
        return CPA_STATUS_FAIL;
    }
    dsaSetup->pLenInBytes = pLenInBits / NUM_BITS_IN_BYTE;
    dsaSetup->qLenInBytes = qLenInBits / NUM_BITS_IN_BYTE;
    dsaSetup->syncMode = syncMode;
    dsaSetup->numBuffers = numBuffers;
    dsaSetup->numLoops = numLoops;

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      setupDsaSignTest
 *
 * @description
 *     This function setups up a DSA sign only test.
 *
 *****************************************************************************/
CpaStatus setupDsaSignTest(Cpa32U pLenInBits,
                           Cpa32U qLenInBits,
                           sync_mode_t syncMode,
                           Cpa32U numBuffers,
                           Cpa32U numLoops)
{
    return setupDsaTestGen(pLenInBits,
                           qLenInBits,
                           syncMode,
                           numBuffers,
                           numLoops,
                           DSA_STEP_SIGNRS);
}

/**
 *****************************************************************************
 * @ingroup dsaPerformance
 *      setupDsaTest
 *
 * @description
 *     This function setups up a DSA sign & verify test.
 *
 *****************************************************************************/
CpaStatus setupDsaTest(Cpa32U pLenInBits,
                       Cpa32U qLenInBits,
                       sync_mode_t syncMode,
                       Cpa32U numBuffers,
                       Cpa32U numLoops)
{
    return setupDsaTestGen(pLenInBits,
                           qLenInBits,
                           syncMode,
                           numBuffers,
                           numLoops,
                           DSA_STEP_VERIFY);
}
