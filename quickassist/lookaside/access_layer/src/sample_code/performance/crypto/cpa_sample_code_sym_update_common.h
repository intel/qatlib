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
 * @file cpa_sample_code_sym_update.c
 *
 * @defgroup sampleSymmetricPerf  Symmetric Performance code
 *
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      This file contains the main symmetric session update performance
 *      sample code. It is capable of performing all ciphers, all hashes,
 *      authenticated hashes and algorithm chaining with session update
 *      operation.
 *
 *****************************************************************************/
#ifndef CPA_SAMPLE_CODE_SYM_UPDATE_COMMON_H_
#define CPA_SAMPLE_CODE_SYM_UPDATE_COMMON_H_

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_sym_dp.h"
#include "icp_sal_poll.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_cy_common.h"

#define CIPHER_ALG_NUM (15)
#define HASH_ALG_NUM (13)
#define ALGCHAIN_CIPHER_NUM (18)
#define ALGCHAIN_HASH_NUM (17)
#define SIZE_BIT_IN_BYTES(bits) ((bits + 7) / 8)
#define DIGEST_LENGTH_16 (16)
#define DIGEST_LENGTH_4 (4)

#if CY_API_VERSION_AT_LEAST(2, 2)
// Test config struct
typedef struct testSetupCipher_s
{
    CpaCySymCipherAlgorithm cipherAlgorithm;
    Cpa32U cipherKeyLen;
} testSetupCipher_t;

typedef struct testSetupHash_s
{
    CpaCySymHashAlgorithm hashAlgorithm;
    Cpa32U authKeyLen;
    Cpa32U digestResultLenInBytes;
} testSetupHash_t;

extern CpaStatus getCryptoInstanceMapping(void);
extern Cpa16U numInstances_g;
extern Cpa32U *cyInstMap_g;
extern Cpa32U *dcInstMap_g;
extern Cpa32U instMap_g;
extern Cpa16U numInst_g;
extern CpaBoolean usePartial_g;

void symUpdateCallback(void *pCallbackTag,
                       CpaStatus status,
                       const CpaCySymOp operationType,
                       void *pOpData,
                       CpaBufferList *pDstBuffer,
                       CpaBoolean verifyResult);

void symDpUpdateCallback(CpaCySymDpOpData *pOpData,
                         CpaStatus status,
                         CpaBoolean verifyResult);

void sessionUpdatePrintStatsDp(thread_creation_data_t *data);

CpaStatus allocAndFillRandom(Cpa8U **pBuff, Cpa32U len, Cpa32U node);

void freeUpdateMem(void **mem);

CpaStatus setupBufferList(Cpa8U **pBuff,
                          Cpa32U numBuff,
                          Cpa32U bufferSize,
                          CpaBufferList **pSrcBuffer,
                          Cpa32U node);

void setupUpdateData(CpaCySymSessionCtx sessionCtx,
                     CpaCySymSessionUpdateData *pUpdateData,
                     Cpa8U **pUpdateCipherKey,
                     Cpa8U **pUpdateHashKey,
                     CpaBoolean updateCipherDirection);

CpaStatus symSetupSessionUpdateTest(CpaCySymOp symOperation,
                                    CpaCySymCipherAlgorithm cipherAlgorithm,
                                    Cpa32U cipherKeyLen,
                                    CpaCySymHashAlgorithm hashAlgorithm,
                                    Cpa32U authKeyLen,
                                    CpaCySymHashMode hashMode,
                                    Cpa32U digestResultLenInBytes,
                                    CpaCySymAlgChainOrder algChainOrder,
                                    CpaCyPriority priority,
                                    sync_mode_t syncMode,
                                    Cpa32U packetSize,
                                    Cpa32U numOfPacketsInBuffer,
                                    Cpa32U numBuffers,
                                    Cpa32U numLoops,
                                    CpaBoolean isDpApi,
                                    void *samplePerformanceFunction);
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */

#endif /* CPA_SAMPLE_CODE_SYM_UPDATE_COMMON_H_ */
