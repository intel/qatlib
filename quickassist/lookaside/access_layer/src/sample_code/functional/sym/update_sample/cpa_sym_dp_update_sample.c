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

/*
 * This is sample code that demonstrates usage of the symmetric DP API, and
 * specifically using this API to perform a "chained" cipher and hash
 * operation.  It performs a KASUMI F9 hash on the ciphertext and then
 * encrypts some sample text using the KASUMI_F8 algorithm. It updates session
 * cipher key and auth key. It performs new cipher and hash operation
 * with new data.
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym_dp.h"
#include "icp_sal_poll.h"
#include "cpa_sample_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 2)
/* The digest length must be less than or equal length(4) for this example */
#define DIGEST_LENGTH 4

extern int gDebugParam;

/* Initialization vector 64 bits long */
static const Cpa8U sampleIv[] =
    {0x0F, 0x27, 0xDD, 0x05, 0x98, 0x58, 0xDE, 0x95};

static const Cpa8U updateIv[] =
    {0x73, 0xDF, 0xFB, 0x1A, 0xE3, 0x26, 0x13, 0xC3};

/* AES CCM, 128 bits long */
static Cpa8U sampleCipherKey[] = {0xB0,
                                  0xFC,
                                  0xBF,
                                  0xE9,
                                  0x4B,
                                  0xFC,
                                  0x91,
                                  0xE4,
                                  0x5B,
                                  0xED,
                                  0x56,
                                  0x96,
                                  0xE8,
                                  0x11,
                                  0x61,
                                  0xA0};

static Cpa8U updateCipherKey[] = {0x23,
                                  0x6A,
                                  0xC9,
                                  0xF3,
                                  0x91,
                                  0x63,
                                  0x28,
                                  0xC2,
                                  0xDE,
                                  0x73,
                                  0xC7,
                                  0xD7,
                                  0x26,
                                  0xFC,
                                  0x70,
                                  0x15};

/* Additional auth data 128 bits long */
static const Cpa8U additionalAuthData[] = {0xD7,
                                           0xAE,
                                           0x18,
                                           0x44,
                                           0xF7,
                                           0xE7,
                                           0x4A,
                                           0x61,
                                           0x10,
                                           0x33,
                                           0xA1,
                                           0xF6,
                                           0x08,
                                           0x36,
                                           0x0A,
                                           0xAB};

static const Cpa8U updateAuthData[] = {0x2C,
                                       0x37,
                                       0x70,
                                       0x63,
                                       0x5F,
                                       0x93,
                                       0x04,
                                       0xB6,
                                       0xCE,
                                       0xC7,
                                       0xDD,
                                       0x6F,
                                       0x7E,
                                       0x86,
                                       0x61,
                                       0x1D};

/* AES CCM, 512 bits long */
static Cpa8U sampleAuthKey[] = {0xD2,
                                0x3E,
                                0x6F,
                                0x12,
                                0x92,
                                0x1E,
                                0x51,
                                0x38,
                                0xED,
                                0x48,
                                0xCC,
                                0x25,
                                0x13,
                                0xF4,
                                0x78,
                                0x8F};

static Cpa8U updateAuthKey[] = {0xCE,
                                0xA4,
                                0x0F,
                                0x59,
                                0x9D,
                                0xA5,
                                0x0D,
                                0xA1,
                                0xEE,
                                0xE1,
                                0x3A,
                                0x8B,
                                0x3A,
                                0xAC,
                                0xAB,
                                0xAF};

/* Source data to encrypt 768 bits long */
static const Cpa8U sampleAlgChainingSrc[] = {
    0x72, 0x09, 0x40, 0xDB, 0xD1, 0x40, 0x55, 0x47, 0x84, 0xB1, 0xAC, 0x8A,
    0x87, 0x89, 0x7A, 0xAA, 0x1E, 0x87, 0xB1, 0x8D, 0xDC, 0x73, 0x94, 0x18,
    0xC6, 0xD8, 0x00, 0x94, 0xBA, 0xCE, 0x77, 0x2C, 0xD7, 0xB7, 0x08, 0xA9,
    0xF8, 0x5D, 0xF0, 0x7C, 0x0E, 0x9D, 0x06, 0x95, 0x26, 0x81, 0x3F, 0x45,
    0x08, 0xF0, 0xD2, 0xE4, 0x63, 0x67, 0xFC, 0x2A, 0x3F, 0xFC, 0xBE, 0xF9,
    0xCA, 0x35, 0x25, 0xA2, 0xED, 0x2D, 0x4B, 0xE5, 0x8A, 0x3B, 0x61, 0x98,
    0xD8, 0x68, 0x2D, 0xFF, 0xE9, 0x6C, 0x44, 0xF1, 0x5C, 0x16, 0xD5, 0xC0,
    0x7D, 0xD1, 0xEA, 0xBC, 0xCD, 0xA8, 0xB5, 0x98, 0xDD, 0xDB, 0x3A, 0xCA};

/* Update data to encrypt 1536 bits long */
static const Cpa8U updateAlgChainingSrc[] = {
    0x7F, 0xD1, 0xF2, 0x23, 0x1E, 0x63, 0x9F, 0xA7, 0x34, 0xB4, 0x3D, 0x8E,
    0x2C, 0x5E, 0x28, 0xE3, 0x85, 0xFB, 0x0C, 0xA7, 0x2F, 0x5F, 0x79, 0x19,
    0x96, 0xC2, 0x33, 0x70, 0x97, 0x21, 0xF0, 0x1B, 0x45, 0x68, 0x90, 0x35,
    0x27, 0x2F, 0xC6, 0x64, 0xDF, 0x32, 0xF8, 0x33, 0xC1, 0x2B, 0x49, 0x89,
    0x2B, 0xD6, 0x0D, 0xA6, 0xA3, 0x5F, 0x2E, 0xF7, 0xE2, 0xEC, 0x94, 0xA8,
    0x92, 0x0E, 0x94, 0xBF, 0x2F, 0xB8, 0x10, 0xAA, 0x60, 0x87, 0xFD, 0x1E,
    0xCE, 0x5D, 0x5D, 0xAA, 0xEE, 0x5D, 0xBE, 0xF7, 0x60, 0x08, 0x27, 0x4A,
    0xB1, 0x4C, 0x73, 0x11, 0xB8, 0x1B, 0x8E, 0x45, 0x4D, 0xA2, 0xBB, 0x5D,
    0x4F, 0xCE, 0x8D, 0xB7, 0xB4, 0x04, 0x75, 0x49, 0xAC, 0x20, 0x20, 0xF5,
    0x19, 0x0F, 0x46, 0xBB, 0x7A, 0x0A, 0x1C, 0xC1, 0x9A, 0x77, 0x88, 0x09,
    0x75, 0x69, 0xC7, 0x29, 0xB6, 0x84, 0xB2, 0xFE, 0x3F, 0x96, 0xCB, 0x1C,
    0x65, 0xD4, 0x91, 0x81, 0xDA, 0x3D, 0x97, 0xAD, 0x1A, 0x10, 0x50, 0xF5,
    0x77, 0x38, 0x94, 0x92, 0x7A, 0x1F, 0xCA, 0xAD, 0xFC, 0x21, 0x9D, 0x52,
    0x03, 0xD4, 0xC2, 0x7E, 0xDC, 0x34, 0x0F, 0xDA, 0x57, 0xD9, 0x71, 0x75,
    0x98, 0xF4, 0x99, 0xBE, 0x7D, 0x6D, 0xB9, 0x4A, 0x5D, 0x18, 0x9F, 0x60,
    0x5A, 0x5D, 0xAA, 0x83, 0x38, 0x6B, 0xBB, 0xAA, 0x38, 0x4A, 0xE4, 0x57};

/* Expected output of the algchain operation with the specified
 * cipher (CPA_CY_SYM_CIPHER_KASUMI_F8), hash (CPA_CY_SYM_HASH_KASUMI_F9),
 * key (sampleCipherKey), authKey (sampleAuthKey), initialization vector
 * (sampleIv) and additional authData (additionalAuthData) */
static const Cpa8U expectedOutput[] = {
    0x90, 0xAF, 0xC3, 0xE2, 0xCE, 0x7F, 0xE3, 0x1A, 0x32, 0x4C, 0x31, 0x8C,
    0x0F, 0x47, 0xCB, 0xD3, 0x71, 0x30, 0x8E, 0x68, 0xDE, 0xD7, 0x96, 0x94,
    0x65, 0x06, 0x23, 0x16, 0x2D, 0xE7, 0x09, 0xF9, 0xA0, 0xBE, 0x9F, 0x31,
    0xCF, 0x3B, 0x2A, 0x07, 0x7C, 0xD8, 0xCC, 0x5B, 0x4E, 0x41, 0x2C, 0xCD,
    0x88, 0xE0, 0xB5, 0xF7, 0xBC, 0x13, 0xCB, 0x6E, 0x55, 0x1D, 0xE2, 0x13,
    0x24, 0x6D, 0xB5, 0xC0, 0x4E, 0xA2, 0xAD, 0x7F, 0xD3, 0x3E, 0xE2, 0x05,
    0x94, 0x26, 0x54, 0x7A, 0xFE, 0x55, 0x66, 0x52, 0x39, 0x6B, 0xE1, 0xEF,
    0x76, 0x5A, 0x29, 0x8B, 0x73, 0x9B, 0x5D, 0xBA, 0xD5, 0xBE, 0xDA, 0x6F,
    0x8C, 0xE1, 0x9B, 0xF1};

/* Expected output of the algchain operation with the specified
 * cipher (CPA_CY_SYM_CIPHER_KASUMI_F8), hash (CPA_CY_SYM_HASH_KASUMI_F9),
 * key (updateCipherKey), authKey (updateAuthKey), initialization vector
 * (updateIv) and additional authData (updateAuthData) */
static const Cpa8U updateExpectedOutput[] = {
    0x71, 0x5A, 0xB7, 0xE0, 0x66, 0xBF, 0x99, 0x24, 0xA0, 0x80, 0x31, 0xEB,
    0x64, 0xD3, 0xC0, 0x9F, 0x2B, 0x15, 0x72, 0x61, 0x42, 0x8B, 0x17, 0x15,
    0x4A, 0x8D, 0x54, 0x64, 0x43, 0x2D, 0x62, 0x95, 0x6A, 0x5D, 0x58, 0xEE,
    0xE1, 0x68, 0xBC, 0x50, 0xEF, 0x55, 0xB4, 0x90, 0xD1, 0xFA, 0xC3, 0xCA,
    0x3C, 0xF0, 0x0C, 0x7C, 0x51, 0xED, 0xB9, 0x0D, 0x38, 0xC5, 0xD2, 0xDE,
    0xE8, 0x5A, 0xEB, 0x37, 0x7A, 0xFD, 0x9B, 0x58, 0xD5, 0xCA, 0x9D, 0xF2,
    0x2C, 0xAB, 0x97, 0x33, 0x78, 0xC6, 0x0A, 0xB6, 0x86, 0x46, 0x38, 0x79,
    0x8E, 0x57, 0xE7, 0xF5, 0x9C, 0x79, 0x37, 0xA7, 0x78, 0xA4, 0xDA, 0xC3,
    0x40, 0x1C, 0x25, 0x2B, 0xB1, 0x95, 0x03, 0x3E, 0x38, 0x1E, 0xB8, 0xE3,
    0x14, 0xFE, 0x20, 0x22, 0x47, 0x33, 0x13, 0xF4, 0x14, 0xC4, 0x5D, 0xE8,
    0x9C, 0xDF, 0x29, 0x86, 0x2D, 0x17, 0xC4, 0xEF, 0xDC, 0xA4, 0xCF, 0x2B,
    0x65, 0xDE, 0x27, 0x8D, 0xC1, 0x3D, 0xA6, 0xBD, 0x33, 0x15, 0x33, 0x70,
    0x47, 0x98, 0x5D, 0x00, 0x8F, 0xDB, 0xED, 0xA0, 0x56, 0xC9, 0xB3, 0x17,
    0x8A, 0x7C, 0x94, 0xA1, 0x83, 0x92, 0xB9, 0x83, 0xC8, 0xDB, 0xC3, 0xD5,
    0xD5, 0xCA, 0x76, 0x15, 0x98, 0x1A, 0x46, 0xEE, 0x40, 0xA4, 0x3C, 0x8B,
    0x39, 0xA0, 0x9D, 0xE4, 0x8C, 0xBD, 0x8F, 0x4F, 0x49, 0x91, 0xD5, 0x48,
    0xF5, 0x96, 0xD6, 0x6F};

CpaStatus symDpUpdateSample(void);

/*
 * Callback function
 *
 * This function is "called back" (invoked by the implementation of
 * the API) when the operation has completed.
 *
 */
static void symDpCallback(CpaCySymDpOpData *pOpData,
                          CpaStatus status,
                          CpaBoolean verifyResult)
{
    PRINT_DBG("Callback called with status = %d.\n", status);
    pOpData->pCallbackTag = (void *)1;
}

/*
 * Perform session update
 */
static CpaStatus initSession(CpaInstanceHandle cyInstHandle,
                             CpaCySymSessionCtx *sessionCtx,
                             Cpa8U *pCipherKey,
                             Cpa32U cipherKeyLen,
                             Cpa8U *authKey,
                             Cpa32U authKeyLen)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionSetupData sessionSetupData = {0};

    /* populate symmetric session data structure */
    //<snippet name="initSession">
    sessionSetupData.sessionPriority = CPA_CY_PRIORITY_HIGH;
    sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
    sessionSetupData.algChainOrder =
        CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
    sessionSetupData.cipherSetupData.cipherAlgorithm =
        CPA_CY_SYM_CIPHER_KASUMI_F8;
    sessionSetupData.cipherSetupData.pCipherKey = pCipherKey;
    sessionSetupData.cipherSetupData.cipherKeyLenInBytes = cipherKeyLen;
    sessionSetupData.cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_KASUMI_F9;
    sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;
    sessionSetupData.hashSetupData.authModeSetupData.authKey = authKey;
    sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
        authKeyLen;
    sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes =
        sizeof(additionalAuthData);
    sessionSetupData.digestIsAppended = CPA_TRUE;
    sessionSetupData.verifyDigest = CPA_FALSE;

    /* Determine size of session context to allocate */
    PRINT_DBG("cpaCySymDpSessionCtxGetSize\n");
    status = cpaCySymDpSessionCtxGetSize(
        cyInstHandle, &sessionSetupData, &sessionCtxSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session context */
        status = PHYS_CONTIG_ALLOC(sessionCtx, sessionCtxSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the session */
        PRINT_DBG("cpaCySymDpInitSession\n");
        status =
            cpaCySymDpInitSession(cyInstHandle, &sessionSetupData, *sessionCtx);
    }
    //</snippet>

    return status;
}

/*
 * Perform session update
 */
static CpaStatus updateSession(CpaCySymSessionCtx sessionCtx,
                               Cpa8U *pCipherKey,
                               Cpa8U *authKey)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymSessionUpdateData sessionUpdateData = {0};

    PRINT_DBG("cpaCySymUpdateSession\n");

    sessionUpdateData.flags = CPA_CY_SYM_SESUPD_CIPHER_KEY;
    sessionUpdateData.flags |= CPA_CY_SYM_SESUPD_AUTH_KEY;
    sessionUpdateData.pCipherKey = pCipherKey;
    sessionUpdateData.authKey = authKey;

    status = cpaCySymUpdateSession(sessionCtx, &sessionUpdateData);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_DBG("cpaCySymUpdateSession failed with status = %d.\n", status);
    }

    return status;
}

/*
 * Perform an algorithm chaining operation (cipher + hash)
 */
static CpaStatus symDpPerformOp(CpaInstanceHandle cyInstHandle,
                                CpaCySymSessionCtx sessionCtx,
                                const Cpa8U *pSrc,
                                Cpa32U srcLen,
                                const Cpa8U *pExpectedOutput,
                                const Cpa8U *pIv,
                                Cpa32U ivLen,
                                const Cpa8U *pAdditionalAuth,
                                Cpa32U additionalAuthLen)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymDpOpData *pOpData = NULL;
    Cpa32U bufferSize = srcLen + DIGEST_LENGTH;
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pDstBuffer = NULL;
    Cpa8U *pIvBuffer = NULL;
    Cpa8U *pAdditionalAuthData = NULL;

    /* Allocate src buffer */
    status = PHYS_CONTIG_ALLOC(&pSrcBuffer, srcLen);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate dst buffer */
        status = PHYS_CONTIG_ALLOC(&pDstBuffer, bufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate IV buffer */
        status = PHYS_CONTIG_ALLOC(&pIvBuffer, ivLen);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate additionalAuthData buffer */
        status =
            PHYS_CONTIG_ALLOC(&pAdditionalAuthData, sizeof(additionalAuthData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate memory for operational data. Note this needs to be
         * 8-byte aligned, contiguous, resident in DMA-accessible
         * memory.
         */
        status =
            PHYS_CONTIG_ALLOC_ALIGNED(&pOpData, sizeof(CpaCySymDpOpData), 8);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* copy source into buffer */
        memcpy(pSrcBuffer, pSrc, srcLen);

        /* copy IV into buffer */
        memcpy(pIvBuffer, pIv, sizeof(sampleIv));

        /* copy additional auth data into buffer */
        memcpy(pAdditionalAuthData, pAdditionalAuth, additionalAuthLen);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Populate the structure containing the operational data that is
         * needed to run the algorithm
         */
        pOpData->thisPhys = sampleVirtToPhys(pOpData);
        pOpData->instanceHandle = cyInstHandle;
        pOpData->sessionCtx = sessionCtx;
        pOpData->pCallbackTag = (void *)0;
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = srcLen;
        pOpData->hashStartSrcOffsetInBytes = 0;
        pOpData->messageLenToHashInBytes = srcLen;
        pOpData->digestResult = sampleVirtToPhys(pSrcBuffer) + srcLen;
        pOpData->iv = sampleVirtToPhys(pIvBuffer);
        pOpData->pIv = pIvBuffer;
        pOpData->ivLenInBytes = ivLen;
        pOpData->additionalAuthData = sampleVirtToPhys(pAdditionalAuthData);
        pOpData->pAdditionalAuthData = pAdditionalAuthData;
        pOpData->srcBuffer = sampleVirtToPhys(pSrcBuffer);
        pOpData->srcBufferLen = bufferSize;
        pOpData->dstBuffer = sampleVirtToPhys(pDstBuffer);
        pOpData->dstBufferLen = bufferSize;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCySymDpEnqueueOp\n");
        /** Enqueue symmetric operation */
        //<snippet name="enqueue">
        status = cpaCySymDpEnqueueOp(pOpData, CPA_FALSE);
        //</snippet>
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymDpEnqueueOp failed. (status = %d)\n", status);
        }
        else
        {
            /* Can now enqueue other requests before submitting all requests to
             * the hardware. The cost of submitting the request to the hardware
             * is
             * then amortized across all enqueued requests.
             * In this simple example we have only 1 request to send
             */

            PRINT_DBG("cpaCySymDpPerformOpNow\n");

            /** Submit all enqueued symmetric operations to the hardware */
            //<snippet name="perform">
            status = cpaCySymDpPerformOpNow(cyInstHandle);
            //</snippet>
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaCySymDpPerformOpNow failed. (status = %d)\n",
                          status);
            }
        }
    }

    /* We can enqueue more operations and/or do other work while
     * hardware processes the request.
     * In this simple example we have no other work to do
     * */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Poll for responses.
         * Polling functions are implementation specific */
        do
        {
            status = icp_sal_CyPollDpInstance(cyInstHandle, 1);
        } while (
            ((CPA_STATUS_SUCCESS == status) || (CPA_STATUS_RETRY == status)) &&
            (pOpData->pCallbackTag == (void *)0));
    }

    /* Check result */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (0 == memcmp(pDstBuffer, pExpectedOutput, bufferSize))
        {
            PRINT_DBG("Output matches expected output\n");
        }
        else
        {
            PRINT_ERR("Output does not match expected output\n");
            status = CPA_STATUS_FAIL;
        }
    }

    PHYS_CONTIG_FREE(pSrcBuffer);
    PHYS_CONTIG_FREE(pDstBuffer);
    PHYS_CONTIG_FREE(pIvBuffer);
    PHYS_CONTIG_FREE(pAdditionalAuthData);
    PHYS_CONTIG_FREE(pOpData);

    return status;
}

CpaStatus symDpUpdateSample(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus sessionStatus = CPA_STATUS_FAIL;
    CpaCySymSessionCtx sessionCtx = NULL;
    CpaInstanceHandle cyInstHandle = NULL;

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    sampleCyGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    /* Start Cryptographic component */
    PRINT_DBG("cpaCyStartInstance\n");
    status = cpaCyStartInstance(cyInstHandle);

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Register callback function for the instance */
        //<snippet name="regCb">
        status = cpaCySymDpRegCbFunc(cyInstHandle, symDpCallback);
        //</snippet>
    }

    /* Init session with sampleCipherKey and sampleAuthKey */
    sessionStatus = initSession(cyInstHandle,
                                &sessionCtx,
                                sampleCipherKey,
                                sizeof(sampleCipherKey),
                                sampleAuthKey,
                                sizeof(sampleAuthKey));

    if (CPA_STATUS_SUCCESS == sessionStatus)
    {
        /* Perform algchaining operation */
        status = symDpPerformOp(cyInstHandle,
                                sessionCtx,
                                sampleAlgChainingSrc,
                                sizeof(sampleAlgChainingSrc),
                                expectedOutput,
                                sampleIv,
                                sizeof(sampleIv),
                                additionalAuthData,
                                sizeof(additionalAuthData));

        /* Update the session with updateCipherKey and updateAuthKey*/
        if (CPA_STATUS_SUCCESS == status)
        {
            status = updateSession(sessionCtx, updateCipherKey, updateAuthKey);
        }

        /* Perform algchaining operation with new src, iv, additional auth
         * data*/
        if (CPA_STATUS_SUCCESS == status)
        {
            status = symDpPerformOp(cyInstHandle,
                                    sessionCtx,
                                    updateAlgChainingSrc,
                                    sizeof(updateAlgChainingSrc),
                                    updateExpectedOutput,
                                    updateIv,
                                    sizeof(updateIv),
                                    updateAuthData,
                                    sizeof(updateAuthData));
        }
    }

    /* Clean up */
    if (CPA_STATUS_SUCCESS == sessionStatus)
    {
        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        /* Remove the session - session init has already succeeded */
        PRINT_DBG("cpaCySymDpRemoveSession\n");

        //<snippet name="removeSession">
        status = cpaCySymDpRemoveSession(cyInstHandle, sessionCtx);
        //</snippet>

        /* Free session Context */
        PHYS_CONTIG_FREE(sessionCtx);

        PRINT_DBG("cpaCyStopInstance\n");
        cpaCyStopInstance(cyInstHandle);
    }

    /* Test end */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Sample code ran successfully\n");
    }
    else
    {
        PRINT_DBG("Sample code failed with status of %d\n", status);
    }

    return status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
