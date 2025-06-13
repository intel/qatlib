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

/*
 * This is sample code that demonstrates usage of the symmetric DP API, and
 * specifically using this API to perform a "chained" cipher and hash
 * operation.  It encrypts some sample text using the AES-256 algorithm in
 * AES-GCM mode, and then performs an AES-GCM hash on the ciphertext.
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym_dp.h"
#include "icp_sal_poll.h"
#include "cpa_sample_utils.h"

#define DIGEST_LENGTH 16
#define AES_BLOCK_SIZE 16

extern int gDebugParam;
/* AES key, 256 bits long */
static Cpa8U sampleCipherKey[] = {
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a,
            0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92,
            0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08};


/* Initialization vector */
static Cpa8U sampleCipherIv[] = {
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca,
            0xf8, 0x88};

/* Additional Authentication Data */
static Cpa8U sampleAddAuthData[] = {
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
            0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };

/* Source data to encrypt */
static Cpa8U sampleAlgChainingSrc[] = {
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
            0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
            0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
            0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
            0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};

/* Expected output of the encryption operation with the specified
 * cipher (CPA_CY_SYM_CIPHER_AES_GCM), key (sampleCipherKey) and
 * initialization vector (sampleCipherIv) */
static Cpa8U expectedOutput[] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3,
    0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48,
    0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
                                  /* Digest */
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53,
    0xbb, 0x2d, 0x55, 0x1b };

CpaStatus symDpSample(void);

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
 * Perform an algorithm chaining operation (cipher + hash)
 */
static CpaStatus symDpPerformOp(CpaInstanceHandle cyInstHandle,
                                CpaCySymSessionCtx sessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymDpOpData *pOpData = NULL;
    Cpa32U bufferSize = sizeof(sampleAlgChainingSrc) + DIGEST_LENGTH;
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pIvBuffer = NULL;
    Cpa32U aadBuffSize = 0;
    Cpa8U *pAadBuffer = NULL;
    CpaInstanceInfo2 info2 = { 0 };

    /* Allocate Src buffer */
    status = PHYS_CONTIG_ALLOC(&pSrcBuffer, bufferSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate IV buffer */
        status = PHYS_CONTIG_ALLOC(&pIvBuffer, sizeof(sampleCipherIv));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate memory for AAD. For GCM this memory will hold the
         * additional authentication data and any padding to ensure total
         * size is a multiple of the AES block size
         */
        aadBuffSize = sizeof(sampleAddAuthData);
        if (aadBuffSize % AES_BLOCK_SIZE)
        {
            aadBuffSize += AES_BLOCK_SIZE - (aadBuffSize % AES_BLOCK_SIZE);
        }
        status = PHYS_CONTIG_ALLOC(&pAadBuffer, aadBuffSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* copy source into buffer */
        memcpy(pSrcBuffer, sampleAlgChainingSrc, sizeof(sampleAlgChainingSrc));

        /* copy IV into buffer */
        memcpy(pIvBuffer, sampleCipherIv, sizeof(sampleCipherIv));

        /* Copy AAD into buffer */
        memcpy(pAadBuffer, sampleAddAuthData, sizeof(sampleAddAuthData));

        /* Allocate memory for operational data. Note this needs to be
         * 8-byte aligned, contiguous, resident in DMA-accessible
         * memory.
         */
        status =
            PHYS_CONTIG_ALLOC_ALIGNED(&pOpData, sizeof(CpaCySymDpOpData), 8);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaPhysicalAddr pPhySrcBuffer;
        /** Populate the structure containing the operational data that is
         * needed to run the algorithm
         */
        //<snippet name="opDataDp">
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = sizeof(sampleAlgChainingSrc);
        pOpData->iv =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pIvBuffer,
                              cyInstHandle,
                              CPA_ACC_SVC_TYPE_CRYPTO);
        pOpData->pIv = pIvBuffer;
        pOpData->hashStartSrcOffsetInBytes = 0;
        pOpData->messageLenToHashInBytes = sizeof(sampleAlgChainingSrc);
        /* Even though MAC follows immediately after the region to hash
           digestIsAppended is set to false in this case due to
           errata number IXA00378322 */
        pPhySrcBuffer =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pSrcBuffer,
                              cyInstHandle,
                              CPA_ACC_SVC_TYPE_CRYPTO);
        pOpData->digestResult = pPhySrcBuffer + sizeof(sampleAlgChainingSrc);
        pOpData->instanceHandle = cyInstHandle;
        pOpData->sessionCtx = sessionCtx;
        pOpData->ivLenInBytes = sizeof(sampleCipherIv);
        pOpData->srcBuffer = pPhySrcBuffer;
        pOpData->srcBufferLen = bufferSize;
        pOpData->dstBuffer = pPhySrcBuffer;
        pOpData->dstBufferLen = bufferSize;
        pOpData->thisPhys =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pOpData,
                              cyInstHandle,
                              CPA_ACC_SVC_TYPE_CRYPTO);
        pOpData->pCallbackTag = (void *)0;
        pOpData->additionalAuthData =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pAadBuffer,
                              cyInstHandle,
                              CPA_ACC_SVC_TYPE_CRYPTO);
        pOpData->pAdditionalAuthData = pAadBuffer;

        //</snippet>
    }
    else
    {
        PRINT_ERR("Memory allocation failed. (status = %d)\n", status);
        PHYS_CONTIG_FREE(pSrcBuffer);
        PHYS_CONTIG_FREE(pIvBuffer);
        PHYS_CONTIG_FREE(pAadBuffer);
        PHYS_CONTIG_FREE(pOpData);

        return status;
    }

    status = cpaCyInstanceGetInfo2(cyInstHandle, &info2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 failed. (status = %d)\n", status);
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
    /* Can now enqueue more operations and/or do other work while
     * hardware processes the request.
     * In this simple example we have no other work to do
     * */

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Poll for responses.
         * Polling functions are implementation specific */
        do
        {
            if (CPA_TRUE == info2.isPolled)
            {
                status = icp_sal_CyPollDpInstance(cyInstHandle, 1);
            }
        } while (
            ((CPA_STATUS_SUCCESS == status) || (CPA_STATUS_RETRY == status)) &&
            (pOpData->pCallbackTag == (void *)0));
    }

    /* Check result */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (0 == memcmp(pSrcBuffer, expectedOutput, bufferSize))
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
    PHYS_CONTIG_FREE(pIvBuffer);
    PHYS_CONTIG_FREE(pAadBuffer);
    PHYS_CONTIG_FREE(pOpData);

    return status;
}

CpaStatus symDpSample(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCySymSessionCtx sessionCtx = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    CpaInstanceInfo2 *info2 = NULL;

    status = OS_MALLOC(&info2, sizeof(CpaInstanceInfo2));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate memory for info2");
        return CPA_STATUS_FAIL;
    }

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    sampleSymGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        OS_FREE(info2);
        return CPA_STATUS_FAIL;
    }

    /* Start Cryptographic component */
    PRINT_DBG("cpaCyStartInstance\n");
    status = cpaCyStartInstance(cyInstHandle);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyInstanceGetInfo2(cyInstHandle, info2);
    }

#if !defined(SC_BSD_UPSTREAM)
    if (CPA_STATUS_SUCCESS == status)
    {
        if (info2->isPolled == CPA_FALSE)
        {
            status = CPA_STATUS_FAIL;
            PRINT_ERR("This sample code works only with instances "
                      "configured in polling mode\n");
        }
    }
#endif

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

    if (CPA_STATUS_SUCCESS == status)
    {
        /* populate symmetric session data structure */
        //<snippet name="initSession">
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_HIGH;
        sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        sessionSetupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;

        sessionSetupData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_GCM;
        sessionSetupData.cipherSetupData.pCipherKey = sampleCipherKey;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
            sizeof(sampleCipherKey);
        sessionSetupData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_GCM;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;
        sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes =
            sizeof(sampleAddAuthData);
        sessionSetupData.hashSetupData.authModeSetupData.authKey =
            sampleCipherKey;
        sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
            sizeof(sampleCipherKey);

        /* Even though MAC follows immediately after the region to hash
           digestIsAppended is set to false in this case due to
           errata number IXA00378322 */
        sessionSetupData.digestIsAppended = CPA_FALSE;
        sessionSetupData.verifyDigest = CPA_FALSE;

        /* Determine size of session context to allocate */
        PRINT_DBG("cpaCySymDpSessionCtxGetSize\n");
        status = cpaCySymDpSessionCtxGetSize(
            cyInstHandle, &sessionSetupData, &sessionCtxSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session context */
        status = PHYS_CONTIG_ALLOC(&sessionCtx, sessionCtxSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the session */
        PRINT_DBG("cpaCySymDpInitSession\n");
        status =
            cpaCySymDpInitSession(cyInstHandle, &sessionSetupData, sessionCtx);
    }

#ifdef LAC_HW_PRECOMPUTES
    if (CPA_STATUS_SUCCESS == status && CPA_TRUE == info2->isPolled)
    {
        /* Poll for hw pre-compute responses. */
        do
        {
            status = icp_sal_CyPollDpInstance(cyInstHandle, 0);
        } while (CPA_STATUS_SUCCESS != status);
    }
#endif

    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        status = symDpPerformOp(cyInstHandle, sessionCtx);

        /* Remove the session - session init has already succeeded */
        PRINT_DBG("cpaCySymDpRemoveSession\n");

        /* Wait for in-flight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        //<snippet name="removeSession">
        sessionStatus = cpaCySymDpRemoveSession(cyInstHandle, sessionCtx);
        //</snippet>

        /* maintain status of remove session only when status of all operations
         * before it are successful. */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }

    /* Clean up */

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionCtx);
    OS_FREE(info2);

    PRINT_DBG("cpaCyStopInstance\n");
    cpaCyStopInstance(cyInstHandle);

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
