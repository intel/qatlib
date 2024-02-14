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
 * This is sample code that demonstrates usage of the symmetric API, and
 * specifically using this API to perform a ZUC operation. For more information
 * on ZUC please reference The ZUC-256 Stream Cipher "
 * http://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180126529970733243.pdf"
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"

#include "cpa_sample_utils.h"

#define DIGEST_LENGTH 16
#define TIMEOUT_MS 5000 /* 5 seconds*/

extern int gDebugParam;
/* ZUC cipher key, 256 bits long */
static Cpa8U sampleCipherKey[] = {
    0x7A, 0x8A, 0x5C, 0x43, 0x35, 0x87, 0x48, 0xE8, 0x3C, 0xFC, 0x05, 0x5B,
    0xA7, 0xC1, 0x32, 0x72, 0xA1, 0x0A, 0xAE, 0x97, 0x92, 0x46, 0x62, 0xB9,
    0x2C, 0xDF, 0xE4, 0x26, 0xAA, 0xD6, 0x09, 0x24};
/* Initialization vector */
static Cpa8U sampleCipherIv[] = {
    0x24, 0xF0, 0x41, 0x1D, 0x2E, 0xA4, 0xAC, 0x7F, 0x63, 0x3E, 0xB7, 0x9F,
    0xC3, 0x1C, 0xD1, 0x8D, 0xAF, 0xDD, 0x20, 0x80, 0xAE, 0x96, 0xAD, 0xFF};
/* ZUC authentication key, 256 bits long */
static Cpa8U sampleAuthKey[] = {
    0xBF, 0xC1, 0xC4, 0x0F, 0x56, 0xE8, 0xC6, 0x53, 0x19, 0xA6, 0xBB, 0xEE,
    0xF2, 0x96, 0x0A, 0xFD, 0x4C, 0xF6, 0x64, 0xA3, 0xFE, 0x0A, 0x2A, 0x8A,
    0x14, 0x79, 0x67, 0xC0, 0xD3, 0xEC, 0xA4, 0x92};

/* Source data to encrypt */
static Cpa8U samplePayload[] = {
    0x44, 0x09, 0xB5, 0xC3, 0xDD, 0x3E, 0x3D, 0x29, 0x09, 0xEF, 0x0E, 0x9F,
    0xA6, 0xED, 0x0C, 0x92, 0xFD, 0xFD, 0xAD, 0x06, 0x88, 0x03, 0xE6, 0x98,
    0x47, 0xD8, 0x5D, 0x9F, 0x34, 0x81, 0x0F, 0x79, 0x8B, 0xC5, 0x3C, 0x68,
    0x03, 0x79, 0x91, 0x0C, 0x68, 0xA0, 0xAB, 0x0F, 0x8D, 0xB7, 0xA1, 0x8A,
    0xB4, 0x4E, 0x90, 0x3D, 0x52, 0x77, 0xD5, 0x99, 0x4F, 0x32, 0x38, 0x84,
    0xB3, 0x47, 0xFD, 0x3E, 0x0C, 0x39, 0xA6, 0x0F, 0xB3, 0x38, 0x1C, 0x1B,
    0xD8, 0xC7, 0x2A, 0x65, 0x7F, 0xCC, 0xF0, 0x33, 0x1A, 0x80, 0x70, 0x6C,
    0xF7, 0x45, 0x05, 0x47, 0x77, 0x3D, 0xCB, 0x2B, 0x85, 0xC8, 0x69, 0x91,
    0x01, 0x10, 0xA1, 0xB4, 0x48, 0xBD, 0xD0, 0x20, 0x84, 0xFA, 0x85, 0x03,
    0xC6, 0x75, 0x37, 0xE1, 0xF6, 0xA7, 0x4D, 0xED, 0xED, 0x53, 0x34, 0x64,
    0x90, 0xFF, 0x8F, 0x15, 0xC7, 0xF9, 0xA7, 0xC9};

/* Expected output of the operation */
static Cpa8U expectedOutput[] = {
    0x09, 0x5F, 0x1C, 0xF7, 0x08, 0x29, 0xC8, 0xED, 0x67, 0xF1, 0xAC, 0x29,
    0xE1, 0x02, 0x2F, 0xA0, 0x1A, 0xC4, 0x8B, 0x72, 0x9B, 0xE9, 0xF0, 0xFD,
    0x50, 0xE9, 0xBB, 0x73, 0x5B, 0xBA, 0x5C, 0x26, 0x32, 0xE8, 0x92, 0x98,
    0xEC, 0xCB, 0x14, 0x85, 0x23, 0xF3, 0x5C, 0x5A, 0x4B, 0x79, 0xED, 0xD2,
    0x57, 0xF8, 0xD6, 0xB3, 0x82, 0x1F, 0x44, 0x84, 0x9E, 0x7C, 0x09, 0xC7,
    0xAC, 0x4D, 0x48, 0x62, 0xA6, 0xDB, 0x23, 0x14, 0x61, 0x2F, 0xB3, 0x17,
    0x87, 0x21, 0x51, 0xD3, 0x63, 0x66, 0x22, 0xC9, 0x0F, 0xC9, 0x8F, 0xE4,
    0x6B, 0x99, 0x63, 0x61, 0x57, 0xD5, 0x5D, 0xEE, 0xF7, 0x19, 0x8E, 0xCD,
    0x45, 0xB5, 0xB3, 0x38, 0x81, 0x18, 0xE8, 0xA5, 0x45, 0xA1, 0x54, 0xF1,
    0x47, 0x3D, 0xDE, 0x1A, 0x6A, 0x43, 0x78, 0x68, 0x30, 0x03, 0xF6, 0xF8,
    0x46, 0x28, 0xC4, 0xC7, 0xE7, 0x1D, 0x64, 0xA4, 0xC3, 0xEE, 0xD1, 0x53,
    0xD2, 0x17, 0x97, 0x3E, 0x9E, 0x3A, 0x58, 0x0C, 0x09, 0xE9, 0x82, 0xB5};
/* Association data */
static Cpa8U sampleAssocData[] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
CpaStatus algChainSample(void);

/*
 * Callback function
 *
 * This function is "called back" (invoked by the implementation of
 * the API) when the asynchronous operation has completed.  The
 * context in which it is invoked depends on the implementation, but
 * as described in the API it should not sleep (since it may be called
 * in a context which does not permit sleeping, e.g. a Linux bottom
 * half).
 *
 * This function can perform whatever processing is appropriate to the
 * application.  For example, it may free memory, continue processing
 * of a decrypted packet, etc.  In this example, the function only
 * sets the complete variable to indicate it has been called.
 */
static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    if (NULL != pCallbackTag)
    {
        /** indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

/*
 * Perform an algorithm chaining operation (cipher + hash)
 */
static CpaStatus algChainPerformOpZUC(CpaInstanceHandle cyInstHandle,
                                      CpaCySymSessionCtx sessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    Cpa32U bufferSize = sizeof(samplePayload) + DIGEST_LENGTH;
    Cpa32U aadBuffSize = sizeof(sampleAssocData);
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pIvBuffer = NULL;
    Cpa8U *pAadBuffer = NULL;
    CpaInstanceInfo2 instanceInfo2;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;

    /* get meta information size */
    PRINT_DBG("cpaCyBufferListGetMetaSize\n");
    status =
        cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMeta, bufferMetaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferList, bufferListMemSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pSrcBuffer, bufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pIvBuffer, sizeof(sampleCipherIv));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* copy source into buffer */
        memcpy(pSrcBuffer, samplePayload, sizeof(samplePayload));

        /* copy IV into buffer */
        memcpy(pIvBuffer, sampleCipherIv, sizeof(sampleCipherIv));

        /* increment by sizeof(CpaBufferList) to get at the
         * array of flatbuffers */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);

        pBufferList->pBuffers = pFlatBuffer;
        pBufferList->numBuffers = 1;
        pBufferList->pPrivateMetaData = pBufferMeta;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pSrcBuffer;

        status = OS_MALLOC(&pOpData, sizeof(CpaCySymOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        aadBuffSize = sizeof(sampleAssocData);
        status = PHYS_CONTIG_ALLOC(&pAadBuffer, aadBuffSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pAadBuffer, sampleAssocData, sizeof(sampleAssocData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyInstanceGetInfo2(cyInstHandle, &instanceInfo2);
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_DBG("sampleCodeCyGetNode error, status: %d\n", status);
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        //<snippet name="opData">
        /** Populate the structure containing the operational data that is
         * needed to run the algorithm
         */
        pOpData->sessionCtx = sessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->pIv = pIvBuffer;
        pOpData->ivLenInBytes = sizeof(sampleCipherIv);
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->hashStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = sizeof(samplePayload);
        pOpData->messageLenToHashInBytes = sizeof(samplePayload);
        pOpData->pAdditionalAuthData = pAadBuffer;
        //</snippet>
        /* pDigestResult does need need to be set as digestIsAppended
            was set at sessionInit */
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** initialization for callback; the "complete" variable is used by the
         * callback function to indicate it has been called*/
        COMPLETION_INIT(&complete);

        PRINT_DBG("cpaCySymPerformOp\n");

        /** Perform symmetric operation */
        status = cpaCySymPerformOp(
            cyInstHandle,
            (void *)&complete, /* data sent as is to the callback function*/
            pOpData,           /* operational data struct */
            pBufferList,       /* source buffer list */
            pBufferList,       /* same src & dst for an in-place operation*/
            NULL);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp failed. (status = %d)\n", status);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /** wait until the completion of the operation*/
            if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
            {
                PRINT_ERR("timeout or interruption in cpaCySymPerformOp\n");
                status = CPA_STATUS_FAIL;
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            if (0 == memcmp(pSrcBuffer, expectedOutput, bufferSize))
            {
                PRINT_DBG("Output matches expected output\n");
            }
            else
            {
                PRINT_DBG("Output does not match expected output\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }

    /* at this stage, the callback function has returned, so it is sure that
     * the structures won't be needed any more*/
    PHYS_CONTIG_FREE(pSrcBuffer);
    PHYS_CONTIG_FREE(pIvBuffer);
    PHYS_CONTIG_FREE(pAadBuffer);
    OS_FREE(pBufferList);
    PHYS_CONTIG_FREE(pBufferMeta);
    OS_FREE(pOpData);

    COMPLETION_DESTROY(&complete);

    return status;
}

CpaStatus algChainSample(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCySymSessionCtx sessionCtx = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionSetupData sessionSetupData;
    CpaCySymStats64 symStats;
    memset(&sessionSetupData, 0, sizeof(CpaCySymSessionSetupData));
    memset(&symStats, 0, sizeof(CpaCySymStats64));

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
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependent.
         */
        sampleCyStartPolling(cyInstHandle);

        /* populate symmetric session data structure */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        //<snippet name="initSession">
        sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        sessionSetupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;

        sessionSetupData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_ZUC_EEA3;
        sessionSetupData.cipherSetupData.pCipherKey = sampleCipherKey;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
            sizeof(sampleCipherKey);
        sessionSetupData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_ZUC_EIA3;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;
        sessionSetupData.hashSetupData.authModeSetupData.authKey =
            sampleAuthKey;
        sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
            sizeof(sampleAuthKey);
        sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes = 24;

        /* The resulting MAC is to be placed immediately after the ciphertext */
        sessionSetupData.digestIsAppended = CPA_TRUE;
        sessionSetupData.verifyDigest = CPA_FALSE;
        //</snippet>

        /* Determine size of session context to allocate */
        PRINT_DBG("cpaCySymSessionCtxGetSize\n");
        status = cpaCySymSessionCtxGetSize(
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
        PRINT_DBG("cpaCySymInitSession\n");
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        status = algChainPerformOpZUC(cyInstHandle, sessionCtx);

        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        /* Remove the session - session init has already succeeded */
        PRINT_DBG("cpaCySymRemoveSession\n");
        sessionStatus = cpaCySymRemoveSession(cyInstHandle, sessionCtx);

        /* maintain status of remove session only when status of all operations
         * before it are successful. */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Query symmetric statistics */
        status = cpaCySymQueryStats64(cyInstHandle, &symStats);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymQueryStats failed, status = %d\n", status);
        }
        else
        {
            PRINT_DBG("Number of symmetric operation completed: %llu\n",
                      (long long unsigned int)symStats.numSymOpCompleted);
        }
    }

    /* Clean up */

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionCtx);

    /* Stop the polling thread */
    sampleCyStopPolling();

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
