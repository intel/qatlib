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
 * specifically using this API to perform an IPSec like operation.
 * In this example we use the algorithm aes128-cbc + sha256-hmac
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"

#include "cpa_sample_utils.h"

#define TIMEOUT_MS 5000

#define ICV_LENGTH 12

/* For IPSec outbound direction we encrypt the payload and then
   generate the ICV. For IPSec inbound direction we compare the
   ICV and decrypt the payload
*/
#define IPSEC_OUTBOUND_DIR 0
#define IPSEC_INBOUND_DIR 1

extern int gDebugParam;

static Cpa8U sampleCipherKey[] = {0x00,
                                  0x11,
                                  0x22,
                                  0x33,
                                  0x44,
                                  0x55,
                                  0x66,
                                  0x77,
                                  0x88,
                                  0x99,
                                  0x00,
                                  0x11,
                                  0x22,
                                  0x33,
                                  0x44,
                                  0x55};

static Cpa8U sampleCipherIv[] = {0xca,
                                 0xfe,
                                 0xba,
                                 0xbe,
                                 0xfa,
                                 0xce,
                                 0xdb,
                                 0xad,
                                 0xde,
                                 0xca,
                                 0xf8,
                                 0x88,
                                 0x3d,
                                 0x11,
                                 0x59,
                                 0x04};

static Cpa8U sampleAuthKey[] = {
    0xEE, 0xE2, 0x7B, 0x5B, 0x10, 0xFD, 0xD2, 0x58, 0x49, 0x77, 0xF1,
    0x22, 0xD7, 0x1B, 0xA4, 0xCA, 0xEC, 0xBD, 0x15, 0xE2, 0x52, 0x6A,
    0x21, 0x0B, 0x41, 0x4C, 0x41, 0x4E, 0xA1, 0xAA, 0x01, 0x3F
};

static Cpa8U sampleEspHdrData[] =
    {0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x05};

/* Payload padded to a multiple of the cipher block size
   (16), 2nd last byte gives pad length, last byte gives
   next header info */
static Cpa8U samplePayload[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09,
    0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34,
    0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c,
    0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24,
    0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6,
    0x57, 0xba, 0x63, 0x7b, 0x39, 0x01, 0x02, 0x02, 0x61};

static Cpa8U expectedOutput[] = {
    /* ESP header unmodified */
    0x00,
    0x00,
    0x01,
    0x2c,
    0x00,
    0x00,
    0x00,
    0x05,
    /* IV unmodified */
    0xca,
    0xfe,
    0xba,
    0xbe,
    0xfa,
    0xce,
    0xdb,
    0xad,
    0xde,
    0xca,
    0xf8,
    0x88,
    0x3d,
    0x11,
    0x59,
    0x04,
    /* Ciphertext */
    0x39,
    0x8E,
    0x4C,
    0x1B,
    0x7B,
    0x28,
    0x94,
    0x52,
    0x97,
    0xAD,
    0x95,
    0x97,
    0xD7,
    0xF9,
    0xB9,
    0x4A,
    0x49,
    0x03,
    0x51,
    0x47,
    0x45,
    0xC7,
    0x58,
    0x6A,
    0x9A,
    0x48,
    0xB6,
    0x38,
    0xB4,
    0xD5,
    0xEE,
    0x42,
    0x4F,
    0x39,
    0x09,
    0x3D,
    0xAB,
    0x1E,
    0xB3,
    0x6A,
    0x71,
    0x0B,
    0xFC,
    0x80,
    0xAD,
    0x2E,
    0x4C,
    0xA5,
    0xAB,
    0x78,
    0xB8,
    0xAB,
    0x87,
    0xCC,
    0x37,
    0xF0,
    0xB9,
    0x61,
    0xDC,
    0xB1,
    0xA7,
    0x24,
    0x26,
    0x23,
    /* ICV */
    0x68,
    0x9A,
    0xAC,
    0x49,
    0xA0,
    0xD2,
    0x45,
    0x21,
    0x15,
    0xD6,
    0xA1,
    0x5B
};

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
 * of a decrypted packet, etc.  In this example, the function checks
 * verifyResult returned and sets the complete variable to indicate it
 * has been called.
 */
static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    /* For this implementation verifyResult is true by default. In
       the digest generate case verifyDigest will never be false. In
       the digest verify case verifyDigest can be false if digest
       verification fails */
    if (CPA_FALSE == verifyResult)
    {
        PRINT_ERR("Callback verify result error\n");
    }

    if (NULL != pCallbackTag)
    {
        /** indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

/*
 * Perform an algorithm chaining operation
 */
static CpaStatus algChainPerformOp(CpaInstanceHandle cyInstHandle,
                                   CpaCySymSessionCtx sessionCtx,
                                   int dir)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    /* buffer size includes space for hdr, iv, payload and icv */
    Cpa32U bufferSize = sizeof(sampleEspHdrData) + sizeof(sampleCipherIv) +
                        sizeof(samplePayload) + ICV_LENGTH;
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pIvBuffer = NULL;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;

    /* get meta information size */
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
        /* increment by sizeof(CpaBufferList) to get at the
         * array of flatbuffers */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);

        pBufferList->pBuffers = pFlatBuffer;
        pBufferList->numBuffers = 1;
        pBufferList->pPrivateMetaData = pBufferMeta;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pSrcBuffer;

        /* copy source into buffer */
        if (IPSEC_OUTBOUND_DIR == dir)
        {
            memcpy(pSrcBuffer, sampleEspHdrData, sizeof(sampleEspHdrData));
            memcpy(pSrcBuffer + sizeof(sampleEspHdrData),
                   sampleCipherIv,
                   sizeof(sampleCipherIv));
            memcpy(pSrcBuffer +
                       (sizeof(sampleEspHdrData) + sizeof(sampleCipherIv)),
                   samplePayload,
                   sizeof(samplePayload));
        }
        else
        {
            memcpy(pSrcBuffer, expectedOutput, sizeof(expectedOutput));
        }

        pIvBuffer = pSrcBuffer + sizeof(sampleEspHdrData);

        status = OS_MALLOC(&pOpData, sizeof(CpaCySymOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (IPSEC_OUTBOUND_DIR == dir)
        {
            //<snippet name="opDataIPSecOut">
            /** Populate the structure containing the operational data that is
             * needed to run the algorithm in outbound direction */
            pOpData->sessionCtx = sessionCtx;
            pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
            pOpData->pIv = pIvBuffer;
            pOpData->ivLenInBytes = sizeof(sampleCipherIv);
            pOpData->cryptoStartSrcOffsetInBytes =
                sizeof(sampleEspHdrData) + sizeof(sampleCipherIv);
            pOpData->messageLenToCipherInBytes = sizeof(samplePayload);
            pOpData->hashStartSrcOffsetInBytes = 0;
            pOpData->messageLenToHashInBytes = sizeof(sampleEspHdrData) +
                                               sizeof(sampleCipherIv) +
                                               sizeof(samplePayload);
            /* Even though ICV follows immediately after the region to hash
            digestIsAppended is set to false in this case due to
            errata number IXA00378322 */
            pOpData->pDigestResult =
                pSrcBuffer + (sizeof(sampleEspHdrData) +
                              sizeof(sampleCipherIv) + sizeof(samplePayload));
            //</snippet>
        }
        else
        {
            //<snippet name="opDataIPSecIn">
            /** Populate the structure containing the operational data that is
             * needed to run the algorithm in inbound direction */
            pOpData->sessionCtx = sessionCtx;
            pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
            pOpData->pIv = pIvBuffer;
            pOpData->ivLenInBytes = sizeof(sampleCipherIv);
            pOpData->cryptoStartSrcOffsetInBytes =
                sizeof(sampleEspHdrData) + sizeof(sampleCipherIv);
            pOpData->messageLenToCipherInBytes =
                bufferSize - (sizeof(sampleEspHdrData) +
                              sizeof(sampleCipherIv) + ICV_LENGTH);
            pOpData->hashStartSrcOffsetInBytes = 0;
            pOpData->messageLenToHashInBytes = bufferSize - ICV_LENGTH;
            //</snippet>
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** initialisation for callback; the "complete" variable is used by the
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
            NULL);             /* pVerifyResult not required in async mode */

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
            if (IPSEC_OUTBOUND_DIR == dir)
            {
                if (0 == memcmp(pSrcBuffer, expectedOutput, bufferSize))
                {
                    PRINT_DBG(
                        "Output matches expected output encrypt generate\n");
                }
                else
                {
                    PRINT_DBG("Output does not match expected output encrypt "
                              "generate\n");
                    status = CPA_STATUS_FAIL;
                }
            }
            else
            {
                if (0 == memcmp(pSrcBuffer + (sizeof(sampleEspHdrData) +
                                              sizeof(sampleCipherIv)),
                                samplePayload,
                                sizeof(samplePayload)))
                {
                    PRINT_DBG(
                        "Output matches expected output decrypt verify\n");
                }
                else
                {
                    PRINT_DBG("Output does not match expected output decrypt "
                              "verify\n");
                    status = CPA_STATUS_FAIL;
                }
            }
        }
    }

    /* at this stage, the callback function has returned, so it is sure that
     * the structures won't be needed any more*/
    PHYS_CONTIG_FREE(pSrcBuffer);
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
    CpaCySymSessionSetupData sessionSetupData = {0};
    CpaCySymStats64 symStats = {0};
    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    sampleCyGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        PRINT_DBG("No crypto instances available\n");
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

        PRINT_DBG("Encrypt-Generate ICV\n");

        /* populate symmetric session data structure */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_HIGH;
        //<snippet name="initSessionIPSecEnc">
        sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        sessionSetupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;

        sessionSetupData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_CBC;
        sessionSetupData.cipherSetupData.pCipherKey = sampleCipherKey;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
            sizeof(sampleCipherKey);
        sessionSetupData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        sessionSetupData.hashSetupData.digestResultLenInBytes = ICV_LENGTH;
        sessionSetupData.hashSetupData.authModeSetupData.authKey =
            sampleAuthKey;
        sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
            sizeof(sampleAuthKey);

        /* Even though ICV follows immediately after the region to hash
           digestIsAppended is set to false in this case due to
           errata number IXA00378322 */
        sessionSetupData.digestIsAppended = CPA_FALSE;
        /* Generate the ICV in outbound direction */
        sessionSetupData.verifyDigest = CPA_FALSE;
        //</snippet>

        /* Determine size of session context to allocate */
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
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        status =
            algChainPerformOp(cyInstHandle, sessionCtx, IPSEC_OUTBOUND_DIR);

        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        /* Remove the session - session init has already succeeded */
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
        PRINT_DBG("Decrypt-Verify ICV\n");

        /* populate symmetric session data structure */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_HIGH;
        //<snippet name="initSessionIPSecDec">
        sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        sessionSetupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;

        sessionSetupData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_CBC;
        sessionSetupData.cipherSetupData.pCipherKey = sampleCipherKey;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
            sizeof(sampleCipherKey);
        sessionSetupData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;

        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        sessionSetupData.hashSetupData.digestResultLenInBytes = ICV_LENGTH;
        sessionSetupData.hashSetupData.authModeSetupData.authKey =
            sampleAuthKey;
        sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
            sizeof(sampleAuthKey);

        /* ICV follows immediately after the region to hash */
        sessionSetupData.digestIsAppended = CPA_TRUE;
        /* Verify the ICV in the inbound direction */
        sessionSetupData.verifyDigest = CPA_TRUE;
        //</snippet>
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the session */
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        status = algChainPerformOp(cyInstHandle, sessionCtx, IPSEC_INBOUND_DIR);

        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        /* Remove the session - session init has already succeeded */
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
            PRINT_DBG("Number of symmetric operations completed: %llu\n",
                      (unsigned long long)symStats.numSymOpCompleted);
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