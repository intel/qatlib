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
 * specifically using this API to perform a CCM operation. For more information
 * on CCM please reference NIST publication SP800-38C "Recommendation for Block
 * Cipher Modes of Operation: the CCM Mode for Authentication and
 * Confidentiality"
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"

#include "cpa_sample_utils.h"

#define DIGEST_LENGTH 4
#define AES_BLOCK_SIZE 16
#define B0_BLOCK_SIZE 16
#define ALEN_ENCODING_SIZE 2
#define TIMEOUT_MS 5000 /* 5 seconds*/
#define GEN_ENCRYPT_DIR 0
#define DECRYPT_VERIFY_DIR 1

extern int gDebugParam;

/* Test vector from NIST SP 800-38C Example 1 */
static Cpa8U sampleKey[] = {0x40,
                            0x41,
                            0x42,
                            0x43,
                            0x44,
                            0x45,
                            0x46,
                            0x47,
                            0x48,
                            0x49,
                            0x4a,
                            0x4b,
                            0x4c,
                            0x4d,
                            0x4e,
                            0x4f};

static Cpa8U sampleNonce[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

static Cpa8U sampleAssocData[] =
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

static Cpa8U samplePayload[] = {0x20, 0x21, 0x22, 0x23};

static Cpa8U expectedOutput[] =
    {0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d};

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
 * verifyResult returned and sets the complete variable to indicate
 * it has been called.
 */
static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    if (CPA_FALSE == verifyResult)
    {
        PRINT_ERR("Error verifyResult failed\n");
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
static CpaStatus algChainPerformOpCCM(CpaInstanceHandle cyInstHandle,
                                      CpaCySymSessionCtx sessionCtx,
                                      int dir)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    Cpa32U bufferSize = sizeof(samplePayload) + DIGEST_LENGTH;
    Cpa32U aadBuffSize = 0;
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pIvBuffer = NULL;
    Cpa8U *pAadBuffer = NULL;

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
        /* increment by sizeof(CpaBufferList) to get at the
         * array of flatbuffers */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);

        pBufferList->pBuffers = pFlatBuffer;
        pBufferList->numBuffers = 1;
        pBufferList->pPrivateMetaData = pBufferMeta;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pSrcBuffer;

        /* copy source into buffer */
        if (GEN_ENCRYPT_DIR == dir)
        {
            memcpy(pSrcBuffer, samplePayload, sizeof(samplePayload));
        }
        else
        {
            memcpy(pSrcBuffer, expectedOutput, sizeof(expectedOutput));
        }
        //<snippet name="ivaad">
        /* Allocate memory to store IV. For CCM this is the counter block
         * ctr0 (size equal to AES block size). The implementation will
         * construct the ctr0 block given the nonce. Space for ctr0 must be
         * allocated here  */
        status = PHYS_CONTIG_ALLOC(&pIvBuffer, AES_BLOCK_SIZE);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate memory for AAD. For CCM this memory will hold the 16 byte
         * B0 block, the 2 bytes encoded length of associated data, the
         * associated data itself and any padding to ensure total size is
         * a multiple of the AES block size
         */
        aadBuffSize =
            B0_BLOCK_SIZE + ALEN_ENCODING_SIZE + sizeof(sampleAssocData);
        if (aadBuffSize % AES_BLOCK_SIZE)
        {
            aadBuffSize += AES_BLOCK_SIZE - (aadBuffSize % AES_BLOCK_SIZE);
        }
        status = PHYS_CONTIG_ALLOC(&pAadBuffer, aadBuffSize);
    }
    //</snippet>
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pOpData, sizeof(CpaCySymOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        //<snippet name="opData">
        pOpData->sessionCtx = sessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->pIv = pIvBuffer;
        /* Even though the iv buffer is 16 bytes the ivLenInBytes
         * is set to the length of the nonce. For CCM valid lengths
         * are in the range 7-13
         */
        pOpData->ivLenInBytes = sizeof(sampleNonce);
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = sizeof(samplePayload);
        /* Notice for CCM hash offset and length are not required */
        pOpData->pAdditionalAuthData = pAadBuffer;

        /* Populate pIv and pAdditionalAuthData buffers with nonce and assoc
         * data */
        CPA_CY_SYM_CCM_SET_NONCE(pOpData, sampleNonce, sizeof(sampleNonce));
        CPA_CY_SYM_CCM_SET_AAD(
            pOpData, sampleAssocData, sizeof(sampleAssocData));
        //</snippet>
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
            if (GEN_ENCRYPT_DIR == dir)
            {
                if (0 == memcmp(pSrcBuffer, expectedOutput, bufferSize))
                {
                    PRINT_DBG("Output matches expected output CCM encrypt\n");
                }
                else
                {
                    PRINT_ERR(
                        "Output does not match expected output CCM encrypt\n");
                    status = CPA_STATUS_FAIL;
                }
            }
            else
            {
                if (0 ==
                    memcmp(pSrcBuffer, samplePayload, sizeof(samplePayload)))
                {
                    PRINT_DBG("Output matches expected output CCM decrypt\n");
                }
                else
                {
                    PRINT_ERR(
                        "Output does not match expected output CCM decrypt\n");
                    status = CPA_STATUS_FAIL;
                }
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
    CpaCySymSessionSetupData sessionSetupData = {0};
    CpaCySymStats64 symStats = {0};

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

        PRINT_DBG("Generation-Encryption Process\n");

        /* populate symmetric session data structure */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        //<snippet name="initSessionEnc">
        sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        sessionSetupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;

        sessionSetupData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_CCM;
        sessionSetupData.cipherSetupData.pCipherKey = sampleKey;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
            sizeof(sampleKey);
        sessionSetupData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_CCM;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;

        /* Notice for CCM authKey and authKeyLen are not required this
         * information is provided by the cipherKey in cipherSetupData
         */
        sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes =
            sizeof(sampleAssocData);
        /* For CCM digestAppended and digestVerify are not required. In
         * the encrypt direction digestAppended is CPA_TRUE and
         * digestVerify is CPA_FALSE
         */
        //</snippet>

        /* Determine size of session context to allocate */
        PRINT_DBG("cpaCySymSessionCtxGetSize CCM encrypt\n");
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
        PRINT_DBG("cpaCySymInitSession CCM encrypt\n");
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        status =
            algChainPerformOpCCM(cyInstHandle, sessionCtx, GEN_ENCRYPT_DIR);

        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        /* Remove the session - session init has already succeeded */
        PRINT_DBG("cpaCySymRemoveSession CCM encrypt\n");
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
        PRINT_DBG("Decryption-Verification Process\n");

        /* populate symmetric session data structure */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        //<snippet name="initSessionDec">
        sessionSetupData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        sessionSetupData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;

        sessionSetupData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_CCM;
        sessionSetupData.cipherSetupData.pCipherKey = sampleKey;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
            sizeof(sampleKey);
        sessionSetupData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;

        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_CCM;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;
        sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes =
            sizeof(sampleAssocData);
        //</snippet>
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the session */
        PRINT_DBG("cpaCySymInitSession CCM Decrypt\n");
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        status =
            algChainPerformOpCCM(cyInstHandle, sessionCtx, DECRYPT_VERIFY_DIR);

        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        /* Remove the session - session init has already succeeded */
        PRINT_DBG("cpaCySymRemoveSession CCM decrypt\n");
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
