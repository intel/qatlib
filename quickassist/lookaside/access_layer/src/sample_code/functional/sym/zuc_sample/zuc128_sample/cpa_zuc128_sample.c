/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
/*
 * This is sample code that demonstrates usage of the symmetric API, and
 * specifically using this API to perform a ZUC-128 operation.
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"

#include "cpa_sample_utils.h"

#define DIGEST_LENGTH 4
#define TIMEOUT_MS 5000 /* 5 seconds*/

extern int gDebugParam;
/* ZUC cipher key, 256 bits long */
static Cpa8U sampleCipherKey[] = {
    0x9F, 0x0E, 0xD2, 0xF0, 0x83, 0x39, 0x12, 0x28, 0xB7, 0x03, 0xA9, 0x4B,
    0xF6, 0x75, 0x73, 0x48};
/* Initialization vector */
static Cpa8U sampleCipherIv[] = {
    0x70, 0xB3, 0xFB, 0xE9, 0x91, 0xCB, 0x49, 0x10, 0xDC, 0x81, 0x27, 0x1D,
    0x60, 0xB5, 0x10, 0x4A};
/* ZUC authentication key, 256 bits long */
static Cpa8U sampleAuthKey[] = {
    0xCB, 0xB6, 0xE5, 0x0E, 0xD0, 0x65, 0xF3, 0x55, 0x62, 0xED, 0x2B, 0x6B,
    0xD7, 0x6A, 0xC8, 0xFB};

/* Source data to encrypt */
static Cpa8U samplePayload[] = {
    0x65, 0x49, 0xC3, 0xD3, 0x10, 0x73, 0x95, 0xEE, 0x0F, 0x54, 0xA1, 0x83,
    0x24, 0xD9, 0xAB, 0xB1, 0x67, 0x8B, 0xA8, 0xBE, 0x4D, 0xE2, 0x62, 0x7A,
    0x21, 0x37, 0x99, 0x61, 0xAE, 0xBF, 0x7E, 0x82, 0x58, 0x88, 0xA6, 0x2A,
    0xA3, 0x59, 0x9E, 0x42, 0x59, 0x11, 0xCF, 0x8D, 0x91, 0xAE, 0x27, 0xA8,
    0x7A, 0xB2, 0x05, 0x9A, 0x41, 0xC0, 0x83, 0x15, 0xBA, 0xE8, 0x91, 0x5B,
    0x01, 0xEE, 0x5D, 0x36};

/* Expected output of the operation */
static Cpa8U expectedOutput[] = {
    0x94, 0xC0, 0x31, 0x5D, 0x2E, 0x0F, 0xCC, 0x1C, 0x94, 0x6A, 0x18, 0xE6,
    0x12, 0xCD, 0x6F, 0x14, 0x05, 0xC7, 0x2C, 0x2E, 0xE0, 0x50, 0xD2, 0xF4,
    0x5E, 0x23, 0x1F, 0x92, 0x6E, 0x48, 0xD7, 0x90, 0xC4, 0xF9, 0xE3, 0xF0,
    0x97, 0x18, 0x21, 0xE9, 0x19, 0x2E, 0xBA, 0x79, 0x12, 0x55, 0x65, 0xD8,
    0x6E, 0xD1, 0xD7, 0x85, 0x45, 0xE6, 0xC9, 0xB0, 0x0E, 0x82, 0x04, 0xCE,
    0x16, 0xBB, 0x89, 0xC9, 0xE6, 0x57, 0xD1, 0x4C};
/* Association data */
static Cpa8U sampleAssocData[] = {
    0xA5, 0x19, 0x66, 0x4D, 0x66, 0x38, 0x27, 0x9B, 0xB3, 0x76, 0xCA, 0xE1,
    0x0F, 0xAE, 0x67, 0xBE};
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

    COMPLETION_INIT(&complete); // Initialize the completion variable

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
    CpaCySymCapabilitiesInfo symCapInfo = { { 0 } };
    memset(&sessionSetupData, 0, sizeof(CpaCySymSessionSetupData));
    memset(&symStats, 0, sizeof(CpaCySymStats64));

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    sampleSymGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    status = cpaCySymQueryCapabilities(cyInstHandle, &symCapInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to query capabilities, status = %d\n", status);
        return status;
    }
    /* Check capabilities before running the test */
    if ((!CPA_BITMAP_BIT_TEST(symCapInfo.ciphers,
                              CPA_CY_SYM_CIPHER_ZUC_EEA3)) ||
        (!CPA_BITMAP_BIT_TEST(symCapInfo.hashes, CPA_CY_SYM_HASH_ZUC_EIA3)))
    {
        PRINT("ZUC algorithm chaining not supported on Instance\n");
        return CPA_STATUS_UNSUPPORTED;
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
        sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes = 16;

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
