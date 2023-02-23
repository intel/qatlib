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
 * specifically using this API to perform a hash of a file using SHA256.
 * Note this program will only work with files greater than SAMPLE_BUFF_SIZE
 * (Output can be compared with sha256sum in linux)
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_utils.h"

extern int gDebugParam;

/* The digest length must be less than or equal to sha256 digest
   length (32) for this example */
#define DIGEST_LENGTH 32

/* Size of the buffer sent to the api */
#define SAMPLE_BUFF_SIZE 4096

extern char *gFileName;

/* Forward declaration */
CpaStatus hashFileSample(void);

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
 * of a hashed packet, etc.  In this example, the function only
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
        /** indicate that the function has been called*/
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

/*
 * Perform a hash operation
 */
static CpaStatus hashPerformOp(CpaInstanceHandle cyInstHandle,
                               CpaCySymSessionCtx sessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    Cpa32U bufferSize = SAMPLE_BUFF_SIZE;
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pDigestBuffer = NULL;
    FILE *srcFile = NULL;
    int i = 0;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;

    /* Open file */
    srcFile = fopen(gFileName, "r");
    if (NULL == srcFile)
    {
        PRINT_ERR("Cannot open file %s\n", gFileName);
        return CPA_STATUS_FAIL;
    }
    else
    {
        PRINT_DBG("Processing file %s\n", gFileName);
    }

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
        status = PHYS_CONTIG_ALLOC(&pDigestBuffer, DIGEST_LENGTH);
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

        status = OS_MALLOC(&pOpData, sizeof(CpaCySymOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** initialization for callback; the "complete" variable is used by the
         * callback function to indicate it has been called*/
        COMPLETION_INIT((&complete));

        //<snippet name="hashFile">
        while (!feof(srcFile))
        {
            /* read from file into src buffer */
            pBufferList->pBuffers->dataLenInBytes =
                fread(pSrcBuffer, 1, SAMPLE_BUFF_SIZE, srcFile);

            /* If we have reached the end of file set the last partial flag */
            if (feof(srcFile))
            {
                pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL;
            }
            else
            {
                pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;
            }
            pOpData->sessionCtx = sessionCtx;
            pOpData->hashStartSrcOffsetInBytes = 0;
            pOpData->messageLenToHashInBytes =
                pBufferList->pBuffers->dataLenInBytes;
            pOpData->pDigestResult = pDigestBuffer;

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
                break;
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                /** wait until the completion of the operation*/
                if (!COMPLETION_WAIT((&complete), TIMEOUT_MS))
                {
                    PRINT_ERR("timeout or interruption in cpaCySymPerformOp\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }

        //</snippet>
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Output Result */
        printf("DIGEST: \n");
        for (i = 0; i < DIGEST_LENGTH; i++)
        {
            if (i && (i % 16 == 0))
            {
                printf("\n");
            }

            printf("%02X", pDigestBuffer[i]);
        }
        printf("\n");
    }

    fclose(srcFile);

    /* At this stage, the callback function should have returned,
     * so it is safe to free the memory */
    PHYS_CONTIG_FREE(pSrcBuffer);
    OS_FREE(pBufferList);
    PHYS_CONTIG_FREE(pBufferMeta);
    PHYS_CONTIG_FREE(pDigestBuffer);
    OS_FREE(pOpData);

    COMPLETION_DESTROY(&complete);

    return status;
}

/*
 * This is the main entry point for the sample cipher code.  It
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more hash operations, and
 * then tear down the session.
 */
CpaStatus hashFileSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionCtx sessionCtx = NULL;
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

        /*
         * We now populate the fields of the session operational data and create
         * the session.  Note that the size required to store a session is
         * implementation-dependent, so we query the API first to determine how
         * much memory to allocate, and then allocate that memory.
         */
        //<snippet name="initSession">
        /* populate symmetric session data structure
         * for a plain hash operation */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        sessionSetupData.symOperation = CPA_CY_SYM_OP_HASH;
        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
        sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;
        /* Place the digest result in a buffer unrelated to srcBuffer */
        sessionSetupData.digestIsAppended = CPA_FALSE;
        /* Generate the digest */
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
        /* Initialize the Hash session */
        PRINT_DBG("cpaCySymInitSession\n");
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform Hash operation */
        status = hashPerformOp(cyInstHandle, sessionCtx);

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
                      (unsigned long long)symStats.numSymOpCompleted);
        }
    }

    /* Clean up */

    /* Stop the polling thread */
    sampleCyStopPolling();

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionCtx);

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
