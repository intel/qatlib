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
 * This is sample code that demonstrates usage of the dc chain API,
 * and specifically using this API to perform hash plus compression chain
 * operation.
 */

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_dc.h"
#include "cpa_dc_chain.h"
#include "cpa_sample_utils.h"
#include "openssl/sha.h"
#include "zlib.h"
#include "cpa_chaining_sample_input.h"

extern int gDebugParam;

#define NUM_SESSIONS_TWO (2)

/* Used by ZLIB */
#define DEFLATE_DEF_WINBITS (15)

/* Return digest length of hash algorithm */
#define GET_HASH_DIGEST_LENGTH(hashAlg)                                        \
    ({                                                                         \
        int length;                                                            \
        if (hashAlg == CPA_CY_SYM_HASH_SHA1)                                   \
        {                                                                      \
            length = 20;                                                       \
        }                                                                      \
        else if (hashAlg == CPA_CY_SYM_HASH_SHA256)                            \
        {                                                                      \
            length = 32;                                                       \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            length = 0;                                                        \
        }                                                                      \
        length;                                                                \
    })

static void dcChainFreeBufferList(CpaBufferList **testBufferList);

/* Calculate software digest */
static inline CpaStatus calSWDigest(Cpa8U *msg,
                                    Cpa32U slen,
                                    Cpa8U *digest,
                                    Cpa32U dlen,
                                    CpaCySymHashAlgorithm hashAlg)
{
    switch (hashAlg)
    {
        case CPA_CY_SYM_HASH_SHA1:
            return (SHA1(msg, slen, digest) == NULL) ? CPA_STATUS_FAIL
                                                     : CPA_STATUS_SUCCESS;
        case CPA_CY_SYM_HASH_SHA256:
            return (SHA256(msg, slen, digest) == NULL) ? CPA_STATUS_FAIL
                                                       : CPA_STATUS_SUCCESS;
        default:
            PRINT_ERR("Unsupported hash algorithm %d\n", hashAlg);
            return CPA_STATUS_UNSUPPORTED;
    }
}

/* Initilise a zlib stream */
static CpaStatus inflate_init(z_stream *stream)
{
    int ret = 0;
    stream->zalloc = (alloc_func)0;
    stream->zfree = (free_func)0;
    stream->opaque = (voidpf)0;
    stream->next_in = Z_NULL;
    stream->next_out = Z_NULL;
    stream->avail_in = stream->avail_out = stream->total_out = 0;
    stream->adler = 0;

    ret = inflateInit2(stream, -DEFLATE_DEF_WINBITS);
    if (Z_OK != ret)
    {
        PRINT_ERR("Error in inflateInit2, ret = %d\n", ret);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/* Decompress data on a zlib stream */
static CpaStatus inflate_decompress(z_stream *stream,
                                    const Cpa8U *src,
                                    Cpa32U slen,
                                    Cpa8U *dst,
                                    Cpa32U dlen)
{
    int ret = 0;
    int flushFlag = Z_NO_FLUSH;

    stream->next_in = (Cpa8U *)src;
    stream->avail_in = slen;
    stream->next_out = (Cpa8U *)dst;
    stream->avail_out = dlen;

    ret = inflate(stream, flushFlag);
    if (ret < Z_OK)
    {
        PRINT_ERR("Error in inflate, ret = %d\n", ret);
        PRINT_ERR("stream->msg = %s\n", stream->msg);
        PRINT_ERR("stream->adler = %u\n", (unsigned int)stream->adler);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/* Close zlib stream */
static void inflate_destroy(struct z_stream_s *stream)
{
    inflateEnd(stream);
}

/* Copy multiple buffers data in buffer lists to flat buffer */
static void copyMultiFlatBufferToBuffer(CpaBufferList *pBufferListSrc,
                                        Cpa8U *pBufferDst)
{
    int i = 0;
    int offset = 0;
    CpaFlatBuffer *pBuffers = pBufferListSrc->pBuffers;

    for (; i < pBufferListSrc->numBuffers; i++)
    {
        memcpy(pBufferDst + offset, pBuffers->pData, pBuffers->dataLenInBytes);
        offset += pBuffers->dataLenInBytes;
        pBuffers++;
    }
}

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
 * of a packet, etc.  In this example, the function only sets the
 * complete variable to indicate it has been called.
 */
//<snippet name="dcCallback">
static void dcCallback(void *pCallbackTag, CpaStatus status)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    if (NULL != pCallbackTag)
    {
        /* indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}
//</snippet>

/* Build dc chain buffer lists */
static CpaStatus dcChainBuildBufferList(CpaBufferList **testBufferList,
                                        Cpa32U numBuffers,
                                        Cpa32U bufferSize,
                                        Cpa32U bufferMetaSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBufferList *pBuffList = NULL;
    CpaFlatBuffer *pFlatBuff = NULL;
    Cpa32U curBuff = 0;
    Cpa8U *pMsg = NULL;
    /*
     * allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required.
     */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));

    status = OS_MALLOC(&pBuffList, bufferListMemSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error in allocating pBuffList\n");
        return CPA_STATUS_FAIL;
    }

    pBuffList->numBuffers = numBuffers;

    if (bufferMetaSize)
    {
        status =
            PHYS_CONTIG_ALLOC(&pBuffList->pPrivateMetaData, bufferMetaSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error in allocating pBuffList->pPrivateMetaData\n");
            OS_FREE(pBuffList);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        pBuffList->pPrivateMetaData = NULL;
    }

    pFlatBuff = (CpaFlatBuffer *)(pBuffList + 1);
    pBuffList->pBuffers = pFlatBuff;

    while (curBuff < numBuffers)
    {
        if (0 != bufferSize)
        {
            status = PHYS_CONTIG_ALLOC(&pMsg, bufferSize);
            if (CPA_STATUS_SUCCESS != status || NULL == pMsg)
            {
                PRINT_ERR("Error in allocating pMsg\n");
                dcChainFreeBufferList(&pBuffList);
                return CPA_STATUS_FAIL;
            }
            memset(pMsg, 0, bufferSize);
            pFlatBuff->pData = pMsg;
        }
        else
        {
            pFlatBuff->pData = NULL;
        }
        pFlatBuff->dataLenInBytes = bufferSize;
        pFlatBuff++;
        curBuff++;
    }

    *testBufferList = pBuffList;

    return CPA_STATUS_SUCCESS;
}

/* Free dc chain buffer lists */
static void dcChainFreeBufferList(CpaBufferList **testBufferList)
{
    CpaBufferList *pBuffList = *testBufferList;
    CpaFlatBuffer *pFlatBuff = NULL;
    Cpa32U curBuff = 0;

    if (NULL == pBuffList)
    {
        PRINT_ERR("testBufferList is NULL\n");
        return;
    }

    pFlatBuff = pBuffList->pBuffers;
    while (curBuff < pBuffList->numBuffers)
    {
        if (NULL != pFlatBuff->pData)
        {
            PHYS_CONTIG_FREE(pFlatBuff->pData);
            pFlatBuff->pData = NULL;
        }
        pFlatBuff++;
        curBuff++;
    }

    if (NULL != pBuffList->pPrivateMetaData)
    {
        PHYS_CONTIG_FREE(pBuffList->pPrivateMetaData);
        pBuffList->pPrivateMetaData = NULL;
    }

    OS_FREE(pBuffList);
    *testBufferList = NULL;
}

/*
 * This function performs a dc chain operation.
 */
static CpaStatus dcChainingPerformOp(CpaInstanceHandle dcInstHandle,
                                     CpaDcSessionHandle sessionHdl)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferListSrc = NULL;
    CpaBufferList *pBufferListDst = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    Cpa32U bufferSize = 0;
    Cpa32U numBuffers = 1;
    Cpa8U *pDigestBuffer = NULL;
    CpaDcChainOpData chainOpData[2] = {{0}, {0}};
    CpaDcOpData dcOpData = {0};
    CpaCySymOpData cySymOpData = {0};
    CpaDcChainRqResults chainResult = {0};
    CpaDcChainOperations operation = CPA_DC_CHAIN_HASH_THEN_COMPRESS;
    CpaCySymHashAlgorithm hashAlg = CPA_CY_SYM_HASH_SHA256;
    Cpa8U numSessions = NUM_SESSIONS_TWO;
    struct COMPLETION_STRUCT complete;
    Cpa8U *pSWDigestBuffer = NULL;

    PRINT_DBG("cpaDcBufferListGetMetaSize\n");

    /*
     * Different implementations of the API require different
     * amounts of space to store meta-data associated with buffer
     * lists.  We query the API to find out how much space the current
     * implementation needs, and then allocate space for the buffer
     * meta data, the buffer list, and for the buffer itself.
     */
    //<snippet name="memAlloc">
    status =
        cpaDcBufferListGetMetaSize(dcInstHandle, numBuffers, &bufferMetaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error get meta size\n");
        return CPA_STATUS_FAIL;
    }
    bufferSize = sampleDataSize;
    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcChainBuildBufferList(
            &pBufferListSrc, numBuffers, bufferSize, bufferMetaSize);
    }

    /* copy source data into buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListSrc + 1);
        memcpy(pFlatBuffer->pData, sampleData, bufferSize);
    }

    /* Allocate destination buffer the four times as source buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcChainBuildBufferList(
            &pBufferListDst, numBuffers, 4 * bufferSize, bufferMetaSize);
    }

    /* Allocate digest result buffer to store hash value */
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            PHYS_CONTIG_ALLOC(&pDigestBuffer, GET_HASH_DIGEST_LENGTH(hashAlg));
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        dcOpData.flushFlag = CPA_DC_FLUSH_FINAL;
        dcOpData.compressAndVerify = CPA_TRUE;
        dcOpData.compressAndVerifyAndRecover = CPA_TRUE;

        cySymOpData.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        cySymOpData.hashStartSrcOffsetInBytes = 0;
        cySymOpData.messageLenToHashInBytes = bufferSize;
        cySymOpData.pDigestResult = pDigestBuffer;

        /* Set chaining operation data */
        chainOpData[0].opType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
        chainOpData[0].pCySymOp = &cySymOpData;
        chainOpData[1].opType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
        chainOpData[1].pDcOp = &dcOpData;

        /*
         * Now, we initialize the completion variable which is used by the
         * callback function to indicate that the operation is complete.
         * We then perform the operation.
         */
        //<snippet name="perfOp">
        COMPLETION_INIT(&complete);
        status = cpaDcChainPerformOp(dcInstHandle,
                                     sessionHdl,
                                     pBufferListSrc,
                                     pBufferListDst,
                                     operation,
                                     numSessions,
                                     chainOpData,
                                     &chainResult,
                                     (void *)&complete);
        //</snippet>

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcChainPerformOp failed. (status = %d)\n", status);
        }

        /*
         * We now wait until the completion of the operation.  This uses a macro
         * which can be defined differently for different OSes.
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
            {
                PRINT_ERR("timeout or interruption in cpaDcChainPerformOp\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }

    /*
     * We now check the results
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (chainResult.dcStatus != CPA_DC_OK)
        {
            PRINT_ERR("Results dcStatus not as expected (dcStatus = %d)\n",
                      chainResult.dcStatus);
            status = CPA_STATUS_FAIL;
        }
        else if (chainResult.cyStatus != CPA_DC_OK)
        {
            PRINT_ERR("Results cyStatus not as expected (cyStatus = %d)\n",
                      chainResult.cyStatus);
            status = CPA_STATUS_FAIL;
        }
        else
        {
            PRINT_DBG("Data consumed %d\n", chainResult.consumed);
            PRINT_DBG("Data produced %d\n", chainResult.produced);
            PRINT_DBG("Crc32 checksum 0x%x\n", chainResult.crc32);
        }
    }
    /* Allocate digest result buffer for execution in software*/
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pSWDigestBuffer,
                                   GET_HASH_DIGEST_LENGTH(hashAlg));
    }
    /* Use software to calculate digest and verify digest */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = calSWDigest(sampleData,
                             bufferSize,
                             pSWDigestBuffer,
                             GET_HASH_DIGEST_LENGTH(hashAlg),
                             hashAlg);

        if (CPA_STATUS_SUCCESS == status)
        {
            if (memcmp(pDigestBuffer,
                       pSWDigestBuffer,
                       GET_HASH_DIGEST_LENGTH(hashAlg)))
            {
                status = CPA_STATUS_FAIL;
                PRINT_ERR("Digest buffer does not match expected output\n");
            }
            else
            {
                PRINT_DBG("Digest buffer matches expected output\n");
            }
        }

        PHYS_CONTIG_FREE(pSWDigestBuffer);
    }

    /* Use zlib to decompress and verify integrity */
    //<snippet name="software decompress">
    if (CPA_STATUS_SUCCESS == status)
    {
        struct z_stream_s stream = {0};
        Cpa8U *pDecompBuffer = NULL;
        Cpa8U *pHWCompBuffer = NULL;
        Cpa32U decompBufferLength = 0;
        Cpa32U compBufferLength = 0;

        status = inflate_init(&stream);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT("zlib stream initialize failed");
        }

        decompBufferLength = pBufferListSrc->numBuffers *
                             pBufferListSrc->pBuffers->dataLenInBytes;

        compBufferLength = pBufferListDst->numBuffers *
                           pBufferListDst->pBuffers->dataLenInBytes;

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pDecompBuffer, decompBufferLength);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pHWCompBuffer, compBufferLength);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            copyMultiFlatBufferToBuffer(pBufferListDst, pHWCompBuffer);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = inflate_decompress(&stream,
                                        pHWCompBuffer,
                                        compBufferLength,
                                        pDecompBuffer,
                                        decompBufferLength);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Decompress data on zlib stream failed\n");
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Compare with original Src buffer */
            if (memcmp(pDecompBuffer, sampleData, bufferSize))
            {
                status = CPA_STATUS_FAIL;
                PRINT_ERR("Decompressed Buffer does not match source buffer\n");
            }
            else
            {
                PRINT_DBG("Decompressed Buffer matches source buffer\n");
            }
        }

        inflate_destroy(&stream);

        PHYS_CONTIG_FREE(pHWCompBuffer);
        PHYS_CONTIG_FREE(pDecompBuffer);
    }
    //</snippet>

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    COMPLETION_DESTROY(&complete);
    PHYS_CONTIG_FREE(pDigestBuffer);
    dcChainFreeBufferList(&pBufferListSrc);
    dcChainFreeBufferList(&pBufferListDst);
    return status;
}

/*
 * This is the main entry point for the sample data dc chain code.
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more hash plus compression operations,
 * and
 * then tear down the session.
 */
CpaStatus dcChainSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaDcChainSessionSetupData chainSessionData[2] = {{0}, {0}};
    CpaDcSessionSetupData dcSessionData = {0};
    CpaCySymSessionSetupData cySessionData = {0};
    Cpa32U sess_size = 0;
    CpaDcStats dcStats = {0};
    CpaDcInstanceCapabilities cap = {0};

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     */
    sampleDcGetInstance(&dcInstHandle);
    if (dcInstHandle == NULL)
    {
        PRINT_ERR("Get instance failed\n");
        return CPA_STATUS_FAIL;
    }

    /* Query Capabilities */
    PRINT_DBG("cpaDcQueryCapabilities\n");
    //<snippet name="queryStart">
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Query capabilities failed\n");
        return status;
    }

    if (CPA_FALSE == CPA_BITMAP_BIT_TEST(cap.dcChainCapInfo,
                                         CPA_DC_CHAIN_HASH_THEN_COMPRESS))
    {
        PRINT_ERR(
            "Hash + compress chained operation is not supported on logical "
            "instance.\n");
        PRINT_ERR("Please ensure Chaining related settings are enabled in the "
                  "device configuration "
                  "file.\n");
        return CPA_STATUS_FAIL;
    }

    if (!cap.statelessDeflateCompression || !cap.checksumCRC32 ||
        !cap.checksumAdler32)
    {
        PRINT_ERR("Error: Unsupported functionality\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set the address translation function for the instance */
        status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Start static data compression component */
        PRINT_DBG("cpaDcStartInstance\n");
        status = cpaDcStartInstance(dcInstHandle, 0, NULL);
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependent.
         */
        sampleDcStartPolling(dcInstHandle);
        /*
         * We now populate the fields of the session operational data and create
         * the session.  Note that the size required to store a session is
         * implementation-dependent, so we query the API first to determine how
         * much memory to allocate, and then allocate that memory.
         */

        //<snippet name="initSession">
        /* Initialize compression session data */
        dcSessionData.compLevel = CPA_DC_L1;
        dcSessionData.compType = CPA_DC_DEFLATE;
        dcSessionData.huffType = CPA_DC_HT_STATIC;
        dcSessionData.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
        dcSessionData.sessDirection = CPA_DC_DIR_COMPRESS;
        dcSessionData.sessState = CPA_DC_STATELESS;
        dcSessionData.checksum = CPA_DC_CRC32;

        /* Initialize crypto session data */
        cySessionData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        /* Hash operation on the source data */
        cySessionData.symOperation = CPA_CY_SYM_OP_HASH;
        cySessionData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
        cySessionData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
        cySessionData.hashSetupData.digestResultLenInBytes =
            GET_HASH_DIGEST_LENGTH(cySessionData.hashSetupData.hashAlgorithm);
        /* Place the digest result in a buffer unrelated to srcBuffer */
        cySessionData.digestIsAppended = CPA_FALSE;
        /* Generate the digest */
        cySessionData.verifyDigest = CPA_FALSE;

        /* Initialize chaining session data - hash + compression
         * chain operation */
        chainSessionData[0].sessType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
        chainSessionData[0].pCySetupData = &cySessionData;
        chainSessionData[1].sessType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
        chainSessionData[1].pDcSetupData = &dcSessionData;

        /* Determine size of session context to allocate */
        PRINT_DBG("cpaDcChainGetSessionSize\n");
        status = cpaDcChainGetSessionSize(dcInstHandle,
                                          CPA_DC_CHAIN_HASH_THEN_COMPRESS,
                                          NUM_SESSIONS_TWO,
                                          chainSessionData,
                                          &sess_size);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session memory */
        status = PHYS_CONTIG_ALLOC(&sessionHdl, sess_size);
    }

    /* Initialize the chaining session */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaDcChainInitSession\n");
        status = cpaDcChainInitSession(dcInstHandle,
                                       sessionHdl,
                                       CPA_DC_CHAIN_HASH_THEN_COMPRESS,
                                       NUM_SESSIONS_TWO,
                                       chainSessionData,
                                       dcCallback);
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform chaining operation */
        status = dcChainingPerformOp(dcInstHandle, sessionHdl);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("dcChainingPerformOp failed\n");
        }
        /*
         * In a typical usage, the session might be used to compression
         * multiple buffers.  In this example however, we can now
         * tear down the session.
         */
        PRINT_DBG("cpaDcChainRemoveSession\n");
        //<snippet name="removeSession">
        status = cpaDcChainRemoveSession(dcInstHandle, sessionHdl);
        //</snippet>

        /* Maintain status of remove session only when status of all operations
         * before it are successful. */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * We can now query the statistics on the instance.
         *
         * Note that some implementations may also make the stats
         * available through other mechanisms, e.g. in the /proc
         * virtual filesystem.
         */
        status = cpaDcGetStats(dcInstHandle, &dcStats);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcGetStats failed, status = %d\n", status);
        }
        else
        {
            PRINT_DBG("Number of compression operations completed: %llu\n",
                      (unsigned long long)dcStats.numCompCompleted);
        }
    }

    /*
     * Free up memory, stop the instance, etc.
     */

    /* Stop the polling thread */
    sampleDcStopPolling();

    PRINT_DBG("cpaDcStopInstance\n");
    cpaDcStopInstance(dcInstHandle);

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionHdl);

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Sample code ran successfully\n");
    }
    else
    {
        PRINT_ERR("Sample code failed with status of %d\n", status);
    }

    return status;
}
