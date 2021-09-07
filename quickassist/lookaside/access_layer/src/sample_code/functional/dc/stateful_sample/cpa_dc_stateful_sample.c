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
 * This is sample code that demonstrates usage of the data compression API,
 * and specifically using this API to statefully compress a file. It
 * will compress the data using static deflate. This code only runs in user
 * space
 */

#include "cpa.h"
#include "cpa_dc.h"

#include "cpa_sample_utils.h"

extern int gDebugParam;

extern char *gFileNameIn;
extern char *gFileNameComp;
extern char *gFileNameOut;

#define SAMPLE_BUFF_SIZE 4096 /* Data will be read from file 4K at and time */
#define TIMEOUT_MS 5000       /* 5 seconds */

/*
 *****************************************************************************
 * Forward declaration
 *****************************************************************************
 */
CpaStatus dcStatefulSample(void);

/*
 * This function performs a cipher operation.
 */
static CpaStatus compPerformOp(CpaInstanceHandle dcInstHandle,
                               CpaDcSessionHandle sessionHdl,
                               CpaDcHuffType huffType)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMetaSrc = NULL;
    Cpa8U *pBufferMetaDst = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferListSrc = NULL;
    CpaBufferList *pBufferListDst = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pDstBuffer = NULL;
    CpaDcOpData opData = {};
    FILE *srcFile = NULL;
    FILE *dstFile = NULL;
    CpaDcRqResults dcResults;
    Cpa32U hdr_sz = 0;
    Cpa32U dstBufferSize = SAMPLE_BUFF_SIZE;

    INIT_OPDATA(&opData, CPA_DC_FLUSH_NONE);

    /* Open files */
    srcFile = fopen(gFileNameIn, "r");
    if (NULL == srcFile)
    {
        PRINT_ERR("Cannot open file %s\n", gFileNameIn);
        return CPA_STATUS_FAIL;
    }
    else
    {
        PRINT_DBG("Processing file %s\n", gFileNameIn);
    }

    dstFile = fopen(gFileNameComp, "w");
    if (NULL == dstFile)
    {
        PRINT_ERR("Cannot open file %s\n", gFileNameComp);
        fclose(srcFile);
        return CPA_STATUS_FAIL;
    }
    else
    {
        PRINT_DBG("Writing to file %s\n", gFileNameComp);
    }

    PRINT_DBG("cpaDcBufferListGetMetaSize\n");

    /* Destination buffer size is hardcoded to SAMPLE_BUFF_SIZE for a
     * Deflate compression operation with DC_API_VERSION < 2.5.
     * cpaDcDeflateCompressBound API is used to get maximum output buffer size
     * for a Deflate compression operation with DC_API_VERSION >= 2.5 */
#if DC_API_VERSION_AT_LEAST(2, 5)
    status = cpaDcDeflateCompressBound(
        dcInstHandle, huffType, SAMPLE_BUFF_SIZE, &dstBufferSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcDeflateCompressBound API failed. (status = %d)\n",
                  status);
        fclose(srcFile);
        fclose(dstFile);
        return CPA_STATUS_FAIL;
    }
#endif
    /*
     * Different implementations of the API require different
     * amounts of space to store meta-data associated with buffer
     * lists.  We query the API to find out how much space the current
     * implementation needs, and then allocate space for the buffer
     * meta data, the buffer list, and for the buffer itself.
     */
    //<snippet name="alloc">
    numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));

    status =
        cpaDcBufferListGetMetaSize(dcInstHandle, numBuffers, &bufferMetaSize);

    /* Allocate source buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMetaSrc, bufferMetaSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferListSrc, bufferListMemSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pSrcBuffer, SAMPLE_BUFF_SIZE);
    }

    /* Allocate destination buffer the same size as source buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMetaDst, bufferMetaSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferListDst, bufferListMemSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pDstBuffer, dstBufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Build source bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListSrc + 1);

        pBufferListSrc->pBuffers = pFlatBuffer;
        pBufferListSrc->numBuffers = 1;
        pBufferListSrc->pPrivateMetaData = pBufferMetaSrc;

        pFlatBuffer->dataLenInBytes = SAMPLE_BUFF_SIZE;
        pFlatBuffer->pData = pSrcBuffer;

        /* Build destination bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListDst + 1);

        pBufferListDst->pBuffers = pFlatBuffer;
        pBufferListDst->numBuffers = 1;
        pBufferListDst->pPrivateMetaData = pBufferMetaDst;

        pFlatBuffer->dataLenInBytes = dstBufferSize;
        pFlatBuffer->pData = pDstBuffer;
        //</snippet>

        //<snippet name="genHdr">
        /* Write RFC1952 gzip header to destination buffer */
        status = cpaDcGenerateHeader(sessionHdl, pFlatBuffer, &hdr_sz);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* write out header */
        fwrite(pFlatBuffer->pData, 1, hdr_sz, dstFile);
        //</snippet>

        //<snippet name="perfOp">
        pBufferListSrc->pBuffers->dataLenInBytes = 0;
        while ((!feof(srcFile)) && (CPA_STATUS_SUCCESS == status))
        {
            /* read from file into src buffer */
            pBufferListSrc->pBuffers->pData = pSrcBuffer;
            pBufferListSrc->pBuffers->dataLenInBytes += fread(
                pSrcBuffer + pBufferListSrc->pBuffers->dataLenInBytes,
                1,
                SAMPLE_BUFF_SIZE - pBufferListSrc->pBuffers->dataLenInBytes,
                srcFile);
            if (pBufferListSrc->pBuffers->dataLenInBytes < SAMPLE_BUFF_SIZE)
            {
                opData.flushFlag = CPA_DC_FLUSH_FINAL;
            }
            else
            {
                opData.flushFlag = CPA_DC_FLUSH_SYNC;
            }
            do
            {

                PRINT_DBG("cpaDcCompressData2\n");
                status = cpaDcCompressData2(
                    dcInstHandle,
                    sessionHdl,
                    pBufferListSrc, /* source buffer list */
                    pBufferListDst, /* destination buffer list */
                    &opData,
                    &dcResults, /* results structure */
                    NULL);

                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("cpaDcCompressData2 failed. (status = %d)\n",
                              status);
                    break;
                }

                /*
                 * We now check the results
                 */
                if ((dcResults.status != CPA_DC_OK) &&
                    (dcResults.status != CPA_DC_OVERFLOW))
                {
                    PRINT_ERR("Results status not as expected (status = %d)\n",
                              dcResults.status);
                    status = CPA_STATUS_FAIL;
                    break;
                }

                fwrite(pDstBuffer, 1, dcResults.produced, dstFile);

                if (dcResults.consumed <=
                    pBufferListSrc->pBuffers->dataLenInBytes)
                {
                    pBufferListSrc->pBuffers->dataLenInBytes -=
                        dcResults.consumed;
                    pBufferListSrc->pBuffers->pData += dcResults.consumed;
                }
                else
                {
                    pBufferListSrc->pBuffers->dataLenInBytes = 0;
                }

                if (dcResults.consumed == 0 &&
                    pBufferListSrc->pBuffers->dataLenInBytes > 0)
                {
                    memcpy(pSrcBuffer,
                           pBufferListSrc->pBuffers->pData,
                           pBufferListSrc->pBuffers->dataLenInBytes);
                    break;
                }
            } while (pBufferListSrc->pBuffers->dataLenInBytes != 0 ||
                     dcResults.status == CPA_DC_OVERFLOW);
        }
        //</snippet>
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        //<snippet name="genFtr">
        dcResults.produced = 0;
        /* Write RFC1952 gzip footer to destination buffer */
        status = cpaDcGenerateFooter(sessionHdl, pFlatBuffer, &dcResults);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* write out footer */
        fwrite(pFlatBuffer->pData, 1, dcResults.produced, dstFile);
    }
    //</snippet>

    /*
     * We now ensure we can decompress to the original buffer.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Close files */
        fclose(srcFile);
        srcFile = NULL;
        fclose(dstFile);
        dstFile = NULL;
        /* Open files */
        srcFile = fopen(gFileNameComp, "r");
        if (NULL == srcFile)
        {
            PRINT_ERR("Cannot open file %s\n", gFileNameComp);
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {

        PRINT_DBG("Processing file %s\n", gFileNameComp);

        dstFile = fopen(gFileNameOut, "w");
        if (NULL == dstFile)
        {
            PRINT_ERR("Cannot open file %s\n", gFileNameOut);
            status = CPA_STATUS_FAIL;
        }
        else
        {
            /* Read in gzip header, 10 bytes */
            if (10 != fread(pSrcBuffer, 1, 10, srcFile))
            {
                PRINT_ERR("Error reading gzip header\n");
                status = CPA_STATUS_FAIL;
            }
            else
            {
                /* Validate hdr if required */
            }

            //<snippet name="perfOpDecomp">
            pBufferListSrc->pBuffers->dataLenInBytes = 0;
            while ((!feof(srcFile)) && (CPA_STATUS_SUCCESS == status))
            {
                /* read from file into src buffer */
                pBufferListSrc->pBuffers->pData = pSrcBuffer;
                pBufferListSrc->pBuffers->dataLenInBytes += fread(
                    pSrcBuffer + pBufferListSrc->pBuffers->dataLenInBytes,
                    1,
                    SAMPLE_BUFF_SIZE - pBufferListSrc->pBuffers->dataLenInBytes,
                    srcFile);

                if (pBufferListSrc->pBuffers->dataLenInBytes < SAMPLE_BUFF_SIZE)
                {
                    opData.flushFlag = CPA_DC_FLUSH_FINAL;
                }
                else
                {
                    opData.flushFlag = CPA_DC_FLUSH_SYNC;
                }

                do
                {
                    PRINT_DBG("cpaDcDecompressData2\n");
                    status = cpaDcDecompressData2(
                        dcInstHandle,
                        sessionHdl,
                        pBufferListSrc, /* source buffer list */
                        pBufferListDst, /* destination buffer list */
                        &opData,
                        &dcResults, /* results structure */
                        NULL);
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT_ERR(
                            "cpaDcDecompressData2 failed. (status = %d)\n",
                            status);
                        break;
                    }

                    /*
                     * We now check the results - in decompress direction the
                     * output
                     * buffer may overflow
                     */
                    if ((dcResults.status != CPA_DC_OK) &&
                        (dcResults.status != CPA_DC_OVERFLOW))
                    {
                        PRINT_ERR(
                            "Results status not as expected (status = %d)\n",
                            dcResults.status);
                        status = CPA_STATUS_FAIL;
                        break;
                    }

                    fwrite(pDstBuffer, 1, dcResults.produced, dstFile);

                    /* The gzip file generated by Deflate algorithm has an
                     * 8-byte
                     * footer, containing a CRC-32 checksum and the length of
                     * the
                     * original uncompressed data. The 'endOfLastBlock' flag
                     * tells
                     * if we have processed the last data block. Break the loop
                     * here, otherwise it will keep on reading gzip file.
                     */
                    if (CPA_TRUE == dcResults.endOfLastBlock)
                    {
                        break;
                    }

                    if (dcResults.consumed <=
                        pBufferListSrc->pBuffers->dataLenInBytes)
                    {
                        pBufferListSrc->pBuffers->dataLenInBytes -=
                            dcResults.consumed;
                        pBufferListSrc->pBuffers->pData += dcResults.consumed;
                    }
                    else
                    {
                        pBufferListSrc->pBuffers->dataLenInBytes = 0;
                    }

                    if (dcResults.consumed == 0 &&
                        pBufferListSrc->pBuffers->dataLenInBytes > 0)
                    {
                        memcpy(pSrcBuffer,
                               pBufferListSrc->pBuffers->pData,
                               pBufferListSrc->pBuffers->dataLenInBytes);
                        break;
                    }
                } while (pBufferListSrc->pBuffers->dataLenInBytes != 0 ||
                         dcResults.status == CPA_DC_OVERFLOW);
            }
            fclose(dstFile);
            dstFile = NULL;
        }

        //</snippet>
    }
    if (NULL != srcFile)
    {
        fclose(srcFile);
    }
    if (NULL != dstFile)
    {
        fclose(dstFile);
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    PHYS_CONTIG_FREE(pSrcBuffer);
    OS_FREE(pBufferListSrc);
    PHYS_CONTIG_FREE(pBufferMetaSrc);
    PHYS_CONTIG_FREE(pDstBuffer);
    OS_FREE(pBufferListDst);
    PHYS_CONTIG_FREE(pBufferMetaDst);

    return status;
}

/*
 * This is the main entry point for the sample data compression code.
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more stateful compression operations,
 * and then tear down the session.
 */
CpaStatus dcStatefulSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcInstanceCapabilities cap = {0};
    CpaBufferList *pBufferCtx = NULL;
    Cpa8U *pBufferMeta = NULL;
    Cpa8U *pCtxBuf = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    Cpa32U buffMetaSize = 0;
    Cpa32U bufferListMemSize = sizeof(CpaBufferList) + sizeof(CpaFlatBuffer);
    Cpa32U sess_size = 0;
    Cpa32U ctx_size = 0;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionSetupData sd = {0};
    CpaDcStats dcStats = {0};

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     */
    sampleDcGetInstance(&dcInstHandle);
    if (dcInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    /* Query Capabilities */
    PRINT_DBG("cpaDcQueryCapabilities\n");
    //<snippet name="queryStart">
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    if (!cap.statefulDeflateCompression || !cap.statefulDeflateDecompression ||
        !cap.checksumCRC32)
    {
        PRINT_ERR("Error: Unsupported functionality\n");
        return CPA_STATUS_UNSUPPORTED;
    }

    /*
     * Set the address translation function for the instance
     */
    status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);
    if (CPA_STATUS_SUCCESS == status)
    {

        /* Start DataCompression component
         * In this example we are performing static compression so
         * an intermediate buffer is not required */
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
         * We now populate the fields of the session operational data and
         * create the session.  Note that the size required to store a
         * session is implementation-dependent, so we query the API first to
         * determine how much memory to allocate, and then allocate that memory.
         */
        //<snippet name="initSession">
        sd.compLevel = CPA_DC_L4;
        sd.compType = CPA_DC_DEFLATE;
        sd.huffType = CPA_DC_HT_STATIC;
        sd.sessDirection = CPA_DC_DIR_COMBINED;
        sd.sessState = CPA_DC_STATEFUL;
#if (CPA_DC_API_VERSION_NUM_MAJOR == 1 && CPA_DC_API_VERSION_NUM_MINOR < 6)
        sd.deflateWindowSize = 7;
#endif
        sd.checksum = CPA_DC_CRC32;

        /* Determine size of session context to allocate */
        PRINT_DBG("cpaDcGetSessionSize\n");
        status = cpaDcGetSessionSize(dcInstHandle, &sd, &sess_size, &ctx_size);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session memory */
        status = PHYS_CONTIG_ALLOC(&sessionHdl, sess_size);
    }

    if ((CPA_STATUS_SUCCESS == status) && (ctx_size != 0))
    {
        /* Allocate context bufferlist */
        status = cpaDcBufferListGetMetaSize(dcInstHandle, 1, &buffMetaSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pBufferMeta, buffMetaSize);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = OS_MALLOC(&pBufferCtx, bufferListMemSize);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pCtxBuf, ctx_size);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            pFlatBuffer = (CpaFlatBuffer *)(pBufferCtx + 1);

            pBufferCtx->pBuffers = pFlatBuffer;
            pBufferCtx->numBuffers = 1;
            pBufferCtx->pPrivateMetaData = pBufferMeta;

            pFlatBuffer->dataLenInBytes = ctx_size;
            pFlatBuffer->pData = pCtxBuf;
        }
    }
    /* Initialize the Stateful session */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaDcInitSession\n");
        status =
            cpaDcInitSession(dcInstHandle,
                             sessionHdl, /* session memory */
                             &sd,        /* session setup data */
                             pBufferCtx, /* context buffer */
                             NULL); /* callback function NULL for sync mode */
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform Compression operation */
        status = compPerformOp(dcInstHandle, sessionHdl, sd.huffType);

        /*
         * In a typical usage, the session might be used to compression
         * multiple buffers.  In this example however, we can now
         * tear down the session.
         */
        PRINT_DBG("cpaDcRemoveSession\n");
        //<snippet name="removeSession">
        sessionStatus = cpaDcRemoveSession(dcInstHandle, sessionHdl);
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
            PRINT_DBG("Number of decompression operations completed: %llu\n",
                      (unsigned long long)dcStats.numDecompCompleted);
        }
    }

    /*
     * Free up memory, stop the instance, etc.
     */

    /* Stop the polling thread */
    sampleDcStopPolling();

    PRINT_DBG("cpaDcStopInstance\n");
    cpaDcStopInstance(dcInstHandle);

    /* Free session Memory */
    PHYS_CONTIG_FREE(sessionHdl);

    /* Free context buffer */
    PHYS_CONTIG_FREE(pBufferMeta);
    OS_FREE(pBufferCtx);
    PHYS_CONTIG_FREE(pCtxBuf);

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
