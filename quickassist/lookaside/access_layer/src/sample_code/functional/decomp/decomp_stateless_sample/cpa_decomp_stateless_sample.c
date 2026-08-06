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
 * This is sample code that demonstrates usage of the data decompression API,
 * and specifically using this API to stateless decompress a gzip file. It
 * will decompress the data using deflate with dynamic huffman trees.
 */

#include "cpa.h"
#include "cpa_dc.h"

#include "cpa_sample_utils.h"

extern int gDebugParam;

extern char *gFileNameComp;
extern char *gFileNameOut;

#define SAMPLE_MAX_BUFF                                                        \
    13286 /* 13KB - Sufficient for the decompressed data in this example */
#define TIMEOUT_MS 5000 /* 5 seconds */
#define GZIP_HEADER_SIZE 10 /* Standard gzip header size */
#define GZIP_FOOTER_SIZE 8 /* Standard gzip footer size (CRC32 + ISIZE) */
/*
 *****************************************************************************
 * Forward declaration
 *****************************************************************************
 */
CpaStatus dcStatelessDecompSample(void);

/*
 * Callback function
 *
 * This function is "called back" (invoked by the implementation of
 * the API) when the asynchronous operation has completed. The
 * context in which it is invoked depends on the implementation, but
 * as described in the API it should not sleep (since it may be called
 * in a context which does not permit sleeping, e.g. a Linux bottom
 * half).
 *
 * This function can perform whatever processing is appropriate to the
 * application. For example, it may free memory, continue processing
 * of a packet, etc. In this example, the function only sets the
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
//<snippet>

/*
 * This function performs a stateless decompression operation.
 */
static CpaStatus decompPerformOp(CpaInstanceHandle dcInstHandle,
                                 CpaDcSessionHandle sessionHdl)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMetaSrc = NULL;
    Cpa8U *pBufferMetaDst = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferListSrc = NULL;
    CpaBufferList *pBufferListDst = NULL;
    CpaDcOpData opData = {};
    CpaFlatBuffer *pFlatBuffer = NULL;
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pDstBuffer = NULL;
    char filePath[MAX_CORPUS_FILE_PATH_LEN];
    FILE *dstFile = NULL;
    Cpa32U srcBufferSize = 0;
    Cpa32U totalBytesProduced = 0;
    file_data_t inputData = { 0 };
    CpaFlatBuffer inputBuffer = { 0 };
    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    CpaDcRqResults dcResults;
    struct COMPLETION_STRUCT complete;
    INIT_OPDATA(&opData, CPA_DC_FLUSH_FINAL);
    /*
     * Initialize the completion variable which is used by the callback
     * function */
    COMPLETION_INIT(&complete);

    /* Get input file path */
    status = sample_getPath(filePath, gFileNameComp);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Cannot access file %s\n", gFileNameComp);
        return CPA_STATUS_FAIL;
    }

    PRINT_DBG("Processing input file %s\n", gFileNameComp);

    /* Get input file data */
    inputData.bufferSize = &inputBuffer.dataLenInBytes;
    inputData.pSrcData = &inputBuffer.pData;
    status = sample_getFile(filePath, &inputData);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sample_getFile failed for input\n");
        return status;
    }

    srcBufferSize = inputBuffer.dataLenInBytes;

    /* Open decompressed output file */
    dstFile = fopen(gFileNameOut, "wb");
    if (NULL == dstFile)
    {
        PRINT_ERR("Cannot open file %s\n", gFileNameOut);
        sample_freeFile(&inputData);
        return CPA_STATUS_FAIL;
    }

    PRINT_DBG("Compressed file size: %u bytes\n", srcBufferSize);

    /*
     * Different implementations of the API require different
     * amounts of space to store meta-data associated with buffer
     * lists. We query the API to find out how much space the current
     * implementation needs.
     */
    //<snippet name="memAlloc">
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
        status = PHYS_CONTIG_ALLOC(&pSrcBuffer, srcBufferSize);
    }

    /* Allocate destination buffer - larger for decompression */
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
        /* Allocate larger buffer for decompressed data */
        status = PHYS_CONTIG_ALLOC(&pDstBuffer, SAMPLE_MAX_BUFF);
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pSrcBuffer, inputBuffer.pData, srcBufferSize);

        /* Build source bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListSrc + 1);

        pBufferListSrc->pBuffers = pFlatBuffer;
        pBufferListSrc->numBuffers = 1;
        pBufferListSrc->pPrivateMetaData = pBufferMetaSrc;

        /* Skip gzip header (10 bytes) and footer (8 bytes) */
        pFlatBuffer->dataLenInBytes =
            srcBufferSize - GZIP_HEADER_SIZE - GZIP_FOOTER_SIZE;
        pFlatBuffer->pData = pSrcBuffer + GZIP_HEADER_SIZE;

        /* Build destination bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListDst + 1);

        pBufferListDst->pBuffers = pFlatBuffer;
        pBufferListDst->numBuffers = 1;
        pBufferListDst->pPrivateMetaData = pBufferMetaDst;

        pFlatBuffer->dataLenInBytes = SAMPLE_MAX_BUFF;
        pFlatBuffer->pData = pDstBuffer;

        /* Perform stateless decompression */
        PRINT_DBG("cpaDcDecompressData2\n");

        //<snippet name="perfOp">

        status = cpaDcDecompressData2(
            dcInstHandle,
            sessionHdl,
            pBufferListSrc,     /* source buffer list */
            pBufferListDst,     /* destination buffer list */
            &opData,            /* Operational data */
            &dcResults,         /* results structure */
            (void *)&complete); /* data sent as is to the callback function*/
                                //</snippet>

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcDecompressData2 failed. (status = %d)\n", status);
        }

        /*
         * We now wait until the completion of the operation. This uses a macro
         * which can be defined differently for different OSes.
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
            {
                PRINT_ERR("timeout or interruption in cpaDcDecompressData2\n");
            }
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            /*
             * Check the results
             */
            if (dcResults.status != CPA_DC_OK)
            {
                PRINT_ERR("Decompression result status not OK (status = %d)\n",
                          dcResults.status);
                status = CPA_STATUS_FAIL;
            }
            else
            {
                PRINT_DBG("Data consumed: %u\n", dcResults.consumed);
                PRINT_DBG("Data produced: %u\n", dcResults.produced);
                PRINT_DBG("CRC32 checksum: 0x%x\n", dcResults.checksum);

                /* Write decompressed data to output file */
                totalBytesProduced =
                    fwrite(pDstBuffer, 1, dcResults.produced, dstFile);
                if (totalBytesProduced != dcResults.produced)
                {
                    PRINT_ERR("Error writing decompressed data\n");
                    status = CPA_STATUS_FAIL;
                }
                else
                {
                    PRINT_DBG(
                        "Successfully decompressed %u bytes to %u bytes\n",
                        dcResults.consumed,
                        dcResults.produced);
                }
            }
        }
    }

    /* Close files */
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
    COMPLETION_DESTROY(&complete);
    sample_freeFile(&inputData);

    return status;
}

/*
 * This is the main entry point for the sample stateless decompression code.
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more stateless decompression operation,
 * and then tear down the session.
 */
CpaStatus dcStatelessDecompSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcInstanceCapabilities cap = { 0 };
    Cpa32U sess_size = 0;
    Cpa32U ctx_size = 0;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionSetupData sd = { 0 };
    CpaDcStats dcStats = { 0 };

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data decompression service.
     */
    sampleDecompGetInstance(&dcInstHandle);

    if (dcInstHandle == NULL)
    {
        PRINT_ERR("No decompression instance was found, skipping the test\n");
        return CPA_STATUS_SUCCESS;
    }

    /* Query Capabilities */
    PRINT_DBG("cpaDcQueryCapabilities\n");
    //<snippet name="queryStart">
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    if (!cap.statelessDeflateDecompression || !cap.checksumCRC32)
    {
        PRINT_DBG("Error: %s is unsupported\n",
                  !cap.statelessDeflateDecompression
                      ? "Stateless deflate decompression"
                      : "Checksum CRC32");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Start Data Decompression component */
        PRINT_DBG("cpaDcStartInstance\n");
        status = cpaDcStartInstance(dcInstHandle, 0, NULL);
    } //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependent.
         */
        sampleDcStartPolling(dcInstHandle);

        /*
         * We now populate the fields of the session operational data and create
         * the session. Note that the size required to store a session is
         * implementation-dependent, so we query the API first to determine how
         * much memory to allocate, and then allocate that memory.
         */
        //<snippet name="initSession">
        sd.compLevel = CPA_DC_L1;
        sd.compType = CPA_DC_DEFLATE;
        sd.huffType = CPA_DC_HT_FULL_DYNAMIC;
        sd.sessDirection = CPA_DC_DIR_DECOMPRESS;
        sd.sessState = CPA_DC_STATELESS;
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

    /* Initialize the stateless session */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaDcInitSession\n");
        status = cpaDcInitSession(
            dcInstHandle,
            sessionHdl, /* session memory */
            &sd,        /* session setup data */
            NULL, /* pContexBuffer not required for stateless operations */
            dcCallback); /* callback function */
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform Decompression operation */
        status = decompPerformOp(dcInstHandle, sessionHdl);

        /*
         * In a typical usage, the session might be used to decompress
         * multiple buffers. In this example however, we can now
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

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionHdl);

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
