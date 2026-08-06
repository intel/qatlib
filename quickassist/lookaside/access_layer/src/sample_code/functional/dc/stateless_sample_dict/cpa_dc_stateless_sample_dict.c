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
 * This is sample code that demonstrates usage of the data compression API,
 * and specifically using this API to statelessly compress an input buffer. It
 * will compress the data using dictionary compression operations with an
 * algorithm.
 */

#include "cpa_sample_utils.h"

extern int gDebugParam;
extern char *gInputFileName;
extern char *gDictFileName;

#define TIMEOUT_MS 5000 /* 5 seconds */
#define SINGLE_INTER_BUFFLIST 1

/*
 *****************************************************************************
 * Forward declaration
 *****************************************************************************
 */
CpaStatus dcStatelessSampleDict();

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
        /* Indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}
//</snippet>

/*
 * This function performs a compression and decompress operation.
 */
static CpaStatus compPerformOp(CpaInstanceHandle dcInstHandle,
                               CpaDcSessionHandle sessionHdl)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pBufferMetaSrc = NULL;
    Cpa8U *pBufferMetaDst = NULL;
    Cpa8U *pBufferMetaDst2 = NULL;
    Cpa32U bufferSrcMetaSize = 0;
    Cpa32U bufferDstMetaSize = 0;
    Cpa32U bufferSrc2MetaSize = 0;
    CpaBufferList *pBufferListSrc = NULL;
    CpaBufferList *pBufferListDst = NULL;
    CpaBufferList *pBufferListDst2 = NULL;
    CpaBufferList *pBufferListDict = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaDcOpData opDataComp = {};
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U numDictBuffers = 1; /* only using 1 dict buffer in this case */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa32U bufferSize = 0;
    Cpa32U dictBufferSize = 0;
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pDstBuffer = NULL;
    Cpa8U *pDst2Buffer = NULL;
    Cpa8U *pDictBuffer = NULL;
    CpaDcRqResults dcResultsComp = { 0 };
    CpaDcRqResults dcResultsDecomp = { 0 };
    file_data_t dictData = { 0 };
    file_data_t inputData = { 0 };
    CpaFlatBuffer inputBuffer = { 0 };
    CpaDcDictionaryData dictionaryOpData = { 0 };
    CpaFlatBuffer dictionaryBuffer = { 0 };
    CpaCrcData compCrcData = { 0 };
    char filePath[MAX_CORPUS_FILE_PATH_LEN];

    struct COMPLETION_STRUCT complete;
    /* Initialize opData */
    opDataComp.compressAndVerify = CPA_TRUE;
    opDataComp.integrityCrcCheck = CPA_FALSE;
    opDataComp.verifyHwIntegrityCrcs = CPA_FALSE;
    opDataComp.pCrcData = &compCrcData;
    /* CPA_DC_FLUSH_FINAL should be the only possible flush flag to be used */
    opDataComp.flushFlag = CPA_DC_FLUSH_FINAL;

    /* Get dictionary file path */
    status = sample_getPath(filePath, gDictFileName);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Cannot access file %s\n", gDictFileName);
        return CPA_STATUS_FAIL;
    }

    PRINT_DBG("Processing dictionary file %s\n", gDictFileName);

    /* Get dictionary file data */
    dictData.bufferSize = &dictionaryBuffer.dataLenInBytes;
    dictData.pSrcData = &dictionaryBuffer.pData;
    status = sample_getFile(filePath, &dictData);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sample_getFile failed for dictionary\n");
        return status;
    }

    dictBufferSize = dictionaryBuffer.dataLenInBytes;

    /* Get input file path */
    status = sample_getPath(filePath, gInputFileName);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Cannot access file %s\n", gInputFileName);
        sample_freeFile(&dictData);
        return CPA_STATUS_FAIL;
    }

    PRINT_DBG("Processing input file %s\n", gInputFileName);

    /* Get input file data */
    inputData.bufferSize = &inputBuffer.dataLenInBytes;
    inputData.pSrcData = &inputBuffer.pData;
    status = sample_getFile(filePath, &inputData);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sample_getFile failed for input\n");
        sample_freeFile(&dictData);
        return status;
    }

    bufferSize = inputBuffer.dataLenInBytes;

    PRINT_DBG("cpaDcGetMetaSizeForSrcBuffWithDict\n");

    /* Below function is used to obtain the size (in bytes) required to
     * allocate a buffer descriptor for the pPrivateMetaData member in the
     * CpaBufferList structure of the source buffer list used in the API's
     * cpaDcCompressDataWithDict() and cpaDcDecompressDataWithDict().
     * In contrast the size in bytes to allocate the descriptor of the
     * destination buffer list must not use this API, and needs to be
     * determined using the API cpaDcBufferListGetMetaSize */
    //<snippet name="memAlloc">
    status = cpaDcGetMetaSizeForSrcBuffWithDict(
        dcInstHandle, numDictBuffers, numBuffers, &bufferSrcMetaSize);

    /* Allocate dictionary buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferListDict, bufferListMemSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMetaSrc, bufferSrcMetaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pDictBuffer,
                                   dictBufferSize); /* save dict data */
    }
    pBufferListDict->pPrivateMetaData = pBufferMetaSrc;


    /* Allocate source buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMetaSrc, bufferSrcMetaSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferListSrc, bufferListMemSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            PHYS_CONTIG_ALLOC(&pSrcBuffer, bufferSize); /* save input data */
    }

    /* Allocate destination buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaDcBufferListGetMetaSize(dcInstHandle, numBuffers, &bufferDstMetaSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pBufferMetaDst, bufferDstMetaSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferListDst, bufferListMemSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pDstBuffer, bufferSize);
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pDictBuffer, dictionaryBuffer.pData, dictBufferSize);
        memcpy(pSrcBuffer, inputBuffer.pData, bufferSize);

        /* Build dict bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListDict + 1);

        pBufferListDict->pBuffers = pFlatBuffer;
        pBufferListDict->numBuffers = numDictBuffers;

        pFlatBuffer->dataLenInBytes = dictBufferSize;
        pFlatBuffer->pData = pDictBuffer;

        /* Build source bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListSrc + 1);

        pBufferListSrc->pBuffers = pFlatBuffer;
        pBufferListSrc->numBuffers = numBuffers;
        pBufferListSrc->pPrivateMetaData = pBufferMetaSrc;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pSrcBuffer;

        /* Build destination bufferList */
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListDst + 1);

        pBufferListDst->pBuffers = pFlatBuffer;
        pBufferListDst->numBuffers = numBuffers;
        pBufferListDst->pPrivateMetaData = pBufferMetaDst;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pDstBuffer;

        /* Initialize dictionary data */
        dictionaryOpData.pDictionaryBuff = pBufferListDict;
        dictionaryOpData.dictionaryType = CPA_DC_UNCOMPRESSED_DICT;
        /*
         * Now, we initialize the completion variable which is used by the
         * callback function to indicate that the operation is complete.
         * We then perform the operation.
         */
        PRINT_DBG("Calling cpaDcCompressDataWithDict\n");

        //<snippet name="perfOp">
        COMPLETION_INIT(&complete); /* add a lock using semophore */

        /* Execute compression operation with dictionary */
        status = cpaDcCompressDataWithDict(
            dcInstHandle,
            sessionHdl,
            pBufferListSrc,     /* source buffer list */
            pBufferListDst,     /* destination buffer list */
            &dictionaryOpData,  /* dictionary data */
            &opDataComp,        /* operational data */
            &dcResultsComp,     /* results structure */
            (void *)&complete); /* data sent as is to the callback function*/
        //</snippet>
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcCompressDataWithDict failed. (status = %d)\n",
                      status);
        }

        /*
         * We now wait until the completion of the operation. This uses a macro
         * which can be defined differently for different OSes.
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
            {
                PRINT_ERR(
                    "Timeout or interruption in cpaDcCompressDataWithDict\n");
                status = CPA_STATUS_FAIL;
            }
        }

        /*
         * We now check the results
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (dcResultsComp.status != CPA_DC_OK)
            {
                PRINT_ERR("Results status not as expected (status = %d)\n",
                          dcResultsComp.status);
                status = CPA_STATUS_FAIL;
            }
            else
            {
                PRINT_DBG("Data consumed %d\n", dcResultsComp.consumed);
                PRINT_DBG("Data produced %d\n", dcResultsComp.produced);
                PRINT_DBG("CRC32 checksum 0x%x\n", dcResultsComp.checksum);
            }
        }
    }
    /*
     * We now ensure we can decompress to the original data.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Destination is now the source buffer - update the length with amount
         * of compressed data added to the buffer */
        pBufferListDst->pBuffers->dataLenInBytes = dcResultsComp.produced;

        PHYS_CONTIG_FREE(pBufferMetaDst);

        PRINT_DBG("cpaDcGetMetaSizeForSrcBuffWithDict\n");

        /* Below function is used to obtain the size (in bytes) required to
         * allocate a buffer descriptor for the pPrivateMetaData member in
         * the CpaBufferList structure of the source buffer list used in the
         * API's cpaDcCompressDataWithDict() and cpaDcDecompressDataWithDict().
         * In contrast the size in bytes to allocate the descriptor of the
         * destination buffer list must not use this API, and needs to be
         * determined using the API cpaDcBufferListGetMetaSize */
        status = cpaDcGetMetaSizeForSrcBuffWithDict(
            dcInstHandle, numDictBuffers, numBuffers, &bufferSrc2MetaSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pBufferMetaDst, bufferSrc2MetaSize);
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pBufferMetaDst2, bufferDstMetaSize);
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = OS_MALLOC(&pBufferListDst2, bufferListMemSize);
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pDst2Buffer, bufferSize);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Build destination 2 bufferList */
            pFlatBuffer = (CpaFlatBuffer *)(pBufferListDst2 + 1);

            pBufferListDst2->pBuffers = pFlatBuffer;
            pBufferListDst2->numBuffers = numBuffers;
            pBufferListDst2->pPrivateMetaData = pBufferMetaDst2;

            pFlatBuffer->dataLenInBytes = bufferSize;
            pFlatBuffer->pData = pDst2Buffer;

            PRINT_DBG("Calling cpaDcDecompressDataWithDict\n");

            /* Execute decompression operation with dictionary */
            //<snippet name="perfOpDecomp">
            status = cpaDcDecompressDataWithDict(
                dcInstHandle,
                sessionHdl,
                pBufferListDst,    /* source buffer list */
                pBufferListDst2,   /* destination buffer list */
                &dictionaryOpData, /* dictionary data */
                &opDataComp,       /* operational data */
                &dcResultsDecomp,  /* results structure */
                (void
                     *)&complete); /* data sent as is to the callback function*/
            //</snippet>
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaDcDeCompressDataWithDict failed. (status = %d)\n",
                          status);
            }

            /*
             * We now wait until the completion of the operation. This uses a
             * macro which can be defined differently for different OSes.
             */
            if (CPA_STATUS_SUCCESS == status)
            {
                if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
                {
                    PRINT_ERR("Timeout or interruption in "
                              "cpaDcDeCompressDataWithDict\n");
                    status = CPA_STATUS_FAIL;
                }
            }

            /*
             * We now check the results
             */
            if (CPA_STATUS_SUCCESS == status)
            {
                if (dcResultsDecomp.status != CPA_DC_OK)
                {
                    PRINT_ERR(
                        "Results status not as expected decomp (status = %d)\n",
                        dcResultsDecomp.status);
                    status = CPA_STATUS_FAIL;
                }
                else
                {
                    PRINT_DBG("Data consumed %d\n", dcResultsDecomp.consumed);
                    PRINT_DBG("Data produced %d\n", dcResultsDecomp.produced);
                    PRINT_DBG("CRC32 checksum 0x%x\n",
                              dcResultsDecomp.checksum);
                }

                /* Compare with original source buffer */
                if (0 == memcmp(pDst2Buffer, pSrcBuffer, bufferSize))
                {
                    PRINT_DBG("Uncompressed data matches with the input plain "
                              "text\n");
                }
                else
                {
                    PRINT_ERR("Output does not match expected output\n");
                    status = CPA_STATUS_FAIL;
                }
            }
        }
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures will not be needed anymore. Free the
     * memory.
     */
    PHYS_CONTIG_FREE(pDictBuffer);
    OS_FREE(pBufferListDict);
    PHYS_CONTIG_FREE(pSrcBuffer);
    OS_FREE(pBufferListSrc);
    PHYS_CONTIG_FREE(pBufferMetaSrc);
    PHYS_CONTIG_FREE(pDstBuffer);
    OS_FREE(pBufferListDst);
    PHYS_CONTIG_FREE(pBufferMetaDst);
    PHYS_CONTIG_FREE(pDst2Buffer);
    OS_FREE(pBufferListDst2);
    PHYS_CONTIG_FREE(pBufferMetaDst2);

    COMPLETION_DESTROY(&complete);
    sample_freeFile(&dictData);
    sample_freeFile(&inputData);
    return status;
}

/*
 * This is the main entry point for the sample data compression code.
 * It demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more stateless dictionary
 * compression operations with an algorithm and then tear down the session.
 */
CpaStatus dcStatelessSampleDict()
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus intStatus = CPA_STATUS_SUCCESS;
    Cpa32U sess_size = 0;
    Cpa32U ctx_size = 0;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionSetupData sd = { 0 };
    CpaDcStats dcStats = { 0 };
    CpaDcCapabilityReq capReq = { 0 };
    CpaDcCapabilityResp capResp = { 0 };

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     */
    sampleDcGetInstance(&dcInstHandle);
    if (dcInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    /* Test algorithm dictionary capabilities as not all the
     * products/algorithms support dictionaries.
     * For now just test the compression direction support
     * will be checked within the test.
     */
    //<snippet name="queryStart">
    capReq.capId = CPA_DC_CAP_BOOL_UNCOMPRESSED_DICT;
    capReq.algo = CPA_DC_DEFLATE;
    capReq.dir = CPA_DC_DIR_COMPRESS;
    status = cpaDcQueryCapabilityByType(dcInstHandle, capReq, &capResp);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get dc instance capabilities.\n");
        return status;
    }
    if (CPA_FALSE == capResp.boolStatus)
    {
        PRINT_DBG("Uncompressed Dictionaries not supported with current "
                  "algorithm\n");
        return CPA_STATUS_FAIL;
    }

    /*
     * Set the address translation function for the instance
     */
    status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Calling cpaDcStartInstance\n");
        status = cpaDcStartInstance(dcInstHandle, 0, NULL);
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependant.
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
        sd.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
        sd.sessDirection = CPA_DC_DIR_COMBINED;
        sd.sessState = CPA_DC_STATELESS;
        sd.windowSize = CPA_DC_WINSIZE_64K;
        sd.checksum = CPA_DC_CRC32;

        /* Determine size of session context to allocate */
        PRINT_DBG("Calling cpaDcGetSessionSize\n");
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
        PRINT_DBG("Calling cpaDcInitSession\n");
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

        /* Perform compression operation */
        status = compPerformOp(dcInstHandle, sessionHdl);

        /*
         * In a typical usage, the session might be used to compress
         * multiple buffers. In this example however, we can now
         * tear down the session.
         */
        PRINT_DBG("Calling cpaDcRemoveSession\n");
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

    PRINT_DBG("Calling cpaDcStopInstance\n");
    intStatus = cpaDcStopInstance(dcInstHandle);
    if (CPA_STATUS_SUCCESS != intStatus)
    {
        PRINT_ERR("cpaDcStopInstance failed, intStatus = %d\n", intStatus);
        status = intStatus;
    }

    /* Free session context */
    PHYS_CONTIG_FREE(sessionHdl);

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Dictionary Sample code ran successfully\n");
    }
    else
    {
        PRINT_DBG("Dictionary Sample code failed with status of %d\n", status);
    }

    return status;
}
