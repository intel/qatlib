/****************************************************************************
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

#include "cpa_dc.h"
#include "../common/qat_perf_buffer_utils.h"
#include "qat_perf_utils.h"
#include "qat_compression_main.h"
#include "qat_perf_sleeptime.h"
#include "busy_loop.h"
#include "qat_perf_cycles.h"
#include "qat_compression_zlib.h"

CpaStatus qatGetCompressBoundDestinationBufferSize(
    compression_test_params_t *setup,
    Cpa32U dcInputBufferSize,
    Cpa32U *dcDestBufferSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(dcDestBufferSize, status);

    if (setup->setupData.compType == CPA_DC_DEFLATE)
    {

        status = cpaDcDeflateCompressBound(setup->dcInstanceHandle,
                                           setup->setupData.huffType,
                                           dcInputBufferSize,
                                           dcDestBufferSize);
    }
#if DC_API_VERSION_AT_LEAST(3, 1)
    else if (setup->setupData.compType == CPA_DC_LZ4)
    {
        status = cpaDcLZ4CompressBound(
            setup->dcInstanceHandle, dcInputBufferSize, dcDestBufferSize);
    }
    else if (setup->setupData.compType == CPA_DC_LZ4S)
    {
        status = cpaDcLZ4SCompressBound(
            setup->dcInstanceHandle, dcInputBufferSize, dcDestBufferSize);
    }
#endif
    else
    {
        PRINT_ERR("%s : Unsupported Compression Type %d\n",
                  __func__,
                  setup->setupData.compType);
        status = CPA_STATUS_FAIL;
    }

    if (status == CPA_STATUS_SUCCESS)
    {
        setup->dcDestBufferSize = *dcDestBufferSize;
    }

    return status;
}

static CpaStatus qatDcGetDestBufferAdditionalSize(
    compression_test_params_t *setup,
    Cpa32U *additionalSize)
{
    Cpa32U compDestBufferSize = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(additionalSize, status);

    *additionalSize = 0;

    status = qatGetCompressBoundDestinationBufferSize(
        setup, setup->bufferSize, &compDestBufferSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        *additionalSize = compDestBufferSize - setup->bufferSize;
    }

    if (setup->setupData.sessDirection != CPA_DC_DIR_COMPRESS)
    {
        /* Save the Destination buffer size in the setup parameters for future
         * use*/
        setup->dcDestBufferSize = *additionalSize + setup->bufferSize;
    }

    return status;
}

/*free the array of source and destination CpaBufferLists
 * free the array of results*/
CpaStatus qatFreeCompressionLists(compression_test_params_t *setup,
                                  CpaBufferList **srcBufferListArray,
                                  CpaBufferList **destBufferListArray,
                                  CpaBufferList **cpmBufferListArray,
                                  CpaDcRqResults **resultArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

    status = FreeArrayOfStructures((void **)srcBufferListArray);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free srcBufferListArray");
        retStatus = CPA_STATUS_FAIL;
    }
    status = FreeArrayOfStructures((void **)destBufferListArray);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free destBufferListArray");
        retStatus = CPA_STATUS_FAIL;
    }
    if (NULL != resultArray)
    {
        status = FreeArrayOfStructures((void **)resultArray);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not free resultArray");
            retStatus = CPA_STATUS_FAIL;
        }
    }
    status = FreeArrayOfStructures((void **)cpmBufferListArray);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not free cpmBufferListArray");
        retStatus = CPA_STATUS_FAIL;
    }
    return retStatus;
}

#ifdef SC_CHAINING_ENABLED
/*free the array of chaining source and destination CpaBufferLists
 * free the array of chainging results*/
CpaStatus qatFreeDcChainLists(void **chainResultArray,
                              CpaDcChainOpData **chainOpDataArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

    if (NULL != chainResultArray)
    {
        status = FreeArrayOfStructures(chainResultArray);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not free chainResultArray");
            retStatus = CPA_STATUS_FAIL;
        }

        status = FreeArrayOfStructures((void **)chainOpDataArray);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not free chainOpDataArray");
            retStatus = CPA_STATUS_FAIL;
        }
    }
    return retStatus;
}
#endif

/*allocate the array of source and destination CpaBufferLists
 * allocate the array of results*/
CpaStatus qatAllocateCompressionLists(compression_test_params_t *setup,
                                      CpaBufferList **srcBufferListArray,
                                      CpaBufferList **destBufferListArray,
                                      CpaBufferList **cpmBufferListArray,
                                      CpaDcRqResults **resultArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = AllocArrayOfStructures(
        (void **)srcBufferListArray, setup->numLists, sizeof(CpaBufferList));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("could not allocate memory for srcBufferListArray\n");
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocArrayOfStructures((void **)destBufferListArray,
                                        setup->numLists,
                                        sizeof(CpaBufferList));
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate destBufferListArray\n");
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocArrayOfStructures((void **)cpmBufferListArray,
                                        setup->numLists,
                                        sizeof(CpaBufferList));

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("could not allocate cpmBufferListArray\n");
        }
    }

    if (NULL != resultArray)
    {
        if (CPA_STATUS_SUCCESS == status)
        {
            status = AllocArrayOfStructures(
                (void **)resultArray, setup->numLists, sizeof(CpaDcRqResults));
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not allocate resultArray\n");
            }
        }
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        /*something went wrong so attempt to free allocated structures
         * Don't capture the status here as we want to return non success anyway
         */
        qatFreeCompressionLists(setup,
                                srcBufferListArray,
                                destBufferListArray,
                                cpmBufferListArray,
                                resultArray);
    }
    return status;
}

#ifdef SC_CHAINING_ENABLED
/*allocate the array of source and destination dc chain Lists
 * allocate the array of results*/
CpaStatus qatAllocateDcChainLists(compression_test_params_t *setup,
                                  void **chainResultArray,
                                  CpaDcChainOpData **chainOpDataArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U chainResultLen = 0;

    if (setup->legacyChainRequest)
        chainResultLen = sizeof(CpaDcChainRqResults);
#ifdef SC_CHAINING_EXT_ENABLED
    else
        chainResultLen = sizeof(CpaDcChainRqVResults);
#endif

    if (NULL != chainResultArray)
    {
        if (CPA_STATUS_SUCCESS == status)
        {
            status = AllocArrayOfStructures(
                chainResultArray, setup->numLists, chainResultLen);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not allocate chainResultArray\n");
            }
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status =
                AllocArrayOfStructures((void **)chainOpDataArray,
                                       setup->numLists * setup->numSessions,
                                       sizeof(CpaDcChainOpData));
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not allocate chainOpDataArray\n");
            }
        }
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        /*something went wrong so attempt to free allocated structures
         * Don't capture the status here as we want to return non success anyway
         */
        qatFreeDcChainLists(chainResultArray, chainOpDataArray);
    }
    return status;
}
#endif

/*free the CpaFlatBuffers and privateMetaData in the CpaBufferLists array
 * for both source and destination lists*/
CpaStatus qatFreeCompressionFlatBuffers(compression_test_params_t *setup,
                                        CpaBufferList *srcBufferListArray,
                                        CpaBufferList *destBufferListArray,
                                        CpaBufferList *cpmBufferListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (CPA_STATUS_SUCCESS !=
        freeBuffersInLists(srcBufferListArray, setup->numLists))
    {
        PRINT_ERR("freeBuffersInLists (src) error\n");
        status = CPA_STATUS_FAIL;
    }
    // keep trying to free destListArray
    if (CPA_STATUS_SUCCESS !=
        freeBuffersInLists(destBufferListArray, setup->numLists))
    {
        status = CPA_STATUS_FAIL;
        PRINT_ERR("freeBuffersInLists (dest) error\n");
    }
    if (CPA_STATUS_SUCCESS !=
        freeBuffersInLists(cpmBufferListArray, setup->numLists))
    {
        status = CPA_STATUS_FAIL;
        PRINT_ERR("freeBuffersInLists (dest) error\n");
    }

    return status;
}

/*free the CpaFlatBuffers and privateMetaData in the CpaBufferLists array
 * for both source and destination lists*/
CpaStatus qatFreeCompressionFlatBuffer(compression_test_params_t *setup,
                                       CpaBufferList *bufferListArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (CPA_STATUS_SUCCESS != qatFreeFlatBuffersInList(bufferListArray))
    {
        PRINT_ERR("freeBuffersInLists (src) error\n");
        status = CPA_STATUS_FAIL;
    }

    return status;
}
/*allocate the CpaFlatBuffers and privateMetaData in the CpaBufferLists array
 * for both source and destination lists*/
CpaStatus qatAllocateCompressionFlatBuffers(
    compression_test_params_t *setup,
    CpaBufferList *srcBufferListArray,
    Cpa32U numBuffersInSrcList,     /*affects the metaSize of CpaBufferList*/
    Cpa32U *sizeOfBuffersInSrcList, /*size of CpaFlatBuffers to  allocate*/
    CpaBufferList *destBufferListArray,
    Cpa32U numBuffersInDstList,
    Cpa32U *sizeOfBuffersInDstList,
    CpaBufferList *cpmBufferListArray,
    Cpa32U numBuffersInCpmList,
    Cpa32U *sizeOfBuffersInCpmList)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U metaSize = 0;
    /*additional size is used to allocate extra buffer space in case compression
     * ends up in expanded */
    Cpa32U additionalSize = 0;

    if (CPA_STATUS_SUCCESS == status)
    {
        // getDcMetaSize required for the src list
        status = cpaDcBufferListGetMetaSize(
            setup->dcInstanceHandle, numBuffersInSrcList, &metaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocateBuffersInLists(srcBufferListArray,
                                        setup->numLists,
                                        numBuffersInSrcList,
                                        sizeOfBuffersInSrcList,
                                        additionalSize,
                                        metaSize,
                                        setup->node,
                                        BYTE_ALIGNMENT_64);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        // getDcMetaSize required for the dest list
        status = cpaDcBufferListGetMetaSize(
            setup->dcInstanceHandle, numBuffersInDstList, &metaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Get Destination buffer additional size.
         * This additionalSize will be added to the packet size
         * and the total size is allocated for destination buffer */
        status = qatDcGetDestBufferAdditionalSize(setup, &additionalSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocateBuffersInLists(destBufferListArray,
                                        setup->numLists,
                                        numBuffersInDstList,
                                        sizeOfBuffersInDstList,
                                        additionalSize,
                                        metaSize,
                                        setup->node,
                                        BYTE_ALIGNMENT_64);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        // getDcMetaSize required for the dest list
        status = cpaDcBufferListGetMetaSize(
            setup->dcInstanceHandle, numBuffersInCpmList, &metaSize);
    }
    if (setup->disableAdditionalCmpbufferSize == CPA_FALSE)
    {
        /* For reliabilty mode we need to allocate double the space to extract
         * the SW compressed data into*/
        additionalSize = sizeOfBuffersInCpmList[0];
    }
    else
    {
        /* For performance use cases additonal buffer size  is not required
         * to be added to the cmp buffer, as there is no SW checks*/
        additionalSize = 0;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = AllocateBuffersInLists(cpmBufferListArray,
                                        setup->numLists,
                                        numBuffersInCpmList,
                                        sizeOfBuffersInCpmList,
                                        additionalSize,
                                        metaSize,
                                        setup->node,
                                        BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        // an error has occurred allocating memory so we need to free
        qatFreeCompressionFlatBuffers(
            setup, srcBufferListArray, destBufferListArray, cpmBufferListArray);
    }
    return status;
}

CpaStatus qatAllocateCompressionFlatBuffer(
    compression_test_params_t *setup,
    CpaBufferList *bufferList,
    Cpa32U numBuffersInList,    /*affects the metaSize of CpaBufferList*/
    Cpa32U sizeOfBuffersInList) /*size of CpaFlatBuffers to  allocate*/
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U metaSize = 0;
    /*shared common buffer allocation with crypto means we need to declare this
    but its not used in compression*/
    Cpa32U bufferSize = sizeOfBuffersInList;
    if (CPA_STATUS_SUCCESS == status)
    {
        // getDcMetaSize required for the list
        status = cpaDcBufferListGetMetaSize(
            setup->dcInstanceHandle, numBuffersInList, &metaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = qatAllocateFlatBuffersInList(bufferList,
                                              setup->node,
                                              metaSize,
                                              numBuffersInList,
                                              bufferSize,
                                              BYTE_ALIGNMENT_64);
    }
    // not able to allocate all memory, so free any that was allocated
    if (CPA_STATUS_SUCCESS != status)
    {
        // an error has occurred allocating memory so we need to free
        qatFreeFlatBuffersInList(bufferList);
    }
    return status;
}

#ifdef USER_SPACE
#ifdef SC_CHAINING_ENABLED
/*allocate a compression session and initialize it for a Chaining thread*/
CpaStatus qatDcChainSessionInit(compression_test_params_t *setup,
                                CpaDcSessionHandle *pSessionHandle,
                                CpaDcSessionHandle *pDecompressSessionHandle,
                                CpaDcCallbackFn dcCbFn)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionSize = 0;

    Cpa8U numSessions = setup->numSessions;
    CpaDcChainSessionSetupData chainSessionData[numSessions];

    /* Assign chain session setup data */
    switch (setup->chainOperation)
    {
        case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
            chainSessionData[0].sessType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
            chainSessionData[0].pCySetupData = &(setup->symSetupData);
            chainSessionData[1].sessType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
            chainSessionData[1].pDcSetupData = &(setup->setupData);
            break;
        case CPA_DC_CHAIN_COMPRESS_THEN_AEAD:
            chainSessionData[0].sessType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
            chainSessionData[0].pDcSetupData = &(setup->setupData);
            chainSessionData[1].sessType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
            chainSessionData[1].pCySetupData = &(setup->symSetupData);
            break;
        case CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS:
            chainSessionData[0].sessType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
            chainSessionData[0].pCySetupData = &(setup->symSetupData);
            chainSessionData[1].sessType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
            chainSessionData[1].pDcSetupData = &(setup->setupData);
            break;
        default:
            PRINT_ERR("Unsupported chaining operation.\n");
            status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Get Size for DC Session */
        status = cpaDcChainGetSessionSize(setup->dcInstanceHandle,
                                          setup->chainOperation,
                                          numSessions,
                                          chainSessionData,
                                          &sessionSize);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcChainGetSessionSize returned status %d\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate Memory for DC Session */
        *pSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
            sessionSize, setup->node, BYTE_ALIGNMENT_64);

        *pDecompressSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
            sessionSize, setup->node, BYTE_ALIGNMENT_64);

        if (*pSessionHandle == NULL || *pDecompressSessionHandle == NULL)
        {
            PRINT_ERR("could not allocate pSessionHandle\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (setup->syncFlag == SYNC)
    {
        dcCbFn = NULL;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaDcChainInitSession(setup->dcInstanceHandle,
                                       *pSessionHandle,
                                       setup->chainOperation,
                                       numSessions,
                                       chainSessionData,
                                       dcCbFn);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcChainInitSession returned status for compression "
                      "handle %d\n",
                      status);
        }
    }
    return status;
}

CpaStatus qatDcChainSessionTeardown(
    compression_test_params_t *setup,
    CpaDcSessionHandle *pSessionHandle,
    CpaDcSessionHandle *pDecompressSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

    status = cpaDcChainRemoveSession(setup->dcInstanceHandle, *pSessionHandle);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcChainRemoveSession returned status %d\n", status);
        retStatus = CPA_STATUS_FAIL;
    }

    qaeMemFreeNUMA((void **)&(*pSessionHandle));
    qaeMemFreeNUMA((void **)&(*pDecompressSessionHandle));

    if (NULL != *pSessionHandle || NULL != *pDecompressSessionHandle)
    {
        PRINT_ERR("could not free pSessionHandle\n");
        retStatus = CPA_STATUS_FAIL;
    }
    return retStatus;
}
#endif
#endif

/*allocate a compression session and initialize it for a compression thread*/
CpaStatus qatCompressionSessionInit(
    compression_test_params_t *setup,
    CpaDcSessionHandle *pSessionHandle,
    CpaDcSessionHandle *pDecompressSessionHandle,
    CpaBufferList *pContextBuffer,
    CpaDcCallbackFn dcCbFn)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionSize = 0;
    Cpa32U contextSize = 0;
    CpaDcSessionSetupData tempSetupData = setup->setupData;
    Cpa32U numberOfBuffersPerList = ONE_BUFFER_DC;
    Cpa8U compressionSessionInitialize = 0;
    Cpa8U decompressionSessionInitialize = 0;

    /*
     *  Required session initialization matrix:
     *  | Dir  | Rel | Required session |
     *  | C    |  0  |        C         |
     *  | C    |  1  |        C         |
     *  | D    |  0  |        CD        |
     *  | D    |  1  |        D         |
     *  | CD   |  0  |   Unsupported    |
     *  | CD   |  1  |   Unsupported    |
     */
    switch (setup->setupData.sessDirection)
    {
        case CPA_DC_DIR_COMPRESS:
            compressionSessionInitialize = 1;
            break;

        case CPA_DC_DIR_DECOMPRESS:
            decompressionSessionInitialize = 1;
            if (!reliability_g)
                compressionSessionInitialize = 1;
            break;

        case CPA_DC_DIR_COMBINED:
            status = CPA_STATUS_UNSUPPORTED;
            PRINT_ERR("Combined session testing unsupported\n");
            break;

        default:
            break;
    }

    // cpaScInitDcSession(...)
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Get Size for DC Session */
        status = cpaDcGetSessionSize(setup->dcInstanceHandle,
                                     &(setup->setupData),
                                     &sessionSize,
                                     &contextSize);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcGetSessionSize returned status %d\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (contextSize > 0)
        {
            // fill context buffer data
            if (CPA_STATUS_SUCCESS !=
                qatAllocateCompressionFlatBuffer(
                    setup, pContextBuffer, numberOfBuffersPerList, contextSize))
            {
                PRINT_ERR("could not allocate context flat buffers for "
                          "compression\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }
    if (setup->syncFlag == SYNC)
    {
        dcCbFn = NULL;
    }

    if (decompressionSessionInitialize == 1)
    {
        /* Allocate Memory for DC Session */
        *pDecompressSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
            (sessionSize + contextSize), setup->node, BYTE_ALIGNMENT_64);

        if (*pDecompressSessionHandle == NULL)
        {
            PRINT_ERR("could not allocate pDecompressSessionHandle\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            tempSetupData.sessDirection = CPA_DC_DIR_DECOMPRESS;
            status = cpaDcInitSession(setup->dcInstanceHandle,
                                      *pDecompressSessionHandle,
                                      &(tempSetupData),
                                      pContextBuffer,
                                      dcCbFn);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaDcInitSession returned status for decompression "
                          "handle %d\n",
                          status);
            }
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            setup->pSessionHandle = *pDecompressSessionHandle;
        }
    }

    if (compressionSessionInitialize == 1)
    {
        /* Allocate Memory for DC Session */
        *pSessionHandle = (CpaDcSessionHandle)qaeMemAllocNUMA(
            (sessionSize + contextSize), setup->node, BYTE_ALIGNMENT_64);

        if (*pSessionHandle == NULL)
        {
            PRINT_ERR("could not allocate pSessionHandle\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            tempSetupData.sessDirection = CPA_DC_DIR_COMPRESS;
            status = cpaDcInitSession(setup->dcInstanceHandle,
                                      *pSessionHandle,
                                      &(tempSetupData),
                                      pContextBuffer,
                                      dcCbFn);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaDcInitSession returned status for compression "
                          "handle %d\n",
                          status);
            }
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            setup->pSessionHandle = *pSessionHandle;
        }
    }

    return status;
}

CpaStatus qatCompressionSessionTeardown(
    compression_test_params_t *setup,
    CpaDcSessionHandle *pSessionHandle,
    CpaDcSessionHandle *pDecompressSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

    if (*pDecompressSessionHandle != NULL)
    {
        status = cpaDcRemoveSession(setup->dcInstanceHandle,
                                    *pDecompressSessionHandle);
        qaeMemFreeNUMA((void **)&(*pDecompressSessionHandle));
        if (NULL != *pDecompressSessionHandle)
        {
            PRINT_ERR("could not free pDecompressSessionHandle\n");
            retStatus = CPA_STATUS_FAIL;
        }
    }

    if (*pSessionHandle != NULL)
    {
        status = cpaDcRemoveSession(setup->dcInstanceHandle, *pSessionHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcRemoveSession returned status %d\n", status);
            retStatus = CPA_STATUS_FAIL;
        }
        qaeMemFreeNUMA((void **)&(*pSessionHandle));
        if (NULL != *pSessionHandle)
        {
            PRINT_ERR("could not free pSessionHandle\n");
            retStatus = CPA_STATUS_FAIL;
        }
    }

    return retStatus;
}

void qatDumpBufferListInfo(compression_test_params_t *setup,
                           CpaBufferList *pSrc,
                           CpaBufferList *pDst,
                           CpaBufferList *pCmp,
                           Cpa32U listNum)
{
    if (listNum > 0)
    {
        qatCompressDumpToFile(
            setup, pSrc, "srcBuffer", "srcBuffSize", listNum + 1);
        qatCompressDumpToFile(
            setup, pDst, "dstBuffer", "dstBufferSize", listNum + 1);
        qatCompressDumpToFile(
            setup, pCmp, "cmpBuffer", "cmpBufferSize", listNum + 1);
    }
    qatCompressDumpToFile(setup, pSrc, "srcFile", "srcFileSize", 0);
    qatCompressDumpToFile(setup, pDst, "dstFile", "dstFileSize", 0);
    qatCompressDumpToFile(setup, pCmp, "cmpFile", "cmpFileSize", 0);
}

CpaStatus qatIsBufEmpty(Cpa8U *buf, size_t pktSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (pktSize < (2 * sizeof(uint64_t)))
    {
        if (*buf != 0 || memcmp(buf, buf + 1, pktSize - 1) != 0)
        {
            status = CPA_STATUS_FAIL;
        }
    }
    else
    {
        if (memcmp(buf, buf + sizeof(uint64_t), pktSize - sizeof(uint64_t)) !=
            0)
        {
            status = CPA_STATUS_FAIL;
        }
    }

    return status;
}

CpaStatus qatCmpBuffers(compression_test_params_t *setup,
                        CpaBufferList *pSrc,
                        CpaBufferList *pDst)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0, j = 0, count = 0;
    Cpa8U *originalData = NULL;
    Cpa8U *processedData = NULL;
    Cpa32U sizeOfSrcFile = 0;
    Cpa32U sizeOfDstFile = 0;
    Cpa32U offset = 0;
    Cpa32U offset2 = 0;
    /* Compare the source and destination
     * buffers
     */

    /*buffer sizes might vary, so tally up the total size of the src and dst
     * bufferLists, the total size of each should match otherwise return
     * an error
     */
    for (j = 0; j < setup->numberOfBuffers[i]; j++)
    {
        sizeOfSrcFile += pSrc[j].pBuffers->dataLenInBytes;
        sizeOfDstFile += pDst[j].pBuffers->dataLenInBytes;
    }
    if (sizeOfSrcFile != sizeOfDstFile)
    {
        PRINT_ERR("Src(%d bytes) and Dst(%d bytes) total size does not match\n",
                  sizeOfSrcFile,
                  sizeOfDstFile);
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        processedData = qaeMemAlloc(sizeOfDstFile);
        originalData = qaeMemAlloc(sizeOfSrcFile);
        if (NULL == processedData || NULL == originalData)
        {
            PRINT_ERR("Memory allocation failure for data comparison\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        for (j = 0; j < setup->numberOfBuffers[i]; j++)
        {
            memcpy((originalData + offset),
                   pSrc[j].pBuffers->pData,
                   pSrc[j].pBuffers->dataLenInBytes);
            memcpy((processedData + offset2),
                   pDst[j].pBuffers->pData,
                   pDst[j].pBuffers->dataLenInBytes);
            offset += pSrc[j].pBuffers->dataLenInBytes;
            offset2 += pDst[j].pBuffers->dataLenInBytes;
            if (setup->setupData.sessState == CPA_DC_STATELESS)
            {
                /*check that src and dst buffer lengths match*/
                if (pSrc[j].pBuffers->dataLenInBytes !=
                    pDst[j].pBuffers->dataLenInBytes)
                {
                    PRINT_ERR("src buffer length (%u) and dst buffer length "
                              "(%u) does not match\n",
                              pSrc[j].pBuffers->dataLenInBytes,
                              pDst[j].pBuffers->dataLenInBytes);
                }
                /*check that src and dst data match*/
                count = memcmp(pSrc[j].pBuffers->pData,
                               pDst[j].pBuffers->pData,
                               pDst[j].pBuffers->dataLenInBytes);
                if (0 != count)
                {
                    PRINT_ERR(
                        "Buffers comparison Failed j:%d, count:%d\n", j, count);
                    qatDumpBufferListInfo(setup, pSrc, pDst, NULL, j);
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
        /* Compare the decompressed data to original*/
        count = memcmp(originalData, processedData, sizeOfDstFile);
        if (0 != count)
        {
            PRINT_ERR("Buffers comparison Failed i:%d, count:%d\n", i, count);
            status = CPA_STATUS_FAIL;
        }
    }
    if (NULL != processedData)
    {
        qaeMemFree((void **)&processedData);
    }
    if (NULL != originalData)
    {
        qaeMemFree((void **)&originalData);
    }

    return status;
}


static CpaStatus qatSwZlibCompress(compression_test_params_t *setup,
                                   CpaBufferList *srcBuffListArray,
                                   CpaBufferList *dstBuffListArray,
                                   CpaDcRqResults *cmpResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    struct z_stream_s stream = {0};
    Cpa32U j = 0;
    int zlibFlushflag;

    /* call the compress api */
    for (j = 0; j < setup->numLists; j++)
    {
        memset(&stream, 0, sizeof(struct z_stream_s));
        deflate_init(&stream);
        if ((CPA_DC_STATEFUL == setup->setupData.sessState) &&
            (j < setup->numLists - 1))
        {
            zlibFlushflag = Z_SYNC_FLUSH;
        }
        else
        {
            zlibFlushflag = Z_FINISH;
        }
        status = deflate_compress(&stream,
                                  srcBuffListArray[j].pBuffers->pData,
                                  srcBuffListArray[j].pBuffers->dataLenInBytes,
                                  dstBuffListArray[j].pBuffers->pData,
                                  dstBuffListArray[j].pBuffers->dataLenInBytes,
                                  zlibFlushflag);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT("srcLen: %d, destLen: %d \n",
                  srcBuffListArray[j].pBuffers->dataLenInBytes,
                  dstBuffListArray[j].pBuffers->dataLenInBytes);
            break;
        }
        cmpResults[j].consumed = stream.total_in;
        cmpResults[j].produced = stream.total_out;
        deflate_destroy(&stream);
    }
    return status;
}

CpaStatus qatSwCompress(compression_test_params_t *setup,
                        CpaBufferList *srcBuffListArray,
                        CpaBufferList *dstBuffListArray,
                        CpaDcRqResults *cmpResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(srcBuffListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(dstBuffListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(cmpResults, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);

    if (CPA_STATUS_SUCCESS == status)
    {

        if (setup->setupData.compType == CPA_DC_DEFLATE)
        {
            status = qatSwZlibCompress(
                setup, srcBuffListArray, dstBuffListArray, cmpResults);
        }
        else
        {
            PRINT_ERR("Unsupported Compression type %d\n",
                      setup->setupData.compType);
            status = CPA_STATUS_FAIL;
        }
    }
    return status;
}

CpaStatus qatHandleUnconsumedData(compression_test_params_t *setup,
                                  CpaBufferList *bufferListArray,
                                  Cpa32U listNum,
                                  Cpa32U offset,
                                  Cpa32U remainder)
{
    CpaFlatBuffer tempFB;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (listNum == setup->numLists - 1)
    {
        PRINT_ERR("Unconsumed data not expected in the last list\n");
        status = CPA_STATUS_FAIL;
    }
    else
    {
        tempFB.pData =
            qaeMemAllocNUMA(setup->bufferSize, setup->node, BYTE_ALIGNMENT_64);
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(tempFB.pData, status);
        if (bufferListArray[listNum + 1].pBuffers->dataLenInBytes + remainder >
            setup->dcDestBufferSize)
        {
            PRINT_ERR("The unconsumed data (%d) does not fit the next buffer "
                      "size (%d) /n",
                      remainder +
                          bufferListArray[listNum + 1].pBuffers->dataLenInBytes,
                      setup->dcDestBufferSize);
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            memcpy(tempFB.pData,
                   bufferListArray[listNum + 1].pBuffers->pData,
                   bufferListArray[listNum + 1].pBuffers->dataLenInBytes);
            tempFB.dataLenInBytes =
                bufferListArray[listNum + 1].pBuffers->dataLenInBytes;
            /* Copy the remaining data to the start of the next
             * request */
            memcpy(bufferListArray[listNum + 1].pBuffers->pData,
                   (bufferListArray[listNum].pBuffers->pData + offset),
                   remainder);
            /* Copy the original data of the next request and
             * append to the remaining data */
            memcpy((bufferListArray[listNum + 1].pBuffers->pData + remainder),
                   tempFB.pData,
                   tempFB.dataLenInBytes);
            /* Update the next request with the correct length */
            bufferListArray[listNum + 1].pBuffers->dataLenInBytes =
                remainder + tempFB.dataLenInBytes;
            /* Update the current request with the correct length */
            bufferListArray[listNum].pBuffers->dataLenInBytes = offset;

            qaeMemFreeNUMA((void **)&tempFB.pData);
        }
    }
    return status;
}

CpaStatus qatCheckAndHandleUnconsumedData(compression_test_params_t *setup,
                                          CpaBufferList *arrayOfDestBufferLists,
                                          CpaDcRqResults *arrayOfResults,
                                          Cpa32U listNum,
                                          const char *partName)
{
    Cpa64S remainder = 0;
    Cpa64S offset = 0;
    CpaStatus status = CPA_STATUS_FAIL;

    remainder = arrayOfDestBufferLists[listNum].pBuffers->dataLenInBytes -
                arrayOfResults[listNum].consumed;
    offset =
        arrayOfDestBufferLists[listNum].pBuffers->dataLenInBytes - remainder;

    /*there should not be any unconsumed data for "c4xx"*/
    if (strncmp(partName, "c4xx", strlen("c4xx")) == 0)
    {
        PRINT_ERR("HW did not consume the entire buffer \n");
        return status;
    }

    if (remainder < 0)
    {
        /*For dh895x in case if the last buffer doesn't contain an end of
         *stream, fw adds tailing zeros to the buffer so the number
         *of consumed bytes became larger than expected.*/
        if ((strncmp(partName, "dh895", strlen("dh895")) == 0) &&
            (listNum == setup->numLists - 1) &&
            (arrayOfDestBufferLists[listNum].pBuffers->dataLenInBytes <
             arrayOfResults[listNum].consumed))
        {
            status = CPA_STATUS_SUCCESS;
        }
    }
    else
    {
        /*copy any unconsumed data into the next buffer*/
        status = qatHandleUnconsumedData(
            setup, arrayOfDestBufferLists, listNum, offset, remainder);
    }
    return status;
}

#ifdef SC_CHAINING_ENABLED
void qatDcChainUpdateProducedBufferLength(compression_test_params_t *setup,
                                          CpaBufferList *bufferListArray,
                                          CpaDcChainRqResults *resultArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i, j = 0;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(bufferListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(resultArray, status);
    if (CPA_STATUS_SUCCESS == status)
    {
        for (i = 0; i < setup->numLists; i++)
        {
            for (j = 0; j < bufferListArray->numBuffers; j++)
            {
                bufferListArray[i].pBuffers[j].dataLenInBytes =
                    resultArray[i].produced;
            }
        }
    }
    else
    {
        PRINT_ERR("Cannot update the bufferListArray\n");
    }
    return;
}
#endif

void qatDcUpdateProducedBufferLength(compression_test_params_t *setup,
                                     CpaBufferList *bufferListArray,
                                     CpaDcRqResults *resultArray)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i, j = 0;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(bufferListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(resultArray, status);
    if (CPA_STATUS_SUCCESS == status)
    {
        for (i = 0; i < setup->numLists; i++)
        {
            for (j = 0; j < bufferListArray->numBuffers; j++)
            {
                bufferListArray[i].pBuffers[j].dataLenInBytes =
                    resultArray[i].produced;
            }
        }
    }
    else
    {
        PRINT_ERR("Cannot update the bufferListArray\n");
    }
    return;
}

CpaStatus qatCompressResetBufferList(compression_test_params_t *setup,
                                     CpaBufferList *buffListArray,
                                     Cpa32U *flafBufferSize,
                                     CpaBoolean isCmpBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i, j = 0;
    Cpa32U bufferSize = 0;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(buffListArray, status);
    if (CPA_STATUS_SUCCESS == status)
    {
        for (i = 0; i < setup->numLists; i++)
        {
            for (j = 0; j < buffListArray->numBuffers; j++)
            {
                /* Recalculate the buffer size as it can be double the
                 * packet size. Destination buffer size is saved in setup */
                if (isCmpBuffer)
                    bufferSize = 2 * flafBufferSize[i];
                else
                    bufferSize = setup->dcDestBufferSize;

                buffListArray[i].pBuffers[j].dataLenInBytes = bufferSize;
                memset(buffListArray[i].pBuffers[j].pData, 0, bufferSize);
            }
        }
    }
    return status;
}

void qatCompressDumpToFile(compression_test_params_t *setup,
                           CpaBufferList *buffListArray,
                           char *fileName,
                           char *fileNameB,
                           Cpa32U list)
{
#ifdef USER_SPACE
    FILE *fp = NULL;
    FILE *otherFile = NULL;
    Cpa32U j = 0;
    if (NULL != buffListArray)
    {
        if (remove(fileName) == 0)
        {
            PRINT("Deleted successfully %s\n", fileName);
        }
        else
        {
            PRINT("Unable to delete the file: %s\n", fileName);
        }
        if (remove(fileNameB) == 0)
        {
            PRINT("Deleted successfully %s\n", fileNameB);
        }
        else
        {
            PRINT("Unable to delete the file: %s\n", fileNameB);
        }
        fp = fopen(fileName, "ab+");
        if (NULL == fp)
        {
            PRINT("Error in opening file: %s\n", fileName);
            return;
        }
        otherFile = fopen(fileNameB, "w");
        if (NULL == otherFile)
        {
            PRINT("Error in opening file: %s\n", fileNameB);
            fclose(fp);
            return;
        }
        if (list > 0)
        {
            fprintf(otherFile,
                    "writing %u bytes of compressed data to file\n",
                    buffListArray[list - 1].pBuffers[0].dataLenInBytes);
            if (fwrite(buffListArray[list - 1].pBuffers[0].pData,
                       1,
                       buffListArray[list - 1].pBuffers[0].dataLenInBytes,
                       fp) < buffListArray[list - 1].pBuffers[0].dataLenInBytes)
            {
                PRINT("Error in file recording\n");
                fclose(otherFile);
                fclose(fp);
                return;
            }
        }
        else
        {
            for (j = 0; j < setup->numLists; j++)
            {
                fprintf(otherFile,
                        "writing %u bytes of compressed data to file\n",
                        buffListArray[j].pBuffers[0].dataLenInBytes);
                if (fwrite(buffListArray[j].pBuffers[0].pData,
                           1,
                           buffListArray[j].pBuffers[0].dataLenInBytes,
                           fp) < buffListArray[j].pBuffers[0].dataLenInBytes)
                {
                    PRINT("Error in file recording\n");
                    fclose(fp);
                    fclose(otherFile);
                    return;
                }
            }
        }
        fflush(fp);
        fflush(otherFile);
        fclose(fp);
        fclose(otherFile);
    }
#else
    struct file *fp = NULL;
    struct file *otherFile = NULL;
    Cpa32U j = 0;
    char *filepath = NULL;
    char *buffer = NULL;
    Cpa32S strSize = 0;
    char *firmwarePath = SAMPLE_CODE_CORPUS_PATH;

    filepath = qaeMemAlloc(QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH);
    if (NULL == filepath)
    {
        PRINT_ERR("Failed to allocate memory for filepath");
        return;
    }

    buffer = qaeMemAlloc(QAT_COMP_DUMP_BUFFER_SIZE);
    QAT_PERF_CHECK_NULL_POINTER_AND_GOTO_LABEL(buffer, exit);

    memset(filepath, 0, QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH);
    strSize = snprintf(filepath,
                       QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH,
                       "%s%s",
                       firmwarePath,
                       fileName);
    QAT_PERF_CHECK_PARAM_RANGE_AND_GOTO_LABEL(
        strSize, 1, QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH, exit);

    fp = filp_open(filepath, O_CREAT | O_RDWR | O_APPEND, 0);
    QAT_PERF_CHECK_NULL_POINTER_AND_GOTO_LABEL(fp, exit);

    memset(filepath, 0, QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH);
    strSize = snprintf(filepath,
                       QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH,
                       "%s%s",
                       firmwarePath,
                       fileNameB);
    QAT_PERF_CHECK_PARAM_RANGE_AND_GOTO_LABEL(
        strSize, 1, QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH, exit);

    otherFile = filp_open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0);
    QAT_PERF_CHECK_NULL_POINTER_AND_GOTO_LABEL(otherFile, exit);
    if (NULL != buffListArray)
    {
        if (list > 0)
        {
            memset(buffer, '\0', QAT_COMP_DUMP_BUFFER_SIZE);
            snprintf(buffer,
                     QAT_COMP_DUMP_BUFFER_SIZE,
                     "writing %u bytes of compressed data to file\n",
                     buffListArray[list - 1].pBuffers[0].dataLenInBytes);
            sampleCodeKernelWrite(otherFile,
                                  buffer,
                                  strnlen(buffer, QAT_COMP_DUMP_BUFFER_SIZE),
                                  &otherFile->f_pos);
            sampleCodeKernelWrite(
                fp,
                buffListArray[list - 1].pBuffers[0].pData,
                buffListArray[list - 1].pBuffers[0].dataLenInBytes,
                &fp->f_pos);
        }
        else
        {
            for (j = 0; j < setup->numLists; j++)
            {
                memset(buffer, '\0', QAT_COMP_DUMP_BUFFER_SIZE);
                snprintf(buffer,
                         QAT_COMP_DUMP_BUFFER_SIZE,
                         "writing %u bytes of compressed data to file\n",
                         buffListArray[j].pBuffers[0].dataLenInBytes);
                sampleCodeKernelWrite(
                    otherFile,
                    buffer,
                    strnlen(buffer, QAT_COMP_DUMP_BUFFER_SIZE),
                    &otherFile->f_pos);
                sampleCodeKernelWrite(
                    fp,
                    buffListArray[j].pBuffers[0].pData,
                    buffListArray[j].pBuffers[0].dataLenInBytes,
                    &fp->f_pos);
            }
        }
    }
    else
    {
        PRINT("CpaFlatBuffer not allocated\n");
    }

exit:
    if (fp != NULL)
    {
        filp_close(fp, NULL);
    }
    if (otherFile != NULL)
    {
        filp_close(otherFile, NULL);
    }
    qaeMemFree((void **)&filepath);
    if (buffer != NULL)
    {
        qaeMemFree((void **)&buffer);
    }
#endif
    return;
}

static CpaStatus qatSwZlibDecompress(compression_test_params_t *setup,
                                     CpaBufferList *destBuffListArray,
                                     CpaBufferList *cmpBuffListArray,
                                     CpaDcRqResults *cmpResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U j = 0;
    struct z_stream_s stream = {0};

    for (j = 0; j < setup->numLists; j++)
    {
        /* For stateful session setup stream once for all the buffers
         * For stateless session stream is initialized for every packet
         */
        if (setup->setupData.sessState != CPA_DC_STATEFUL || j == 0)
        {
            inflate_init(&stream, setup->setupData.sessState);
        }
        status =
            inflate_decompress(&stream,
                               destBuffListArray[j].pBuffers->pData,
                               cmpResults[j].produced,
                               cmpBuffListArray[j].pBuffers->pData,
                               cmpBuffListArray[j].pBuffers->dataLenInBytes,
                               setup->setupData.sessState);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT("%02x%02x%02x%02x\n",
                  destBuffListArray[j].pBuffers->pData[0],
                  destBuffListArray[j].pBuffers->pData[1],
                  destBuffListArray[j].pBuffers->pData[2],
                  destBuffListArray[j].pBuffers->pData[3]);
            PRINT_ERR("j: %d, srcLen: %d, destLen: %d \n",
                      j,
                      destBuffListArray[j].pBuffers->dataLenInBytes,
                      cmpBuffListArray[j].pBuffers->dataLenInBytes);
            qatCompressDumpToFile(
                setup, destBuffListArray, "destBuffer", "destBuffSize", 0);
            break;
        }
        cmpBuffListArray[j].pBuffers[0].dataLenInBytes = stream.avail_out;
        /*the results passed in contain the uncompressed consumed data
         * and the compressed produced data, so now we swap them, so that
         * consumed contains the compressed data consumed by zlib and the
         * decompressed data produced by zlib*/
        cmpResults[j].consumed = cmpResults[j].produced;
        cmpResults[j].produced = cmpBuffListArray[j].pBuffers->dataLenInBytes;
        /* Destroy the stream every time for stateless but only in the end
         * for stateful.
         */
        if (setup->setupData.sessState != CPA_DC_STATEFUL ||
            j == (setup->numLists - 1))
        {
            inflate_destroy(&stream);
        }
    }
    return status;
}


CpaStatus qatSwDecompress(compression_test_params_t *setup,
                          CpaBufferList *destBuffListArray,
                          CpaBufferList *cmpBuffListArray,
                          CpaDcRqResults *cmpResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(destBuffListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(cmpBuffListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(cmpResults, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);

    if (CPA_STATUS_SUCCESS == status)
    {

        if (setup->setupData.compType == CPA_DC_DEFLATE)
        {
            status = qatSwZlibDecompress(
                setup, destBuffListArray, cmpBuffListArray, cmpResults);
        }
        else
        {
            PRINT_ERR("Unsupported Compression type %d\n",
                      setup->setupData.compType);
            status = CPA_STATUS_FAIL;
        }
    }
    return status;
}
#ifdef SC_CHAINING_ENABLED
CpaStatus qatSwChainDecompress(compression_test_params_t *setup,
                               CpaBufferList *destBuffListArray,
                               CpaBufferList *cmpBufferListArray,
                               CpaDcChainRqResults *cmpResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U j = 0;
    struct z_stream_s stream = {0};
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(destBuffListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(cmpBufferListArray, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(cmpResults, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);

    if (CPA_STATUS_SUCCESS == status)
    {
        for (j = 0; j < setup->numLists; j++)
        {
            /* For stateful session setup stream once for all the buffers
             * For stateless session stream is initialized for every packet
             */
            if (setup->setupData.sessState != CPA_DC_STATEFUL || j == 0)
            {
                inflate_init(&stream, setup->setupData.sessState);
            }
            status = inflate_decompress(
                &stream,
                destBuffListArray[j].pBuffers->pData,
                cmpResults[j].produced,
                cmpBufferListArray[j].pBuffers->pData,
                cmpBufferListArray[j].pBuffers->dataLenInBytes,
                setup->setupData.sessState);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("%02x%02x%02x%02x\n",
                      destBuffListArray[j].pBuffers->pData[0],
                      destBuffListArray[j].pBuffers->pData[1],
                      destBuffListArray[j].pBuffers->pData[2],
                      destBuffListArray[j].pBuffers->pData[3]);
                PRINT_ERR("j: %d, srcLen: %d, destLen: %d \n",
                          j,
                          destBuffListArray[j].pBuffers->dataLenInBytes,
                          cmpBufferListArray[j].pBuffers->dataLenInBytes);
                qatCompressDumpToFile(
                    setup, destBuffListArray, "destBuffer", "destBuffSize", 0);
                break;
            }
            cmpBufferListArray[j].pBuffers[0].dataLenInBytes = stream.avail_out;
            /*the results passed in contain the uncompressed consumed data
             * and the compressed produced data, so now we swap them, so that
             * consumed contains the compressed data consumed by zlib and the
             * decompressed data produced by zlib*/
            cmpResults[j].consumed = cmpResults[j].produced;
            cmpResults[j].produced =
                cmpBufferListArray[j].pBuffers->dataLenInBytes;
            /* Destroy the stream every time for stateless but only in the end
             * for stateful.
             */
            if (setup->setupData.sessState != CPA_DC_STATEFUL ||
                j == (setup->numLists - 1))
            {
                inflate_destroy(&stream);
            }
        }
    }
    return status;
}
#endif

void qatDcPollAndSetNextPollCounter(compression_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /*poll to try and free space on q's*/
    if (setup->setupData.sessState == CPA_DC_STATEFUL ||
        CPA_TRUE == setup->useStatefulLite)
    {
        /*if stateful of stateful-lite wait for response of last request*/
        while (setup->performanceStats->responses !=
               setup->performanceStats->submissions)
        {
            /* Keep polling until compression of the buffer
             * completes
             * and dcPerformCallback2k() increments
             * perfData->responses */
            coo_poll_trad_dc(
                setup->performanceStats, setup->dcInstanceHandle, &status);
            if (CPA_STATUS_RETRY == status)
            {
                setup->performanceStats->pollRetries++;
                AVOID_SOFTLOCKUP;
            }
        }
        setup->performanceStats->nextPoll =
            setup->performanceStats->submissions + 1;
    }
    else
    {
        coo_poll_trad_dc(
            setup->performanceStats, setup->dcInstanceHandle, &status);
        if (CPA_STATUS_RETRY == status)
        {
            setup->performanceStats->pollRetries++;
            AVOID_SOFTLOCKUP;
        }
        setup->performanceStats->nextPoll =
            setup->performanceStats->submissions + dcPollingInterval_g;
    }
}

void qatDcRetryHandler(compression_test_params_t *setup,
                       const CpaInstanceInfo2 *pInstanceInfo2)
{
    setup->performanceStats->retries++;

    // poll if DP API is being used, or if poll inline flag is set
    if ((poll_inline_g || setup->isDpApi) && (pInstanceInfo2 != NULL) &&
        pInstanceInfo2->isPolled)
    {
        qatDcPollAndSetNextPollCounter(setup);
    }

    return;
}

#ifdef SC_CHAINING_ENABLED
void qatDcChainResponseStatusCheck(compression_test_params_t *setup,
                                   CpaDcChainRqResults *arrayOfResults,
                                   Cpa32U listNum,
                                   CpaStatus *status)
{
    Cpa32U i = 0;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, *status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfResults, *status);
    if (CPA_STATUS_SUCCESS == *status)
    {
        if (CPA_STATUS_FAIL == setup->performanceStats->threadReturnStatus)
        {
            PRINT_ERR("threadReturnStatus is set to CPA_STATUS_FAIL\n");
            /*find the request that cause the fail*/
            for (i = 0; i <= listNum; i++)
            {
                if (CPA_DC_OK != arrayOfResults[i].dcStatus)
                {
                    setup->performanceStats->additionalStatus =
                        arrayOfResults[i].dcStatus;
                    PRINT("Additional status in dcresults for list %d is %d\n",
                          i,
                          arrayOfResults[i].dcStatus);
                }
            }
            *status = CPA_STATUS_FAIL;
        }
    }
}
#endif

void qatCompressionResponseStatusCheck(compression_test_params_t *setup,
                                       CpaDcRqResults *arrayOfResults,
                                       Cpa32U listNum,
                                       CpaStatus *status)
{
    Cpa32U i = 0;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, *status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfResults, *status);
    setup->performanceStats->additionalStatus = CPA_STATUS_SUCCESS;
    if (CPA_STATUS_FAIL == setup->performanceStats->threadReturnStatus)
    {
        PRINT_ERR("threadReturnStatus is set to CPA_STATUS_FAIL\n");
        /*find the request that cause the fail*/
        do
        {
            if (CPA_DC_OK != arrayOfResults[i].status)
            {
                setup->performanceStats->additionalStatus =
                    arrayOfResults[i].status;
                PRINT("Additional status in dcresults for list %d is %d\n",
                      i,
                      arrayOfResults[i].status);
            }
        } while (++i < listNum);
        *status = CPA_STATUS_FAIL;
    }
}

CpaStatus populateCorpusAndStartDcService(Cpa32U testBufferSize,
                                          corpus_type_t corpusType)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /* Populate Corpus: copy from file on disk into memory*/
    /* this method limits to compressing 1 corpus at any point in time */
    status = populateCorpus(testBufferSize, corpusType);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to load one or more corpus files, have they been "
                  "extracted to %s?\n",
                  SAMPLE_CODE_CORPUS_PATH);
        return CPA_STATUS_FAIL;
    }

    /*Start DC Services */
    status = startDcServices(DYNAMIC_BUFFER_AREA, TEMP_NUM_BUFFS);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error in Starting Dc Services\n");
        return CPA_STATUS_FAIL;
    }
    return status;
}

CpaStatus qatCompressionSetFlushFlag(compression_test_params_t *setup,
                                     Cpa32U listNum)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    if (CPA_STATUS_SUCCESS == status)
    {
#if DC_API_VERSION_AT_LEAST(3, 1)
        /* LZ4 FW requires users to set the BFINAL for every request, *
         * when Rolling XXHASH is disabled. *
         * LZ4S FW requires users to set the BFINAL for every request */
        if (((setup->setupData.compType == CPA_DC_LZ4 &&
              setup->setupData.accumulateXXHash == CPA_FALSE) ||
             setup->setupData.compType == CPA_DC_LZ4S) &&
            setup->setupData.sessState == CPA_DC_STATELESS)
        {
            setup->flushFlag = CPA_DC_FLUSH_FINAL;
            setup->requestOps.flushFlag = CPA_DC_FLUSH_FINAL;
            return status;
        }
#endif
        /* flush flag for last request is always final for all types of
         * compression*/
        if (listNum == (setup->numLists - 1))
        {
            setup->flushFlag = CPA_DC_FLUSH_FINAL;
            setup->requestOps.flushFlag = CPA_DC_FLUSH_FINAL;
        }
        else
        {
            /*set to flush_sync for stateful otherwise flush_final*/
            if ((CPA_DC_STATEFUL == setup->setupData.sessState))
            {
                setup->flushFlag = CPA_DC_FLUSH_SYNC;
                setup->requestOps.flushFlag = CPA_DC_FLUSH_SYNC;
            }
            else
            {
                setup->flushFlag = CPA_DC_FLUSH_FULL;
                setup->requestOps.flushFlag = CPA_DC_FLUSH_FULL;
            }
        }
    }
    return status;
}

CpaStatus performSleeptimeCalculation(compression_test_params_t *setup,
                                      CpaBufferList *arrayOfSrcBufferLists,
                                      CpaBufferList *arrayOfDestBufferLists,
                                      CpaBufferList *arrayOfCmpBufferLists,
                                      CpaDcRqResults *resultArray,
                                      CpaDcCallbackFn dcCbFn,
                                      CpaDcSessionDir dcSessDir,
                                      CpaDcSessionHandle pSessionHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U baseThroughput = 0, currentThroughput = 0;
    Cpa32U packetSize = 0, lowerBound = 0, upperBound = 0;
    perf_data_t *pPerfData = setup->performanceStats;
    setup->sleepTime = 1;

    packetSize = setup->bufferSize;

    baseThroughput = getThroughput(pPerfData->responses,
                                   packetSize,
                                   pPerfData->endCyclesTimestamp -
                                       pPerfData->startCyclesTimestamp);
    currentThroughput = baseThroughput;

    /* Find the lower bound (within margin 5%)
        upper (outside of throughput margin)
     */
    while (CPA_STATUS_SUCCESS == status &&
           findSleeptimeMargin(
               baseThroughput, currentThroughput, QAT_COMP_FIVE_PERCENT))
    {
        lowerBound = setup->sleepTime;

        setup->sleepTime = setup->sleepTime << 1;

        status = qatCompressData(setup,
                                 pSessionHandle,
                                 dcSessDir,
                                 arrayOfSrcBufferLists,
                                 arrayOfDestBufferLists,
                                 arrayOfCmpBufferLists,
                                 resultArray);
        dcScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, dcSessDir);
        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);
    }
    upperBound = setup->sleepTime;

    /* Binary Search for no retries and maintaining throughput */
    while (CPA_STATUS_SUCCESS == status && lowerBound <= upperBound)
    {
        setup->sleepTime = (upperBound + lowerBound) / 2;
        status = qatCompressData(setup,
                                 pSessionHandle,
                                 dcSessDir,
                                 arrayOfSrcBufferLists,
                                 arrayOfDestBufferLists,
                                 arrayOfCmpBufferLists,
                                 resultArray);
        dcScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, dcSessDir);
        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);

        if (currentThroughput >= baseThroughput)
        {
            lowerBound = setup->sleepTime + 1;
        }
        else
        {
            /* If within ERROR_MARGIN (1.5%) of base throughput */
            if ((findSleeptimeMargin(baseThroughput,
                                     currentThroughput,
                                     QAT_COMP_ONE_POINT_FIVE_PERCENT) == 1))
            {
                break;
            }
            else
            {
                upperBound = setup->sleepTime - 1;
            }
        }
    }
    return status;
}

#ifdef USER_SPACE
#ifdef SC_CHAINING_ENABLED
CpaStatus performDcChainOffloadCalculationBusyLoop(
    compression_test_params_t *setup,
    CpaBufferList *arrayOfSrcBufferLists,
    CpaBufferList *arrayOfDestBufferLists,
    CpaBufferList *arrayOfCmpBufferLists,
    CpaDcChainRqResults *resultArray,
    CpaDcChainOpData *chainOpData,
    CpaDcCallbackFn dcCbFn,
    CpaDcSessionDir dcSessDir,
    CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U baseThroughput = 0, currentThroughput = 0, staticAssign = 0;
    Cpa32U packetSize = 0, lowerBound = 0, upperBound = 0, j = 0;
    perf_cycles_t startBusyLoopTime = 0, endBusyLoopTime = 0;
    perf_data_t *pPerfData = setup->performanceStats;

    pPerfData->busyLoopValue = 1;
    packetSize = setup->packetSizeInBytesArray[0];

    baseThroughput = getThroughput(pPerfData->responses,
                                   packetSize,
                                   pPerfData->endCyclesTimestamp -
                                       pPerfData->startCyclesTimestamp);
    currentThroughput = baseThroughput;
    /* Find the lower bound(retries) and upper bound(no retries) for subsequent
     * binary search.
     */
    while (CPA_STATUS_SUCCESS == status && pPerfData->retries != 0)
    {
        lowerBound = pPerfData->busyLoopValue;

        pPerfData->busyLoopValue = pPerfData->busyLoopValue << 1;
        status = qatDcChainCompressData(setup,
                                        pSessionHandle,
                                        dcSessDir,
                                        arrayOfSrcBufferLists,
                                        arrayOfDestBufferLists,
                                        arrayOfCmpBufferLists,
                                        resultArray,
                                        chainOpData);

        dcChainScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, dcSessDir);

        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);
    }
    upperBound = pPerfData->busyLoopValue;

    while (CPA_STATUS_SUCCESS == status && lowerBound <= upperBound)
    {
        pPerfData->busyLoopValue = (upperBound + lowerBound) / 2;

        qatDcChainCompressData(setup,
                               pSessionHandle,
                               dcSessDir,
                               arrayOfSrcBufferLists,
                               arrayOfDestBufferLists,
                               arrayOfCmpBufferLists,
                               resultArray,
                               chainOpData);

        dcChainScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, dcSessDir);

        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);

        /* If no retries and we're within ERROR_MARGIN (0.1%) of base throughput
         */
        if (pPerfData->retries == 0 &&
            (withinMargin(baseThroughput, currentThroughput, ERROR_MARGIN) ==
             1))
        {
            break;
        }
        /* If we see retries */
        else if (pPerfData->retries != 0)
        {
            lowerBound = pPerfData->busyLoopValue + 1;
        }
        /* Else retries are zero, but throughput has been affected. */
        else
        {
            upperBound = pPerfData->busyLoopValue - 1;
        }
    }
    busyLoopTimeStamp();
    startBusyLoopTime = busyLoopTimeStamp();
    for (j = 0; j < setup->performanceStats->busyLoopCount; j++)
    {
        busyLoop(setup->performanceStats->busyLoopValue, &staticAssign);
    }
    endBusyLoopTime = busyLoopTimeStamp();

    setup->performanceStats->totalBusyLoopCycles =
        endBusyLoopTime - startBusyLoopTime;

    setup->performanceStats->offloadCycles =
        (setup->performanceStats->endCyclesTimestamp -
         setup->performanceStats->startCyclesTimestamp) -
        setup->performanceStats->totalBusyLoopCycles;

    do_div(setup->performanceStats->offloadCycles,
           setup->performanceStats->responses);
    return status;
}
#endif
#endif

CpaStatus performOffloadCalculationBusyLoop(
    compression_test_params_t *setup,
    CpaBufferList *arrayOfSrcBufferLists,
    CpaBufferList *arrayOfDestBufferLists,
    CpaBufferList *arrayOfCmpBufferLists,
    CpaDcRqResults *resultArray,
    CpaDcCallbackFn dcCbFn,
    CpaDcSessionDir dcSessDir,
    CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U baseThroughput = 0, currentThroughput = 0, staticAssign = 0;
    Cpa32U packetSize = 0, lowerBound = 0, upperBound = 0, j = 0;
    perf_cycles_t startBusyLoopTime = 0, endBusyLoopTime = 0;
    perf_data_t *pPerfData = setup->performanceStats;

    pPerfData->busyLoopValue = 1;
    packetSize = setup->packetSizeInBytesArray[0];

    baseThroughput = getThroughput(pPerfData->responses,
                                   packetSize,
                                   pPerfData->endCyclesTimestamp -
                                       pPerfData->startCyclesTimestamp);
    currentThroughput = baseThroughput;
    /* Find the lower bound(retries) and upper bound(no retries) for subsequent
     * binary search.
     */
    while (CPA_STATUS_SUCCESS == status && pPerfData->retries != 0)
    {
        lowerBound = pPerfData->busyLoopValue;

        pPerfData->busyLoopValue = pPerfData->busyLoopValue << 1;
        status = qatCompressData(setup,
                                 pSessionHandle,
                                 dcSessDir,
                                 arrayOfSrcBufferLists,
                                 arrayOfDestBufferLists,
                                 arrayOfCmpBufferLists,
                                 resultArray);

        dcScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, dcSessDir);

        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);
    }
    upperBound = pPerfData->busyLoopValue;

    while (CPA_STATUS_SUCCESS == status && lowerBound <= upperBound)
    {
        pPerfData->busyLoopValue = (upperBound + lowerBound) / 2;

        status = qatCompressData(setup,
                                 pSessionHandle,
                                 dcSessDir,
                                 arrayOfSrcBufferLists,
                                 arrayOfDestBufferLists,
                                 arrayOfCmpBufferLists,
                                 resultArray);

        dcScSetBytesProducedAndConsumed(
            resultArray, setup->performanceStats, setup, dcSessDir);

        currentThroughput = getThroughput(pPerfData->responses,
                                          packetSize,
                                          pPerfData->endCyclesTimestamp -
                                              pPerfData->startCyclesTimestamp);

        /* If no retries and we're within ERROR_MARGIN (0.1%) of base throughput
         */
        if (pPerfData->retries == 0 &&
            (withinMargin(baseThroughput, currentThroughput, ERROR_MARGIN) ==
             1))
        {
            break;
        }
        /* If we see retries */
        else if (pPerfData->retries != 0)
        {
            lowerBound = pPerfData->busyLoopValue + 1;
        }
        /* Else retries are zero, but throughput has been affected. */
        else
        {
            upperBound = pPerfData->busyLoopValue - 1;
        }
    }
    busyLoopTimeStamp();
    startBusyLoopTime = busyLoopTimeStamp();
    for (j = 0; j < setup->performanceStats->busyLoopCount; j++)
    {
        busyLoop(setup->performanceStats->busyLoopValue, &staticAssign);
    }
    endBusyLoopTime = busyLoopTimeStamp();

    setup->performanceStats->totalBusyLoopCycles =
        endBusyLoopTime - startBusyLoopTime;

    setup->performanceStats->offloadCycles =
        (setup->performanceStats->endCyclesTimestamp -
         setup->performanceStats->startCyclesTimestamp) -
        setup->performanceStats->totalBusyLoopCycles;

    do_div(setup->performanceStats->offloadCycles,
           setup->performanceStats->responses);
    return status;
}

CpaStatus qatDcGetPreTestRecoveryCount(compression_test_params_t *dcSetup,
                                       CpaDcInstanceCapabilities *capabilities,
                                       perf_data_t *performanceStats)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcStats dcStats = {0};

    if (CNV_RECOVERY(&(dcSetup->requestOps)) == CPA_TRUE)
    {
        if (CNV_RECOVERY(capabilities) == CPA_FALSE)
        {
            PRINT_ERR("CnVnR requested but not supported on instance\n");
            return CPA_STATUS_FAIL;
        }
        status = cpaDcGetStats(dcSetup->dcInstanceHandle, &dcStats);
        if (status == CPA_STATUS_SUCCESS)
        {
            performanceStats->preTestRecoveryCount =
                GET_CNV_RECOVERY_COUNTERS(&dcStats);
        }
        else
        {
            performanceStats->preTestRecoveryCount = 0;
        }
    }

    return status;
}

void qatDcGetPostTestRecoveryCount(compression_test_params_t *dcSetup,
                                   perf_data_t *performanceStats)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcStats dcStats = {0};

    if (CNV_RECOVERY(&(dcSetup->requestOps)) == CPA_TRUE)
    {
        status = cpaDcGetStats(dcSetup->dcInstanceHandle, &dcStats);
        if (status == CPA_STATUS_SUCCESS)
        {
            performanceStats->postTestRecoveryCount =
                GET_CNV_RECOVERY_COUNTERS(&dcStats);
        }
        else
        {
            performanceStats->postTestRecoveryCount = 0;
        }
    }
}


CpaStatus qatCompressionVerifyOverflow(compression_test_params_t *setup,
                                       CpaDcRqResults *arrayOfResults,
                                       CpaBufferList *arrayOfSrcBufferLists,
                                       Cpa32U listNum)
{
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U totalSrcLength = 0;
    Cpa32U numBuffs = 0;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfResults, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(arrayOfSrcBufferLists,
                                                  status);

    /*Loop through all result structures and verify consumed data size */
    do
    {
        totalSrcLength = 0;
        for (numBuffs = 0; numBuffs < arrayOfSrcBufferLists[i].numBuffers;
             numBuffs++)
        {
            totalSrcLength +=
                arrayOfSrcBufferLists[i].pBuffers[numBuffs].dataLenInBytes;
        }
        if ((arrayOfResults[i].status == CPA_DC_OVERFLOW) ||
            (arrayOfResults[i].consumed < totalSrcLength))
        {
            PRINT_ERR(
                "%s: Consumed %d out of %d bytes in the Source buffer for "
                "List Number %d\n",
                __func__,
                arrayOfResults[i].consumed,
                totalSrcLength,
                i);
            status = CPA_STATUS_FAIL;
            break;
        }
    } while (++i < listNum);

    return status;
}
