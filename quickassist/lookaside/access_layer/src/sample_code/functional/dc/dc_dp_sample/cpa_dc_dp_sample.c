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
 * This is sample code that demonstrates usage of the data plane data
 * compression API, and specifically using this API to do stateless
 * compress an input buffer.
 * It will compress the data using deflate with dynamic huffman trees.
 */

#include "cpa.h"
#include "cpa_dc_dp.h"
#include "icp_sal_poll.h"

#include "cpa_sample_utils.h"
#include "cpa_sample_cnv_utils.h"

extern int gDebugParam;

#define SAMPLE_MAX_BUFF 1024
#define SINGLE_INTER_BUFFLIST 1

static Cpa8U sampleData[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0xEF, 0xEF, 0xEF, 0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36,
    0x45, 0x64, 0xab, 0xd5, 0x27, 0x4a, 0xcb, 0xbb, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xEF, 0xEF, 0xEF,
    0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36, 0x45, 0x64, 0xab, 0xd5,
    0x27, 0x4a, 0xcb, 0xbb, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0xEF, 0xEF, 0xEF, 0x34, 0x53, 0x84, 0x68,
    0x76, 0x34, 0x65, 0x36, 0x45, 0x64, 0xab, 0xd5, 0x27, 0x4a, 0xcb, 0xbb,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xEE, 0xEE,
    0xDE, 0xAD, 0xBB, 0xBF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0xEF, 0xEF, 0xEF, 0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36,
    0x45, 0x64, 0xab, 0xd5, 0x27, 0x4A, 0xCB, 0xBB};

/*
 *****************************************************************************
 * Forward declaration
 *****************************************************************************
 */
CpaStatus dcDpSample(void);

/*
 * Callback function
 *
 * This function is "called back" (invoked by the implementation of
 * the API) when the operation has completed.
 *
 */
static void dcDpCallback(CpaDcDpOpData *pOpData)
{
    pOpData->pCallbackTag = (void *)1;
}

/*
 * This function performs a compression operation.
 */
static CpaStatus compPerformOp(CpaInstanceHandle dcInstHandle,
                               CpaDcSessionHandle sessionHdl,
                               CpaDcHuffType huffType)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaPhysBufferList *pBufferListSrc = NULL;
    CpaPhysBufferList *pBufferListDst = NULL;
    CpaPhysBufferList *pBufferListDst2 = NULL;
    Cpa32U bufferSize = sizeof(sampleData);
    Cpa32U dstBufferSize = bufferSize;
    Cpa32U numBuffers = 0;
    Cpa32U bufferListMemSize = 0;
    Cpa8U *pSrcBuffer = NULL;
    Cpa8U *pSrcBuffer2 = NULL;
    Cpa8U *pDstBuffer = NULL;
    Cpa8U *pDst2Buffer = NULL;
    CpaDcDpOpData *pOpData = NULL;
    Cpa32U checksum = 0;

    //<snippet name="memAlloc">
    numBuffers = 2;
    /* Size of CpaPhysBufferList and array of CpaPhysFlatBuffers */
    bufferListMemSize =
        sizeof(CpaPhysBufferList) + (numBuffers * sizeof(CpaPhysFlatBuffer));

    /* Allocate 8-byte aligned source buffer List */
    status = PHYS_CONTIG_ALLOC_ALIGNED(&pBufferListSrc, bufferListMemSize, 8);
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate first data buffer to hold half the data */
        status = PHYS_CONTIG_ALLOC(&pSrcBuffer, (sizeof(sampleData)) / 2);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate second data buffer to hold half the data */
        status = PHYS_CONTIG_ALLOC(&pSrcBuffer2, (sizeof(sampleData)) / 2);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* copy source into buffer */
        memcpy(pSrcBuffer, sampleData, sizeof(sampleData) / 2);
        memcpy(pSrcBuffer2,
               &(sampleData[sizeof(sampleData) / 2]),
               sizeof(sampleData) / 2);

        /* Build source bufferList */
        pBufferListSrc->numBuffers = 2;
        pBufferListSrc->flatBuffers[0].dataLenInBytes = sizeof(sampleData) / 2;
        pBufferListSrc->flatBuffers[0].bufferPhysAddr =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pSrcBuffer,
                              dcInstHandle,
                              CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
        pBufferListSrc->flatBuffers[1].dataLenInBytes = sizeof(sampleData) / 2;
        pBufferListSrc->flatBuffers[1].bufferPhysAddr =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pSrcBuffer2,
                              dcInstHandle,
                              CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
        //</snippet>
    }

    /* Destination buffer size is set as sizeof(sampelData) for a
     * Deflate compression operation with DC_API_VERSION < 2.5.
     * cpaDcDeflateCompressBound API is used to get maximum output buffer size
     * for a Deflate compression operation with DC_API_VERSION >= 2.5 */
#if DC_API_VERSION_AT_LEAST(2, 5)
    status = cpaDcDeflateCompressBound(
        dcInstHandle, huffType, bufferSize, &dstBufferSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcDeflateCompressBound API failed. (status = %d)\n",
                  status);
        return CPA_STATUS_FAIL;
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate destination buffer the same size as source buffer but in
           an SGL with 1 buffer */
        bufferListMemSize = sizeof(CpaPhysBufferList) + dstBufferSize;
        status =
            PHYS_CONTIG_ALLOC_ALIGNED(&pBufferListDst, bufferListMemSize, 8);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pDstBuffer, bufferSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Build destination bufferList */
        pBufferListDst->numBuffers = 1;
        pBufferListDst->flatBuffers[0].dataLenInBytes = bufferSize;
        pBufferListDst->flatBuffers[0].bufferPhysAddr =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pDstBuffer,
                              dcInstHandle,
                              CPA_ACC_SVC_TYPE_DATA_COMPRESSION);

        //<snippet name="opDataDp">
        /* Allocate memory for operational data. Note this needs to be
         * 8-byte aligned, contiguous, resident in DMA-accessible
         * memory.
         */
        status = PHYS_CONTIG_ALLOC_ALIGNED(&pOpData, sizeof(CpaDcDpOpData), 8);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        memset(pOpData, 0, sizeof(CpaDcDpOpData));
        pOpData->bufferLenToCompress = sizeof(sampleData);
        pOpData->bufferLenForData = dstBufferSize;
        pOpData->dcInstance = dcInstHandle;
        pOpData->pSessionHandle = sessionHdl;
        pOpData->srcBuffer =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pBufferListSrc,
                              dcInstHandle,
                              CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
        pOpData->srcBufferLen = CPA_DP_BUFLIST;
        pOpData->destBuffer =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pBufferListDst,
                              dcInstHandle,
                              CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
        pOpData->destBufferLen = CPA_DP_BUFLIST;
        pOpData->sessDirection = CPA_DC_DIR_COMPRESS;
        INIT_DC_DP_CNV_OPDATA(pOpData);
        pOpData->thisPhys =
            virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pOpData,
                              dcInstHandle,
                              CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
        pOpData->pCallbackTag = (void *)0;
        //</snippet>

        /** Enqueue and submit operation */
        //<snippet name="perform">
        status = cpaDcDpEnqueueOp(pOpData, CPA_TRUE);
        //</snippet>
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcDpEnqueueOp failed. (status = %d)\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Poll for responses.
         * Polling functions are implementation specific */
        do
        {
            status = icp_sal_DcPollDpInstance(dcInstHandle, 1);
        } while (
            ((CPA_STATUS_SUCCESS == status) || (CPA_STATUS_RETRY == status)) &&
            (pOpData->pCallbackTag == (void *)0));
    }
    /*
     * We now check the results
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (pOpData->responseStatus != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR(
                "status from compression operation failed. (status = %d)\n",
                pOpData->responseStatus);
            status = CPA_STATUS_FAIL;
        }
        else
        {
            if (pOpData->results.status != CPA_DC_OK)
            {
                PRINT_ERR("Results status not as expected (status = %d)\n",
                          pOpData->results.status);
                status = CPA_STATUS_FAIL;
            }
            else
            {
                PRINT_DBG("Data consumed %d\n", pOpData->results.consumed);
                PRINT_DBG("Data produced %d\n", pOpData->results.produced);
                PRINT_DBG("CRC checksum 0x%x\n", pOpData->results.checksum);
            }
            /* To compare the checksum with decompressed output */
            checksum = pOpData->results.checksum;
        }
    }

    /*
     * We now ensure we can decompress to the original buffer.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Dst is now the Src buffer - update the length with amount of
           compressed data added to the buffer */
        pBufferListDst->flatBuffers[0].dataLenInBytes =
            pOpData->results.produced;

        /* Allocate memory for new destination bufferList Dst2, we can use
         * stateless decompression here because in this scenario we know
         * that all transmitted data before compress was less than some
         * max size */
        status =
            PHYS_CONTIG_ALLOC_ALIGNED(&pBufferListDst2, bufferListMemSize, 8);
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pDst2Buffer, SAMPLE_MAX_BUFF);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Build destination 2 bufferList */
            pBufferListDst2->numBuffers = 1;
            pBufferListDst2->flatBuffers[0].dataLenInBytes = SAMPLE_MAX_BUFF;
            pBufferListDst2->flatBuffers[0].bufferPhysAddr =
                virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pDst2Buffer,
                                  dcInstHandle,
                                  CPA_ACC_SVC_TYPE_DATA_COMPRESSION);

            /** Can reuse prev OpData
             */
            pOpData->bufferLenToCompress = pOpData->results.produced;
            pOpData->bufferLenForData = SAMPLE_MAX_BUFF;
            pOpData->dcInstance = dcInstHandle;
            pOpData->pSessionHandle = sessionHdl;
            pOpData->srcBuffer =
                virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pBufferListDst,
                                  dcInstHandle,
                                  CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
            pOpData->srcBufferLen = CPA_DP_BUFLIST;
            pOpData->destBuffer = virtAddrToDevAddr(
                (SAMPLE_CODE_UINT *)(uintptr_t)pBufferListDst2,
                dcInstHandle,
                CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
            pOpData->destBufferLen = CPA_DP_BUFLIST;
            pOpData->sessDirection = CPA_DC_DIR_DECOMPRESS;
            INIT_DC_DP_CNV_OPDATA(pOpData);
            pOpData->thisPhys =
                virtAddrToDevAddr((SAMPLE_CODE_UINT *)(uintptr_t)pOpData,
                                  dcInstHandle,
                                  CPA_ACC_SVC_TYPE_DATA_COMPRESSION);
            pOpData->pCallbackTag = (void *)0;

            PRINT_DBG("cpaDcDpEnqueueOpBatch\n");
            /** Enqueue symmetric operation */
            status = cpaDcDpEnqueueOpBatch(1, &pOpData, CPA_TRUE);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR(
                    "cpaDcDpEnqueueOpBatch Decomp failed. (status = %d)\n",
                    status);
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Poll for responses.
             * Polling functions are implementation specific */
            do
            {
                status = icp_sal_DcPollDpInstance(dcInstHandle, 1);
            } while (((CPA_STATUS_SUCCESS == status) ||
                      (CPA_STATUS_RETRY == status)) &&
                     (pOpData->pCallbackTag == (void *)0));
        }

        /*
         * We now check the results
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (pOpData->responseStatus != CPA_STATUS_SUCCESS)
            {
                PRINT_ERR("status from decompression operation failed. (status "
                          "= %d)\n",
                          pOpData->responseStatus);

                status = CPA_STATUS_FAIL;
            }
            else
            {
                if (pOpData->results.status != CPA_DC_OK)
                {
                    PRINT_ERR("Results status not as expected (status = %d)\n",
                              pOpData->results.status);
                    status = CPA_STATUS_FAIL;
                }
                else
                {
                    PRINT_DBG("Data consumed %d\n", pOpData->results.consumed);
                    PRINT_DBG("Data produced %d\n", pOpData->results.produced);
                    PRINT_DBG("CRC checksum 0x%x\n", pOpData->results.checksum);

                    /* Compare with original data */
                    if (0 ==
                        memcmp(pDst2Buffer, sampleData, sizeof(sampleData)))
                    {
                        PRINT_DBG("Output matches expected output\n");
                    }
                    else
                    {
                        PRINT_ERR("Output does not match expected output\n");
                        status = CPA_STATUS_FAIL;
                    }
                    if (checksum == pOpData->results.checksum)
                    {
                        PRINT_DBG("Checksums match after compression and "
                                  "decompression\n");
                    }
                    else
                    {
                        PRINT_ERR("Checksums does not match after compression "
                                  "and decompression\n");
                        status = CPA_STATUS_FAIL;
                    }
                }
            }
        }
    }

    /*
     * Free the memory!
     */
    PHYS_CONTIG_FREE(pOpData);
    PHYS_CONTIG_FREE(pSrcBuffer);
    PHYS_CONTIG_FREE(pSrcBuffer2);
    PHYS_CONTIG_FREE(pBufferListSrc);
    PHYS_CONTIG_FREE(pDstBuffer);
    PHYS_CONTIG_FREE(pBufferListDst);
    PHYS_CONTIG_FREE(pDst2Buffer);
    PHYS_CONTIG_FREE(pBufferListDst2);

    return status;
}

/*
 * This is the main entry point for the sample data compression code.
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more stateless compression operations,
 * and then tear down the session.
 */
CpaStatus dcDpSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcInstanceCapabilities cap = {0};
    Cpa32U sess_size = 0;
    Cpa32U ctx_size = 0;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionSetupData sd = {0};
    /* Variables required to setup the intermediate buffer */
    CpaBufferList **bufferInterArray = NULL;
    Cpa16U numInterBuffLists = 0;
    Cpa16U bufferNum = 0;
    Cpa32U buffMetaSize = 0;

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     * Note this is the same as was done for "traditional" api.
     */
    sampleDcGetInstance(&dcInstHandle);
    if (dcInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    /* Query Capabilities */
    PRINT_DBG("cpaDcQueryCapabilities\n");
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    if (!cap.statelessDeflateCompression ||
        !cap.statelessDeflateDecompression || !cap.checksumCRC32 ||
        !cap.dynamicHuffman)
    {
        PRINT_ERR("Error: Unsupported functionality\n");
        return CPA_STATUS_FAIL;
    }

    if (cap.dynamicHuffmanBufferReq)
    {

        status = cpaDcBufferListGetMetaSize(dcInstHandle, 1, &buffMetaSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = cpaDcGetNumIntermediateBuffers(dcInstHandle,
                                                    &numInterBuffLists);
        }
        if (CPA_STATUS_SUCCESS == status && 0 != numInterBuffLists)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferInterArray, numInterBuffLists * sizeof(CpaBufferList *));
        }
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            if (CPA_STATUS_SUCCESS == status)
            {
                status = PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum],
                                           sizeof(CpaBufferList));
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                status = PHYS_CONTIG_ALLOC(
                    &bufferInterArray[bufferNum]->pPrivateMetaData,
                    buffMetaSize);
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                status =
                    PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum]->pBuffers,
                                      sizeof(CpaFlatBuffer));
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                /* Implementation requires an intermediate buffer approximately
                           twice the size of the output buffer */
                status = PHYS_CONTIG_ALLOC(
                    &bufferInterArray[bufferNum]->pBuffers->pData,
                    2 * SAMPLE_MAX_BUFF);
                bufferInterArray[bufferNum]->numBuffers = 1;
                bufferInterArray[bufferNum]->pBuffers->dataLenInBytes =
                    2 * SAMPLE_MAX_BUFF;
            }

        } /* End numInterBuffLists */
    }

    /*
     * Set the address translation function for the instance
     */
    status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);

    /* Start DataCompression component */
    PRINT_DBG("cpaDcStartInstance\n");
    status =
        cpaDcStartInstance(dcInstHandle, numInterBuffLists, bufferInterArray);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Register callback function for the instance */
        //<snippet name="regCb">
        status = cpaDcDpRegCbFunc(dcInstHandle, dcDpCallback);
        //</snippet>
    }

    /*
     * We now populate the fields of the session operational data and create
     * the session.  Note that the size required to store a session is
     * implementation-dependent, so we query the API first to determine how
     * much memory to allocate, and then allocate that memory.
     */
    //<snippet name="initSession">
    if (CPA_STATUS_SUCCESS == status)
    {
        sd.compLevel = CPA_DC_L4;
        sd.compType = CPA_DC_DEFLATE;
        sd.huffType = huffmanType_g;
        /* If the implementation supports it, the session will be configured
         * to select static Huffman encoding over dynamic Huffman as
         * the static encoding will provide better compressibility.
         */
        if (cap.autoSelectBestHuffmanTree)
        {
            sd.autoSelectBestHuffmanTree = CPA_DC_ASB_STATIC_DYNAMIC;
        }
        else
        {
            sd.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
        }
        sd.sessDirection = CPA_DC_DIR_COMBINED;
        sd.sessState = CPA_DC_STATELESS;
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

    /* Initialize the Stateless session */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaDcDpInitSession\n");
        status = cpaDcDpInitSession(dcInstHandle,
                                    sessionHdl, /* session memory */
                                    &sd);       /* session setup data */
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform Compression operation */
        status = compPerformOp(dcInstHandle, sessionHdl, sd.huffType);

        PRINT_DBG("cpaDcDpRemoveSession\n");
        //<snippet name="removeSession">
        sessionStatus = cpaDcDpRemoveSession(dcInstHandle, sessionHdl);
        //</snippet>

        /* Maintain status of remove session only when status of all operations
         * before it are successful. */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }

    /*
     * Free up memory, stop the instance, etc.
     */

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionHdl);

    PRINT_DBG("cpaDcStopInstance\n");
    cpaDcStopInstance(dcInstHandle);

    /* Free intermediate buffers */
    if (bufferInterArray != NULL)
    {
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pBuffers->pData);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pBuffers);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pPrivateMetaData);
        }
        PHYS_CONTIG_FREE(bufferInterArray);
    }

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
