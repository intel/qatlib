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
 * This is sample code that demonstrates usage of the data compression API,
 * and specifically using this API to statelessly compress input buffers using
 * a cumulative checksum.
 * It will compress the data using deflate with dynamic huffman trees.
 */

#include "cpa.h"
#include "cpa_dc.h"

#include "cpa_sample_utils.h"

extern int gDebugParam;

#define SAMPLE_MAX_BUFF 512
#define TIMEOUT_MS 5000 /* 5 seconds */

#define SINGLE_BUFFER_PER_BUFFERLIST 1

#define SAMPLE_DATA_SIZE 1024
#define NUM_SAMPLE_DATA_BUFFERS (SAMPLE_DATA_SIZE / SAMPLE_MAX_BUFF)

static Cpa8U sampleData[SAMPLE_DATA_SIZE] = {
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
    0x45, 0x64, 0xab, 0xd5, 0x27, 0x4A, 0xCB, 0xBB, 0xDE, 0xAD, 0xBE, 0xEF,
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
    0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xEE, 0xEE, 0xDE, 0xAD, 0xBB, 0xBF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xEF, 0xEF, 0xEF,
    0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36, 0x45, 0x64, 0xab, 0xd5,
    0x27, 0x4A, 0xCB, 0xBB};

/*
 *****************************************************************************
 * Forward declaration
 *****************************************************************************
 */
CpaStatus dcStatelessSample(void);

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
static void dcCallback(void *pCallbackTag, CpaStatus status)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    if (NULL != pCallbackTag)
    {
        /* indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

/*
 * This function performs a compression and decompress operation.
 */
static CpaStatus compPerformOp(CpaInstanceHandle dcInstHandle,
                               CpaDcSessionHandle sessionHdl,
                               CpaDcSessionSetupData sd)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBufferList bufferListSrcArray[NUM_SAMPLE_DATA_BUFFERS];
    CpaBufferList bufferListDstArray[NUM_SAMPLE_DATA_BUFFERS];
    CpaBufferList bufferListDstArray2[NUM_SAMPLE_DATA_BUFFERS];
    Cpa32U bufferSize = SAMPLE_MAX_BUFF;
    Cpa32U numBuffers = NUM_SAMPLE_DATA_BUFFERS;
    Cpa32U bufferNum = 0;
    Cpa32U bufferMetaSize = 0;
    CpaDcOpData opData = {};
    CpaDcRqResults dcResults;
    Cpa32U dataConsumed = 0;
    Cpa32U dataProduced = 0;
    Cpa32U checksum = 0;
    struct COMPLETION_STRUCT complete;

    INIT_OPDATA(&opData, CPA_DC_FLUSH_FINAL);

    status = cpaDcBufferListGetMetaSize(
        dcInstHandle, SINGLE_BUFFER_PER_BUFFERLIST, &bufferMetaSize);

    for (bufferNum = 0; bufferNum < numBuffers; bufferNum++)
    {
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferListSrcArray[bufferNum].pPrivateMetaData,
                bufferMetaSize);
            bufferListSrcArray[bufferNum].numBuffers = 1;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferListDstArray[bufferNum].pPrivateMetaData,
                bufferMetaSize);
            bufferListDstArray[bufferNum].numBuffers = 1;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferListDstArray2[bufferNum].pPrivateMetaData,
                bufferMetaSize);
            bufferListDstArray2[bufferNum].numBuffers = 1;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = OS_MALLOC(&bufferListSrcArray[bufferNum].pBuffers,
                               sizeof(CpaFlatBuffer));
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = OS_MALLOC(&bufferListDstArray[bufferNum].pBuffers,
                               sizeof(CpaFlatBuffer));
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = OS_MALLOC(&bufferListDstArray2[bufferNum].pBuffers,
                               sizeof(CpaFlatBuffer));
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferListSrcArray[bufferNum].pBuffers->pData, bufferSize);
            bufferListSrcArray[bufferNum].pBuffers->dataLenInBytes = bufferSize;
        }

        /* Destination buffer size is set as sizeof(sampelData) for a
         * Deflate compression operation with DC_API_VERSION < 2.5.
         * cpaDcDeflateCompressBound API is used to get maximum output buffer
         * size for a Deflate compression operation with DC_API_VERSION >= 2.5
         */
#if DC_API_VERSION_AT_LEAST(2, 5)
        status = cpaDcDeflateCompressBound(
            dcInstHandle, sd.huffType, bufferSize, &bufferSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcDeflateCompressBound API failed. (status = %d)\n",
                      status);
            return CPA_STATUS_FAIL;
        }
#endif

        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferListDstArray[bufferNum].pBuffers->pData, bufferSize);
            bufferListDstArray[bufferNum].pBuffers->dataLenInBytes = bufferSize;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferListDstArray2[bufferNum].pBuffers->pData, bufferSize);
            bufferListDstArray2[bufferNum].pBuffers->dataLenInBytes =
                bufferSize;
        }
        memcpy(bufferListSrcArray[bufferNum].pBuffers->pData,
               sampleData + (bufferNum * bufferSize),
               bufferSize);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        //<snippet name="initChecksum">
        if (sd.checksum == CPA_DC_ADLER32)
        {
            /* Initialize checksum to 1 for Adler32 */
            dcResults.checksum = 1;
        }
        else
        {
            /* Initialize checksum to 0 for CRC32 */
            dcResults.checksum = 0;
        }
        //</snippet>

        for (bufferNum = 0; bufferNum < numBuffers; bufferNum++)
        {

            COMPLETION_INIT(&complete);

            PRINT_DBG("cpaDcCompressData2\n");
            status = cpaDcCompressData2(
                dcInstHandle,
                sessionHdl,
                &bufferListSrcArray[bufferNum], /* source buffer list */
                &bufferListDstArray[bufferNum], /* destination buffer list */
                &opData,
                &dcResults, /* contains initialized checksum for first request
                             * or
                             * checksum from previous request */
                (void *)&complete);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaDcCompressData2 failed. (status = %d)\n", status);
                break;
            }
            /*
             * We now wait until the completion of the operation.  This uses a
             * macro
             * which can be defined differently for different OSes.
             */
            if (CPA_STATUS_SUCCESS == status)
            {
                if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
                {
                    PRINT_ERR(
                        "timeout or interruption in cpaDcCompressData2\n");
                    status = CPA_STATUS_FAIL;
                }
            }

            /*
             * We now check the results
             */
            if (dcResults.status != CPA_DC_OK)
            {
                PRINT_ERR("Results status not as expected (status = %d)\n",
                          dcResults.status);
                status = CPA_STATUS_FAIL;
                break;
            }

            if (dcResults.consumed !=
                bufferListSrcArray[bufferNum].pBuffers->dataLenInBytes)
            {
                PRINT_ERR("Not all data consumed !\n");
                status = CPA_STATUS_FAIL;
                break;
            }

            dataConsumed += dcResults.consumed;
            dataProduced += dcResults.produced;
            bufferListDstArray[bufferNum].pBuffers->dataLenInBytes =
                dcResults.produced;

        } /* End for numBuffers */
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Data consumed %d\n", dataConsumed);
        PRINT_DBG("Data produced %d\n", dataProduced);
        PRINT_DBG("Checksum 0x%x\n", dcResults.checksum);
        /* Reset counters and checksum */
        dataConsumed = 0;
        dataProduced = 0;

        /* To compare the checksum with decompressed output */
        checksum = dcResults.checksum;

        memset(&dcResults, 0, sizeof(CpaDcRqResults));
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        if (sd.checksum == CPA_DC_ADLER32)
        {
            /* Initialize checksum to 1 for Adler32 */
            dcResults.checksum = 1;
        }
        else
        {
            /* Initialize checksum to 0 for CRC32 */
            dcResults.checksum = 0;
        }
        for (bufferNum = 0; bufferNum < numBuffers; bufferNum++)
        {

            COMPLETION_INIT(&complete);

            PRINT_DBG("cpaDcDecompressData2\n");
            status = cpaDcDecompressData2(
                dcInstHandle,
                sessionHdl,
                &bufferListDstArray[bufferNum],  /* source buffer list */
                &bufferListDstArray2[bufferNum], /* destination buffer list */
                &opData,
                &dcResults, /* contains initialized checksum for first request
                             * or
                             * checksum from previous request */
                (void *)&complete);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaDcCompressData2 failed. (status = %d)\n", status);
                break;
            }

            /*
             * We now wait until the completion of the operation.  This uses a
             * macro
             * which can be defined differently for different OSes.
             */
            if (CPA_STATUS_SUCCESS == status)
            {
                if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
                {
                    PRINT_ERR(
                        "timeout or interruption in cpaDcDecompressData2\n");
                    status = CPA_STATUS_FAIL;
                }
            }

            /*
             * We now check the results
             */
            if (dcResults.status != CPA_DC_OK)
            {
                PRINT_ERR("Results status not as expected (status = %d)\n",
                          dcResults.status);
                status = CPA_STATUS_FAIL;
                break;
            }

            if (dcResults.consumed !=
                bufferListDstArray[bufferNum].pBuffers->dataLenInBytes)
            {
                PRINT_ERR("Not all data consumed !\n");
                status = CPA_STATUS_FAIL;
                break;
            }
            dataConsumed += dcResults.consumed;
            dataProduced += dcResults.produced;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Data consumed %d\n", dataConsumed);
        PRINT_DBG("Data produced %d\n", dataProduced);
        PRINT_DBG("Checksum 0x%x\n", dcResults.checksum);
        for (bufferNum = 0; bufferNum < numBuffers; bufferNum++)
        {
            /* Compare with original Src buffer */
            if (0 == memcmp(bufferListDstArray2[bufferNum].pBuffers->pData,
                            bufferListSrcArray[bufferNum].pBuffers->pData,
                            SAMPLE_MAX_BUFF))
            {
                PRINT_DBG("Output matches expected output\n");
            }
            else
            {
                PRINT_ERR("Output does not match expected output\n");
                status = CPA_STATUS_FAIL;
            }
        }
        if (checksum == dcResults.checksum)
        {
            PRINT_DBG("Checksums match after compression and decompression\n");
        }
        else
        {
            PRINT_ERR("Checksums does not match after compression and "
                      "decompression\n");
            status = CPA_STATUS_FAIL;
        }
    }
    for (bufferNum = 0; bufferNum < numBuffers; bufferNum++)
    {
        PHYS_CONTIG_FREE(bufferListSrcArray[bufferNum].pPrivateMetaData);
        PHYS_CONTIG_FREE(bufferListDstArray[bufferNum].pPrivateMetaData);
        PHYS_CONTIG_FREE(bufferListDstArray2[bufferNum].pPrivateMetaData);

        PHYS_CONTIG_FREE(bufferListSrcArray[bufferNum].pBuffers->pData);
        PHYS_CONTIG_FREE(bufferListDstArray[bufferNum].pBuffers->pData);
        PHYS_CONTIG_FREE(bufferListDstArray2[bufferNum].pBuffers->pData);

        OS_FREE(bufferListSrcArray[bufferNum].pBuffers);
        OS_FREE(bufferListDstArray[bufferNum].pBuffers);
        OS_FREE(bufferListDstArray2[bufferNum].pBuffers);
    }

    COMPLETION_DESTROY(&complete);
    return status;
}

/*
 * This is the main entry point for the sample data compression code.
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more stateless compression operations,
 * and then tear down the session.
 */
CpaStatus dcStatelessSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcInstanceCapabilities cap = {0};
    CpaBufferList **bufferInterArray = NULL;
    Cpa16U numInterBuffLists = 0;
    Cpa16U bufferNum = 0;
    Cpa32U buffMetaSize = 0;

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
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    if (!cap.statelessDeflateCompression ||
        !cap.statelessDeflateDecompression || !cap.checksumAdler32 ||
        !cap.dynamicHuffman)
    {
        PRINT_DBG("Error: Unsupported functionality\n");
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
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Start DataCompression component */
        PRINT_DBG("cpaDcStartInstance\n");
        status = cpaDcStartInstance(
            dcInstHandle, numInterBuffLists, bufferInterArray);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependant.
         */
        sampleDcStartPolling(dcInstHandle);
        /*
         * We now populate the fields of the session operational data and create
         * the session.  Note that the size required to store a session is
         * implementation-dependent, so we query the API first to determine how
         * much memory to allocate, and then allocate that memory.
         */
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
        PRINT_DBG("cpaDcInitSession\n");
        status = cpaDcInitSession(
            dcInstHandle,
            sessionHdl, /* session memory */
            &sd,        /* session setup data */
            NULL, /* pContexBuffer not required for stateless operations */
            dcCallback); /* callback function */
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform Compression operation */
        status = compPerformOp(dcInstHandle, sessionHdl, sd);

        /*
         * In a typical usage, the session might be used to compression
         * multiple buffers.  In this example however, we can now
         * tear down the session.
         */
        PRINT_DBG("cpaDcRemoveSession\n");
        sessionStatus = cpaDcRemoveSession(dcInstHandle, sessionHdl);

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

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionHdl);

    /* Free intermediate buffer */
    if (bufferInterArray != NULL)
    {
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pBuffers->pData);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pBuffers);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pPrivateMetaData);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]);
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
