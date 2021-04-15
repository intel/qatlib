/****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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

/**
 *****************************************************************************
 * @file dc_buffers.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the buffer management operations for
 *      Data Compression service.
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_dc.h"

#include "sal_types_compression.h"
#include "icp_qat_fw_comp.h"

#define CPA_DC_CEIL_DIV(x, y) (((x) + (y)-1) / (y))
#define DC_DEST_BUFF_EXTRA_DEFLATE_GEN2 (55)

CpaStatus cpaDcBufferListGetMetaSize(const CpaInstanceHandle instanceHandle,
                                     Cpa32U numBuffers,
                                     Cpa32U *pSizeInBytes)
{
#ifdef ICP_PARAM_CHECK
    CpaInstanceHandle insHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = instanceHandle;
    }

    LAC_CHECK_INSTANCE_HANDLE(insHandle);
    LAC_CHECK_NULL_PARAM(pSizeInBytes);

    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);

    if (0 == numBuffers)
    {
        LAC_INVALID_PARAM_LOG("Number of Buffers");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    *pSizeInBytes = (sizeof(icp_buffer_list_desc_t) +
                     (sizeof(icp_flat_buffer_desc_t) * (numBuffers + 1)) +
                     ICP_DESCRIPTOR_ALIGNMENT_BYTES);

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, %d, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             numBuffers,
             (LAC_ARCH_UINT)pSizeInBytes,
             *pSizeInBytes);
#endif

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcBnpBufferListGetMetaSize(const CpaInstanceHandle instanceHandle,
                                        Cpa32U numJobs,
                                        Cpa32U *pSizeInBytes)
{
    LAC_UNUSED_VARIABLE(instanceHandle);
    LAC_UNUSED_VARIABLE(numJobs);
    LAC_UNUSED_VARIABLE(pSizeInBytes);

    return CPA_STATUS_UNSUPPORTED;
}

STATIC inline CpaStatus dcDeflateBoundGen2(CpaDcHuffType huffType,
                                           Cpa32U inputSize,
                                           Cpa32U *outputSize)
{
    /* Formula for GEN2 deflate:
     * ceil(9 * Total input bytes / 8) + 55 bytes.
     * 55 bytes is the skid pad value for GEN2 devices.
     */
    *outputSize =
        CPA_DC_CEIL_DIV(9 * inputSize, 8) + DC_DEST_BUFF_EXTRA_DEFLATE_GEN2;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcDeflateCompressBound(const CpaInstanceHandle dcInstance,
                                    CpaDcHuffType huffType,
                                    Cpa32U inputSize,
                                    Cpa32U *outputSize)
{
#ifdef ICP_PARAM_CHECK
    CpaInstanceHandle insHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    LAC_CHECK_INSTANCE_HANDLE(insHandle);
    LAC_CHECK_NULL_PARAM(outputSize);
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    if (!inputSize)
    {
        LAC_INVALID_PARAM_LOG("The input size needs to be greater than zero");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((CPA_DC_HT_STATIC != huffType) && (CPA_DC_HT_FULL_DYNAMIC != huffType))
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    return dcDeflateBoundGen2(huffType, inputSize, outputSize);
}
