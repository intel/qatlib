/******************************************************************************
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
 *****************************************************************************/

/**
 *****************************************************************************
 * @file lac_buffer_desc.c  Utility functions for setting buffer descriptors
 *
 * @ingroup LacBufferDesc
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include header files
*******************************************************************************
*/
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"
#include "icp_adf_init.h"
#include "lac_list.h"
#include "lac_sal_types.h"
#ifndef ICP_DC_DYN_NOT_SUPPORTED
#include "icp_buffer_desc.h"
#endif
#include "lac_mem.h"
#include "cpa_cy_common.h"
#include "dc_session.h"
#include "sal_misc_error_stats.h"

/*
*******************************************************************************
* Define public/global function definitions
*******************************************************************************
*/
/* Invalid physical address value */
#define INVALID_PHYSICAL_ADDRESS 0

/* Indicates what type of buffer writes need to be perfomed */
typedef enum lac_buff_write_op_e
{
    WRITE_NORMAL = 0,
    WRITE_AND_GET_SIZE,
    WRITE_AND_ALLOW_ZERO_BUFFER,
} lac_buff_write_op_t;

/* This function implements the buffer description writes for the traditional
 * APIs */
STATIC CpaStatus
LacBuffDesc_CommonBufferListDescWrite(const CpaBufferList *pUserBufferList,
                                      Cpa64U *pBufListAlignedPhyAddr,
                                      CpaBoolean isPhysicalAddress,
                                      Cpa64U *totalDataLenInBytes,
                                      sal_service_t *pService,
                                      lac_buff_write_op_t operationType)
{
    Cpa32U numBuffers = 0;
    icp_qat_addr_width_t bufListDescPhyAddr = 0;
    icp_qat_addr_width_t bufListAlignedPhyAddr = 0;
    CpaFlatBuffer *pCurrClientFlatBuffer = NULL;
    icp_buffer_list_desc_t *pBufferListDesc = NULL;
    icp_flat_buffer_desc_t *pCurrFlatBufDesc = NULL;

    LAC_ENSURE_NOT_NULL(pUserBufferList);
    LAC_ENSURE_NOT_NULL(pUserBufferList->pBuffers);
    LAC_ENSURE_NOT_NULL(pUserBufferList->pPrivateMetaData);
    LAC_ENSURE_NOT_NULL(pBufListAlignedPhyAddr);

    if (WRITE_AND_GET_SIZE == operationType)
    {
        LAC_ENSURE_NOT_NULL(totalDataLenInBytes);
        *totalDataLenInBytes = 0;
    }

    numBuffers = pUserBufferList->numBuffers;
    pCurrClientFlatBuffer = pUserBufferList->pBuffers;

    /*
     * Get the physical address of this descriptor - need to offset by the
     * alignment restrictions on the buffer descriptors
     */
    bufListDescPhyAddr = (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        (*pService), pUserBufferList->pPrivateMetaData);

    if (INVALID_PHYSICAL_ADDRESS == bufListDescPhyAddr)
    {
        LAC_LOG_ERROR("Unable to get the physical address of the metadata\n");
        return CPA_STATUS_FAIL;
    }

    bufListAlignedPhyAddr = LAC_ALIGN_POW2_ROUNDUP(
        bufListDescPhyAddr, ICP_DESCRIPTOR_ALIGNMENT_BYTES);

    pBufferListDesc = (icp_buffer_list_desc_t *)(LAC_ARCH_UINT)(
        (LAC_ARCH_UINT)pUserBufferList->pPrivateMetaData +
        ((LAC_ARCH_UINT)bufListAlignedPhyAddr -
         (LAC_ARCH_UINT)bufListDescPhyAddr));

    /* Go past the Buffer List descriptor to the list of buffer descriptors */
    pCurrFlatBufDesc =
        (icp_flat_buffer_desc_t *)((pBufferListDesc->phyBuffers));

    pBufferListDesc->numBuffers = numBuffers;

    if (WRITE_AND_GET_SIZE != operationType)
    {
        /* Defining zero buffers is useful for example if running zero length
         * hash */
        if (0 == numBuffers)
        {
            /* In the case where there are zero buffers within the BufList
             * it is required by firmware that the number is set to 1
             * but the phyBuffer and dataLenInBytes are set to NULL.*/
            pBufferListDesc->numBuffers = 1;
            pCurrFlatBufDesc->dataLenInBytes = 0;
            pCurrFlatBufDesc->phyBuffer = 0;
        }
    }

    while (0 != numBuffers)
    {
        pCurrFlatBufDesc->dataLenInBytes =
            pCurrClientFlatBuffer->dataLenInBytes;

        if (WRITE_AND_GET_SIZE == operationType)
        {
            /* Calculate the total data length in bytes */
            *totalDataLenInBytes += pCurrClientFlatBuffer->dataLenInBytes;
        }

        /* Check if providing a physical address in the function. If not we
         * need to convert it to a physical one */
        if (CPA_TRUE == isPhysicalAddress)
        {
            pCurrFlatBufDesc->phyBuffer = LAC_MEM_CAST_PTR_TO_UINT64(
                (LAC_ARCH_UINT)(pCurrClientFlatBuffer->pData));
        }
        else
        {
            pCurrFlatBufDesc->phyBuffer =
                LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
                    (*pService), pCurrClientFlatBuffer->pData));

            if (WRITE_AND_ALLOW_ZERO_BUFFER != operationType)
            {
                if (INVALID_PHYSICAL_ADDRESS == pCurrFlatBufDesc->phyBuffer)
                {
                    LAC_LOG_ERROR("Unable to get the physical address of the "
                                  "client buffer\n");
                    return CPA_STATUS_FAIL;
                }
            }
        }

        pCurrFlatBufDesc++;
        pCurrClientFlatBuffer++;

        numBuffers--;
    }

    *pBufListAlignedPhyAddr = bufListAlignedPhyAddr;
    return CPA_STATUS_SUCCESS;
}

/* This function implements the buffer description writes for the traditional
 * APIs Zero length buffers are allowed, should be used for CHA-CHA-POLY and
 * GCM aglorithms */
CpaStatus LacBuffDesc_BufferListDescWriteAndAllowZeroBuffer(
    const CpaBufferList *pUserBufferList,
    Cpa64U *pBufListAlignedPhyAddr,
    CpaBoolean isPhysicalAddress,
    sal_service_t *pService)
{
    return LacBuffDesc_CommonBufferListDescWrite(pUserBufferList,
                                                 pBufListAlignedPhyAddr,
                                                 isPhysicalAddress,
                                                 NULL,
                                                 pService,
                                                 WRITE_AND_ALLOW_ZERO_BUFFER);
}

/* This function implements the buffer description writes for the traditional
 * APIs */
CpaStatus LacBuffDesc_BufferListDescWrite(const CpaBufferList *pUserBufferList,
                                          Cpa64U *pBufListAlignedPhyAddr,
                                          CpaBoolean isPhysicalAddress,
                                          sal_service_t *pService)
{
    return LacBuffDesc_CommonBufferListDescWrite(pUserBufferList,
                                                 pBufListAlignedPhyAddr,
                                                 isPhysicalAddress,
                                                 NULL,
                                                 pService,
                                                 WRITE_NORMAL);
}

/* This function does the same processing as LacBuffDesc_BufferListDescWrite
 * but calculate as well the total length in bytes of the buffer list. */
CpaStatus LacBuffDesc_BufferListDescWriteAndGetSize(
    const CpaBufferList *pUserBufferList,
    Cpa64U *pBufListAlignedPhyAddr,
    CpaBoolean isPhysicalAddress,
    Cpa64U *totalDataLenInBytes,
    sal_service_t *pService)
{
    return LacBuffDesc_CommonBufferListDescWrite(pUserBufferList,
                                                 pBufListAlignedPhyAddr,
                                                 isPhysicalAddress,
                                                 totalDataLenInBytes,
                                                 pService,
                                                 WRITE_AND_GET_SIZE);
}

CpaStatus LacBuffDesc_FlatBufferVerify(
    const CpaFlatBuffer *pUserFlatBuffer,
    Cpa64U *pPktSize,
    lac_aligment_shift_t alignmentShiftExpected)
{
    LAC_CHECK_NULL_PARAM(pUserFlatBuffer);
    LAC_ENSURE_NOT_NULL(pPktSize);
    LAC_CHECK_NULL_PARAM(pUserFlatBuffer->pData);

    if (0 == pUserFlatBuffer->dataLenInBytes)
    {
        LAC_INVALID_PARAM_LOG("FlatBuffer empty");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Expected alignment */
    if (LAC_NO_ALIGNMENT_SHIFT != alignmentShiftExpected)
    {
        if (!LAC_ADDRESS_ALIGNED(pUserFlatBuffer->pData,
                                 alignmentShiftExpected))
        {
            LAC_INVALID_PARAM_LOG1("FlatBuffer not aligned as expected."
                                   " Expected alignment %u Bytes.",
                                   (uintptr_t)(1 << alignmentShiftExpected));
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    /* Update the total size of the packet. This function being called in a loop
     * for an entire buffer list we need to increment the value */
    *pPktSize += pUserFlatBuffer->dataLenInBytes;

    return CPA_STATUS_SUCCESS;
}

CpaStatus LacBuffDesc_FlatBufferVerifyNull(
    const CpaFlatBuffer *pUserFlatBuffer,
    Cpa64U *pPktSize,
    lac_aligment_shift_t alignmentShiftExpected)
{
    LAC_CHECK_NULL_PARAM(pUserFlatBuffer);
    LAC_ENSURE_NOT_NULL(pPktSize);

    if (0 != pUserFlatBuffer->dataLenInBytes)
    {
        LAC_CHECK_NULL_PARAM(pUserFlatBuffer->pData);
    }

    /* Expected alignment */
    if (LAC_NO_ALIGNMENT_SHIFT != alignmentShiftExpected)
    {
        if (!LAC_ADDRESS_ALIGNED(pUserFlatBuffer->pData,
                                 alignmentShiftExpected))
        {
            LAC_INVALID_PARAM_LOG1("FlatBuffer not aligned as expected."
                                   " Expected alignment %u Bytes.",
                                   (uintptr_t)(1 << alignmentShiftExpected));
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    /* Update the total size of the packet. This function being called in a loop
     * for an entire buffer list we need to increment the value */
    *pPktSize += pUserFlatBuffer->dataLenInBytes;

    return CPA_STATUS_SUCCESS;
}

CpaStatus LacBuffDesc_BufferListVerify(
    const CpaBufferList *pUserBufferList,
    Cpa64U *pPktSize,
    lac_aligment_shift_t alignmentShiftExpected)
{
    CpaFlatBuffer *pCurrClientFlatBuffer = NULL;
    Cpa32U numBuffers = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    LAC_CHECK_NULL_PARAM(pUserBufferList);
    LAC_CHECK_NULL_PARAM(pUserBufferList->pBuffers);
    LAC_ENSURE_NOT_NULL(pPktSize);
    LAC_CHECK_NULL_PARAM(pUserBufferList->pPrivateMetaData);

    numBuffers = pUserBufferList->numBuffers;

    if (0 == pUserBufferList->numBuffers)
    {
        LAC_INVALID_PARAM_LOG("Number of Buffers");
        return CPA_STATUS_INVALID_PARAM;
    }

    pCurrClientFlatBuffer = pUserBufferList->pBuffers;

    *pPktSize = 0;
    while (0 != numBuffers && status == CPA_STATUS_SUCCESS)
    {
        status = LacBuffDesc_FlatBufferVerify(
            pCurrClientFlatBuffer, pPktSize, alignmentShiftExpected);

        pCurrClientFlatBuffer++;
        numBuffers--;
    }
    return status;
}

CpaStatus LacBuffDesc_BufferListVerifyNull(
    const CpaBufferList *pUserBufferList,
    Cpa64U *pPktSize,
    lac_aligment_shift_t alignmentShiftExpected)
{
    CpaFlatBuffer *pCurrClientFlatBuffer = NULL;
    Cpa32U numBuffers = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    LAC_CHECK_NULL_PARAM(pUserBufferList);
    LAC_CHECK_NULL_PARAM(pUserBufferList->pBuffers);
    LAC_ENSURE_NOT_NULL(pPktSize);
    LAC_CHECK_NULL_PARAM(pUserBufferList->pPrivateMetaData);

    numBuffers = pUserBufferList->numBuffers;

    if (0 == numBuffers)
    {
        LAC_INVALID_PARAM_LOG("Number of Buffers");
        return CPA_STATUS_INVALID_PARAM;
    }

    pCurrClientFlatBuffer = pUserBufferList->pBuffers;

    *pPktSize = 0;
    while (0 != numBuffers && status == CPA_STATUS_SUCCESS)
    {
        status = LacBuffDesc_FlatBufferVerifyNull(
            pCurrClientFlatBuffer, pPktSize, alignmentShiftExpected);

        pCurrClientFlatBuffer++;
        numBuffers--;
    }
    return status;
}

/**
 ******************************************************************************
 * @ingroup LacBufferDesc
 *****************************************************************************/
void LacBuffDesc_BufferListTotalSizeGet(const CpaBufferList *pUserBufferList,
                                        Cpa64U *pPktSize)
{
    CpaFlatBuffer *pCurrClientFlatBuffer = NULL;
    Cpa32U numBuffers = 0;

    LAC_ENSURE_NOT_NULL(pUserBufferList);
    LAC_ENSURE_NOT_NULL(pPktSize);
    LAC_ENSURE_NOT_NULL(pUserBufferList->pBuffers);

    pCurrClientFlatBuffer = pUserBufferList->pBuffers;
    numBuffers = pUserBufferList->numBuffers;

    *pPktSize = 0;
    while (0 != numBuffers)
    {
        *pPktSize += pCurrClientFlatBuffer->dataLenInBytes;
        pCurrClientFlatBuffer++;
        numBuffers--;
    }
}

void LacBuffDesc_BufferListZeroFromOffset(CpaBufferList *pBuffList,
                                          Cpa32U offset,
                                          Cpa32U lenToZero)
{
    Cpa32U zeroLen = 0, sizeLeftToZero = 0;
    Cpa64U currentBufferSize = 0;
    CpaFlatBuffer *pBuffer = NULL;
    Cpa8U *pZero = NULL;
    pBuffer = pBuffList->pBuffers;

    /* Take a copy of total length to zero. */
    sizeLeftToZero = lenToZero;

    while (sizeLeftToZero > 0)
    {
        currentBufferSize = pBuffer->dataLenInBytes;
        /* check where to start zeroing */
        if (offset >= currentBufferSize)
        {
            /* Need to get to next buffer and reduce
             * offset size by data len of buffer */
            offset = offset - pBuffer->dataLenInBytes;
            pBuffer++;
        }
        else
        {
            /* Start to Zero from this position */
            pZero = (Cpa8U *)pBuffer->pData + offset;

            /* Need to calculate the correct number of bytes to zero
             * for this iteration and for this location.
             */
            if (sizeLeftToZero >= pBuffer->dataLenInBytes)
            {
                /* The size to zero is spanning buffers, zeroLen in
                 * this case is from pZero (position) to end of buffer.
                 */
                zeroLen = pBuffer->dataLenInBytes - offset;
            }
            else
            {
                /* zeroLen is set to sizeLeftToZero, then check if zeroLen and
                 * the offset is greater or equal to the size of the buffer, if
                 * yes, adjust the zeroLen to zero out the remainder of this
                 * buffer.
                 */
                zeroLen = sizeLeftToZero;
                if ((zeroLen + offset) >= pBuffer->dataLenInBytes)
                {
                    zeroLen = pBuffer->dataLenInBytes - offset;
                }
            } /* end inner else */
            osalMemSet((void *)pZero, 0, zeroLen);
            sizeLeftToZero = sizeLeftToZero - zeroLen;
            /* offset is no longer required as any data left to zero is now
             * at the start of the next buffer. set offset to zero and move on
             * the buffer pointer to the next buffer.
             */
            offset = 0;
            pBuffer++;

        } /* end outer else */

    } /* end while */
}
