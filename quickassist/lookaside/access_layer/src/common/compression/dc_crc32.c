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

/**
 *****************************************************************************
 * @file dc_crc32.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the CRC-32 operations.
 *
 *****************************************************************************/

#include "dc_crc32.h"

/**
 * @description
 *     Calculates CRC-32 checksum for given Buffer List
 *
 *     Function loop through all of the flat buffers in the buffer list.
 *     CRC is calculated for each flat buffer, but output CRC from
 *     buffer[0] is used as input seed for buffer[1] CRC calculation
 *     (and so on until looped through all flat buffers).
 *     Resulting CRC is final CRC for all buffers in the buffer list struct
 *
 * @param[in]  bufferList      Pointer to data byte array to calculate CRC on
 * @param[in]  consumedBytes   Total number of bytes to calculate CRC on
 *                             (for all buffer in buffer list)
 * @param[in]  seedChecksums   Input checksum from where the calculation will
 *                             start from.
 *
 * @retval Cpa32U              32bit long CRC checksum for given buffer list
 */
Cpa32U dcCalculateCrc32(CpaBufferList *pBufferList,
                        Cpa32U consumedBytes,
                        const Cpa32U seedChecksum)
{
    Cpa32U i = 0;
    Cpa64U computeLength = 0;
    Cpa32U flatBufferLength = 0;
    Cpa32U currentCrc = seedChecksum;
    CpaFlatBuffer *pBuffer = NULL;

    LAC_ENSURE_NOT_NULL(pBufferList);

    pBuffer = &pBufferList->pBuffers[0];

    for (i = 0; i < pBufferList->numBuffers; i++)
    {
        flatBufferLength = pBuffer->dataLenInBytes;

        /* Get number of bytes based on remaining data (consumedBytes) and
         * max buffer length, then calculate CRC on them */
        if (consumedBytes > flatBufferLength)
        {
            computeLength = flatBufferLength;
            consumedBytes -= flatBufferLength;
        }
        else
        {
            computeLength = consumedBytes;
            consumedBytes = 0;
        }
#ifdef USE_CCODE_CRC
        currentCrc =
            crc32_gzip_refl_base(currentCrc, pBuffer->pData, computeLength);
#else
        currentCrc =
            crc32_gzip_refl_by8(currentCrc, pBuffer->pData, computeLength);
#endif
        pBuffer++;
    }

    return currentCrc;
}
