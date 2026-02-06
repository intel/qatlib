/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
