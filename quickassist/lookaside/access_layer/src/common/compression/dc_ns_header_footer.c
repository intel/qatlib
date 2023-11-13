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
 * @file dc_ns_header_footer.c
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the No-Session (NS) variant of the Data Compression
 *      header and footer operations.
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include public/global header files
 *******************************************************************************
 */
#include "cpa.h"
#include "cpa_dc.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "dc_header_footer.h"
#include "dc_header_footer_lz4.h"
#include "dc_session.h"

typedef struct
{
    Cpa8U id1;
    Cpa8U id2;
    Cpa8U cm;
    Cpa8U fileFlags;
    Cpa8U timeStamp[4];
    Cpa8U compFlags;
    Cpa8U osId;
} gzip_hdr_t;

typedef struct
{
    Cpa8U compCmf;
    Cpa8U compFlags;
} zlib_hdr_t;

CpaStatus cpaDcNsGenerateHeader(CpaDcNsSetupData *pSetupData,
                                CpaFlatBuffer *pDestBuff,
                                Cpa32U *count)
{
    gzip_hdr_t *gzipHeader;
    zlib_hdr_t *zlibHeader;
    Cpa32U zlibLevel;
    Cpa32U headerSize;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%1x, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)pSetupData,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)count);
#endif

#ifdef ICP_PARAM_CHECK
    /* Check parameters */

    LAC_CHECK_NULL_PARAM(pSetupData);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(count);

    if (pSetupData->compType == CPA_DC_DEFLATE)
    {
        if (pSetupData->checksum != CPA_DC_CRC32 &&
            pSetupData->checksum != CPA_DC_ADLER32)
        {
            LAC_INVALID_PARAM_LOG("Invalid checksum type");

            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else if (pSetupData->compType == CPA_DC_LZ4)
    {
        if (pSetupData->checksum != CPA_DC_XXHASH32)
        {
            LAC_INVALID_PARAM_LOG("Invalid checksum type");

            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        LAC_INVALID_PARAM_LOG("Invalid compression type");

        return CPA_STATUS_INVALID_PARAM;
    }

    if (pSetupData->compLevel < CPA_DC_L1 || pSetupData->compLevel > CPA_DC_L12)
    {
        LAC_INVALID_PARAM_LOG("Invalid compression level");

        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    switch (pSetupData->checksum)
    {
        case CPA_DC_CRC32:
            headerSize = DC_GZIP_HEADER_SIZE;
            break;
        case CPA_DC_ADLER32:
            headerSize = DC_ZLIB_HEADER_SIZE;
            break;
        case CPA_DC_XXHASH32:
            headerSize = DC_LZ4_HEADER_SIZE;
            break;
        default:
            LAC_INVALID_PARAM_LOG("Invalid checksum type");
            return CPA_STATUS_INVALID_PARAM;
    }

#ifdef ICP_PARAM_CHECK
    if (pDestBuff->dataLenInBytes < headerSize)
    {
        LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer is too "
                              "small");

        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (pSetupData->checksum == CPA_DC_CRC32)
    {
        gzipHeader = (gzip_hdr_t *)pDestBuff->pData;
        memset(gzipHeader, 0, sizeof(gzip_hdr_t));

        /* Adding a Gzip header */
        gzipHeader->id1 = DC_GZIP_ID1;
        gzipHeader->id2 = DC_GZIP_ID2;
        gzipHeader->cm = 0x08;
        /* OS = 0 means FAT filesystem (MS-DOS, OS/2, NT/Win32), 3 - Unix */
        gzipHeader->osId = DC_GZIP_FILESYSTYPE;

        /* XFL = 4 - compressor used fastest compression, */
        /* XFL = 2 - compressor used maximum compression. */
        if (pSetupData->compLevel == CPA_DC_L1)
            gzipHeader->compFlags = DC_GZIP_FAST_COMP;
        else
            gzipHeader->compFlags = DC_GZIP_MAX_COMP;

        /* Set to the number of bytes added to the buffer */
        *count = headerSize;
    }
    else if (pSetupData->checksum == CPA_DC_ADLER32)
    {
        zlibHeader = (zlib_hdr_t *)pDestBuff->pData;

        /* Adding a Zlib header */

        /* CMF = CM | CMINFO.
         * CM = 8 denotes "deflate" compression,
         * CMINFO = 7 indicates a 32K window size */

        /* Depending on the device, at compression levels above L1, the window
         * size can be 8 or 16K bytes. The file will decompress ok if a greater
         * window size is specified in the header. */
        zlibHeader->compCmf = DC_ZLIB_CM_DEFLATE +
                              (DC_32K_WINDOW_SIZE << DC_ZLIB_WINDOWSIZE_OFFSET);

        switch (pSetupData->compLevel)
        {
            case CPA_DC_L1:
                zlibLevel = DC_ZLIB_LEVEL_0;
                break;
            case CPA_DC_L2:
                zlibLevel = DC_ZLIB_LEVEL_1;
                break;
            case CPA_DC_L3:
                zlibLevel = DC_ZLIB_LEVEL_2;
                break;
            default:
                zlibLevel = DC_ZLIB_LEVEL_3;
        }

        /* Bits 6 - 7: FLEVEL, compression level */
        zlibHeader->compFlags = zlibLevel << DC_ZLIB_FLEVEL_OFFSET;

        /* The header has to be a multiple of 31 */
        zlibHeader->compFlags |=
            DC_ZLIB_HEADER_OFFSET -
            ((zlibHeader->compCmf << LAC_NUM_BITS_IN_BYTE) + zlibHeader->compFlags) %
             DC_ZLIB_HEADER_OFFSET;

        /* Set to the number of bytes added to the buffer */
        *count = headerSize;
    }
    else
    {
        return dc_lz4_generate_header(pDestBuff,
                                      pSetupData->lz4BlockMaxSize,
                                      pSetupData->lz4BlockIndependence,
                                      count);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcNsGenerateFooter(CpaDcNsSetupData *pSetupData,
                                Cpa64U totalLength,
                                CpaFlatBuffer *pDestBuff,
                                CpaDcRqResults *pResults)
{
    CpaStatus ret;
    Cpa8U *pDest;
    Cpa32U crc32;
    Cpa32U adler32;
    Cpa32U footerSize;

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%1x, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)pSetupData,
             (LAC_ARCH_UINT)totalLength,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pResults);
#endif

#ifdef ICP_PARAM_CHECK
    /* Check parameters */

    LAC_CHECK_NULL_PARAM(pSetupData);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(pResults);

    if (pSetupData->compType == CPA_DC_DEFLATE)
    {
        if (pSetupData->checksum != CPA_DC_CRC32 &&
            pSetupData->checksum != CPA_DC_ADLER32)
        {
            LAC_INVALID_PARAM_LOG("Invalid checksum type");

            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else if (pSetupData->compType == CPA_DC_LZ4)
    {
        if (pSetupData->checksum != CPA_DC_XXHASH32)
        {
            LAC_INVALID_PARAM_LOG("Invalid checksum type");

            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        LAC_INVALID_PARAM_LOG("Invalid compression type");

        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    switch (pSetupData->checksum)
    {
        case CPA_DC_CRC32:
            footerSize = DC_GZIP_FOOTER_SIZE;
            break;
        case CPA_DC_ADLER32:
            footerSize = DC_ZLIB_FOOTER_SIZE;
            break;
        case CPA_DC_XXHASH32:
            footerSize = DC_LZ4_FOOTER_SIZE;
            break;
        default:
            LAC_INVALID_PARAM_LOG("Invalid checksum type");
            return CPA_STATUS_INVALID_PARAM;
    }

#ifdef ICP_PARAM_CHECK
    if (pDestBuff->dataLenInBytes < footerSize)
    {
        LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer is too "
                              "small");

        return CPA_STATUS_INVALID_PARAM;
    }

    if (UINT32_MAX - pResults->produced < footerSize)
    {
        LAC_INVALID_PARAM_LOG("Footer size will make produced byte counter "
                              "overflow");

        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pDest = pDestBuff->pData;

    if (pSetupData->checksum == CPA_DC_CRC32)
    {
        crc32 = pResults->checksum;

        /* Crc32 of the uncompressed data */
        pDest[0] = (Cpa8U)crc32;
        pDest[1] = (Cpa8U)(crc32 >> LAC_NUM_BITS_IN_BYTE);
        pDest[2] = (Cpa8U)(crc32 >> 2 * LAC_NUM_BITS_IN_BYTE);
        pDest[3] = (Cpa8U)(crc32 >> 3 * LAC_NUM_BITS_IN_BYTE);

        /* Length of the uncompressed data */
        pDest[4] = (Cpa8U)totalLength;
        pDest[5] = (Cpa8U)(totalLength >> LAC_NUM_BITS_IN_BYTE);
        pDest[6] = (Cpa8U)(totalLength >> 2 * LAC_NUM_BITS_IN_BYTE);
        pDest[7] = (Cpa8U)(totalLength >> 3 * LAC_NUM_BITS_IN_BYTE);

        /* Increment produced by the number of bytes added to the buffer */
        pResults->produced += footerSize;
    }
    else if (pSetupData->checksum == CPA_DC_ADLER32)
    {
        adler32 = pResults->checksum;

        /* Adler32 of the uncompressed data */
        pDest[0] = (Cpa8U)(adler32 >> 3 * LAC_NUM_BITS_IN_BYTE);
        pDest[1] = (Cpa8U)(adler32 >> 2 * LAC_NUM_BITS_IN_BYTE);
        pDest[2] = (Cpa8U)(adler32 >> LAC_NUM_BITS_IN_BYTE);
        pDest[3] = (Cpa8U)adler32;

        /* Increment produced by the number of bytes added to the buffer */
        pResults->produced += footerSize;
    }
    else if (pSetupData->checksum == CPA_DC_XXHASH32)
    {
        ret = dc_lz4_generate_footer(pDestBuff, pResults);

        if (ret != CPA_STATUS_SUCCESS)
            return ret;

        pResults->produced += footerSize;
    }

    return CPA_STATUS_SUCCESS;
}
