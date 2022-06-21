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
 * @file dc_header_footer.c
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the Data Compression header and footer operations.
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include public/global header files
 *******************************************************************************
 */
#include "cpa.h"
#include "cpa_dc.h"
#include "icp_adf_init.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "dc_header_footer.h"
#include "dc_header_footer_lz4.h"
#include "dc_session.h"
#include "dc_datapath.h"

CpaStatus cpaDcGenerateHeader(CpaDcSessionHandle pSessionHandle,
                              CpaFlatBuffer *pDestBuff,
                              Cpa32U *count)
{
    dc_session_desc_t *pSessionDesc = NULL;

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(count);
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    if (NULL == pSessionDesc)
    {
        LAC_INVALID_PARAM_LOG("Session handle not as expected");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid session direction");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (CPA_DC_DEFLATE == pSessionDesc->compType)
    {
        /* Adding a Gzip header */
        if (CPA_DC_CRC32 == pSessionDesc->checksumType)
        {
            Cpa8U *pDest = pDestBuff->pData;

#ifdef ICP_PARAM_CHECK
            if (pDestBuff->dataLenInBytes < DC_GZIP_HEADER_SIZE)
            {
                LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer "
                                      "is too small");
                return CPA_STATUS_INVALID_PARAM;
            }
#endif

            pDest[0] = DC_GZIP_ID1; /* ID1 */
            pDest[1] = DC_GZIP_ID2; /* ID2 */
            pDest[2] = 0x08;        /* CM = 8 denotes "deflate" compression */
            pDest[3] = 0x00;        /* FLG = 0 denotes "No extra fields" */
            pDest[4] = 0x00;
            pDest[5] = 0x00;
            pDest[6] = 0x00;
            pDest[7] = 0x00; /* MTIME = 0x00 means time stamp not available */

            /* XFL = 4 - compressor used fastest compression, */
            /* XFL = 2 - compressor used maximum compression. */
            pDest[8] = 0;
            if (CPA_DC_L1 == pSessionDesc->compLevel)
                pDest[8] = DC_GZIP_FAST_COMP;
            else
                pDest[8] = DC_GZIP_MAX_COMP;

            pDest[9] = DC_GZIP_FILESYSTYPE; /* OS = 0 means FAT filesystem
                             (MS-DOS, OS/2, NT/Win32), 3 - Unix */

            /* Set to the number of bytes added to the buffer */
            *count = DC_GZIP_HEADER_SIZE;
        }

        /* Adding a Zlib header */
        else if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
        {
            Cpa8U *pDest = pDestBuff->pData;
            Cpa16U header = 0, level = 0;

#ifdef ICP_PARAM_CHECK
            if (pDestBuff->dataLenInBytes < DC_ZLIB_HEADER_SIZE)
            {
                LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer "
                                      "is too small");
                return CPA_STATUS_INVALID_PARAM;
            }
#endif

            /*  CMF = CM | CMINFO.
                CM = 8 denotes "deflate" compression,
                CMINFO = 7 indicates a 32K window size */
            /* Depending on the device, at compression levels above L1, the
               window size can be 8 or 16K bytes.
               The file will decompress ok if a greater window size is specified
               in the header. */
            header = (DC_ZLIB_CM_DEFLATE +
                      (DC_32K_WINDOW_SIZE << DC_ZLIB_WINDOWSIZE_OFFSET))
                     << LAC_NUM_BITS_IN_BYTE;

            switch (pSessionDesc->compLevel)
            {
                case CPA_DC_L1:
                    level = DC_ZLIB_LEVEL_0;
                    break;
                case CPA_DC_L2:
                    level = DC_ZLIB_LEVEL_1;
                    break;
                case CPA_DC_L3:
                    level = DC_ZLIB_LEVEL_2;
                    break;
                default:
                    level = DC_ZLIB_LEVEL_3;
            }

            /* Bits 6 - 7: FLEVEL, compression level */
            header |= level << DC_ZLIB_FLEVEL_OFFSET;

            /* The header has to be a multiple of 31 */
            header += DC_ZLIB_HEADER_OFFSET - (header % DC_ZLIB_HEADER_OFFSET);

            pDest[0] = (Cpa8U)(header >> LAC_NUM_BITS_IN_BYTE);
            pDest[1] = (Cpa8U)header;

            /* Set to the number of bytes added to the buffer */
            *count = DC_ZLIB_HEADER_SIZE;
        }

        /* If deflate but no checksum required */
        else
        {
            *count = 0;
        }
    }
    else if (CPA_DC_LZ4 == pSessionDesc->compType)
    {
        CpaStatus ret;
        ret = dc_lz4_generate_header(pDestBuff,
                                     pSessionDesc->lz4BlockMaxSize,
                                     pSessionDesc->lz4BlockIndependence,
                                     count);
        if (CPA_STATUS_SUCCESS != ret)
            return ret;
    }
    else
    {
        /* There is no header for other compressed data */
        *count = 0;
    }
#ifdef ICP_TRACE
    if (NULL == count)
    {
        LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
                 (LAC_ARCH_UINT)pSessionHandle,
                 (LAC_ARCH_UINT)pDestBuff,
                 (LAC_ARCH_UINT)count);
    }
    else
    {
        LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
                 (LAC_ARCH_UINT)pSessionHandle,
                 (LAC_ARCH_UINT)pDestBuff,
                 (LAC_ARCH_UINT)count,
                 *count);
    }
#endif
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcGenerateFooter(CpaDcSessionHandle pSessionHandle,
                              CpaFlatBuffer *pDestBuff,
                              CpaDcRqResults *pRes)
{
    dc_session_desc_t *pSessionDesc = NULL;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pRes);
#endif

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(pRes);
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    if (NULL == pSessionDesc)
    {
        LAC_INVALID_PARAM_LOG("Session handle not as expected");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid session direction");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (CPA_DC_DEFLATE == pSessionDesc->compType)
    {
        if (CPA_DC_CRC32 == pSessionDesc->checksumType)
        {
            Cpa8U *pDest = pDestBuff->pData;
            Cpa32U crc32 = pRes->checksum;
            Cpa64U totalLenBeforeCompress =
                pSessionDesc->cumulativeConsumedBytes;

#ifdef ICP_PARAM_CHECK
            if (pDestBuff->dataLenInBytes < DC_GZIP_FOOTER_SIZE)
            {
                LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer "
                                      "is too small");
                return CPA_STATUS_INVALID_PARAM;
            }
#endif

            /* Crc32 of the uncompressed data */
            pDest[0] = (Cpa8U)crc32;
            pDest[1] = (Cpa8U)(crc32 >> LAC_NUM_BITS_IN_BYTE);
            pDest[2] = (Cpa8U)(crc32 >> 2 * LAC_NUM_BITS_IN_BYTE);
            pDest[3] = (Cpa8U)(crc32 >> 3 * LAC_NUM_BITS_IN_BYTE);

            /* Length of the uncompressed data */
            pDest[4] = (Cpa8U)totalLenBeforeCompress;
            pDest[5] = (Cpa8U)(totalLenBeforeCompress >> LAC_NUM_BITS_IN_BYTE);
            pDest[6] =
                (Cpa8U)(totalLenBeforeCompress >> 2 * LAC_NUM_BITS_IN_BYTE);
            pDest[7] =
                (Cpa8U)(totalLenBeforeCompress >> 3 * LAC_NUM_BITS_IN_BYTE);

            /* Increment produced by the number of bytes added to the buffer */
            pRes->produced += DC_GZIP_FOOTER_SIZE;
        }
        else if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
        {
            Cpa8U *pDest = pDestBuff->pData;
            Cpa32U adler32 = pRes->checksum;

#ifdef ICP_PARAM_CHECK
            if (pDestBuff->dataLenInBytes < DC_ZLIB_FOOTER_SIZE)
            {
                LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer "
                                      "is too small");
                return CPA_STATUS_INVALID_PARAM;
            }
#endif

            /* Adler32 of the uncompressed data */
            pDest[0] = (Cpa8U)(adler32 >> 3 * LAC_NUM_BITS_IN_BYTE);
            pDest[1] = (Cpa8U)(adler32 >> 2 * LAC_NUM_BITS_IN_BYTE);
            pDest[2] = (Cpa8U)(adler32 >> LAC_NUM_BITS_IN_BYTE);
            pDest[3] = (Cpa8U)adler32;

            /* Increment produced by the number of bytes added to the buffer */
            pRes->produced += DC_ZLIB_FOOTER_SIZE;
        }
    }
    else if (CPA_DC_LZ4 == pSessionDesc->compType)
    {
        CpaStatus ret;
        ret = dc_lz4_generate_footer(pDestBuff, pRes);
        if (CPA_STATUS_SUCCESS != ret)
            return ret;
        pRes->produced += DC_LZ4_FOOTER_SIZE;
    }

    return CPA_STATUS_SUCCESS;
}
