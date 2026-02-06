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

CpaStatus dcDeflateGenerateHeader(CpaFlatBuffer *pDestBuff,
                                  CpaDcChecksum checksum,
                                  CpaDcCompLvl compLevel,
                                  Cpa32U *count)
{
    Cpa8U *pDest = NULL;
    Cpa16U header = 0, level = 0;

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(count);
#endif

    /* Adding a Gzip header */
    if (CPA_DC_CRC32 == checksum)
    {
        pDest = pDestBuff->pData;

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
        if (CPA_DC_L1 == compLevel)
            pDest[8] = DC_GZIP_FAST_COMP;
        else
            pDest[8] = DC_GZIP_MAX_COMP;

        pDest[9] = DC_GZIP_FILESYSTYPE; /* OS = 0 means FAT filesystem
                         (MS-DOS, OS/2, NT/Win32), 3 - Unix */

        /* Set to the number of bytes added to the buffer */
        *count = DC_GZIP_HEADER_SIZE;
    }

    /* Adding a Zlib header */
    else if (CPA_DC_ADLER32 == checksum)
    {
        pDest = pDestBuff->pData;

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

        switch (compLevel)
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

    return CPA_STATUS_SUCCESS;
}

CpaStatus dcDeflateGenerateFooter(CpaFlatBuffer *pDestBuff,
                                  CpaDcRqResults *pResults,
                                  Cpa64U totalLength,
                                  CpaDcChecksum checksum)
{
    Cpa8U *pDest = NULL;
    Cpa32U crc32 = 0;
    Cpa32U adler32 = 0;

#ifdef ICP_PARAM_CHECK
    /* Check parameters */
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(pResults);
#endif

    pDest = pDestBuff->pData;
    if (CPA_DC_CRC32 == checksum)
    {
#ifdef ICP_PARAM_CHECK
        if (pDestBuff->dataLenInBytes < DC_GZIP_FOOTER_SIZE)
        {
            LAC_INVALID_PARAM_LOG(
                "The dataLenInBytes of the destination buffer is too "
                "small");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (UINT32_MAX - pResults->produced < DC_GZIP_FOOTER_SIZE)
        {
            LAC_INVALID_PARAM_LOG("Footer size will make produced byte counter "
                                  "overflow");
            return CPA_STATUS_INVALID_PARAM;
        }
#endif
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
        pResults->produced += DC_GZIP_FOOTER_SIZE;
    }
    else if (CPA_DC_ADLER32 == checksum)
    {
#ifdef ICP_PARAM_CHECK
        if (pDestBuff->dataLenInBytes < DC_ZLIB_FOOTER_SIZE)
        {
            LAC_INVALID_PARAM_LOG(
                "The dataLenInBytes of the destination buffer is too "
                "small");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (UINT32_MAX - pResults->produced < DC_ZLIB_FOOTER_SIZE)
        {
            LAC_INVALID_PARAM_LOG("Footer size will make produced byte counter "
                                  "overflow");
            return CPA_STATUS_INVALID_PARAM;
        }
#endif
        adler32 = pResults->checksum;

        /* Adler32 of the uncompressed data */
        pDest[0] = (Cpa8U)(adler32 >> 3 * LAC_NUM_BITS_IN_BYTE);
        pDest[1] = (Cpa8U)(adler32 >> 2 * LAC_NUM_BITS_IN_BYTE);
        pDest[2] = (Cpa8U)(adler32 >> LAC_NUM_BITS_IN_BYTE);
        pDest[3] = (Cpa8U)adler32;

        /* Increment produced value by the number of bytes added with the
         * footer */
        pResults->produced += DC_ZLIB_FOOTER_SIZE;
    }
    else
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum type");
        return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcGenerateHeader(CpaDcSessionHandle pSessionHandle,
                              CpaFlatBuffer *pDestBuff,
                              Cpa32U *count)
{
    dc_session_desc_t *pSessionDesc = NULL;
    CpaStatus ret = CPA_STATUS_FAIL;

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

    switch (pSessionDesc->compType)
    {
        case CPA_DC_DEFLATE:
            ret = dcDeflateGenerateHeader(pDestBuff,
                                          pSessionDesc->checksumType,
                                          pSessionDesc->compLevel,
                                          count);
            if (CPA_STATUS_SUCCESS != ret)
                return ret;
            break;
        case CPA_DC_LZ4:
            if (CPA_DC_XXHASH32 == pSessionDesc->checksumType)
            {
                ret = dc_lz4_generate_header(pDestBuff,
                                             pSessionDesc->lz4BlockMaxSize,
                                             pSessionDesc->lz4BlockIndependence,
                                             count);
                if (CPA_STATUS_SUCCESS != ret)
                    return ret;
            }
            break;
        default:
            /* There is no header for other compression formats */
            *count = 0;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcGenerateFooter(CpaDcSessionHandle pSessionHandle,
                              CpaFlatBuffer *pDestBuff,
                              CpaDcRqResults *pRes)
{
    dc_session_desc_t *pSessionDesc = NULL;
    CpaStatus ret = CPA_STATUS_FAIL;

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

    switch (pSessionDesc->compType)
    {
        case CPA_DC_DEFLATE:
            ret = dcDeflateGenerateFooter(pDestBuff,
                                          pRes,
                                          pSessionDesc->cumulativeConsumedBytes,
                                          pSessionDesc->checksumType);
            if (CPA_STATUS_SUCCESS != ret)
                return ret;
            break;
        case CPA_DC_LZ4:
            ret = dc_lz4_generate_footer(pDestBuff, pRes);
            if (CPA_STATUS_SUCCESS != ret)
                return ret;
            pRes->produced += DC_LZ4_FOOTER_SIZE;
            break;
        default:
            LAC_INVALID_PARAM_LOG("Invalid compression type\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    return CPA_STATUS_SUCCESS;
}
