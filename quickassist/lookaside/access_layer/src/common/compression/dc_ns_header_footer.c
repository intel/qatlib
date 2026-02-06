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

CpaStatus cpaDcNsGenerateHeader(CpaDcNsSetupData *pSetupData,
                                CpaFlatBuffer *pDestBuff,
                                Cpa32U *count)
{
    CpaStatus ret = CPA_STATUS_FAIL;

#ifdef ICP_TRACE
    if (NULL == count)
    {
        LAC_LOG3("Called with params (0x%1x, 0x%lx, 0x%lx)\n",
                 (LAC_ARCH_UINT)pSetupData,
                 (LAC_ARCH_UINT)pDestBuff,
                 (LAC_ARCH_UINT)count);
    }
    else
    {
        LAC_LOG4("Called with params (0x%1x, 0x%lx, 0x%lx[%d])\n",
                 (LAC_ARCH_UINT)pSetupData,
                 (LAC_ARCH_UINT)pDestBuff,
                 (LAC_ARCH_UINT)count,
                 *count);
    }
#endif
#ifdef ICP_PARAM_CHECK
    /* Check parameters */
    LAC_CHECK_NULL_PARAM(pSetupData);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff->pData);
    LAC_CHECK_NULL_PARAM(count);

    if (pSetupData->compLevel < CPA_DC_L1 || pSetupData->compLevel > CPA_DC_L12)
    {
        LAC_INVALID_PARAM_LOG("Invalid compression level");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    switch (pSetupData->compType)
    {
        case CPA_DC_DEFLATE:
            ret = dcDeflateGenerateHeader(
                pDestBuff, pSetupData->checksum, pSetupData->compLevel, count);
            if (CPA_STATUS_SUCCESS != ret)
                return ret;
            break;
        case CPA_DC_LZ4:
            if (CPA_DC_XXHASH32 == pSetupData->checksum)
            {
                ret = dc_lz4_generate_header(pDestBuff,
                                             pSetupData->lz4BlockMaxSize,
                                             pSetupData->lz4BlockIndependence,
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

CpaStatus cpaDcNsGenerateFooter(CpaDcNsSetupData *pSetupData,
                                Cpa64U totalLength,
                                CpaFlatBuffer *pDestBuff,
                                CpaDcRqResults *pResults)
{
    CpaStatus ret = CPA_STATUS_FAIL;

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
#endif

    switch (pSetupData->compType)
    {
        case CPA_DC_DEFLATE:
            ret = dcDeflateGenerateFooter(
                pDestBuff, pResults, totalLength, pSetupData->checksum);
            if (CPA_STATUS_SUCCESS != ret)
                return ret;
            break;
        case CPA_DC_LZ4:
            if (CPA_DC_XXHASH32 == pSetupData->checksum)
            {
                ret = dc_lz4_generate_footer(pDestBuff, pResults);
                if (ret != CPA_STATUS_SUCCESS)
                    return ret;
                pResults->produced += DC_LZ4_FOOTER_SIZE;
            }
            break;
        default:
            LAC_INVALID_PARAM_LOG("Invalid compression type");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}
