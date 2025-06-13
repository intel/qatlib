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
