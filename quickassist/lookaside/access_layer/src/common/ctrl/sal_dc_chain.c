
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
 * @file sal_dc_chain.c
 *
 * @ingroup SalCtrl
 *
 * @description
 *      This file contains the sal implementation of dc_chain.
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include public/global header files
 *******************************************************************************
 */
#include "cpa.h"
#include "cpa_dc.h"

#include "icp_qat_fw.h"
#include "icp_qat_fw_comp.h"
#include "icp_qat_hw.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "dc_session.h"
#include "dc_datapath.h"
#include "dc_chain.h"
#include "lac_mem_pools.h"
#include "sal_types_compression.h"
#include "lac_buffer_desc.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "sal_string_parse.h"
#include "lac_sym.h"

/*
 * @ingroup Dc_Chaining
 *     Frees resources (memory and transhandles) if allocated
 *
 * @param[in]  pChainService       Pointer to chaining service instance
 *
 * @retval none.
 */
STATIC void dcChainService_FreeResources(sal_dc_chain_service_t *pChainService)
{
    /* 1. Free memory pools if not NULL */
    Lac_MemPoolDestroy(pChainService->lac_sym_cookie_pool);
    pChainService->lac_sym_cookie_pool = LAC_MEM_POOL_INIT_POOL_ID;
    Lac_MemPoolDestroy(pChainService->dc_chain_cookie_pool);
    pChainService->dc_chain_cookie_pool = LAC_MEM_POOL_INIT_POOL_ID;
    Lac_MemPoolDestroy(pChainService->dc_chain_serv_resp_pool);
    pChainService->dc_chain_serv_resp_pool = LAC_MEM_POOL_INIT_POOL_ID;
    /* Free hash lookup table if allocated */
    if (NULL != pChainService->pLacHashLookupDefs)
    {
        LAC_OS_FREE(pChainService->pLacHashLookupDefs);
        pChainService->pLacHashLookupDefs = NULL;
    }
}

/**
 ***********************************************************************
 * @ingroup Dc_Chaining
 *   This macro verifies that the status is _SUCCESS
 *   If status is not _SUCCESS then Chaining Instance resources are
 *   freed before the function returns the error
 *
 * @param[in] status    status we are checking
 *
 *
 ******************************************************************************/
#define LAC_CHECK_STATUS_DC_CHAIN_INIT(status)                                 \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != status)                                      \
        {                                                                      \
            dcChainService_FreeResources(pChainService);                       \
            return status;                                                     \
        }                                                                      \
    } while (0)

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Initialize chaining service
 *
 * @description
 *      Initialize chaining service
 *
 * @param[in,out]       pCompService     Compression service
 * @param[out]          pChainService    Chaining service
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 *
 *****************************************************************************/
CpaStatus dcChainServiceInit(sal_compression_service_t *pCompService,
                             sal_dc_chain_service_t *pChainService)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    Cpa32U numCompConcurrentReq = 0;
    Cpa32U rspSize = 0;

    /* Chaining service is attached to compression service, the number of
     * concurrent requests is based on compression concurrent requests
     */
    numCompConcurrentReq =
        pCompService->maxNumCompConcurrentReq + SAL_BATCH_SUBMIT_FREE_SPACE + 1;

    pCompService->pDcChainService = NULL;
    pChainService->lac_sym_cookie_pool = LAC_MEM_POOL_INIT_POOL_ID;
    pChainService->dc_chain_cookie_pool = LAC_MEM_POOL_INIT_POOL_ID;
    pChainService->dc_chain_serv_resp_pool = LAC_MEM_POOL_INIT_POOL_ID;
    pChainService->pLacHashLookupDefs = NULL;

    status = Sal_StringParsing("Dc",
                               pCompService->generic_service_info.instance,
                               "SymPool",
                               temp_string);
    LAC_CHECK_STATUS(status);

    status = Lac_MemPoolCreate(&pChainService->lac_sym_cookie_pool,
                               temp_string,
                               numCompConcurrentReq,
                               sizeof(lac_sym_bulk_cookie_t),
                               LAC_64BYTE_ALIGNMENT,
                               CPA_FALSE,
                               pCompService->nodeAffinity);
    LAC_CHECK_STATUS_DC_CHAIN_INIT(status);

    /* Enable only ICP_QAT_HW_AUTH_MODE1 mode for hash operation */
    pChainService->qatHmacMode = ICP_QAT_HW_AUTH_MODE1;

    status = Sal_StringParsing("Dc",
                               pCompService->generic_service_info.instance,
                               "ChainCookiePool",
                               temp_string);
    LAC_CHECK_STATUS_DC_CHAIN_INIT(status);

    status = Lac_MemPoolCreate(&pChainService->dc_chain_cookie_pool,
                               temp_string,
                               numCompConcurrentReq,
                               sizeof(dc_chain_cookie_t),
                               LAC_64BYTE_ALIGNMENT,
                               CPA_FALSE,
                               pCompService->nodeAffinity);
    LAC_CHECK_STATUS_DC_CHAIN_INIT(status);

    rspSize = LAC_QAT_DC_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;

    status = Sal_StringParsing("Dc",
                               pCompService->generic_service_info.instance,
                               "ChainDescPool",
                               temp_string);
    LAC_CHECK_STATUS_DC_CHAIN_INIT(status);

    status = Lac_MemPoolCreate(&pChainService->dc_chain_serv_resp_pool,
                               temp_string,
                               numCompConcurrentReq * DC_CHAIN_MAX_LINK,
                               rspSize,
                               LAC_64BYTE_ALIGNMENT,
                               CPA_FALSE,
                               pCompService->nodeAffinity);
    LAC_CHECK_STATUS_DC_CHAIN_INIT(status);

    pCompService->pDcChainService = pChainService;
    status = LacSymQat_HashLookupInit(pCompService);
    LAC_CHECK_STATUS_DC_CHAIN_INIT(status);

    return status;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Shutdown chaining service
 *
 * @description
 *      Shutdown chaining service
 *
 * @param[in,out]       pCompService     Compression service
 * @param[in]           pChainService    Chaining service
 *
 * @retval none
 *
 *****************************************************************************/
void dcChainServiceShutdown(sal_compression_service_t *pCompService,
                            sal_dc_chain_service_t *pChainService)
{
    /* Free resources allocated for chaining */
    /* pChainService will be freed in SalCtrl_CompressionShutdown */
    dcChainService_FreeResources(pChainService);
}
