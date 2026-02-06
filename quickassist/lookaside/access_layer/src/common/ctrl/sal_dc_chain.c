
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

    status = Sal_StringParsing(SAL_CFG_DC,
                               pCompService->generic_service_info.instance,
                               SAL_CFG_SYM_POOL,
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

    status = Sal_StringParsing(SAL_CFG_DC,
                               pCompService->generic_service_info.instance,
                               SAL_CFG_CHAIN_COOKIE_POOL,
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

    status = Sal_StringParsing(SAL_CFG_DC,
                               pCompService->generic_service_info.instance,
                               SAL_CFG_CHAIN_DESC_POOL,
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
