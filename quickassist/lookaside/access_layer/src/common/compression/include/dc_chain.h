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
 * @file dc_chain.h
 *
 * @ingroup Dc_Chaining
 *
 * @description
 *      Definition of the data compression and crypto chaining parameters.
 *
 *****************************************************************************/
#ifndef DC_CHAIN_H
#define DC_CHAIN_H

#include "sal_types_compression.h"
#include "icp_qat_fw_dc_chain.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "cpa_dc_chain.h"
#include "lac_session.h"
#include "dc_session.h"

#define DC_CHAIN_TYPE_GET(pType) (*(CpaDcChainSessionType *)pType)

#define DC_COMP_SESSION_SIZE                                                   \
    (sizeof(dc_session_desc_t) + sizeof(LAC_ARCH_UINT) + LAC_64BYTE_ALIGNMENT)

#define FIRST_DC_CHAIN_ITEM 0
#define NOT_APPLICABLE 0

/* List of the different OpData types supported as defined in the DC Chain API
 * header file.
 */
typedef enum dc_chain_opdata_type_e
{
    DC_CHAIN_OPDATA_TYPE0 = 0,
/**< Refer to the API definition for CpaDcChainOpData format */
} dc_chain_opdata_type_t;

typedef struct dc_chain_opdata_ext_s
{
    void *pOpData;
    /**< Pointer to the OpData structure being used */
    dc_chain_opdata_type_t opDataType;
    /**< Indicates the type of OpData being used */
} dc_chain_opdata_ext_t;

/* List of the different results structure types supported as defined in the DC
 * Chain API header file.
 */
typedef enum dc_chain_results_type_e
{
    DC_CHAIN_RESULTS_TYPE0 = 0,
/**< Refer to the API definition for CpaDcChainRqResults format */
} dc_chain_results_type_t;

typedef struct dc_chain_results_ext_s
{
    void *pResults;
    /**< Pointer to the results structure being used */
    dc_chain_results_type_t resultsType;
    /**< Indicates the type of results being used */
} dc_chain_results_ext_t;

typedef struct dc_chain_cmd_tbl_s
{
    Cpa16U link0_key;
    /**< Session type key for first session in chaining */
    Cpa16U link1_key;
    /**< Session type key for second session in chaining */
    Cpa16U link2_key;
    /**< Session type key for third session in chaining */
    icp_qat_comp_chain_cmd_id_t cmd_id;
    /**< Chaining operation */
    icp_qat_comp_chain_20_cmd_id_t cmd_20_id;
    /**< Chaining 2.0 operation */
} dc_chain_cmd_tbl_t;

typedef struct dc_chain_cookie_s
{
    CpaInstanceHandle dcInstance;
    /**< Compression instance handle */
    CpaDcSessionHandle pSessionHandle;
    /**< Pointer to the session handle */
    icp_qat_fw_comp_chain_req_t request;
    /**< Compression chaining request */
    dc_chain_results_ext_t extResults;
    /**< Extensible results buffer holding consumed and produced data */
    void *pDcRspAddr;
    /**< chaining compression response buffer */
    void *pCyRspAddr;
    /**< chaining hash response buffer */
    void *pDcCookieAddr;
    /**< chaining compression cookie buffer */
    void *pCyCookieAddr;
    /**< chaining hash cookie buffer */
    void *callbackTag;
    /**< Opaque data supplied by the client */
} dc_chain_cookie_t;

typedef struct dc_chain_session_head_s
{
    union {
        icp_qat_comp_chain_req_hdr_t comn_hdr;
        /**< Compression chaining header for Gen2 */
        icp_qat_fw_comn_req_hdr_t comn_hdr2;
        /**< Compression chaining header for non Gen2 */
    } hdr;
    Cpa16U numLinks;
    dc_session_desc_t *pDcSessionDesc;
    lac_session_desc_t *pCySessionDesc;
    CpaDcCallbackFn pdcChainCb;
    /**< Callback function defined for the traditional compression session */
    OsalAtomic pendingChainCbCount;
    /**< Keeps track of number of pending requests on stateless session */
} dc_chain_session_head_t;

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Initialize chaining service
 *
 * @description
 *      Initialize chaining service, it will be call by
 *      compression service initialization API
 *
 * @param[in,out]       pCompService     Compression service
 * @param[out]          pChainService    Chaining service
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcChainServiceInit(sal_compression_service_t *pCompService,
                             sal_dc_chain_service_t *pChainService);
/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Shutdown chaining service
 *
 * @description
 *      Shutdown chaining service, it will be called by
 *      compression shutdown API
 *
 * @param[in,out]       pCompService     Compression service
 * @param[in]           pChainService    Chaining service
 *
 * @retval none
 *
 *****************************************************************************/
void dcChainServiceShutdown(sal_compression_service_t *pCompService,
                            sal_dc_chain_service_t *pChainService);

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Chaining perform operation
 *
 * @description
 *      Chaining perform operation
 *
 * @param[in]       dcInstance         Instance handle derived from discovery
 *                                     functions.
 * @param[in]       pSessionHandle     Pointer to a session handle.
 * @param[in]       pSrcBuff           Source buffer
 * @param[in]       pDestBuff          Destination buffer
 * @param[in]       pInterBuff         Pointer to intermediate buffer to be
 *                                     used as internal staging area for
 *                                     chaining operations.
 * @param[in]       operation          Chaining operation type
 * @param[in]       numOperations      Number of operations for the chaining
 * @param[in]       pChainOpDataExt    Extensible chaining operation data
 * @param[in,out]   pResultsExt        Extensible chaining response result
 * @param[in]       callbackTag        For synchronous operation this callback
 *                                     shall be a null pointer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESOURCE       Failed to allocate required resources
 * @retval CPA_STATUS_RETRY          Request re-submission needed
 *
 *****************************************************************************/
CpaStatus dcChainPerformOp(CpaInstanceHandle dcInstance,
                           CpaDcSessionHandle pSessionHandle,
                           CpaBufferList *pSrcBuff,
                           CpaBufferList *pDestBuff,
                           CpaBufferList *pInterBuff,
                           CpaDcChainOperations operation,
                           Cpa8U numOperations,
                           dc_chain_opdata_ext_t *pChainOpDataExt,
                           dc_chain_results_ext_t *pResultsExt,
                           void *callbackTag);

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Chaining response callback
 *
 * @description
 *      Chaining response callback
 *
 * @param[in]       pRespMsg         Chaining response descriptor
 *
 * @retval none
 *
 *****************************************************************************/
void dcChainProcessResults(void *pRespMsg);

#endif /* DC_CHAIN_H */
