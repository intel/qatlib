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
} dc_chain_cmd_tbl_t;

typedef struct dc_chain_cookie_s
{
    CpaInstanceHandle dcInstance;
    /**< Compression instance handle */
    CpaDcSessionHandle pSessionHandle;
    /**< Pointer to the session handle */
    icp_qat_fw_comp_chain_req_t request;
    /**< Compression chaining request */
    CpaDcChainRqResults *pResults;
    /**< Pointer to result buffer holding consumed and produced data */
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
    icp_qat_comp_chain_req_hdr_t comn_hdr;
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
 *      Populate symmetric crypto setup data for chaining operation
 *
 * @description
 *      Populate symmetric crypto setup data for chaining operation
 *
 * @param[in]       instanceHandle     Instance handle
 * @param[in]       pSessionCtx        Symmetric crypto session context
 * @param[out]      pSessionSetupData  Symmetric crypto session setup data
 * @param[out]      proto              Protocol define for firmware
 * @param[out]      chainOrder         Symmetric crypto algorithm chaining order
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcChainSession_PopulateSymSetupData(
    CpaInstanceHandle instanceHandle,
    CpaCySymSessionCtx pSessionCtx,
    CpaCySymSessionSetupData *pSessionSetupData,
    Cpa16U *proto,
    CpaCySymAlgChainOrder *chainOrder);

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Build symmetric crypto template for chaining operation
 *
 * @description
 *      Build symmetric crypto template for chaining operation
 *
 * @param[in]       instanceHandle     Instance handle
 * @param[in]       pSessionCtx        Symmetric crypto session content
 * @param[in]       pSessionSetupData  Symmetric crypto session setup data
 * @param[in]       proto              Protocol define for firmware
 * @param[in]       chainOrder         Symmetric crypto algorithm chaining order
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcChainSession_BuildSymTemplate(
    CpaInstanceHandle instanceHandle,
    CpaCySymSessionCtx pSessionCtx,
    CpaCySymSessionSetupData *pSessionSetupData,
    Cpa16U proto,
    CpaCySymAlgChainOrder chainOrder);

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
 *      Initialization for chaining sessions
 *
 * @description
 *      Initialization for chaining sessions
 *
 * @param[in]         dcInstance    Instance handle derived from discovery
 *                                  functions.
 * @param[in,out]   pSessionHandle  Pointer to a session handle.
 * @param[in,out]   pSessionData    Pointer to an array of
 *                                  CpaDcChainSessionSetupData structures.
 *                                  There should be numSessions entries in the
 *                                  array.
 * @param[in]         numSessions   Number of sessions for the chaining
 * @param[in]         callbackFn    For synchronous operation this callback
 *                                  shall be a null pointer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcChainInitSessions(CpaInstanceHandle dcInstance,
                              CpaDcSessionHandle pSessionHandle,
                              CpaDcChainSessionSetupData *pSessionData,
                              Cpa8U numSessions,
                              CpaDcCallbackFn callbackFn);

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
 * @param[in]       numOperations      Number of operations for the chaining
 * @param[in]       pChainOpData       Chaining operation data
 * @param[in,out]   pResults           Chaining response result
 * @param[in]       callbackTag        For synchronous operation this callback
 *                                     shall be a null pointer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcChainPerformOp(CpaInstanceHandle dcInstance,
                           CpaDcSessionHandle pSessionHandle,
                           CpaBufferList *pSrcBuff,
                           CpaBufferList *pDestBuff,
                           Cpa8U numOperations,
                           CpaDcChainOpData *pChainOpData,
                           CpaDcChainRqResults *pResults,
                           void *callbackTag);

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Chaining response callback
 *
 * @description
 *      Chaining response callback
 *
 * @param[in]       pRespMsg         Chaining response discriptor
 *
 * @retval none
 *
 *****************************************************************************/
void dcChainProcessResults(void *pRespMsg);

#endif /* DC_CHAIN_H */
