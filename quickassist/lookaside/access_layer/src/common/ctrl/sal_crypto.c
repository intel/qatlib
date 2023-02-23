/*****************************************************************************
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
 *****************************************************************************/

/**
 ***************************************************************************
 * @file sal_crypto.c     Instance handling functions for crypto
 *
 * @ingroup SalCtrl
 *
 ***************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

/* QAT-API includes */
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_common.h"
#include "cpa_cy_im.h"
#include "cpa_cy_drbg.h"
#include "cpa_cy_ln.h"
#include "cpa_cy_dh.h"
#include "cpa_cy_dsa.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_prime.h"
#include "cpa_cy_key.h"
#include "cpa_cy_sym.h"

/* Osal includes */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_cfg.h"
#include "icp_adf_accel_mgr.h"
#include "icp_adf_poll.h"
#include "icp_adf_debug.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_sw_responses.h"
#include "sal_statistics.h"
#include "lac_common.h"
#include "lac_list.h"
#include "lac_hooks.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym.h"
#include "lac_sym_key.h"
#include "lac_sym_hash.h"
#include "lac_sym_cb.h"
#include "lac_sym_stats.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_ec.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "sal_string_parse.h"
#include "sal_service_state.h"
#include "icp_sal_poll.h"
#include "lac_sync.h"
#include "lac_sym_qat.h"
#include "icp_sal_versions.h"

#define MAX_CY_RX_RINGS 2
#define TH_CY_RX_0 0
#define TH_CY_RX_1 1
#define DOUBLE_INCR 2

#define NUM_CRYPTO_SYM_RX_RINGS 1
#define NUM_CRYPTO_ASYM_RX_RINGS 1

#ifdef KERNEL_SPACE
#define ASYM_NOT_SUPPORTED
#endif

STATIC CpaInstanceHandle Lac_CryptoGetFirstHandle(void)
{
    CpaInstanceHandle instHandle;
    instHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO);
    if (!instHandle)
    {
        instHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
        if (!instHandle)
        {
            instHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
        }
    }
    return instHandle;
}

STATIC
CpaStatus SalCtrl_AsymGetFileDescriptor(sal_crypto_service_t *crypto_handle,
                                        int *fd)
{
    int ret = 0;
    int fd_asym = -1;

    if (NULL == crypto_handle->trans_handle_asym_rx)
    {
        return CPA_STATUS_FAIL;
    }
    ret = icp_adf_transGetFdForHandle(crypto_handle->trans_handle_asym_rx,
                                      &fd_asym);

    if (ret != CPA_STATUS_SUCCESS)
    {
        LAC_LOG_ERROR("Error getting file descriptor for asym instance");
        return CPA_STATUS_FAIL;
    }

    *fd = fd_asym;
    return CPA_STATUS_SUCCESS;
}

STATIC
CpaStatus SalCtrl_SymGetFileDescriptor(sal_crypto_service_t *crypto_handle,
                                       int *fd)
{
    int ret = 0;
    int fd_sym = -1;

    if (NULL == crypto_handle->trans_handle_sym_rx)
    {
        return CPA_STATUS_FAIL;
    }
    ret = icp_adf_transGetFdForHandle(crypto_handle->trans_handle_sym_rx,
                                      &fd_sym);

    if (ret != CPA_STATUS_SUCCESS)
    {
        LAC_LOG_ERROR("Error getting file descriptor for sym instance");
        return CPA_STATUS_FAIL;
    }

    *fd = fd_sym;
    return CPA_STATUS_SUCCESS;
}

STATIC
CpaStatus SalCtrl_CyGetFileDescriptor(sal_crypto_service_t *crypto_handle,
                                      int *fd)
{
    CpaStatus ret_sym = CPA_STATUS_SUCCESS;
    CpaStatus ret_asym = CPA_STATUS_SUCCESS;
    int fd_sym = -1;
    int fd_asym = -1;

    ret_sym = SalCtrl_SymGetFileDescriptor(crypto_handle, &fd_sym);
    ret_asym = SalCtrl_AsymGetFileDescriptor(crypto_handle, &fd_asym);

    if (ret_sym != CPA_STATUS_SUCCESS || ret_asym != CPA_STATUS_SUCCESS)
    {
        LAC_LOG_ERROR("Error getting file descriptor for crypto instance");
        return CPA_STATUS_FAIL;
    }

    /* They should always be the same. Otherwise, return error */
    if (fd_sym != fd_asym)
    {
        LAC_LOG_ERROR("Symmetric and asymmetric crypto cannot be used"
                      " within the same instance across different bundles");
        return CPA_STATUS_FAIL;
    }

    *fd = fd_sym;
    return CPA_STATUS_SUCCESS;
}

#ifndef ASYM_NOT_SUPPORTED
STATIC void SalCtrl_AsymMemPoolDisable(sal_crypto_service_t *pCryptoService)
{
    Lac_MemPoolDisable(pCryptoService->lac_pke_req_pool);
}
#endif

STATIC void SalCtrl_SymMemPoolDisable(sal_crypto_service_t *pCryptoService)
{
    Lac_MemPoolDisable(pCryptoService->lac_sym_cookie_pool);
}

STATIC void SalCtrl_CyMemPoolDisable(sal_service_t *service)
{
    sal_service_type_t svc_type = service->type;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    switch (svc_type)
    {
#ifndef ASYM_NOT_SUPPORTED
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            SalCtrl_AsymMemPoolDisable(pCryptoService);
            break;
#endif
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            SalCtrl_SymMemPoolDisable(pCryptoService);
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
            SalCtrl_AsymMemPoolDisable(pCryptoService);
#endif
            SalCtrl_SymMemPoolDisable(pCryptoService);
            break;
        default:
            break;
    }
    return;
}

STATIC void SalCtrl_CyUpdatePoolsBusy(sal_service_t *service)
{
    sal_service_type_t svc_type = service->type;
    CpaBoolean isInstanceStarted = service->isInstanceStarted;
#ifndef ASYM_NOT_SUPPORTED
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
#endif

    if (CPA_TRUE == isInstanceStarted)
    {
        switch (svc_type)
        {
#ifndef ASYM_NOT_SUPPORTED
            case SAL_SERVICE_TYPE_CRYPTO_ASYM:
                LacSwResp_IncNumPoolsBusy(pCryptoService->lac_pke_req_pool);
                break;
#endif
            case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
                LacSwResp_IncNumPoolsBusy(pCryptoService->lac_pke_req_pool);
#endif
                break;
            default:
                break;
        }
    }
    return;
}

/* Generates dummy responses when the device is in error state */
STATIC
CpaStatus SalCtrl_CyGenResponses(sal_crypto_service_t *crypto_handle,
                                 sal_service_t *gen_handle)
{
    CpaStatus status = CPA_STATUS_RETRY;
    switch (gen_handle->type)
    {
#ifndef ASYM_NOT_SUPPORTED
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            status =
                LacSwResp_Asym_CallbackWake(crypto_handle->lac_pke_req_pool);
            if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
            {
                LAC_LOG_ERROR1(
                    "Failed to perform asym callbacks with status %d\n",
                    status);
            }
            break;
#endif
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
            status =
                LacSwResp_Asym_CallbackWake(crypto_handle->lac_pke_req_pool);
            if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
            {
                LAC_LOG_ERROR1(
                    "Failed to perform asym callbacks with status %d\n",
                    status);
            }
#endif
            break;
        default:
            break;
    }

    if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
    {
        LAC_LOG_ERROR1("Failed to perform cy callbacks with status %d\n",
                       status);
    }
    return status;
}

STATIC CpaStatus SalCtrl_CyCheckRespInstance(sal_service_t *service)
{
    sal_crypto_service_t *crypto_handle = (sal_crypto_service_t *)service;
    icp_comms_trans_handle trans_hndTable[MAX_CY_RX_RINGS];
    Cpa32U num_rx_rings = 0;

    switch (service->type)
    {
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_asym_rx;
            num_rx_rings = 1;
            break;
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_sym_rx;
            num_rx_rings = 1;
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
            trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_sym_rx;
            trans_hndTable[TH_CY_RX_1] = crypto_handle->trans_handle_asym_rx;
            num_rx_rings = MAX_CY_RX_RINGS;
            break;
        default:
            break;
    }
    return icp_adf_check_RespInstance(trans_hndTable, num_rx_rings);
}

#ifndef ASYM_NOT_SUPPORTED
/* Function to release the asym handles. */
STATIC CpaStatus SalCtrl_AsymReleaseTransHandle(sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    if (NULL != pCryptoService->trans_handle_asym_tx)
    {
        status =
            icp_adf_transReleaseHandle(pCryptoService->trans_handle_asym_tx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (NULL != pCryptoService->trans_handle_asym_rx)
    {
        status =
            icp_adf_transReleaseHandle(pCryptoService->trans_handle_asym_rx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }
    return ret_status;
}

/* Function to reset the asym handles. */
STATIC CpaStatus SalCtrl_AsymResetTransHandle(sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    if (NULL != pCryptoService->trans_handle_asym_tx)
    {
        status = icp_adf_transResetHandle(pCryptoService->trans_handle_asym_tx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (NULL != pCryptoService->trans_handle_asym_rx)
    {
        status = icp_adf_transResetHandle(pCryptoService->trans_handle_asym_rx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }
    return ret_status;
}
#endif

/* Function to release the sym handles. */
STATIC CpaStatus SalCtrl_SymReleaseTransHandle(sal_service_t *service)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    if (NULL != pCryptoService->trans_handle_sym_tx)
    {
        status =
            icp_adf_transReleaseHandle(pCryptoService->trans_handle_sym_tx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }
    if (NULL != pCryptoService->trans_handle_sym_rx)
    {
        status =
            icp_adf_transReleaseHandle(pCryptoService->trans_handle_sym_rx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    return ret_status;
}

/* Function to reset the sym handles. */
STATIC CpaStatus SalCtrl_SymResetTransHandle(sal_service_t *service)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    if (NULL != pCryptoService->trans_handle_sym_tx)
    {
        status = icp_adf_transResetHandle(pCryptoService->trans_handle_sym_tx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }
    if (NULL != pCryptoService->trans_handle_sym_rx)
    {
        status = icp_adf_transResetHandle(pCryptoService->trans_handle_sym_rx);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    return ret_status;
}

#ifndef ASYM_NOT_SUPPORTED
/*
 * @ingroup sal_crypto
 *     Frees resources (memory and transhandles) if allocated
 *
 * @param[in]  pCryptoService       Pointer to asym service instance
 * @retval                          SUCCESS if transhandles released
 *                                  successfully
 */
STATIC CpaStatus SalCtrl_AsymFreeResources(sal_crypto_service_t *pCryptoService)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Free memory pools if not NULL */
    Lac_MemPoolDestroy(pCryptoService->lac_pke_align_pool);
    Lac_MemPoolDestroy(pCryptoService->lac_pke_req_pool);
    Lac_MemPoolDestroy(pCryptoService->lac_ec_pool);
    Lac_MemPoolDestroy(pCryptoService->lac_prime_pool);

    /* Free the statistics */
    LacDh_StatsFree(pCryptoService);
    LacDsa_StatsFree(pCryptoService);
    LacRsa_StatsFree(pCryptoService);
    LacEc_StatsFree(pCryptoService);
    LacPrime_StatsFree(pCryptoService);
    LacLn_StatsFree(pCryptoService);

    /* Free transport handles */
    status = SalCtrl_AsymReleaseTransHandle((sal_service_t *)pCryptoService);
    return status;
}

/*
 * @ingroup sal_crypto
 *     Resets resources (memory and transhandles)
 *
 * @param[in]  pCryptoService       Pointer to asym service instance
 * @retval                          SUCCESS if transhandles released
 *                                  successfully
 */
STATIC CpaStatus
SalCtrl_AsymResetResources(sal_crypto_service_t *pCryptoService)
{
    /* Reset the statistics */
    LacDh_StatsReset(pCryptoService);
    LacDsa_StatsReset(pCryptoService);
    LacRsa_StatsReset(pCryptoService);
    LacEc_StatsReset(pCryptoService);
    LacPrime_StatsReset(pCryptoService);
    LacLn_StatsReset(pCryptoService);

    /* Reset transport handles */
    return SalCtrl_AsymResetTransHandle((sal_service_t *)pCryptoService);
}
#endif

/*
 * @ingroup sal_crypto
 *     Frees resources (memory and transhandles) if allocated
 *
 * @param[in]  pCryptoService       Pointer to sym service instance
 * @retval                          SUCCESS if transhandles released
 *                                  successfully.
 */
STATIC CpaStatus SalCtrl_SymFreeResources(sal_crypto_service_t *pCryptoService)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Free memory pools if not NULL */
    Lac_MemPoolDestroy(pCryptoService->lac_sym_cookie_pool);

    /* Free key stats */
    LacSymKey_StatsFree(pCryptoService);
    /* Free misc memory if allocated */
    /* Frees memory allocated for Hmac precomputes */
    LacSymHash_HmacPrecompShutdown(pCryptoService);
    /* Free memory allocated for key labels
       Also clears key stats  */
    LacSymKey_Shutdown(pCryptoService);
    /* Free hash lookup table if allocated */
    if (NULL != pCryptoService->pLacHashLookupDefs)
    {
        LAC_OS_FREE(pCryptoService->pLacHashLookupDefs);
    }

    /* Free statistics */
    LacSym_StatsFree(pCryptoService);

    /* Free transport handles */
    status = SalCtrl_SymReleaseTransHandle((sal_service_t *)pCryptoService);
    return status;
}

/*
 * @ingroup sal_crypto
 *     Resets resources (memory and transhandles)
 *
 * @param[in]  pCryptoService       Pointer to sym service instance
 * @retval                          SUCCESS if transhandles released
 *                                  successfully.
 */
STATIC CpaStatus SalCtrl_SymResetResources(sal_crypto_service_t *pCryptoService)
{
    LacSymKey_StatsReset(pCryptoService);

    /* Reset transport handles */
    return SalCtrl_SymResetTransHandle((sal_service_t *)pCryptoService);
}

#ifndef ASYM_NOT_SUPPORTED
/**
 ***********************************************************************
 * @ingroup SalCtrl
 *   This macro verifies that the status is _SUCCESS
 *   If status is not _SUCCESS then Asym Instance resources are
 *   freed before the function returns the error
 *
 * @param[in] status    status we are checking
 *
 * @return void         status is ok (CPA_STATUS_SUCCESS)
 * @return status       The value in the status parameter is an error one
 *
 ****************************************************************************/
#define LAC_CHECK_STATUS_ASYM_INIT(status)                                     \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != status)                                      \
        {                                                                      \
            SalCtrl_AsymFreeResources(pCryptoService);                         \
            return status;                                                     \
        }                                                                      \
    } while (0)
#endif

/**
 ***********************************************************************
 * @ingroup SalCtrl
 *   This macro verifies that the status is _SUCCESS
 *   If status is not _SUCCESS then Sym Instance resources are
 *   freed before the function returns the error
 *
 * @param[in] status    status we are checking
 *
 * @return void         status is ok (CPA_STATUS_SUCCESS)
 * @return status       The value in the status parameter is an error one
 *
 ****************************************************************************/
#define LAC_CHECK_STATUS_SYM_INIT(status)                                      \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != status)                                      \
        {                                                                      \
            SalCtrl_SymFreeResources(pCryptoService);                          \
            return status;                                                     \
        }                                                                      \
    } while (0)

#ifndef ASYM_NOT_SUPPORTED
/* Function that creates the Asym Handles. */
STATIC CpaStatus SalCtrl_AsymCreateTransHandle(icp_accel_dev_t *device,
                                               sal_service_t *service,
                                               Cpa32U numAsymRequests,
                                               char *section)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    icp_resp_deliv_method rx_resp_type = ICP_RESP_TYPE_IRQ;
    Cpa32U msgSize = 0;

    if (SAL_RESP_POLL_CFG_FILE == pCryptoService->isPolled)
    {
        rx_resp_type = ICP_RESP_TYPE_POLL;
    }

    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    /* Parse Asym ring details first */
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_ASYM_TX,
                               temp_string);
    /* Need to free resources in case not _SUCCESS from here */
    LAC_CHECK_STATUS_ASYM_INIT(status);

    msgSize = LAC_QAT_ASYM_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transCreateHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumAsym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_A_ASYM),
        NULL,
        ICP_RESP_TYPE_NONE,
        numAsymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_asym_tx));
    LAC_CHECK_STATUS_ASYM_INIT(status);

    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_ASYM_RX,
                               temp_string);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    msgSize = LAC_QAT_ASYM_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transCreateHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumAsym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_NONE),
        LacPke_MsgCallback,
        rx_resp_type,
        numAsymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_asym_rx));
    LAC_CHECK_STATUS_ASYM_INIT(status);

    return status;
}

/* Function that reinitializes the Asym Handles after restart. */
STATIC CpaStatus SalCtrl_AsymReinitTransHandle(icp_accel_dev_t *device,
                                               sal_service_t *service,
                                               Cpa32U numAsymRequests,
                                               char *section)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    icp_resp_deliv_method rx_resp_type = ICP_RESP_TYPE_IRQ;
    Cpa32U msgSize = 0;

    if (SAL_RESP_POLL_CFG_FILE == pCryptoService->isPolled)
    {
        rx_resp_type = ICP_RESP_TYPE_POLL;
    }

    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    /* Parse Asym ring details first */
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_ASYM_TX,
                               temp_string);
    /* Need to free resources in case not _SUCCESS from here */
    LAC_CHECK_STATUS_ASYM_INIT(status);

    msgSize = LAC_QAT_ASYM_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transReinitHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumAsym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_A_ASYM),
        NULL,
        ICP_RESP_TYPE_NONE,
        numAsymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_asym_tx));
    LAC_CHECK_STATUS_ASYM_INIT(status);

    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_ASYM_RX,
                               temp_string);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    msgSize = LAC_QAT_ASYM_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transReinitHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumAsym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_NONE),
        LacPke_MsgCallback,
        rx_resp_type,
        numAsymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_asym_rx));
    LAC_CHECK_STATUS_ASYM_INIT(status);

    return status;
}

#endif

/* Function that creates the Sym Handles. */
STATIC CpaStatus SalCtrl_SymCreateTransHandle(icp_accel_dev_t *device,
                                              sal_service_t *service,
                                              Cpa32U numSymRequests,
                                              char *section)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    icp_resp_deliv_method rx_resp_type = ICP_RESP_TYPE_IRQ;
    Cpa32U msgSize = 0;

    if (SAL_RESP_POLL_CFG_FILE == pCryptoService->isPolled)
    {
        rx_resp_type = ICP_RESP_TYPE_POLL;
    }

    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    /* Parse Sym ring details */
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_SYM_TX,
                               temp_string);

    /* Need to free resources in case not _SUCCESS from here */
    LAC_CHECK_STATUS_SYM_INIT(status);

    msgSize = LAC_QAT_SYM_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transCreateHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumSym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_A_SYM_HI),
        NULL,
        ICP_RESP_TYPE_NONE,
        numSymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_sym_tx));
    LAC_CHECK_STATUS_SYM_INIT(status);

    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_SYM_RX,
                               temp_string);
    LAC_CHECK_STATUS_SYM_INIT(status);

    msgSize = LAC_QAT_SYM_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transCreateHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumSym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_NONE),
        (icp_trans_callback)LacSymQat_SymRespHandler,
        rx_resp_type,
        numSymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_sym_rx));
    LAC_CHECK_STATUS_SYM_INIT(status);

    return status;
}

/* Function that reinitializes the Sym Handles after restart. */
STATIC CpaStatus SalCtrl_SymReinitTransHandle(icp_accel_dev_t *device,
                                              sal_service_t *service,
                                              Cpa32U numSymRequests,
                                              char *section)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    icp_resp_deliv_method rx_resp_type = ICP_RESP_TYPE_IRQ;
    Cpa32U msgSize = 0;

    if (SAL_RESP_POLL_CFG_FILE == pCryptoService->isPolled)
    {
        rx_resp_type = ICP_RESP_TYPE_POLL;
    }

    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    /* Parse Sym ring details */
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_ASYM_TX,
                               temp_string);

    /* Need to free resources in case not _SUCCESS from here */
    LAC_CHECK_STATUS_SYM_INIT(status);

    msgSize = LAC_QAT_SYM_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transReinitHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumSym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_A_SYM_HI),
        NULL,
        ICP_RESP_TYPE_NONE,
        numSymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_sym_tx));
    LAC_CHECK_STATUS_SYM_INIT(status);

    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_RING_ASYM_RX,
                               temp_string);
    LAC_CHECK_STATUS_SYM_INIT(status);

    msgSize = LAC_QAT_SYM_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transReinitHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCryptoService->acceleratorNum,
        pCryptoService->bankNumSym,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_NONE),
        (icp_trans_callback)LacSymQat_SymRespHandler,
        rx_resp_type,
        numSymRequests,
        msgSize,
        (icp_comms_trans_handle *)&(pCryptoService->trans_handle_sym_rx));
    LAC_CHECK_STATUS_SYM_INIT(status);

    return status;
}

STATIC int SalCtrl_CryptoDebug(void *private_data,
                               char *data,
                               int size,
                               int offset)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U len = 0;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)private_data;

    switch (offset)
    {
        case SAL_STATS_SYM:
        {
            CpaCySymStats64 symStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bSymStatsEnabled)
            {
                break;
            }
            status = cpaCySymQueryStats64(pCryptoService, &symStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCySymQueryStats64 returned error\n");
                return 0;
            }

            /* Engine Info */
            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " Statistics for Instance %24s |\n" BORDER
                " Symmetric Stats                                  " BORDER
                "\n" SEPARATOR,
                pCryptoService->debug_file->name);

            /* Session Info */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " Sessions Initialized:           %16llu " BORDER "\n" BORDER
                " Sessions Removed:               %16llu " BORDER "\n" BORDER
                " Session Errors:                 %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)symStats.numSessionsInitialized,
                (long long unsigned int)symStats.numSessionsRemoved,
                (long long unsigned int)symStats.numSessionErrors);

            /* Session info */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " Symmetric Requests:             %16llu " BORDER "\n" BORDER
                " Symmetric Request Errors:       %16llu " BORDER "\n" BORDER
                " Symmetric Completed:            %16llu " BORDER "\n" BORDER
                " Symmetric Completed Errors:     %16llu " BORDER "\n" BORDER
                " Symmetric Verify Failures:      %16llu " BORDER "\n",
                (long long unsigned int)symStats.numSymOpRequests,
                (long long unsigned int)symStats.numSymOpRequestErrors,
                (long long unsigned int)symStats.numSymOpCompleted,
                (long long unsigned int)symStats.numSymOpCompletedErrors,
                (long long unsigned int)symStats.numSymOpVerifyFailures);
            break;
        }
        case SAL_STATS_DSA:
        {
            CpaCyDsaStats64 dsaStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bDsaStatsEnabled)
            {
                ++offset;
                break;
            }

            status = cpaCyDsaQueryStats64(pCryptoService, &dsaStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyDsaQueryStats4 returned error\n");
                return 0;
            }
            /* engine info */
            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " DSA Stats                                        " BORDER
                "\n" SEPARATOR);

            /* p parameter generation requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA P Param Gen Requests-Succ:  %16llu " BORDER "\n" BORDER
                " DSA P Param Gen Requests-Err:   %16llu " BORDER "\n" BORDER
                " DSA P Param Gen Completed-Succ: %16llu " BORDER "\n" BORDER
                " DSA P Param Gen Completed-Err:  %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dsaStats.numDsaPParamGenRequests,
                (long long unsigned int)dsaStats.numDsaPParamGenRequestErrors,
                (long long unsigned int)dsaStats.numDsaPParamGenCompleted,
                (long long unsigned int)
                    dsaStats.numDsaPParamGenCompletedErrors);

            /* g parameter generation requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA G Param Gen Requests-Succ:  %16llu " BORDER "\n" BORDER
                " DSA G Param Gen Requests-Err:   %16llu " BORDER "\n" BORDER
                " DSA G Param Gen Completed-Succ: %16llu " BORDER "\n" BORDER
                " DSA G Param Gen Completed-Err:  %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dsaStats.numDsaGParamGenRequests,
                (long long unsigned int)dsaStats.numDsaGParamGenRequestErrors,
                (long long unsigned int)dsaStats.numDsaGParamGenCompleted,
                (long long unsigned int)
                    dsaStats.numDsaGParamGenCompletedErrors);

            /* y parameter generation requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA Y Param Gen Requests-Succ:  %16llu " BORDER "\n" BORDER
                " DSA Y Param Gen Requests-Err:   %16llu " BORDER "\n" BORDER
                " DSA Y Param Gen Completed-Succ: %16llu " BORDER "\n" BORDER
                " DSA Y Param Gen Completed-Err:  %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dsaStats.numDsaYParamGenRequests,
                (long long unsigned int)dsaStats.numDsaYParamGenRequestErrors,
                (long long unsigned int)dsaStats.numDsaYParamGenCompleted,
                (long long unsigned int)
                    dsaStats.numDsaYParamGenCompletedErrors);
            break;
        }
        case SAL_STATS_DSA2:
        {
            CpaCyDsaStats64 dsaStats = {0};
            status = cpaCyDsaQueryStats64(pCryptoService, &dsaStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyDsaQueryStats4 returned error\n");
                return 0;
            }
            /* r sign requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA R Sign Requests-Succ:       %16llu " BORDER "\n" BORDER
                " DSA R Sign Request-Err:         %16llu " BORDER "\n" BORDER
                " DSA R Sign Completed-Succ:      %16llu " BORDER "\n" BORDER
                " DSA R Sign Completed-Err:       %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dsaStats.numDsaRSignRequests,
                (long long unsigned int)dsaStats.numDsaRSignRequestErrors,
                (long long unsigned int)dsaStats.numDsaRSignCompleted,
                (long long unsigned int)dsaStats.numDsaRSignCompletedErrors);

            /* s sign requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA S Sign Requests-Succ:       %16llu " BORDER "\n" BORDER
                " DSA S Sign Request-Err:         %16llu " BORDER "\n" BORDER
                " DSA S Sign Completed-Succ:      %16llu " BORDER "\n" BORDER
                " DSA S Sign Completed-Err:       %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dsaStats.numDsaSSignRequests,
                (long long unsigned int)dsaStats.numDsaSSignRequestErrors,
                (long long unsigned int)dsaStats.numDsaSSignCompleted,
                (long long unsigned int)dsaStats.numDsaSSignCompletedErrors);

            /* rs sign requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA RS Sign Requests-Succ:      %16llu " BORDER "\n" BORDER
                " DSA RS Sign Request-Err:        %16llu " BORDER "\n" BORDER
                " DSA RS Sign Completed-Succ:     %16llu " BORDER "\n" BORDER
                " DSA RS Sign Completed-Err:      %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dsaStats.numDsaRSSignRequests,
                (long long unsigned int)dsaStats.numDsaRSSignRequestErrors,
                (long long unsigned int)dsaStats.numDsaRSSignCompleted,
                (long long unsigned int)dsaStats.numDsaRSSignCompletedErrors);

            /* verify requests */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DSA Verify Requests-Succ:       %16llu " BORDER "\n" BORDER
                " DSA Verify Request-Err:         %16llu " BORDER "\n" BORDER
                " DSA Verify Completed-Succ:      %16llu " BORDER "\n" BORDER
                " DSA Verify Completed-Err:       %16llu " BORDER "\n" BORDER
                " DSA Verify Completed-Failure:   %16llu " BORDER "\n",
                (long long unsigned int)dsaStats.numDsaVerifyRequests,
                (long long unsigned int)dsaStats.numDsaVerifyRequestErrors,
                (long long unsigned int)dsaStats.numDsaVerifyCompleted,
                (long long unsigned int)dsaStats.numDsaVerifyCompletedErrors,
                (long long unsigned int)dsaStats.numDsaVerifyFailures);
            break;
        }
        case SAL_STATS_RSA:
        {
            CpaCyRsaStats64 rsaStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bRsaStatsEnabled)
            {
                break;
            }

            status = cpaCyRsaQueryStats64(pCryptoService, &rsaStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyRsaQueryStats64 returned error\n");
                return 0;
            }

            /* Engine Info */
            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " RSA Stats                                        " BORDER
                "\n" SEPARATOR);

            /* rsa keygen Info */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " RSA Key Gen Requests:           %16llu " BORDER "\n" BORDER
                " RSA Key Gen Request Errors      %16llu " BORDER "\n" BORDER
                " RSA Key Gen Completed:          %16llu " BORDER "\n" BORDER
                " RSA Key Gen Completed Errors:   %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)rsaStats.numRsaKeyGenRequests,
                (long long unsigned int)rsaStats.numRsaKeyGenRequestErrors,
                (long long unsigned int)rsaStats.numRsaKeyGenCompleted,
                (long long unsigned int)rsaStats.numRsaKeyGenCompletedErrors);

            /* rsa enc Info */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " RSA Encrypt Requests:           %16llu " BORDER "\n" BORDER
                " RSA Encrypt Request Errors:     %16llu " BORDER "\n" BORDER
                " RSA Encrypt Completed:          %16llu " BORDER "\n" BORDER
                " RSA Encrypt Completed Errors:   %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)rsaStats.numRsaEncryptRequests,
                (long long unsigned int)rsaStats.numRsaEncryptRequestErrors,
                (long long unsigned int)rsaStats.numRsaEncryptCompleted,
                (long long unsigned int)rsaStats.numRsaEncryptCompletedErrors);

            /* rsa dec Info */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " RSA Decrypt Requests:           %16llu " BORDER "\n" BORDER
                " RSA Decrypt Request Errors:     %16llu " BORDER "\n" BORDER
                " RSA Decrypt Completed:          %16llu " BORDER "\n" BORDER
                " RSA Decrypt Completed Errors:   %16llu " BORDER "\n",
                (long long unsigned int)rsaStats.numRsaDecryptRequests,
                (long long unsigned int)rsaStats.numRsaDecryptRequestErrors,
                (long long unsigned int)rsaStats.numRsaDecryptCompleted,
                (long long unsigned int)rsaStats.numRsaDecryptCompletedErrors);
            break;
        }
        case SAL_STATS_DH:
        {
            CpaCyDhStats64 dhStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bDhStatsEnabled)
            {
                break;
            }
            status = cpaCyDhQueryStats64(pCryptoService, &dhStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyDhQueryStats returned error\n");
                return 0;
            }

            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " Diffie Hellman Stats                             " BORDER
                "\n" SEPARATOR);

            /* perform Info */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DH Phase1 Key Gen Requests:     %16llu " BORDER "\n" BORDER
                " DH Phase1 Key Gen Request Err:  %16llu " BORDER "\n" BORDER
                " DH Phase1 Key Gen Completed:    %16llu " BORDER "\n" BORDER
                " DH Phase1 Key Gen Completed Err:%16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)dhStats.numDhPhase1KeyGenRequests,
                (long long unsigned int)dhStats.numDhPhase1KeyGenRequestErrors,
                (long long unsigned int)dhStats.numDhPhase1KeyGenCompleted,
                (long long unsigned int)
                    dhStats.numDhPhase1KeyGenCompletedErrors);

            len += snprintf(
                data + len,
                size - len,
                BORDER
                " DH Phase2 Key Gen Requests:     %16llu " BORDER "\n" BORDER
                " DH Phase2 Key Gen Request Err:  %16llu " BORDER "\n" BORDER
                " DH Phase2 Key Gen Completed:    %16llu " BORDER "\n" BORDER
                " DH Phase2 Key Gen Completed Err:%16llu " BORDER "\n",
                (long long unsigned int)dhStats.numDhPhase2KeyGenRequests,
                (long long unsigned int)dhStats.numDhPhase2KeyGenRequestErrors,
                (long long unsigned int)dhStats.numDhPhase2KeyGenCompleted,
                (long long unsigned int)
                    dhStats.numDhPhase2KeyGenCompletedErrors);
            break;
        }
        case SAL_STATS_KEYGEN:
        {
            CpaCyKeyGenStats64 keyStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bKeyGenStatsEnabled)
            {
                break;
            }
            status = cpaCyKeyGenQueryStats64(pCryptoService, &keyStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyKeyGenQueryStats64 returned error\n");
                return 0;
            }

            /* Key Gen stats */
            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " Key Stats                                        " BORDER
                "\n" SEPARATOR);

            len += snprintf(
                data + len,
                size - len,
                BORDER
                " SSL Key Requests:               %16llu " BORDER "\n" BORDER
                " SSL Key Request Errors:         %16llu " BORDER "\n" BORDER
                " SSL Key Completed               %16llu " BORDER "\n" BORDER
                " SSL Key Complete Errors:        %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)keyStats.numSslKeyGenRequests,
                (long long unsigned int)keyStats.numSslKeyGenRequestErrors,
                (long long unsigned int)keyStats.numSslKeyGenCompleted,
                (long long unsigned int)keyStats.numSslKeyGenCompletedErrors);

            len += snprintf(
                data + len,
                size - len,
                BORDER
                " TLS Key Requests:               %16llu " BORDER "\n" BORDER
                " TLS Key Request Errors:         %16llu " BORDER "\n" BORDER
                " TLS Key Completed               %16llu " BORDER "\n" BORDER
                " TLS Key Complete Errors:        %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)keyStats.numTlsKeyGenRequests,
                (long long unsigned int)keyStats.numTlsKeyGenRequestErrors,
                (long long unsigned int)keyStats.numTlsKeyGenCompleted,
                (long long unsigned int)keyStats.numTlsKeyGenCompletedErrors);

            len += snprintf(
                data + len,
                size - len,
                BORDER
                " MGF Key Requests:               %16llu " BORDER "\n" BORDER
                " MGF Key Request Errors:         %16llu " BORDER "\n" BORDER
                " MGF Key Completed               %16llu " BORDER "\n" BORDER
                " MGF Key Complete Errors:        %16llu " BORDER "\n",
                (long long unsigned int)keyStats.numMgfKeyGenRequests,
                (long long unsigned int)keyStats.numMgfKeyGenRequestErrors,
                (long long unsigned int)keyStats.numMgfKeyGenCompleted,
                (long long unsigned int)keyStats.numMgfKeyGenCompletedErrors);
            break;
        }
        case SAL_STATS_LN:
        {
            CpaCyLnStats64 lnStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bLnStatsEnabled)
            {
                break;
            }
            status = cpaCyLnStatsQuery64(pCryptoService, &lnStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyLnStatsQuery64 returned error\n");
                return 0;
            }

            /* Engine Info */
            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " LN ModExp/ModInv Stats                           " BORDER
                "\n" SEPARATOR);

            /* Large Number Modular Exponentationstats operations stats */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " LN ModEXP successful requests:  %16llu " BORDER "\n" BORDER
                " LN ModEXP requests with error:  %16llu " BORDER "\n" BORDER
                " LN ModEXP completed operations: %16llu " BORDER "\n" BORDER
                " LN ModEXP not completed-errors: %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)lnStats.numLnModExpRequests,
                (long long unsigned int)lnStats.numLnModExpRequestErrors,
                (long long unsigned int)lnStats.numLnModExpCompleted,
                (long long unsigned int)lnStats.numLnModExpCompletedErrors);

            /*  Large Number Modular Inversion operations stats */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " LN ModINV successful requests:  %16llu " BORDER "\n" BORDER
                " LN ModINV requests with error:  %16llu " BORDER "\n" BORDER
                " LN ModINV completed operations: %16llu " BORDER "\n" BORDER
                " LN ModINV not completed-errors: %16llu " BORDER "\n",
                (long long unsigned int)lnStats.numLnModInvRequests,
                (long long unsigned int)lnStats.numLnModInvRequestErrors,
                (long long unsigned int)lnStats.numLnModInvCompleted,
                (long long unsigned int)lnStats.numLnModInvCompletedErrors);

            break;
        }
        case SAL_STATS_PRIME:
        {
            CpaCyPrimeStats64 primeStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bPrimeStatsEnabled)
            {
                break;
            }
            status = cpaCyPrimeQueryStats64(pCryptoService, &primeStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyPrimeQueryStats64 returned error\n");
                return 0;
            }

            /* Engine Info */
            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " PRIME Stats                                      " BORDER
                "\n" SEPARATOR);

            /* Parameter generation requests - PRIME stats */
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " PRIME successfull requests:     %16llu " BORDER "\n" BORDER
                " PRIME failed requests:          %16llu " BORDER "\n" BORDER
                " PRIME successfully completed:   %16llu " BORDER "\n" BORDER
                " PRIME failed completion:        %16llu " BORDER "\n" BORDER
                " PRIME completed - not a prime:  %16llu " BORDER "\n",
                (long long unsigned int)primeStats.numPrimeTestRequests,
                (long long unsigned int)primeStats.numPrimeTestRequestErrors,
                (long long unsigned int)primeStats.numPrimeTestCompleted,
                (long long unsigned int)primeStats.numPrimeTestCompletedErrors,
                (long long unsigned int)primeStats.numPrimeTestFailures);
            break;
        }
        case SAL_STATS_ECC:
        {
            CpaCyEcStats64 ecStats = {0};
            if (CPA_TRUE !=
                pCryptoService->generic_service_info.stats->bEccStatsEnabled)
            {
                offset += DOUBLE_INCR;
                break;
            }
            status = cpaCyEcQueryStats64(pCryptoService, &ecStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyEcQueryStats64 returned error\n");
                return 0;
            }

            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " EC Stats                                         " BORDER
                "\n" SEPARATOR);

            len += snprintf(
                data + len,
                size - len,
                BORDER
                " EC Pt Multiply Requests-Succ:   %16llu " BORDER "\n" BORDER
                " EC Pt Multiply Request-Err:     %16llu " BORDER "\n" BORDER
                " EC Pt Multiply Completed-Succ:  %16llu " BORDER "\n" BORDER
                " EC Pt Multiply Completed-Err:   %16llu " BORDER "\n" BORDER
                " EC Pt Multiply Output Invalid:  %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)ecStats.numEcPointMultiplyRequests,
                (long long unsigned int)ecStats.numEcPointMultiplyRequestErrors,
                (long long unsigned int)ecStats.numEcPointMultiplyCompleted,
                (long long unsigned int)
                    ecStats.numEcPointMultiplyCompletedError,
                (long long unsigned int)
                    ecStats.numEcPointMultiplyCompletedOutputInvalid);
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " EC Pt Verify Requests-Succ:     %16llu " BORDER "\n" BORDER
                " EC Pt Verify Request-Err:       %16llu " BORDER "\n" BORDER
                " EC Pt Verify Completed-Succ:    %16llu " BORDER "\n" BORDER
                " EC Pt Verify Completed-Err:     %16llu " BORDER "\n" BORDER
                " EC Pt Verify Output Invalid:    %16llu " BORDER "\n",
                (long long unsigned int)ecStats.numEcPointVerifyRequests,
                (long long unsigned int)ecStats.numEcPointVerifyRequestErrors,
                (long long unsigned int)ecStats.numEcPointVerifyCompleted,
                (long long unsigned int)ecStats.numEcPointVerifyCompletedErrors,
                (long long unsigned int)
                    ecStats.numEcPointVerifyCompletedOutputInvalid);
            break;
        }
        case SAL_STATS_ECDH:
        {
            CpaCyEcdhStats64 ecdhStats = {0};
            status = cpaCyEcdhQueryStats64(pCryptoService, &ecdhStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyEcdhQueryStats64 returned error\n");
                return 0;
            }

            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " ECDH Stats                                       " BORDER
                "\n" SEPARATOR);
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " ECDH Pt Multiply Requests-Succ: %16llu " BORDER "\n" BORDER
                " ECDH Pt Multiply Request-Err:   %16llu " BORDER "\n" BORDER
                " ECDH Pt Multiply Completed-Succ:%16llu " BORDER "\n" BORDER
                " ECDH Pt Multiply Completed-Err: %16llu " BORDER "\n" BORDER
                " ECDH Output Invalid:            %16llu " BORDER "\n",
                (long long unsigned int)ecdhStats.numEcdhPointMultiplyRequests,
                (long long unsigned int)
                    ecdhStats.numEcdhPointMultiplyRequestErrors,
                (long long unsigned int)ecdhStats.numEcdhPointMultiplyCompleted,
                (long long unsigned int)
                    ecdhStats.numEcdhPointMultiplyCompletedError,
                (long long unsigned int)
                    ecdhStats.numEcdhRequestCompletedOutputInvalid);
            break;
        }
        case SAL_STATS_ECDSA:
        {
            CpaCyEcdsaStats64 ecdsaStats = {0};
            status = cpaCyEcdsaQueryStats64(pCryptoService, &ecdsaStats);
            if (status != CPA_STATUS_SUCCESS)
            {
                LAC_LOG_ERROR("cpaCyEcdsaQueryStats64 returned error\n");
                return 0;
            }

            len += snprintf(
                data + len,
                size - len,
                SEPARATOR BORDER
                " ECDSA Stats                                      " BORDER
                "\n" SEPARATOR);
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " ECDSA Sign R Requests-Succ:     %16llu " BORDER "\n" BORDER
                " ECDSA Sign R Request-Err:       %16llu " BORDER "\n" BORDER
                " ECDSA Sign R Completed-Succ:    %16llu " BORDER "\n" BORDER
                " ECDSA Sign R Completed-Err:     %16llu " BORDER "\n" BORDER
                " ECDSA Sign R Output Invalid:    %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)ecdsaStats.numEcdsaSignRRequests,
                (long long unsigned int)ecdsaStats.numEcdsaSignRRequestErrors,
                (long long unsigned int)ecdsaStats.numEcdsaSignRCompleted,
                (long long unsigned int)ecdsaStats.numEcdsaSignRCompletedErrors,
                (long long unsigned int)
                    ecdsaStats.numEcdsaSignRCompletedOutputInvalid);
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " ECDSA Sign S Requests-Succ:     %16llu " BORDER "\n" BORDER
                " ECDSA Sign S Request-Err:       %16llu " BORDER "\n" BORDER
                " ECDSA Sign S Completed-Succ:    %16llu " BORDER "\n" BORDER
                " ECDSA Sign S Completed-Err:     %16llu " BORDER "\n" BORDER
                " ECDSA Sign S Output Invalid:    %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)ecdsaStats.numEcdsaSignSRequests,
                (long long unsigned int)ecdsaStats.numEcdsaSignSRequestErrors,
                (long long unsigned int)ecdsaStats.numEcdsaSignSCompleted,
                (long long unsigned int)ecdsaStats.numEcdsaSignSCompletedErrors,
                (long long unsigned int)
                    ecdsaStats.numEcdsaSignSCompletedOutputInvalid);
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " ECDSA Sign RS Requests-Succ:    %16llu " BORDER "\n" BORDER
                " ECDSA Sign RS Request-Err:      %16llu " BORDER "\n" BORDER
                " ECDSA Sign RS Completed-Succ:   %16llu " BORDER "\n" BORDER
                " ECDSA Sign RS Completed-Err:    %16llu " BORDER "\n" BORDER
                " ECDSA Sign RS Output Invalid:   %16llu " BORDER
                "\n" SEPARATOR,
                (long long unsigned int)ecdsaStats.numEcdsaSignRSRequests,
                (long long unsigned int)ecdsaStats.numEcdsaSignRSRequestErrors,
                (long long unsigned int)ecdsaStats.numEcdsaSignRSCompleted,
                (long long unsigned int)
                    ecdsaStats.numEcdsaSignRSCompletedErrors,
                (long long unsigned int)
                    ecdsaStats.numEcdsaSignRSCompletedOutputInvalid);
            len += snprintf(
                data + len,
                size - len,
                BORDER
                " ECDSA Verify Requests-Succ:     %16llu " BORDER "\n" BORDER
                " ECDSA Verify Request-Err:       %16llu " BORDER "\n" BORDER
                " ECDSA Verify Completed-Succ:    %16llu " BORDER "\n" BORDER
                " ECDSA Verify Completed-Err:     %16llu " BORDER "\n" BORDER
                " ECDSA Verify Output Invalid:    %16llu " BORDER "\n",
                (long long unsigned int)ecdsaStats.numEcdsaVerifyRequests,
                (long long unsigned int)ecdsaStats.numEcdsaVerifyRequestErrors,
                (long long unsigned int)ecdsaStats.numEcdsaVerifyCompleted,
                (long long unsigned int)
                    ecdsaStats.numEcdsaVerifyCompletedErrors,
                (long long unsigned int)
                    ecdsaStats.numEcdsaVerifyCompletedOutputInvalid);
            break;
        }
        default:
        {
            len += snprintf(data + len, size - len, SEPARATOR);
            return 0;
        }
    }
    return ++offset;
}

STATIC CpaStatus
SalCtrl_GetCyConcurrentReqNum(char *string1,
                              char *section,
                              char *string2,
                              sal_crypto_service_t *pCryptoService,
                              Cpa32U *pNumCyConcurrentReq,
                              icp_accel_dev_t *device)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    Cpa32U numCyConcurrentReq = 0;

    /* get num concurrent requests from config file */
    status = Sal_StringParsing(string1,
                               pCryptoService->generic_service_info.instance,
                               string2,
                               temp_string);
    LAC_CHECK_STATUS(status);
    status =
        icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }

    numCyConcurrentReq =
        (Cpa32U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);
    if (CPA_STATUS_FAIL == validateConcurrRequest(numCyConcurrentReq))
    {
        LAC_LOG_ERROR("Invalid NumConcurrentAsymRequests, valid "
                      "values {64, 128, 256, 512, .. 32768, 65536}");
        return CPA_STATUS_FAIL;
    }

    *pNumCyConcurrentReq = numCyConcurrentReq;

    return status;
}

#ifndef ASYM_NOT_SUPPORTED
STATIC CpaStatus SalCtrl_AsymInit(icp_accel_dev_t *device,
                                  sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numAsymConcurrentReq = 0;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    char *section = DYN_SEC;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    /* get num concurrent requests from config file */
    if (CPA_STATUS_SUCCESS !=
        SalCtrl_GetCyConcurrentReqNum(SAL_CFG_CY,
                                      section,
                                      SAL_CFG_RING_ASYM_SIZE,
                                      pCryptoService,
                                      &numAsymConcurrentReq,
                                      device))
    {
        LAC_LOG_ERROR("Failed to get NumConcurrentAsymRequests");
        return CPA_STATUS_FAIL;
    }

    /* Create transport handles */
    status = SalCtrl_AsymCreateTransHandle(
        device, service, numAsymConcurrentReq, section);
    LAC_CHECK_STATUS(status);

    /* Allocates memory pools */
    pCryptoService->lac_pke_align_pool = LAC_MEM_POOL_INIT_POOL_ID;
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_ASYM_RESIZE_POOL,
                               temp_string);
    LAC_CHECK_STATUS_ASYM_INIT(status);
    status = Lac_MemPoolCreate(
        &pCryptoService->lac_pke_align_pool,
        temp_string,
        (((numAsymConcurrentReq + 1)) * LAC_PKE_BUFFERS_PER_OP_MAX),
        LAC_BITS_TO_BYTES(LAC_MAX_OP_SIZE_IN_BITS),
        LAC_64BYTE_ALIGNMENT,
        CPA_FALSE,
        pCryptoService->nodeAffinity);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Allocate pke request memory pool */
    pCryptoService->lac_pke_req_pool = LAC_MEM_POOL_INIT_POOL_ID;
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_ASYM_REQ_POOL,
                               temp_string);
    LAC_CHECK_STATUS_ASYM_INIT(status);
    status = Lac_MemPoolCreate(
        &(pCryptoService->lac_pke_req_pool),
        temp_string,
        (((numAsymConcurrentReq + 1)) * LAC_PKE_MAX_CHAIN_LENGTH),
        sizeof(lac_pke_qat_req_data_t),
        LAC_64BYTE_ALIGNMENT,
        CPA_TRUE,
        pCryptoService->nodeAffinity);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Allocate prime memory pool */
    pCryptoService->lac_prime_pool = LAC_MEM_POOL_INIT_POOL_ID;
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_ASYM_PRIME_POOL,
                               temp_string);
    LAC_CHECK_STATUS_ASYM_INIT(status);
    status = Lac_MemPoolCreate(&pCryptoService->lac_prime_pool,
                               temp_string,
                               (numAsymConcurrentReq * 2 + 1),
                               (sizeof(CpaFlatBuffer) * (LAC_PRIME_MAX_MR + 1)),
                               LAC_64BYTE_ALIGNMENT,
                               CPA_FALSE,
                               pCryptoService->nodeAffinity);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Allocate EC memory pool */
    pCryptoService->lac_ec_pool = LAC_MEM_POOL_INIT_POOL_ID;
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_ASYM_EC_MEM_POOL,
                               temp_string);
    LAC_CHECK_STATUS_ASYM_INIT(status);
    status =
        Lac_MemPoolCreate(&pCryptoService->lac_ec_pool,
                          temp_string,
                          ((numAsymConcurrentReq + 1)),
                          ((LAC_EC_NUM_CONCAT_INPUTS * LAC_EC_SIZE_BYTES_MAX) +
                           sizeof(CpaFlatBuffer)),
                          LAC_64BYTE_ALIGNMENT,
                          CPA_FALSE,
                          pCryptoService->nodeAffinity);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Clear Key stats and allocate memory of SSL and TLS labels
        These labels are initialised to standard values */

    /* Init DH stats */
    status = LacDh_Init(pCryptoService);
    LAC_CHECK_STATUS_ASYM_INIT(status);

#ifdef QAT_LEGACY_ALGORITHMS
    /* Init Dsa stats */
    status = LacDsa_Init(pCryptoService);
    LAC_CHECK_STATUS_ASYM_INIT(status);
#endif

    /* Init Ec stats */
    status = LacEc_Init(pCryptoService);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Init Ln Stats */
    status = LacLn_Init(pCryptoService);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Init Prime stats */
    status = LacPrime_Init(pCryptoService);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Init Rsa Stats */
    status = LacRsa_Init(pCryptoService);
    LAC_CHECK_STATUS_ASYM_INIT(status);

    /* Build Flow ID for all pke request sent on this instance */
    pCryptoService->pkeFlowId =
        (LAC_PKE_FLOW_ID_TAG |
         (pCryptoService->acceleratorNum << LAC_PKE_ACCEL_ID_BIT_POS) |
         (pCryptoService->executionEngine << LAC_PKE_SLICE_ID_BIT_POS));

    /* For all asym requests fill out known data */
    Lac_MemPoolInitAsymCookies(pCryptoService->lac_pke_req_pool,
                               pCryptoService);

    return status;
}

STATIC CpaStatus SalCtrl_AsymReinit(icp_accel_dev_t *device,
                                    sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numAsymConcurrentReq = 0;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    char *section = DYN_SEC;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    /* get num concurrent requests from config file */
    if (CPA_STATUS_SUCCESS !=
        SalCtrl_GetCyConcurrentReqNum(SAL_CFG_CY,
                                      section,
                                      SAL_CFG_RING_ASYM_SIZE,
                                      pCryptoService,
                                      &numAsymConcurrentReq,
                                      device))
    {
        LAC_LOG_ERROR("Failed to get NumConcurrentAsymRequests");
        return CPA_STATUS_FAIL;
    }

    /* Create transport handles */
    status = SalCtrl_AsymReinitTransHandle(
        device, service, numAsymConcurrentReq, section);
    LAC_CHECK_STATUS(status);

    /* Enables memory pools for allocation */
    Lac_MemPoolEnable(pCryptoService->lac_pke_req_pool);

    /* Build Flow ID for all pke request sent on this instance */
    pCryptoService->pkeFlowId =
        (LAC_PKE_FLOW_ID_TAG |
         (pCryptoService->acceleratorNum << LAC_PKE_ACCEL_ID_BIT_POS) |
         (pCryptoService->executionEngine << LAC_PKE_SLICE_ID_BIT_POS));

    /* For all asym requests fill out known data */
    Lac_MemPoolInitAsymCookies(pCryptoService->lac_pke_req_pool,
                               pCryptoService);

    return status;
}
#endif

STATIC CpaStatus SalCtrl_SymInit(icp_accel_dev_t *device,
                                 sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numSymConcurrentReq = 0;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    char *section = DYN_SEC;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }


    /* Set default value of HMAC mode */
    pCryptoService->qatHmacMode = ICP_QAT_HW_AUTH_MODE1;

    /* Register callbacks for the symmetric services
     * (Hash, Cipher, Algorithm-Chaining) (returns void)*/
    LacSymCb_CallbacksRegister();

    /* Get num concurrent requests from config file */
    if (CPA_STATUS_SUCCESS !=
        SalCtrl_GetCyConcurrentReqNum(SAL_CFG_CY,
                                      section,
                                      SAL_CFG_RING_SYM_SIZE,
                                      pCryptoService,
                                      &numSymConcurrentReq,
                                      device))
    {
        LAC_LOG_ERROR("Failed to get NumConcurrentAsymRequests");
        return CPA_STATUS_FAIL;
    }

    /* ADF does not allow us to completely fill the ring for batch requests */
    pCryptoService->maxNumSymReqBatch =
        (numSymConcurrentReq - SAL_BATCH_SUBMIT_FREE_SPACE);

    /* Create transport handles */
    status = SalCtrl_SymCreateTransHandle(
        device, service, numSymConcurrentReq, section);
    LAC_CHECK_STATUS(status);

    /* Allocates memory pools */

    /* Create and initialise symmetric cookie memory pool */
    pCryptoService->lac_sym_cookie_pool = LAC_MEM_POOL_INIT_POOL_ID;
    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_SYM_POOL,
                               temp_string);
    LAC_CHECK_STATUS_SYM_INIT(status);
    /* Note we need twice (i.e. <<1) the number of sym cookies to
       support sym ring pairs (and some, for partials) */
    status = Lac_MemPoolCreate(
        &pCryptoService->lac_sym_cookie_pool,
        temp_string,
        ((numSymConcurrentReq + numSymConcurrentReq + 1) << 1),
        sizeof(lac_sym_cookie_t),
        LAC_64BYTE_ALIGNMENT,
        CPA_FALSE,
        pCryptoService->nodeAffinity);
    LAC_CHECK_STATUS_SYM_INIT(status);
    /* For all sym cookies fill out the physical address of data that
       will be set to QAT */
    Lac_MemPoolInitSymCookiesPhyAddr(pCryptoService->lac_sym_cookie_pool);

    /* Clear stats */
    status = LacSymKey_StatsInit(pCryptoService);
    LAC_CHECK_STATUS_SYM_INIT(status);

    /* Clears Key stats and allocate memory of SSL and TLS labels
        These labels are initialised to standard values */
    status = LacSymKey_Init(pCryptoService);
    LAC_CHECK_STATUS_SYM_INIT(status);

    /* Initialises the hash lookup table*/
    status = LacSymQat_Init(pCryptoService);
    LAC_CHECK_STATUS_SYM_INIT(status);

    /* Fills out content descriptor for precomputes and registers the
       hash precompute callback */
    status = LacSymHash_HmacPrecompInit(pCryptoService);
    LAC_CHECK_STATUS_SYM_INIT(status);

    /* Init the Sym stats */
    status = LacSym_StatsInit(pCryptoService);
    LAC_CHECK_STATUS_SYM_INIT(status);

    return status;
}

STATIC CpaStatus SalCtrl_SymReinit(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numSymConcurrentReq = 0;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    char *section = DYN_SEC;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }


    /* Register callbacks for the symmetric services
     * (Hash, Cipher, Algorithm-Chaining) (returns void)*/
    LacSymCb_CallbacksRegister();

    /* Get num concurrent requests from config file */
    if (CPA_STATUS_SUCCESS !=
        SalCtrl_GetCyConcurrentReqNum(SAL_CFG_CY,
                                      section,
                                      SAL_CFG_RING_SYM_SIZE,
                                      pCryptoService,
                                      &numSymConcurrentReq,
                                      device))
    {
        LAC_LOG_ERROR("Failed to get NumConcurrentAsymRequests");
        return CPA_STATUS_FAIL;
    }

    /* ADF does not allow us to completely fill the ring for batch requests */
    pCryptoService->maxNumSymReqBatch =
        (numSymConcurrentReq - SAL_BATCH_SUBMIT_FREE_SPACE);

    /* Create transport handles */
    status = SalCtrl_SymReinitTransHandle(
        device, service, numSymConcurrentReq, section);
    LAC_CHECK_STATUS(status);

    /* Enables memory pools for allocation */
    Lac_MemPoolEnable(pCryptoService->lac_sym_cookie_pool);
    /* For all sym cookies fill out the physical address of data that
       will be set to QAT */
    Lac_MemPoolInitSymCookiesPhyAddr(pCryptoService->lac_sym_cookie_pool);

    return status;
}

STATIC void SalCtrl_DebugCleanup(icp_accel_dev_t *device,
                                 sal_service_t *service)
{
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;

    if (CPA_TRUE == pStatsCollection->bStatsEnabled)
    {
        /* Clean stats */
        if (NULL != pCryptoService->debug_file)
        {
            LAC_OS_FREE(pCryptoService->debug_file->name);
            LAC_OS_FREE(pCryptoService->debug_file);
            pCryptoService->debug_file = NULL;
        }
    }
}

STATIC void SalCtrl_DebugShutdown(icp_accel_dev_t *device,
                                  sal_service_t *service)
{
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    SalCtrl_DebugCleanup(device, service);
    pCryptoService->generic_service_info.stats = NULL;
}

STATIC void SalCtrl_DebugRestarting(icp_accel_dev_t *device,
                                    sal_service_t *service)
{
    SalCtrl_DebugCleanup(device, service);
}

STATIC CpaStatus SalCtrl_DebugInit(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char *instance_name = NULL;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char *section = DYN_SEC;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    if (CPA_TRUE == pStatsCollection->bStatsEnabled)
    {
        /* Get instance name for stats */
        status = LAC_OS_MALLOC(&instance_name, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
        LAC_CHECK_STATUS(status);

        status =
            Sal_StringParsing(SAL_CFG_CY,
                              pCryptoService->generic_service_info.instance,
                              SAL_CFG_NAME,
                              temp_string);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_OS_FREE(instance_name);
            return status;
        }
        status =
            icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                                  temp_string);
            LAC_OS_FREE(instance_name);
            return status;
        }
        snprintf(
            instance_name, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%s", adfGetParam);

        status = LAC_OS_MALLOC(&pCryptoService->debug_file,
                               sizeof(debug_file_info_t));
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_OS_FREE(instance_name);
            return status;
        }
        osalMemSet(pCryptoService->debug_file, 0, sizeof(debug_file_info_t));
        pCryptoService->debug_file->name = instance_name;
        pCryptoService->debug_file->seq_read = SalCtrl_CryptoDebug;
        pCryptoService->debug_file->private_data = pCryptoService;
        pCryptoService->debug_file->parent =
            pCryptoService->generic_service_info.debug_parent_dir;
    }
    pCryptoService->generic_service_info.stats = pStatsCollection;

    return status;
}

STATIC CpaStatus SalCtrl_GetBankNum(icp_accel_dev_t *device,
                                    Cpa32U inst,
                                    char *section,
                                    char *bank_name,
                                    Cpa16U *bank)
{
    char adfParamValue[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char adfParamName[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = Sal_StringParsing(SAL_CFG_CY, inst, bank_name, adfParamName);
    LAC_CHECK_STATUS(status);
    status =
        icp_adf_cfgGetParamValue(device, section, adfParamName, adfParamValue);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              adfParamName);
        return status;
    }
    *bank = (Cpa16U)Sal_Strtoul(adfParamValue, NULL, SAL_CFG_BASE_DEC);
    return status;
}

STATIC CpaStatus SalCtr_InstInit(icp_accel_dev_t *device,
                                 sal_service_t *service)
{
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string2[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char *section = DYN_SEC;
    Cpa32S strSize = 0;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }


    /* Get Config Info: Accel Num, bank Num, packageID,
                            coreAffinity, nodeAffinity and response mode */

    pCryptoService->acceleratorNum = 0;

        switch (service->type)
        {
            case SAL_SERVICE_TYPE_CRYPTO_ASYM:
                status = SalCtrl_GetBankNum(
                    device,
                    pCryptoService->generic_service_info.instance,
                    section,
                    "BankNumberAsym",
                    &pCryptoService->bankNumAsym);
                if (CPA_STATUS_SUCCESS != status)
                    return status;
                break;
            case SAL_SERVICE_TYPE_CRYPTO_SYM:
                status = SalCtrl_GetBankNum(
                    device,
                    pCryptoService->generic_service_info.instance,
                    section,
                    "BankNumberSym",
                    &pCryptoService->bankNumSym);
                if (CPA_STATUS_SUCCESS != status)
                    return status;
                break;
            case SAL_SERVICE_TYPE_CRYPTO:
                status = SalCtrl_GetBankNum(
                    device,
                    pCryptoService->generic_service_info.instance,
                    section,
                    "BankNumberAsym",
                    &pCryptoService->bankNumAsym);
                if (CPA_STATUS_SUCCESS != status)
                    return status;
                status = SalCtrl_GetBankNum(
                    device,
                    pCryptoService->generic_service_info.instance,
                    section,
                    "BankNumberSym",
                    &pCryptoService->bankNumSym);
                if (CPA_STATUS_SUCCESS != status)
                    return status;
                break;
            default:
                return CPA_STATUS_FAIL;
        }

    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_POLL_MODE,
                               temp_string);
    LAC_CHECK_STATUS(status);
    status =
        icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }
    pCryptoService->isPolled =
        (Cpa8U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

#ifdef KERNEL_SPACE
    /* Kernel instances do not support epoll mode */
    if (SAL_RESP_EPOLL_CFG_FILE == pCryptoService->isPolled)
    {
        LAC_LOG_ERROR_PARAMS(
            "IsPolled %u is not supported for kernel instance %s",
            pCryptoService->isPolled,
            temp_string);
        return CPA_STATUS_FAIL;
    }
#endif
#ifndef KERNEL_SPACE
    /* User instances only support poll and epoll mode */
    if (SAL_RESP_POLL_CFG_FILE != pCryptoService->isPolled &&
        SAL_RESP_EPOLL_CFG_FILE != pCryptoService->isPolled)
    {
        LAC_LOG_ERROR_PARAMS("IsPolled %u is not supported for "
                             "user instance %s",
                             pCryptoService->isPolled,
                             temp_string);
        return CPA_STATUS_FAIL;
    }
#endif

    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_DEV_PKG_ID, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              ADF_DEV_PKG_ID);
        return status;
    }
    pCryptoService->pkgID =
        (Cpa16U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_DEV_NODE_ID, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              ADF_DEV_NODE_ID);
        return status;
    }
    pCryptoService->nodeAffinity =
        (Cpa32U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);
    /* In case of interrupt instance, use the bank affinity set by adf_ctl
     * Otherwise, use the instance affinity for backwards compatibility */
    if (SAL_RESP_POLL_CFG_FILE != pCryptoService->isPolled)
    {
        /* Next need to read the [AcceleratorX] section of the config file */
        status = Sal_StringParsing(SAL_CFG_ACCEL_SEC,
                                   pCryptoService->acceleratorNum,
                                   "",
                                   temp_string2);
        LAC_CHECK_STATUS(status);
        if (service->type == SAL_SERVICE_TYPE_CRYPTO_ASYM)
            status = Sal_StringParsing(SAL_CFG_ETRMGR_BANK,
                                       pCryptoService->bankNumAsym,
                                       SAL_CFG_ETRMGR_CORE_AFFINITY,
                                       temp_string);
        else
            /* For cy service, asym bank and sym bank will set the same
               core affinity. So Just read one*/
            status = Sal_StringParsing(SAL_CFG_ETRMGR_BANK,
                                       pCryptoService->bankNumSym,
                                       SAL_CFG_ETRMGR_CORE_AFFINITY,
                                       temp_string);
        LAC_CHECK_STATUS(status);
    }
    else
    {
        strSize = snprintf(temp_string2, sizeof(temp_string2), "%s", section);
        LAC_CHECK_PARAM_RANGE(strSize, 1, sizeof(temp_string2));

        status =
            Sal_StringParsing(SAL_CFG_CY,
                              pCryptoService->generic_service_info.instance,
                              SAL_CFG_ETRMGR_CORE_AFFINITY,
                              temp_string);
        LAC_CHECK_STATUS(status);
    }

    status = icp_adf_cfgGetParamValue(
        device, temp_string2, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }
    pCryptoService->coreAffinity =
        (Cpa32U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

    /* No Execution Engine in DH895xcc, so make sure it is zero */
    pCryptoService->executionEngine = 0;

    return status;
}

/* This function:
 * 1. Creates sym and asym transport handles
 * 2. Allocates memory pools required by sym and asym services
.* 3. Clears the sym and asym stats counters
 * 4. In case service asym or sym is enabled then this function
 *    only allocates resources for these services. i.e if the
 *    service asym is enabled then only asym transport handles
 *    are created and vice versa.
 */
CpaStatus SalCtrl_CryptoInit(icp_accel_dev_t *device, sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    sal_service_type_t svc_type = service->type;

    SAL_SERVICE_GOOD_FOR_INIT(pCryptoService);
    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_INITIALIZING;

    /* Set up the instance parameters such as bank number,
     * coreAffinity, pkgId and node affinity etc
     */
    status = SalCtr_InstInit(device, service);
    LAC_CHECK_STATUS(status);

    /* Create debug directory for service */
    status = SalCtrl_DebugInit(device, service);
    LAC_CHECK_STATUS(status);

    switch (svc_type)
    {
#ifndef ASYM_NOT_SUPPORTED
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            status = SalCtrl_AsymInit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
                return status;
            }
            break;
#endif
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            status = SalCtrl_SymInit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
                return status;
            }
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
            status = SalCtrl_AsymInit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
                return status;
            }
#endif
            status = SalCtrl_SymInit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
#ifndef ASYM_NOT_SUPPORTED
                SalCtrl_AsymFreeResources(pCryptoService);
#endif
                return status;
            }
            break;
        default:
            LAC_LOG_ERROR("Invalid service type\n");
            status = CPA_STATUS_FAIL;
            break;
    }

    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_INITIALIZED;

    return status;
}

CpaStatus SalCtrl_CryptoStart(icp_accel_dev_t *device, sal_service_t *service)
{
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (pCryptoService->generic_service_info.state !=
        SAL_SERVICE_STATE_INITIALIZED)
    {
        LAC_LOG_ERROR("Not in the correct state to call start\n");
        return CPA_STATUS_FAIL;
    }

    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_RUNNING;
    return status;
}

CpaStatus SalCtrl_CryptoStop(icp_accel_dev_t *device, sal_service_t *service)
{
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    if (SAL_SERVICE_STATE_RUNNING != pCryptoService->generic_service_info.state)
    {
        LAC_LOG_ERROR("Not in the correct state to call stop");
    }

    pCryptoService->generic_service_info.state =
        SAL_SERVICE_STATE_SHUTTING_DOWN;
    return CPA_STATUS_SUCCESS;
}

CpaStatus SalCtrl_CryptoShutdown(icp_accel_dev_t *device,
                                 sal_service_t *service)
{
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_service_type_t svc_type = service->type;

    if ((SAL_SERVICE_STATE_INITIALIZED !=
         pCryptoService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_SHUTTING_DOWN !=
         pCryptoService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_RESTARTING !=
         pCryptoService->generic_service_info.state))
    {
        LAC_LOG_ERROR("Not in the correct state to call shutdown \n");
        return CPA_STATUS_FAIL;
    }


    /* Free memory and transhandles */
    switch (svc_type)
    {
#ifndef ASYM_NOT_SUPPORTED
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            if (SalCtrl_AsymFreeResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
            break;
#endif
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            if (SalCtrl_SymFreeResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
            if (SalCtrl_AsymFreeResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
#endif
            if (SalCtrl_SymFreeResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
            break;
        default:
            LAC_LOG_ERROR("Invalid service type\n");
            status = CPA_STATUS_FAIL;
            break;
    }

    SalCtrl_DebugShutdown(device, service);

    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_SHUTDOWN;

    return status;
}

CpaStatus SalCtrl_CryptoError(icp_accel_dev_t *device, sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;

    LAC_CHECK_NULL_PARAM(service);

    SalCtrl_CyMemPoolDisable(service);
    SalCtrl_CyUpdatePoolsBusy(service);

    /* Considering the detachment of the VFs, the device is still alive and
     * can generate responses normally. After the state of the service is
     * set to ERROR, if it goes to the function to check responses in such
     * cases, it will indicate there are some responses on the ring. However,
     * icp_sal_CyPollInstance() function will only call
     * SalCtrl_CyGenResponses() to generate dummy responses not poll the
     * instance with icp_adf_pollInstance() as the service has been set to
     * ERROR. So adding a judgment condition here to avoid to check the
     * response ring again. */
    if (SAL_SERVICE_STATE_ERROR != pCryptoService->generic_service_info.state)
    {
        status = SalCtrl_CyCheckRespInstance(service);
        /* The polling functions would be prevented to poll due to
         * SAL_RUNNING_CHECK check which may cause missing retrieving in-flight
         * responses. Hence the error status is only set after there are no
         * remained responses on the response ring. */
        if (CPA_STATUS_SUCCESS == status)
        {
            pCryptoService->generic_service_info.state =
                SAL_SERVICE_STATE_ERROR;
        }
    }
    return status;
}

CpaStatus SalCtrl_CryptoRestarting(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_service_type_t svc_type = service->type;

    if ((SAL_SERVICE_STATE_RUNNING !=
         pCryptoService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_ERROR != pCryptoService->generic_service_info.state))
    {
        LAC_LOG_ERROR("Not in the correct state to call restarting\n");
        return CPA_STATUS_FAIL;
    }

    switch (svc_type)
    {
#ifndef ASYM_NOT_SUPPORTED
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            if (SalCtrl_AsymResetResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
            break;
#endif
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            if (SalCtrl_SymResetResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
            if (SalCtrl_AsymResetResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
#endif
            if (SalCtrl_SymResetResources(pCryptoService))
            {
                status = CPA_STATUS_FAIL;
            }
            break;
        default:
            LAC_LOG_ERROR("Invalid service type\n");
            status = CPA_STATUS_FAIL;
            break;
    }

    SalCtrl_DebugRestarting(device, service);

    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_RESTARTING;

    return status;
}

CpaStatus SalCtrl_CryptoRestarted(icp_accel_dev_t *device,
                                  sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = (sal_crypto_service_t *)service;
    sal_service_type_t svc_type = service->type;

    SAL_SERVICE_GOOD_FOR_RESTARTED(pCryptoService);
    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_INITIALIZING;

    /* Set up the instance parameters such as bank number,
     * coreAffinity, pkgId and node affinity etc
     */
    status = SalCtr_InstInit(device, service);
    LAC_CHECK_STATUS(status);

    /* Create debug directory for service */
    status = SalCtrl_DebugInit(device, service);
    LAC_CHECK_STATUS(status);

    switch (svc_type)
    {
#ifndef ASYM_NOT_SUPPORTED
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            status = SalCtrl_AsymReinit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
                return status;
            }
            break;
#endif
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            status = SalCtrl_SymReinit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
                return status;
            }
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
#ifndef ASYM_NOT_SUPPORTED
            status = SalCtrl_AsymReinit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
                return status;
            }
#endif
            status = SalCtrl_SymReinit(device, service);
            if (CPA_STATUS_SUCCESS != status)
            {
                SalCtrl_DebugShutdown(device, service);
#ifndef ASYM_NOT_SUPPORTED
                SalCtrl_AsymFreeResources(pCryptoService);
#endif
                return status;
            }
            break;
        default:
            SalCtrl_DebugShutdown(device, service);
            LAC_LOG_ERROR("Invalid service type\n");
            status = CPA_STATUS_FAIL;
            break;
    }

    pCryptoService->generic_service_info.state = SAL_SERVICE_STATE_RUNNING;

    return status;
}

void SalCtrl_CyQueryCapabilities(sal_service_t *pGenericService,
                                 CpaCyCapabilitiesInfo *pCapInfo)
{
    osalMemSet(pCapInfo, 0, sizeof(CpaCyCapabilitiesInfo));

    if (SAL_SERVICE_TYPE_CRYPTO == pGenericService->type ||
        SAL_SERVICE_TYPE_CRYPTO_SYM == pGenericService->type)
    {
        pCapInfo->symSupported = CPA_TRUE;
        if (pGenericService->capabilitiesMask &
            ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN)
        {
            pCapInfo->extAlgchainSupported = CPA_TRUE;
        }
        if (pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_HKDF)
        {
            pCapInfo->hkdfSupported = CPA_TRUE;
        }
    }

    if (SAL_SERVICE_TYPE_CRYPTO == pGenericService->type ||
        SAL_SERVICE_TYPE_CRYPTO_ASYM == pGenericService->type)
    {
#ifdef ASYM_NOT_SUPPORTED
        pCapInfo->dhSupported = CPA_FALSE;
        pCapInfo->dsaSupported = CPA_FALSE;
        pCapInfo->rsaSupported = CPA_FALSE;
        pCapInfo->ecSupported = CPA_FALSE;
        pCapInfo->ecdhSupported = CPA_FALSE;
        pCapInfo->ecdsaSupported = CPA_FALSE;
        pCapInfo->keySupported = CPA_FALSE;
        pCapInfo->lnSupported = CPA_FALSE;
        pCapInfo->primeSupported = CPA_FALSE;
        pCapInfo->ecEdMontSupported = CPA_FALSE;
#else
        pCapInfo->dhSupported = CPA_TRUE;
#ifdef QAT_LEGACY_ALGORITHMS
        pCapInfo->dsaSupported = CPA_TRUE;
#else
        pCapInfo->dsaSupported = CPA_FALSE;
#endif
        pCapInfo->rsaSupported = CPA_TRUE;
        pCapInfo->ecSupported = CPA_TRUE;
        pCapInfo->ecdhSupported = CPA_TRUE;
        pCapInfo->ecdsaSupported = CPA_TRUE;
        pCapInfo->keySupported = CPA_TRUE;
        pCapInfo->lnSupported = CPA_TRUE;
        pCapInfo->primeSupported = CPA_TRUE;
        if (pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_ECEDMONT)
        {
            pCapInfo->ecEdMontSupported = CPA_TRUE;
        }
#endif
    }
    pCapInfo->drbgSupported = CPA_FALSE;
    pCapInfo->nrbgSupported = CPA_FALSE;
    pCapInfo->randSupported = CPA_FALSE;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyGetStatusText(const CpaInstanceHandle instanceHandle,
                             CpaStatus errStatus,
                             Cpa8S *pStatusText)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, %d, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             errStatus,
             (LAC_ARCH_UINT)pStatusText);
#endif

    LAC_CHECK_NULL_PARAM(pStatusText);

    switch (errStatus)
    {
        case CPA_STATUS_SUCCESS:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_SUCCESS);
            break;
        case CPA_STATUS_FAIL:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_FAIL);
            break;
        case CPA_STATUS_RETRY:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_RETRY);
            break;
        case CPA_STATUS_RESOURCE:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_RESOURCE);
            break;
        case CPA_STATUS_INVALID_PARAM:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_INVALID_PARAM);
            break;
        case CPA_STATUS_FATAL:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_FATAL);
            break;
        case CPA_STATUS_UNSUPPORTED:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_UNSUPPORTED);
            break;
        default:
            status = CPA_STATUS_INVALID_PARAM;
            break;
    }
    return status;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyStartInstance(CpaInstanceHandle instanceHandle_in)
{
    CpaInstanceHandle instanceHandle = NULL;

/* Structure initializer is supported by C99, but it is
 * not supported by some former Intel compilers. */
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(disable : 188)
#endif
    CpaInstanceInfo2 info = {0};
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(enable)
#endif
    icp_accel_dev_t *dev = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)instanceHandle_in);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_CryptoGetFirstHandle();
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }
    LAC_CHECK_NULL_PARAM(instanceHandle);

    pService = (sal_crypto_service_t *)instanceHandle;

    status = cpaCyInstanceGetInfo2(instanceHandle, &info);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not get instance info\n");
        return status;
    }
    dev = icp_adf_getAccelDevByAccelId(info.physInstId.packageId);
    if (NULL == dev)
    {
        LAC_LOG_ERROR("Can not find device for the instance\n");
        return CPA_STATUS_FAIL;
    }

    pService->generic_service_info.isInstanceStarted = CPA_TRUE;

    /* Increment dev ref counter */
    icp_adf_qaDevGet(dev);
    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyStopInstance(CpaInstanceHandle instanceHandle_in)
{
    CpaInstanceHandle instanceHandle = NULL;

/* Structure initializer is supported by C99, but it is
 * not supported by some former Intel compilers. */
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(disable : 188)
#endif
    CpaInstanceInfo2 info = {0};
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(enable)
#endif
    icp_accel_dev_t *dev = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)instanceHandle_in);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_CryptoGetFirstHandle();
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }
    LAC_CHECK_NULL_PARAM(instanceHandle);

    status = cpaCyInstanceGetInfo2(instanceHandle, &info);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not get instance info\n");
        return status;
    }
    dev = icp_adf_getAccelDevByAccelId(info.physInstId.packageId);
    if (NULL == dev)
    {
        LAC_LOG_ERROR("Can not find device for the instance\n");
        return CPA_STATUS_FAIL;
    }

    pService = (sal_crypto_service_t *)instanceHandle;


    pService->generic_service_info.isInstanceStarted = CPA_FALSE;

    /* Decrement dev ref counter */
    icp_adf_qaDevPut(dev);
    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyInstanceSetNotificationCb(
    const CpaInstanceHandle instanceHandle,
    const CpaCyInstanceNotificationCbFunc pInstanceNotificationCb,
    void *pCallbackTag)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_service_t *gen_handle = instanceHandle;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pInstanceNotificationCb,
             (LAC_ARCH_UINT)pCallbackTag);
#endif

    LAC_CHECK_NULL_PARAM(gen_handle);
    gen_handle->notification_cb = pInstanceNotificationCb;
    gen_handle->cb_tag = pCallbackTag;
    return status;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyGetNumInstances(Cpa16U *pNumInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0;
    Cpa16U num_inst = 0;
    Cpa16U i = 0;

    LAC_CHECK_NULL_PARAM(pNumInstances);

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }
    num_accel_dev = 0;
    /* Get ADF to return all accel_devs that support either
     * symmetric or asymmetric crypto */
    status = icp_adf_getAllAccelDevByCapabilities(
        (ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
         ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC),
        pAdfInsts,
        &num_accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("No support for crypto\n");
        *pNumInstances = 0;
        osalMemFree(pAdfInsts);
        return status;
    }

    for (i = 0; i < num_accel_dev; i++)
    {
        dev_addr = (icp_accel_dev_t *)pAdfInsts[i];
        if (NULL == dev_addr || NULL == dev_addr->pSalHandle)
        {
            continue;
        }

        base_addr = dev_addr->pSalHandle;
        list_temp = base_addr->crypto_services;
        while (NULL != list_temp)
        {
            num_inst++;
            list_temp = SalList_next(list_temp);
        }
        list_temp = base_addr->asym_services;
        while (NULL != list_temp)
        {
            num_inst++;
            list_temp = SalList_next(list_temp);
        }
        list_temp = base_addr->sym_services;
        while (NULL != list_temp)
        {
            num_inst++;
            list_temp = SalList_next(list_temp);
        }
    }
    *pNumInstances = num_inst;
    osalMemFree(pAdfInsts);

#ifdef ICP_TRACE
    if (NULL != pNumInstances)
    {
        LAC_LOG2("Called with params (0x%lx[%d])\n",
                 (LAC_ARCH_UINT)pNumInstances,
                 *pNumInstances);
    }
    else
    {
        LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)pNumInstances);
    }
#endif

    return status;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyGetInstances(Cpa16U numInstances,
                            CpaInstanceHandle *pCyInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0;
    Cpa16U num_allocated_instances = 0;
    Cpa16U index = 0;
    Cpa16U i = 0;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (%d, 0x%lx)\n",
             numInstances,
             (LAC_ARCH_UINT)pCyInstances);
#endif

    LAC_CHECK_NULL_PARAM(pCyInstances);
    if (0 == numInstances)
    {
        LAC_INVALID_PARAM_LOG("NumInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Get the number of crypto instances */
    status = cpaCyGetNumInstances(&num_allocated_instances);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    if (numInstances > num_allocated_instances)
    {
        LAC_LOG_ERROR1("Only %d crypto instances available",
                       num_allocated_instances);
        return CPA_STATUS_RESOURCE;
    }

    /* Get the number of accel devices in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }

    num_accel_dev = 0;
    /* Get ADF to return all accel_devs that support either
     * symmetric or asymmetric crypto */
    status = icp_adf_getAllAccelDevByCapabilities(
        (ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
         ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC),
        pAdfInsts,
        &num_accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("No support for crypto\n");
        osalMemFree(pAdfInsts);
        return status;
    }

    for (i = 0; i < num_accel_dev; i++)
    {
        dev_addr = (icp_accel_dev_t *)pAdfInsts[i];
        /* Note dev_addr cannot be NULL here as numInstances = 0
         * is not valid and if dev_addr = NULL then index = 0 (which
         * is less than numInstances and status is set to _RESOURCE
         * above
         */
        base_addr = dev_addr->pSalHandle;
        if (NULL == base_addr)
        {
            continue;
        }
        list_temp = base_addr->crypto_services;
        while (NULL != list_temp)
        {
            if (index > (numInstances - 1))
            {
                break;
            }
            pCyInstances[index] = SalList_getObject(list_temp);
            list_temp = SalList_next(list_temp);
            index++;
        }
        list_temp = base_addr->asym_services;
        while (NULL != list_temp)
        {
            if (index > (numInstances - 1))
            {
                break;
            }
            pCyInstances[index] = SalList_getObject(list_temp);
            list_temp = SalList_next(list_temp);
            index++;
        }
        list_temp = base_addr->sym_services;
        while (NULL != list_temp)
        {
            if (index > (numInstances - 1))
            {
                break;
            }
            pCyInstances[index] = SalList_getObject(list_temp);
            list_temp = SalList_next(list_temp);
            index++;
        }
    }
    osalMemFree(pAdfInsts);

    return status;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyInstanceGetInfo(const CpaInstanceHandle instanceHandle_in,
                               struct _CpaInstanceInfo *pInstanceInfo)
{
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
    sal_service_t *pGenericService = NULL;

    Cpa8U name[CPA_INST_NAME_SIZE] =
        "Intel(R) DH89XXCC instance number: %02x, type: Crypto";
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pInstanceInfo);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_CryptoGetFirstHandle();
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_NULL_PARAM(instanceHandle);
    LAC_CHECK_NULL_PARAM(pInstanceInfo);
    SAL_CHECK_INSTANCE_TYPE(instanceHandle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    pInstanceInfo->type = CPA_INSTANCE_TYPE_CRYPTO;

    /* According to cpa.h instance state is initialized and ready for use
     * or shutdown. Therefore need to map our running state to initialised
     * or shutdown */
    if (SAL_SERVICE_STATE_RUNNING == pCryptoService->generic_service_info.state)
    {
        pInstanceInfo->state = CPA_INSTANCE_STATE_INITIALISED;
    }
    else
    {
        pInstanceInfo->state = CPA_INSTANCE_STATE_SHUTDOWN;
    }

    pGenericService = (sal_service_t *)instanceHandle;
    snprintf((char *)pInstanceInfo->name,
             CPA_INST_NAME_SIZE,
             (char *)name,
             pGenericService->instance);

    pInstanceInfo->name[CPA_INST_NAME_SIZE - 1] = '\0';

    snprintf((char *)pInstanceInfo->version,
             CPA_INSTANCE_MAX_NAME_SIZE_IN_BYTES,
             "%d.%d",
             CPA_CY_API_VERSION_NUM_MAJOR,
             CPA_CY_API_VERSION_NUM_MINOR);

    pInstanceInfo->version[CPA_INSTANCE_MAX_VERSION_SIZE_IN_BYTES - 1] = '\0';
    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyInstanceGetInfo2(const CpaInstanceHandle instanceHandle_in,
                                CpaInstanceInfo2 *pInstanceInfo2)
{
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
    icp_accel_dev_t *dev = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char keyStr[ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {0};
    char valStr[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char *section = DYN_SEC;
    Cpa32S strSize = 0;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pInstanceInfo2);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_CryptoGetFirstHandle();
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_NULL_PARAM(instanceHandle);
    LAC_CHECK_NULL_PARAM(pInstanceInfo2);
    SAL_CHECK_INSTANCE_TYPE(instanceHandle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));

    LAC_OS_BZERO(pInstanceInfo2, sizeof(CpaInstanceInfo2));
    pInstanceInfo2->accelerationServiceType = CPA_ACC_SVC_TYPE_CRYPTO;
    snprintf((char *)pInstanceInfo2->vendorName,
             CPA_INST_VENDOR_NAME_SIZE,
             "%s",
             SAL_INFO2_VENDOR_NAME);
    pInstanceInfo2->vendorName[CPA_INST_VENDOR_NAME_SIZE - 1] = '\0';

    snprintf((char *)pInstanceInfo2->swVersion,
             CPA_INST_SW_VERSION_SIZE,
             "Version %d.%d",
             SAL_INFO2_DRIVER_SW_VERSION_MAJ_NUMBER,
             SAL_INFO2_DRIVER_SW_VERSION_MIN_NUMBER);
    pInstanceInfo2->swVersion[CPA_INST_SW_VERSION_SIZE - 1] = '\0';

    /* Note we can safely read the contents of the crypto service instance
       here because icp_adf_getAllAccelDevByCapabilities() only returns devs
       that have started */
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    pInstanceInfo2->physInstId.packageId = pCryptoService->pkgID;
    pInstanceInfo2->physInstId.acceleratorId = pCryptoService->acceleratorNum;
    pInstanceInfo2->physInstId.executionEngineId =
        pCryptoService->executionEngine;
    pInstanceInfo2->physInstId.busAddress =
        icp_adf_getBusAddress(pInstanceInfo2->physInstId.packageId);

    /* set coreAffinity to zero before use */
    LAC_OS_BZERO(pInstanceInfo2->coreAffinity,
                 sizeof(pInstanceInfo2->coreAffinity));
    CPA_BITMAP_BIT_SET(pInstanceInfo2->coreAffinity,
                       pCryptoService->coreAffinity);
    pInstanceInfo2->nodeAffinity = pCryptoService->nodeAffinity;

    if (CPA_TRUE == pCryptoService->generic_service_info.isInstanceStarted)
    {
        pInstanceInfo2->operState = CPA_OPER_STATE_UP;
    }
    else
    {
        pInstanceInfo2->operState = CPA_OPER_STATE_DOWN;
    }

    pInstanceInfo2->requiresPhysicallyContiguousMemory = CPA_TRUE;
    if (SAL_RESP_POLL_CFG_FILE == pCryptoService->isPolled ||
        SAL_RESP_EPOLL_CFG_FILE == pCryptoService->isPolled)
    {
        pInstanceInfo2->isPolled = CPA_TRUE;
    }
    else
    {
        pInstanceInfo2->isPolled = CPA_FALSE;
    }
    pInstanceInfo2->isOffloaded = CPA_TRUE;

    /* Get the instance name and part name*/
    dev = icp_adf_getAccelDevByAccelId(pCryptoService->pkgID);
    if (NULL == dev)
    {
        LAC_LOG_ERROR("Can not find device for the instance\n");
        LAC_OS_BZERO(pInstanceInfo2, sizeof(CpaInstanceInfo2));
        return CPA_STATUS_FAIL;
    }
    snprintf((char *)pInstanceInfo2->partName,
             CPA_INST_PART_NAME_SIZE,
             SAL_INFO2_PART_NAME,
             dev->deviceName);
    pInstanceInfo2->partName[CPA_INST_PART_NAME_SIZE - 1] = '\0';

    status = Sal_StringParsing(SAL_CFG_CY,
                               pCryptoService->generic_service_info.instance,
                               SAL_CFG_NAME,
                               keyStr);
    LAC_CHECK_STATUS(status);

    if (CPA_FALSE == pCryptoService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    status = icp_adf_cfgGetParamValue(dev, section, keyStr, valStr);
    LAC_CHECK_STATUS(status);

    strSize = snprintf(
        (char *)pInstanceInfo2->instName, CPA_INST_NAME_SIZE, "%s", valStr);
    LAC_CHECK_PARAM_RANGE(strSize, 1, CPA_INST_NAME_SIZE);

    strSize = snprintf((char *)pInstanceInfo2->instID,
                       CPA_INST_ID_SIZE,
                       "%s_%s",
                       section,
                       valStr);
    LAC_CHECK_PARAM_RANGE(strSize, 1, CPA_INST_ID_SIZE);

    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCyQueryCapabilities(const CpaInstanceHandle instanceHandle_in,
                                 CpaCyCapabilitiesInfo *pCapInfo)
{
    /* Verify Instance exists */
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pCapInfo);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_CryptoGetFirstHandle();
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_NULL_PARAM(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(instanceHandle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pCapInfo);

    SalCtrl_CyQueryCapabilities((sal_service_t *)instanceHandle, pCapInfo);

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaCySymQueryCapabilities(const CpaInstanceHandle instanceHandle_in,
                                    CpaCySymCapabilitiesInfo *pCapInfo)
{
    sal_crypto_service_t *pCryptoService = NULL;
    sal_service_t *pGenericService = NULL;
    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pCapInfo);
#endif
    /* Verify Instance exists */
    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO);
        if (!instanceHandle)
        {
            instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
        }
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_NULL_PARAM(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(instanceHandle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pCapInfo);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;
    pGenericService = &(pCryptoService->generic_service_info);

    osalMemSet(pCapInfo, '\0', sizeof(CpaCySymCapabilitiesInfo));
    /* An asym crypto instance does not support sym service */
    if (SAL_SERVICE_TYPE_CRYPTO_ASYM == pGenericService->type)
    {
        return CPA_STATUS_SUCCESS;
    }

    if (pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_CIPHER)
    {
#ifdef QAT_LEGACY_ALGORITHMS
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_AES_ECB);
#endif
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_NULL);
        
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_AES_CBC);
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_AES_CTR);
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_AES_XTS);
    }

    if (pGenericService->capabilitiesMask &
        ICP_ACCEL_CAPABILITIES_AUTHENTICATION)
    {
#ifdef QAT_LEGACY_ALGORITHMS
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA1);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA224);
#endif
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA256);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA384);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA512);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_AES_XCBC);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_AES_CMAC);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_AES_CBC_MAC);
    }

    if ((pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_CIPHER) &&
        (pGenericService->capabilitiesMask &
         ICP_ACCEL_CAPABILITIES_AUTHENTICATION))
    {
        /* When one of the following cipher algorithms is used, the elements of
         * the CpaCySymHashAlgorithm enum MUST be used to set up the related
         * CpaCySymHashSetupData structure in the session context.
         *    CPA_CY_SYM_CIPHER_AES_CCM
         *    CPA_CY_SYM_CIPHER_AES_GCM
         */
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_AES_CCM);
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_AES_GCM);

        /* When one of the following hash algorithms is used, the elements of
         * the CpaCySymCipherAlgorithm enum MUST be used to set up the related
         * CpaCySymCipherSetupData structure in the session context.
         *    CPA_CY_SYM_HASH_AES_CCM
         *    CPA_CY_SYM_HASH_AES_GCM
         *    CPA_CY_SYM_HASH_AES_GMAC
         */
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_AES_CCM);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_AES_GCM);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_AES_GMAC);
    }


    if (pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SHA3)
    {
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA3_256);
    }
    if (pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_CHACHA_POLY)
    {
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_POLY);
        CPA_BITMAP_BIT_SET(pCapInfo->ciphers, CPA_CY_SYM_CIPHER_CHACHA);
    }

    pCapInfo->partialPacketSupported = CPA_TRUE;

    if (pGenericService->capabilitiesMask & ICP_ACCEL_CAPABILITIES_SHA3_EXT)
    {
#ifdef QAT_LEGACY_ALGORITHMS
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA3_224);
#endif
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA3_256);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA3_384);
        CPA_BITMAP_BIT_SET(pCapInfo->hashes, CPA_CY_SYM_HASH_SHA3_512);
    }
    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 *****************************************************************************/
CpaStatus cpaCySetAddressTranslation(const CpaInstanceHandle instanceHandle_in,
                                     CpaVirtualToPhysical virtual2physical)
{

    CpaInstanceHandle instanceHandle = NULL;
    sal_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)virtual2physical);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_CryptoGetFirstHandle();
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_NULL_PARAM(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(instanceHandle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(virtual2physical);

    pService = (sal_service_t *)instanceHandle;

    pService->virt2PhysClient = virtual2physical;

    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaCyCommon
 * Crypto specific polling function which polls a crypto instance.
 *****************************************************************************/
CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle_in,
                                 Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *crypto_handle = NULL;
    sal_service_t *gen_handle = NULL;
    icp_comms_trans_handle trans_hndTable[MAX_CY_RX_RINGS];
    Cpa32U num_rx_rings = 0;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        crypto_handle = (sal_crypto_service_t *)Lac_CryptoGetFirstHandle();
    }
    else
    {
        crypto_handle = (sal_crypto_service_t *)instanceHandle_in;
    }
    LAC_CHECK_NULL_PARAM(crypto_handle);
    SAL_CHECK_INSTANCE_TYPE(crypto_handle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));

    gen_handle = &(crypto_handle->generic_service_info);

    if ((Sal_ServiceIsInError(crypto_handle)))
    {

        LAC_LOG_DEBUG("PollCyInstance: generate dummy responses\n");
        status = SalCtrl_CyGenResponses(crypto_handle, gen_handle);
        if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
        {
            LAC_LOG_ERROR("Failed to Generate Responses for CY\n");
        }
        return status;
    }

    SAL_RUNNING_CHECK(crypto_handle);

    /*
     * From the instanceHandle we must get the trans_handle and send
     * down to adf for polling.
     * Populate our trans handle table with the appropriate handles.
     */
    switch (gen_handle->type)
    {
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_asym_rx;
            num_rx_rings = 1;
            break;
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_sym_rx;
            num_rx_rings = 1;
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
            trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_sym_rx;
            trans_hndTable[TH_CY_RX_1] = crypto_handle->trans_handle_asym_rx;
            num_rx_rings = MAX_CY_RX_RINGS;
            break;
        default:
            break;
    }

    /* Call adf to do the polling. */
    status = icp_adf_pollInstance(trans_hndTable, num_rx_rings, response_quota);

    return status;
}

/*
 ******************************************************************************
 * @ingroup cpaCyCommon
 * Crypto specific polling function which polls a symmetric instance.
 *****************************************************************************/
CpaStatus icp_sal_CyPollSymRing(CpaInstanceHandle instanceHandle_in,
                                Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *crypto_handle = NULL;
    icp_comms_trans_handle trans_hndTable[NUM_CRYPTO_SYM_RX_RINGS] = {0};

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        crypto_handle = (sal_crypto_service_t *)Lac_GetFirstHandle(
            SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        crypto_handle = (sal_crypto_service_t *)instanceHandle_in;
    }
    LAC_CHECK_NULL_PARAM(crypto_handle);
    SAL_CHECK_INSTANCE_TYPE(
        crypto_handle, (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    SAL_RUNNING_CHECK(crypto_handle);
    /*
     * From the instanceHandle we must get the trans_handle and send
     * down to adf for polling.
     * Populate trans handle table with the appropriate handle.
     */
    trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_sym_rx;
    /* Call adf to do the polling. */
    status = icp_adf_pollInstance(
        trans_hndTable, NUM_CRYPTO_SYM_RX_RINGS, response_quota);
    return status;
}

/*
 ******************************************************************************
 * @ingroup cpaCyCommon
 * Crypto specific polling function which polls an asymmetric instance.
 *****************************************************************************/
CpaStatus icp_sal_CyPollAsymRing(CpaInstanceHandle instanceHandle_in,
                                 Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *crypto_handle = NULL;
    sal_service_t *gen_handle = NULL;
    icp_comms_trans_handle trans_hndTable[NUM_CRYPTO_ASYM_RX_RINGS] = {0};

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        crypto_handle = (sal_crypto_service_t *)Lac_GetFirstHandle(
            SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        crypto_handle = (sal_crypto_service_t *)instanceHandle_in;
    }
    LAC_CHECK_NULL_PARAM(crypto_handle);
    SAL_CHECK_INSTANCE_TYPE(
        crypto_handle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    gen_handle = &(crypto_handle->generic_service_info);

    if ((Sal_ServiceIsInError(crypto_handle)))
    {
        LAC_LOG_DEBUG("Generate dummy responses\n");
        status = SalCtrl_CyGenResponses(crypto_handle, gen_handle);
        if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
        {
            LAC_LOG_ERROR("Failed to generate dummy Responses\n");
        }
        return status;
    }

    SAL_RUNNING_CHECK(crypto_handle);
    /*
     * From the instanceHandle we must get the trans_handle and send
     * down to adf for polling.
     * Populate trans handle table with the appropriate handle.
     */
    trans_hndTable[TH_CY_RX_0] = crypto_handle->trans_handle_asym_rx;
    /* Call adf to do the polling. */
    status = icp_adf_pollInstance(
        trans_hndTable, NUM_CRYPTO_ASYM_RX_RINGS, response_quota);
    return status;
}

/* Polling CY instances' memory pool in progress of all banks for one device */
STATIC CpaStatus Lac_CyService_GenResponses(sal_list_t **services)
{
    CpaInstanceHandle cyInstHandle = NULL;
    sal_list_t *sal_service = NULL;
    sal_crypto_service_t *crypto_handle = NULL;
    sal_service_t *gen_handle = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    LAC_CHECK_NULL_PARAM(services);

    sal_service = *services;
    while (sal_service)
    {
        cyInstHandle = (void *)SalList_getObject(sal_service);
        crypto_handle = (sal_crypto_service_t *)cyInstHandle;
        LAC_CHECK_NULL_PARAM(crypto_handle);

        gen_handle = &(crypto_handle->generic_service_info);
        status = SalCtrl_CyGenResponses(crypto_handle, gen_handle);
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
        sal_service = SalList_next(sal_service);
    }
    return status;
}

CpaStatus Lac_CyPollAllBanks_GenResponses(icp_accel_dev_t *accel_dev)
{
    sal_t *service_container = NULL;
    Cpa32U enabled_services = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    service_container = accel_dev->pSalHandle;

    status = SalCtrl_GetEnabledServices(accel_dev, &enabled_services);

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to get supported services");
        return status;
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = Lac_CyService_GenResponses(&service_container->asym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR(
                "Failed to generate dummy responses for asym service");
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status =
            Lac_CyService_GenResponses(&service_container->crypto_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR(
                "Failed to generate dummy responses for crypto service");
            return status;
        }
    }
    return status;
}

/* Returns the handle to the first asym crypto instance */
STATIC CpaInstanceHandle
Lac_GetFirstAsymHandle(icp_accel_dev_t *adfInsts[ADF_MAX_DEVICES],
                       Cpa16U num_dev)
{
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    CpaInstanceHandle cyInst = NULL;
    Cpa16U i = 0;

    for (i = 0; i < num_dev; i++)
    {
        dev_addr = (icp_accel_dev_t *)adfInsts[i];
        base_addr = dev_addr->pSalHandle;
        if ((NULL != base_addr) && (NULL != base_addr->asym_services))
        {
            list_temp = base_addr->asym_services;
            cyInst = SalList_getObject(list_temp);
            break;
        }
    }

    return cyInst;
}

/* Returns the handle to the first sym crypto instance */
STATIC CpaInstanceHandle
Lac_GetFirstSymHandle(icp_accel_dev_t *adfInsts[ADF_MAX_DEVICES],
                      Cpa16U num_dev)
{
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    CpaInstanceHandle cyInst = NULL;
    Cpa16U i = 0;

    for (i = 0; i < num_dev; i++)
    {
        dev_addr = (icp_accel_dev_t *)adfInsts[i];
        base_addr = dev_addr->pSalHandle;
        if ((NULL != base_addr) && (NULL != base_addr->sym_services))
        {
            list_temp = base_addr->sym_services;
            cyInst = SalList_getObject(list_temp);
            break;
        }
    }

    return cyInst;
}

/* Returns the handle to the first crypto instance
 * Note that the crypto instance in this case supports
 * both asym and sym services */
STATIC CpaInstanceHandle
Lac_GetFirstCyHandle(icp_accel_dev_t *adfInsts[ADF_MAX_DEVICES], Cpa16U num_dev)
{
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    CpaInstanceHandle cyInst = NULL;
    Cpa16U i = 0;

    for (i = 0; i < num_dev; i++)
    {
        dev_addr = (icp_accel_dev_t *)adfInsts[i];
        base_addr = dev_addr->pSalHandle;
        if ((NULL != base_addr) && (NULL != base_addr->crypto_services))
        {
            list_temp = base_addr->crypto_services;
            cyInst = SalList_getObject(list_temp);
            break;
        }
    }
    return cyInst;
}

CpaInstanceHandle Lac_GetFirstHandle(sal_service_type_t svc_type)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    static icp_accel_dev_t *adfInsts[ADF_MAX_DEVICES] = {0};
    CpaInstanceHandle cyInst = NULL;
    Cpa16U num_cy_dev = 0;
    Cpa32U capabilities = 0;

    switch (svc_type)
    {
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            capabilities = ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
            break;
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            capabilities = ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
            capabilities = ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
            capabilities |= ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
            break;
        default:
            LAC_LOG_ERROR("Invalid service type\n");
            return NULL;
            break;
    }
    /* Only need 1 dev with crypto enabled - so check all devices*/
    status = icp_adf_getAllAccelDevByEachCapability(
        capabilities, adfInsts, &num_cy_dev);
    if ((0 == num_cy_dev) || (CPA_STATUS_SUCCESS != status))
    {
        LAC_LOG_ERROR("No crypto devices enabled in the system\n");
        return NULL;
    }

    switch (svc_type)
    {
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            /* Try to find an asym only instance first */
            cyInst = Lac_GetFirstAsymHandle(adfInsts, num_cy_dev);
            /* Try to find a cy instance since it also supports asym */
            if (NULL == cyInst)
            {
                cyInst = Lac_GetFirstCyHandle(adfInsts, num_cy_dev);
            }
            break;
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            /* Try to find a sym only instance first */
            cyInst = Lac_GetFirstSymHandle(adfInsts, num_cy_dev);
            /* Try to find a cy instance since it also supports sym */
            if (NULL == cyInst)
            {
                cyInst = Lac_GetFirstCyHandle(adfInsts, num_cy_dev);
            }
            break;
        case SAL_SERVICE_TYPE_CRYPTO:
            /* Try to find a cy instance */
            cyInst = Lac_GetFirstCyHandle(adfInsts, num_cy_dev);
            break;
        default:
            break;
    }
    if (NULL == cyInst)
    {
        LAC_LOG_ERROR("No remaining crypto instances available\n");
    }
    return cyInst;
}

CpaStatus icp_sal_CyGetFileDescriptor(CpaInstanceHandle instanceHandle, int *fd)
{
    sal_crypto_service_t *crypto_handle = NULL;
    sal_service_t *gen_handle = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    crypto_handle = (sal_crypto_service_t *)instanceHandle;

    /* Make sure that we zero file descriptor
     * in case of error or unsupported. */
    LAC_CHECK_NULL_PARAM(fd);
    *fd = 0;

    LAC_CHECK_NULL_PARAM(crypto_handle);
    SAL_RUNNING_CHECK(crypto_handle);
    if (SAL_RESP_EPOLL_CFG_FILE != crypto_handle->isPolled)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    gen_handle = &(crypto_handle->generic_service_info);

    switch (gen_handle->type)
    {
        case SAL_SERVICE_TYPE_CRYPTO:
        {
            status = SalCtrl_CyGetFileDescriptor(crypto_handle, fd);
            break;
        }
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
        {
            status = SalCtrl_AsymGetFileDescriptor(crypto_handle, fd);
            break;
        }
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
        {
            status = SalCtrl_SymGetFileDescriptor(crypto_handle, fd);
            break;
        }
        default:
            LAC_LOG_ERROR("The instance handle is the wrong type");
            return CPA_STATUS_FAIL;
    }

    return status;
}

CpaStatus icp_sal_CyPutFileDescriptor(CpaInstanceHandle instanceHandle, int fd)
{
    sal_crypto_service_t *crypto_handle = NULL;

    crypto_handle = (sal_crypto_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(crypto_handle);
    SAL_RUNNING_CHECK(crypto_handle);
    SAL_CHECK_INSTANCE_TYPE(instanceHandle,
                            (SAL_SERVICE_TYPE_CRYPTO |
                             SAL_SERVICE_TYPE_CRYPTO_ASYM |
                             SAL_SERVICE_TYPE_CRYPTO_SYM));

    if (SAL_RESP_EPOLL_CFG_FILE != crypto_handle->isPolled)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    return CPA_STATUS_SUCCESS;
}
