/***************************************************************************
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
 * @file lac_sym_qat.c Interfaces for populating the symmetric qat structures
 *
 * @ingroup LacSymQat
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "icp_accel_devices.h"
#include "icp_adf_cfg.h"
#include "lac_sym.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "sal_string_parse.h"
#include "lac_sym_key.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym_qat_constants_table.h"
#include "lac_sym_qat_cipher.h"
#include "lac_sym_qat_hash.h"
#include "sal_misc_error_stats.h"

#define EMBEDDED_CIPHER_KEY_MAX_SIZE 16
STATIC void LacSymQat_SymLogSliceHangError(icp_qat_fw_la_cmd_id_t symCmdId)
{
    Cpa8U cmdId = symCmdId;

    switch (cmdId)
    {
        case ICP_QAT_FW_LA_CMD_CIPHER:
        case ICP_QAT_FW_LA_CMD_CIPHER_PRE_COMP:
            LAC_LOG_ERROR("slice hang detected on CPM cipher slice. ");
            break;

        case ICP_QAT_FW_LA_CMD_AUTH:
        case ICP_QAT_FW_LA_CMD_AUTH_PRE_COMP:
            LAC_LOG_ERROR("slice hang detected on CPM auth slice. ");
            break;

        case ICP_QAT_FW_LA_CMD_CIPHER_HASH:
        case ICP_QAT_FW_LA_CMD_HASH_CIPHER:
        case ICP_QAT_FW_LA_CMD_SSL3_KEY_DERIVE:
        case ICP_QAT_FW_LA_CMD_TLS_V1_1_KEY_DERIVE:
        case ICP_QAT_FW_LA_CMD_TLS_V1_2_KEY_DERIVE:
        case ICP_QAT_FW_LA_CMD_MGF1:
        default:
            LAC_LOG_ERROR("slice hang detected on CPM cipher or auth slice. ");
    }
    return;
}

/* sym crypto response handlers */
STATIC
sal_qat_resp_handler_func_t respHandlerSymTbl[ICP_QAT_FW_LA_CMD_DELIMITER];

void LacSymQat_SymRespHandler(void *pRespMsg)
{
    Cpa8U lacCmdId = 0;
    void *pOpaqueData = NULL;
    icp_qat_fw_la_resp_t *pRespMsgFn = NULL;
    sal_crypto_service_t *pInst = NULL;
    Cpa8U opStatus = ICP_QAT_FW_COMN_STATUS_FLAG_OK;
    Cpa8U comnErr = ERR_CODE_NO_ERROR;

    pRespMsgFn = (icp_qat_fw_la_resp_t *)pRespMsg;
    LAC_ENSURE(pRespMsgFn != NULL,
               "LacSymQat_SymRespHandler - pRespMsgFn NULL\n");
    LAC_MEM_SHARED_READ_TO_PTR(pRespMsgFn->opaque_data, pOpaqueData);
    LAC_ENSURE(pOpaqueData != NULL,
               "LacSymQat_SymRespHandler - pOpaqueData NULL\n");

    lacCmdId = pRespMsgFn->comn_resp.cmd_id;
    opStatus = pRespMsgFn->comn_resp.comn_status;
    comnErr = pRespMsgFn->comn_resp.comn_error.s.comn_err_code;
    pInst = (sal_crypto_service_t *)(((lac_sym_bulk_cookie_t *)pOpaqueData)
                                         ->instanceHandle);

    /* log the slice hang and endpoint push/pull error inside the response */
    if (ERR_CODE_SSM_ERROR == (Cpa8S)comnErr)
    {
        LacSymQat_SymLogSliceHangError(lacCmdId);
    }
    else if (ERR_CODE_ENDPOINT_ERROR == (Cpa8S)comnErr)
    {
        LAC_LOG_ERROR("The PCIe End Point Push/Pull or"
                      " TI/RI Parity error detected.");
    }

    SAL_MISC_ERR_STATS_INC(comnErr, &pInst->generic_service_info);

    /* call the response message handler registered for the command ID */
    respHandlerSymTbl[lacCmdId]((icp_qat_fw_la_cmd_id_t)lacCmdId,
                                pOpaqueData,
                                (icp_qat_fw_comn_flags)opStatus);
}

CpaStatus LacSymQat_Init(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Initialize the SHRAM constants table */
    LacSymQat_ConstantsInitLookupTables(instanceHandle);

    /* Initialise the Hash lookup table */
    status = LacSymQat_HashLookupInit(instanceHandle);

    return status;
}

void LacSymQat_RespHandlerRegister(icp_qat_fw_la_cmd_id_t lacCmdId,
                                   sal_qat_resp_handler_func_t pCbHandler)
{
    /* clang-format off */
    LAC_ENSURE_RETURN_VOID((lacCmdId < ICP_QAT_FW_LA_CMD_DELIMITER), "Invalid Command ID");
    /* clang-format on */

    /* set the response handler for the command ID */
    respHandlerSymTbl[lacCmdId] = pCbHandler;
}

void LacSymQat_LaPacketCommandFlagSet(Cpa32U qatPacketType,
                                      icp_qat_fw_la_cmd_id_t laCmdId,
                                      CpaCySymCipherAlgorithm cipherAlgorithm,
                                      Cpa16U *pLaCommandFlags,
                                      Cpa32U ivLenInBytes)
{
    /* For Chacha ciphers set command flag as partial none to proceed
     * with stateless processing */
    if (LAC_CIPHER_IS_CHACHA(cipherAlgorithm))
    {
        ICP_QAT_FW_LA_PARTIAL_SET(*pLaCommandFlags, ICP_QAT_FW_LA_PARTIAL_NONE);
        return;
    }
    ICP_QAT_FW_LA_PARTIAL_SET(*pLaCommandFlags, qatPacketType);

    /* For ECB-mode ciphers, IV is NULL so update-state flag
     * must be disabled always.
     * For all other ciphers and auth
     * update state is disabled for full packets and final partials */
    if ((ICP_QAT_FW_LA_PARTIAL_NONE == qatPacketType) ||
        (ICP_QAT_FW_LA_PARTIAL_END == qatPacketType) ||
        ((laCmdId != ICP_QAT_FW_LA_CMD_AUTH) &&
         LAC_CIPHER_IS_ECB_MODE(cipherAlgorithm)))
    {
        ICP_QAT_FW_LA_UPDATE_STATE_SET(*pLaCommandFlags,
                                       ICP_QAT_FW_LA_NO_UPDATE_STATE);
    }
    /* For first or middle partials set the update state command flag */
    else
    {
        ICP_QAT_FW_LA_UPDATE_STATE_SET(*pLaCommandFlags,
                                       ICP_QAT_FW_LA_UPDATE_STATE);

        if (laCmdId == ICP_QAT_FW_LA_CMD_AUTH)
        {
            /* For hash only partial - verify and return auth result are
             * disabled */
            ICP_QAT_FW_LA_RET_AUTH_SET(*pLaCommandFlags,
                                       ICP_QAT_FW_LA_NO_RET_AUTH_RES);

            ICP_QAT_FW_LA_CMP_AUTH_SET(*pLaCommandFlags,
                                       ICP_QAT_FW_LA_NO_CMP_AUTH_RES);
        }
    }

    if ((LAC_CIPHER_IS_GCM(cipherAlgorithm)) &&
        (LAC_CIPHER_IV_SIZE_GCM_12 == ivLenInBytes))

    {
        ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(*pLaCommandFlags,
                                          ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
    }
}

void LacSymQat_packetTypeGet(CpaCySymPacketType packetType,
                             CpaCySymPacketType packetState,
                             Cpa32U *pQatPacketType)
{
    switch (packetType)
    {
        /* partial */
        case CPA_CY_SYM_PACKET_TYPE_PARTIAL:
            /* if the previous state was full, then this is the first packet */
            if (CPA_CY_SYM_PACKET_TYPE_FULL == packetState)
            {
                *pQatPacketType = ICP_QAT_FW_LA_PARTIAL_START;
            }
            else
            {
                *pQatPacketType = ICP_QAT_FW_LA_PARTIAL_MID;
            }
            break;

        /* final partial */
        case CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL:
            *pQatPacketType = ICP_QAT_FW_LA_PARTIAL_END;
            break;

        /* full packet - CPA_CY_SYM_PACKET_TYPE_FULL */
        default:
            *pQatPacketType = ICP_QAT_FW_LA_PARTIAL_NONE;
    }
}

void LacSymQat_LaSetDefaultFlags(icp_qat_fw_serv_specif_flags *laCmdFlags,
                                 CpaCySymOp symOp)
{

    ICP_QAT_FW_LA_PARTIAL_SET(*laCmdFlags, ICP_QAT_FW_LA_PARTIAL_NONE);

    ICP_QAT_FW_LA_UPDATE_STATE_SET(*laCmdFlags, ICP_QAT_FW_LA_NO_UPDATE_STATE);

    if (symOp != CPA_CY_SYM_OP_CIPHER)
    {
        ICP_QAT_FW_LA_RET_AUTH_SET(*laCmdFlags, ICP_QAT_FW_LA_RET_AUTH_RES);
    }
    else
    {
        ICP_QAT_FW_LA_RET_AUTH_SET(*laCmdFlags, ICP_QAT_FW_LA_NO_RET_AUTH_RES);
    }

    ICP_QAT_FW_LA_CMP_AUTH_SET(*laCmdFlags, ICP_QAT_FW_LA_NO_CMP_AUTH_RES);

    ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(*laCmdFlags,
                                      ICP_QAT_FW_LA_GCM_IV_LEN_NOT_12_OCTETS);
}

CpaBoolean LacSymQat_UseSymConstantsTable(lac_session_desc_t *pSession,
                                          Cpa8U *pCipherOffset,
                                          Cpa8U *pHashOffset)
{

    CpaBoolean useOptimisedContentDesc = CPA_FALSE;
    CpaBoolean useSHRAMConstants = CPA_FALSE;

    LAC_ENSURE_NOT_NULL(pSession);
    LAC_ENSURE_NOT_NULL(pCipherOffset);
    LAC_ENSURE_NOT_NULL(pHashOffset);

    *pCipherOffset = 0;
    *pHashOffset = 0;

    LAC_LOG_DEBUG1("UseSymConstantsTable called. laCmdId = %d ",
                   pSession->laCmdId);

    /* for chaining can we use the optimised content descritor */
    if (pSession->laCmdId == ICP_QAT_FW_LA_CMD_CIPHER_HASH ||
        pSession->laCmdId == ICP_QAT_FW_LA_CMD_HASH_CIPHER)
    {
        useOptimisedContentDesc = LacSymQat_UseOptimisedContentDesc(pSession);
    }

    /* Cipher-only case or chaining */
    if (pSession->laCmdId == ICP_QAT_FW_LA_CMD_CIPHER ||
        useOptimisedContentDesc)
    {
        icp_qat_hw_cipher_algo_t algorithm;
        icp_qat_hw_cipher_mode_t mode;
        icp_qat_hw_cipher_dir_t dir;
        icp_qat_hw_cipher_convert_t key_convert;

        if (pSession->cipherKeyLenInBytes >
            sizeof(icp_qat_fw_comn_req_hdr_cd_pars_t))
        {
            LAC_LOG_DEBUG1("keyLen > %d - don't use SymConstantsTable",
                           sizeof(icp_qat_fw_comn_req_hdr_cd_pars_t));
            return CPA_FALSE;
        }

        LacSymQat_CipherGetCfgData(
            pSession, &algorithm, &mode, &dir, &key_convert);

        /* Check if cipher config is available in table. */
        LacSymQat_ConstantsGetCipherOffset(pSession->pInstance,
                                           algorithm,
                                           mode,
                                           dir,
                                           key_convert,
                                           pCipherOffset);
        if (*pCipherOffset > 0)
        {
            LAC_LOG_DEBUG("UseSymConstantsTable - cipher cfg in table");
            useSHRAMConstants = CPA_TRUE;
        }
        else
        {
            LAC_LOG_DEBUG("cipher config not in SymConstantsTable");
            useSHRAMConstants = CPA_FALSE;
        }
    }

    /* hash only case or when chaining, cipher must be found in SHRAM table for
     * optimised CD case */
    if (pSession->laCmdId == ICP_QAT_FW_LA_CMD_AUTH ||
        (useOptimisedContentDesc && useSHRAMConstants))
    {
        icp_qat_hw_auth_algo_t algorithm;
        CpaBoolean nested;

        if (pSession->digestVerify)
        {
            LAC_LOG_DEBUG("digestVerify is set - don't use SymConstantsTable");
            return CPA_FALSE;
        }

        if ((!(useOptimisedContentDesc && useSHRAMConstants)) &&
            (pSession->qatHashMode == ICP_QAT_HW_AUTH_MODE1))
        {
            /* we can only use the SHA1-mode1 in the SHRAM constants table when
             * we are using the opimised content desc */
            LAC_LOG_DEBUG("HASH only SHA1-MODE1 - don't use SymConstTable");
            return CPA_FALSE;
        }

        LacSymQat_HashGetCfgData(pSession->pInstance,
                                 pSession->qatHashMode,
                                 pSession->hashMode,
                                 pSession->hashAlgorithm,
                                 &algorithm,
                                 &nested);

        /* Check if config data is available in table. */
        LacSymQat_ConstantsGetAuthOffset(pSession->pInstance,
                                         algorithm,
                                         pSession->qatHashMode,
                                         nested,
                                         pHashOffset);
        if (*pHashOffset > 0)
        {
            LAC_LOG_DEBUG("UseSymConstantsTable - hash cfg in table");
            useSHRAMConstants = CPA_TRUE;
        }
        else
        {
            LAC_LOG_DEBUG("hash config not in SymConstantsTable");
            useSHRAMConstants = CPA_FALSE;
        }
    }

    return useSHRAMConstants;
}

CpaBoolean LacSymQat_UseOptimisedContentDesc(lac_session_desc_t *pSession)
{

    /* AES128-CBC-HMAC-SHA1 MODE 1*/
    if ((pSession->cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CBC &&
         pSession->cipherKeyLenInBytes <= EMBEDDED_CIPHER_KEY_MAX_SIZE) &&
        (pSession->hashAlgorithm == CPA_CY_SYM_HASH_SHA1 &&
         pSession->qatHashMode == ICP_QAT_HW_AUTH_MODE1))
    {
        return CPA_TRUE;
    }
    else
    {
        return CPA_FALSE;
    }
}
