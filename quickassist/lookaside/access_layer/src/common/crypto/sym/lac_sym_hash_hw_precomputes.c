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
 ***************************************************************************
 * @file lac_sym_hash_hw_precomputes.c
 *
 * @ingroup LacHashDefs
 *
 * Hash Precomputes
 ***************************************************************************/

/*
******************************************************************************
* Include public/global header files
******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_sym.h"

#include "Osal.h"

#include "icp_accel_devices.h"
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_adf_debug.h"

#include "icp_qat_fw_la.h"
/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "lac_mem.h"
#include "lac_sym.h"
#include "lac_log.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "icp_accel_devices.h"
#include "lac_sym_hash_defs.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "lac_session.h"
#include "lac_sym_hash.h"
#include "lac_sym_qat.h"
#include "lac_sym_qat_hash.h"
#include "lac_sym_qat_cipher.h"
#include "lac_sym_hash_precomputes.h"

/**
 *****************************************************************************
 * @ingroup LacHashDefs
 *      Definition of the callback function for processing responses for
 *      precompute operations
 *
 * @description
 *      This callback, which is registered with the common symmetric response
 *      message handler, It is invoked to process precompute response messages
 *      from the QAT.
 *
 * @param[in] lacCmdId          ID of the symmetric QAT command of the request
 *                              message
 * @param[in] pOpaqueData       pointer to opaque data in the request message
 * @param[in] cmnRespFlags      Flags set by QAT to indicate response status
 *
 * @return  None
 *****************************************************************************/
STATIC void LacSymHash_PrecompCbFunc(icp_qat_fw_la_cmd_id_t lacCmdId,
                                     void *pOpaqueData,
                                     icp_qat_fw_comn_flags cmnRespFlags)
{
    lac_sym_hash_precomp_op_data_t *pPrecompOpData =
        (lac_sym_hash_precomp_op_data_t *)pOpaqueData;
    lac_sym_hash_precomp_op_t *pOpStatus = NULL;
    lac_session_desc_t *pSessionDesc = NULL;
    Cpa8U k1[LAC_HASH_CMAC_BLOCK_SIZE], k2[LAC_HASH_CMAC_BLOCK_SIZE];
    Cpa8U *ptr = NULL;
    size_t i = 0;

    if (NULL == pPrecompOpData)
    {
        LAC_LOG_ERROR("Opaque data for precompute is NULL");
        return;
    }

    pOpStatus = pPrecompOpData->pOpStatus;
    pSessionDesc = (lac_session_desc_t *)pOpStatus->pCallbackTag;

    if (LAC_SYM_HASH_PRECOMP_HMAC == pPrecompOpData->opType)
    {
        lac_sym_hash_hmac_precomp_qat_t *pHmacQatData =
            &pPrecompOpData->u.hmacQatData;

        /* Copy the hash state */
        memcpy(pPrecompOpData->pState,
               (Cpa8U *)pHmacQatData->hashStateStorage +
                   sizeof(icp_qat_hw_auth_counter_t),
               pPrecompOpData->stateSize);
    }
    else
    {
        lac_sym_hash_aes_precomp_qat_t *pAesQatData =
            &pPrecompOpData->u.aesQatData;

        if (pSessionDesc->hashAlgorithm == CPA_CY_SYM_HASH_AES_CMAC &&
            pSessionDesc->symOperation == CPA_CY_SYM_OP_HASH)
        {
            /* Use K0 (stored in pAesQatData->data) to derive K1 and K2.
             * When you have the derived keys, copy them to
             * pPrecompOpData->pState but remember that at the beginning
             * is original key
             */
            /* Calculating K1 */
            for (i = 0, ptr = pAesQatData->data; i < LAC_HASH_CMAC_BLOCK_SIZE;
                 i++, ptr++)
            {
                k1[i] = (*ptr) << 1;
                if (i != 0)
                {
                    k1[i - 1] |= (*ptr) >> (LAC_NUM_BITS_IN_BYTE - 1);
                }

                if (i + 1 == LAC_HASH_CMAC_BLOCK_SIZE)
                {
                    /* If msb of pAesQatData->data is set xor with RB.
                       Because only the final byte of RB is non-zero this is
                       all we need to xor */
                    if ((pAesQatData->data[0]) & LAC_SYM_HASH_MSBIT_MASK)
                    {
                        k1[i] ^= LAC_SYM_AES_CMAC_RB_128;
                    }
                }
            }
            /* Calculating K2 */
            for (i = 0; i < LAC_HASH_CMAC_BLOCK_SIZE; i++)
            {
                k2[i] = (k1[i]) << 1;
                if (i != 0)
                {
                    k2[i - 1] |= (k1[i]) >> (LAC_NUM_BITS_IN_BYTE - 1);
                }
                if (i + 1 == LAC_HASH_CMAC_BLOCK_SIZE)
                {
                    /* If msb of k1 is set xor last byte with RB */
                    if (k1[0] & LAC_SYM_HASH_MSBIT_MASK)
                    {
                        k2[i] ^= LAC_SYM_AES_CMAC_RB_128;
                    }
                }
            }
            /* Now, when we have K1 & K2 lets copy them to the state2 */
            ptr = pPrecompOpData->pState + LAC_HASH_CMAC_BLOCK_SIZE;
            memcpy(ptr, k1, LAC_HASH_CMAC_BLOCK_SIZE);
            ptr += LAC_HASH_CMAC_BLOCK_SIZE;
            memcpy(ptr, k2, LAC_HASH_CMAC_BLOCK_SIZE);
        }
        else
        {
            memcpy(pPrecompOpData->pState,
                   pAesQatData->data,
                   pPrecompOpData->stateSize);
        }
    }
    /* Check if there are any more pending requests by testing for opsPending
     * for 0. If there arent then we can signal to the user that we're done
     */
    if (CPA_FALSE != osalAtomicDecAndTest(&(pOpStatus->opsPending)))
    {
        pOpStatus->callbackFn(pOpStatus->pCallbackTag);
    }
}

CpaStatus LacSymHash_HmacPrecompInit(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;
    icp_qat_fw_auth_cd_ctrl_hdr_t *pContentDesc = NULL;

    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

    LacSymQat_RespHandlerRegister(ICP_QAT_FW_LA_CMD_AUTH_PRE_COMP,
                                  LacSymHash_PrecompCbFunc);

    status = LAC_OS_MALLOC(&(pService->ppHmacContentDesc),
                           (CPA_CY_HASH_ALG_END + 1) * sizeof(Cpa8U *));
    LAC_CHECK_STATUS(status);

    for (i = CPA_CY_SYM_HASH_MD5; i <= CPA_CY_SYM_HASH_SHA512; i++)
    {
        pContentDesc = NULL;
        pHashAlgInfo = NULL;

        LacSymQat_HashAlgLookupGet(instanceHandle, i, &pHashAlgInfo);

        status = LAC_OS_CAMALLOC(&pContentDesc,
                                 LAC_SYM_QAT_MAX_HASH_SETUP_BLK_SZ,
                                 LAC_64BYTE_ALIGNMENT,
                                 pService->nodeAffinity);

        if (CPA_STATUS_SUCCESS == status)
        {
            pService->ppHmacContentDesc[i] = (Cpa8U *)pContentDesc;
        }
        else
        {
            break;
        }
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        for (i = CPA_CY_SYM_HASH_MD5; i <= CPA_CY_SYM_HASH_SHA512; i++)
        {
            LAC_OS_CAFREE(pService->ppHmacContentDesc[i]);
        }
        LAC_OS_FREE(pService->ppHmacContentDesc);
    }

    return status;
}

void LacSymHash_HmacPrecompShutdown(CpaInstanceHandle instanceHandle)
{
    Cpa32U i = 0;
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

    if (NULL != pService->ppHmacContentDesc)
    {
        for (i = CPA_CY_SYM_HASH_MD5; i <= CPA_CY_SYM_HASH_SHA512; i++)
        {
            LAC_OS_CAFREE(pService->ppHmacContentDesc[i]);
        }
        LAC_OS_FREE(pService->ppHmacContentDesc);
    }
}

/**
*******************************************************************************
* @ingroup LacHashDefs
*      Perform single hash precompute operation for HMAC
*
* @description
*      This function builds up a request and sends it to the QAT for a single
*      hmac precompute operation.
*
* @param[in]  instanceHandle       Instance Handle
* @param[in]  hashAlgorithm        Hash Algorithm
* @param[in]  pHashOpData          Operation data used for a single hmac
*                                  precompute operation for a session
*
* @retval CPA_STATUS_SUCCESS       Success
* @retval CPA_STATUS_RETRY         Retry the operation.
* @retval CPA_STATUS_FAIL          Operation Failed
*
*****************************************************************************/
STATIC CpaStatus
LacSymHash_HmacPreCompute(CpaInstanceHandle instanceHandle,
                          CpaCySymHashAlgorithm hashAlgorithm,
                          lac_sym_hash_precomp_op_data_t *pHashOpData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_buffer_list_desc_t *pBufferListDesc = NULL;
    icp_flat_buffer_desc_t *pCurrFlatBufDesc = NULL;
    lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;
    Cpa64U srcAddrPhys = 0;
    lac_sym_qat_hash_state_buffer_info_t hashStateBufferInfo = {0};
    icp_qat_fw_la_bulk_req_t bulkMsg;
    Cpa64U hashReqParamsPhys = 0;
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

    /* Convenience pointer */
    lac_sym_hash_hmac_precomp_qat_t *pHmacQatData = &pHashOpData->u.hmacQatData;

    LacSymQat_HashAlgLookupGet(instanceHandle, hashAlgorithm, &pHashAlgInfo);

    hashStateBufferInfo.pData = pHmacQatData->hashStateStorage;
    hashStateBufferInfo.pDataPhys =
        LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
            pService->generic_service_info, pHmacQatData->hashStateStorage));

    if (hashStateBufferInfo.pDataPhys == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of "
                      "the hashStateStorage\n");
        return CPA_STATUS_FAIL;
    }

    hashStateBufferInfo.stateStorageSzQuadWords =
        LAC_BYTES_TO_QUADWORDS(sizeof(icp_qat_hw_auth_counter_t) +
                               LAC_ALIGN_POW2_ROUNDUP(pHashAlgInfo->stateSize,
                                                      LAC_QUAD_WORD_IN_BYTES));
    hashStateBufferInfo.prefixAadSzQuadWords = 0;

    pBufferListDesc = (icp_buffer_list_desc_t *)pHmacQatData->bufferDesc;
    pBufferListDesc->numBuffers = 1;

    pCurrFlatBufDesc = (icp_flat_buffer_desc_t *)(pBufferListDesc->phyBuffers);
    pCurrFlatBufDesc->dataLenInBytes = pHashAlgInfo->blockLength;
    pCurrFlatBufDesc->phyBuffer =
        LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
            pService->generic_service_info, pHmacQatData->data));

    if (pCurrFlatBufDesc->phyBuffer == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of "
                      "the HMAC data\n");
        return CPA_STATUS_FAIL;
    }

    srcAddrPhys = LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        pService->generic_service_info, pBufferListDesc));

    if (srcAddrPhys == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of "
                      "the source buffer\n");
        return CPA_STATUS_FAIL;
    }

    pHashOpData->pInstance = pService;

    hashReqParamsPhys = LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        pService->generic_service_info, &(pHmacQatData->hashReqParams));

    if (hashReqParamsPhys == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of the hash request"
                      " params\n");
        return CPA_STATUS_FAIL;
    }

    /* Send to QAT */
    status = SalQatMsg_transPutMsg(pService->trans_handle_sym_tx,
                                   (void *)&(bulkMsg),
                                   LAC_QAT_SYM_REQ_SZ_LW,
                                   LAC_LOG_MSG_SYMCYBULK,
                                   NULL);

    return status;
}

CpaStatus LacSymHash_HmacPreComputes(CpaInstanceHandle instanceHandle,
                                     CpaCySymHashAlgorithm hashAlgorithm,
                                     Cpa32U authKeyLenInBytes,
                                     Cpa8U *pAuthKey,
                                     Cpa8U *pWorkingMemory,
                                     Cpa8U *pState1,
                                     Cpa8U *pState2,
                                     lac_hash_precompute_done_cb_t callbackFn,
                                     void *pCallbackTag)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Memory is carved up for pHmacIpadOpData and for pHmacOpadOpData
     * one after another. As the structure size is a multiple of 8, if the
     * first one is aligned on an 8 byte boundary, so too will the second
     * structure. The pOpStatus structure is carved up just after these two
     * structures and has no alignment constraints. Pointer arithemtic is
     * used to carve the memory up. */
    lac_sym_hash_precomp_op_data_t *pHmacIpadOpData =
        (lac_sym_hash_precomp_op_data_t *)pWorkingMemory;
    lac_sym_hash_precomp_op_data_t *pHmacOpadOpData = pHmacIpadOpData + 1;
    lac_sym_hash_precomp_op_t *pOpStatus =
        (lac_sym_hash_precomp_op_t *)(pHmacOpadOpData + 1);

    /* Convenience pointers */
    lac_sym_hash_hmac_precomp_qat_t *pHmacIpadQatData =
        &pHmacIpadOpData->u.hmacQatData;
    lac_sym_hash_hmac_precomp_qat_t *pHmacOpadQatData =
        &pHmacOpadOpData->u.hmacQatData;

    lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;
    Cpa32U wordIndex = 0;
    Cpa32U padLenBytes = 0;

    LacSymQat_HashAlgLookupGet(instanceHandle, hashAlgorithm, &pHashAlgInfo);

    /* Initialise opsPending to the number of operations
     * needed to complete this precompute
     */
    osalAtomicSet(2, &(pOpStatus->opsPending));
    pOpStatus->callbackFn = callbackFn;
    pOpStatus->pCallbackTag = pCallbackTag;

    pHmacIpadOpData->opType = LAC_SYM_HASH_PRECOMP_HMAC;
    pHmacIpadOpData->pOpStatus = pOpStatus;
    pHmacIpadOpData->pState = pState1;
    pHmacIpadOpData->stateSize = pHashAlgInfo->stateSize;

    pHmacOpadOpData->opType = LAC_SYM_HASH_PRECOMP_HMAC;
    pHmacOpadOpData->pOpStatus = pOpStatus;
    pHmacOpadOpData->pState = pState2;
    pHmacOpadOpData->stateSize = pHashAlgInfo->stateSize;

    /* Copy HMAC key into buffers */
    if (authKeyLenInBytes > 0)
    {
        memcpy(pHmacIpadQatData->data, pAuthKey, authKeyLenInBytes);
        memcpy(pHmacOpadQatData->data, pAuthKey, authKeyLenInBytes);
    }

    padLenBytes = pHashAlgInfo->blockLength - authKeyLenInBytes;

    /* Clear the remaining buffer space */
    if (padLenBytes > 0)
    {
        LAC_OS_BZERO(pHmacIpadQatData->data + authKeyLenInBytes, padLenBytes);
        LAC_OS_BZERO(pHmacOpadQatData->data + authKeyLenInBytes, padLenBytes);
    }

    /* XOR Key with IPAD at 4-byte level */
    for (wordIndex = 0;
         wordIndex < LAC_BYTES_TO_LONGWORDS(pHashAlgInfo->blockLength);
         wordIndex++)
    {
        Cpa32U *pIpadData = ((Cpa32U *)pHmacIpadQatData->data) + wordIndex;
        Cpa32U *pOpadData = ((Cpa32U *)pHmacOpadQatData->data) + wordIndex;

        *pIpadData ^= LAC_HASH_IPAD_4_BYTES;
        *pOpadData ^= LAC_HASH_OPAD_4_BYTES;
    }

    status = LacSymHash_HmacPreCompute(
        instanceHandle, hashAlgorithm, pHmacIpadOpData);

    if (CPA_STATUS_SUCCESS == status)
    {

        status = LacSymHash_HmacPreCompute(
            instanceHandle, hashAlgorithm, pHmacOpadOpData);
    }

    return status;
}

CpaStatus LacSymHash_AesECBPreCompute(CpaInstanceHandle instanceHandle,
                                      CpaCySymHashAlgorithm hashAlgorithm,
                                      Cpa32U authKeyLenInBytes,
                                      Cpa8U *pAuthKey,
                                      Cpa8U *pWorkingMemory,
                                      Cpa8U *pState,
                                      lac_hash_precompute_done_cb_t callbackFn,
                                      void *pCallbackTag)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /* Carve up memory for the following structures: */
    /* Memory is user supplied via session memory */
    lac_sym_hash_precomp_op_data_t *pAesOpData =
        (lac_sym_hash_precomp_op_data_t *)pWorkingMemory;
    lac_sym_hash_precomp_op_t *pOpStatus =
        (lac_sym_hash_precomp_op_t *)(pAesOpData + 1);
    /* Convenience pointer */
    lac_sym_hash_aes_precomp_qat_t *pAesQatData = &pAesOpData->u.aesQatData;
    icp_buffer_list_desc_t *pBufferListDesc = NULL;
    icp_flat_buffer_desc_t *pCurrFlatBufDesc = NULL;
    icp_qat_fw_la_bulk_req_t bulkMsg;
    Cpa64U srcAddrPhys = 0;
    Cpa32U stateSize = 0;
    Cpa64U cipherRequestParamPhys = 0;

    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

    if (CPA_CY_SYM_HASH_AES_XCBC == hashAlgorithm)
    {
        lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;

        LacSymQat_HashAlgLookupGet(
            instanceHandle, hashAlgorithm, &pHashAlgInfo);
        stateSize = pHashAlgInfo->stateSize;

        memcpy(pAesQatData->data, pHashAlgInfo->initState, stateSize);
    }
    else if (CPA_CY_SYM_HASH_AES_CMAC == hashAlgorithm)
    {
        lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;

        LacSymQat_HashAlgLookupGet(
            instanceHandle, hashAlgorithm, &pHashAlgInfo);
        /* Original state size includes K, K1 and K2 which are of equal length.
         * For precompute state size is only of the length of K which is equal
         * to the block size for CPA_CY_SYM_HASH_AES_CMAC. */
        stateSize = LAC_HASH_CMAC_BLOCK_SIZE;

        memcpy(pAesQatData->data, pHashAlgInfo->initState, stateSize);
    }
    else if (CPA_CY_SYM_HASH_AES_GCM == hashAlgorithm)
    {
        stateSize = ICP_QAT_HW_GALOIS_H_SZ;
        LAC_OS_BZERO(pAesQatData->data, stateSize);
    }
    else
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Initialise opsPending to the number of operations
     * needed to complete this precompute
     */
    osalAtomicSet(1, &(pOpStatus->opsPending));
    pOpStatus->callbackFn = callbackFn;
    pOpStatus->pCallbackTag = pCallbackTag;

    pAesOpData->opType = LAC_SYM_HASH_PRECOMP_AES_ECB;
    pAesOpData->pOpStatus = pOpStatus;
    pAesOpData->stateSize = stateSize;
    pAesOpData->pState = pState;

    /* Key length must not exceed the max supported AES key length */
    if (authKeyLenInBytes > ICP_QAT_HW_AES_256_KEY_SZ)
    {
        LAC_INVALID_PARAM_LOG("authKeyLenInBytes exceeds max supported size");
        return CPA_STATUS_INVALID_PARAM;
    }

    pBufferListDesc = (icp_buffer_list_desc_t *)pAesQatData->bufferDesc;
    pBufferListDesc->numBuffers = 1;
    pCurrFlatBufDesc = (icp_flat_buffer_desc_t *)(pBufferListDesc->phyBuffers);

    pCurrFlatBufDesc->dataLenInBytes = stateSize;
    pCurrFlatBufDesc->phyBuffer =
        LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
            pService->generic_service_info, pAesQatData->data));

    if (pCurrFlatBufDesc->phyBuffer == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of pAesQatData\n");
        return CPA_STATUS_FAIL;
    }

    srcAddrPhys = LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        pService->generic_service_info, pBufferListDesc));

    if (srcAddrPhys == 0)
    {
        LAC_LOG_ERROR(
            "Unable to get the physical address of the source buffer\n");
        return CPA_STATUS_FAIL;
    }

    pAesOpData->pInstance = pService;
    cipherRequestParamPhys = LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        pService->generic_service_info, &pAesQatData->cipherReqParams);

    if (cipherRequestParamPhys == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of the cipher"
                      " request parameter\n");
        return CPA_STATUS_FAIL;
    }

    /* Send to QAT */
    status = SalQatMsg_transPutMsg(pService->trans_handle_sym_tx,
                                   (void *)&(bulkMsg),
                                   LAC_QAT_SYM_REQ_SZ_LW,
                                   LAC_LOG_MSG_SYMCYBULK,
                                   NULL);
    return status;
}
