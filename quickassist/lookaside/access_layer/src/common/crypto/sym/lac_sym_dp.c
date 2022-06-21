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
 * @file lac_sym_dp.c
 *    Implementation of the symmetric data plane API
 *
 * @ingroup cpaCySymDp
 ***************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_sym_dp.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/

#include "icp_accel_devices.h"
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_adf_transport_dp.h"
#include "icp_adf_debug.h"
#include "icp_sal_poll.h"

#include "lac_mem.h"
#include "lac_log.h"
#include "lac_sym.h"
#include "lac_sym_cipher.h"
#include "lac_sym_qat_cipher.h"
#include "lac_list.h"
#include "lac_sal_types_crypto.h"
#include "sal_service_state.h"
#include "lac_sym_auth_enc.h"

typedef void (*write_ringMsgFunc_t)(CpaCySymDpOpData *pRequest,
                                    icp_qat_fw_la_bulk_req_t *pCurrentQatMsg);

#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup cpaCySymDp
 *      Check that the operation data is valid
 *
 * @description
 *      Check that all the parameters defined in the operation data are valid
 *
 * @param[in]       pRequest         Pointer to an operation data for crypto
 *                                   data plane API
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus LacDp_EnqueueParamCheck(const CpaCySymDpOpData *pRequest)
{
    lac_session_desc_t *pSessionDesc = NULL;
    CpaCySymCipherAlgorithm cipher = 0;
    CpaCySymHashAlgorithm hash = 0;
    Cpa32U capabilitiesMask = 0;

    LAC_CHECK_NULL_PARAM(pRequest);
    LAC_CHECK_NULL_PARAM(pRequest->instanceHandle);
    LAC_CHECK_NULL_PARAM(pRequest->sessionCtx);

    /* Ensure this is a crypto instance */
    SAL_CHECK_INSTANCE_TYPE(
        pRequest->instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));

    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequest->sessionCtx);
    if (NULL == pSessionDesc)
    {
        do
        {
            osalSleep(500);
            pSessionDesc =
                LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequest->sessionCtx);
        } while (NULL == pSessionDesc);
    }
    if (NULL == pSessionDesc)
    {
        LAC_INVALID_PARAM_LOG("Session context not as expected");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_FALSE == pSessionDesc->isDPSession)
    {
        LAC_INVALID_PARAM_LOG("Session not initialised for data plane API");
        return CPA_STATUS_INVALID_PARAM;
    }

    /*check whether Payload size is zero for CHACHA-POLY */
    if ((CPA_CY_SYM_CIPHER_CHACHA == pSessionDesc->cipherAlgorithm) &&
        (CPA_CY_SYM_HASH_POLY == pSessionDesc->hashAlgorithm) &&
        (CPA_CY_SYM_OP_ALGORITHM_CHAINING == pSessionDesc->symOperation))
    {
        if (!pRequest->messageLenToCipherInBytes)
        {
            LAC_INVALID_PARAM_LOG(
                "Invalid messageLenToCipherInBytes for CHACHA-POLY");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    if (0 == pRequest->srcBuffer)
    {
        LAC_INVALID_PARAM_LOG("Invalid srcBuffer");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (0 == pRequest->dstBuffer)
    {
        LAC_INVALID_PARAM_LOG("Invalid destBuffer");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (0 == pRequest->thisPhys)
    {
        LAC_INVALID_PARAM_LOG("Invalid thisPhys");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that src buffer Len = dst buffer Len
    Note this also checks that they are of the same type */
    if (pRequest->srcBufferLen != pRequest->dstBufferLen)
    {
        LAC_INVALID_PARAM_LOG(
            "Source and Destination buffer lengths need to be equal");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* digestVerify and digestIsAppended on Hash-Only operation not supported */
    if (pSessionDesc->digestIsAppended && pSessionDesc->digestVerify &&
        (pSessionDesc->symOperation == CPA_CY_SYM_OP_HASH))
    {
        LAC_INVALID_PARAM_LOG("digestVerify and digestIsAppended set "
                              "on Hash-Only operation is not supported");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Cipher specific tests */
    if (CPA_CY_SYM_OP_HASH != pSessionDesc->symOperation)
    {
        /* Perform IV check */
        switch (pSessionDesc->cipherAlgorithm)
        {
            case CPA_CY_SYM_CIPHER_AES_CTR:
            case CPA_CY_SYM_CIPHER_3DES_CTR:
            case CPA_CY_SYM_CIPHER_AES_GCM:
            case CPA_CY_SYM_CIPHER_CHACHA:
            case CPA_CY_SYM_CIPHER_AES_CBC:
            case CPA_CY_SYM_CIPHER_DES_CBC:
            case CPA_CY_SYM_CIPHER_3DES_CBC:
            case CPA_CY_SYM_CIPHER_AES_F8:
            {
                Cpa32U ivLenInBytes = LacSymQat_CipherIvSizeBytesGet(
                    pSessionDesc->cipherAlgorithm);
                if (pRequest->ivLenInBytes != ivLenInBytes)
                {
                    if (!(/* GCM with 12 byte IV is OK */
                          (LAC_CIPHER_IS_GCM(pSessionDesc->cipherAlgorithm) &&
                           pRequest->ivLenInBytes ==
                               LAC_CIPHER_IV_SIZE_GCM_12)))
                    {
                        LAC_INVALID_PARAM_LOG("invalid cipher IV size");
                        return CPA_STATUS_INVALID_PARAM;
                    }
                }
                if (0 == pRequest->iv)
                {
                    LAC_INVALID_PARAM_LOG("invalid iv of 0");
                    return CPA_STATUS_INVALID_PARAM;
                }
                /* pRequest->pIv is only used for CCM so is not checked here */
            }
            break;
            case CPA_CY_SYM_CIPHER_KASUMI_F8:
            {
                if (LAC_CIPHER_KASUMI_F8_IV_LENGTH != pRequest->ivLenInBytes)
                {
                    LAC_INVALID_PARAM_LOG("invalid cipher IV size");
                    return CPA_STATUS_INVALID_PARAM;
                }
                if (0 == pRequest->iv)
                {
                    LAC_INVALID_PARAM_LOG("invalid iv of 0");
                    return CPA_STATUS_INVALID_PARAM;
                }
            }
            break;
            case CPA_CY_SYM_CIPHER_SNOW3G_UEA2:
            {
                if (ICP_QAT_HW_SNOW_3G_UEA2_IV_SZ != pRequest->ivLenInBytes)
                {
                    LAC_INVALID_PARAM_LOG("invalid cipher IV size");
                    return CPA_STATUS_INVALID_PARAM;
                }
                if (0 == pRequest->iv)
                {
                    LAC_INVALID_PARAM_LOG("invalid iv of 0");
                    return CPA_STATUS_INVALID_PARAM;
                }
            }
            break;
            case CPA_CY_SYM_CIPHER_ZUC_EEA3:
            {
                if (ICP_QAT_HW_ZUC_3G_EEA3_IV_SZ != pRequest->ivLenInBytes)
                {
                    LAC_INVALID_PARAM_LOG("invalid cipher IV size");
                    return CPA_STATUS_INVALID_PARAM;
                }
                if (0 == pRequest->iv)
                {
                    LAC_INVALID_PARAM_LOG("invalid iv of 0");
                    return CPA_STATUS_INVALID_PARAM;
                }
            }
            break;
            case CPA_CY_SYM_CIPHER_AES_CCM:
            {
                if (CPA_STATUS_SUCCESS !=
                    LacSymAlgChain_CheckCCMData(
                        pRequest->pAdditionalAuthData,
                        pRequest->pIv,
                        pRequest->messageLenToCipherInBytes,
                        pRequest->ivLenInBytes))
                {
                    return CPA_STATUS_INVALID_PARAM;
                }
            }
            break;
            default:
                break;
        }
        /* Perform algorithm-specific checks */
        switch (pSessionDesc->cipherAlgorithm)
        {
            case CPA_CY_SYM_CIPHER_ARC4:
            case CPA_CY_SYM_CIPHER_AES_CTR:
            case CPA_CY_SYM_CIPHER_3DES_CTR:
            case CPA_CY_SYM_CIPHER_AES_CCM:
            case CPA_CY_SYM_CIPHER_AES_GCM:
            case CPA_CY_SYM_CIPHER_CHACHA:
            case CPA_CY_SYM_CIPHER_KASUMI_F8:
            case CPA_CY_SYM_CIPHER_AES_F8:
            case CPA_CY_SYM_CIPHER_SNOW3G_UEA2:
            case CPA_CY_SYM_CIPHER_ZUC_EEA3:
                /* No action needed */
                break;
            default:
            {
                /* Mask & check below is based on assumption that block size is
                 * a power of 2. If data size is not a multiple of the block
                 * size, the "remainder" bits selected by the mask be non-zero
                 */
                if (pRequest->messageLenToCipherInBytes &
                    (LacSymQat_CipherBlockSizeBytesGet(
                         pSessionDesc->cipherAlgorithm) -
                     1))
                {
                    LAC_INVALID_PARAM_LOG("Data size must be block size"
                                          " multiple");
                    return CPA_STATUS_INVALID_PARAM;
                }
            }
        }

        cipher = pSessionDesc->cipherAlgorithm;
        hash = pSessionDesc->hashAlgorithm;
        capabilitiesMask = ((sal_crypto_service_t *)pRequest->instanceHandle)
                               ->generic_service_info.capabilitiesMask;
        if (LAC_CIPHER_IS_SPC(cipher, hash, capabilitiesMask))
        {
            /* For CHACHA and AES_GCM single pass there is an AAD buffer
             * if aadLenInBytes is nonzero. AES_GMAC AAD is stored in
             * source buffer, therefore there is no separate AAD buffer.
             * For AES_CCM single pass that always will be AAD buffer,
             * even if aadLenInBytes will be zero */
            if (LAC_CIPHER_IS_SPC_CCM(cipher, hash, capabilitiesMask) ||
                ((0 != pSessionDesc->aadLenInBytes) &&
                 (CPA_CY_SYM_HASH_AES_GMAC != pSessionDesc->hashAlgorithm)))
            {
                LAC_CHECK_NULL_PARAM(pRequest->pAdditionalAuthData);
            }

            /* Ensure AAD length for AES_GMAC spc */
            if ((CPA_CY_SYM_HASH_AES_GMAC == hash) &&
                (ICP_QAT_FW_SPC_AAD_SZ_MAX < pRequest->messageLenToHashInBytes))
            {
                LAC_INVALID_PARAM_LOG("aadLenInBytes for AES_GMAC");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
    }

    /* Hash specific tests */
    if (CPA_CY_SYM_OP_CIPHER != pSessionDesc->symOperation)
    {
        /* For CCM, snow3G and ZUC there is always an AAD buffer
           For GCM there is an AAD buffer if aadLenInBytes is
           nonzero */
        if ((CPA_CY_SYM_HASH_AES_CCM == pSessionDesc->hashAlgorithm) ||
            (CPA_CY_SYM_HASH_AES_GCM == pSessionDesc->hashAlgorithm &&
             (0 != pSessionDesc->aadLenInBytes)))
        {
            LAC_CHECK_NULL_PARAM(pRequest->pAdditionalAuthData);
            if (0 == pRequest->additionalAuthData)
            {
                LAC_INVALID_PARAM_LOG("Invalid additionalAuthData");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        else if (CPA_CY_SYM_HASH_SNOW3G_UIA2 == pSessionDesc->hashAlgorithm ||
                 CPA_CY_SYM_HASH_ZUC_EIA3 == pSessionDesc->hashAlgorithm)
        {
            if (0 == pRequest->additionalAuthData)
            {
                LAC_INVALID_PARAM_LOG("Invalid additionalAuthData");
                return CPA_STATUS_INVALID_PARAM;
            }
        }

        if ((CPA_CY_SYM_HASH_AES_CCM != pSessionDesc->hashAlgorithm) &&
            (!pSessionDesc->digestIsAppended) && (0 == pRequest->digestResult))
        {
            LAC_INVALID_PARAM_LOG("Invalid digestResult");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (CPA_CY_SYM_HASH_AES_CCM == pSessionDesc->hashAlgorithm)
        {
            if ((pRequest->cryptoStartSrcOffsetInBytes +
                 pRequest->messageLenToCipherInBytes +
                 pSessionDesc->hashResultSize) > pRequest->dstBufferLen)
            {
                LAC_INVALID_PARAM_LOG("CCM - Not enough room for"
                                      " digest in destination buffer");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        else if (CPA_TRUE == pSessionDesc->digestIsAppended)
        {
            if (CPA_CY_SYM_HASH_AES_GMAC == pSessionDesc->hashAlgorithm)
            {
                if ((pRequest->hashStartSrcOffsetInBytes +
                     pRequest->messageLenToHashInBytes +
                     pSessionDesc->hashResultSize) > pRequest->dstBufferLen)
                {
                    LAC_INVALID_PARAM_LOG("Append Digest - Not enough room for"
                                          " digest in destination buffer for "
                                          "AES GMAC algorithm");
                    return CPA_STATUS_INVALID_PARAM;
                }
            }
            if (CPA_CY_SYM_HASH_AES_GCM == pSessionDesc->hashAlgorithm)
            {
                if ((pRequest->cryptoStartSrcOffsetInBytes +
                     pRequest->messageLenToCipherInBytes +
                     pSessionDesc->hashResultSize) > pRequest->dstBufferLen)
                {
                    LAC_INVALID_PARAM_LOG("Append Digest - Not enough room "
                                          "for digest in destination buffer"
                                          " for GCM algorithm");
                    return CPA_STATUS_INVALID_PARAM;
                }
            }

            if ((pRequest->hashStartSrcOffsetInBytes +
                 pRequest->messageLenToHashInBytes +
                 pSessionDesc->hashResultSize) > pRequest->dstBufferLen)
            {
                LAC_INVALID_PARAM_LOG("Append Digest - Not enough room for"
                                      " digest in destination buffer");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        if (CPA_CY_SYM_HASH_AES_GMAC == pSessionDesc->hashAlgorithm)
        {
            if (pRequest->messageLenToHashInBytes == 0 ||
                pRequest->pAdditionalAuthData != NULL)
            {
                LAC_INVALID_PARAM_LOG("For AES_GMAC, AAD Length "
                                      "(messageLenToHashInBytes) must be "
                                      "non zero and pAdditionalAuthData "
                                      "must be NULL");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
    }

    if (CPA_DP_BUFLIST != pRequest->srcBufferLen)
    {
        if ((CPA_CY_SYM_OP_HASH != pSessionDesc->symOperation) &&
            ((pRequest->messageLenToCipherInBytes +
              pRequest->cryptoStartSrcOffsetInBytes) > pRequest->srcBufferLen))
        {
            LAC_INVALID_PARAM_LOG("cipher len + offset greater than "
                                  "srcBufferLen");
            return CPA_STATUS_INVALID_PARAM;
        }
        else if ((CPA_CY_SYM_OP_CIPHER != pSessionDesc->symOperation) &&
                 (CPA_CY_SYM_HASH_AES_CCM != pSessionDesc->hashAlgorithm) &&
                 (CPA_CY_SYM_HASH_AES_GCM != pSessionDesc->hashAlgorithm) &&
                 (CPA_CY_SYM_HASH_AES_GMAC != pSessionDesc->hashAlgorithm) &&
                 ((pRequest->messageLenToHashInBytes +
                   pRequest->hashStartSrcOffsetInBytes) >
                  pRequest->srcBufferLen))
        {
            LAC_INVALID_PARAM_LOG(
                "hash len + offset greater than srcBufferLen");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        LAC_CHECK_8_BYTE_ALIGNMENT(pRequest->srcBuffer);
        LAC_CHECK_8_BYTE_ALIGNMENT(pRequest->dstBuffer);
    }

    LAC_CHECK_8_BYTE_ALIGNMENT(pRequest->thisPhys);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 *****************************************************************************
 * @ingroup cpaCySymDp
 *      Write Message on the ring and write request params
 *      This is the optimized version, which should not be used for
 *      algorithm of CCM, GCM, CHACHA and RC4
 *
 * @description
 *      Write Message on the ring and write request params
 *
 * @param[in/out]    pRequest       Pointer to operation data for crypto
 *                                  data plane API
 * @param[in/out]    pCurrentQatMsg Pointer to ring memory where msg will
 *                                  be written
 *
 * @retval none
 *
 *****************************************************************************/

void LacDp_WriteRingMsgOpt(CpaCySymDpOpData *pRequest,
                           icp_qat_fw_la_bulk_req_t *pCurrentQatMsg)
{
    lac_session_desc_t *pSessionDesc =
        LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequest->sessionCtx);
    Cpa8U *pMsgDummy = NULL;
    Cpa8U *pCacheDummyHdr = NULL;
    Cpa8U *pCacheDummyFtr = NULL;

    pMsgDummy = (Cpa8U *)pCurrentQatMsg;
    /* Write Request */
    /*
     * Fill in the header and footer bytes of the ET ring message - cached from
     * the session descriptor.
     */
    if (!pSessionDesc->useSymConstantsTable)
    {
        pCacheDummyHdr = (Cpa8U *)&(pSessionDesc->reqCacheHdr);
        pCacheDummyFtr = (Cpa8U *)&(pSessionDesc->reqCacheFtr);
    }
    else
    {
        pCacheDummyHdr = (Cpa8U *)&(pSessionDesc->shramReqCacheHdr);
        pCacheDummyFtr = (Cpa8U *)&(pSessionDesc->shramReqCacheFtr);
    }
    osalMemCopy(pMsgDummy,
                pCacheDummyHdr,
                (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_HDR_IN_LW));
    osalMemSet(
        (pMsgDummy + (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_HDR_IN_LW)),
        0,
        (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_TO_CLEAR_IN_LW));
    osalMemCopy(pMsgDummy +
                    (LAC_LONG_WORD_IN_BYTES * LAC_START_OF_CACHE_FTR_IN_LW),
                pCacheDummyFtr,
                (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_FTR_IN_LW));

    SalQatMsg_CmnMidWrite(pCurrentQatMsg,
                          pRequest,
                          (CPA_DP_BUFLIST == pRequest->srcBufferLen
                               ? QAT_COMN_PTR_TYPE_SGL
                               : QAT_COMN_PTR_TYPE_FLAT),
                          pRequest->srcBuffer,
                          pRequest->dstBuffer,
                          pRequest->srcBufferLen,
                          pRequest->dstBufferLen);

    /* Write Request Params */
    if (pSessionDesc->isCipher)
    {

        LacSymQat_CipherRequestParamsPopulate(
            pSessionDesc,
            pCurrentQatMsg,
            pRequest->cryptoStartSrcOffsetInBytes,
            pRequest->messageLenToCipherInBytes,
            pRequest->iv,
            pRequest->pIv);
    }

    if (pSessionDesc->isAuth)
    {
        lac_sym_qat_hash_state_buffer_info_t *pHashStateBufferInfo =
            &(pSessionDesc->hashStateBufferInfo);
        icp_qat_fw_la_auth_req_params_t *pAuthReqPars =
            (icp_qat_fw_la_auth_req_params_t
                 *)((Cpa8U *)&(pCurrentQatMsg->serv_specif_rqpars) +
                    ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);

        if ((CPA_CY_SYM_HASH_SNOW3G_UIA2 != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_AES_CCM != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_AES_GCM != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_AES_GMAC != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_ZUC_EIA3 != pSessionDesc->hashAlgorithm) &&
            (pHashStateBufferInfo->prefixAadSzQuadWords > 0))
        {
            /* prefixAadSzQuadWords > 0 when there is prefix data
           - i.e. nested hash or HMAC no precompute cases
           Note partials not supported on DP api so we do not need
           dynamic hash state in this case */
            pRequest->additionalAuthData =
                pHashStateBufferInfo->pDataPhys +
                LAC_QUADWORDS_TO_BYTES(
                    pHashStateBufferInfo->stateStorageSzQuadWords);
        }

        /* The first 24 bytes in icp_qat_fw_la_auth_req_params_t can be
         * copied directly from the op request data because they share a
         * corresponding layout.  The remaining 4 bytes are taken
         * from the session message template and use values preconfigured at
         * sessionInit (updated per request for some specific cases below)
         */
        memcpy(pAuthReqPars,
               (Cpa32U *)&(pRequest->hashStartSrcOffsetInBytes),
               ((uintptr_t) &
                (pAuthReqPars->u2.inner_prefix_sz) - (uintptr_t)pAuthReqPars));

        if (CPA_TRUE == pSessionDesc->isAuthEncryptOp)
        {
            pAuthReqPars->hash_state_sz =
                LAC_BYTES_TO_QUADWORDS(pAuthReqPars->u2.aad_sz);
        }
        else if (CPA_CY_SYM_HASH_SNOW3G_UIA2 == pSessionDesc->hashAlgorithm ||
                 CPA_CY_SYM_HASH_ZUC_EIA3 == pSessionDesc->hashAlgorithm)
        {
            pAuthReqPars->hash_state_sz =
                LAC_BYTES_TO_QUADWORDS(pSessionDesc->aadLenInBytes);
        }
    }

}

/**
 *****************************************************************************
 * @ingroup cpaCySymDp
 *      Write Message on the ring and write request params
 *
 * @description
 *      Write Message on the ring and write request params
 *
 * @param[in/out]    pRequest       Pointer to operation data for crypto
 *                                  data plane API
 * @param[in/out]    pCurrentQatMsg Pointer to ring memory where msg will
 *                                  be written
 *
 * @retval none
 *
 *****************************************************************************/

void LacDp_WriteRingMsgFull(CpaCySymDpOpData *pRequest,
                            icp_qat_fw_la_bulk_req_t *pCurrentQatMsg)
{
    lac_session_desc_t *pSessionDesc =
        LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequest->sessionCtx);
    Cpa8U *pMsgDummy = NULL;
    Cpa8U *pCacheDummyHdr = NULL;
    Cpa8U *pCacheDummyFtr = NULL;
    sal_qat_content_desc_info_t *pCdInfo = NULL;
    Cpa8U *pHwBlockBaseInDRAM = NULL;
    Cpa32U hwBlockOffsetInDRAM = 0;
    Cpa32U sizeInBytes = 0;
    CpaCySymCipherAlgorithm cipher = pSessionDesc->cipherAlgorithm;
    CpaCySymHashAlgorithm hash = pSessionDesc->hashAlgorithm;
    sal_crypto_service_t *pService =
        (sal_crypto_service_t *)pRequest->instanceHandle;
    Cpa32U capabilitiesMask = ((sal_crypto_service_t *)pRequest->instanceHandle)
                                  ->generic_service_info.capabilitiesMask;

    CpaBoolean isSpGcm = LAC_CIPHER_IS_SPC_GCM(cipher, hash, capabilitiesMask);
    CpaBoolean isSpCcp = LAC_CIPHER_IS_SPC_CCP(cipher, hash, capabilitiesMask);
    CpaBoolean isSpCcm = LAC_CIPHER_IS_SPC_CCM(cipher, hash, capabilitiesMask);

    Cpa8U paddingLen = 0;
    Cpa8U blockLen = 0;
    Cpa32U aadDataLen = 0;

    pMsgDummy = (Cpa8U *)pCurrentQatMsg;
    /* Write Request */
    /*
     * Fill in the header and footer bytes of the ET ring message - cached from
     * the session descriptor.
     */

    /* Convert Alg Chain Request to Cipher Request for CCP,
     * AES_GCM and AES_CCM single pass.
     * HW supports only 12 bytes IVs for single pass CCP and AES_GCM,
     * there is no such restriction for single pass CCM */
    if ((SPC_NO != pSessionDesc->singlePassState) &&
        ((LAC_CIPHER_SPC_IV_SIZE == pRequest->ivLenInBytes &&
          (isSpGcm || isSpCcp)) ||
         isSpCcm))
    {
        pSessionDesc->singlePassState = SPC_YES;
        pSessionDesc->isCipher = CPA_TRUE;
        pSessionDesc->isAuthEncryptOp = CPA_FALSE;
        pSessionDesc->isAuth = CPA_FALSE;
        pSessionDesc->symOperation = CPA_CY_SYM_OP_CIPHER;
        pSessionDesc->laCmdId = ICP_QAT_FW_LA_CMD_CIPHER;
        if (CPA_CY_SYM_HASH_AES_GMAC == pSessionDesc->hashAlgorithm)
        {
            pSessionDesc->aadLenInBytes = pRequest->messageLenToHashInBytes;
        }
        /* New bit position (13) for SINGLE PASS.
         * The FW provides a specific macro to use to set the proto flag */
        ICP_QAT_FW_LA_SINGLE_PASS_PROTO_FLAG_SET(
            pSessionDesc->laCmdFlags, ICP_QAT_FW_LA_SINGLE_PASS_PROTO);

        /* Set extended service flags - used only in algorithm chaining */
        ICP_QAT_FW_USE_EXTENDED_PROTOCOL_FLAGS_SET(pSessionDesc->laExtCmdFlags,
                                                   0);

        pCdInfo = &(pSessionDesc->contentDescInfo);
        pHwBlockBaseInDRAM = (Cpa8U *)pCdInfo->pData;
        if (CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT ==
            pSessionDesc->cipherDirection)
        {
            if (LAC_CIPHER_IS_GCM(cipher))
                hwBlockOffsetInDRAM = LAC_QUADWORDS_TO_BYTES(
                    LAC_SYM_QAT_CIPHER_GCM_SPC_OFFSET_IN_DRAM);
            else if (LAC_CIPHER_IS_CHACHA(cipher))
                hwBlockOffsetInDRAM = LAC_QUADWORDS_TO_BYTES(
                    LAC_SYM_QAT_CIPHER_CHACHA_SPC_OFFSET_IN_DRAM);
        }
        else if (isSpCcm)
        {
            hwBlockOffsetInDRAM = LAC_QUADWORDS_TO_BYTES(
                LAC_SYM_QAT_CIPHER_CCM_SPC_OFFSET_IN_DRAM);
        }

        /* Update slice type, as used algos changed */
        pSessionDesc->cipherSliceType = LacCipher_GetCipherSliceType(
            &pService->generic_service_info, cipher);

        ICP_QAT_FW_LA_SLICE_TYPE_SET(pSessionDesc->laCmdFlags,
                                     pSessionDesc->cipherSliceType);

        /* construct cipherConfig in CD in DRAM */
        LacSymQat_CipherHwBlockPopulateCfgData(pSessionDesc,
                                               pHwBlockBaseInDRAM +
                                                   hwBlockOffsetInDRAM,
                                               &sizeInBytes);
        SalQatMsg_CmnHdrWrite(
            (icp_qat_fw_comn_req_t *)&(pSessionDesc->reqSpcCacheHdr),
            ICP_QAT_FW_COMN_REQ_CPM_FW_LA,
            pSessionDesc->laCmdId,
            pSessionDesc->cmnRequestFlags,
            pSessionDesc->laCmdFlags,
            pSessionDesc->laExtCmdFlags);
    }
    else if (CPA_CY_SYM_HASH_AES_GMAC == pSessionDesc->hashAlgorithm)
    {
        pSessionDesc->aadLenInBytes = pRequest->messageLenToHashInBytes;
    }
    if (SPC_YES == pSessionDesc->singlePassState)
    {
        pCacheDummyHdr = (Cpa8U *)&(pSessionDesc->reqSpcCacheHdr);
        pCacheDummyFtr = (Cpa8U *)&(pSessionDesc->reqSpcCacheFtr);
    }
    else
    {
        if (!pSessionDesc->useSymConstantsTable)
        {
            pCacheDummyHdr = (Cpa8U *)&(pSessionDesc->reqCacheHdr);
            pCacheDummyFtr = (Cpa8U *)&(pSessionDesc->reqCacheFtr);
        }
        else
        {
            pCacheDummyHdr = (Cpa8U *)&(pSessionDesc->shramReqCacheHdr);
            pCacheDummyFtr = (Cpa8U *)&(pSessionDesc->shramReqCacheFtr);
        }
    }
    osalMemCopy(pMsgDummy,
                pCacheDummyHdr,
                (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_HDR_IN_LW));
    osalMemSet(
        (pMsgDummy + (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_HDR_IN_LW)),
        0,
        (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_TO_CLEAR_IN_LW));
    osalMemCopy(pMsgDummy +
                    (LAC_LONG_WORD_IN_BYTES * LAC_START_OF_CACHE_FTR_IN_LW),
                pCacheDummyFtr,
                (LAC_LONG_WORD_IN_BYTES * LAC_SIZE_OF_CACHE_FTR_IN_LW));

    SalQatMsg_CmnMidWrite(pCurrentQatMsg,
                          pRequest,
                          (CPA_DP_BUFLIST == pRequest->srcBufferLen
                               ? QAT_COMN_PTR_TYPE_SGL
                               : QAT_COMN_PTR_TYPE_FLAT),
                          pRequest->srcBuffer,
                          pRequest->dstBuffer,
                          pRequest->srcBufferLen,
                          pRequest->dstBufferLen);

    if ((CPA_CY_SYM_HASH_AES_CCM == pSessionDesc->hashAlgorithm &&
         pSessionDesc->isAuth == CPA_TRUE) ||
        isSpCcm)
    {
        /* prepare IV and AAD for CCM */
        LacSymAlgChain_PrepareCCMData(pSessionDesc,
                                      pRequest->pAdditionalAuthData,
                                      pRequest->pIv,
                                      pRequest->messageLenToCipherInBytes,
                                      pRequest->ivLenInBytes);

        /* According to the API, for CCM and GCM, messageLenToHashInBytes
         * and hashStartSrcOffsetInBytes are not initialized by the
         * user and must be set by the driver
         */
        pRequest->hashStartSrcOffsetInBytes =
            pRequest->cryptoStartSrcOffsetInBytes;
        pRequest->messageLenToHashInBytes = pRequest->messageLenToCipherInBytes;
    }
    else if ((SPC_NO == pSessionDesc->singlePassState) &&
             (CPA_CY_SYM_HASH_AES_GCM == pSessionDesc->hashAlgorithm ||
              CPA_CY_SYM_HASH_AES_GMAC == pSessionDesc->hashAlgorithm))
    {
        /* GCM case */
        if (CPA_CY_SYM_HASH_AES_GMAC != pSessionDesc->hashAlgorithm)
        {
            /* According to the API, for CCM and GCM,
             * messageLenToHashInBytes and hashStartSrcOffsetInBytes
             * are not initialized by the user and must be set
             * by the driver
             */
            pRequest->hashStartSrcOffsetInBytes =
                pRequest->cryptoStartSrcOffsetInBytes;
            pRequest->messageLenToHashInBytes =
                pRequest->messageLenToCipherInBytes;

            LacSymAlgChain_PrepareGCMData(pSessionDesc,
                                          pRequest->pAdditionalAuthData);
        }

        if (LAC_CIPHER_IV_SIZE_GCM_12 == pRequest->ivLenInBytes)
        {
            ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(
                pCurrentQatMsg->comn_hdr.serv_specif_flags,
                ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
        }
    }

    /* Write Request Params */
    if (pSessionDesc->isCipher)
    {
        if (CPA_CY_SYM_CIPHER_ARC4 == pSessionDesc->cipherAlgorithm)
        {
            /* ARC4 does not have an IV but the field is used to store the
             * initial state */
            pRequest->iv = pSessionDesc->cipherARC4InitialStatePhysAddr;
        }

        ICP_QAT_FW_LA_SLICE_TYPE_SET(pCurrentQatMsg->comn_hdr.serv_specif_flags,
                                     pSessionDesc->cipherSliceType);

        LacSymQat_CipherRequestParamsPopulate(
            pSessionDesc,
            pCurrentQatMsg,
            pRequest->cryptoStartSrcOffsetInBytes,
            pRequest->messageLenToCipherInBytes,
            pRequest->iv,
            pRequest->pIv);
        if (SPC_YES == pSessionDesc->singlePassState)
        {
            icp_qat_fw_la_cipher_20_req_params_t *pCipher20ReqParams =
                (void *)((Cpa8U *)&(pCurrentQatMsg->serv_specif_rqpars) +
                         ICP_QAT_FW_CIPHER_REQUEST_PARAMETERS_OFFSET);

                pCipher20ReqParams->spc_aad_addr =
                    (Cpa64U)pRequest->additionalAuthData;
                pCipher20ReqParams->spc_aad_sz = pSessionDesc->aadLenInBytes;
                pCipher20ReqParams->spc_aad_offset = 0;
                if (isSpCcm)
                    pCipher20ReqParams->spc_aad_sz += LAC_CIPHER_CCM_AAD_OFFSET;

                pCipher20ReqParams->spc_auth_res_addr =
                    (Cpa64U)pRequest->digestResult;
                pCipher20ReqParams->spc_auth_res_sz =
                    (Cpa8U)pSessionDesc->hashResultSize;

            /* For CHACHA, AES_GCM and AES_CCM single pass AAD buffer needs
             * alignment if aadLenInBytes is nonzero.
             * In case of AES-GMAC, AAD buffer passed in the src buffer.
             * Additionally even if aadLenInBytes is 0 for AES-CCM,
             * still AAD buffer need to be used, as it contains B0 block
             * and encoded AAD len.
             */
            if ((0 != pSessionDesc->aadLenInBytes &&
                 CPA_CY_SYM_HASH_AES_GMAC != pSessionDesc->hashAlgorithm) ||
                isSpCcm)
            {
                blockLen = LacSymQat_CipherBlockSizeBytesGet(
                    pSessionDesc->cipherAlgorithm);
                aadDataLen = pSessionDesc->aadLenInBytes;

                /* In case of AES_CCM, B0 block size and 2 bytes of AAD len
                 * encoding need to be added to total AAD data len */
                if (isSpCcm)
                    aadDataLen += LAC_CIPHER_CCM_AAD_OFFSET;

                if (blockLen && (aadDataLen % blockLen) != 0)
                {
                    paddingLen = blockLen - (aadDataLen % blockLen);
                    osalMemSet(&pRequest->pAdditionalAuthData[aadDataLen],
                               0,
                               paddingLen);
                }
            }
        }
    }

    if (pSessionDesc->isAuth)
    {
        lac_sym_qat_hash_state_buffer_info_t *pHashStateBufferInfo =
            &(pSessionDesc->hashStateBufferInfo);
        icp_qat_fw_la_auth_req_params_t *pAuthReqPars =
            (icp_qat_fw_la_auth_req_params_t
                 *)((Cpa8U *)&(pCurrentQatMsg->serv_specif_rqpars) +
                    ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);

        if ((CPA_CY_SYM_HASH_SNOW3G_UIA2 != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_AES_CCM != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_AES_GCM != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_AES_GMAC != pSessionDesc->hashAlgorithm &&
             CPA_CY_SYM_HASH_ZUC_EIA3 != pSessionDesc->hashAlgorithm) &&
            (pHashStateBufferInfo->prefixAadSzQuadWords > 0))
        {
            /* prefixAadSzQuadWords > 0 when there is prefix data
           - i.e. nested hash or HMAC no precompute cases
           Note partials not supported on DP api so we do not need
           dynamic hash state in this case */
            pRequest->additionalAuthData =
                pHashStateBufferInfo->pDataPhys +
                LAC_QUADWORDS_TO_BYTES(
                    pHashStateBufferInfo->stateStorageSzQuadWords);
        }

        /* The first 24 bytes in icp_qat_fw_la_auth_req_params_t can be
         * copied directly from the op request data because they share a
         * corresponding layout.  The remaining 4 bytes are taken
         * from the session message template and use values preconfigured at
         * sessionInit (updated per request for some specific cases below)
         */
        memcpy(pAuthReqPars,
               (Cpa32U *)&(pRequest->hashStartSrcOffsetInBytes),
               ((uintptr_t) &
                (pAuthReqPars->u2.inner_prefix_sz) - (uintptr_t)pAuthReqPars));

        if (CPA_TRUE == pSessionDesc->isAuthEncryptOp)
        {
            pAuthReqPars->hash_state_sz =
                LAC_BYTES_TO_QUADWORDS(pAuthReqPars->u2.aad_sz);
        }
        else if (CPA_CY_SYM_HASH_SNOW3G_UIA2 == pSessionDesc->hashAlgorithm ||
                 CPA_CY_SYM_HASH_ZUC_EIA3 == pSessionDesc->hashAlgorithm)
        {
            pAuthReqPars->hash_state_sz =
                LAC_BYTES_TO_QUADWORDS(pSessionDesc->aadLenInBytes);
        }
    }

}

CpaStatus cpaCySymDpSessionCtxGetSize(
    const CpaInstanceHandle instanceHandle,
    const CpaCySymSessionSetupData *pSessionSetupData,
    Cpa32U *pSessionCtxSizeInBytes)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    /* CPA_INSTANCE_HANDLE_SINGLE is not supported on DP apis */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    /* All other param checks are common with trad api */
    /* Check for valid pointers */
    LAC_CHECK_NULL_PARAM(pSessionCtxSizeInBytes);
#endif
    status = cpaCySymSessionCtxGetSize(
        instanceHandle, pSessionSetupData, pSessionCtxSizeInBytes);

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pSessionSetupData,
             (LAC_ARCH_UINT)pSessionCtxSizeInBytes,
             *pSessionCtxSizeInBytes);
#endif
    return status;
}

CpaStatus cpaCySymDpSessionCtxGetDynamicSize(
    const CpaInstanceHandle instanceHandle,
    const CpaCySymSessionSetupData *pSessionSetupData,
    Cpa32U *pSessionCtxSizeInBytes)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    /* CPA_INSTANCE_HANDLE_SINGLE is not supported on DP apis */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    /* All other param checks are common with trad api */
    /* Check for valid pointers */
    LAC_CHECK_NULL_PARAM(pSessionCtxSizeInBytes);
#endif
    status = cpaCySymSessionCtxGetDynamicSize(
        instanceHandle, pSessionSetupData, pSessionCtxSizeInBytes);

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pSessionSetupData,
             (LAC_ARCH_UINT)pSessionCtxSizeInBytes,
             *pSessionCtxSizeInBytes);
#endif
    return status;
}

/** @ingroup cpaCySymDp */
CpaStatus cpaCySymDpInitSession(
    CpaInstanceHandle instanceHandle,
    const CpaCySymSessionSetupData *pSessionSetupData,
    CpaCySymDpSessionCtx sessionCtx)
{
    CpaStatus status = CPA_STATUS_FAIL;
    sal_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pSessionSetupData,
             (LAC_ARCH_UINT)sessionCtx);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSessionSetupData);
#endif /*ICP_PARAM_CHECK*/
    pService = (sal_service_t *)instanceHandle;

    /* Check crypto service is running otherwise return an error */
    SAL_RUNNING_CHECK(pService);

    status = LacSym_InitSession(instanceHandle,
                                NULL, /* Callback */
                                pSessionSetupData,
                                CPA_TRUE, /* isDPSession */
                                sessionCtx);
    return status;
}

CpaStatus cpaCySymDpRemoveSession(const CpaInstanceHandle instanceHandle,
                                  CpaCySymDpSessionCtx sessionCtx)
{
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)sessionCtx);
#endif

#ifdef ICP_PARAM_CHECK
    /* CPA_INSTANCE_HANDLE_SINGLE is not supported on DP apis */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    /* All other param checks are common with trad api */
#endif

    return cpaCySymRemoveSession(instanceHandle, sessionCtx);
}

CpaStatus cpaCySymDpRegCbFunc(const CpaInstanceHandle instanceHandle,
                              const CpaCySymDpCbFunc pSymDpCb)
{
    sal_crypto_service_t *pService = (sal_crypto_service_t *)instanceHandle;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pSymDpCb);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSymDpCb);
#endif
    SAL_RUNNING_CHECK(instanceHandle);
    pService->pSymDpCb = pSymDpCb;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaCySymDpEnqueueOp(CpaCySymDpOpData *pRequest,
                              const CpaBoolean performOpNow)
{
    icp_qat_fw_la_bulk_req_t *pCurrentQatMsg = NULL;
    icp_comms_trans_handle trans_handle = NULL;
    lac_session_desc_t *pSessionDesc = NULL;
    write_ringMsgFunc_t callFunc;

#ifdef ICP_PARAM_CHECK
    CpaStatus status = CPA_STATUS_SUCCESS;
#endif

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, %d)\n",
             (LAC_ARCH_UINT)pRequest,
             performOpNow);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pRequest);
    status = LacDp_EnqueueParamCheck(pRequest);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
#endif

    /* Check if SAL is running in crypto data plane otherwise return an error */
    SAL_RUNNING_CHECK(pRequest->instanceHandle);

    trans_handle =
        ((sal_crypto_service_t *)pRequest->instanceHandle)->trans_handle_sym_tx;

    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequest->sessionCtx);

    icp_adf_getSingleQueueAddr(trans_handle, (void **)&pCurrentQatMsg);
    if (NULL == pCurrentQatMsg)
    {
        /*
         * No space is available on the queue.
         */
        return CPA_STATUS_RETRY;
    }

    callFunc = (write_ringMsgFunc_t)pSessionDesc->writeRingMsgFunc;

    LAC_CHECK_NULL_PARAM(callFunc);

    callFunc(pRequest, pCurrentQatMsg);

    pSessionDesc->u.pendingDpCbCount++;

    if (CPA_TRUE == performOpNow)
    {
        SalQatMsg_updateQueueTail(trans_handle);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaCySymDpPerformOpNow(const CpaInstanceHandle instanceHandle)
{
    icp_comms_trans_handle trans_handle = NULL;

#ifdef ICP_TRACE
    LAC_LOG1("Called with param (0x%lx)\n", (LAC_ARCH_UINT)instanceHandle);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);

    trans_handle =
        ((sal_crypto_service_t *)instanceHandle)->trans_handle_sym_tx;

    if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
    {
        SalQatMsg_updateQueueTail(trans_handle);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaCySymDpEnqueueOpBatch(const Cpa32U numberRequests,
                                   CpaCySymDpOpData *pRequests[],
                                   const CpaBoolean performOpNow)
{
    icp_qat_fw_la_bulk_req_t *pCurrentQatMsg = NULL;
    icp_comms_trans_handle trans_handle = NULL;
    lac_session_desc_t *pSessionDesc = NULL;
    write_ringMsgFunc_t callFunc;
    Cpa32U i = 0;

#ifdef ICP_PARAM_CHECK
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pService = NULL;
#endif

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (%d, 0x%lx, %d)\n",
             numberRequests,
             (LAC_ARCH_UINT)pRequests,
             performOpNow);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pRequests);
    LAC_CHECK_NULL_PARAM(pRequests[0]);
    LAC_CHECK_NULL_PARAM(pRequests[0]->instanceHandle);

    pService = (sal_crypto_service_t *)(pRequests[0]->instanceHandle);

    if ((0 == numberRequests) || (numberRequests > pService->maxNumSymReqBatch))
    {
        LAC_INVALID_PARAM_LOG1("The number of requests needs to be between 1 "
                               "and %d",
                               pService->maxNumSymReqBatch);
        return CPA_STATUS_INVALID_PARAM;
    }

    for (i = 0; i < numberRequests; i++)
    {
        status = LacDp_EnqueueParamCheck(pRequests[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }

        /* Check that all instance handles are the same */
        if (pRequests[i]->instanceHandle != pRequests[0]->instanceHandle)
        {
            LAC_INVALID_PARAM_LOG("All instance handles should be the same "
                                  "in the requests");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    /* Check if SAL is running in crypto data plane otherwise return an error */
    SAL_RUNNING_CHECK(pRequests[0]->instanceHandle);

    trans_handle = ((sal_crypto_service_t *)pRequests[0]->instanceHandle)
                       ->trans_handle_sym_tx;
    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequests[0]->sessionCtx);

    icp_adf_getQueueMemory(
        trans_handle, numberRequests, (void **)&pCurrentQatMsg);
    if (NULL == pCurrentQatMsg)
    {
        /*
         * No space is available on the queue.
         */
        return CPA_STATUS_RETRY;
    }

    for (i = 0; i < numberRequests; i++)
    {
        pSessionDesc =
            LAC_SYM_SESSION_DESC_FROM_CTX_GET(pRequests[i]->sessionCtx);
        callFunc = (write_ringMsgFunc_t)pSessionDesc->writeRingMsgFunc;
        callFunc(pRequests[i], pCurrentQatMsg);
        icp_adf_getQueueNext(trans_handle, (void **)&pCurrentQatMsg);
        pSessionDesc->u.pendingDpCbCount++;
    }

    if (CPA_TRUE == performOpNow)
    {
        SalQatMsg_updateQueueTail(trans_handle);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_sal_CyPollDpInstance(const CpaInstanceHandle instanceHandle,
                                   const Cpa32U responseQuota)
{
    icp_comms_trans_handle trans_handle = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);

    trans_handle =
        ((sal_crypto_service_t *)instanceHandle)->trans_handle_sym_rx;

    return icp_adf_pollQueue(trans_handle, responseQuota);
}
