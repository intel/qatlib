/******************************************************************************
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
 * @file lac_sym_api.c      Implementation of the symmetric API
 *
 * @ingroup LacSym
 *
 ***************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_im.h"

#include "Osal.h"

#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_adf_transport_dp.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"
#include "icp_qat_fw_la.h"

/*
 ******************************************************************************
 * Include private header files
 ******************************************************************************
 */
#include "lac_common.h"
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "lac_sym.h"
#include "lac_sym_qat.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "lac_session.h"
#include "lac_sym_cipher.h"
#include "lac_sym_hash.h"
#include "lac_sym_alg_chain.h"
#include "lac_sym_stats.h"
#include "lac_sym_partial.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym_cb.h"
#include "lac_buffer_desc.h"
#include "lac_sync.h"
#include "lac_hooks.h"
#include "lac_sal_types_crypto.h"
#include "sal_service_state.h"

/* Macro for checking if partial packet are supported for a given
 * symmetric operation */
#define IS_PARTIAL_ON_SYM_OP_SUPPORTED(                                        \
    symOp, cipherAlgorithm, hashAlgorithm, hashMode)                           \
    (((CPA_CY_SYM_OP_CIPHER == symOp) &&                                       \
      (CPA_CY_SYM_CIPHER_KASUMI_F8 != cipherAlgorithm) &&                      \
      (CPA_CY_SYM_CIPHER_AES_F8 != cipherAlgorithm) &&                         \
      (CPA_CY_SYM_CIPHER_SNOW3G_UEA2 != cipherAlgorithm) &&                    \
      (CPA_CY_SYM_CIPHER_ZUC_EEA3 != cipherAlgorithm)) ||                      \
     ((CPA_CY_SYM_OP_HASH == symOp) &&                                         \
      (CPA_CY_SYM_HASH_KASUMI_F9 != hashAlgorithm) &&                          \
      (CPA_CY_SYM_HASH_SNOW3G_UIA2 != hashAlgorithm) &&                        \
      (CPA_CY_SYM_HASH_ZUC_EIA3 != hashAlgorithm)) ||                          \
     ((CPA_CY_SYM_OP_ALGORITHM_CHAINING == symOp) &&                           \
      (CPA_CY_SYM_CIPHER_KASUMI_F8 != cipherAlgorithm) &&                      \
      (CPA_CY_SYM_CIPHER_AES_F8 != cipherAlgorithm) &&                         \
      (CPA_CY_SYM_CIPHER_SNOW3G_UEA2 != cipherAlgorithm) &&                    \
      (CPA_CY_SYM_CIPHER_ZUC_EEA3 != cipherAlgorithm) &&                       \
      (CPA_CY_SYM_CIPHER_CHACHA != cipherAlgorithm) &&                         \
      (CPA_CY_SYM_HASH_KASUMI_F9 != hashAlgorithm) &&                          \
      (CPA_CY_SYM_HASH_SNOW3G_UIA2 != hashAlgorithm) &&                        \
      (CPA_CY_SYM_HASH_SHA3_256 != hashAlgorithm) &&                           \
      (CPA_CY_SYM_HASH_ZUC_EIA3 != hashAlgorithm) &&                           \
      (CPA_CY_SYM_HASH_POLY != hashAlgorithm)))

#define IS_EXT_ALG_CHAIN_UNSUPPORTED(                                          \
    cipherAlgorithm, hashAlgorithm, extAlgchainSupported)                      \
    ((((CPA_CY_SYM_CIPHER_ZUC_EEA3 == cipherAlgorithm ||                       \
        CPA_CY_SYM_CIPHER_SNOW3G_UEA2 == cipherAlgorithm) &&                   \
       CPA_CY_SYM_HASH_AES_CMAC == hashAlgorithm) ||                           \
      ((CPA_CY_SYM_CIPHER_NULL == cipherAlgorithm ||                           \
        CPA_CY_SYM_CIPHER_AES_CTR == cipherAlgorithm ||                        \
        CPA_CY_SYM_CIPHER_ZUC_EEA3 == cipherAlgorithm) &&                      \
       CPA_CY_SYM_HASH_SNOW3G_UIA2 == hashAlgorithm) ||                        \
      ((CPA_CY_SYM_CIPHER_NULL == cipherAlgorithm ||                           \
        CPA_CY_SYM_CIPHER_AES_CTR == cipherAlgorithm ||                        \
        CPA_CY_SYM_CIPHER_SNOW3G_UEA2 == cipherAlgorithm) &&                   \
       CPA_CY_SYM_HASH_ZUC_EIA3 == hashAlgorithm)) &&                          \
     !extAlgchainSupported)

/*** Local functions definitions ***/
#ifdef ICP_PARAM_CHECK
STATIC CpaStatus
LacSymPerform_BufferParamCheck(const CpaBufferList *const pSrcBuffer,
                               const CpaBufferList *const pDstBuffer,
                               const lac_session_desc_t *const pSessionDesc,
                               const CpaCySymOpData *const pOpData);
#endif

void LacDp_WriteRingMsgFull(CpaCySymDpOpData *pRequest,
                            icp_qat_fw_la_bulk_req_t *pCurrentQatMsg);
void LacDp_WriteRingMsgOpt(CpaCySymDpOpData *pRequest,
                           icp_qat_fw_la_bulk_req_t *pCurrentQatMsg);
void getCtxSize(const CpaCySymSessionSetupData *pSessionSetupData,
                Cpa32U *pSessionCtxSizeInBytes);

/**
 *****************************************************************************
 * @ingroup LacSym
 *      Generic bufferList callback function.
 * @description
 *      This function is used when the API is called in synchronous mode.
 *      It's assumed the callbackTag holds a lac_sync_op_data_t type
 *      and when the callback is received, this callback shall set the
 *      status and opResult element of that cookie structure and
 *      kick the sid.
 *      This function may be used directly as a callback function.
 *
 * @param[in]  callbackTag       Callback Tag
 * @param[in]  status            Status of callback
 * @param[in]  operationType     Operation Type
 * @param[in]  pOpData           Pointer to the Op Data
 * @param[out] pDstBuffer        Pointer to destination buffer list
 * @param[out] opResult          Boolean to indicate the result of the operation
 *
 * @return void
 *
 *****************************************************************************/
void LacSync_GenBufListVerifyCb(void *pCallbackTag,
                                CpaStatus status,
                                CpaCySymOp operationType,
                                void *pOpData,
                                CpaBufferList *pDstBuffer,
                                CpaBoolean opResult)
{
    LacSync_GenVerifyWakeupSyncCaller(pCallbackTag, status, opResult);
}

/*
*******************************************************************************
* Define static function definitions
*******************************************************************************
*/
#ifdef ICP_PARAM_CHECK
/**
 * @ingroup LacSym
 * Function which perform parameter checks on session setup data
 *
 * @param[in] CpaInstanceHandle     Instance Handle
 * @param[in] pSessionSetupData     Pointer to session setup data
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_INVALID_PARAM  An invalid parameter value was found
 * @retval CPA_STATUS_UNSUPPORTED  An unsupported algorithm was found
 */
STATIC CpaStatus
LacSymSession_ParamCheck(const CpaInstanceHandle instanceHandle,
                         const CpaCySymSessionSetupData *pSessionSetupData)
{
    /* initialize convenient pointers to cipher and hash contexts */
    const CpaCySymCipherSetupData *const pCipherSetupData =
        (const CpaCySymCipherSetupData *)&pSessionSetupData->cipherSetupData;
    const CpaCySymHashSetupData *const pHashSetupData =
        &pSessionSetupData->hashSetupData;

    CpaCySymCapabilitiesInfo capInfo;
    CpaCyCapabilitiesInfo cyCapInfo;
    cpaCySymQueryCapabilities(instanceHandle, &capInfo);
    SalCtrl_CyQueryCapabilities(instanceHandle, &cyCapInfo);

    /* Ensure cipher algorithm is correct and supported */
    if ((CPA_CY_SYM_OP_ALGORITHM_CHAINING == pSessionSetupData->symOperation) ||
        (CPA_CY_SYM_OP_CIPHER == pSessionSetupData->symOperation))
    {
        /* Protect against value of cipher outside the bitmap
         * and check if cipher algorithm is correct
         */
        if (pCipherSetupData->cipherAlgorithm >=
            CPA_CY_SYM_CIPHER_CAP_BITMAP_SIZE)
        {
            LAC_INVALID_PARAM_LOG("cipherAlgorithm");
            return CPA_STATUS_INVALID_PARAM;
        }
        if (!CPA_BITMAP_BIT_TEST(capInfo.ciphers,
                                 pCipherSetupData->cipherAlgorithm))
        {
            LAC_UNSUPPORTED_PARAM_LOG("UnSupported cipherAlgorithm");
            return CPA_STATUS_UNSUPPORTED;
        }
    }

    /* Ensure hash algorithm is correct and supported */
    if ((CPA_CY_SYM_OP_ALGORITHM_CHAINING == pSessionSetupData->symOperation) ||
        (CPA_CY_SYM_OP_HASH == pSessionSetupData->symOperation))
    {
        /* Protect against value of hash outside the bitmap
         * and check if hash algorithm is correct
         */
        if (pHashSetupData->hashAlgorithm >= CPA_CY_SYM_HASH_CAP_BITMAP_SIZE)
        {
            LAC_INVALID_PARAM_LOG("hashAlgorithm");
            return CPA_STATUS_INVALID_PARAM;
        }
        if (!CPA_BITMAP_BIT_TEST(capInfo.hashes, pHashSetupData->hashAlgorithm))
        {
            LAC_UNSUPPORTED_PARAM_LOG("UnSupported hashAlgorithm");
            return CPA_STATUS_UNSUPPORTED;
        }
    }

    /* ensure CCM, GCM, Kasumi, Snow3G and ZUC cipher and hash algorithms are
     * selected together for Algorithm Chaining */
    if (CPA_CY_SYM_OP_ALGORITHM_CHAINING == pSessionSetupData->symOperation)
    {
        /* ensure both hash and cipher algorithms are POLY and CHACHA */
        if (((CPA_CY_SYM_CIPHER_CHACHA == pCipherSetupData->cipherAlgorithm) &&
             (CPA_CY_SYM_HASH_POLY != pHashSetupData->hashAlgorithm)) ||
            ((CPA_CY_SYM_HASH_POLY == pHashSetupData->hashAlgorithm) &&
             (CPA_CY_SYM_CIPHER_CHACHA != pCipherSetupData->cipherAlgorithm)))
        {
            LAC_INVALID_PARAM_LOG("Invalid combination of Cipher/Hash "
                                  "Algorithms for CHACHA/POLY");
            return CPA_STATUS_INVALID_PARAM;
        }

        /* ensure both hash and cipher algorithms are CCM */
        if (((CPA_CY_SYM_CIPHER_AES_CCM == pCipherSetupData->cipherAlgorithm) &&
             (CPA_CY_SYM_HASH_AES_CCM != pHashSetupData->hashAlgorithm)) ||
            ((CPA_CY_SYM_HASH_AES_CCM == pHashSetupData->hashAlgorithm) &&
             (CPA_CY_SYM_CIPHER_AES_CCM != pCipherSetupData->cipherAlgorithm)))
        {
            LAC_INVALID_PARAM_LOG(
                "Invalid combination of Cipher/Hash Algorithms for CCM");
            return CPA_STATUS_INVALID_PARAM;
        }

        /* ensure both hash and cipher algorithms are GCM/GMAC */
        if ((CPA_CY_SYM_CIPHER_AES_GCM == pCipherSetupData->cipherAlgorithm &&
             (CPA_CY_SYM_HASH_AES_GCM != pHashSetupData->hashAlgorithm &&
              CPA_CY_SYM_HASH_AES_GMAC != pHashSetupData->hashAlgorithm)) ||
            ((CPA_CY_SYM_HASH_AES_GCM == pHashSetupData->hashAlgorithm ||
              CPA_CY_SYM_HASH_AES_GMAC == pHashSetupData->hashAlgorithm) &&
             CPA_CY_SYM_CIPHER_AES_GCM != pCipherSetupData->cipherAlgorithm))
        {
            LAC_INVALID_PARAM_LOG(
                "Invalid combination of Cipher/Hash Algorithms for GCM");
            return CPA_STATUS_INVALID_PARAM;
        }

        /* ensure both hash and cipher algorithms are Kasumi */
        if (((CPA_CY_SYM_CIPHER_KASUMI_F8 ==
              pCipherSetupData->cipherAlgorithm) &&
             (CPA_CY_SYM_HASH_KASUMI_F9 != pHashSetupData->hashAlgorithm)) ||
            ((CPA_CY_SYM_HASH_KASUMI_F9 == pHashSetupData->hashAlgorithm) &&
             (CPA_CY_SYM_CIPHER_KASUMI_F8 !=
              pCipherSetupData->cipherAlgorithm)))
        {
            LAC_INVALID_PARAM_LOG(
                "Invalid combination of Cipher/Hash Algorithms for Kasumi");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (IS_EXT_ALG_CHAIN_UNSUPPORTED(pCipherSetupData->cipherAlgorithm,
                                         pHashSetupData->hashAlgorithm,
                                         cyCapInfo.extAlgchainSupported))
        {
            LAC_UNSUPPORTED_PARAM_LOG("ExtAlgChain feature not supported");
            return CPA_STATUS_UNSUPPORTED;
        }

        /* Ensure that algorithm chaining operation is performed for supported
         * wireless algorithms.
         *
         * Following are supported algorithm chaining cipher + hash
         * combinations. Any cipher from the below list can be mixed with any
         * hash from below hash list.
         *
         * Ciphers: Snow3g_UEA2, ZUC_EEA3, AES_CTR, NULL_CIPHER.
         *
         * Hash: Snow3g_UIA2, ZUC_EIA3, AES_CMAC.
         */
        if ((CPA_CY_SYM_CIPHER_SNOW3G_UEA2 ==
             pCipherSetupData->cipherAlgorithm) ||
            (CPA_CY_SYM_CIPHER_ZUC_EEA3 == pCipherSetupData->cipherAlgorithm))
        {
            if ((CPA_CY_SYM_HASH_SNOW3G_UIA2 !=
                 pHashSetupData->hashAlgorithm) &&
                (CPA_CY_SYM_HASH_ZUC_EIA3 != pHashSetupData->hashAlgorithm) &&
                (CPA_CY_SYM_HASH_AES_CMAC != pHashSetupData->hashAlgorithm))
            {
                LAC_INVALID_PARAM_LOG2("Invalid algorithm chaining "
                                       "combination, cipher: %d, hash: %d",
                                       pCipherSetupData->cipherAlgorithm,
                                       pHashSetupData->hashAlgorithm);

                return CPA_STATUS_INVALID_PARAM;
            }
        }
        else if ((CPA_CY_SYM_HASH_SNOW3G_UIA2 ==
                  pHashSetupData->hashAlgorithm) ||
                 (CPA_CY_SYM_HASH_ZUC_EIA3 == pHashSetupData->hashAlgorithm))
        {
            if ((CPA_CY_SYM_CIPHER_SNOW3G_UEA2 !=
                 pCipherSetupData->cipherAlgorithm) &&
                (CPA_CY_SYM_CIPHER_ZUC_EEA3 !=
                 pCipherSetupData->cipherAlgorithm) &&
                (CPA_CY_SYM_CIPHER_AES_CTR !=
                 pCipherSetupData->cipherAlgorithm) &&
                (CPA_CY_SYM_CIPHER_NULL != pCipherSetupData->cipherAlgorithm))
            {
                LAC_INVALID_PARAM_LOG2("Invalid algorithm chaining "
                                       "combination, hash: %d, cipher: %d",
                                       pHashSetupData->hashAlgorithm,
                                       pCipherSetupData->cipherAlgorithm);

                return CPA_STATUS_INVALID_PARAM;
            }
        }
    }
    /* not Algorithm Chaining so prevent CCM/GCM being selected */
    else if (CPA_CY_SYM_OP_CIPHER == pSessionSetupData->symOperation)
    {
        /* ensure cipher algorithm is not CCM, CHACHA or GCM */
        if ((CPA_CY_SYM_CIPHER_AES_CCM == pCipherSetupData->cipherAlgorithm) ||
            (CPA_CY_SYM_CIPHER_AES_GCM == pCipherSetupData->cipherAlgorithm) ||
            (CPA_CY_SYM_CIPHER_CHACHA == pCipherSetupData->cipherAlgorithm))
        {
            LAC_INVALID_PARAM_LOG("Invalid Cipher Algorithm for non-Algorithm "
                                  "Chaining operation");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else if (CPA_CY_SYM_OP_HASH == pSessionSetupData->symOperation)
    {
        /* ensure hash algorithm is not CCM, POLY or GCM/GMAC */
        if ((CPA_CY_SYM_HASH_AES_CCM == pHashSetupData->hashAlgorithm) ||
            (CPA_CY_SYM_HASH_AES_GCM == pHashSetupData->hashAlgorithm) ||
            (CPA_CY_SYM_HASH_AES_GMAC == pHashSetupData->hashAlgorithm) ||
            (CPA_CY_SYM_HASH_POLY == pHashSetupData->hashAlgorithm))
        {
            LAC_INVALID_PARAM_LOG(
                "Invalid Hash Algorithm for non-Algorithm Chaining operation");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    /* Unsupported operation. Return error */
    else
    {
        LAC_INVALID_PARAM_LOG("symOperation");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* ensure that cipher direction param is
     * valid for cipher and algchain ops */
    if (CPA_CY_SYM_OP_HASH != pSessionSetupData->symOperation)
    {
        if ((pCipherSetupData->cipherDirection !=
             CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT) &&
            (pCipherSetupData->cipherDirection !=
             CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT))
        {
            LAC_INVALID_PARAM_LOG("Invalid Cipher Direction");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    return CPA_STATUS_SUCCESS;
}
#endif /*ICP_PARAM_CHECK*/

#ifdef ICP_PARAM_CHECK

/**
 * @ingroup LacSym
 * Function which perform parameter checks on data buffers for symmetric
 * crypto operations
 *
 * @param[in] pSrcBuffer          Pointer to source buffer list
 * @param[in] pDstBuffer          Pointer to destination buffer list
 * @param[in] pSessionDesc        Pointer to session descriptor
 * @param[in] pOpData             Pointer to CryptoSymOpData.
 *
 * @retval CPA_STATUS_SUCCESS        The operation succeeded
 * @retval CPA_STATUS_INVALID_PARAM  An invalid parameter value was found
 */

STATIC CpaStatus
LacSymPerform_BufferParamCheck(const CpaBufferList *const pSrcBuffer,
                               const CpaBufferList *const pDstBuffer,
                               const lac_session_desc_t *const pSessionDesc,
                               const CpaCySymOpData *const pOpData)
{
    Cpa64U srcBufferLen = 0, dstBufferLen = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* verify packet type is in correct range */
    switch (pOpData->packetType)
    {
        case CPA_CY_SYM_PACKET_TYPE_FULL:
        case CPA_CY_SYM_PACKET_TYPE_PARTIAL:
        case CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL:
            break;
        default:
        {
            LAC_INVALID_PARAM_LOG("packetType");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    if (!((CPA_CY_SYM_OP_CIPHER != pSessionDesc->symOperation &&
           CPA_CY_SYM_HASH_MODE_PLAIN == pSessionDesc->hashMode) &&
          (0 == pOpData->messageLenToHashInBytes)))
    {
        if (IS_ZERO_LENGTH_BUFFER_SUPPORTED(pSessionDesc->cipherAlgorithm,
                                            pSessionDesc->hashAlgorithm))
        {
            status = LacBuffDesc_BufferListVerifyNull(
                pSrcBuffer, &srcBufferLen, LAC_NO_ALIGNMENT_SHIFT);
        }
        else
        {
            status = LacBuffDesc_BufferListVerify(
                pSrcBuffer, &srcBufferLen, LAC_NO_ALIGNMENT_SHIFT);
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_INVALID_PARAM_LOG("Source buffer invalid");
            return CPA_STATUS_INVALID_PARAM;
        }
    }
    else
    {
        /* check MetaData !NULL */
        if (NULL == pSrcBuffer->pPrivateMetaData)
        {
            LAC_INVALID_PARAM_LOG("Source buffer MetaData cannot be NULL");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    /* out of place checks */
    if (pSrcBuffer != pDstBuffer)
    {
        /* exception for this check is zero length hash requests to allow */
        /* for srcBufflen=DstBufferLen=0 */
        if (!((CPA_CY_SYM_OP_CIPHER != pSessionDesc->symOperation &&
               CPA_CY_SYM_HASH_MODE_PLAIN == pSessionDesc->hashMode) &&
              (0 == pOpData->messageLenToHashInBytes)))
        {
            /* Verify buffer(s) for dest packet & return packet length */
            if (IS_ZERO_LENGTH_BUFFER_SUPPORTED(pSessionDesc->cipherAlgorithm,
                                                pSessionDesc->hashAlgorithm))
            {
                status = LacBuffDesc_BufferListVerifyNull(
                    pDstBuffer, &dstBufferLen, LAC_NO_ALIGNMENT_SHIFT);
            }
            else
            {
                status = LacBuffDesc_BufferListVerify(
                    pDstBuffer, &dstBufferLen, LAC_NO_ALIGNMENT_SHIFT);
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                LAC_INVALID_PARAM_LOG("Destination buffer invalid");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        else
        {
            /* check MetaData !NULL */
            if (NULL == pDstBuffer->pPrivateMetaData)
            {
                LAC_INVALID_PARAM_LOG("Dest buffer MetaData cannot be NULL");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        /* Check that src Buffer and dst Buffer Lengths are equal */
        /* CCM output needs to be longer than input buffer for appending tag*/
        if (srcBufferLen != dstBufferLen && pSessionDesc->cipherAlgorithm != CPA_CY_SYM_CIPHER_AES_CCM)
        {
            LAC_INVALID_PARAM_LOG(
                "Source and Dest buffer lengths need to be equal ");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    /* check for partial packet suport for the session operation */
    if (CPA_CY_SYM_PACKET_TYPE_FULL != pOpData->packetType)
    {
        if (!(IS_PARTIAL_ON_SYM_OP_SUPPORTED(pSessionDesc->symOperation,
                                             pSessionDesc->cipherAlgorithm,
                                             pSessionDesc->hashAlgorithm,
                                             pSessionDesc->hashMode)))

        {
            /* return out here to simplify cleanup */
            LAC_INVALID_PARAM_LOG(
                "Partial packets not supported for operation");
            return CPA_STATUS_INVALID_PARAM;
        }
        else
        {
            /* This function checks to see if the partial packet sequence
             * is correct */
            if (CPA_STATUS_SUCCESS !=
                LacSym_PartialPacketStateCheck(pOpData->packetType,
                                               pSessionDesc->partialState))
            {
                LAC_INVALID_PARAM_LOG("Partial packet Type");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
    }
    return CPA_STATUS_SUCCESS;
}
#endif

/** @ingroup LacSym */
CpaStatus cpaCySymInitSession(const CpaInstanceHandle instanceHandle_in,
                              const CpaCySymCbFunc pSymCb,
                              const CpaCySymSessionSetupData *pSessionSetupData,
                              CpaCySymSessionCtx pSessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    sal_service_t *pService = NULL;
#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pSymCb,
             (LAC_ARCH_UINT)pSessionSetupData,
             (LAC_ARCH_UINT)pSessionCtx);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
#endif /*ICP_PARAM_CHECK*/

    pService = (sal_service_t *)instanceHandle;

    /* check crypto service is running otherwise return an error */
    SAL_RUNNING_CHECK(pService);

    status = LacSym_InitSession(instanceHandle,
                                pSymCb,
                                pSessionSetupData,
                                CPA_FALSE, /* isDPSession */
                                pSessionCtx);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Increment the stats for a session registered successfully */
        LAC_SYM_STAT_INC(numSessionsInitialized, instanceHandle);
    }
    else /* if there was an error */
    {
        LAC_SYM_STAT_INC(numSessionErrors, instanceHandle);
    }
    return status;
}

CpaStatus cpaCySymSessionInUse(CpaCySymSessionCtx pSessionCtx,
                               CpaBoolean *pSessionInUse)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_session_desc_t *pSessionDesc = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionInUse);
    LAC_CHECK_INSTANCE_HANDLE(pSessionCtx);
#endif

    *pSessionInUse = CPA_FALSE;

    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pSessionCtx);

    /* If there are pending requests */
    if (pSessionDesc->isDPSession)
    {
        if (pSessionDesc->u.pendingDpCbCount)
            *pSessionInUse = CPA_TRUE;
    }
    else
    {
        if (osalAtomicGet(&(pSessionDesc->u.pendingCbCount)))
            *pSessionInUse = CPA_TRUE;
    }

    return status;
}

CpaStatus LacSym_InitSession(const CpaInstanceHandle instanceHandle,
                             const CpaCySymCbFunc pSymCb,
                             const CpaCySymSessionSetupData *pSessionSetupData,
                             const CpaBoolean isDPSession,
                             CpaCySymSessionCtx pSessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_session_desc_t *pSessionDesc = NULL;
    Cpa32U sessionCtxSizeInBytes = 0;
    CpaPhysicalAddr physAddress = 0;
    CpaPhysicalAddr physAddressAligned = 0;
    sal_service_t *pService = NULL;
    const CpaCySymCipherSetupData *pCipherSetupData = NULL;
    const CpaCySymHashSetupData *pHashSetupData = NULL;

    /* Instance param checking done by calling function */

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionSetupData);
    LAC_CHECK_NULL_PARAM(pSessionCtx);
    status = LacSymSession_ParamCheck(instanceHandle, pSessionSetupData);
    LAC_CHECK_STATUS(status);

    /* set the session priority for QAT AL*/
    if ((CPA_CY_PRIORITY_HIGH == pSessionSetupData->sessionPriority) ||
        (CPA_CY_PRIORITY_NORMAL == pSessionSetupData->sessionPriority))
    {
        // do nothing - clean up this code. use RANGE macro
    }
    else
    {
        LAC_INVALID_PARAM_LOG("sessionPriority");
        return CPA_STATUS_INVALID_PARAM;
    }

#endif /*ICP_PARAM_CHECK*/

    pCipherSetupData = &pSessionSetupData->cipherSetupData;
    pHashSetupData = &pSessionSetupData->hashSetupData;

    pService = (sal_service_t *)instanceHandle;

    /* Re-align the session structure to 64 byte alignment */
    physAddress = LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        (*pService), (Cpa8U *)pSessionCtx + sizeof(void *));

    if (0 == physAddress)
    {
        LAC_LOG_ERROR("Unable to get the physical address of the session\n");
        return CPA_STATUS_FAIL;
    }

    physAddressAligned =
        LAC_ALIGN_POW2_ROUNDUP(physAddress, LAC_64BYTE_ALIGNMENT);

    pSessionDesc = (lac_session_desc_t *)
        /* Move the session pointer by the physical offset
        between aligned and unaligned memory */
        ((Cpa8U *)pSessionCtx + sizeof(void *) +
         (physAddressAligned - physAddress));

    /* save the aligned pointer in the first bytes (size of unsigned long)
     * of the session memory */
    *((LAC_ARCH_UINT *)pSessionCtx) = (LAC_ARCH_UINT)pSessionDesc;

    /* start off with a clean session */
    /* Choose Session Context size */
    getCtxSize(pSessionSetupData, &sessionCtxSizeInBytes);
    switch (sessionCtxSizeInBytes)
    {
        case LAC_SYM_SESSION_D1_SIZE:
            osalMemSet(pSessionDesc, 0, sizeof(lac_session_desc_d1_t));
            break;
        case LAC_SYM_SESSION_D2_SIZE:
            osalMemSet(pSessionDesc, 0, sizeof(lac_session_desc_d2_t));
            break;
        default:
            osalMemSet(pSessionDesc, 0, sizeof(lac_session_desc_t));
            break;
    }

    /* Setup content descriptor info structure
     * assumption that content descriptor is the first field in
     * in the session descriptor */
    pSessionDesc->contentDescInfo.pData = (Cpa8U *)pSessionDesc;
    pSessionDesc->contentDescInfo.hardwareSetupBlockPhys = physAddressAligned;

    pSessionDesc->contentDescOptimisedInfo.pData =
        ((Cpa8U *)pSessionDesc + LAC_SYM_QAT_CONTENT_DESC_MAX_SIZE);
    pSessionDesc->contentDescOptimisedInfo.hardwareSetupBlockPhys =
        (physAddressAligned + LAC_SYM_QAT_CONTENT_DESC_MAX_SIZE);

    /* Set the Common Session Information */
    pSessionDesc->symOperation = pSessionSetupData->symOperation;

    if (CPA_FALSE == isDPSession)
    {
        /* For asynchronous - use the user supplied callback
         * for synchronous - use the internal synchronous callback */
        pSessionDesc->pSymCb = ((void *)NULL != (void *)pSymCb)
                                   ? pSymCb
                                   : LacSync_GenBufListVerifyCb;
    }

    pSessionDesc->isDPSession = isDPSession;
    if ((CPA_CY_SYM_HASH_AES_GCM == pHashSetupData->hashAlgorithm) ||
        (CPA_CY_SYM_HASH_AES_GMAC == pHashSetupData->hashAlgorithm) ||
        (CPA_CY_SYM_HASH_AES_CCM == pHashSetupData->hashAlgorithm) ||
        (CPA_CY_SYM_CIPHER_CHACHA == pCipherSetupData->cipherAlgorithm) ||
        (CPA_CY_SYM_CIPHER_ARC4 == pCipherSetupData->cipherAlgorithm))
    {
        pSessionDesc->writeRingMsgFunc = LacDp_WriteRingMsgFull;
    }
    else
    {
        pSessionDesc->writeRingMsgFunc = LacDp_WriteRingMsgOpt;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Session set up via API call (not internal one) */
        /* Services such as DRBG call the crypto api as part of their service
         * hence the need to for the flag, it is needed to distinguish between
         * an internal and external session.
         */
        pSessionDesc->internalSession = CPA_FALSE;

        status = LacAlgChain_SessionInit(
            instanceHandle, pSessionSetupData, pSessionDesc);
    }
    return status;
}

/** @ingroup LacSym */
CpaStatus cpaCySymRemoveSession(const CpaInstanceHandle instanceHandle_in,
                                CpaCySymSessionCtx pSessionCtx)
{
    lac_session_desc_t *pSessionDesc = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = NULL;
    Cpa64U numPendingRequests = 0;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pSessionCtx);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSessionCtx);
#endif /*ICP_PARAM_CHECK*/

    /* check crypto service is running otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);
    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pSessionCtx);

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif /*ICP_PARAM_CHECK*/

    if (CPA_TRUE == pSessionDesc->isDPSession)
    {
        /*
         * Based on one instance, we can initialize multiple sessions.
         * For example, we can initialize the session "X" and session "Y" with
         * the same instance "A". If there is no operation pending for session
         * "X", we can remove the session "X".
         *
         * Now we only check the @pSessionDesc->pendingDpCbCount, if it becomes
         * zero, we can remove the session.
         *
         * Why?
         *   (1) We increase it in the cpaCySymDpEnqueueOp/
         *       cpaCySymDpEnqueueOpBatch.
         *   (2) We decrease it in the LacSymCb_ProcessCallback.
         *
         * If the @pSessionDesc->pendingDpCbCount becomes zero, it means
         * there is no operation pending for the session "X" anymore, so we can
         * remove this session. Maybe there is still some requests left in the
         * instance's ring (icp_adf_queueDataToSend() returns true), but the
         * request does not belong to "X", it belongs to session "Y".
         */
        numPendingRequests = pSessionDesc->u.pendingDpCbCount;
    }
    else
    {
        numPendingRequests = osalAtomicGet(&(pSessionDesc->u.pendingCbCount));
    }

    /* If there are pending requests */
    if (0 != numPendingRequests)
    {
        LAC_LOG1("There are %d requests pending", numPendingRequests);
        status = CPA_STATUS_RETRY;
        if (CPA_TRUE == pSessionDesc->isDPSession)
        {
            /* Need to update tail if messages queue on tx hi ring for
             data plane api */
            icp_comms_trans_handle trans_handle =
                ((sal_crypto_service_t *)instanceHandle)->trans_handle_sym_tx;

            if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
            {
                /* process the remaining messages in the ring */
                LAC_LOG("Submitting enqueued requests");
                /*
                 * icp_adf_updateQueueTail
                 */
                SalQatMsg_updateQueueTail(trans_handle);
                return status;
            }
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_SPINLOCK_DESTROY(&pSessionDesc->requestQueueLock);
        LAC_DESTROY_MUTEX(&pSessionDesc->accessLock);
        if (CPA_FALSE == pSessionDesc->isDPSession)
        {
            LAC_SYM_STAT_INC(numSessionsRemoved, instanceHandle);
        }
    }
    else if (CPA_FALSE == pSessionDesc->isDPSession)
    {
        LAC_SYM_STAT_INC(numSessionErrors, instanceHandle);
    }
    return status;
}

CpaStatus cpaCySymUpdateSession(
    CpaCySymSessionCtx pSessionCtx,
    const CpaCySymSessionUpdateData *pSessionUpdateData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_session_desc_t *pSessionDesc = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionUpdateData);
    LAC_CHECK_NULL_PARAM(pSessionCtx);
#endif

    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pSessionCtx);

    if (CPA_CY_SYM_PACKET_TYPE_FULL != pSessionDesc->partialState)
    {
        return CPA_STATUS_FAIL;
    }

    status = LacAlgChain_SessionUpdate(pSessionDesc, pSessionUpdateData);

    return status;
}

/** @ingroup LacSym */
STATIC CpaStatus LacSym_Perform(const CpaInstanceHandle instanceHandle,
                                void *callbackTag,
                                const CpaCySymOpData *pOpData,
                                const CpaBufferList *pSrcBuffer,
                                CpaBufferList *pDstBuffer,
                                CpaBoolean *pVerifyResult,
                                CpaBoolean isAsyncMode)
{
    lac_session_desc_t *pSessionDesc = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
#endif
    /* check crypto service is running otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pOpData->sessionCtx);
    LAC_CHECK_NULL_PARAM(pSrcBuffer);
    LAC_CHECK_NULL_PARAM(pDstBuffer);
#endif /*ICP_PARAM_CHECK*/

    pSessionDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pOpData->sessionCtx);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);

    /*check whether Payload size is zero for CHACHA-POLY*/
    if ((CPA_CY_SYM_CIPHER_CHACHA == pSessionDesc->cipherAlgorithm) &&
        (CPA_CY_SYM_HASH_POLY == pSessionDesc->hashAlgorithm) &&
        (CPA_CY_SYM_OP_ALGORITHM_CHAINING == pSessionDesc->symOperation))
    {
        if (!pOpData->messageLenToCipherInBytes)
        {
            LAC_INVALID_PARAM_LOG(
                "Invalid messageLenToCipherInBytes for CHACHA-POLY");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

#endif /*ICP_PARAM_CHECK*/

    /* If synchronous Operation - Callback function stored in the session
     * descriptor so a flag is set in the perform to indicate that
     * the perform is being re-called for the synchronous operation */
    if ((LacSync_GenBufListVerifyCb == pSessionDesc->pSymCb) &&
        isAsyncMode == CPA_TRUE)
    {
        CpaBoolean opResult = CPA_FALSE;
        lac_sync_op_data_t *pSyncCallbackData = NULL;

        status = LacSync_CreateSyncCookie(&pSyncCallbackData);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = LacSym_Perform(instanceHandle,
                                    pSyncCallbackData,
                                    pOpData,
                                    pSrcBuffer,
                                    pDstBuffer,
                                    pVerifyResult,
                                    CPA_FALSE);
        }
        else
        {
            /* Failure allocating sync cookie */
            LAC_SYM_STAT_INC(numSymOpRequestErrors, instanceHandle);
            return status;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            CpaStatus syncStatus = CPA_STATUS_SUCCESS;
            syncStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                                 LAC_SYM_SYNC_CALLBACK_TIMEOUT,
                                                 &status,
                                                 &opResult);
            /* If callback doesn't come back */
            if (CPA_STATUS_SUCCESS != syncStatus)
            {
                LAC_SYM_STAT_INC(numSymOpCompletedErrors, instanceHandle);
                LAC_LOG_ERROR("Callback timed out");
                status = syncStatus;
            }
        }
        else
        {
            /* As the Request was not sent the Callback will never
             * be called, so need to indicate that we're finished
             * with cookie so it can be destroyed. */
            LacSync_SetSyncCookieComplete(pSyncCallbackData);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            if (NULL != pVerifyResult)
            {
                *pVerifyResult = opResult;
            }
        }

        LacSync_DestroySyncCookie(&pSyncCallbackData);
        return status;
    }

#ifdef ICP_PARAM_CHECK
    status = LacSymPerform_BufferParamCheck(
        (const CpaBufferList *)pSrcBuffer, pDstBuffer, pSessionDesc, pOpData);
    LAC_CHECK_STATUS(status);

    if ((!pSessionDesc->digestIsAppended) &&
        (CPA_CY_SYM_OP_ALGORITHM_CHAINING == pSessionDesc->symOperation))
    {
        /* Check that pDigestResult is not NULL */
        LAC_CHECK_NULL_PARAM(pOpData->pDigestResult);
    }

#endif /*ICP_PARAM_CHECK*/
    status = LacAlgChain_Perform(instanceHandle,
                                 pSessionDesc,
                                 callbackTag,
                                 pOpData,
                                 pSrcBuffer,
                                 pDstBuffer,
                                 pVerifyResult);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* check for partial packet suport for the session operation */
        if (CPA_CY_SYM_PACKET_TYPE_FULL != pOpData->packetType)
        {
            LacSym_PartialPacketStateUpdate(pOpData->packetType,
                                            &pSessionDesc->partialState);
        }
        /* increment #requests stat */
        LAC_SYM_STAT_INC(numSymOpRequests, instanceHandle);
    }
    /* Retry also results in the errors stat been incremented */
    else
    {
        /* increment #errors stat */
        LAC_SYM_STAT_INC(numSymOpRequestErrors, instanceHandle);
    }
    return status;
}

/** @ingroup LacSym */
CpaStatus cpaCySymPerformOp(const CpaInstanceHandle instanceHandle_in,
                            void *callbackTag,
                            const CpaCySymOpData *pOpData,
                            const CpaBufferList *pSrcBuffer,
                            CpaBufferList *pDstBuffer,
                            CpaBoolean *pVerifyResult)
{
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_TRACE
    CpaStatus status = CPA_STATUS_SUCCESS;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_TRACE
    status = LacSym_Perform(instanceHandle,
                            callbackTag,
                            pOpData,
                            pSrcBuffer,
                            pDstBuffer,
                            pVerifyResult,
                            CPA_TRUE);

    LAC_LOG("Currently being called\n");
    return (status);
#else
    return LacSym_Perform(instanceHandle,
                          callbackTag,
                          pOpData,
                          pSrcBuffer,
                          pDstBuffer,
                          pVerifyResult,
                          CPA_TRUE);
#endif
}

/** @ingroup LacSym */
CpaStatus cpaCySymQueryStats(const CpaInstanceHandle instanceHandle_in,
                             struct _CpaCySymStats *pSymStats)
{

    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pSymStats);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSymStats);
#endif /*ICP_PARAM_CHECK*/

    /* check if crypto service is running
     * otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);

    /* copy the fields from the internal structure into the api defined
     * structure */
    LacSym_Stats32CopyGet(instanceHandle, pSymStats);
    return CPA_STATUS_SUCCESS;
}

/** @ingroup LacSym */
CpaStatus cpaCySymQueryStats64(const CpaInstanceHandle instanceHandle_in,
                               CpaCySymStats64 *pSymStats)
{

    CpaInstanceHandle instanceHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pSymStats);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSymStats);
#endif /*ICP_PARAM_CHECK*/

    /* check if crypto service is running
     * otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);

    /* copy the fields from the internal structure into the api defined
     * structure */
    LacSym_Stats64CopyGet(instanceHandle, pSymStats);

    return CPA_STATUS_SUCCESS;
}

/** @ingroup LacSym */
CpaStatus cpaCySymSessionCtxGetSize(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCySymSessionSetupData *pSessionSetupData,
    Cpa32U *pSessionCtxSizeInBytes)
{
    CpaInstanceHandle instanceHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSessionSetupData);
    LAC_CHECK_NULL_PARAM(pSessionCtxSizeInBytes);
#endif /*ICP_PARAM_CHECK*/

    /* check crypto service is running otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);
    *pSessionCtxSizeInBytes = LAC_SYM_SESSION_SIZE;
#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pSessionSetupData,
             (LAC_ARCH_UINT)pSessionCtxSizeInBytes,
             *pSessionCtxSizeInBytes);
#endif

    return CPA_STATUS_SUCCESS;
}

/** @ingroup LacSym */
CpaStatus cpaCySymSessionCtxGetDynamicSize(
    const CpaInstanceHandle instanceHandle_in,
    const CpaCySymSessionSetupData *pSessionSetupData,
    Cpa32U *pSessionCtxSizeInBytes)
{
    CpaInstanceHandle instanceHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSessionSetupData);
    LAC_CHECK_NULL_PARAM(pSessionCtxSizeInBytes);
#endif /*ICP_PARAM_CHECK*/

    /* check crypto service is running otherwise return an error */
    SAL_RUNNING_CHECK(instanceHandle);
    /* Choose Session Context size */
    getCtxSize(pSessionSetupData, pSessionCtxSizeInBytes);

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pSessionSetupData,
             (LAC_ARCH_UINT)pSessionCtxSizeInBytes,
             *pSessionCtxSizeInBytes);
#endif

    return CPA_STATUS_SUCCESS;
}

void getCtxSize(const CpaCySymSessionSetupData *pSessionSetupData,
                Cpa32U *pSessionCtxSizeInBytes)
{
    /* using lac_session_desc_d1_t */
    if ((pSessionSetupData->cipherSetupData.cipherAlgorithm !=
         CPA_CY_SYM_CIPHER_ARC4) &&
        (pSessionSetupData->cipherSetupData.cipherAlgorithm !=
         CPA_CY_SYM_CIPHER_SNOW3G_UEA2) &&
        (pSessionSetupData->hashSetupData.hashAlgorithm !=
         CPA_CY_SYM_HASH_SNOW3G_UIA2) &&
        (pSessionSetupData->cipherSetupData.cipherAlgorithm !=
         CPA_CY_SYM_CIPHER_AES_CCM) &&
        (pSessionSetupData->cipherSetupData.cipherAlgorithm !=
         CPA_CY_SYM_CIPHER_AES_GCM) &&
        (pSessionSetupData->hashSetupData.hashMode !=
         CPA_CY_SYM_HASH_MODE_AUTH) &&
        (pSessionSetupData->hashSetupData.hashMode !=
         CPA_CY_SYM_HASH_MODE_NESTED) &&
        (pSessionSetupData->partialsNotRequired == CPA_TRUE))
    {
        *pSessionCtxSizeInBytes = LAC_SYM_SESSION_D1_SIZE;
    }
    /* using lac_session_desc_d2_t */
    else if (((pSessionSetupData->cipherSetupData.cipherAlgorithm ==
               CPA_CY_SYM_CIPHER_AES_CCM) ||
              (pSessionSetupData->cipherSetupData.cipherAlgorithm ==
               CPA_CY_SYM_CIPHER_AES_GCM)) &&
             (pSessionSetupData->partialsNotRequired == CPA_TRUE))
    {
        *pSessionCtxSizeInBytes = LAC_SYM_SESSION_D2_SIZE;
    }
    /* using lac_session_desc_t */
    else
    {
        *pSessionCtxSizeInBytes = LAC_SYM_SESSION_SIZE;
    }
}

/**
 ******************************************************************************
 * @ingroup LacSym
 *****************************************************************************/
CpaStatus cpaCyBufferListGetMetaSize(const CpaInstanceHandle instanceHandle_in,
                                     Cpa32U numBuffers,
                                     Cpa32U *pSizeInBytes)
{

#ifdef ICP_PARAM_CHECK
    CpaInstanceHandle instanceHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_SYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_SYM));
    LAC_CHECK_NULL_PARAM(pSizeInBytes);

#endif
    /* In the case of zero buffers we still need to allocate one
     * descriptor to pass to the firmware */
    if (0 == numBuffers)
    {
        numBuffers = 1;
    }

    /* Note: icp_buffer_list_desc_t is 8 bytes in size and
     * icp_flat_buffer_desc_t is 16 bytes in size. Therefore if
     * icp_buffer_list_desc_t is aligned
     * so will each icp_flat_buffer_desc_t structure */

    *pSizeInBytes = sizeof(icp_buffer_list_desc_t) +
                    (sizeof(icp_flat_buffer_desc_t) * numBuffers) +
                    ICP_DESCRIPTOR_ALIGNMENT_BYTES;

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, %d, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             numBuffers,
             (LAC_ARCH_UINT)pSizeInBytes,
             *pSizeInBytes);
#endif

    return CPA_STATUS_SUCCESS;
}
