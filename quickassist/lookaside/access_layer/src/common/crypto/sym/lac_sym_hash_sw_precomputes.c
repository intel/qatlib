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
 * @file lac_sym_hash_sw_precomputes.c
 *
 * @ingroup LacHashDefs
 *
 * Hash Software
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
#include "lac_sym_hash_defs.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_session.h"
#include "lac_sym_hash_precomputes.h"

STATIC
CpaStatus LacSymHash_Compute(CpaCySymHashAlgorithm hashAlgorithm,
                             lac_sym_qat_hash_alg_info_t *pHashAlgInfo,
                             Cpa8U *in,
                             Cpa8U *out)
{
    /*
     * Call specific osal implementation.
     * Note: from SHA hashes appropriate endian swapping is required.
     * For sha1, sha224 and sha256 double words based swapping.
     * For sha384 and sha512 quad words swapping.
     * No endianes swapping for md5 is required.
     */
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;
    switch (hashAlgorithm)
    {
        case CPA_CY_SYM_HASH_MD5:
            if (OSAL_SUCCESS != osalHashMD5(in, out))
            {
                LAC_LOG_ERROR("osalHashMD5 Failed\n");
                return status;
            }
            status = CPA_STATUS_SUCCESS;
            break;
        case CPA_CY_SYM_HASH_SHA1:
            if (OSAL_SUCCESS != osalHashSHA1(in, out))
            {
                LAC_LOG_ERROR("osalHashSHA1 Failed\n");
                return status;
            }
            for (i = 0; i < LAC_BYTES_TO_LONGWORDS(pHashAlgInfo->stateSize);
                 i++)
            {
                ((Cpa32U *)(out))[i] = LAC_MEM_WR_32(((Cpa32U *)(out))[i]);
            }
            status = CPA_STATUS_SUCCESS;
            break;
        case CPA_CY_SYM_HASH_SHA224:
            if (OSAL_SUCCESS != osalHashSHA224(in, out))
            {
                LAC_LOG_ERROR("osalHashSHA224 Failed\n");
                return status;
            }
            for (i = 0; i < LAC_BYTES_TO_LONGWORDS(pHashAlgInfo->stateSize);
                 i++)
            {
                ((Cpa32U *)(out))[i] = LAC_MEM_WR_32(((Cpa32U *)(out))[i]);
            }
            status = CPA_STATUS_SUCCESS;
            break;
        case CPA_CY_SYM_HASH_SHA256:
            if (OSAL_SUCCESS != osalHashSHA256(in, out))
            {
                LAC_LOG_ERROR("osalHashSHA256 Failed\n");
                return status;
            }
            for (i = 0; i < LAC_BYTES_TO_LONGWORDS(pHashAlgInfo->stateSize);
                 i++)
            {
                ((Cpa32U *)(out))[i] = LAC_MEM_WR_32(((Cpa32U *)(out))[i]);
            }
            status = CPA_STATUS_SUCCESS;
            break;
        case CPA_CY_SYM_HASH_SHA384:
            if (OSAL_SUCCESS != osalHashSHA384(in, out))
            {
                LAC_LOG_ERROR("osalHashSHA384 Failed\n");
                return status;
            }
            for (i = 0; i < LAC_BYTES_TO_QUADWORDS(pHashAlgInfo->stateSize);
                 i++)
            {
                ((Cpa64U *)(out))[i] = LAC_MEM_WR_64(((Cpa64U *)(out))[i]);
            }
            status = CPA_STATUS_SUCCESS;
            break;
        case CPA_CY_SYM_HASH_SHA512:
            if (OSAL_SUCCESS != osalHashSHA512(in, out))
            {
                LAC_LOG_ERROR("osalHashSHA512 Failed\n");
                return status;
            }
            for (i = 0; i < LAC_BYTES_TO_QUADWORDS(pHashAlgInfo->stateSize);
                 i++)
            {
                ((Cpa64U *)(out))[i] = LAC_MEM_WR_64(((Cpa64U *)(out))[i]);
            }
            status = CPA_STATUS_SUCCESS;
            break;
        default:
            return CPA_STATUS_INVALID_PARAM;
    }
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
    Cpa8U *pIpadData = NULL;
    Cpa8U *pOpadData = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sym_hash_precomp_op_data_t *pHmacIpadOpData =
        (lac_sym_hash_precomp_op_data_t *)pWorkingMemory;
    lac_sym_hash_precomp_op_data_t *pHmacOpadOpData = pHmacIpadOpData + 1;

    /* Convenience pointers */
    lac_sym_hash_hmac_precomp_qat_t *pHmacIpadQatData =
        &pHmacIpadOpData->u.hmacQatData;
    lac_sym_hash_hmac_precomp_qat_t *pHmacOpadQatData =
        &pHmacOpadOpData->u.hmacQatData;

    lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;
    Cpa32U i = 0;
    Cpa32U padLenBytes = 0;

    LacSymQat_HashAlgLookupGet(instanceHandle, hashAlgorithm, &pHashAlgInfo);
    pHmacIpadOpData->stateSize = pHashAlgInfo->stateSize;
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
    for (i = 0; i < pHashAlgInfo->blockLength; i++)
    {
        Cpa8U *ipad = pHmacIpadQatData->data + i;
        Cpa8U *opad = pHmacOpadQatData->data + i;

        *ipad ^= LAC_HASH_IPAD_BYTE;
        *opad ^= LAC_HASH_OPAD_BYTE;
    }
    pIpadData = (Cpa8U *)pHmacIpadQatData->data;
    pOpadData = (Cpa8U *)pHmacOpadQatData->data;

    status = LacSymHash_Compute(
        hashAlgorithm, pHashAlgInfo, (Cpa8U *)pIpadData, pState1);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacSymHash_Compute(
            hashAlgorithm, pHashAlgInfo, (Cpa8U *)pOpadData, pState2);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        callbackFn(pCallbackTag);
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
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U stateSize = 0, x = 0;
    lac_sym_qat_hash_alg_info_t *pHashAlgInfo = NULL;

    if (CPA_CY_SYM_HASH_AES_XCBC == hashAlgorithm)
    {
        Cpa8U *in = pWorkingMemory;
        Cpa8U *out = pState;
        LacSymQat_HashAlgLookupGet(
            instanceHandle, hashAlgorithm, &pHashAlgInfo);
        stateSize = pHashAlgInfo->stateSize;
        memcpy(pWorkingMemory, pHashAlgInfo->initState, stateSize);

        for (x = 0; x < LAC_HASH_XCBC_PRECOMP_KEY_NUM; x++)
        {
            if (OSAL_SUCCESS !=
                osalAESEncrypt(pAuthKey, authKeyLenInBytes, in, out))
            {
                return status;
            }
            in += LAC_HASH_XCBC_MAC_BLOCK_SIZE;
            out += LAC_HASH_XCBC_MAC_BLOCK_SIZE;
        }
        status = CPA_STATUS_SUCCESS;
    }
    else if (CPA_CY_SYM_HASH_AES_CMAC == hashAlgorithm)
    {
        Cpa8U *out = pState;
        Cpa8U k1[LAC_HASH_CMAC_BLOCK_SIZE], k2[LAC_HASH_CMAC_BLOCK_SIZE];
        Cpa8U *ptr = NULL;
        size_t i = 0;
        stateSize = LAC_HASH_CMAC_BLOCK_SIZE;
        LacSymQat_HashAlgLookupGet(
            instanceHandle, hashAlgorithm, &pHashAlgInfo);
        /* Original state size includes K, K1 and K2 which are of equal length.
         * For precompute state size is only of the length of K which is equal
         * to the block size for CPA_CY_SYM_HASH_AES_CMAC.
         * The algorithm is described in rfc4493
         * K is just copeid, K1 and K2 need to be single inplace encrypt
         * with AES.
         * */
        memcpy(out, pHashAlgInfo->initState, stateSize);
        memcpy(out, pAuthKey, authKeyLenInBytes);
        out += LAC_HASH_CMAC_BLOCK_SIZE;

        for (x = 0; x < LAC_HASH_XCBC_PRECOMP_KEY_NUM - 1; x++)
        {
            if (OSAL_SUCCESS !=
                osalAESEncrypt(pAuthKey, authKeyLenInBytes, out, out))
            {
                return status;
            }
            out += LAC_HASH_CMAC_BLOCK_SIZE;
        }

        ptr = pState + LAC_HASH_CMAC_BLOCK_SIZE;

        /* Derived keys (k1 and k2), copy them to pPrecompOpData->pState,
         * but remember that at the beginning is original key (K0)
         */
        /* Calculating K1 */
        for (i = 0; i < LAC_HASH_CMAC_BLOCK_SIZE; i++, ptr++)
        {
            k1[i] = (*ptr) << 1;
            if (i != 0)
            {
                k1[i - 1] |= (*ptr) >> (LAC_NUM_BITS_IN_BYTE - 1);
            }
            if (i + 1 == LAC_HASH_CMAC_BLOCK_SIZE)
            {
                /* If msb of pState + LAC_HASH_CMAC_BLOCK_SIZE is set xor
                   with RB. Because only the final byte of RB is non-zero
                   this is all we need to xor */
                if ((*(pState + LAC_HASH_CMAC_BLOCK_SIZE)) &
                    LAC_SYM_HASH_MSBIT_MASK)
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
        ptr = pState + LAC_HASH_CMAC_BLOCK_SIZE;
        memcpy(ptr, k1, LAC_HASH_CMAC_BLOCK_SIZE);
        ptr += LAC_HASH_CMAC_BLOCK_SIZE;
        memcpy(ptr, k2, LAC_HASH_CMAC_BLOCK_SIZE);
        status = CPA_STATUS_SUCCESS;
    }
    else if (CPA_CY_SYM_HASH_AES_GCM == hashAlgorithm ||
             CPA_CY_SYM_HASH_AES_GMAC == hashAlgorithm)
    {
        Cpa8U *in = pWorkingMemory;
        Cpa8U *out = pState;
        LAC_OS_BZERO(pWorkingMemory, ICP_QAT_HW_GALOIS_H_SZ);

        if (OSAL_SUCCESS !=
            osalAESEncrypt(pAuthKey, authKeyLenInBytes, in, out))
        {
            return status;
        }
        status = CPA_STATUS_SUCCESS;
    }
    else
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    callbackFn(pCallbackTag);
    return status;
}

CpaStatus LacSymHash_HmacPrecompInit(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    return status;
}

void LacSymHash_HmacPrecompShutdown(CpaInstanceHandle instanceHandle)
{
    return;
}
