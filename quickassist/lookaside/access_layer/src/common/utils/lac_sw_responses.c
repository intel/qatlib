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
 * @file lac_sw_responses.c
 *
 * @ingroup LacSwResponses
 *
 * Calculation of memory pools which contain infilght requests function
 * implementations. The memory pools which contain inflight requests will
 * be named as busy memory pools.
 *
 ***************************************************************************/
#include "cpa.h"
#include "icp_accel_devices.h"
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "lac_lock_free_stack.h"
#include "lac_mem_pools.h"
#include "lac_mem.h"
#include "lac_common.h"
#include "Osal.h"

#ifndef ICP_DC_ONLY
#include "lac_pke_qat_comms.h"
#endif

#ifdef KERNEL_SPACE
#define ASYM_NOT_SUPPORTED
#endif

static OsalAtomic lac_sw_resp_num_pools_busy = ATOMIC_INIT(0);
/**< @ingroup LacSwResponses
 * Number of busy memory pools
 */

void LacSwResp_IncNumPoolsBusy(lac_memory_pool_id_t poolID)
{
    lac_mem_pool_hdr_t *pPoolID = (lac_mem_pool_hdr_t *)poolID;
    if (pPoolID->availBlks != pPoolID->numElementsInPool)
    {
        osalAtomicInc(&lac_sw_resp_num_pools_busy);
    }
    return;
}

Cpa16U LacSwResp_GetNumPoolsBusy(void)
{
    return (Cpa16U)osalAtomicGet(&lac_sw_resp_num_pools_busy);
}

void LacSwResp_InitNumPoolsBusy(void)
{
    osalAtomicSet(0, &lac_sw_resp_num_pools_busy);
}

#ifndef ICP_DC_ONLY
#ifndef ASYM_NOT_SUPPORTED
/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * This function creates a bucket with in-order memblks.
 ******************************************************************************/
STATIC
lac_memblk_bucket_t *LacSwResp_MemBlkBucketCreate(lac_mem_pool_hdr_t *pPoolID)
{
    lac_mem_blk_t *pCurrentBlk = NULL;
    lac_mem_blk_t **pBucketBlk = NULL;
    lac_memblk_bucket_t *pBucket = NULL;
    Cpa32U i = 0;
    Cpa64U opaque = 0;
    Cpa32U numBlksUsed = 0;
    Cpa64U seq = ICP_ADF_INVALID_SEND_SEQ;

    numBlksUsed = pPoolID->numElementsInPool - pPoolID->availBlks;

    if (0 == numBlksUsed)
    {
        return NULL;
    }

    pBucket = osalMemAlloc(sizeof(lac_memblk_bucket_t));
    if (!pBucket)
    {
        LAC_LOG_ERROR("Failed to allocate memory for pBucket.");
        return NULL;
    }
    osalMemSet(pBucket, 0, sizeof(lac_memblk_bucket_t));

    pBucket->mem_blk =
        (lac_mem_blk_t **)osalMemAlloc(sizeof(lac_mem_blk_t *) * numBlksUsed);

    if (!pBucket->mem_blk)
    {
        osalMemFree(pBucket);
        LAC_LOG_ERROR("Failed to allocate memory for mem_blk.");
        return NULL;
    }
    pBucket->numBucketBlks = numBlksUsed;
    pBucket->numBlksInRing = 0;
    pBucketBlk = pBucket->mem_blk;
    osalMemSet(pBucketBlk, 0, sizeof(lac_mem_blk_t *) * numBlksUsed);

    while (i < pPoolID->numElementsInPool)
    {
        pCurrentBlk = pPoolID->trackBlks[i++];
        if (CPA_TRUE != pCurrentBlk->isInUse)
        {
            continue;
        }
        opaque = pCurrentBlk->opaque;
        if (ICP_ADF_INVALID_SEND_SEQ == opaque)
        {
            pCurrentBlk->isInUse = CPA_FALSE;
            push(&pCurrentBlk->pPoolID->stack, pCurrentBlk);
            __sync_add_and_fetch(&pCurrentBlk->pPoolID->availBlks, 1);
            continue;
        }
        pBucket->numBlksInRing++;
        pBucketBlk[opaque % numBlksUsed] = pCurrentBlk;
        if (opaque < seq)
        {
            seq = opaque;
            pBucket->startIndex = opaque % numBlksUsed;
        }
    }
    return pBucket;
}

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * This function frees the bucket with memblks containing inflight requests.
 ******************************************************************************/
STATIC
void LacSwResp_MemBlkBucketDestroy(lac_memblk_bucket_t *pBucket)
{
    if (NULL == pBucket)
    {
        return;
    }

    if (NULL != pBucket->mem_blk)
    {
        osalMemFree(pBucket->mem_blk);
    }

    osalMemFree(pBucket);

    return;
}

CpaStatus LacSwResp_Asym_CallbackWake(lac_memory_pool_id_t lac_mem_pool)
{
    CpaStatus status = CPA_STATUS_RETRY;
    lac_mem_pool_hdr_t *pPoolID = (lac_mem_pool_hdr_t *)lac_mem_pool;
    lac_memblk_bucket_t *pBucket;

    if (NULL == pPoolID || CPA_TRUE == pPoolID->active)
    {
        LAC_LOG_ERROR("Invalid pPoolID or active status!");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (Lac_MemPoolTestAndGet(lac_mem_pool))
    {
        if (pPoolID->numElementsInPool < pPoolID->availBlks)
        {
            LAC_LOG_ERROR("Invalid availBlks!");
            return CPA_STATUS_FATAL;
        }

        if (pPoolID->numElementsInPool == pPoolID->availBlks)
        {
            return CPA_STATUS_RETRY;
        }

        if (NULL == pPoolID->trackBlks)
        {
            LAC_LOG_ERROR("Invalid trackBlks!");
            return CPA_STATUS_FAIL;
        }

        pBucket = LacSwResp_MemBlkBucketCreate(pPoolID);
        if (NULL == pBucket)
        {
            LAC_LOG_ERROR("Failed to create pBucket!");
            return CPA_STATUS_RESOURCE;
        }
        status = LacPke_SwRespMsgCallback(pBucket);
        if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
        {
            LAC_LOG_ERROR("Failed to generate PKE dummy responses!");
        }
        LacSwResp_MemBlkBucketDestroy(pBucket);
    }
    return status;
}
#endif
#endif
