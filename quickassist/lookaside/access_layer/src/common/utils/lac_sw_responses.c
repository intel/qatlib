/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 ***************************************************************************
 * @file lac_sw_responses.c
 *
 * @ingroup LacSwResponses
 *
 * Calculation of memory pools which contain in-flight requests function
 * implementations. The memory pools which contain in-flight requests will
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
#include "lac_session.h"
#include "lac_sym_cb.h"
#include "Osal.h"

#ifndef ICP_DC_ONLY
#include "lac_pke_qat_comms.h"
#endif

#include "dc_datapath.h"

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
 * This function frees the bucket with memblks containing in-flight requests.
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

STATIC
CpaStatus LacSwResp_GenRespMsgCallback(lac_memblk_bucket_t *pBucket,
                                       sal_service_type_t type)
{
    CpaStatus status = CPA_STATUS_RETRY;

    switch (type)
    {
        case SAL_SERVICE_TYPE_COMPRESSION:
        case SAL_SERVICE_TYPE_DECOMPRESSION:
            status = dcCompression_SwRespMsgCallback(pBucket);
            break;
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
            status = LacSym_SwRespMsgCallback(pBucket);
            break;
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
            status = LacPke_SwRespMsgCallback(pBucket);
            break;
        default:
            break;
    }

    return status;
}

CpaStatus LacSwResp_GenResp(lac_memory_pool_id_t lac_mem_pool,
                            sal_service_type_t type)
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

        status = LacSwResp_GenRespMsgCallback(pBucket, type);
        if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_RETRY != status))
        {
            LAC_LOG_ERROR("Failed to generate dummy responses!");
        }
        LacSwResp_MemBlkBucketDestroy(pBucket);
    }
    return status;
}
#endif
#endif
