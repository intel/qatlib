/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *****************************************************************************
 *
 * @file lac_kpt_crypto_qat_comms.c
 *
 * @ingroup LacKptCryptoQatComms
 *
 * This file implements the common functions used in KPT crypto services.
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/
#include "cpa.h"

/*
****************************************************************************
* Include private header files
****************************************************************************
*/
/* SAL includes */
#include "lac_common.h"
#include "lac_kpt_crypto_qat_comms.h"

/* KPT WPK size array index */
#define LAC_KPT_PKE_WPK_SIZE_COLUMN (0)
/* KPT CPK size array index */
#define LAC_KPT_PKE_CPK_SIZE_COLUMN (1)

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *      Build a KPT unwrap context memory buffer which will be accessed by QAT
 *      device, the total size is 24 bytes and the layout is:
 *      ------------------------------------------------
 *      |KeyHandle(8B)|           IV(16B)              |
 *      ------------------------------------------------
 ***************************************************************************/
void LacKpt_BuildUnwrapCtxMemBuffer(Cpa8U *pMemPool,
                                    CpaCyKptUnwrapContext *pKptUnwrapContext)
{
    if (!pMemPool || !pKptUnwrapContext)
        return;

    osalMemSet(pMemPool, 0, LAC_KPT_UNWRAP_CTX_SIZE_IN_BYTES);
    /* The first part is kptHandle */
    *((CpaCyKptHandle *)pMemPool) = pKptUnwrapContext->kptHandle;
    /* The rest part is IV */
    osalMemCopy(pMemPool + sizeof(CpaCyKptHandle),
                pKptUnwrapContext->iv,
                CPA_CY_KPT_MAX_IV_LENGTH);
}

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *      Get CPK size according to WPK size.
 ***************************************************************************/
Cpa32U LacKpt_GetCpkSize(Cpa32U sizeInBytes,
                         const Cpa32U pSizeTable[][LAC_KPT_PKE_NUM_COLUMNS],
                         Cpa32U numTableEntries)
{
    Cpa32U size = LAC_KPT_PKE_INVALID_KEY_SIZE;
    Cpa32U sizeIndex = 0;

    for (sizeIndex = 0; sizeIndex < numTableEntries; sizeIndex++)
    {
        if (pSizeTable[sizeIndex][LAC_KPT_PKE_WPK_SIZE_COLUMN] == sizeInBytes)
        {
            size = pSizeTable[sizeIndex][LAC_KPT_PKE_CPK_SIZE_COLUMN];
            break;
        }
    }

    return size;
}

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *      Allocate one entry from KPT memory pool to store KPT unwrap context.
 ***************************************************************************/
CpaStatus LacKpt_MemPoolAlloc(Cpa8U **ppMemPool, lac_memory_pool_id_t poolId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pMemPool = NULL;

    do
    {
        pMemPool = (Cpa8U *)Lac_MemPoolEntryAlloc(poolId);
        if (NULL == pMemPool)
        {
            LAC_LOG_ERROR("Cannot get KPT unwrap ctx mem pool entry");
            status = CPA_STATUS_RESOURCE;
        }
        else if ((void *)CPA_STATUS_RETRY == pMemPool)
        {
            osalYield();
        }
    } while ((void *)CPA_STATUS_RETRY == pMemPool);
    *ppMemPool = pMemPool;

    return status;
}

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *     Free a KPT unwrap ctx memory pool.
 ***************************************************************************/
void LacKpt_MemPoolFree(Cpa8U *pMemPool)
{
    if (pMemPool)
    {
        Lac_MemPoolEntryFree(pMemPool);
    }
}
