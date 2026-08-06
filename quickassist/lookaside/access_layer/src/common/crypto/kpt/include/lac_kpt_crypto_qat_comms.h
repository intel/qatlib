/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *****************************************************************************
 * @file lac_kpt_crypto_qat_comms.h
 *
 * @ingroup LacKptCryptoQatComms
 *
 * Common definitions that are KPT service specific
 *
 *****************************************************************************/
#ifndef _LAC_KPT_CRYPTO_QAT_COMMS_H_
#define _LAC_KPT_CRYPTO_QAT_COMMS_H_

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/
#include "cpa.h"
#include "cpa_cy_kpt.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
/* SAL includes */
#include "lac_mem_pools.h"

/* Initialization Vector (IV) size of KPT unwrap context */
#define MAX_KPT_IV_LENGTH (16)
/* Total size of KPT unwrap context */
#define LAC_KPT_UNWRAP_CTX_SIZE_IN_BYTES                                       \
    (sizeof(CpaCyKptHandle) + MAX_KPT_IV_LENGTH)

/* Invalid KPT key size */
#define LAC_KPT_PKE_INVALID_KEY_SIZE (0)
/* Columns count of KPT key size mapping table */
#define LAC_KPT_PKE_NUM_COLUMNS (2)

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *       Build a KPT crypto flat buffer which contains KPT unwrap context.
 *
 * @description
 *       This function builds a KPT crypto input flat buffer which contains
 *       Wrapped Private Key (WPK)'s unwrap context, QAT device will parse it
 *       and get the necessary information to unwrapp the WPK to Clear
 *       Private Key (CPK) in device internal memory.
 *
 * @param[in] pMempool             Pointer to a pre-allocated memory pool entry.
 * @param[in] pKptUnwrapContext    Pointer to WPK unwrapping context.
 * @retval NULL
 ***************************************************************************/
void LacKpt_BuildUnwrapCtxMemBuffer(Cpa8U *pMempool,
                                    CpaCyKptUnwrapContext *pKptUnwrapContext);

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *       Get CPK size according to WPK size.
 *
 * @description
 *       Get CPK size according to WPK size.
 *
 * @param[in] sizeInBytes        WPK size.
 * @param[in] pSizeTable         Key size mapping table between WPK and CPK.
 * @param[in] numTableEntries    Entry count of key size mapping table.
 *
 * @retval CPK size
 ***************************************************************************/
Cpa32U LacKpt_GetCpkSize(Cpa32U sizeInBytes,
                         const Cpa32U pSizeTable[][LAC_KPT_PKE_NUM_COLUMNS],
                         Cpa32U numTableEntries);

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *       Allocate a memory pool entry from a specific memory pool.
 *
 * @description
 *       This function applies to a memory pool entry from a pre-allocated
 *       memory pool.
 *
 * @param[in]  poolID        Memory pool id of target memory pool.
 * @param[out] ppMemPool     Pointer to the pointer of allocated memory entry.
 *
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_RESOURCE      Does not have available memory pool entry.
 ***************************************************************************/
CpaStatus LacKpt_MemPoolAlloc(Cpa8U **ppMemPool, lac_memory_pool_id_t poolID);

/**
 ***************************************************************************
 * @ingroup LacKptCryptoQatComms
 *       Free a memory pool entry.
 *
 * @description
 *       This function frees a allocated memory pool entry.
 *
 * @param[in] pMemPool     Pointer to allocated memory entry.
 *
 * @retval NULL
 ***************************************************************************/
void LacKpt_MemPoolFree(Cpa8U *pMemPool);

#endif /* _LAC_KPT_CRYPTO_QAT_COMMS_H_ */
