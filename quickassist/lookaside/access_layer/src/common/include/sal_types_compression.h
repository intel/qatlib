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
 * @file sal_types_compression.h
 *
 * @ingroup SalCtrl
 *
 * Generic compression instance type definition
 *
 ***************************************************************************/
#ifndef SAL_TYPES_COMPRESSION_H_
#define SAL_TYPES_COMPRESSION_H_

#include "cpa_dc.h"
#include "cpa_dc_capabilities.h"
#include "cpa_dc_dp.h"
#include "lac_sal_types.h"
#include "icp_qat_hw.h"
#include "icp_buffer_desc.h"

#include "lac_mem_pools.h"
#include "icp_adf_transport.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym_qat_constants_table.h"
#include "dc_capabilities.h"

#define DC_NUM_RX_RINGS (1)

/**
 *****************************************************************************
 * @ingroup SalCtrl
 *      Chaining specific Service Container
 *
 * @description
 *      Contains information required per chaining service instance.
 *
 *****************************************************************************/
/* Parameters to provide chaining service */
typedef struct sal_dc_chain_service_s
{
    lac_memory_pool_id_t lac_sym_cookie_pool;
    /**< Memory pool ID used for symmetric operations */
    icp_qat_hw_auth_mode_t qatHmacMode;
    /**< Hmac Mode */
    lac_sym_qat_hash_defs_t **pLacHashLookupDefs;
    /**< table of pointers to standard defined information for all hash
     * algorithms. We support an extra hash algo that is not exported by
     * cy API which is why we need the extra +1 */

    lac_sym_qat_constants_t constantsLookupTables;
    /**< constant table of auth and cipher */

    Cpa8U **ppHmacContentDesc;
    /**< table of pointers to content descriptor for Hmac precomputes
     * - used at session init */

    lac_memory_pool_id_t dc_chain_cookie_pool;
    /**< Memory pool ID used for chaining operations */
    lac_memory_pool_id_t dc_chain_serv_resp_pool;
    /**< Memory pool ID used for linked crypto and compression request
     * descriptor */
} sal_dc_chain_service_t;

/**
 *****************************************************************************
 * @ingroup SalCtrl
 *      Compression specific Service Container
 *
 * @description
 *      Contains information required per compression service instance.
 *
 *****************************************************************************/
typedef struct sal_compression_service_s
{
    /* An instance of the Generic Service Container */
    sal_service_t generic_service_info;

    /* Memory pool ID used for compression */
    lac_memory_pool_id_t compression_mem_pool;

    /* Memory pool ID used for decompression */
    lac_memory_pool_id_t decompression_mem_pool;

    /* Pointer to an array of atomic stats for compression */
    OsalAtomic *pCompStatsArr;

    /* Size of the DRAM intermediate buffer in bytes */
    Cpa64U minInterBuffSizeInBytes;

    /* Number of DRAM intermediate buffers */
    Cpa16U numInterBuffs;

    /* Address of the array of DRAM intermediate buffers*/
    icp_qat_addr_width_t *pInterBuffPtrsArray;
    CpaPhysicalAddr pInterBuffPtrsArrayPhyAddr;

    icp_comms_trans_handle trans_handle_compression_tx;
    icp_comms_trans_handle trans_handle_compression_rx;
    icp_comms_trans_handle trans_handle_decompression_tx;
    icp_comms_trans_handle trans_handle_decompression_rx;

    /* Maximum number of in flight requests */
    Cpa32U maxNumCompConcurrentReq;

    /* Callback function defined for the DcDp API compression session */
    CpaDcDpCallbackFn pDcDpCb;

    /* Config info */
    Cpa16U acceleratorNum;
    Cpa16U bankNum;
    Cpa16U bankNumDecomp;
    Cpa16U pkgID;
    Cpa16U isPolled;
    Cpa32U coreAffinity;
    Cpa32U nodeAffinity;

    /* Statistics handler */
    debug_file_info_t *debug_file;

    /* Chaining service */
    sal_dc_chain_service_t *pDcChainService;

    /* Compression service capabilities */
    dc_capabilities_t dc_capabilities;
} sal_compression_service_t;

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *  This function returns a valid compression instance handle for the system
 *  if it exists.
 *
 *  @performance
 *    To avoid calling this function the user of the QA api should not use
 *    instanceHandle = CPA_INSTANCE_HANDLE_SINGLE.
 *
 * @context
 *    This function is called whenever instanceHandle =
 *    CPA_INSTANCE_HANDLE_SINGLE at the QA Dc api.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @retval   Pointer to first compression instance handle or NULL if no
 *           compression instances in the system.
 *
 *************************************************************************/
CpaInstanceHandle dcGetFirstHandle(void);

#endif /*SAL_TYPES_COMPRESSION_H_*/
