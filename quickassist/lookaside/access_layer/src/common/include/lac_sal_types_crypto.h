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
 * @file lac_sal_types_crypto.h
 *
 * @ingroup SalCtrl
 *
 * Generic crypto instance type definition
 *
 ***************************************************************************/

#ifndef LAC_SAL_TYPES_CRYPTO_H_
#define LAC_SAL_TYPES_CRYPTO_H_

#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym_qat_constants_table.h"
#include "lac_sym_key.h"
#include "cpa_cy_sym_dp.h"
#include "cpa_cy_im.h"

#include "icp_adf_debug.h"
#include "lac_sal_types.h"
#include "icp_adf_transport.h"
#include "lac_mem_pools.h"

#define LAC_PKE_FLOW_ID_TAG 0xFFFFFFFC
#define LAC_PKE_ACCEL_ID_BIT_POS 1
#define LAC_PKE_SLICE_ID_BIT_POS 0

/**
 *****************************************************************************
 * @ingroup SalCtrl
 *      Crypto specific Service Container
 *
 * @description
 *      Contains information required per crypto service instance.
 *
 *****************************************************************************/
typedef struct sal_crypto_service_s
{
    sal_service_t generic_service_info;
    /**< An instance of the Generic Service Container */

    lac_memory_pool_id_t lac_sym_cookie_pool;
    /**< Memory pool ID used for symmetric operations */
    lac_memory_pool_id_t lac_ec_pool;
    /**< Memory pool ID used for asymmetric operations */
    lac_memory_pool_id_t lac_prime_pool;
    /**< Memory pool ID used for asymmetric operations */
    lac_memory_pool_id_t lac_pke_req_pool;
    /**< Memory pool ID used for asymmetric operations */
    lac_memory_pool_id_t lac_pke_align_pool;
    /**< Memory pool ID used for asymmetric operations */

    OsalAtomic *pLacSymStatsArr;
    /**< pointer to an array of atomic stats for symmetric */

    OsalAtomic *pLacKeyStats;
    /**< pointer to an array of atomic stats for key */

    OsalAtomic *pLacDhStatsArr;
    /**< pointer to an array of atomic stats for DH */

    OsalAtomic *pLacDsaStatsArr;
    /**< pointer to an array of atomic stats for Dsa */

    OsalAtomic *pLacRsaStatsArr;
    /**< pointer to an array of atomic stats for Rsa */

    OsalAtomic *pLacEcStatsArr;
    /**< pointer to an array of atomic stats for Ecc */

    OsalAtomic *pLacEcdhStatsArr;
    /**< pointer to an array of atomic stats for Ecc DH */

    OsalAtomic *pLacEcdsaStatsArr;
    /**< pointer to an array of atomic stats for Ecc DSA */

    OsalAtomic *pLacEcsm2StatsArr;
    /**< pointer to an array of atomic stats for Ecc SM2 */

    OsalAtomic *pLacPrimeStatsArr;
    /**< pointer to an array of atomic stats for prime */

    OsalAtomic *pLacLnStatsArr;
    /**< pointer to an array of atomic stats for large number */

    OsalAtomic *pLacDrbgStatsArr;
    /**< pointer to an array of atomic stats for DRBG */

    icp_qat_hw_auth_mode_t qatHmacMode;
    /**< Hmac Mode */

    Cpa32U pkeFlowId;
    /**< Flow ID for all pke requests from this instance - identifies
     accelerator and execution engine to use */

    icp_comms_trans_handle trans_handle_sym_tx;
    icp_comms_trans_handle trans_handle_sym_rx;

    icp_comms_trans_handle trans_handle_asym_tx;
    icp_comms_trans_handle trans_handle_asym_rx;

    Cpa32U maxNumSymReqBatch;
    /**< Maximum number of requests that can be placed on the sym tx ring
          for any one batch request (DP api) */

    Cpa16U acceleratorNum;
    Cpa16U bankNumAsym;
    Cpa16U bankNumSym;
    Cpa16U pkgID;
    Cpa8U isPolled;
    Cpa8U executionEngine;
    Cpa32U coreAffinity;
    Cpa32U nodeAffinity;
    /**< Config Info */

    CpaCySymDpCbFunc pSymDpCb;
    /**< Sym DP Callback */

    lac_sym_qat_hash_defs_t **pLacHashLookupDefs;
    /**< table of pointers to standard defined information for all hash
         algorithms. We support an extra hash algo that is not exported by
         cy api which is why we need the extra +1 */

    lac_sym_qat_constants_t constantsLookupTables;

    Cpa8U **ppHmacContentDesc;
    /**< table of pointers to CD for Hmac precomputes - used at session init */

    Cpa8U *pSslLabel;
    /**< pointer to memory holding the standard SSL label ABBCCC.. */

    lac_sym_key_tls_labels_t *pTlsLabel;
    /**< pointer to memory holding the 4 standard TLS labels */

    lac_sym_key_tls_hkdf_sub_labels_t *pTlsHKDFSubLabel;
    /**< pointer to memory holding the 4 HKDFLabels sublabels */

    debug_file_info_t *debug_file;
    /**< Statistics handler */

    CpaCyCapabilitiesInfo capInfo;
    /* Cryptographic Capabilities Info */

} sal_crypto_service_t;

/*************************************************************************
 * @ingroup cpaCyCommon
 * @description
 *  This function returns a valid asym/sym/crypto instance handle for the
 *  system if it exists. When requesting an instance handle of type sym or
 *  asym, if either is not found then a crypto instance handle is returned
 *  if found, since a crypto handle supports both sym and asym services.
 *  Similarly when requesting a crypto instance handle, if it is not found
 *  then an asym or sym crypto instance handle is returned.
 *
 *  @performance
 *    To avoid calling this function the user of the QA api should not use
 *    instanceHandle = CPA_INSTANCE_HANDLE_SINGLE.
 *
 * @context
 *    This function is called whenever instanceHandle =
 *    CPA_INSTANCE_HANDLE_SINGLE at the QA Cy api.
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
 * @param[in]  svc_type        Type of crypto service requested.
 *
 * @retval   Pointer to first crypto instance handle or NULL if no crypto
 *           instances in the system.
 *
 *************************************************************************/

CpaInstanceHandle Lac_GetFirstHandle(sal_service_type_t svc_type);

#endif /*LAC_SAL_TYPES_CRYPTO_H_*/
