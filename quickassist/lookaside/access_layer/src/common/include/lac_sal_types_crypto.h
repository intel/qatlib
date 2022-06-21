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
