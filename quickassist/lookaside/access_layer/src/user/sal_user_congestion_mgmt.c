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

/*
 *****************************************************************************
 * @file sal_user_congestion_mgmt.c
 *
 * @defgroup SalUserCongsMgmt
 *
 * @description
 *    This file contains Congestion Management API implementations
 *****************************************************************************/

/* QAT-API includes */
#include "cpa.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_adf_transport_dp.h"

/* SAL includes */
#include "icp_sal_congestion_mgmt.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "sal_service_state.h"

CpaStatus icp_sal_SymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                         Cpa32U *maxInflightRequests,
                                         Cpa32U *numInflightRequests)
{
    sal_crypto_service_t *crypto_handle = NULL;

    crypto_handle = (sal_crypto_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(crypto_handle);
    LAC_CHECK_NULL_PARAM(maxInflightRequests);
    LAC_CHECK_NULL_PARAM(numInflightRequests);
    SAL_RUNNING_CHECK(crypto_handle);

    return icp_adf_getInflightRequests(crypto_handle->trans_handle_sym_tx,
                                       maxInflightRequests,
                                       numInflightRequests);
}

CpaStatus icp_sal_AsymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                          Cpa32U *maxInflightRequests,
                                          Cpa32U *numInflightRequests)
{
    sal_crypto_service_t *crypto_handle = NULL;

    crypto_handle = (sal_crypto_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(crypto_handle);
    LAC_CHECK_NULL_PARAM(maxInflightRequests);
    LAC_CHECK_NULL_PARAM(numInflightRequests);
    SAL_RUNNING_CHECK(crypto_handle);

    return icp_adf_getInflightRequests(crypto_handle->trans_handle_asym_tx,
                                       maxInflightRequests,
                                       numInflightRequests);
}

CpaStatus icp_sal_dp_SymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                            Cpa32U *maxInflightRequests,
                                            Cpa32U *numInflightRequests)
{
    sal_crypto_service_t *crypto_handle = NULL;

    crypto_handle = (sal_crypto_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(crypto_handle);
    LAC_CHECK_NULL_PARAM(maxInflightRequests);
    LAC_CHECK_NULL_PARAM(numInflightRequests);
    SAL_RUNNING_CHECK(crypto_handle);

    icp_adf_getDpInflightRequests(crypto_handle->trans_handle_sym_tx,
                                  maxInflightRequests,
                                  numInflightRequests);
    return CPA_STATUS_SUCCESS;
}
