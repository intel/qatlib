/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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

/*
 *****************************************************************************
 * @ingroup SalCongsMgmt
 *      Symmetric get in-flight requests
 *
 * @description
 *      This function is used to fetch in-flight and max in-flight request
 *      counts for the given symmetric instance handle.
 *
 * @param[in]  instanceHandle         Symmetric instance handle
 * @param[out] maxInflightRequests    Max in-flight request count
 * @param[out] numInflightRequests    Current in-flight request count
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
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

/*
 *****************************************************************************
 * @ingroup SalCongsMgmt
 *      Symmetric data plane get in-flight requests
 *
 * @description
 *      Data plane API to fetch in-flight and max in-flight request counts
 *      for the given symmetric instance handle.
 *
 * @param[in]  instanceHandle         Symmetric instance handle
 * @param[out] maxInflightRequests    Max in-flight request count
 * @param[out] numInflightRequests    Current in-flight request count
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
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
