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
 ***************************************************************************
 * @file icp_sal_congestion_mgmt.h
 *
 * @ingroup SalUserCongsMgmt
 *
 * This file contains function prototypes for Congestion Management APIs.
 *
 ***************************************************************************/

#ifndef ICP_SAL_CONGESTION_MGMT_H
#define ICP_SAL_CONGESTION_MGMT_H

#include "icp_sal.h"

/*
 *****************************************************************************
 * @ingroup SalUserCongsMgmt
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
                                         Cpa32U *numInflightRequests);

/*
 *****************************************************************************
 * @ingroup SalUserCongsMgmt
 *      Asymmetric get in-flight requests
 *
 * @description
 *      This function is used to fetch in-flight and max in-flight request
 *      counts for the given asymmetric instance handle.
 *
 * @param[in]  instanceHandle         Asymmetric instance handle
 * @param[out] maxInflightRequests    Max in-flight request count
 * @param[out] numInflightRequests    Current in-flight request count
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
CpaStatus icp_sal_AsymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                          Cpa32U *maxInflightRequests,
                                          Cpa32U *numInflightRequests);

/*
 *****************************************************************************
 * @ingroup SalUserCongsMgmt
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
                                            Cpa32U *numInflightRequests);

#endif
