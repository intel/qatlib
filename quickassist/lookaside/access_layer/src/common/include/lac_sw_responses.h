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
 * @file lac_sw_responses.h
 *
 * @defgroup LacSwResponses     Management for software responses
 *
 * @ingroup LacCommon
 *
 * Busy memory pools calculation functions and dummy responses generation
 * functions.
 *
 * @lld_start
 * @lld_overview
 *     This component is designed as a set of utility functions for the
 * generation of dummy responses and calculation of memory pools which contain
 * in-flight requests. If the memory pools contain in-flight requests, they
 * will be named as busy memory pools.
 * @lld_dependencies
 *     These utilities rely on OSAL for locking mechanisms and memory
 * allocation. It also depends on the implementation of the memory pool.
 * @lld_initialization
 *     The initialization of the number of busy memory pools should be done
 * prior to the increment.
 *
 * @lld_process_context
 * @lld_end
 ***************************************************************************/

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 *
 *
 ******************************************************************************/

/***************************************************************************/

#ifndef LAC_SW_RESPONSES_H
#define LAC_SW_RESPONSES_H

#include "lac_mem_pools.h"
#include "lac_sal_types.h"

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * @description
 * This function increases the number of busy memory pools if the poolID's
 * memory pool is not full.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 ******************************************************************************/
void LacSwResp_IncNumPoolsBusy(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * @description
 * This function initializes the number of busy memory pools to zero. This
 * function should be called prior to the calculation of busy memory pools.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 ******************************************************************************/
void LacSwResp_InitNumPoolsBusy(void);

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * @description
 * This function is used to get the number of busy memory pools.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 ******************************************************************************/
Cpa16U LacSwResp_GetNumPoolsBusy(void);

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * This function searches the DC /PKE request memory pool to find all inflight
 * requests and extracts the callback function from request data which will be
 * called to generate dummy responses.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] lac_mem_pool           The ID of the specific pool
 * @param[in] type                   SAL_SERVICE Type
 *
 *
 * @retval CPA_STATUS_FAIL           The function failed to retrieve all the
 *                                   in-flight requests in the memory pool.
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_FATAL          A serious error has occurred.
 * @retval CPA_STATUS_RETRY          function retried to generate response.
 *
 ******************************************************************************/
CpaStatus LacSwResp_GenResp(lac_memory_pool_id_t lac_mem_pool,
                            sal_service_type_t type);
#endif /* LAC_SW_RESPONSES_H */
