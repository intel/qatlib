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
 * @file icp_sal.h
 *
 * @ingroup SalCommon
 *
 * Functions for both user space and kernel space.
 *
 ***************************************************************************/

#ifndef ICP_SAL_H
#define ICP_SAL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * icp_sal_dc_simulate_error
 *
 * @description:
 *  This function injects a simulated compression error for a defined
 *  number of compression requests
 *
 * @context
 *      This function is called from the user process context
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 * @param[in] numErrors              Num DC Errors
 *                                   0 - No Error injection
 *                                   1-0xFE - Num Errors to Inject
 *                                   0xFF - Always inject Error
 * @param[in] dcError                DC Error Type
 * @retval CPA_STATUS_SUCCESS        No error
 * @retval CPA_STATUS_FAIL           Operation failed
 */
CpaStatus icp_sal_dc_simulate_error(Cpa8U numErrors, Cpa8S dcError);

/*
 * icp_sal_get_dc_error
 *
 * @description:
 *  This function returns the occurrences of compression errors specified
 *  in the input parameter
 *
 * @context
 *      This function is called from the user process context
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] dcError                DC Error Type
 *
 * returns                           Number of failing requests of type dcError
 */
Cpa64U icp_sal_get_dc_error(Cpa8S dcError);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif
