/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/**
 *****************************************************************************
 * @file icp_sal_dc_err_sim.c
 *
 * @defgroup SalCommon
 *
 * @ingroup SalCommon
 *
 *****************************************************************************/

/*
******************************************************************************
* Include public/global header files
******************************************************************************
*/
#include "cpa.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "dc_error_counter.h"
#ifdef ICP_DC_ERROR_SIMULATION
#include "dc_err_sim.h"
#endif

CpaStatus icp_sal_dc_simulate_error(Cpa8U numErrors, Cpa8S dcError)
{
#ifdef ICP_DC_ERROR_SIMULATION
    return dcSetNumError(numErrors, dcError);
#else
    return CPA_STATUS_UNSUPPORTED;
#endif
}

Cpa64U icp_sal_get_dc_error(Cpa8S dcError)
{
    return getDcErrorCounter(dcError);
}
