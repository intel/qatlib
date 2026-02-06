/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file dc_err_sim.c
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the Data Compression error inject operations.
 *
 *****************************************************************************/

#include "dc_err_sim.h"
#include "lac_log.h"

static Cpa8U num_dc_errors;
static CpaDcReqStatus dc_error;

CpaStatus dcSetNumError(Cpa8U numErrors, CpaDcReqStatus dcError)
{
    if ((dcError < CPA_DC_EMPTY_DYM_BLK) || (dcError >= CPA_DC_OK) ||
        (CPA_DC_INCOMPLETE_FILE_ERR == dcError))
    {
        LAC_LOG_ERROR1("Unsupported ErrorType %d\n", dcError);
        return CPA_STATUS_FAIL;
    }
    num_dc_errors = numErrors;
    dc_error = dcError;

    return CPA_STATUS_SUCCESS;
}

CpaBoolean dcErrorSimEnabled(void)
{
    if (num_dc_errors > 0)
    {
        return CPA_TRUE;
    }
    else
    {
        return CPA_FALSE;
    }
}

CpaDcReqStatus dcGetErrors(void)
{
    CpaDcReqStatus error = 0;

    if (DC_ERROR_SIM == num_dc_errors)
    {
        error = dc_error;
    }
    else if (num_dc_errors > 0 && num_dc_errors <= DC_ERROR_SIM_MAX)
    {
        num_dc_errors--;
        error = dc_error;
    }
    else
    {
        error = 0;
    }
    return error;
}
