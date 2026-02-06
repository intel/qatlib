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
 * @file dc_err_sim.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression Error Simulation parameters.
 *
 *****************************************************************************/
#ifndef DC_ERROR_SIM_H
#define DC_ERROR_SIM_H

#include "cpa_types.h"
#include "cpa_dc.h"

#define DC_ERROR_SIM 0xFF
#define DC_ERROR_SIM_MAX 0xFE

CpaDcReqStatus dcGetErrors(void);
CpaStatus dcSetNumError(Cpa8U numErrors, CpaDcReqStatus dcError);
CpaBoolean dcErrorSimEnabled(void);

#endif /* DC_ERROR_SIM_H */
