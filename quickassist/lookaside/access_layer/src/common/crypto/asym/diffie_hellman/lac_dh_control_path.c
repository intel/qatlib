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
 *****************************************************************************
 * @file lac_dh_control_path.c  Control path functions for diffie hellman.
 *       Implements the API functions and the init and shutdown functions
 *
 * @ingroup LacDh
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_dh.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Osal include */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_sym.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "lac_common.h"
#include "lac_hooks.h"

#include "lac_dh_stats_p.h"

/*
********************************************************************************
* Static Variables
********************************************************************************
*/

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

/**
 *****************************************************************************
 * @ingroup LacDh
 *
 *****************************************************************************/

#ifdef QAT_LEGACY_ALGORITHMS
CpaStatus LacDh_Init(CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Initialise and reset all statistics */
    status = LacDh_StatsInit(instanceHandle);
    /* Call compile time param check function to ensure it is included
       in the build by the compiler */
    LacDh_CompileTimeAssertions();

    return status;
} /* LacDh_Init */
#else
CpaStatus LacDh_Init(CpaInstanceHandle instanceHandle)
{
    LAC_LOG("DH algorithm is not supported\n");
    return CPA_STATUS_UNSUPPORTED;
}
#endif
