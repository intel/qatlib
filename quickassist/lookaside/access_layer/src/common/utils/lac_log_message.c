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
 * @file lac_log_message.c  Utility functions for logging contents of Msgs on
 *                      IA-FW interface
 *
 * @ingroup LacLog
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

#include "cpa.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "icp_adf_cfg.h"
#include "icp_adf_transport.h"
#include "icp_adf_transport_dp.h"
#include "icp_accel_devices.h"
#include "sal_statistics.h"
#include "sal_string_parse.h"
#include "icp_adf_debug.h"
#include "lac_sal_types.h"

/*
*******************************************************************************
* Define public/global function definitions
*******************************************************************************
*/

/**
 *****************************************************************************
 * @ingroup LacLog
 *****************************************************************************/

/*
*******************************************************************************
* Local functions
*******************************************************************************
*/

/**
 *****************************************************************************
 * @ingroup lac_log_message
 *      LacLogMsg_writeToDmesg()
 *
 * @description
 *      Log the message to dmesg
 *
 * @param[in/out]    pBlock
 * @param[in/out]    size_in_lws
 * @param[in/out]    block_type
 *
 * @retval CpaStatus
 *
 *****************************************************************************/

/**
 *****************************************************************************
 * @ingroup lac_log_message
 *      set_osal_log_debug_level()
 *
 * @description
 *
 *
 * @retval None
 *
 *****************************************************************************/
Cpa64U conf_osal_log_level_debug = 0;
void set_osal_log_debug_level(void)
{
    Cpa64U previous_level = 0;

    if (conf_osal_log_level_debug > 0)
    {
        /* enable output from LAC_LOG_DEBUG */
        /* LAC_LOG_LVL_DEBUG1 = 6, DEBUG2=7, DEBUG3=8 */
        osalLogLevelSet(conf_osal_log_level_debug);
    }
    else
    {
        /*don't change the conf level, just print it. */
        previous_level = osalLogLevelSet(0);
        osalLogLevelSet(previous_level);
    }
}

/**
 *****************************************************************************
 * @ingroup lac_log_message
 *      LacLogMsg_SetConfig()
 *
 * @description
 *
 * @param[in/out]    device
 *
 * @retval None
 *
 *****************************************************************************/
void LacLogMsg_SetConfig(icp_accel_dev_t *device)
{

    char paramValue[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, "osal_log_level_debug", paramValue);

    if (status == CPA_STATUS_SUCCESS)
    {
        Cpa64U new_level = 0;

        new_level = Sal_Strtoul(paramValue, NULL, SAL_CFG_BASE_DEC);
        if ((new_level >= 1) && (new_level <= 3))
        {
            /* enable output from LAC_LOG_DEBUG  - filtered out by default*/
            /* LAC_LOG_LVL_DEBUG1 = 6, DEBUG2=7, DEBUG3=8 */
            conf_osal_log_level_debug = new_level + 5;
        }
    }
    set_osal_log_debug_level();
}
