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
 * @file sal_user_process.c
 *
 * @ingroup SalUserProcess
 *
 * @description
 *    This file contains implementation of functions to set/get user process
 *    name
 *
 *****************************************************************************/

#include "lac_common.h"
#include "icp_adf_user_proxy.h"
static char lacProcessName[LAC_USER_PROCESS_NAME_MAX_LEN] =
    LAC_KERNEL_PROCESS_NAME;

/**< Process name used to obtain values from correct section of config file. */

/*
 * @ingroup LacCommon
 * @description
 *      This function sets the process name
 *
 * @context
 *      This functions is called from module_init or from user space process
 *      initialisation function
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 * param[in]  processName    Process name to be set
 */
CpaStatus icpSetProcessName(const char *processName)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(processName);

    if (strnlen(processName, LAC_USER_PROCESS_NAME_MAX_LEN) ==
        LAC_USER_PROCESS_NAME_MAX_LEN)
    {
        LAC_LOG_ERROR1("Process name too long, maximum process name is %d",
                       LAC_USER_PROCESS_NAME_MAX_LEN - 1);
        return CPA_STATUS_FAIL;
    }
#endif

    snprintf(lacProcessName, LAC_USER_PROCESS_NAME_MAX_LEN, "%s", processName);
    return CPA_STATUS_SUCCESS;
}

/*
 * @ingroup LacCommon
 * @description
 *      This function gets the process name
 *
 * @context
 *      This functions is called from LAC context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 */
char *icpGetProcessName(void)
{
    return lacProcessName;
}
