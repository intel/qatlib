/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
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
        previous_level = osalLogLevelSet(conf_osal_log_level_debug);
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
