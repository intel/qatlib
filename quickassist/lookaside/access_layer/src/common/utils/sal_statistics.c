/***************************************************************************
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
 ***************************************************************************/

/**
 *****************************************************************************
 * @file sal_statistics.c
 *
 * @defgroup SalStats  Sal Statistics
 *
 * @ingroup SalStats
 *
 * @description
 *    This file contains implementation of statistic related functions
 *
 *****************************************************************************/

#include "cpa.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "icp_adf_cfg.h"
#include "icp_accel_devices.h"
#include "sal_statistics.h"

#include "icp_adf_debug.h"
#include "lac_sal_types.h"
#include "lac_sal.h"

/**
 ******************************************************************************
 * @ingroup SalStats
 *      Reads from the config file if the given statistic is enabled
 *
 * @description
 *      Reads from the config file if the given statistic is enabled
 *
 * @param[in]  device           Pointer to an acceleration device structure
 * @param[in]  statsName        Name of the config value to read the value from
 * @param[out] pIsEnabled       Pointer to a variable where information if the
 *                              given stat is enabled or disabled will be stored
 *
 * @retval  CPA_STATUS_SUCCESS          Operation successful
 * @retval  CPA_STATUS_INVALID_PARAM    Invalid param provided
 * @retval  CPA_STATUS_FAIL             Operation failed
 *
 ******************************************************************************/
STATIC
CpaStatus SalStatistics_GetStatEnabled(icp_accel_dev_t *device,
                                       const char *statsName,
                                       CpaBoolean *pIsEnabled)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char param_value[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pIsEnabled);
    LAC_CHECK_NULL_PARAM(statsName);
#endif

    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, statsName, param_value);

    if (CPA_STATUS_SUCCESS != status)
    {
        if (!strncmp(statsName, SAL_STATS_CFG_MISC, sizeof(SAL_STATS_CFG_MISC)))
        {
            *pIsEnabled = CPA_FALSE;
            return CPA_STATUS_SUCCESS;
        }
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              statsName);
        return status;
    }

    if (0 == strncmp(param_value,
                     SAL_STATISTICS_STRING_OFF,
                     sizeof(SAL_STATISTICS_STRING_OFF)))
    {
        *pIsEnabled = CPA_FALSE;
    }
    else
    {
        *pIsEnabled = CPA_TRUE;
    }

    return status;
}

/* @ingroup SalStats */
CpaStatus SalStatistics_InitStatisticsCollection(icp_accel_dev_t *device)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_statistics_collection_t *pStatsCollection = NULL;
    Cpa32U enabled_services = 0;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(device);
#endif

    status =
        LAC_OS_MALLOC(&pStatsCollection, sizeof(sal_statistics_collection_t));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to allocate memory for statistic.\n");
        return status;
    }
    LAC_OS_BZERO(pStatsCollection, sizeof(sal_statistics_collection_t));
    device->pQatStats = pStatsCollection;

    status = SalStatistics_GetStatEnabled(
        device, SAL_STATS_CFG_ENABLED, &pStatsCollection->bStatsEnabled);
    LAC_CHECK_STATUS(status);

    pStatsCollection->bDcStatsEnabled = CPA_FALSE;
    pStatsCollection->bDhStatsEnabled = CPA_FALSE;
    pStatsCollection->bDsaStatsEnabled = CPA_FALSE;
    pStatsCollection->bEccStatsEnabled = CPA_FALSE;
    pStatsCollection->bKeyGenStatsEnabled = CPA_FALSE;
    pStatsCollection->bLnStatsEnabled = CPA_FALSE;
    pStatsCollection->bPrimeStatsEnabled = CPA_FALSE;
    pStatsCollection->bRsaStatsEnabled = CPA_FALSE;
    pStatsCollection->bSymStatsEnabled = CPA_FALSE;
    pStatsCollection->bMiscStatsEnabled = CPA_FALSE;

    if (CPA_FALSE == pStatsCollection->bStatsEnabled)
        return status;

    /* What services are enabled */
    status = SalCtrl_GetEnabledServices(device, &enabled_services);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to get enabled services\n");
        return CPA_STATUS_FAIL;
    }

    /* Check if the compression service is enabled */
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
        pStatsCollection->bDcStatsEnabled = CPA_TRUE;

    /* Check if the asym service is enabled */
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM) ||
        SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        pStatsCollection->bDhStatsEnabled = CPA_TRUE;
        pStatsCollection->bDsaStatsEnabled = CPA_TRUE;
        pStatsCollection->bEccStatsEnabled = CPA_TRUE;
        pStatsCollection->bKeyGenStatsEnabled = CPA_TRUE;
        pStatsCollection->bLnStatsEnabled = CPA_TRUE;
        pStatsCollection->bPrimeStatsEnabled = CPA_TRUE;
        pStatsCollection->bRsaStatsEnabled = CPA_TRUE;
    }

    /* Check if the sym service is enabled */
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_SYM) ||
        SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
        pStatsCollection->bSymStatsEnabled = CPA_TRUE;

    /*Check if any of the service is enabled*/
    if (SalCtrl_IsServiceEnabled(
            enabled_services,
            SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_CRYPTO |
                SAL_SERVICE_TYPE_CRYPTO_SYM | SAL_SERVICE_TYPE_CRYPTO_ASYM))
        pStatsCollection->bMiscStatsEnabled = CPA_TRUE;

    return status;
}

/* @ingroup SalStats */
CpaStatus SalStatistics_CleanStatisticsCollection(icp_accel_dev_t *device)
{
    sal_statistics_collection_t *pStatsCollection = NULL;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(device);
#endif
    pStatsCollection = (sal_statistics_collection_t *)device->pQatStats;
    LAC_OS_FREE(pStatsCollection);
    device->pQatStats = NULL;
    return CPA_STATUS_SUCCESS;
}
