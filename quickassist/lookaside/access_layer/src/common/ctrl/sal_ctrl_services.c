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
 * @file sal_ctrl_services.c
 *
 * @ingroup SalCtrl
 *
 * @description
 *    This file contains the core of the service controller implementation.
 *
 *****************************************************************************/

/* QAT-API includes */
#include "cpa.h"
#include "cpa_cy_key.h"
#include "cpa_cy_ln.h"
#include "cpa_cy_dh.h"
#include "cpa_cy_dsa.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_prime.h"
#include "cpa_cy_sym.h"
#include "cpa_dc.h"

/* Osal includes */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_cfg.h"
#include "icp_adf_init.h"
#include "icp_adf_accel_mgr.h"
#include "icp_adf_debug.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_sw_responses.h"
#include "lac_list.h"
#include "lac_hooks.h"
#include "sal_string_parse.h"
#include "lac_sym.h"
#include "lac_sym_key.h"
#include "lac_common.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "lac_sym_qat.h"
#include "lac_sal_types.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "icp_sal_versions.h"
#include "sal_misc_error_stats.h"
#include "icp_qat_fw_comp.h"
#define SAL_USER_SPACE_START_TIMEOUT_MS 120000
#define MAX_SUBSYSTEM_RETRY 64

#define ASYM_SERVICE "asym"
#define SYM_SERVICE "sym"
#define CY_SERVICE "cy"
#define DECOMP_SERVICE "decomp"
#define DC_SERVICE "dc"
#define INLINE_SERVICE "inline"

static char *subsystem_name = "SAL";
/**< Name used by ADF to identify this component. */
#ifndef ICP_DC_ONLY
static char *cy_dir_name = CY_SERVICE;
static char *asym_dir_name = ASYM_SERVICE;
static char *sym_dir_name = SYM_SERVICE;
#endif
static char *dc_dir_name = DC_SERVICE;
static char *decomp_dir_name = DECOMP_SERVICE;
/**< Stats dir names. */
static char *ver_file_name = "version";

static subservice_registation_handle_t sal_service_reg_handle;

static inline const char *get_sku_info(enum dev_sku_info info)
{
    switch (info)
    {
        case DEV_SKU_1:
            return "SKU1";
        case DEV_SKU_2:
            return "SKU2";
        case DEV_SKU_3:
            return "SKU3";
        case DEV_SKU_4:
            return "SKU4";
        case DEV_SKU_VF:
            return "SKUVF";
        case DEV_SKU_UNKNOWN:
        default:
            break;
    }
    return "Unknown SKU";
}

/**< Data structure used by ADF to keep a reference to this component. */

/*
 * @ingroup SalCtrl
 * @description
 *      This function is used to parse the results from ADF
 *      in response to ServiceEnabled query.The results are
 *      semi-colon separated. Internally, the bitmask represented
 *      by the enabled_service is used to track which features are enabled.
 *
 * @context
 *      This functions is called from the SalCtrl_ServiceEventInit function.
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
 * @param[in] device              pointer to icp_accel_dev_t structure
 * @param[in] pEnabledServices    pointer to memory where enabled services will
 *                               be written.
 * @retval Status
 */
CpaStatus SalCtrl_GetEnabledServices(icp_accel_dev_t *device,
                                     Cpa32U *pEnabledServices)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char param_value[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char *token = NULL;
    char *running = NULL;

    *pEnabledServices = 0;

    osalMemSet(param_value, 0, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, "ServicesEnabled", param_value);

    if (CPA_STATUS_SUCCESS == status)
    {
        running = param_value;

        token = strsep(&running, ";");

        while (NULL != token)
        {
            do
            {
#ifndef ICP_DC_ONLY
                if (strncmp(token, ASYM_SERVICE, strlen(ASYM_SERVICE)) == 0)
                {
                    *pEnabledServices |= SAL_SERVICE_TYPE_CRYPTO_ASYM;
                    break;
                }
                if (strncmp(token, SYM_SERVICE, strlen(SYM_SERVICE)) == 0)
                {
                    *pEnabledServices |= SAL_SERVICE_TYPE_CRYPTO_SYM;
                    break;
                }
                if (strncmp(token, CY_SERVICE, strlen(CY_SERVICE)) == 0)
                {
                    *pEnabledServices |= SAL_SERVICE_TYPE_CRYPTO;
                    break;
                }
#endif
                if (strncmp(token, DECOMP_SERVICE, strlen(DECOMP_SERVICE)) == 0)
                {
                    *pEnabledServices |= SAL_SERVICE_TYPE_DECOMPRESSION;
                    break;
                }
                if (strncmp(token, DC_SERVICE, strlen(DC_SERVICE)) == 0)
                {
                    *pEnabledServices |= SAL_SERVICE_TYPE_COMPRESSION;
                    break;
                }
                if (strncmp(token, INLINE_SERVICE, strlen(INLINE_SERVICE)) == 0)
                {
                    *pEnabledServices |= SAL_SERVICE_TYPE_INLINE;
                    break;
                }
                LAC_LOG_ERROR("Error parsing enabled services from ADF\n");
                return CPA_STATUS_FAIL;

            } while (0);
            token = strsep(&running, ";");
        }
    }
    else
    {
        LAC_LOG_ERROR("Failed to get enabled services from ADF");
    }
    return status;
}

/*
 * @ingroup SalCtrl
 * @description
 *      This function is used to check whether a service is enabled
 *
 * @context
 *      This functions is called from the SalCtrl_ServiceEventInit function.
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
 * param[in] enabled_services    It is the bitmask for the enabled services
 * param[in] service    It is the service we want to check for
 */
CpaBoolean SalCtrl_IsServiceEnabled(Cpa32U enabled_services,
                                    sal_service_type_t service)
{
    return (CpaBoolean)((enabled_services & (Cpa32U)(service)) != 0);
}

/*
 * @ingroup SalCtrl
 * @description
 *      This function is used to check whether enabled services has associated
 *      hardware capability support
 *
 * @context
 *      This functions is called from the SalCtrl_ServiceEventInit function.
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
 * param[in] device              A pointer to an icp_accel_dev_t
 * param[in] enabled_services    It is the bitmask for the enabled services
 */

CpaStatus SalCtrl_GetSupportedServices(icp_accel_dev_t *device,
                                       Cpa32U enabled_services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U capabilitiesMask = 0;

    status = icp_adf_getAccelDevCapabilities(device, &capabilitiesMask);

    if (CPA_STATUS_SUCCESS == status)
    {
#ifndef ICP_DC_ONLY
        if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
        {
            if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC) ||
                !(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC))
            {
                LAC_LOG_ERROR("Device does not support Crypto service");
                status = CPA_STATUS_FAIL;
            }
        }
        if (SalCtrl_IsServiceEnabled(enabled_services,
                                     SAL_SERVICE_TYPE_CRYPTO_ASYM))
        {
            if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC))
            {
                LAC_LOG_ERROR("Device does not support Asym service");
                status = CPA_STATUS_FAIL;
            }
        }
        if (SalCtrl_IsServiceEnabled(enabled_services,
                                     SAL_SERVICE_TYPE_CRYPTO_SYM))
        {
            if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC))
            {
                LAC_LOG_ERROR("Device does not support Sym service");
                status = CPA_STATUS_FAIL;
            }
        }
#endif
        if (SalCtrl_IsServiceEnabled(enabled_services,
                                     SAL_SERVICE_TYPE_COMPRESSION))
        {
            if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_COMPRESSION))
            {
                LAC_LOG_ERROR("Device does not support Compression service");
                status = CPA_STATUS_FAIL;
            }
        }

        if (SalCtrl_IsServiceEnabled(enabled_services,
                                     SAL_SERVICE_TYPE_DECOMPRESSION))
        {
            if (!(device->services & SERV_TYPE_DECOMP))
            {
                LAC_LOG_ERROR("Device does not support DeComp only service");
                status = CPA_STATUS_FAIL;
            }
        }
    }

    return status;
}

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function is used to check if a service is supported
 *      on the device. The key difference between this and
 *      SalCtrl_GetSupportedServices() is that the latter treats it as
 *      an error if the service is unsupported.
 *
 * @context
 *      This can be called anywhere.
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
 * param[in] device
 * param[in] service    service or services to check
 *
 *************************************************************************/
CpaBoolean SalCtrl_IsServiceSupported(icp_accel_dev_t *device,
                                      sal_service_type_t service_to_check)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U capabilitiesMask = 0;
    CpaBoolean service_supported = CPA_TRUE;

    if (!(SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                   SAL_SERVICE_TYPE_CRYPTO)) &&
        !(SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                   SAL_SERVICE_TYPE_CRYPTO_ASYM)) &&
        !(SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                   SAL_SERVICE_TYPE_CRYPTO_SYM)) &&
        !(SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                   SAL_SERVICE_TYPE_COMPRESSION)) &&
        !(SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                   SAL_SERVICE_TYPE_DECOMPRESSION)))
    {
        LAC_LOG_ERROR("Invalid service type");
        service_supported = CPA_FALSE;
    }

    status = icp_adf_getAccelDevCapabilities(device, &capabilitiesMask);

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can't get device capabilities so default");
        return CPA_FALSE;
    }

#ifndef ICP_DC_ONLY
    if (SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                 SAL_SERVICE_TYPE_CRYPTO))
    {
        if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC) ||
            !(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC))
        {
            LAC_LOG_DEBUG("Device does not support Crypto service");
            service_supported = CPA_FALSE;
        }
    }
    if (SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC))
        {
            LAC_LOG_DEBUG("Device does not support Asym service");
            service_supported = CPA_FALSE;
        }
    }
    if (SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                 SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC))
        {
            LAC_LOG_DEBUG("Device does not support Sym service");
            service_supported = CPA_FALSE;
        }
    }
#endif
    if (SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        if (!(capabilitiesMask & ICP_ACCEL_CAPABILITIES_COMPRESSION))
        {
            LAC_LOG_DEBUG("Device does not support Compression service");
            service_supported = CPA_FALSE;
        }
    }
    if (SalCtrl_IsServiceEnabled((Cpa32U)service_to_check,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        if (!(device->services & SERV_TYPE_DECOMP))
        {
            LAC_LOG_DEBUG("Device does not support Decompression service");
            service_supported = CPA_FALSE;
        }
    }
    return service_supported;
}

/*
 * @ingroup SalCtrl
 * @description
 *      This function is used to retrieve how many instances are
 *      to be configured for process specific service.
 *
 * @context
 *      This functions is called from the SalCtrl_ServiceEventInit function.
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
 * @param[in] device    A pointer to an icp_accel_dev_t
 * @param[in] key       Represents the parameter's name we want to query
 * @param[out] pCount   Pointer to memory where num instances will be stored
 * @retval status       returned status from ADF or _FAIL if number of instances
 *                      is out of range for the device.
 */
STATIC CpaStatus SalCtrl_GetInstanceCount(icp_accel_dev_t *device,
                                          char *key,
                                          Cpa32U *pCount)
{
    CpaStatus status = CPA_STATUS_FAIL;
    char param_value[ADF_CFG_MAX_VAL_LEN_IN_BYTES];

    osalMemSet(param_value, 0, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
    status =
        icp_adf_cfgGetParamValue(device, icpGetProcessName(), key, param_value);
    if (CPA_STATUS_SUCCESS == status)
    {
        *pCount = (Cpa32U)(Sal_Strtoul(param_value, NULL, SAL_CFG_BASE_DEC));
        if (*pCount > SAL_MAX_NUM_INSTANCES_PER_DEV)
        {
            LAC_LOG_ERROR("num instances out of range");
            status = CPA_STATUS_FAIL;
        }
    }
    return status;
}

/**************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the shutdown function on all the
 *      service instances.
 *      It also frees all service instance memory allocated at Init.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventShutdown
 *      function.
 *
 * @assumptions
 *      params[in] should not be NULL
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] device           An icp_accel_dev_t* type
 * @param[in] services         A pointer to the container of services
 * @param[in] dbg_dir          A pointer to the debug directory
 * @param[in] svc_type         The type of the service instance
 *
 ****************************************************************************/
STATIC CpaStatus SalCtrl_ServiceShutdown(icp_accel_dev_t *device,
                                         sal_list_t **services,
                                         debug_dir_info_t **debug_dir,
                                         sal_service_type_t svc_type)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_service_t *inst = (sal_service_t *)SalList_getObject(*services);
#ifndef KERNEL_SPACE
    Sal_CleanMiscErrStats(inst);
#endif
    /* Call Shutdown function for each service instance */
    SAL_FOR_EACH(*services, sal_service_t, device, shutdown, status);

    if (*debug_dir)
    {
        LAC_OS_FREE(*debug_dir);
        *debug_dir = NULL;
    }

    /* Free Sal services controller memory */
    SalList_free(services);
    return status;
}

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function is used to initialise the service instances.
 *      It allocates memory for service instances and invokes the
 *      Init function on them.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventInit function.
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
 * @param[in] device           An icp_accel_dev_t* type
 * @param[in] services         A pointer to the container of services
 * @param[in] dbg_dir          A pointer to the debug directory
 * @param[in] dbg_dir_name     Name of the debug directory
 * @param[in] tail_list        SAL's list of services
 * @param[in] instance_count   Number of instances
 * @param[in] svc_type         The type of the service instance
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceInit(icp_accel_dev_t *device,
                                     sal_list_t **services,
                                     debug_dir_info_t **dbg_dir,
                                     char *dbg_dir_name,
                                     sal_list_t *tail_list,
                                     Cpa32U instance_count,
                                     sal_service_type_t svc_type)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_service_t *pInst = NULL;
    Cpa32U i = 0;
    debug_dir_info_t *debug_dir = NULL;
#ifndef KERNEL_SPACE
    sal_statistics_collection_t *pStats =
        (sal_statistics_collection_t *)device->pQatStats;
#endif

    status = LAC_OS_MALLOC(&debug_dir, sizeof(debug_dir_info_t));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to allocate memory for debug dir");
        return status;
    }
    debug_dir->name = dbg_dir_name;
    debug_dir->parent = NULL;

    for (i = 0; i < instance_count; i++)
    {
        status = SalCtrl_ServiceCreate(svc_type, i, &pInst);
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
        pInst->debug_parent_dir = debug_dir;
        pInst->capabilitiesMask = device->accelCapabilitiesMask;
        pInst->isGen4 = IS_QAT_GEN4(device->deviceType);
        pInst->isGen4_2 = IS_QAT_GEN4_2(device->deviceType);
        pInst->ns_isCnvErrorInjection = ICP_QAT_FW_COMP_NO_CNV_DFX;
        if (pInst->isGen4)
        {
            pInst->optimisedCurveSupport = CPA_TRUE;
        }

        status = SalList_add(services, &tail_list, pInst);
        if (CPA_STATUS_SUCCESS != status)
        {
            osalMemFree(pInst);
            break;
        }
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to allocate all instances");
        LAC_OS_FREE(debug_dir);
        debug_dir = NULL;
        SalList_free(services);
        return status;
    }
#ifndef KERNEL_SPACE
    status = Sal_InitMiscErrStats(pStats);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to Initialize Misc Error Stats");
        LAC_OS_FREE(debug_dir);
        SalList_free(services);
        return status;
    }
#endif
    /* Call init function for each service instance */
    SAL_FOR_EACH(*services, sal_service_t, device, init, status);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to initialise all service instances");
        /* shutdown all instances initialised before error */
        SAL_FOR_EACH_STATE(*services,
                           sal_service_t,
                           device,
                           shutdown,
                           SAL_SERVICE_STATE_INITIALIZED);
        LAC_OS_FREE(debug_dir);
        debug_dir = NULL;

#ifndef KERNEL_SPACE
        Sal_CleanMiscErrStats(pInst);
#endif
        SalList_free(services);
        return status;
    }
    /* initialize the debug directory for relevant service */
    *dbg_dir = debug_dir;

    return status;
}

/**************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the start function on all the service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventStart function.
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
 * @param[in] device     An icp_accel_dev_t* type
 * @param[in] services   A pointer to the container of services
 *
 **************************************************************************/
STATIC CpaStatus SalCtrl_ServiceStart(icp_accel_dev_t *device,
                                      sal_list_t *services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Call Start function for each service instance */
    SAL_FOR_EACH(services, sal_service_t, device, start, status);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to start all instances");
        /* stop all instances started before error */
        SAL_FOR_EACH_STATE(
            services, sal_service_t, device, stop, SAL_SERVICE_STATE_RUNNING);
        return status;
    }

    return status;
}

/****************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the stop function on all the
 *      service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventStop function.
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
 * @param[in] device    An icp_accel_dev_t* type
 * @param[in] services   A pointer to the container of services
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceStop(icp_accel_dev_t *device,
                                     sal_list_t *services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Call Stop function for each service instance */
    SAL_FOR_EACH(services, sal_service_t, device, stop, status);

    return status;
}

/****************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the error handling function on all the
 *      service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventError function.
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
 * @param[in] device    An icp_accel_dev_t* type
 * @param[in] services   A pointer to the container of services
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceError(icp_accel_dev_t *device,
                                      sal_list_t *services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_list_t *curr_element = services;
    sal_service_t *service = NULL;

    /* Call error function for each service instance */
    SAL_FOR_EACH(services, sal_service_t, device, error, status);
    if (!icp_adf_isDevInError(device))
    {
        while (NULL != curr_element)
        {
            service = (sal_service_t *)SalList_getObject(curr_element);
            if (service->notification_cb)
            {
                service->notification_cb(
                    service, service->cb_tag, CPA_INSTANCE_EVENT_FATAL_ERROR);
            }
            curr_element = SalList_next(curr_element);
        }
    }
    return status;
}

/****************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the restarting event handling function on all
 *      the service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventRestarting
 *      function.
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
 * @param[in] device     An icp_accel_dev_t* type
 * @param[in] services   A pointer to the container of services
 * @param[in] dbg_dir    A pointer to the debug directory
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceRestarting(icp_accel_dev_t *device,
                                           sal_list_t *services,
                                           debug_dir_info_t **debug_dir)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_list_t *curr_element = services;
    sal_service_t *service = NULL;

    if (*debug_dir)
    {
        LAC_OS_FREE(*debug_dir);
        *debug_dir = NULL;
    }

    while (NULL != curr_element)
    {
        service = (sal_service_t *)SalList_getObject(curr_element);
        if (service->notification_cb)
        {
            service->notification_cb(
                service, service->cb_tag, CPA_INSTANCE_EVENT_RESTARTING);
        }
        curr_element = SalList_next(curr_element);
    }

    /* Call restarting function for each service instance */
    SAL_FOR_EACH(services, sal_service_t, device, restarting, status);

    return status;
}

/****************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the restarted handling function on all the
 *      service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventRestarted function.
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
 * @param[in] device     An icp_accel_dev_t* type
 * @param[in] services   A pointer to the container of services
 * @param[in] dbg_dir    A pointer to the debug directory
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceRestarted(icp_accel_dev_t *device,
                                          sal_list_t **services,
                                          debug_dir_info_t **dbg_dir,
                                          char *dbg_dir_name,
                                          sal_list_t *tail_list,
                                          Cpa32U instance_count,
                                          sal_service_type_t svc_type)

{
    CpaStatus status = CPA_STATUS_SUCCESS;
    debug_dir_info_t *debug_dir = NULL;
    sal_list_t *curr_element = *services;
    sal_service_t *service = NULL;

    status = LAC_OS_MALLOC(&debug_dir, sizeof(debug_dir_info_t));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to allocate memory for debug dir");
        return status;
    }
    debug_dir->name = dbg_dir_name;
    debug_dir->parent = NULL;

    while (NULL != curr_element)
    {
        service = (sal_service_t *)SalList_getObject(curr_element);
        service->debug_parent_dir = debug_dir;

        if (CPA_TRUE == service->isInstanceStarted)
        {
            icp_adf_qaDevGet(device);
        }

        curr_element = SalList_next(curr_element);
    }

    /* Call restarted function for each service instance */
    SAL_FOR_EACH(*services, sal_service_t, device, restarted, status);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to restart all service instances");
        return status;
    }

    curr_element = *services;
    while (NULL != curr_element)
    {
        service = (sal_service_t *)SalList_getObject(curr_element);
        if (service->notification_cb)
        {
            service->notification_cb(
                service, service->cb_tag, CPA_INSTANCE_EVENT_RESTARTED);
        }
        curr_element = SalList_next(curr_element);
    }
    /* initialize the debug directory for relevant service */
    *dbg_dir = debug_dir;
    return status;
}

/*
 * @ingroup SalCtrl
 * @description
 *      This function is used to print hardware and software versions in proc
 *      filesystem entry via ADF Debug interface
 *
 * @context
 *    This functions is called from proc filesystem interface
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
 * @param[in]  private_data    A pointer to a private data passed to the
 *                             function while adding a debug file.
 * @param[out] data            Pointer to a buffer where version information
 *                             needs to be printed to.
 * @param[in]  size            Size of a buffer pointed by data.
 * @param[in]  offset          Offset in a debug file
 *
 * @retval 0    This function always returns 0
 */
STATIC int SalCtrl_VersionDebug(void *private_data,
                                char *data,
                                int size,
                                int offset)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U len = 0;
    icp_accel_dev_t *device = (icp_accel_dev_t *)private_data;
    char param_value[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};

    len += snprintf(data + len,
                    size - len,
                    SEPARATOR BORDER
                    " Hardware and Software versions for device %d      " BORDER
                    "\n" SEPARATOR,
                    device->accelId);

    osalMemSet(param_value, 0, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_HW_REV_ID_KEY, param_value);
    LAC_CHECK_STATUS(status);

    len += snprintf(data + len,
                    size - len,
                    " Hardware Version:             %s %s \n",
                    param_value,
                    get_sku_info(device->sku));

    osalMemSet(param_value, 0, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_UOF_VER_KEY, param_value);
    LAC_CHECK_STATUS(status);

    len += snprintf(data + len,
                    size - len,
                    " Firmware Version:             %s \n",
                    param_value);
#ifndef ICP_DC_ONLY
    osalMemSet(param_value, 0, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_MMP_VER_KEY, param_value);
    LAC_CHECK_STATUS(status);

    len += snprintf(data + len,
                    size - len,
                    " MMP Version:                  %s \n",
                    param_value);
#endif
    len += snprintf(data + len,
                    size - len,
                    " Driver Version:               %d.%d.%d \n",
                    SAL_INFO2_DRIVER_SW_VERSION_MAJ_NUMBER,
                    SAL_INFO2_DRIVER_SW_VERSION_MIN_NUMBER,
                    SAL_INFO2_DRIVER_SW_VERSION_PATCH_NUMBER);

    osalMemSet(param_value, 0, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
    status = icp_adf_cfgGetParamValue(device,
                                      LAC_CFG_SECTION_GENERAL,
                                      ICP_CFG_LO_COMPATIBLE_DRV_KEY,
                                      param_value);
    LAC_CHECK_STATUS(status);

    len += snprintf(data + len,
                    size - len,
                    " Lowest Compatible Driver:     %s \n",
                    param_value);

    len += snprintf(data + len,
                    size - len,
                    " QuickAssist API CY Version:   %d.%d \n",
                    CPA_CY_API_VERSION_NUM_MAJOR,
                    CPA_CY_API_VERSION_NUM_MINOR);
    len += snprintf(data + len,
                    size - len,
                    " QuickAssist API DC Version:   %d.%d \n",
                    CPA_DC_API_VERSION_NUM_MAJOR,
                    CPA_DC_API_VERSION_NUM_MINOR);

    snprintf(data + len, size - len, SEPARATOR);
    return 0;
}

/**************************************************************************
 * @ingroup SalCtrl
 * @description
 *       This function calls the shutdown function on all the service
 *       instances. It also frees all service instance memory
 *       allocated at Init.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device             An icp_accel_dev_t* type
 * @param[in] enabled_services   Services enabled by user
 *
 ****************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventShutdown(icp_accel_dev_t *device,
                                              Cpa32U enabled_services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    sal_t *service_container = (sal_t *)device->pSalHandle;

    if (NULL == service_container)
    {
        LAC_LOG_ERROR("Private data is NULL");
        return CPA_STATUS_FATAL;
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status = SalCtrl_ServiceShutdown(device,
                                         &service_container->crypto_services,
                                         &service_container->cy_dir,
                                         SAL_SERVICE_TYPE_CRYPTO);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_ServiceShutdown(device,
                                         &service_container->asym_services,
                                         &service_container->asym_dir,
                                         SAL_SERVICE_TYPE_CRYPTO_ASYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_ServiceShutdown(device,
                                         &service_container->sym_services,
                                         &service_container->sym_dir,
                                         SAL_SERVICE_TYPE_CRYPTO_SYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status =
            SalCtrl_ServiceShutdown(device,
                                    &service_container->compression_services,
                                    &service_container->dc_dir,
                                    SAL_SERVICE_TYPE_COMPRESSION);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status =
            SalCtrl_ServiceShutdown(device,
                                    &service_container->decompression_services,
                                    &service_container->decomp_dir,
                                    SAL_SERVICE_TYPE_DECOMPRESSION);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    /* This condition is only met for aysm;asym;dc or asym;asym;decomp configurations. 
     * In such cases, service_container->crypto_services may be initialized if
     * the function Lac_GetCyNumInstancesByType is invoked with CPA_ACC_SVC_TYPE_CRYPTO
     * as the first parameter.
     * To ensure all allocated structures are properly cleaned up, the SalList_free
     * operation should be executed for crypto_services during the Service Shutdown phase.
     */
    if (SalCtrl_IsServiceEnabled(enabled_services,SAL_SERVICE_TYPE_CRYPTO_SYM) 
            && SalCtrl_IsServiceEnabled(enabled_services,SAL_SERVICE_TYPE_CRYPTO_ASYM) 
            && !SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        SalList_free(&service_container->crypto_services);
    }

    if (service_container->ver_file)
    {
        LAC_OS_FREE(service_container->ver_file);
        service_container->ver_file = NULL;
    }

    /* Free container also */
    osalMemFree(service_container);
    device->pSalHandle = NULL;

    return ret_status;
}

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function is used to initialize the service instances.
 *      It first checks (via ADF query) which services are enabled in the
 *      system and the number of each services.
 *      It then invokes the init function on them which creates the
 *      instances and allocates memory for them.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device             An icp_accel_dev_t* type
 * @param[in] enabled_services   Services enabled by user
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventInit(icp_accel_dev_t *device,
                                          Cpa32U enabled_services)
{
    sal_t *service_container = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_list_t *tail_list = NULL;
    Cpa32U instance_count = 0;

    status = SalCtrl_GetSupportedServices(device, enabled_services);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to get supported services");
        return status;
    }

    service_container = osalMemAlloc(sizeof(sal_t));
    if (NULL == service_container)
    {
        LAC_LOG_ERROR("Failed to allocate service memory");
        return CPA_STATUS_RESOURCE;
    }
    device->pSalHandle = service_container;
    service_container->asym_services = NULL;
    service_container->sym_services = NULL;
    service_container->crypto_services = NULL;
    service_container->compression_services = NULL;
    service_container->decompression_services = NULL;

    service_container->asym_dir = NULL;
    service_container->sym_dir = NULL;
    service_container->cy_dir = NULL;
    service_container->dc_dir = NULL;
    service_container->decomp_dir = NULL;
    service_container->ver_file = NULL;

    status =
        LAC_OS_MALLOC(&service_container->ver_file, sizeof(debug_file_info_t));
    if (CPA_STATUS_SUCCESS != status)
    {
        osalMemFree(service_container);
        return status;
    }

    osalMemSet(service_container->ver_file, 0, sizeof(debug_file_info_t));
    service_container->ver_file->name = ver_file_name;
    service_container->ver_file->seq_read = SalCtrl_VersionDebug;
    service_container->ver_file->private_data = device;
    service_container->ver_file->parent = NULL;

#ifndef ICP_DC_ONLY
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberAsymInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceInit(device,
                                     &service_container->asym_services,
                                     &service_container->asym_dir,
                                     asym_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_CRYPTO_ASYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_init;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberSymInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceInit(device,
                                     &service_container->sym_services,
                                     &service_container->sym_dir,
                                     sym_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_CRYPTO_SYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_init;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberCyInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceInit(device,
                                     &service_container->crypto_services,
                                     &service_container->cy_dir,
                                     cy_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_CRYPTO);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_init;
        }
    }
#endif
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberDcInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceInit(device,
                                     &service_container->compression_services,
                                     &service_container->dc_dir,
                                     dc_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_COMPRESSION);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_init;
        }
    }
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberDecompInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceInit(device,
                                     &service_container->decompression_services,
                                     &service_container->decomp_dir,
                                     decomp_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_DECOMPRESSION);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_init;
        }
    }
    return status;

err_init:
    SalCtrl_ServiceEventShutdown(device, enabled_services);
    return status;
}

/****************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the stop function on all the service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device              An icp_accel_dev_t* type
 * @param[in] enabled_services    Enabled services by user
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventStop(icp_accel_dev_t *device,
                                          Cpa32U enabled_services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    sal_t *service_container = device->pSalHandle;

    if (service_container == NULL)
    {
        LAC_LOG_ERROR("Private data is NULL");
        return CPA_STATUS_FATAL;
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_ServiceStop(device, service_container->asym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_ServiceStop(device, service_container->sym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status =
            SalCtrl_ServiceStop(device, service_container->crypto_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status = SalCtrl_ServiceStop(device,
                                     service_container->compression_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status = SalCtrl_ServiceStop(device,
                                     service_container->decompression_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            ret_status = status;
        }
    }

    return ret_status;
}

/**************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the start function on all the service instances.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device              An icp_accel_dev_t* type
 * @param[in] enabled_services    Enabled services by user
 *
 **************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventStart(icp_accel_dev_t *device,
                                           Cpa32U enabled_services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_t *service_container = device->pSalHandle;

    if (service_container == NULL)
    {
        LAC_LOG_ERROR("Private data is NULL");
        return CPA_STATUS_FATAL;
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_ServiceStart(device, service_container->asym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_start;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_ServiceStart(device, service_container->sym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_start;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status =
            SalCtrl_ServiceStart(device, service_container->crypto_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_start;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status = SalCtrl_ServiceStart(device,
                                      service_container->compression_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_start;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status = SalCtrl_ServiceStart(
            device, service_container->decompression_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_start;
        }
    }

    return status;
err_start:
    SalCtrl_ServiceEventStop(device, enabled_services);
    return status;
}

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function calls the error function on all the service instances
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device             An icp_accel_dev_t* type
 * @param[in] enabled_services   Services enabled by user
 *
 *************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventError(icp_accel_dev_t *device,
                                           Cpa32U enabled_services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_t *service_container = device->pSalHandle;

    if (service_container == NULL)
    {
        LAC_LOG_ERROR("Private data is NULL");
        return CPA_STATUS_FATAL;
    }

    LacSwResp_InitNumPoolsBusy();

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_ServiceError(device, service_container->asym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_ServiceError(device, service_container->sym_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status =
            SalCtrl_ServiceError(device, service_container->crypto_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status = SalCtrl_ServiceError(device,
                                      service_container->compression_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status = SalCtrl_ServiceError(
            device, service_container->decompression_services);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (0 != LacSwResp_GetNumPoolsBusy())
    {
        status = CPA_STATUS_RETRY;
    }

    return status;
}

/**************************************************************************
 * @ingroup SalCtrl
 * @description
 *       This function calls the restarting function on all the service
 *       instances. It cleans some service instance resources.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device             An icp_accel_dev_t* type
 * @param[in] enabled_services   Services enabled by user
 *
 ****************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventRestarting(icp_accel_dev_t *device,
                                                Cpa32U enabled_services)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_t *service_container = device->pSalHandle;

    if (service_container == NULL)
    {
        LAC_LOG_ERROR("Private data is NULL");
        return CPA_STATUS_FATAL;
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_ServiceRestarting(device,
                                           service_container->asym_services,
                                           &service_container->asym_dir);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_ServiceRestarting(device,
                                           service_container->sym_services,
                                           &service_container->sym_dir);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status = SalCtrl_ServiceRestarting(device,
                                           service_container->crypto_services,
                                           &service_container->cy_dir);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status =
            SalCtrl_ServiceRestarting(device,
                                      service_container->compression_services,
                                      &service_container->dc_dir);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status =
            SalCtrl_ServiceRestarting(device,
                                      service_container->decompression_services,
                                      &service_container->decomp_dir);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    if (service_container->ver_file)
    {
        LAC_OS_FREE(service_container->ver_file);
        service_container->ver_file = NULL;
    }

    return status;
}

/**************************************************************************
 * @ingroup SalCtrl
 * @description
 *       This function calls the restarted function on all the service
 *       instances. It reinitializes the instance resources.
 *
 * @context
 *      This function is called from the SalCtrl_ServiceEventHandler function.
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
 * @param[in] device             An icp_accel_dev_t* type
 * @param[in] enabled_services   Services enabled by user
 *
 ****************************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventRestarted(icp_accel_dev_t *device,
                                               Cpa32U enabled_services)
{
    sal_t *service_container = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_list_t *tail_list = NULL;
    Cpa32U instance_count = 0;

    status = SalCtrl_GetSupportedServices(device, enabled_services);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to get supported services");
        return status;
    }

    service_container = device->pSalHandle;
    service_container->asym_dir = NULL;
    service_container->sym_dir = NULL;
    service_container->cy_dir = NULL;
    service_container->dc_dir = NULL;
    service_container->decomp_dir = NULL;
    service_container->ver_file = NULL;

    status =
        LAC_OS_MALLOC(&service_container->ver_file, sizeof(debug_file_info_t));
    if (CPA_STATUS_SUCCESS != status)
    {
        goto err_restarted;
    }

    osalMemSet(service_container->ver_file, 0, sizeof(debug_file_info_t));
    service_container->ver_file->name = ver_file_name;
    service_container->ver_file->seq_read = SalCtrl_VersionDebug;
    service_container->ver_file->private_data = device;
    service_container->ver_file->parent = NULL;

#ifndef ICP_DC_ONLY
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_CRYPTO_ASYM))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberAsymInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceRestarted(device,
                                          &service_container->asym_services,
                                          &service_container->asym_dir,
                                          asym_dir_name,
                                          tail_list,
                                          instance_count,
                                          SAL_SERVICE_TYPE_CRYPTO_ASYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_restarted;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO_SYM))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberSymInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceRestarted(device,
                                          &service_container->sym_services,
                                          &service_container->sym_dir,
                                          sym_dir_name,
                                          tail_list,
                                          instance_count,
                                          SAL_SERVICE_TYPE_CRYPTO_SYM);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_restarted;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services, SAL_SERVICE_TYPE_CRYPTO))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberCyInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status = SalCtrl_ServiceRestarted(device,
                                          &service_container->crypto_services,
                                          &service_container->cy_dir,
                                          cy_dir_name,
                                          tail_list,
                                          instance_count,
                                          SAL_SERVICE_TYPE_CRYPTO);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_restarted;
        }
    }
#endif
    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_COMPRESSION))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberDcInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status =
            SalCtrl_ServiceRestarted(device,
                                     &service_container->compression_services,
                                     &service_container->dc_dir,
                                     dc_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_COMPRESSION);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_restarted;
        }
    }

    if (SalCtrl_IsServiceEnabled(enabled_services,
                                 SAL_SERVICE_TYPE_DECOMPRESSION))
    {
        status = SalCtrl_GetInstanceCount(
            device, "NumberDecompInstances", &instance_count);
        if (CPA_STATUS_SUCCESS != status)
        {
            instance_count = 0;
        }
        status =
            SalCtrl_ServiceRestarted(device,
                                     &service_container->decompression_services,
                                     &service_container->decomp_dir,
                                     decomp_dir_name,
                                     tail_list,
                                     instance_count,
                                     SAL_SERVICE_TYPE_DECOMPRESSION);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto err_restarted;
        }
    }

    return status;

err_restarted:
    SalCtrl_ServiceEventStop(device, enabled_services);
    SalCtrl_ServiceEventShutdown(device, enabled_services);
    return status;
}

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *      This function is the events handler registered with ADF
 *      for the QA API services (cy, dc) - kernel and user
 *
 * @context
 *      This function is called from an ADF context.
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
 * @param[in]  device      An icp_accel_dev_t* type
 * @param[in]  event       Event from ADF
 * @param[in]  param       Parameter used for back compatibility
 *
 ***********************************************************************/
STATIC CpaStatus SalCtrl_ServiceEventHandler(icp_accel_dev_t *device,
                                             enum adf_event event,
                                             void *param)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus stats_status = CPA_STATUS_SUCCESS;
    Cpa32U enabled_services = 0;

    status = SalCtrl_GetEnabledServices(device, &enabled_services);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to get enabled services");
        return status;
    }

    switch (event)
    {
        case ADF_EVENT_INIT:
        {
            /* In case there is no QAT SAL needs to call InitStats */
            if (NULL == device->pQatStats)
            {
                status = SalStatistics_InitStatisticsCollection(device);
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                return status;
            }
            status = SalCtrl_ServiceEventInit(device, enabled_services);
            break;
        }
        case ADF_EVENT_START:
        {
            status = SalCtrl_ServiceEventStart(device, enabled_services);
            break;
        }
        case ADF_EVENT_STOP:
        {
            status = SalCtrl_ServiceEventStop(device, enabled_services);
            break;
        }
        case ADF_EVENT_SHUTDOWN:
        {
            status = SalCtrl_ServiceEventShutdown(device, enabled_services);
            stats_status = SalStatistics_CleanStatisticsCollection(device);
            if (CPA_STATUS_SUCCESS != status ||
                CPA_STATUS_SUCCESS != stats_status)
            {
                return CPA_STATUS_FAIL;
            }
            break;
        }
        case ADF_EVENT_ERROR:
        {
            status = SalCtrl_ServiceEventError(device, enabled_services);
            break;
        }
        case ADF_EVENT_RESTARTING:
        {
            status = SalCtrl_ServiceEventRestarting(device, enabled_services);
            break;
        }
        case ADF_EVENT_RESTARTED:
        {
            status = SalCtrl_ServiceEventRestarted(device, enabled_services);
            break;
        }
        default:
            status = CPA_STATUS_SUCCESS;
            break;
    }
    return status;
}

CpaStatus SalCtrl_AdfServicesRegister(void)
{
    /* Fill out the global sal_service_reg_handle structure */
    sal_service_reg_handle.subserviceEventHandler = SalCtrl_ServiceEventHandler;
    /* Set subsystem name to globally defined name */
    sal_service_reg_handle.subsystem_name = subsystem_name;

    return icp_adf_subsystemRegister(&sal_service_reg_handle);
}

CpaStatus SalCtrl_AdfServicesUnregister(void)
{
    return icp_adf_subsystemUnregister(&sal_service_reg_handle);
}

CpaStatus SalCtrl_AdfServicesStartedCheck(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U retry_num = 0;
    CpaBoolean state = CPA_FALSE;

    do
    {
        state = icp_adf_isSubsystemStarted(&sal_service_reg_handle);
        retry_num++;
    } while ((CPA_FALSE == state) && (retry_num < MAX_SUBSYSTEM_RETRY));

    if (CPA_FALSE == state)
    {
        LAC_LOG_ERROR("Sal Ctrl failed to start in given time\n");
        status = CPA_STATUS_FAIL;
    }

    return status;
}

CpaStatus validateConcurrRequest(Cpa32U numConcurrRequests)
{
    Cpa32U baseReq = SAL_64_CONCURR_REQUESTS;

    if (SAL_64_CONCURR_REQUESTS > numConcurrRequests)
    {
        LAC_LOG_ERROR("Invalid numConcurrRequests, "
                      "it is less than min value");
        return CPA_STATUS_FAIL;
    }

    while (SAL_MAX_CONCURR_REQUESTS >= baseReq)
    {
        if (baseReq != numConcurrRequests)
        {
            baseReq = baseReq << 1;
        }
        else
        {
            break;
        }
    }
    if (SAL_MAX_CONCURR_REQUESTS < baseReq)
    {
        LAC_LOG_ERROR("Invalid baseReg, it is greater than max value");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}
