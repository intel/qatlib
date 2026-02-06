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
 * @file sal_instances.c
 *
 * @defgroup SalCtrl Service Access Layer Controller
 *
 * @ingroup SalCtrl
 *
 * @description
 *      This file contains generic functions to get instances of a specified
 *      service type. Note these are complementary to the already existing
 *      service-specific functions.
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

/* QAT-API includes */
#include "cpa.h"
#ifndef ICP_DC_ONLY
#include "cpa_cy_common.h"
#include "cpa_cy_im.h"
#endif
#include "cpa_dc.h"

/* Osal includes */
#include "Osal.h"

/* ADF includes */
#include "icp_accel_devices.h"
#include "icp_adf_accel_mgr.h"

/* SAL includes */
#include "lac_mem.h"
#include "lac_list.h"
#include "lac_sal_types.h"
#include "lac_sal_types_crypto.h"
#include "sal_instances.h"

#ifndef ICP_DC_ONLY

STATIC void Lac_ConstructCyServicesfromSymAsym(sal_list_t **sym_services, sal_list_t **asym_services, sal_list_t **crypto_services)
{
    sal_crypto_service_t* asym_item = NULL;
    sal_crypto_service_t* sym_item = NULL;

    if (*crypto_services == NULL && *sym_services != NULL && *asym_services != NULL)
    {
        asym_item = (sal_crypto_service_t *)osalMemAlloc(sizeof(sal_crypto_service_t));
        osalMemCopy(asym_item, SalList_getObject(*asym_services), sizeof(sal_crypto_service_t) );
        sym_item = (sal_crypto_service_t*) SalList_getObject(*sym_services);

        asym_item->generic_service_info.type = SAL_SERVICE_TYPE_CRYPTO;
        asym_item->generic_service_info.virt2PhysClient =
            sym_item->generic_service_info.virt2PhysClient;
        asym_item->pSymDpCb = sym_item->pSymDpCb;
        asym_item->bankNumSym = sym_item->bankNumSym;
        asym_item->maxNumSymReqBatch = sym_item->maxNumSymReqBatch;
        asym_item->trans_handle_sym_rx = sym_item->trans_handle_sym_rx;
        asym_item->trans_handle_sym_tx = sym_item->trans_handle_sym_tx;
        asym_item->lac_sym_cookie_pool = sym_item->lac_sym_cookie_pool;
        asym_item->constantsLookupTables = sym_item->constantsLookupTables;
        asym_item->capInfo.symSupported = sym_item->capInfo.symSupported;
        asym_item->capInfo.symDpSupported = sym_item->capInfo.symDpSupported;

        asym_item->pLacSymStatsArr = sym_item->pLacSymStatsArr;
        asym_item->pTlsLabel = sym_item->pTlsLabel;
        asym_item->pSslLabel = sym_item->pSslLabel;
        asym_item->pTlsHKDFSubLabel = sym_item->pTlsHKDFSubLabel;
        asym_item->pLacHashLookupDefs = sym_item->pLacHashLookupDefs;

        SalList_add(crypto_services, crypto_services, asym_item);
        *asym_services = NULL;
        *sym_services = NULL;
    }
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 * @description
 *   Get the total number of either sym, asym or cy instances
 *****************************************************************************/
CpaStatus Lac_GetCyNumInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U *pNumInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0;
    Cpa16U num_inst = 0;
    Cpa16U i = 0;
    Cpa32U accel_capability = 0;
    char *service = NULL;

    LAC_CHECK_NULL_PARAM(pNumInstances);
    *pNumInstances = 0;

    switch (accelerationServiceType)
    {
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
            accel_capability = ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
            service = "asym";
            break;

        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
            accel_capability = ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
            service = "sym";
            break;

        case CPA_ACC_SVC_TYPE_CRYPTO:
            accel_capability = ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
                               ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
            service = "cy";
            break;

        default:
            LAC_LOG_ERROR("Invalid service type\n");
            return CPA_STATUS_INVALID_PARAM;
    }

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }

    num_accel_dev = 0;
    status = icp_adf_getAllAccelDevByCapabilities(
        accel_capability, pAdfInsts, &num_accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR_PARAMS("No support for service %s\n", service);
        osalMemFree(pAdfInsts);
        return status;
    }

    for (i = 0; i < num_accel_dev; i++)
    {
        dev_addr = pAdfInsts[i];
        if (NULL == dev_addr || NULL == dev_addr->pSalHandle)
        {
            continue;
        }
        base_addr = dev_addr->pSalHandle;

        /* Meeting these conditions indicates an imbalance in the number of
         * instances between SYM and ASYM. Given that we have only 4 ring pairs,
         * this scenario occurs only for sym;asym;dc and sym;asym;decomp
         * configurations.
         * The table below outlines the expected number of instances per
         * service (for these 2 configurations):
         * sym | asym | (dc or decomp) | cy
         * 1   |  2   | 1              | 1
         * When CPA_ACC_SVC_TYPE_CRYPTO is requested, the number of CY instances
         * is always 1 for these 2 configurations. Therefore, we handle this
         * situation separately and proceed to the next accel_dev.
         */
        if (CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType &&
            base_addr->sym_services != NULL && base_addr->asym_services != NULL)
        {
            num_inst++;
            continue;
        }

        if (CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType)
        {
            list_temp = base_addr->crypto_services;
            while (NULL != list_temp)
            {
                num_inst++;
                list_temp = SalList_next(list_temp);
            }
        }

        if (CPA_ACC_SVC_TYPE_CRYPTO_ASYM == accelerationServiceType ||
            CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType)
        {
            list_temp = base_addr->asym_services;
            if ((NULL == list_temp) &&
                (CPA_ACC_SVC_TYPE_CRYPTO != accelerationServiceType))
            {
                list_temp = base_addr->crypto_services;
            }
            while (NULL != list_temp)
            {
                num_inst++;
                list_temp = SalList_next(list_temp);
            }
        }

        if (CPA_ACC_SVC_TYPE_CRYPTO_SYM == accelerationServiceType ||
            CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType)
        {
            list_temp = base_addr->sym_services;
            if ((NULL == list_temp) &&
                (CPA_ACC_SVC_TYPE_CRYPTO != accelerationServiceType))
            {
                list_temp = base_addr->crypto_services;
            }
            while (NULL != list_temp)
            {
                num_inst++;
                list_temp = SalList_next(list_temp);
            }
        }
    }

    *pNumInstances = num_inst;
    osalMemFree(pAdfInsts);

#ifdef ICP_TRACE
    if (NULL != pNumInstances)
    {
        LAC_LOG2("Called with params (0x%lx[%d])\n",
                 (LAC_ARCH_UINT)pNumInstances,
                 *pNumInstances);
    }
    else
    {
        LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)pNumInstances);
    }
#endif

    return status;
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 * @description
 *   Get either sym, asym or cy instance
 *****************************************************************************/
CpaStatus Lac_GetCyInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U numInstances,
    CpaInstanceHandle *pInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_list_t *sym_services = NULL;
    sal_list_t *asym_services = NULL;
    sal_list_t **crypto_services = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0;
    Cpa16U num_allocated_instances = 0;
    Cpa16U index = 0;
    Cpa16U i = 0;
    Cpa32U accel_capability = 0;
    char *service = NULL;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (%d ,%d, 0x%lx)\n",
             accelerationServiceType,
             numInstances,
             (LAC_ARCH_UINT)pInstances);
#endif

    LAC_CHECK_NULL_PARAM(pInstances);
    if (0 == numInstances)
    {
        LAC_INVALID_PARAM_LOG("NumInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    switch (accelerationServiceType)
    {
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
            accel_capability = ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
            service = "asym";
            break;

        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
            accel_capability = ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
            service = "sym";
            break;

        case CPA_ACC_SVC_TYPE_CRYPTO:
            accel_capability = ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
                               ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
            service = "cy";
            break;

        default:
            LAC_LOG_ERROR("Invalid service type\n");
            return CPA_STATUS_INVALID_PARAM;
    }

    /* Get the number of instances */
    status = Lac_GetCyNumInstancesByType(accelerationServiceType,
                                         &num_allocated_instances);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    if (numInstances > num_allocated_instances)
    {
        LAC_LOG_ERROR1("Only %d instances available", num_allocated_instances);
        return CPA_STATUS_RESOURCE;
    }

    /* Get the number of accel devices in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }

    num_accel_dev = 0;
    status = icp_adf_getAllAccelDevByCapabilities(
        accel_capability, pAdfInsts, &num_accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR_PARAMS("No support for service %s\n", service);
        osalMemFree(pAdfInsts);
        return status;
    }

    for (i = 0; i < num_accel_dev; i++)
    {
        dev_addr = pAdfInsts[i];
        /* Note dev_addr cannot be NULL here as numInstances = 0
         * is not valid and if dev_addr = NULL then index = 0 (which
         * is less than numInstances and status is set to _RESOURCE
         * above
         */
        if (NULL == dev_addr->pSalHandle)
        {
            continue;
        }
        sym_services = ((sal_t*)dev_addr->pSalHandle)->sym_services;
        asym_services = ((sal_t*)dev_addr->pSalHandle)->asym_services;
        crypto_services = &((sal_t*)dev_addr->pSalHandle)->crypto_services;

        if (CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType)
        {
            Lac_ConstructCyServicesfromSymAsym(&sym_services, &asym_services, crypto_services);
            list_temp = *crypto_services;
            while (NULL != list_temp)
            {
                if (index > (numInstances - 1))
                    break;

                pInstances[index] = SalList_getObject(list_temp);
                list_temp = SalList_next(list_temp);
                index++;
            }
        }

        if (CPA_ACC_SVC_TYPE_CRYPTO_ASYM == accelerationServiceType ||
            CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType)
        {
            list_temp = asym_services;
            if ((NULL == list_temp) &&
                (CPA_ACC_SVC_TYPE_CRYPTO != accelerationServiceType))
            {
                list_temp = *crypto_services;
            }
            while (NULL != list_temp)
            {
                if (index > (numInstances - 1))
                    break;

                pInstances[index] = SalList_getObject(list_temp);
                list_temp = SalList_next(list_temp);
                index++;
            }
        }

        if (CPA_ACC_SVC_TYPE_CRYPTO_SYM == accelerationServiceType ||
            CPA_ACC_SVC_TYPE_CRYPTO == accelerationServiceType)
        {
            list_temp = sym_services;
            if ((NULL == list_temp) &&
                (CPA_ACC_SVC_TYPE_CRYPTO != accelerationServiceType))
            {
                list_temp = *crypto_services;
            }
            while (NULL != list_temp)
            {
                if (index > (numInstances - 1))
                    break;

                pInstances[index] = SalList_getObject(list_temp);
                list_temp = SalList_next(list_temp);
                index++;
            }
        }
    }
    osalMemFree(pAdfInsts);

    return status;
}
#endif

static CpaStatus GetServiceInfoByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U *servType,
    char *service,
    size_t size)
{
    switch (accelerationServiceType)
    {
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
            *servType = SERV_TYPE_DC;
            strncpy(service, "dc", size);
            break;
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            *servType = SERV_TYPE_DECOMP;
            strncpy(service, "decomp", size);
            break;
        default:
            LAC_LOG_ERROR("Invalid service type");
            return CPA_STATUS_INVALID_PARAM;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 * @description
 *   Get the total number of either Compression or decompression instances
 *****************************************************************************/
CpaStatus Lac_GetDcNumInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U *pNumInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0, num_accel_dev_valid = 0;
    Cpa16U num_inst = 0;
    Cpa16U i = 0;
    Cpa16U servType = 0;
    char service[ADF_CFG_MAX_STR_LEN] = { '\0' };

#ifdef ICP_TRACE
    LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)pNumInstances);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pNumInstances);
#endif
    *pNumInstances = 0;

    status = GetServiceInfoByType(
        accelerationServiceType, &servType, service, sizeof(service));
    LAC_CHECK_STATUS(status);

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    if (num_accel_dev == 0)
    {
        LAC_LOG_ERROR("Accel devices are not available");
        return CPA_STATUS_RESOURCE;
    }

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate device instance memory");
        return CPA_STATUS_RESOURCE;
    }

    status = icp_adf_getAllAccelDevByServices(
        servType, pAdfInsts, &num_accel_dev_valid);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR_PARAMS("No support for service %s", service);
        osalMemFree(pAdfInsts);
        return status;
    }

    for (i = 0; i < num_accel_dev_valid; i++)
    {
        dev_addr = pAdfInsts[i];
        if (NULL == dev_addr || NULL == dev_addr->pSalHandle)
        {
            continue;
        }
        base_addr = dev_addr->pSalHandle;

        if (CPA_ACC_SVC_TYPE_DATA_COMPRESSION == accelerationServiceType)
        {
            /* This case supports compression services */
            list_temp = base_addr->compression_services;
        }
        else
        {
            /* This case supports decompression services */
            list_temp = base_addr->decompression_services;
        }
        while (NULL != list_temp)
        {
            num_inst++;
            list_temp = SalList_next(list_temp);
        }
    }

    *pNumInstances = num_inst;
    osalMemFree(pAdfInsts);

#ifdef ICP_TRACE
    if (NULL != pNumInstances)
    {
        LAC_LOG2("Called with params (0x%lx[%d])\n",
                 (LAC_ARCH_UINT)pNumInstances,
                 *pNumInstances);
    }
#endif

    return status;
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 * @description
 *   Get either Compression & decompression instance
 *****************************************************************************/
CpaStatus Lac_GetDcInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U numInstances,
    CpaInstanceHandle *pInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0, num_accel_dev_valid = 0;
    Cpa16U num_allocated_instances = 0;
    Cpa16U index = 0;
    Cpa16U i = 0;
    Cpa16U servType = 0;
    char service[ADF_CFG_MAX_STR_LEN] = { '\0' };

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (%d ,%d, 0x%lx)\n",
             accelerationServiceType,
             numInstances,
             (LAC_ARCH_UINT)pInstances);
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pInstances);
#endif

    if (0 == numInstances)
    {
        LAC_INVALID_PARAM_LOG("NumInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    status = GetServiceInfoByType(
        accelerationServiceType, &servType, service, sizeof(service));
    LAC_CHECK_STATUS(status);

    /* Get the number of instances */
    status = Lac_GetDcNumInstancesByType(accelerationServiceType,
                                         &num_allocated_instances);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    if (numInstances > num_allocated_instances)
    {
        LAC_LOG_ERROR1("Only %d instances available", num_allocated_instances);
        return CPA_STATUS_RESOURCE;
    }

    /* Get the number of accel devices in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    if (num_accel_dev == 0)
    {
        LAC_LOG_ERROR("Accel devices are not available");
        return CPA_STATUS_RESOURCE;
    }

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }

    status = icp_adf_getAllAccelDevByServices(
        servType, pAdfInsts, &num_accel_dev_valid);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR_PARAMS("No support for service %s", service);
        osalMemFree(pAdfInsts);
        return status;
    }

    for (i = 0; i < num_accel_dev_valid; i++)
    {
        dev_addr = pAdfInsts[i];
        if (NULL == dev_addr || NULL == dev_addr->pSalHandle)
        {
            continue;
        }
        base_addr = dev_addr->pSalHandle;

        if (CPA_ACC_SVC_TYPE_DATA_COMPRESSION == accelerationServiceType)
        {
            /* This case supports compression services */
            list_temp = base_addr->compression_services;
        }
        else
        {
            /* This case supports decompression services */
            list_temp = base_addr->decompression_services;
        }
        while (NULL != list_temp)
        {
            if (index > (numInstances - 1))
                break;

            pInstances[index] = SalList_getObject(list_temp);
            list_temp = SalList_next(list_temp);
            index++;
        }
    }
    osalMemFree(pAdfInsts);

    return status;
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 *****************************************************************************/
CpaStatus cpaGetNumInstances(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U *pNumInstances)
{
    LAC_CHECK_NULL_PARAM(pNumInstances);

    switch (accelerationServiceType)
    {
#ifndef ICP_DC_ONLY
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
        case CPA_ACC_SVC_TYPE_CRYPTO:
            return Lac_GetCyNumInstancesByType(accelerationServiceType,
                                               pNumInstances);

#endif
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            return Lac_GetDcNumInstancesByType(accelerationServiceType,
                                               pNumInstances);

        case CPA_ACC_SVC_TYPE_PATTERN_MATCH:
        case CPA_ACC_SVC_TYPE_RAID:
        case CPA_ACC_SVC_TYPE_XML:
            LAC_LOG_ERROR("Unsupported service type\n");
            return CPA_STATUS_UNSUPPORTED;

        default:
            LAC_LOG_ERROR("Invalid service type\n");
            *pNumInstances = 0;
            return CPA_STATUS_INVALID_PARAM;
    }
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 *****************************************************************************/
CpaStatus cpaGetInstances(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U numInstances,
    CpaInstanceHandle *pInstances)
{
    LAC_CHECK_NULL_PARAM(pInstances);

    switch (accelerationServiceType)
    {
#ifndef ICP_DC_ONLY
        case CPA_ACC_SVC_TYPE_CRYPTO_ASYM:
        case CPA_ACC_SVC_TYPE_CRYPTO_SYM:
        case CPA_ACC_SVC_TYPE_CRYPTO:
            return Lac_GetCyInstancesByType(
                accelerationServiceType, numInstances, pInstances);

#endif
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
        case CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION:
            return Lac_GetDcInstancesByType(
                accelerationServiceType, numInstances, pInstances);

        case CPA_ACC_SVC_TYPE_PATTERN_MATCH:
        case CPA_ACC_SVC_TYPE_RAID:
        case CPA_ACC_SVC_TYPE_XML:
            LAC_LOG_ERROR("Unsupported service type\n");
            return CPA_STATUS_UNSUPPORTED;

        default:
            LAC_LOG_ERROR("Invalid service type\n");
            return CPA_STATUS_INVALID_PARAM;
    }
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 *****************************************************************************/
CpaStatus cpaAllocInstance(const CpaAccelerationServiceType serviceType,
                           const CpaInstanceAllocPolicy policy,
                           CpaInstanceHandle *pInstanceHandle)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 ******************************************************************************
 * @ingroup SalCtrl
 *****************************************************************************/
CpaStatus cpaFreeInstance(CpaInstanceHandle instanceHandle)
{
    return CPA_STATUS_UNSUPPORTED;
}
