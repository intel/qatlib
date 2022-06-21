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
 * @file sal_user_dyn_instance.c
 *
 * @defgroup SalUser
 *
 * @description
 *    This file contains implementation of functions
 *    to allocate/free dynamic crypto/compression instances
 *
 *****************************************************************************/

/* QAT-API includes */
#include "cpa.h"

/* Osal includes */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_accel_devices.h"
#include "icp_adf_accel_mgr.h"
#include "icp_adf_user_proxy.h"
#include "icp_adf_transport.h"
#include "icp_adf_cfg.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"

/* SAL includes */
#include "icp_sal_user.h"
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "lac_sal_types_crypto.h"
#include "sal_types_compression.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "sal_string_parse.h"

#define PENDING_DELAY 1
#define ALL_DEVPKGS 0xffffffff

static pthread_mutex_t sync_multi_lock = PTHREAD_MUTEX_INITIALIZER;

STATIC CpaStatus
do_userGetAvailableNumDynInstances(Cpa32U *pNumInstances,
                                   sal_service_type_t serviceType,
                                   Cpa32U devPkgID)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U x = 0;

    Cpa16U numAccelDev = 0; /* the number of devices (icp_accel_dev_t). */
    icp_accel_dev_t **pAdfInsts = NULL; /* store the address for
                                           all adf device instances' pointers.
                                           here, it's the array
                                           of (icp_accel_dev_t *) */
    icp_accel_dev_t *pDevice = NULL;    /* store the address of
                                           one adf device instance */

    Cpa32U num = 0;
    Cpa32U availableInstCnt = 0; /* the available number of sal service
                                    object instances (sal_service_t). */
    Cpa32U capabilitiesMask = 0;
    adf_service_type_t stype = ADF_SERVICE_MAX;
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    Cpa32U *pDevPkgId = NULL;

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&numAccelDev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(numAccelDev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory\n");
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pAdfInsts, 0, (numAccelDev * sizeof(icp_accel_dev_t *)));
    numAccelDev = 0;
#ifndef ICP_DC_ONLY
    if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
    {
        capabilitiesMask = ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
                           ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
        stype = ADF_SERVICE_CRYPTO;
    }
#endif
    if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
    {
        capabilitiesMask = ICP_ACCEL_CAPABILITIES_COMPRESSION;
        stype = ADF_SERVICE_COMPRESS;
    }
    /* Get devices with crypto or compression service enabled */
    status = icp_adf_getAllAccelDevByCapabilities(
        capabilitiesMask, pAdfInsts, &numAccelDev);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not find device with sufficient capabilities\n");
        osalMemFree(pAdfInsts);
        return CPA_STATUS_FAIL;
    }
    /* Allocate memory to store addr of devPkgId */
    pDevPkgId = osalMemAlloc(numAccelDev * sizeof(Cpa32U));
    if (NULL == pDevPkgId)
    {
        LAC_LOG_ERROR("Failed to allocate devPkgId memory\n");
        osalMemFree(pAdfInsts);
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pDevPkgId, 0xff, (numAccelDev * sizeof(Cpa32U)));

    /* Check if there are enough available dyn cy or dc instances */
    availableInstCnt = 0;
    for (x = 0; x < numAccelDev; x++)
    {
        pDevice = (icp_accel_dev_t *)pAdfInsts[x];
        if (NULL == pDevice->pSalHandle)
        {
            /* Try the next device */
            continue;
        }
        if (devPkgID != ALL_DEVPKGS)
        {
            status = icp_adf_cfgGetParamValue(
                pDevice, LAC_CFG_SECTION_GENERAL, ADF_DEV_PKG_ID, adfGetParam);
            if (CPA_STATUS_SUCCESS != status)
            {
                /* Try the next device */
                continue;
            }
            pDevPkgId[x] = Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);
            if (pDevPkgId[x] != devPkgID)
            {
                /* Try the next device */
                continue;
            }
        }
        status = icp_adf_getNumAvailDynInstance(pDevice, stype, &num);
        if (CPA_STATUS_SUCCESS != status)
        {
            /* Try the next device */
            continue;
        }
        availableInstCnt += num;
    }
    *pNumInstances = availableInstCnt;
    osalMemFree(pAdfInsts);
    osalMemFree(pDevPkgId);
    return CPA_STATUS_SUCCESS;
}

#ifndef ICP_DC_ONLY
CpaStatus icp_sal_userCyGetAvailableNumDynInstances(Cpa32U *pNumCyInstances)
{
    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pNumCyInstances);

    return do_userGetAvailableNumDynInstances(
        pNumCyInstances, SAL_SERVICE_TYPE_CRYPTO, ALL_DEVPKGS);
}
#endif

CpaStatus icp_sal_userDcGetAvailableNumDynInstances(Cpa32U *pNumDcInstances)
{
    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pNumDcInstances);

    return do_userGetAvailableNumDynInstances(
        pNumDcInstances, SAL_SERVICE_TYPE_COMPRESSION, ALL_DEVPKGS);
}

#ifndef ICP_DC_ONLY
CpaStatus icp_sal_userCyGetAvailableNumDynInstancesByDevPkg(
    Cpa32U *pNumCyInstances,
    Cpa32U devPkgID)
{
    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pNumCyInstances);

    return do_userGetAvailableNumDynInstances(
        pNumCyInstances, SAL_SERVICE_TYPE_CRYPTO, devPkgID);
}
#endif

CpaStatus icp_sal_userDcGetAvailableNumDynInstancesByDevPkg(
    Cpa32U *pNumDcInstances,
    Cpa32U devPkgID)
{
    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pNumDcInstances);

    return do_userGetAvailableNumDynInstances(
        pNumDcInstances, SAL_SERVICE_TYPE_COMPRESSION, devPkgID);
}

#ifndef ICP_DC_ONLY
CpaStatus icp_sal_userCyGetAvailableNumDynInstancesByPkgAccel(
    Cpa32U *pNumCyInstances,
    Cpa32U devPkgID,
    Cpa32U accelerator_number)
{
    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pNumCyInstances);
    if (accelerator_number > 0)
    {
        LAC_LOG_ERROR1("accelerator_number is invalid(%u)\n",
                       accelerator_number);
        return CPA_STATUS_INVALID_PARAM;
    }

    return icp_sal_userCyGetAvailableNumDynInstancesByDevPkg(pNumCyInstances,
                                                             devPkgID);
}
#endif

/* allocate sal service instances */
STATIC CpaStatus do_userInstancesAlloc(Cpa32U numInstances,
                                       sal_service_type_t serviceType,
                                       CpaInstanceHandle *pInstances,
                                       Cpa32U devPkgID)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    Cpa16U numAccelDev = 0; /* the number of devices (icp_accel_dev_t). */
    icp_accel_dev_t **pAdfInsts = NULL; /* store the address for
                                           all adf device instances' pointers.
                                           here, it's the array
                                           of (icp_accel_dev_t *) */
    icp_accel_dev_t *pDevice = NULL;    /* store the address of
                                           one adf device instance */
    Cpa32U num = 0;
    Cpa32U availableInstCnt = 0; /* the available number of sal service
                                    object instances (sal_service_t). */
    Cpa32U instanceId = ADF_CFG_NO_INSTANCE; /* the id of
                                                sal service instance */
    sal_list_t **pSalLists = NULL;           /* store the address of
                                                sal service list head pointers
                                                of all device.
                                                here, it's the array of (sal_list_t *) */
    sal_list_t *pDynServices = NULL;         /* store the address of
                                               one sal service list of one device.
                                               here, sal service list is the list
                                               of (sal_service_t *) */
    sal_service_t *pInst = NULL;             /* store the address of
                                                one sal service object */

    sal_list_t *pTailList = NULL;
    sal_list_t *pHeadList = NULL;
    sal_list_t *pList = NULL;
    sal_list_t **pNewLists = NULL; /* store the address of all new added
                                   sal list head pointers
                                   in pServiceContainer->crypto_services,
                                   or pServiceContainer->compression_services */
    sal_list_t *pNextElement = NULL;
    Cpa32U enabledServices = 0;
    Cpa32U i = 0;
    Cpa32U x = 0;
    Cpa32U *pNumSals = 0;
    Cpa32U capabilitiesMask = 0;
    adf_service_type_t stype = ADF_SERVICE_MAX;
    sal_t *pServiceContainer = NULL;
    sal_list_t *pServiceList = NULL;
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    Cpa32U *pDevPkgId = NULL;

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&numAccelDev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(numAccelDev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory\n");
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pAdfInsts, 0, (numAccelDev * sizeof(icp_accel_dev_t *)));
    numAccelDev = 0;
#ifndef ICP_DC_ONLY
    if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
    {
        capabilitiesMask = ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
                           ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
        stype = ADF_SERVICE_CRYPTO;
    }
#endif
    if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
    {
        capabilitiesMask = ICP_ACCEL_CAPABILITIES_COMPRESSION;
        stype = ADF_SERVICE_COMPRESS;
    }
    /* Get devices with crypto or compression service enabled */
    status = icp_adf_getAllAccelDevByCapabilities(
        capabilitiesMask, pAdfInsts, &numAccelDev);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not find device with sufficient capabilities\n");
        osalMemFree(pAdfInsts);
        return CPA_STATUS_FAIL;
    }
    /* Allocate memory to store addr of devPkgId */
    pDevPkgId = osalMemAlloc(numAccelDev * sizeof(Cpa32U));
    if (NULL == pDevPkgId)
    {
        LAC_LOG_ERROR("Failed to allocate devPkgId memory\n");
        osalMemFree(pAdfInsts);
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pDevPkgId, 0xff, (numAccelDev * sizeof(Cpa32U)));

    /* Check if there are enough available dyn cy or dc instances */
    availableInstCnt = 0;
    for (x = 0; x < numAccelDev; x++)
    {
        pDevice = (icp_accel_dev_t *)pAdfInsts[x];
        if (NULL == pDevice->pSalHandle)
        {
            /* Try the next device */
            continue;
        }

        if (devPkgID != ALL_DEVPKGS)
        {
            status = icp_adf_cfgGetParamValue(
                pDevice, LAC_CFG_SECTION_GENERAL, ADF_DEV_PKG_ID, adfGetParam);
            if (CPA_STATUS_SUCCESS != status)
            {
                /* Try the next device */
                continue;
            }
            pDevPkgId[x] = Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);
            if (pDevPkgId[x] != devPkgID)
            {
                /* Try the next device */
                continue;
            }
        }
        status = icp_adf_getNumAvailDynInstance(pDevice, stype, &num);
        if (CPA_STATUS_SUCCESS != status)
        {
            /* Try the next device */
            continue;
        }
        availableInstCnt += num;
    }
    if (availableInstCnt < numInstances)
    {
        LAC_LOG_ERROR("No enough available dyn cy or dc instances\n");
        osalMemFree(pAdfInsts);
        osalMemFree(pDevPkgId);
        return CPA_STATUS_FAIL;
    }

    /* Allocate memory to store addr of sal lists */
    pSalLists = osalMemAlloc(numAccelDev * sizeof(sal_list_t *));
    if (NULL == pSalLists)
    {
        LAC_LOG_ERROR("Failed to allocate sal list memory\n");
        osalMemFree(pAdfInsts);
        osalMemFree(pDevPkgId);
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pSalLists, 0, (numAccelDev * sizeof(sal_list_t *)));

    pNumSals = osalMemAlloc(numAccelDev * sizeof(Cpa32U));
    if (NULL == pNumSals)
    {
        LAC_LOG_ERROR("Failed to allocate pNumSals\n");
        osalMemFree(pAdfInsts);
        osalMemFree(pDevPkgId);
        osalMemFree(pSalLists);
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pNumSals, 0, (numAccelDev * sizeof(Cpa32U)));

    /* Allocate memory to store addr of the new added sal lists
     * in pServiceContainer->crypto_services
     * or pServiceContainer->compression_services */
    pNewLists = osalMemAlloc(numAccelDev * sizeof(sal_list_t *));
    if (NULL == pNewLists)
    {
        LAC_LOG_ERROR("Failed to allocate sal list memory\n");
        osalMemFree(pAdfInsts);
        osalMemFree(pDevPkgId);
        osalMemFree(pSalLists);
        osalMemFree(pNumSals);
        return CPA_STATUS_RESOURCE;
    }
    osalMemSet(pNewLists, 0, (numAccelDev * sizeof(sal_list_t *)));

    do
    {
        /* Allocate instances from multiple devices
         * with crypto or compression service enabled.
         * Allocated instances are saved in
         * pAdfInsts[x]->pSalHandle->crypto_services,
         * or pAdfInsts[x]->pSalHandle->compression_services */
        for (x = 0, i = 0; x < numAccelDev; x++)
        {
            pDynServices = NULL;
            pDevice = (icp_accel_dev_t *)pAdfInsts[x];

            if (devPkgID != ALL_DEVPKGS)
            {
                if (pDevPkgId[x] != devPkgID)
                {
                    /* Try the next device */
                    continue;
                }
            }
            if (NULL == pDevice->pSalHandle)
            {
                /* Try the next device */
                continue;
            }
            pServiceContainer = pDevice->pSalHandle;

            /* Get enabled services from device cfg data */
            status = SalCtrl_GetEnabledServices(pDevice, &enabledServices);
            if (CPA_STATUS_SUCCESS != status)
            {
                /* Try the next device */
                continue;
            }
            if (CPA_FALSE ==
                SalCtrl_IsServiceEnabled(enabledServices, serviceType))
            {
                /* Try the next device */
                continue;
            }

            /* Create sal crypto or compression service instance described
             * in DYN section of cfg file */
            for (; i < numInstances; i++)
            {
                instanceId = ADF_CFG_NO_INSTANCE;
                pInst = NULL;
                /* Get an available instance from dyn instance pool
                 * for the device */
                status = icp_adf_getDynInstance(pDevice, stype, &instanceId);
                if ((CPA_STATUS_SUCCESS != status) ||
                    (ADF_CFG_NO_INSTANCE == instanceId))
                { /* No available instance in the device */
                    break;
                }
                status = SalCtrl_ServiceCreate(serviceType, instanceId, &pInst);
                if ((CPA_STATUS_SUCCESS != status) || (NULL == pInst))
                {
                    icp_adf_putDynInstance(pDevice, stype, instanceId);
                    break;
                }
                /* SalCtrl_ServiceCreate will set pInst->is_dyn
                 * to be CPA_FALSE by default.
                 * Set pInst->is_dyn to be CPA_TRUE, so as to get cfg data
                 * from DYN section. */
                pInst->is_dyn = CPA_TRUE;
                pInst->capabilitiesMask = pDevice->accelCapabilitiesMask;
                status = SalList_add(&pDynServices, &pTailList, pInst);
                if (CPA_STATUS_SUCCESS != status)
                {
                    icp_adf_putDynInstance(pDevice, stype, instanceId);
                    osalMemFree(pInst);
                    break;
                }
            }
            pSalLists[x] = pDynServices;
            if ((CPA_STATUS_SUCCESS != status) ||
                (ADF_CFG_NO_INSTANCE == instanceId))
            {
                /* Try the next device */
                continue;
            }
        }
        if (i < numInstances)
        {
            LAC_LOG_ERROR1("Fail to get %d dyn cy or dc instances\n",
                           numInstances);
            status = CPA_STATUS_FAIL;
            break;
        }

        for (x = 0; x < numAccelDev; x++)
        {
            if (devPkgID != ALL_DEVPKGS)
            {
                if (pDevPkgId[x] != devPkgID)
                {
                    /* Try the next device */
                    continue;
                }
            }
            pDevice = (icp_accel_dev_t *)pAdfInsts[x];
            /* Call init function for each service instance */
            SAL_FOR_EACH(pSalLists[x], sal_service_t, pDevice, init, status);
            if (CPA_STATUS_SUCCESS != status)
            {
                LAC_LOG_ERROR1(
                    "Failed to initialise all instances for icp_dev%d\n",
                    ((icp_accel_dev_t *)pAdfInsts[x])->accelId);
                break;
            }

            /* Call Start function for each service instance */
            SAL_FOR_EACH(pSalLists[x], sal_service_t, pDevice, start, status);
            if (CPA_STATUS_SUCCESS != status)
            {
                LAC_LOG_ERROR1("Failed to start all instances for icp_dev%d\n",
                               ((icp_accel_dev_t *)pAdfInsts[x])->accelId);
                break;
            }
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }

        pTailList = NULL;
        pHeadList = NULL;

        for (x = 0, i = 0; x < numAccelDev; x++)
        { /* Add initialized sal crypto or compression service instance
           * from pSalLists[x] into
           * pServiceContainer->crypto_services
           * or pServiceContainer->compression_services of each device
           * pAdfInsts[x] */
            if (devPkgID != ALL_DEVPKGS)
            {
                if (pDevPkgId[x] != devPkgID)
                {
                    /* Try the next device */
                    continue;
                }
            }
            pDevice = (icp_accel_dev_t *)pAdfInsts[x];
            pServiceContainer = pDevice->pSalHandle;
#ifndef ICP_DC_ONLY
            if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
            {
                pServiceList = pServiceContainer->crypto_services;
            }
#endif
            if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
            {
                pServiceList = pServiceContainer->compression_services;
            }
            /* Move pTailList point to the end
             * of the existing pServiceContainer->crypto_services,
             * or pServiceContainer->compression_services */
            pTailList = pServiceList;
            if (NULL != pServiceList)
            {
                pTailList = pServiceList;
                while (SalList_next(pTailList))
                {
                    pTailList = SalList_next(pTailList);
                }
            }
            pHeadList = pTailList;

            /* save the address of the end
             * of the existing pServiceContainer->crypto_services,
             * or pServiceContainer->compression_services,
             * which is the new added list head pointer */
            pNewLists[x] = pHeadList;

            pDynServices = pSalLists[x];
            pNumSals[x] = 0;
            while (pDynServices)
            {
                pInst = (sal_service_t *)SalList_getObject(pDynServices);
#ifndef ICP_DC_ONLY
                if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
                {
                    status = SalList_add(
                        &pServiceContainer->crypto_services, &pTailList, pInst);
                }
#endif
                if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
                {
                    status =
                        SalList_add(&pServiceContainer->compression_services,
                                    &pTailList,
                                    pInst);
                }
                if (CPA_STATUS_SUCCESS != status)
                {
                    break;
                }
                pNumSals[x]++;
                pInstances[i++] = (CpaInstanceHandle)pInst;
                pDynServices = SalList_next(pDynServices);
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                LAC_LOG_ERROR1("Failed to add instances for icp_dev%d\n",
                               ((icp_accel_dev_t *)pAdfInsts[x])->accelId);
                break;
            }
        }
        break;
    } while (0);

    /* Handle error */
    if (CPA_STATUS_SUCCESS != status)
    {
        for (x = 0; x < numAccelDev; x++)
        {
            pList = pSalLists[x];
            pDevice = (icp_accel_dev_t *)pAdfInsts[x];
            while (pList)
            {
                pInst = (sal_service_t *)SalList_getObject(pList);
                if (NULL == pInst)
                {
                    pList = SalList_next(pList);
                    continue;
                }
                if (SAL_SERVICE_STATE_RUNNING == pInst->state)
                {
                    status = pInst->stop(pDevice, pInst);
                }
                if (CPA_STATUS_RETRY == status)
                {
                    osalSleep(PENDING_DELAY);
                }

                if ((SAL_SERVICE_STATE_INITIALIZED == pInst->state) ||
                    (SAL_SERVICE_STATE_SHUTTING_DOWN == pInst->state) ||
                    (SAL_SERVICE_STATE_RESTARTING == pInst->state))
                {
                    pInst->shutdown(pDevice, pInst);
                }
                icp_adf_putDynInstance(pDevice, stype, pInst->instance);
                pList = SalList_next(pList);
            }
            SalList_free(&pSalLists[x]);
            if (NULL != pNewLists[x])
            {
                /* Free new added list in pServiceContainer->crypto_services,
                 * or pServiceContainer->compression_services,
                 * sal object should have been freed when free pSalLists[x] */
                pList = SalList_next(pNewLists[x]);
                while ((NULL != pList) && (pNumSals[x]-- > 0))
                {
                    pNextElement = SalList_next(pList);
                    LAC_OS_FREE(pList);
                    pList = pNextElement;
                }
                pNewLists[x]->next = pList;
            }
        }
        for (i = 0; i < numInstances; i++)
        {
            pInstances[i] = NULL;
        }
        osalMemFree(pAdfInsts);
        osalMemFree(pDevPkgId);
        osalMemFree(pSalLists);
        osalMemFree(pNewLists);
        osalMemFree(pNumSals);
        return status;
    }

    for (x = 0; x < numAccelDev; x++)
    {
        /* Delete sal object from pSalLists[x] to avoid free it
         * when free pSalLists[x] as it has been added into
         * pServiceContainer->crypto_services
         * or pServiceContainer->compression_services for each device */
        pList = pSalLists[x];
        while (pList)
        {
            SalList_delObject(&pList);
            pList = SalList_next(pList);
        }
        SalList_free(&pSalLists[x]);
    }
    osalMemFree(pAdfInsts);
    osalMemFree(pDevPkgId);
    osalMemFree(pSalLists);
    osalMemFree(pNewLists);
    osalMemFree(pNumSals);
    return status;
}

#ifndef ICP_DC_ONLY
/* allocate crypto sal service instances */
CpaStatus icp_sal_userCyInstancesAlloc(Cpa32U numCyInstances,
                                       CpaInstanceHandle *pCyInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pCyInstances);
    if (0 == numCyInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        return CPA_STATUS_FAIL;
    }
    status = do_userInstancesAlloc(
        numCyInstances, SAL_SERVICE_TYPE_CRYPTO, pCyInstances, ALL_DEVPKGS);
    if (pthread_mutex_unlock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}
#endif

/* allocate compression sal service instances */
CpaStatus icp_sal_userDcInstancesAlloc(Cpa32U numDcInstances,
                                       CpaInstanceHandle *pDcInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pDcInstances);
    if (0 == numDcInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        return CPA_STATUS_FAIL;
    }
    status = do_userInstancesAlloc(numDcInstances,
                                   SAL_SERVICE_TYPE_COMPRESSION,
                                   pDcInstances,
                                   ALL_DEVPKGS);
    if (pthread_mutex_unlock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}

#ifndef ICP_DC_ONLY
/* allocate crypto sal service instances
 * which are from the specific device package. */
CpaStatus icp_sal_userCyInstancesAllocByDevPkg(Cpa32U numCyInstances,
                                               CpaInstanceHandle *pCyInstances,
                                               Cpa32U devPkgID)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pCyInstances);
    if (0 == numCyInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        return CPA_STATUS_FAIL;
    }
    status = do_userInstancesAlloc(
        numCyInstances, SAL_SERVICE_TYPE_CRYPTO, pCyInstances, devPkgID);
    if (pthread_mutex_unlock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}
#endif

/* allocate compression sal service instances
 * which are from the specific device package. */
CpaStatus icp_sal_userDcInstancesAllocByDevPkg(Cpa32U numDcInstances,
                                               CpaInstanceHandle *pDcInstances,
                                               Cpa32U devPkgID)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pDcInstances);
    if (0 == numDcInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        return CPA_STATUS_FAIL;
    }
    status = do_userInstancesAlloc(
        numDcInstances, SAL_SERVICE_TYPE_COMPRESSION, pDcInstances, devPkgID);
    if (pthread_mutex_unlock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}

#ifndef ICP_DC_ONLY
/**
 * Allocate crypto sal service instances
 * which are from the specific device package and accelerator.
 */
CpaStatus icp_sal_userCyInstancesAllocByPkgAccel(
    Cpa32U numCyInstances,
    CpaInstanceHandle *pCyInstances,
    Cpa32U devPkgID,
    Cpa32U accelerator_number)
{
    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pCyInstances);
    if (accelerator_number > 0)
    {
        LAC_LOG_ERROR1("accelerator_number is invalid(%u)\n",
                       accelerator_number);
        return CPA_STATUS_INVALID_PARAM;
    }
    return icp_sal_userCyInstancesAllocByDevPkg(
        numCyInstances, pCyInstances, devPkgID);
}
#endif

STATIC CpaStatus do_userFreeInstances(Cpa32U numInstances,
                                      sal_service_type_t serviceType,
                                      CpaInstanceHandle *pInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifndef ICP_DC_ONLY
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    sal_compression_service_t *pCompressionService = NULL;
    sal_service_t *pInst = NULL; /* store the address of
                                    one sal service object */
    Cpa32U i = 0;
    icp_accel_dev_t *pDevice = NULL;
    sal_t *pServiceContainer = NULL;

    sal_list_t *pPreList = NULL;
    sal_list_t *pList = NULL;

    adf_service_type_t stype = ADF_SERVICE_MAX;
    sal_list_t *pServiceList = NULL;
    Cpa16U deviceId = 0;
    Cpa32U instanceId = 0;
#ifndef ICP_DC_ONLY
    if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
    {
        stype = ADF_SERVICE_CRYPTO;
    }
#endif
    if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
    {
        stype = ADF_SERVICE_COMPRESS;
    }

    for (i = 0; i < numInstances; i++)
    {
        if (NULL == pInstances[i])
        {
            continue;
        }
#ifndef ICP_DC_ONLY
        if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
        {
            pCryptoService = (sal_crypto_service_t *)pInstances[i];
            deviceId = pCryptoService->pkgID;
            instanceId = pCryptoService->generic_service_info.instance;
        }
#endif
        if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
        {
            pCompressionService = (sal_compression_service_t *)pInstances[i];
            deviceId = pCompressionService->pkgID;
            instanceId = pCompressionService->generic_service_info.instance;
        }

        pInst = (sal_service_t *)pInstances[i];
        pDevice = icp_adf_getAccelDevByAccelId(deviceId);
        if (NULL == pDevice)
        {
            LAC_LOG_ERROR2("Can not find device%d for the instance%d\n",
                           deviceId,
                           instanceId);
            continue;
        }
        /* stop crypto or compressioninstance */
        if (CPA_STATUS_RETRY == pInst->stop(pDevice, pInst))
        {
            osalSleep(PENDING_DELAY);
        }
        /* shutdown crypto or compression instance */
        pInst->shutdown(pDevice, pInst);

        /* put crypto or cmopression instance
         * into dyn crypto or compression instances pool */
        icp_adf_putDynInstance(pDevice, stype, pInst->instance);

        /* Remove crypto or compression instance
         * from pServiceContainer->crypto_services,
         * or pServiceContainer->compression_services,
         * free crypto instance */
        pServiceContainer = pDevice->pSalHandle;
        if (NULL == pServiceContainer)
        {
            continue;
        }
#ifndef ICP_DC_ONLY
        if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
        {
            pServiceList = pServiceContainer->crypto_services;
        }
#endif
        if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
        {
            pServiceList = pServiceContainer->compression_services;
        }

        if (NULL != pServiceList)
        {
            pList = pServiceList;
            pPreList = pList;

            while (pList)
            {
                if ((((sal_service_t *)SalList_getObject(pList))->instance ==
                     pInst->instance) &&
                    (CPA_TRUE ==
                     ((sal_service_t *)SalList_getObject(pList))->is_dyn))
                {
#ifndef ICP_DC_ONLY
                    if (SAL_SERVICE_TYPE_CRYPTO == serviceType)
                    {
                        SalList_del(&pServiceContainer->crypto_services,
                                    &pPreList,
                                    pList);
                    }
#endif
                    if (SAL_SERVICE_TYPE_COMPRESSION == serviceType)
                    {
                        SalList_del(&pServiceContainer->compression_services,
                                    &pPreList,
                                    pList);
                    }
                    pInstances[i] = NULL;
                    break;
                }
                pPreList = pList;
                pList = (sal_list_t *)SalList_next(pList);
            }
        }
    }
    return status;
}

#ifndef ICP_DC_ONLY
CpaStatus icp_sal_userCyFreeInstances(Cpa32U numCyInstances,
                                      CpaInstanceHandle *pCyInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pCyInstances);
    if (0 == numCyInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        return CPA_STATUS_FAIL;
    }
    status = do_userFreeInstances(
        numCyInstances, SAL_SERVICE_TYPE_CRYPTO, pCyInstances);
    if (pthread_mutex_unlock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}
#endif

CpaStatus icp_sal_userDcFreeInstances(Cpa32U numDcInstances,
                                      CpaInstanceHandle *pDcInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Input parameters check */
    LAC_CHECK_NULL_PARAM(pDcInstances);
    if (0 == numDcInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex lock failed\n");
        return CPA_STATUS_FAIL;
    }
    status = do_userFreeInstances(
        numDcInstances, SAL_SERVICE_TYPE_COMPRESSION, pDcInstances);
    if (pthread_mutex_unlock(&sync_multi_lock))
    {
        LAC_LOG_ERROR("Mutex unlock failed\n");
        status = CPA_STATUS_FAIL;
    }
    return status;
}
