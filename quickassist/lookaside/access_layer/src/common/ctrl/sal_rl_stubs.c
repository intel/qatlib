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
 * @file sal_rl_stubs.c
 *
 * @ingroup SalCtrl
 *
 * @description
 *      These functions specify the API for rate limiting, setting with
 *      respect to device, instance and queue pair.
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

/* QAT-API includes */
#include "cpa_rl.h"

CpaStatus cpaGetDevRlPropertiesHandle(Cpa16U devIdx,
                                      const CpaAccelerationServiceType srvType,
                                      CpaRlPropertiesHandle *handle,
                                      CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaRlPropGetNumInterfaces(const CpaRlPropertiesHandle handle,
                                    Cpa32U *totalSlaInterfaces,
                                    Cpa32U *remSlaInterfaces,
                                    CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaGetDevRlPropSlaCir(const CpaRlPropertiesHandle handle,
                                Cpa32U *totalCir,
                                Cpa32U *remCir,
                                CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaGetDevRlPropSlaPir(const CpaRlPropertiesHandle handle,
                                Cpa32U *totalPir,
                                Cpa32U *totalAssignedPir,
                                CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaGetInstanceRlSlaPir(const CpaInstanceHandle handle,
                                 Cpa32U *pirSetting,
                                 CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaGetInstanceRlSlaCir(const CpaInstanceHandle handle,
                                 Cpa32U *cirSetting,
                                 CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaRlGetQpNumHandles(Cpa32U devIdx,
                               CpaAccelerationServiceType svcType,
                               Cpa8U *numHandles,
                               CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaRlGetQpHandles(Cpa32U devIdx,
                            CpaAccelerationServiceType svcType,
                            CpaRlQpHandle *handles,
                            CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaSetRlSla(CpaRlQpHandle handle,
                      CpaUserSla *sla,
                      CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDeleteRlSla(CpaRlQpHandle handle, CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaGetRlSla(const CpaRlQpHandle handle,
                      CpaUserSla *sla,
                      CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaEnableRateLimiting(Cpa32U devIdx, CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDisableRateLimiting(Cpa32U devIdx, CpaRlError *rlError)
{
    return CPA_STATUS_UNSUPPORTED;
}
