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
 * @file sal_user_dyn_instance.c
 *
 * @defgroup SalUser
 *
 * @description
 *    This file contains implementation of functions
 *    to allocate/free dynamic crypto/compression instances
 *    These APIs have been deprecated.
 *
 *****************************************************************************/

/* QAT-API includes */
#include "cpa.h"

#ifndef ICP_DC_ONLY
CpaStatus icp_sal_userCyGetAvailableNumDynInstances(Cpa32U *pNumCyInstances)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userCyGetAvailableNumDynInstancesByDevPkg(
    Cpa32U *pNumCyInstances,
    Cpa32U devPkgID)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userCyGetAvailableNumDynInstancesByPkgAccel(
    Cpa32U *pNumCyInstances,
    Cpa32U devPkgID,
    Cpa32U accelerator_number)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userCyInstancesAlloc(Cpa32U numCyInstances,
                                       CpaInstanceHandle *pCyInstances)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userCyInstancesAllocByDevPkg(Cpa32U numCyInstances,
                                               CpaInstanceHandle *pCyInstances,
                                               Cpa32U devPkgID)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userCyFreeInstances(Cpa32U numCyInstances,
                                      CpaInstanceHandle *pCyInstances)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userCyInstancesAllocByPkgAccel(
    Cpa32U numCyInstances,
    CpaInstanceHandle *pCyInstances,
    Cpa32U devPkgID,
    Cpa32U accelerator_number)
{
    return CPA_STATUS_UNSUPPORTED;
}
#endif

CpaStatus icp_sal_userDcGetAvailableNumDynInstances(Cpa32U *pNumDcInstances)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userDcGetAvailableNumDynInstancesByDevPkg(
    Cpa32U *pNumDcInstances,
    Cpa32U devPkgID)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userDcInstancesAlloc(Cpa32U numDcInstances,
                                       CpaInstanceHandle *pDcInstances)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userDcInstancesAllocByDevPkg(Cpa32U numDcInstances,
                                               CpaInstanceHandle *pDcInstances,
                                               Cpa32U devPkgID)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus icp_sal_userDcFreeInstances(Cpa32U numDcInstances,
                                      CpaInstanceHandle *pDcInstances)
{
    return CPA_STATUS_UNSUPPORTED;
}
