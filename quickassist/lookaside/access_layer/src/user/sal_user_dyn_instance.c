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
