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
