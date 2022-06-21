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

/*
 ***************************************************************************
 * @file icp_sal_congestion_mgmt.h
 *
 * @ingroup SalUserCongsMgmt
 *
 * This file contains function prototypes for Congestion Management APIs.
 *
 ***************************************************************************/

#ifndef ICP_SAL_CONGESTION_MGMT_H
#define ICP_SAL_CONGESTION_MGMT_H

#include "icp_sal.h"

/*
 *****************************************************************************
 * @ingroup SalUserCongsMgmt
 *      Symmetric get in-flight requests
 *
 * @description
 *      This function is used to fetch in-flight and max in-flight request
 *      counts for the given symmetric instance handle.
 *
 * @param[in]  instanceHandle         Symmetric instance handle
 * @param[out] maxInflightRequests    Max in-flight request count
 * @param[out] numInflightRequests    Current in-flight request count
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
CpaStatus icp_sal_SymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                         Cpa32U *maxInflightRequests,
                                         Cpa32U *numInflightRequests);

/*
 *****************************************************************************
 * @ingroup SalUserCongsMgmt
 *      Asymmetric get in-flight requests
 *
 * @description
 *      This function is used to fetch in-flight and max in-flight request
 *      counts for the given asymmetric instance handle.
 *
 * @param[in]  instanceHandle         Asymmetric instance handle
 * @param[out] maxInflightRequests    Max in-flight request count
 * @param[out] numInflightRequests    Current in-flight request count
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
CpaStatus icp_sal_AsymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                          Cpa32U *maxInflightRequests,
                                          Cpa32U *numInflightRequests);

/*
 *****************************************************************************
 * @ingroup SalUserCongsMgmt
 *      Symmetric data plane get in-flight requests
 *
 * @description
 *      Data plane API to fetch in-flight and max in-flight request counts
 *      for the given symmetric instance handle.
 *
 * @param[in]  instanceHandle         Symmetric instance handle
 * @param[out] maxInflightRequests    Max in-flight request count
 * @param[out] numInflightRequests    Current in-flight request count
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
CpaStatus icp_sal_dp_SymGetInflightRequests(CpaInstanceHandle instanceHandle,
                                            Cpa32U *maxInflightRequests,
                                            Cpa32U *numInflightRequests);

#endif
