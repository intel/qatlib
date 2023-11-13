/****************************************************************************
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
 * @file dc_ns_datapath.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression datapath parameters.
 *
 ****************************************************************************/
#ifndef DC_NS_DATAPATH_H
#define DC_NS_DATAPATH_H

/* No-Session [NS] operations can come into the lib on the following APIs:
 * - Traditional API [Trad] : cpaDcNsXxx APIs
 * - Data-plane API [DP]    : cpaDcDpEnqueueXxx with
 *  	                      CpaDcDpOpData->pSetupData populated and
 *  	                      pSessionHandle = NULL 
 * The response from the firmware needs to be handled differently
 * depending on whether the request came in the DP or Trad path.
 *
 * As the pSessionHandle field in the internal cookie is superfluous for
 * NS operations, that field is overloaded to convey DP/Trad information.
 * This field is set when the request is set up and examined during the
 * response handling.
 */
#define DCNS 1
#define DCDPNS 0

void dcNsCompression_ProcessCallback(void *pRespMsg);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Construct compression base request
 *
 * @description
 *      This function will construct a compression base request, i.e. a request
 *      that serves as the base for a Traditional API request or a Data Plane
 *      API request. The function is the NS API equivalent of dcInitSession.
 *
 * @param[out]      pMsg             Pointer to empty message
 * @param[in]       pService         Pointer to compression service
 * @param[in]       pSetupData       Pointer to (de)compression parameters
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported algorithm/feature
 *****************************************************************************/

CpaStatus dcNsCreateBaseRequest(icp_qat_fw_comp_req_t *pMsg,
                                sal_compression_service_t *pService,
                                CpaDcNsSetupData *pSetupData);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Set the cnvErrorInjection flag in sal compression service request
 *
 * @description
 *      This function enables/disable the CnVError injection for the No-Session
 *      case. All Compression requests sent are injected with CnV errors.
 *
 * @param[in]       dcInstance       Instance Handle
 * @param[in]       enableCnvErrInj  TRUE/FALSE to Enable/Disable CnV Error
 *                                   Injection
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported feature
 *****************************************************************************/
CpaStatus dcNsSetCnvErrorInj(CpaInstanceHandle dcInstance,
                             CpaBoolean enableCnvErrInj);

#endif /* DC_NS_DATAPATH_H */
