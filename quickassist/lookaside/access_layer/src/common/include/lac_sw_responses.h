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
 ***************************************************************************
 * @file lac_sw_responses.h
 *
 * @defgroup LacSwResponses     Management for software responses
 *
 * @ingroup LacCommon
 *
 * Busy memory pools calculation functions and dummy responses generation
 * functions.
 *
 * @lld_start
 * @lld_overview
 *     This component is designed as a set of utility functions for the
 * generation of dummy responses and calculation of memory pools which contain
 * inflight requests. If the memory pools contain inflight requests, they
 * will be named as busy memory pools.
 * @lld_dependencies
 *     These utilities rely on OSAL for locking mechanisms and memory
 * allocation. It also depends on the implementation of the memory pool.
 * @lld_initialization
 *     The initialization of the number of busy memory pools should be done
 * prior to the increment.
 *
 * @lld_process_context
 * @lld_end
 ***************************************************************************/

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 *
 *
 ******************************************************************************/

/***************************************************************************/

#ifndef LAC_SW_RESPONSES_H
#define LAC_SW_RESPONSES_H

#include "lac_mem_pools.h"

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * @description
 * This function increases the number of busy memory pools if the poolID's
 * memory pool is not full.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 ******************************************************************************/
void LacSwResp_IncNumPoolsBusy(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * @description
 * This function initializes the number of busy memory pools to zero. This
 * function should be called prior to the calculation of busy memory pools.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 ******************************************************************************/
void LacSwResp_InitNumPoolsBusy(void);

/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * @description
 * This function is used to get the number of busy memory pools.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 ******************************************************************************/
Cpa16U LacSwResp_GetNumPoolsBusy(void);

#ifndef ICP_DC_ONLY
#ifndef ASYM_NOT_SUPPORTED
/**
 *******************************************************************************
 * @ingroup LacSwResponses
 * This function searches the pke request memory pool to find all inflight
 * requests and extracts the callback function from request data which will be
 * called to generate dummy responses.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] lac_mem_pool           The ID of the specific pool
 *
 *
 * @retval CPA_STATUS_FAIL           The function failed to retrieve all the
 *                                   inflight requests in the memory pool.
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 *
 ******************************************************************************/
CpaStatus LacSwResp_Asym_CallbackWake(lac_memory_pool_id_t lac_mem_pool);
#endif
#endif
#endif /* LAC_SW_RESPONSES_H */
