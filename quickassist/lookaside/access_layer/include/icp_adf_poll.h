/*****************************************************************************
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
 *****************************************************************************/

/*****************************************************************************
 * @file icp_adf_poll.h
 *
 * @description
 *      File contains Public API Definitions for the polling method.
 *
 *****************************************************************************/
#ifndef ICP_ADF_POLL_H
#define ICP_ADF_POLL_H

#include "cpa.h"
/*
 * icp_adf_pollInstance
 *
 * Description:
 * Poll an instance. In order to poll an instance
 * sal will pass in a table of trans handles from which
 * the ring to be polled can be obtained and subsequently
 * polled.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS   on polling a ring with data
 *   CPA_STATUS_FAIL      on failure
 *   CPA_STATUS_RETRY     if ring has no data on it
 *                        or ring is already being polled.
 */
CpaStatus icp_adf_pollInstance(icp_comms_trans_handle *trans_hnd,
                               Cpa32U num_transHandles,
                               Cpa32U response_quota);

/*
 * icp_adf_check_RespInstance
 *
 * Description:
 * Check whether an instance is empty or has remaining responses on it. In
 * order to check an instance for the remaining responses, sal will pass in
 * a table of trans handles from which the instance to be checked can be
 * obtained and subsequently checked.
 *
 * Returns:
 *   CPA_STATUS_SUCCESS         if response ring is empty
 *   CPA_STATUS_FAIL            on failure
 *   CPA_STATUS_RETRY           if response ring is not empty
 *   CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 */
CpaStatus icp_adf_check_RespInstance(icp_comms_trans_handle *trans_hnd,
                                     Cpa32U num_transHandles);
/*
 * This function allows the user to check ring error bit status
 */
CpaStatus icp_adf_checkRingError(icp_comms_trans_handle *trans_hnd,
                                 Cpa32U num_transHandles);

#endif /* ICP_ADF_POLL_H */
