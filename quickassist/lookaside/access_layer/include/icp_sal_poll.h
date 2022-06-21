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
 * @file icp_sal_poll.h
 *
 * @defgroup SalPoll
 *
 * @ingroup SalPoll
 *
 * @description
 *    Polling APIs for instance polling.
 *    These functions retrieve requests on appropriate response rings and
 *    dispatch the associated callbacks. Callbacks are called in the
 *    context of the polling function itself.
 *
 *
 ***************************************************************************/

#ifndef ICP_SAL_POLL_H
#define ICP_SAL_POLL_H

#ifdef __cplusplus
extern "C" {
#endif

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    Poll a Cy logical instance to retrieve requests that are on the
 *    response rings associated with that instance and dispatch the
 *    associated callbacks.
 *
 * @context
 *      This functions is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] instanceHandle         Instance handle.
 * @param[in] response_quota         The maximum number of messages that
 *                                   will be read in one polling. Setting
 *                                   the response quota to zero means that
 *                                   all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS        Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY          There are no responses on the rings
 *                                   associated with this instance
 * @retval CPA_STATUS_FAIL           Indicates a failure
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESOURCE       Error related to system resources
 * @retval CPA_STATUS_FATAL          A serious error has occurred.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting. Resubmit
 *                                   the request.
 *************************************************************************/
CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
                                 Cpa32U response_quota);

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    Poll the symmetric logical instance to retrieve requests that are on
 *    the response rings associated with that instance and dispatch the
 *    associated callbacks.
 *
 * @context
 *      This functions is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] instanceHandle         Instance handle.
 * @param[in] response_quota         The maximum number of messages that
 *                                   will be read in one polling. Setting
 *                                   the response quota to zero means that
 *                                   all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS        Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY          There are no responses on the rings
 *                                   associated with this instance
 * @retval CPA_STATUS_FAIL           Indicates a failure
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESTARTING     Device restarting. Resubmit the
 *                                   request
 *************************************************************************/
CpaStatus icp_sal_CyPollSymRing(CpaInstanceHandle instanceHandle,
                                Cpa32U response_quota);

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    Poll the asymmetric logical instance to retrieve requests that are on
 *    the response rings associated with that instance and dispatch the
 *    associated callbacks.
 *
 * @context
 *      This functions is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] instanceHandle         Instance handle.
 * @param[in] response_quota         The maximum number of messages that
 *                                   will be read in one polling. Setting
 *                                   the response quota to zero means that
 *                                   all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS        Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY          There are no responses on the rings
 *                                   associated with this instance
 * @retval CPA_STATUS_FAIL           Indicates a failure
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESOURCE       Error related to system resources
 * @retval CPA_STATUS_FATAL          A serious error has occurred.
 * @retval CPA_STATUS_RESTARTING     Device restarting. Resubmit the
 *                                   request
 *************************************************************************/
CpaStatus icp_sal_CyPollAsymRing(CpaInstanceHandle instanceHandle,
                                 Cpa32U response_quota);

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    Poll the high priority symmetric response ring associated with a Cy
 *    logical instance to retrieve requests and dispatch the
 *    associated callbacks.
 *
 *    This API is recommended for data plane applications, in which the
 *    cost of offload - that is, the cycles consumed by the driver in
 *    sending requests to the hardware, and processing responses - needs
 *    to be minimized.  In particular, use of this API is recommended
 *    if the following constraints are acceptable to your application:
 *
 *    - Thread safety is not guaranteed.  Each software thread should
 *      have access to its own unique instance (CpaInstanceHandle) to
 *      avoid contention.
 *    - The "default" instance (@ref CPA_INSTANCE_HANDLE_SINGLE) is not
 *      supported on this API.  The specific handle should be obtained
 *      using the instance discovery functions (@ref cpaCyGetNumInstances,
 *      @ref cpaCyGetInstances).
 *
 *    This polling function should be used with the functions described
 *    in cpa_cy_sym_dp.h
 *
 * @context
 *      This functions is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 * @param[in] instanceHandle     Instance handle.
 * @param[in] response_quota     The maximum number of messages that
 *                               will be read in one polling. Setting
 *                               the response quota to zero means that
 *                               all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS    Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY      There are no responses on the ring
 *                               associated with this instance
 * @retval CPA_STATUS_FAIL       Indicates a failure
 *************************************************************************/
CpaStatus icp_sal_CyPollDpInstance(const CpaInstanceHandle instanceHandle,
                                   const Cpa32U response_quota);

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    Poll a Dc logical instance to retrieve requests that are on the
 *    response ring associated with that instance and dispatch the
 *    associated callbacks.
 *
 * @context
 *      This function is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] instanceHandle     Instance handle.
 * @param[in] response_quota     The maximum number of messages that
 *                               will be read in one polling. Setting
 *                               the response quota to zero means that
 *                               all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS    Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY      There are no responses on the ring
 *                               associated with this instance
 * @retval CPA_STATUS_FAIL       Indicates a failure
 *************************************************************************/
CpaStatus icp_sal_DcPollInstance(CpaInstanceHandle instanceHandle,
                                 Cpa32U response_quota);

/*************************************************************************
  * @ingroup SalPoll
  * @description
  *    Poll the response ring associated with a Dc logical instance to
  *    retrieve requests and dispatch the associated callbacks.
  *
  *    This API is recommended for data plane applications, in which the
  *    cost of offload - that is, the cycles consumed by the driver in
  *    sending requests to the hardware, and processing responses - needs
  *    to be minimized.  In particular, use of this API is recommended
  *    if the following constraints are acceptable to your application:
  *
  *    - Thread safety is not guaranteed.  Each software thread should
  *      have access to its own unique instance (CpaInstanceHandle) to
  *      avoid contention.
  *    - The "default" instance (@ref CPA_INSTANCE_HANDLE_SINGLE) is not
  *      supported on this API.  The specific handle should be obtained
  *      using the instance discovery functions (@ref cpaDcGetNumInstances,
  *      @ref cpaDcGetInstances).
  *
  *    This polling function should be used with the functions described
  *    in cpa_dc_dp.h

  *
  * @context
  *      This functions is called from both the user and kernel context
  *
  * @assumptions
  *      None
  * @sideEffects
  *      None
  * @reentrant
  *      No
  * @threadSafe
  *      No
  *
  * @param[in] instanceHandle     Instance handle.
  * @param[in] response_quota     The maximum number of messages that
  *                               will be read in one polling. Setting
  *                               the response quota to zero means that
  *                               all messages on the ring will be read.
  *
  * @retval CPA_STATUS_SUCCESS    Successfully polled a ring with data
  * @retval CPA_STATUS_RETRY      There are no responses on the ring
  *                               associated with this instance
  * @retval CPA_STATUS_FAIL       Indicates a failure
  *************************************************************************/
CpaStatus icp_sal_DcPollDpInstance(CpaInstanceHandle dcInstance,
                                   Cpa32U responseQuota);

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    This function polls the rings on the given bank to determine
 *    if any of the rings contain messages to be read. The
 *    response quota is per ring.
 *
 * @context
 *      This functions is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] accelId            Acceleration device Id, also known as
 *                               packageId. This can be obtained using
 *                               instance info functions (
 *                               @ref cpaCyInstanceGetInfo2
 *                               and @ref cpaDcInstanceGetInfo2)
 *
 * @param[in] bank_number        Bank number
 *
 * @param[in] response_quota     The maximum number of messages that
 *                               will be read in one polling. Setting
 *                               the response quota to zero means that
 *                               all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS    Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY      There is no data on any ring on the bank
 *                               or the bank is already being polled
 * @retval CPA_STATUS_FAIL       Indicates a failure
 *************************************************************************/
CpaStatus icp_sal_pollBank(Cpa32U accelId,
                           Cpa32U bank_number,
                           Cpa32U response_quota);

/*************************************************************************
 * @ingroup SalPoll
 * @description
 *    This function polls the rings on all banks to determine
 *    if any of the rings contain messages to be read. The
 *    response quota is per ring.
 *
 * @context
 *      This functions is called from both the user and kernel context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] accelId            Acceleration device Id, also known as
 *                               packageId. This can be obtained using
 *                               instance info functions (
 *                               @ref cpaCyInstanceGetInfo2
 *                               and @ref cpaDcInstanceGetInfo2)
 *
 * @param[in] response_quota     The maximum number of messages that
 *                               will be read in one polling. Setting
 *                               the response quota to zero means that
 *                               all messages on the ring will be read.
 *
 * @retval CPA_STATUS_SUCCESS    Successfully polled a ring with data
 * @retval CPA_STATUS_RETRY      There is no data on any ring on any bank
 *                               or the banks are already being polled
 * @retval CPA_STATUS_FAIL       Indicates a failure
 *************************************************************************/
CpaStatus icp_sal_pollAllBanks(Cpa32U accelId, Cpa32U response_quota);

/**
 *****************************************************************************
 * @ingroup cpaDc
 *      Get file descriptor for an instance
 *
 * @description
 *      This function is used to get a file descriptor for a particular
 *      instance. The fd will be set only in case of success and be kept
 *      unchanged otherwise.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] handle                 Data Compression API instance handle.
 * @param[in] fd                     File descriptor address to be set.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_UNSUPPORTED    Instance not in EPOLL mode.
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus icp_sal_DcGetFileDescriptor(CpaInstanceHandle instanceHandle,
                                      int *fd);

/**
 *****************************************************************************
 * @ingroup SalCtrl
 *      Get file descriptor for an instance
 *
 * @description
 *      This function is used to get a file descriptor for a particular
 *      instance. The fd will be set only in case of success and be kept
 *      unchanged otherwise.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] handle                 Crypto Compression API instance handle.
 * @param[in] fd                     File descriptor address to be set.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_UNSUPPORTED    Instance not in EPOLL mode.
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus icp_sal_CyGetFileDescriptor(CpaInstanceHandle instanceHandle,
                                      int *fd);

/**
 *****************************************************************************
 * @ingroup cpaDc
 *      Put file descriptor for an instance
 *
 * @description
 *      This function exists for compatibility reasons.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] handle                 Data Compression API instance handle.
 * @param[in] fd                     File descriptor.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_UNSUPPORTED    Instance not in EPOLL mode.
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus icp_sal_DcPutFileDescriptor(CpaInstanceHandle instanceHandle, int fd);
/**
 *****************************************************************************
 * @ingroup cpaDc
 *      Put file descriptor for an instance
 *
 * @description
 *      This function exists for compatibility reasons.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] handle                 Data Compression API instance handle.
 * @param[in] fd                     File descriptor.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_UNSUPPORTED    Instance not in EPOLL mode.
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus icp_sal_CyPutFileDescriptor(CpaInstanceHandle instanceHandle, int fd);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif
