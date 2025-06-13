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

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file cpa_rl.h
 *
 * @defgroup cpaRl Rate Limiting API
 *
 * @ingroup cpa
 *
 *
 * @description
 *      Rate limiting feature is a feature designed in QAT software to enforce
 *      Service Level Agreements (SLA), which allocate a specified amount of
 *      acceleration capacity for a specified service at a ring-pair or
 *      queue-pair (QP) granularity.
 *
 *      A single queue-pair or a bundle of queue-pairs can be assigned to
 *      guest virtual machines or to the host. However, rate limits can only
 *      be allocated by the host.
 *
 *      These functions specify the API for setting and querying the rate
 *      limits with respect to device, instance and queue-pair.
 *
 *      Terminology:
 *      CIR - Committed Information Rate. A value used to specify the committed
 *            rate for a QP. A given QP should always be able to use the
 *            acceleration bandwidth up to its CIR value
 *      PIR - Peak Information Rate. A value used to specify the peak rate for
 *            a QP. A given QP cannot use acceleration bandwidth beyond its PIR
 *            value. The PIR value is always >= CIR value.
 *
 * @remarks
 *
 *****************************************************************************/

#ifndef CPA_RL_H
#define CPA_RL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CPA_H
#include "cpa.h"
#endif

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Supported additional details from accelerator
 *
 * @description
 *      This enumeration lists the supported additional details about rate
 *      limiting requests status from accelerator.
 *
 *****************************************************************************/
typedef enum _CpaRlError
{
    CPA_STATUS_RL_FAIL = -1,
    /**< Failure not covered in the other cases */
    CPA_STATUS_RL_FAIL_IO = -2,
    /**< Failed to send request to hardware */
    CPA_STATUS_RL_NOT_ENABLED = -3,
    /* Rate limiting is not enabled */
    CPA_STATUS_RL_INVALID_CIR_PIR = -4,
    /* CIR or PIR is beyond the parent node capacity */
    CPA_STATUS_RL_SLA_NOT_CONFIGURED = -5,
    /* For SLA delete, SLA is not configured on the QP */
} CpaRlError;

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Rate limiting handle type.
 *
 * @description
 *      Handle used to uniquely identify a QP to configure sla.
 *
 *****************************************************************************/
typedef void *CpaRlQpHandle;

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Rate limiting property handle type.
 *
 * @description
 *      Handle used to identify a specific device's rate limiting properties
 *      for a specific service. The properties includes available and remaining
 *      number of interfaces for SLA configuration, PIR and CIR.
 *
 *****************************************************************************/
typedef void *CpaRlPropertiesHandle;

/**
 *****************************************************************************
 * @ingroup cpa
 *      User SLA Info Structure
 *
 * @description
 *      Structure that contains the CIR, PIR and service type for a handle.
 *      The value of cir and pir are absolute value in Mbps or Kops. The unit
 *      is dependent on the service type as following:
 *      Sym and Dc: Mbps
 *      Asym: Kops
 *
 *****************************************************************************/
typedef struct _CpaUserSla
{
    CpaAccelerationServiceType svcType;
    /**< Service type associated with the cpaQpHandle.
     * Supported service types are CPA_ACC_SVC_TYPE_DATA_COMPRESSION,
     * CPA_ACC_SVC_TYPE_CRYPTO_ASYM and CPA_ACC_SVC_TYPE_CRYPTO_SYM.
     * This parameter is only for checking, and not a setter param. */
    Cpa32U cir;
    /**< Committed Information Rate for the associated cpaQpHandle.
     * With a correctly provisioned configuration, a QP should always be able
     * to use acceleration bandwidth up to its CIR. */
    Cpa32U pir;
    /**< Peak Information Rate for the associated cpaQpHandle.
     * The handle's rate must not exceed this. PIR is always >= CIR. */
} CpaUserSla;

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the rate limiting properties handle associated with a device for
 *      the service type.
 *
 * @description
 *      This function gets the rate limiting properties handle associated with
 *      a device for the given service type.
 *
 *      This function is called for a user application to discover rate limiting
 *      properties on a device of specific service type. Error code is returned
 *      if incorrect device ID or service type is called.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  devIdx                Device index from which to fetch the rate
 *                                   limiting handle.
 * @param[in]  svcType               The service type that the rate limiting
 *                                   handle is associated with.
 * @param[out] handle                Pointer to rate limiting handle or NULL if
 *                                   failed to fetch, incorrect device index
 *                                   or/and incorrect service type.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        A handle was successfully retrieved.
 * @retval CPA_STATUS_FAIL           Function failed to fetch a handle.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid device index or invalid service
 *                                   type.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaGetDevRlPropertiesHandle(Cpa16U devIdx,
                                      const CpaAccelerationServiceType svcType,
                                      CpaRlPropertiesHandle *handle,
                                      CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the number of interfaces that can be assigned an SLA with respect
 *      to a rate limiting handle.
 *
 * @description
 *      This function is used to query total number of interfaces for this
 *      service that can be assigned and the number of interfaces that are
 *      currently unassigned.
 *
 *      The value of total interfaces and remaining interfaces on a physical
 *      device are HW dependent.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                Rate limiting handle
 * @param[out] totalSlaInterfaces    Total number of interfaces that can be as-
 *                                   signed an SLA on a device with a service
 *                                   that a rate limiting handle represents.
 * @param[out] remSlaInterfaces      Number of unassigned interfaces for SLA on
 *                                   a device with a service that a rate
 *                                   limiting handle represents.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        Query the total number of interfaces and
 *                                   unassigned interfaces successfully.
 * @retval CPA_STATUS_FAIL           Function failed to query total interfaces
 *                                   and unassigned interfaces for SLA.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaRlPropGetNumInterfaces(const CpaRlPropertiesHandle handle,
                                    Cpa32U *totalSlaInterfaces,
                                    Cpa32U *remSlaInterfaces,
                                    CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the current CIR values with respect to rate limiting handle
 *
 * @description
 *      This function is used to query total CIR and remaining CIR for the
 *      service represented on a specific QAT device represented by the handle.
 *
 *      The returned value of CIRs are absolute value in Mbps or Kops. The unit
 *      is dependent on the service type as following:
 *      Sym and Dc: Mbps
 *      Asym: Kops
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                Rate limiting handle specifies a service
 *                                   on a specific QAT device.
 * @param[out] totalCir              Total CIR on a device with a service that
 *                                   a rate limiting handle represents.
 * @param[out] remCir                Remaining CIR on a device with a service
 *                                   that a rate limiting handle represents.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        CIR query on a handle successfully
 * @retval CPA_STATUS_FAIL           Function failed to query CIR on that rate
 *                                   limiting handle.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaGetDevRlPropSlaCir(const CpaRlPropertiesHandle handle,
                                Cpa32U *totalCir,
                                Cpa32U *remCir,
                                CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the current PIR values with respect to rate limiting handle
 *
 * @description
 *      This function is used to query total PIR and total assigned PIR for
 *      the service represented on a specific QAT device represented by the
 *      handle.
 *
 *      The returned value of PIR are absolute value in Mbps or Kops. The unit
 *      is dependent on the service type as following:
 *      Sym and Dc: Mbps
 *      Asym: Kops
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                Rate limiting handle specifies a service
 *                                   on a specific QAT device.
 * @param[out] totalPir              Total PIR on a device with a service that
 *                                   a rate limiting handle represents.
 * @param[out] totalAssignedPir      Total assigned PIR to QPs on a device
 *                                   with a service that a rate limiting handle
 *                                   represents.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        PIR queries on a handle successfully
 * @retval CPA_STATUS_FAIL           Function failed to query PIR on that rate
 *                                   limiting handle.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaGetDevRlPropSlaPir(const CpaRlPropertiesHandle handle,
                                Cpa32U *totalPir,
                                Cpa32U *totalAssignedPir,
                                CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get PIR setting on current instance handle.
 *
 * @description
 *      This function is used to query the PIR of an instance.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                An instance handle.
 * @param[out] pirSetting            PIR value set on selected instance.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        PIR queries on an instance successfully.
 * @retval CPA_STATUS_FAIL           Function failed to query PIR on that
 *                                   instance.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This API can only be inside the partition where the instance is assigned
 *
 *****************************************************************************/
CpaStatus cpaGetInstanceRlSlaPir(const CpaInstanceHandle handle,
                                 Cpa32U *pirSetting,
                                 CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get CIR setting on current instance handle.
 *
 * @description
 *      This function is used to query the CIR of an instance.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                An instance handle.
 * @param[out] cirSetting            CIR value set on selected instance.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        CIR queries on an instance successfully
 * @retval CPA_STATUS_FAIL           Function failed to query CIR on that
 *                                   instance.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This API can only be inside the partition where the instance is assigned
 *
 *****************************************************************************/
CpaStatus cpaGetInstanceRlSlaCir(const CpaInstanceHandle handle,
                                 Cpa32U *cirSetting,
                                 CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the number of handles associated with a device for
 *      the service type.
 *
 * @description
 *      This function gets the number of handles associated with
 *      a device for the given service type.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  devIdx                Device id to fetch the number of
 *                                   handles from.
 * @param[in]  svcType               Service type of the handles.
 * @param[out] numHandles            Number of handles associated
 *                                   with the service type.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        Number of handles fetched successfully.
 * @retval CPA_STATUS_FAIL           Failed to get the number of handles
 *                                   associated with the device for the given
 *                                   service type.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaRlGetQpNumHandles(Cpa32U devIdx,
                               CpaAccelerationServiceType svcType,
                               Cpa8U *numHandles,
                               CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the handles associated with a device for the given service type.
 *
 * @description
 *      This function gets the handles associated with a device for the given
 *      service type. These handles can then be used as input parameters with
 *      other Rate limiting API.
 *
 *      This function will populate an array that has been allocated by the
 *      caller. The size of this array is determined by the
 *      cpaGetQpNumHandles() function.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]     devIdx             Device id to fetch the handles from.
 * @param[in]     svcType            Service type of the handles to fetch.
 * @param[in/out] handles            Pointer to where the handles will be
 *                                   written.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        Handles fetched successfully.
 * @retval CPA_STATUS_FAIL           Function failed to fetch handles from
 *                                   the device of that service type.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaRlGetQpHandles(Cpa32U devIdx,
                            CpaAccelerationServiceType svcType,
                            CpaRlQpHandle *handles,
                            CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Set the SLA information on the given QP handle.
 *
 * @description
 *      This function sets the SLA information on the given QP handle.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                Handle to the QP.
 * @param[in]  sla                   SLA information to be set.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 *                                   CPA_STATUS_RL_INVALID_CIR_PIR if CIR or
 *                                   PIR requested exceeds device available
 *                                   capacity.
 *                                   CPA_STATUS_RL_FAIL_IO if failed to send
 *                                   request to hardware.
 * @retval CPA_STATUS_SUCCESS        SLA is created successfully.
 * @retval CPA_STATUS_FAIL           Function failed to set SLA on the given
 *                                   handle.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 * @retVal CPA_STATUS_RESOURCE       Error related to system resources.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaSetRlSla(CpaRlQpHandle handle,
                      CpaUserSla *sla,
                      CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Delete the SLA information associated with the handle.
 *
 * @description
 *      This function deletes the SLA information associated with the handle.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                Handle to the QP.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 *                                   CPA_STATUS_RL_SLA_NOT_CONFIGURED if SLA is
 *                                   not configured on this QP.
 *                                   CPA_STATUS_RL_FAIL_IO if failed to send
 *                                   request to hardware.
 * @retval CPA_STATUS_SUCCESS        SLA is deleted successfully.
 * @retval CPA_STATUS_FAIL           Function failed to delete SLA on that
 *                                   handle.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 * @retVal CPA_STATUS_RESOURCE       Error related to system resources.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaDeleteRlSla(CpaRlQpHandle handle, CpaRlError *rlStatus);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Get the SLA information associated with the handle.
 *
 * @description
 *      This function gets the SLA information associated with the handle.
 *
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  handle                Handle to the QP.
 * @param[out] sla                   SLA information.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_NOT_ENABLED if rate limiting
 *                                   is not enabled.
 * @retval CPA_STATUS_SUCCESS        SLA information is fetched successfully.
 * @retval CPA_STATUS_FAIL           Function failed to query SLA information
 *                                   on that instance.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 *
 * @pre
 *      Rate limiting has been enabled via cpaEnableRateLimiting() function.
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaGetRlSla(const CpaRlQpHandle handle,
                      CpaUserSla *sla,
                      CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Enable Rate limiting.
 *
 * @description
 *      This function enables rate limiting if it is not already enabled.
 *      If the rate limiting is already enabled, then the function would
 *      return successfully.
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  devIdx                Device index to enable rate limiting.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_FAIL_IO if failed to send
 *                                   request to hardware.
 * @retval CPA_STATUS_SUCCESS        Enabled rate limiting successfully.
 * @retval CPA_STATUS_FAIL           Failed to enable rate limiting.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 * @retVal CPA_STATUS_RESOURCE       Error related to system resources.
 *
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaEnableRateLimiting(Cpa32U devIdx, CpaRlError *rlError);

/**
 *****************************************************************************
 * @ingroup cpaRl
 *      Disable Rate limiting.
 *
 * @description
 *      This function disables rate limiting if it is already enabled.
 *      If the rate limiting is already disabled, then the function would
 *      return successfully.
 * @context
 *      The function shall not be called in an interrupt context.
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
 * @param[in]  devIdx                Device index to disable rate limiting.
 * @param[out] rlError               Error status of rate limiting query. This
 *                                   parameter is only valid if CPA_STATUS_FAIL
 *                                   is returned.
 *                                   CPA_STATUS_RL_FAIL_IO if failed to send
 *                                   request to hardware.
 * @retval CPA_STATUS_SUCCESS        Disabled rate limiting successfully.
 * @retval CPA_STATUS_FAIL           Failed to disable rate limiting.
 * @retval CPA_STATUS_UNSUPPORTED    Feature is not supported.
 * @retVal CPA_STATUS_RESOURCE       Error related to system resources.
 *
 * @pre
 *      None
 * @post
 *      None
 * @see
 *      None
 * @note
 *      This function can only be called from the partition that has the
 *      physical function (PF) device mapped.
 *
 *****************************************************************************/
CpaStatus cpaDisableRateLimiting(Cpa32U devIdx, CpaRlError *rlError);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_RL_H */
