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
 * @file sal_service_state.h
 *
 * @defgroup SalServiceState
 *
 * @ingroup SalCtrl
 *
 * Checks state for generic service instance
 *
 ***************************************************************************/

#ifndef SAL_SERVICE_STATE_H_
#define SAL_SERVICE_STATE_H_

/**
*******************************************************************************
* @ingroup SalServiceState
*      Check to see if the instance is in the running state
*
* @description
*      This function checks the state of an instance to see if it is in the
*      runnning state
*
* @param[in]  instance   Instance handle (assumes this is valid, i.e. checked
*                        before this function is called)
* @retval CPA_TRUE       Instance in the RUNNING state
* @retval CPA_FALSE      Instance not in RUNNING state
*
*****************************************************************************/
CpaBoolean Sal_ServiceIsRunning(CpaInstanceHandle instanceHandle);

/**
*******************************************************************************
* @ingroup SalServiceState
*      Check to see if the instance is beign restarted
*
* @description
*      This function checks the state of an instance to see if the device it
*      uses is being restarted because of hardware error.
*
* @param[in]  instance   Instance handle (assumes this is valid, i.e. checked
*                        before this function is called)
* @retval CPA_TRUE       Device the instance is using is restarting.
* @retval CPA_FALSE      Device the instance is running.
*
*****************************************************************************/
CpaBoolean Sal_ServiceIsRestarting(CpaInstanceHandle instanceHandle);

/**
*******************************************************************************
* @ingroup SalServiceState
*      Check to see if the instance is in error state
*
* @description
*      This function checks the state of an instance to see if the device it
*      uses is in an error state due to a hardware error
*
* @param[in]  instance   Instance handle (assumes this is valid, i.e. checked
*                        before this function is called)
* @retval CPA_TRUE       Device the instance is using is in error state.
* @retval CPA_FALSE      Device the instance is not in error state.
*
*****************************************************************************/
CpaBoolean Sal_ServiceIsInError(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup SalServiceState
 *      This macro checks if an instance is running. An error message is logged
 *      if it is not in a running state.
 *
 * @return CPA_STATUS_FAIL Instance not in RUNNING state.
 * @return void            Instance is in RUNNING state.
 ******************************************************************************/
#define SAL_RUNNING_CHECK(instanceHandle)                                      \
    do                                                                         \
    {                                                                          \
        if (unlikely(CPA_TRUE != Sal_ServiceIsRunning(instanceHandle)))        \
        {                                                                      \
            if (CPA_TRUE == Sal_ServiceIsRestarting(instanceHandle))           \
            {                                                                  \
                return CPA_STATUS_RESTARTING;                                  \
            }                                                                  \
            LAC_LOG_ERROR("Instance not in a Running state");                  \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup SalServiceState
 *      This macro checks if an instance is in a state to get init event.
 *
 * @return CPA_STATUS_FAIL Instance not in good state.
 * @return void            Instance is in good state.
 ******************************************************************************/
#define SAL_SERVICE_GOOD_FOR_INIT(instanceHandle)                              \
    do                                                                         \
    {                                                                          \
        sal_service_t *pService = (sal_service_t *)instanceHandle;             \
        if ((SAL_SERVICE_STATE_UNINITIALIZED != pService->state) &&            \
            (SAL_SERVICE_STATE_RESTARTING != pService->state))                 \
        {                                                                      \
            LAC_LOG_ERROR("Not in the correct state to call init\n");          \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup SalServiceState
 *      This macro checks if an instance is in a state to get restarted event.
 *
 * @return CPA_STATUS_FAIL Instance not in good state.
 * @return void            Instance is in good state.
 ******************************************************************************/
#define SAL_SERVICE_GOOD_FOR_RESTARTED(instanceHandle)                         \
    do                                                                         \
    {                                                                          \
        sal_service_t *pService = (sal_service_t *)instanceHandle;             \
        if ((SAL_SERVICE_STATE_UNINITIALIZED != pService->state) &&            \
            (SAL_SERVICE_STATE_RESTARTING != pService->state))                 \
        {                                                                      \
            LAC_LOG_ERROR("Not in the correct state to call restarted\n");     \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

#endif /* SAL_SERVICE_STATE_H_ */
