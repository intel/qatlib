/******************************************************************************
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
 *****************************************************************************/

/**
 *****************************************************************************
 * @file adf_io_user_proxy.h
 *
 * @defgroup adf_io
 *
 * @description
 *      This file contains defines the low level API of the adf user proxy
 *      in user space.
 *
 *****************************************************************************/
#ifndef ADF_IO_USER_PROXY_H
#define ADF_IO_USER_PROXY_H

#include "cpa.h"
#include "icp_accel_devices.h"

/**
 * @ingroup adf_io
 *
 * @description
 *      This function checks if a user space process with a given name can
 *      be started and returns the name of the process to be used when calling
 *      adf_io_userProxyInit().
 *
 * @param[in] name_in       Process name that the user wants to start.
 * @param[in] name_tml_len  Size of the buffer pointed by name_in.
 * @param[out] name         Buffer containing the process name to start.
 * @param[out] name_len     Size of the buffer pointed by name.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Provided argument is invalid.
 */
CpaStatus adf_io_userProcessToStart(char const *const name_in,
                                    size_t name_tml_len,
                                    char *name,
                                    size_t name_len);
/**
 * @ingroup adf_io
 *
 * @description
 *      This function is used to initialize the io specific layer of the
 *      ADF proxy in user space.
 *      It takes a process name as a parameter. Caller should check if
 *      such process name is not already started using
 *      icp_adf_userProcessStarted function.
 *
 * @param[in] name          Process name that the user wants to start.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Provided argument is invalid.
 */
CpaStatus adf_io_userProxyInit(char const *const name);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function is used to stop the io specific layer of the
 *      ADF proxy in user space.
 */
void adf_io_userProcessStop(void);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function is used to shutdown the io specific layer of the
 *      ADF proxy in user space.
 */
void adf_io_userProxyShutdown(void);

/**
 * @ingroup adf_io
 *
 * @description
 *      This function is used to reset the data structures used by the
 *      io specific layer of the ADF proxy in user space.
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_RESOURCE       Function failed.
 */
CpaStatus adf_io_resetUserProxy(void);

/*
 * adf_io_pollProxyEvent
 *
 * Description:
 *  check if there is any event for given device id
 *
 * Returns:
 *   CPA_FALSE         there are no reported events
 *   CPA_TRUE          there are reported events
 */
CpaBoolean adf_io_pollProxyEvent(Cpa32U *dev_id, enum adf_event *event);
#endif
