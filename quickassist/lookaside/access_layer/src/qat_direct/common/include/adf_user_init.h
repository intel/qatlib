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
/******************************************************************************
 * @file adf_user_init.h
 *
 * @description
 *      This header file that contains the prototypes and definitions required
 *      for ADF userspace initialisation.
 *
 *****************************************************************************/
#ifndef ADF_USER_INIT_H
#define ADF_USER_INIT_H

#include "icp_accel_devices.h"
/**
 *****************************************************************************
 * @description
 *      This function will initialise the registered subcomponents.
 *
 *****************************************************************************/
CpaStatus adf_user_subsystemInit(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function will send a start event to the subcomponents
 *
 *****************************************************************************/
CpaStatus adf_user_subsystemStart(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function stops the registered subcomponents.
 *
 *****************************************************************************/
CpaStatus adf_user_subsystemStop(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function will shutdown the subcomponents in the system.
 *
 *****************************************************************************/
CpaStatus adf_user_subsystemShutdown(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function sends a resume event to registered subcomponents.
 *
 *****************************************************************************/
CpaStatus adf_user_subsystemResume(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function sends a suspend event to registered subcomponents.
 *
 *****************************************************************************/
CpaStatus adf_user_subsystemSuspend(icp_accel_dev_t *accel_dev);

#endif /* ADF_USER_INIT_H */
