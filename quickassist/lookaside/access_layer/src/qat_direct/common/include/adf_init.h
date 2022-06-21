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
 * @file adf_init.h
 *
 * @description
 *      This header file that contains the prototypes and definitions required
 *      for ADF initialisation.
 *
 *****************************************************************************/
#ifndef ADF_INIT_H
#define ADF_INIT_H

#include "icp_accel_devices.h"

/*
 * Initialisation value for the adfModuleId, a value of 0 implies ADF has
 * not registered the version information with the DCC component.
 */
#define VERSION_INFO_UNREGISTERED 0

/*
 * This macro sets the specified bit in status to 1
 * i.e. set the bit
 */
#define SET_STATUS_BIT(status, bit) status |= (1 << bit)

/*
 * This macro sets the specified bit in status to 0
 * i.e. clears the bit
 */
#define CLEAR_STATUS_BIT(status, bit) status &= ~(1 << bit)

/*
 * This macro checks if the specified bit in status is set or not.
 */
#define BIT_IS_SET(status, bit) (status & (1 << bit))

/*
 * Pending time in ms that ADF will sleep before sending shutdown
 * when a subsystem return pending on stop
 */
#define PENDING_DELAY 100

/**
 *****************************************************************************
 * @description
 *      This function will initialise the AEs, map the firmware,
 *      send an init event to the subservice and call adf_subsystemStart.
 *
 *****************************************************************************/
CpaStatus adf_subsystemInit(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function will download the Ucode, start the AEs and send
 *      a start event to the subservices
 *
 *****************************************************************************/
CpaStatus adf_subsystemStart(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function will load the firmware, patch the previously loaded
 *      symbols and send a start event to the subservices
 *
 *****************************************************************************/
CpaStatus adf_subsystemResume(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function will stop the subcomponents in the system,
 *      and free resources for ISR and firmware loading that have been allocated
 *
 *****************************************************************************/
CpaStatus adf_subsystemStop(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This is a wrapper function to adf_subsystemStop called when the OS
 *      issues a suspend.
 *
 *****************************************************************************/
CpaStatus adf_subsystemSuspend(icp_accel_dev_t *accel_dev);

/**
 *****************************************************************************
 * @description
 *      This function will shutdown the subcomponents in the system.
 *
 *****************************************************************************/
CpaStatus adf_subsystemShutdown(icp_accel_dev_t *accel_dev);

#endif /* ADF_INIT_H */
