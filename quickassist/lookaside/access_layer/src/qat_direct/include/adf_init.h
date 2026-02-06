/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
