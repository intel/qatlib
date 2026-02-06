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

#endif /* ADF_USER_INIT_H */
