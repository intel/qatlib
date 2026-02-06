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
 * @file adf_devmgr.h
 *
 * @description
 *      This is the header file for the ADF Accelerated Device Manager.
 *      This file contains function prototypes to manage and access devices.
 *
 *****************************************************************************/
#ifndef ADF_DEVMGR_H
#define ADF_DEVMGR_H

/******************************************************************************
 * Include public/global header files
 ******************************************************************************/
#include "cpa.h"
#include "icp_accel_devices.h"

/* Device get & put commands */
#define DEV_PUT_CMD 0
#define DEV_GET_CMD 1

/******************************************************************************
 * Section for interface function prototypes
 ******************************************************************************/

/******************************************************************************
 * @description
 * Add a new accelerator to the Accelerator Table
 *
 *****************************************************************************/
CpaStatus adf_devmgrAddAccelDev(icp_accel_dev_t *pAccel_dev);

/******************************************************************************
 * @description
 * Remove an accelerator structure from the Accelerator Table
 *
 *****************************************************************************/
CpaStatus adf_devmgrRemoveAccelDev(icp_accel_dev_t *pAccel_dev);

/******************************************************************************
 * @description
 * Get the head of the Accelerator Table structure
 *
 *****************************************************************************/
CpaStatus adf_devmgrGetAccelHead(icp_accel_dev_t **pAccel_dev);

/******************************************************************************
 * @description
 * Check the accel table for a structure that contains the PCI device
 * Returns a pointer to the accelerator structure or NULL if not found.
 *
 *****************************************************************************/
icp_accel_dev_t *adf_devmgrGetAccelDev(void *pdev);

/******************************************************************************
 * @description
 * Gets the accel_dev structure based on accelId
 * Returns a pointer to the accelerator structure or NULL if not found.
 *
 *****************************************************************************/
icp_accel_dev_t *adf_devmgrGetAccelDevByAccelId(Cpa32U accelId);

/******************************************************************************
 * @description
 * Checks if there is an acceleration device with the given accelId
 * in the system
 *
 *****************************************************************************/
CpaStatus adf_devmgrVerifyAccelId(Cpa32U accelId);

/******************************************************************************
 * @description
 *
 * Initialise that accel table
 *****************************************************************************/
CpaStatus adf_devmgrInit(void);

/******************************************************************************
 * @description
 *
 * Uninitialise that accel table
 *****************************************************************************/
void adf_devmgrExit(void);

#endif /* ADF_DEVMGR_H */
