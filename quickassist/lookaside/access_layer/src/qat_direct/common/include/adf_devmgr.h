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
