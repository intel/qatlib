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
 * @file cpa_dev.h
 *
 * @defgroup cpaDev Device API
 *
 * @ingroup cpa
 *
 * @description
 *      These functions specify the API for device level operation.
 *
 * @remarks
 *
 *
 *****************************************************************************/

#ifndef CPA_DEV_H
#define CPA_DEV_H

#ifdef __cplusplus
extern"C" {
#endif


#ifndef CPA_H
#include "cpa.h"
#endif


 /*****************************************************************************
 * @ingroup cpaDev
 *      Returns device information
 *
 * @description
 *      This data structure contains the device information. The device
 *      information are available to both Physical and Virtual Functions.
 *      Depending on the resource partitioning configuration, the services
 *      available may changes. This configuration will impact the size of the
 *      Security Association Database (SADB). Other properties such device SKU
 *      and device ID are also reported.
 *
 *****************************************************************************/
typedef struct _CpaDeviceInfo {
	Cpa32U sku;
	/**< Identifies the SKU of the device. */
	Cpa16U bdf;
	/**< Identifies the Bus Device Function of the device.
	 *   Format is reported as follow:
	 *   - bits<2:0> represent the function number.
	 *   - bits<7:3> represent the device
	 *   - bits<15:8> represent the bus
	 */
	Cpa32U deviceId;
	/**< Returns the device ID. */
	Cpa32U numaNode;
	/**< Return the local NUMA node mapped to the device. */
	CpaBoolean isVf;
	/**< Return whether the device is currently used in a virtual function
	 *   or not. */
	CpaBoolean dcEnabled;
    /**< Compression service enabled */
	CpaBoolean cySymEnabled;
    /**< Symmetric crypto service enabled */
	CpaBoolean cyAsymEnabled;
    /**< Asymmetric crypto service enabled */
	CpaBoolean inlineEnabled;
    /**< Inline service enabled */
	Cpa32U deviceMemorySizeAvailable;
	/**< Return the size of the device memory available. This device memory
	 *   section could be used for the intermediate buffers in the
	 *   compression service.
	 */
} CpaDeviceInfo;


/*****************************************************************************
* @ingroup cpaDev
*      Returns number devices.
*
* @description
*      This API returns the number of devices available to the application.
*      If used on the host, it will return the number of physical devices.
*      If used on the guest, it will return the number of function mapped
*      to the virtual machine.
*
*****************************************************************************/
CpaStatus cpaGetNumDevices (Cpa16U *numDevices);

/*****************************************************************************
* @ingroup cpaDev
*      Returns device information for a given device index.
*
* @description
*      Returns device information for a given device index. This API must
*      be used with cpaGetNumDevices().
*****************************************************************************/
CpaStatus cpaGetDeviceInfo (Cpa16U device, CpaDeviceInfo *deviceInfo);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_DEV_H */
