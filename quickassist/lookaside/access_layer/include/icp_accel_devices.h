/*****************************************************************************
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
 *****************************************************************************/
/*****************************************************************************
 * @file icp_accel_devices.h
 *
 * @defgroup Acceleration Driver Framework
 *
 * @ingroup icp_Adf
 *
 * @description
 *      This is the top level header file that contains the layout of the ADF
 *      icp_accel_dev_t structure and related macros/definitions.
 *      It can be used to dereference the icp_accel_dev_t *passed into upper
 *      layers.
 *
 *****************************************************************************/

#ifndef ICP_ACCEL_DEVICES_H_
#define ICP_ACCEL_DEVICES_H_

#include "cpa.h"
#include "Osal.h"

#define ADF_CFG_MAX_STR_LEN 128
#define MAX_DEVICE_NAME_SIZE 32
#define ADF_DEVICE_NAME_LENGTH 32
#define ADF_CFG_MAX_STR_LEN 128
#define ADF_CFG_MAX_KEY_LEN_IN_BYTES ADF_CFG_MAX_STR_LEN
#define ADF_CFG_MAX_VAL_LEN_IN_BYTES ADF_CFG_MAX_STR_LEN
#define ADF_CFG_MAX_SECTION_LEN_IN_BYTES ADF_CFG_MAX_STR_LEN
#define ADF_MAX_DEVICES (32 * 32)
enum dev_sku_info
{
    DEV_SKU_1 = 0,
    DEV_SKU_2,
    DEV_SKU_3,
    DEV_SKU_4,
    DEV_SKU_VF,
    DEV_SKU_UNKNOWN,
};

enum adf_event
{
    ADF_EVENT_INIT = 0,
    ADF_EVENT_START,
    ADF_EVENT_STOP,
    ADF_EVENT_SHUTDOWN,
    ADF_EVENT_RESTARTING,
    ADF_EVENT_RESTARTED,
    ADF_EVENT_ERROR,
};


#define ADF_CFG_NO_INSTANCE 0xFFFFFFFF
#define ADF_CTL_DEVICE_NAME "/dev/qat_adf_ctl"

#define ADF_DEVICE_TYPE_LENGTH 16

/**
 *****************************************************************************
 * @ingroup icp_AdfAccelHandle
 *
 * @description
 *      Accelerator capabilities
 *
 *****************************************************************************/
typedef enum
{
    ICP_ACCEL_CAPABILITIES_NULL = 0,
    ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC = 0x01,
    ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC = 0x02,
    ICP_ACCEL_CAPABILITIES_CIPHER = 0x04,
    ICP_ACCEL_CAPABILITIES_AUTHENTICATION = 0x08,
    ICP_ACCEL_CAPABILITIES_COMPRESSION = 0x20,
    ICP_ACCEL_CAPABILITIES_DEPRECATED = 0x40,
    ICP_ACCEL_CAPABILITIES_RANDOM_NUMBER = 0x80,
    ICP_ACCEL_CAPABILITIES_CRYPTO_ZUC = 0x100,
    ICP_ACCEL_CAPABILITIES_CRYPTO_SHA3 = 0x200,
    ICP_ACCEL_CAPABILITIES_RESERVED = 0x400,
    ICP_ACCEL_CAPABILITIES_RL = 0x800,
    ICP_ACCEL_CAPABILITIES_HKDF = 0x1000,
    ICP_ACCEL_CAPABILITIES_ECEDMONT = 0x2000,
    ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN = 0x4000,
    ICP_ACCEL_CAPABILITIES_SHA3_EXT = 0x8000,
    ICP_ACCEL_CAPABILITIES_AESGCM_SPC = 0x10000,
    ICP_ACCEL_CAPABILITIES_CHACHA_POLY = 0x20000,
    ICP_ACCEL_CAPABILITIES_SM2 = 0x40000,
    ICP_ACCEL_CAPABILITIES_SM3 = 0x80000,
    ICP_ACCEL_CAPABILITIES_SM4 = 0x100000,
    ICP_ACCEL_CAPABILITIES_INLINE = 0x200000,
    ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY = 0x400000,
    ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY64 = 0x800000,
    ICP_ACCEL_CAPABILITIES_LZ4_COMPRESSION = 0x1000000,
    ICP_ACCEL_CAPABILITIES_LZ4S_COMPRESSION = 0x2000000,
    ICP_ACCEL_CAPABILITIES_AES_V2 = 0x4000000,
    ICP_ACCEL_CAPABILITIES_KPT2 = 0x8000000,
} icp_accel_capabilities_t;

/**
 *****************************************************************************
 * @ingroup icp_AdfAccelHandle
 *
 * @description
 *      Device Configuration Data Structure
 *
 *****************************************************************************/
typedef enum device_type_e
{
    DEVICE_UNKNOWN = 0,
    DEVICE_DH895XCC,
    DEVICE_DH895XCCVF,
    DEVICE_C62X,
    DEVICE_C62XVF,
    DEVICE_C3XXX,
    DEVICE_C3XXXVF,
    DEVICE_D15XX,
    DEVICE_D15XXVF,
    DEVICE_200XX,
    DEVICE_200XXVF,
    DEVICE_C4XXX,
    DEVICE_C4XXXVF,
    DEVICE_4XXX,
    DEVICE_4XXXVF
} device_type_t;

/*
 * Macro for checking if given device_type_t enum value
 * belongs to QAT 4 generation.
 */
#ifdef IS_QAT_4XXX
#undef IS_QAT_4XXX
#endif
#define IS_QAT_4XXX(dev_type)                                                  \
    ({                                                                         \
        int _dt = dev_type;                                                    \
        _dt == DEVICE_4XXX || _dt == DEVICE_4XXXVF;                            \
    })

/*
 * Enumeration on Service Type
 */
typedef enum adf_service_type_s
{
    ADF_SERVICE_CRYPTO,
    ADF_SERVICE_COMPRESS,
    ADF_SERVICE_MAX /* this is always the last one */
} adf_service_type_t;

typedef struct accel_dev_s
{
    /* Some generic information */
    Cpa32U accelId;
    device_type_t deviceType;                    /* Device Type */
    char deviceName[ADF_DEVICE_TYPE_LENGTH + 1]; /* Device name for SAL */
    Cpa32U accelCapabilitiesMask; /* Accelerator's capabilities mask */
    Cpa32U dcExtendedFeatures;    /* bit field of features */
    OsalAtomic usageCounter;      /* Prevents shutting down the dev if not 0 */
    void *pSalHandle;             /* For SAL */
    void *pQatStats;              /* For QATAL/SAL stats */
    void *ringInfoCallBack;       /* Callback for user space ring enabling */
    Cpa32U adfSubsystemStatus;    /* Status of ADF and registered subsystems */
    Cpa32S numa_node; /* Physical processor to which the dev is connected */
    enum dev_sku_info sku;
    void *accel;
    Cpa32U maxNumBanks;
    Cpa32U maxNumRingsPerBank;
    void *pInstMgr; /* pointer to dynamic instance resource manager */
    void *banks;    /* banks information */
#ifdef KERNEL_SPACE
    const Cpa8U *pAccelName; /* Name given to accelerator */
    struct adf_accel_dev *accel_dev;
    struct accel_dev_s *pPrev;
    struct accel_dev_s *pNext;
#endif
    Cpa32U deviceMemAvail; /* Device memory for intermediate buffers */
    Cpa32U pciDevId;
    CpaBoolean isVf; /* Device runs on a virtual function */
    Cpa32U arb_mask;
    void *ioPriv;
} icp_accel_dev_t;

#endif /* ICP_ACCEL_HANDLE_H_ */
