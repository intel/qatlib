/******************************************************************************
 *
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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

#ifndef ADF_H_
#define ADF_H_

#include <linux/ioctl.h>
#define ADF_CFG_MAX_STR_LEN 128
#define MAX_DEVICE_NAME_SIZE 32
#define ADF_DEVICE_NAME_LENGTH 32
#define ADF_CFG_MAX_KEY_LEN_IN_BYTES ADF_CFG_MAX_STR_LEN
#define ADF_CFG_MAX_VAL_LEN_IN_BYTES ADF_CFG_MAX_STR_LEN
#define ADF_CFG_MAX_SECTION_LEN_IN_BYTES ADF_CFG_MAX_STR_LEN
#define ADF_MAX_DEVICES (32 * 32)

enum adf_device_heartbeat_status
{
    DEV_HB_UNRESPONSIVE = 0,
    DEV_HB_ALIVE,
    DEV_HB_UNSUPPORTED
};

struct adf_dev_heartbeat_status_ctl
{
    uint32_t device_id;
    enum adf_device_heartbeat_status status;
};

#define ADF_CTL_IOC_MAGIC 'a'
#define IOCTL_GET_NUM_DEVICES _IOW(ADF_CTL_IOC_MAGIC, 4, int32_t)
#define IOCTL_HEARTBEAT_ACCEL_DEV                                              \
    _IOW(ADF_CTL_IOC_MAGIC, 15, struct adf_dev_heartbeat_status_ctl)
#ifdef QAT_HB_FAIL_SIM
#define IOCTL_HEARTBEAT_SIM_FAIL _IOW(ADF_CTL_IOC_MAGIC, 99, uint32_t)
#endif

#define IOCTL_STATUS_ACCEL_DEV _IOW(ADF_CTL_IOC_MAGIC, 3, uint32_t)
#define IOCTL_GET_CFG_VAL                                                      \
    _IOW(ADF_CTL_IOC_MAGIC, 5, struct adf_user_cfg_ctl_data)
#define IOCTL_RESET_ACCEL_DEV                                                  \
    _IOW(ADF_CTL_IOC_MAGIC, 10, struct adf_user_cfg_ctl_data)

enum adf_cfg_val_type
{
    ADF_DEC,
    ADF_HEX,
    ADF_STR
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

enum adf_device_type
{
    DEV_UNKNOWN = 0,
    DEV_DH895XCC,
    DEV_DH895XCCVF,
    DEV_C62X,
    DEV_C62XVF,
    DEV_C3XXX,
    DEV_C3XXXVF,
    DEV_D15XX,
    DEV_D15XXVF
};

enum dev_sku_info
{
    DEV_SKU_1 = 0,
    DEV_SKU_2,
    DEV_SKU_3,
    DEV_SKU_4,
    DEV_SKU_VF,
    DEV_SKU_UNKNOWN,
};

struct adf_dev_status_info
{
    enum adf_device_type type;
    uint32_t accel_id;
    uint32_t instance_id;
#ifdef QAT_UIO
    uint32_t kpt_achandle;
#endif
    uint8_t num_ae;
    uint8_t num_accel;
    uint8_t num_logical_accel;
    uint8_t banks_per_accel;
    uint8_t state;
    uint8_t bus;
    uint8_t dev;
    uint8_t fun;
    char name[MAX_DEVICE_NAME_SIZE];
    uint32_t node_id;
    int domain;
};

struct adf_user_cfg_key_val
{
    char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
    char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
    union {
        struct adf_user_cfg_key_val *next;
        uint64_t padding3;
    };
    enum adf_cfg_val_type type;
};

struct adf_user_cfg_section
{
    char name[ADF_CFG_MAX_SECTION_LEN_IN_BYTES];
    union {
        struct adf_user_cfg_key_val *params;
        uint64_t padding1;
    };
    union {
        struct adf_user_cfg_section *next;
        uint64_t padding3;
    };
};

struct adf_user_cfg_ctl_data
{
    union {
        struct adf_user_cfg_section *config_section;
        uint64_t padding;
    };
    uint32_t device_id;
};

static inline const char *get_sku_info(enum dev_sku_info info)
{
    switch (info)
    {
        case DEV_SKU_1:
            return "SKU1";
        case DEV_SKU_2:
            return "SKU2";
        case DEV_SKU_3:
            return "SKU3";
        case DEV_SKU_4:
            return "SKU4";
        case DEV_SKU_VF:
            return "SKUVF";
        case DEV_SKU_UNKNOWN:
        default:
            break;
    }
    return "Unknown SKU";
}

#endif
