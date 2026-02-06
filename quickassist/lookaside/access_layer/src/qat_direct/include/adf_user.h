/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef ADF_USER_H

#define ADF_USER_H

#include "adf_io_bundles.h"

#include <linux/ioctl.h>
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

enum adf_cfg_val_type
{
    ADF_DEC,
    ADF_HEX,
    ADF_STR
};

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

struct adf_dev_miscellaneous_stats
{
    uint64_t misc_counter;
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

struct adf_dev_status_info
{
    enum adf_device_type type;
    uint32_t accel_id;
    uint32_t instance_id;
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

int32_t adf_init_devices(void);
CpaStatus adf_proxy_get_devices(void);
int32_t adf_cleanup_devices(void);

#endif /* end of include guard: ADF_USER_H */
