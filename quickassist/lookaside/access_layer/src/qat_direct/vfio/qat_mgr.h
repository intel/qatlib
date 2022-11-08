/***************************************************************************
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
 ***************************************************************************/
#ifndef QAT_MGR_H
#define QAT_MGR_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "icp_sal_versions.h"

/* The running qatlib/qatmgr pair must be from the same package.
 * There's no requirement for backwards compatibility if
 * versions are different. As all requests are initiated
 * by qatlib only qatmgr should need to check the version in hdr.
 * However checking is done in qatlib to catch incompatibilities if paired
 * with an earlier qatmgr version created before this check was added.
 */
#define THIS_LIB_VERSION                                                       \
    (uint16_t)((SAL_INFO2_DRIVER_SW_VERSION_MAJ_NUMBER << 8) +                 \
               SAL_INFO2_DRIVER_SW_VERSION_MIN_NUMBER)
#define VER_STR_LEN 12
#define VER_STR(n, str) (snprintf(str, VER_STR_LEN, "%d.%d", n >> 8, n & 0xff))

/* Socket interface to the QAT manager */
#define QATMGR_SOCKET "/run/qat/qatmgr.sock"

/* Message types */
#define QATMGR_MSGTYPE_SECTION_GET 1
#define QATMGR_MSGTYPE_SECTION_PUT 2
#define QATMGR_MSGTYPE_NUM_DEVICES 3
#define QATMGR_MSGTYPE_DEVICE_INFO 4
#define QATMGR_MSGTYPE_DEVICE_ID 5
#define QATMGR_MSGTYPE_SECTION_INFO 6
#define QATMGR_MSGTYPE_INSTANCE_INFO 7
#define QATMGR_MSGTYPE_INSTANCE_NAME 8
#define QATMGR_MSGTYPE_VFIO_FILE 9
#define QATMGR_MSGTYPE_UNKNOWN 998
#define QATMGR_MSGTYPE_BAD 999

#define QATMGR_MAX_STRLEN 256
#define DEVICE_NAME_SIZE 64
#define MAX_INSTANCES 16
#define MAX_SERVICES 4
#define BIT(n) (1 << n)
#ifndef MAX
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#endif
#define MAX_PAYLOAD_SIZE                                                       \
    MAX(sizeof(struct qatmgr_msg_req), sizeof(struct qatmgr_msg_rsp))

enum serv_type
{
    SERV_TYPE_DC = BIT(0),
    SERV_TYPE_SYM = BIT(1),
    SERV_TYPE_ASYM = BIT(2),
    SERV_TYPE_CY = (BIT(1) + BIT(2)),
};

struct qatmgr_msg_hdr
{
    uint16_t len;
    uint16_t version;
    uint16_t type;
    uint16_t filler;
};

struct qatmgr_msg_req
{
    struct qatmgr_msg_hdr hdr;
    union {
        /* QATMGR_MSGTYPE_SECTION_PUT */
        /* QATMGR_MSGTYPE_NUM_DEVICES */
        /* QATMGR_MSTYPEQ_SECTION_INFO */
        /* No data */

        /* QATMGR_MSYPE_SECTION_GET */
        char name[QATMGR_MAX_STRLEN];

        /* QATMGR_MSGTYPE_DEVICE_INFO */
        /* QATMGR_MSGTYPE_DEVICE_ID */
        /* QATMGR_MSGTYPE_VFIO_FILE*/
        uint16_t device_num;

        /* QATMGR_MSGTYPE_INSTANCE_INFO */
        /* QATMGR_MSGTYPE_INSTANCE_NAME */
        struct
        {
            enum serv_type type;
            uint16_t num;
            uint16_t device_num;
        } inst;
    };
};

struct ring_info
{
    uint16_t accelid;
    uint16_t bank_number;
    uint16_t is_polled;
    uint16_t core_affinity;
    uint16_t num_concurrent_requests;
    uint16_t ring_tx;
    uint16_t ring_rx;
};

struct qatmgr_msg_rsp
{
    struct qatmgr_msg_hdr hdr;
    union {
        /* QATMGR_MSGTYPE_UNKNOWN */
        /* QATMGR_MSGTYPE_SECTION_PUT */
        /* No data */

        /* QATMGR_MSGTYPE_BAD */
        char error_text[QATMGR_MAX_STRLEN];

        /* QATMGR_MSGTYPE_SECTION_GET */
        /* QATMGR_MSGTYPE_INSTANCE_NAME */
        char name[QATMGR_MAX_STRLEN];

        /* QATMGR_MSGTYPE_VFIO_FILE*/
        struct
        {
            int16_t fd;
            char name[QATMGR_MAX_STRLEN];
        } vfio_file;

        /* QATMGR_MSGTYPE_NUM_DEVICES */
        uint16_t num_devices;

        /* QATMGR_MSGTYPE_DEVICE_INFO */
        struct
        {
            uint16_t device_num;
            uint16_t device_type;
            uint16_t device_pci_id;
            uint32_t capability_mask;
            uint32_t extended_capabilities;
            uint16_t max_banks;
            uint16_t max_rings_per_bank;
            uint16_t arb_mask;
            uint16_t services;
            uint16_t pkg_id;
            uint16_t node_id;
            char device_name[DEVICE_NAME_SIZE];
        } device_info;

        /* QATMGR_MSGTYPE_DEVICE_ID */
        char device_id[QATMGR_MAX_STRLEN];

        /* QATMGR_MSGTYPE_SECTION_INFO */
        struct
        {
            uint16_t num_cy_instances;
            uint16_t num_dc_instances;
        } section_info;

        /* QATMGR_MSGTYPE_INSTANCE_INFO */
        struct
        {
            union {
                struct
                {
                    struct ring_info sym;
                    struct ring_info asym;
                } cy;
                struct ring_info dc;
            };
        } instance_info;
    };
};

struct qatmgr_section_data
{
    char section_name[QATMGR_MAX_STRLEN];
    char base_name[QATMGR_MAX_STRLEN];
    pthread_t assigned_tid;
    int num_devices;
    int num_cy_inst;
    int num_sym_inst;
    int num_asym_inst;
    int num_dc_inst;
    struct qatmgr_device_data *device_data;
    struct qatmgr_instance_data *dc_instance_data;
    struct qatmgr_cy_instance_data *cy_instance_data;
};

struct qatmgr_device_data
{
    char device_id[DEVICE_NAME_SIZE];   /* BDF or mdev uuid */
    char device_file[DEVICE_NAME_SIZE]; /* /dev/vfio/<n> */
    int group_fd;
    int accelid;
    char name[DEVICE_NAME_SIZE];
    int node;
    int max_banks;
    int max_rings_per_bank;
    int arb_mask;
    uint64_t accel_capabilities;
    uint64_t extended_capabilities;
    int device_type;
    uint16_t pci_id;
    uint16_t services;
};

struct qatmgr_instance_data
{
    char name[QATMGR_MAX_STRLEN];
    int accelid;
    enum serv_type service_type;
    int bank_number;
    int ring_tx;
    int ring_rx;
    int is_polled;
    int num_concurrent_requests;
    int core_affinity;
};

struct qatmgr_cy_instance_data
{
    struct qatmgr_instance_data asym;
    struct qatmgr_instance_data sym;
};

struct qatmgr_dev_data
{
    unsigned bdf;
    char vfio_file[32];
    int group_fd;
    unsigned devid;
};

int qatmgr_query(struct qatmgr_msg_req *req,
                 struct qatmgr_msg_rsp *rsp,
                 uint16_t type);
int qatmgr_open(void);
int qatmgr_close(void);

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define BDF_NODE(bdf) (bdf >> 16)
#define BDF_BUS(bdf) (bdf >> 8 & 0xFF)
#define BDF_DEV(bdf) (bdf >> 3 & 0x1F)
#define BDF_FUN(bdf) (bdf & 0x7)

void qat_mgr_cleanup_cfg(void);
int qat_mgr_get_dev_list(unsigned *num_devices,
                         struct qatmgr_dev_data *dev_list,
                         const unsigned list_size,
                         int keep_fd);

int qat_mgr_build_data(const struct qatmgr_dev_data dev_list[],
                       const int num_devices,
                       int policy,
                       int static_cfg);

bool qat_mgr_is_dev_available(void);

int handle_message(struct qatmgr_msg_req *req,
                   struct qatmgr_msg_rsp *rsp,
                   char **section_name,
                   pid_t tid,
                   int *index);

int release_section(int index, pthread_t tid, char *name, size_t name_len);
int init_section_data_mutex(void);
int destroy_section_data_mutex(void);

#endif /* QAT_MGR_H */
