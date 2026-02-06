/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef QAT_MGR_H
#define QAT_MGR_H

#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>
#include "icp_sal_versions.h"
#include "icp_accel_devices.h"
#include "adf_pfvf_proto.h"
#include "adf_io_bundles.h"

/* The running qatlib/qatmgr pair must be from the same package.
 * There's no requirement for backwards compatibility if
 * versions are different. As all requests are initiated
 * by qatlib only qatmgr should need to check the version in hdr.
 * However checking is done in qatlib to catch incompatibilities if paired
 * with an earlier qatmgr version created before this check was added.
 *
 * Note, this is a 16-bit representation of the QAT_LIBRARY_VERSION for
 * ease of sharing across the socket interface and it intentionally leaves
 * out the patch number as changes that are significant enough to make the
 * qatlib/qatmgr pair incompatible should not be done in a patch release.
 */
#define THIS_LIB_VERSION                                                       \
    (uint16_t)((QAT_LIBRARY_VERSION_MAJOR << 8) +                 \
               QAT_LIBRARY_VERSION_MINOR)
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
#define QATMGR_MSGTYPE_RESERVED 6
#define QATMGR_MSGTYPE_INSTANCE_INFO 7
#define QATMGR_MSGTYPE_INSTANCE_NAME 8
#define QATMGR_MSGTYPE_VFIO_FILE 9
#define QATMGR_MSGTYPE_NUM_PF_DEVS 10
#define QATMGR_MSGTYPE_PF_DEV_INFO 11
#define QATMGR_MSGTYPE_UNKNOWN 998
#define QATMGR_MSGTYPE_BAD 999

#define QATMGR_MAX_STRLEN 256
#define DEVICE_NAME_SIZE 64
#define VFIO_FILE_SIZE 32
#define MAX_INSTANCES 16
#define MAX_SERVICES 5
#define RPS_PER_4XXX_VF 4
#define INSTANCES_PER_DEVICE RPS_PER_4XXX_VF
#define VM_PACKAGE_ID_NONE 0xFFFF
#ifndef MAX
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#endif
#define MAX_PAYLOAD_SIZE                                                       \
    MAX(sizeof(struct qatmgr_msg_req), sizeof(struct qatmgr_msg_rsp))

#define MAX_DEVS 512

/* Below definitions are dependent on kernel drivers for creating the same
 * mapping
 */
#define RING_PAIR_SHIFT 3
#define SVC_MASK 0x7
#define CFG_SERV_RING_PAIR_0_SHIFT 0
#define CFG_SERV_RING_PAIR_1_SHIFT 3
#define CFG_SERV_RING_PAIR_2_SHIFT 6
#define CFG_SERV_RING_PAIR_3_SHIFT 9

#ifndef ENABLE_DC
#define DEFAULT_RING_TO_SRV_MAP                                                \
    (ASYM | SYM << CFG_SERV_RING_PAIR_1_SHIFT |                                \
     ASYM << CFG_SERV_RING_PAIR_2_SHIFT | SYM << CFG_SERV_RING_PAIR_3_SHIFT)
#else
#define DEFAULT_RING_TO_SRV_MAP                                                \
    (COMP | DECOMP << CFG_SERV_RING_PAIR_1_SHIFT |                             \
     COMP << CFG_SERV_RING_PAIR_2_SHIFT |                                      \
     DECOMP << CFG_SERV_RING_PAIR_3_SHIFT)
#endif
#define DC_ONLY_RING_TO_SRV_MAP                                                \
    (COMP | COMP << CFG_SERV_RING_PAIR_1_SHIFT |                               \
     COMP << CFG_SERV_RING_PAIR_2_SHIFT | COMP << CFG_SERV_RING_PAIR_3_SHIFT)

#define INTEL_VENDOR_ID 0x8086
#define MAX_NUM_CONCURRENT_REQUEST 512
#define PF_INFO_UNINITIALISED (-1)
#define ADDITIONAL_BUF_LEN 2
#define STR_FORMAT_SPECIFIER_LEN 4
#define NUM_STR_FORMAT_SPECIFIER 2

extern char *device_names[];
extern int device_names_size;

/* enum must be in alignment with the one defined by the kernel drivers */
enum cfg_service_type
{
    UNUSED = 0,
    CRYPTO,
    COMP,
    SYM,
    ASYM,
    DECOMP,
    USED

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
        /* QATMGR_MSGTYPE_NUM_PF_DEVS */
        /* No data */

        /* QATMGR_MSYPE_SECTION_GET */
        char name[QATMGR_MAX_STRLEN];

        /* QATMGR_MSGTYPE_DEVICE_INFO */
        /* QATMGR_MSGTYPE_DEVICE_ID */
        /* QATMGR_MSGTYPE_VFIO_FILE */
        /* QATMGR_MSGTYPE_PF_DEV_INFO */
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

struct fw_caps_qat
{
    uint16_t comp_algos;
    uint16_t cksum_algos;
    uint32_t deflate_caps;
    uint16_t lz4_caps;
    uint16_t lz4s_caps;
    uint8_t is_fw_caps;
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

        union {
            /* QATMGR_MSGTYPE_VFIO_FILE*/
            struct
            {
                int16_t fd;
                char name[QATMGR_MAX_STRLEN];
            } vfio_file;
        };

        /* QATMGR_MSGTYPE_NUM_DEVICES */
        /* QATMGR_MSGTYPE_NUM_PF_DEVS */
        uint16_t num_devices;

        /* QATMGR_MSGTYPE_DEVICE_INFO */
        struct
        {
            uint16_t device_num;
            uint16_t device_type;
            uint16_t device_pci_id;
            uint32_t capability_mask;
            uint32_t extended_capabilities;
            struct fw_caps_qat fw_caps;
            uint16_t max_banks;
            uint16_t max_rings_per_bank;
            uint16_t arb_mask;
            uint16_t ring_mode;
            uint16_t services;
            int16_t pkg_id;
            uint16_t node_id;
            uint16_t num_cy_instances;
            uint16_t num_sym_instances;
            uint16_t num_asym_instances;
            uint16_t num_dc_instances;
            uint16_t num_decomp_instances;
            char device_name[DEVICE_NAME_SIZE];
        } device_info;

        /* QATMGR_MSGTYPE_DEVICE_ID */
        char device_id[QATMGR_MAX_STRLEN];

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
                struct ring_info decomp;
            };
            /* For Sym, Asym, Dc or Decomp IsPolled */
            int is_polled;
        } instance_info;

        /* QATMGR_MSGTYPE_PF_DEV_INFO */
        icp_accel_pf_info_t pf_info;
    };
};

struct qatmgr_section_data
{
    char section_name[QATMGR_MAX_STRLEN];
    char base_name[QATMGR_MAX_STRLEN];
    unsigned long assigned_id;
    int num_devices;
    struct qatmgr_device_data *device_data;
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
    uint16_t ring_mode;
    uint64_t accel_capabilities;
    uint64_t extended_capabilities;
    struct fw_caps_qat fw_caps;
    int device_type;
    uint16_t pci_id;
    /* PF index, describes which device it comes from */
    int16_t pkg_id;
    uint16_t services;
    /* This includes all cy instances whether asym-only, sym-only or sym+asym */
    int num_cy_inst;
    int num_sym_inst;
    int num_asym_inst;
    /* dc-only, decomp only or dc+decomp */
    int num_dc_inst;
    int num_decomp_inst;
    struct qatmgr_instance_data *dc_instance_data;
    struct qatmgr_instance_data *decomp_instance_data;
    struct qatmgr_cy_instance_data *cy_instance_data;
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
    union {
        char vfio_file[VFIO_FILE_SIZE];
    };
    int group_fd;
    unsigned devid;
    int numa_node;
};

struct qatmgr_cpu_data
{
    int idx;
    int *cpu;
    int cores_in_node;
};

/* Cache of PF capabilities */
struct pf_capabilities
{
    uint32_t pf;
    uint32_t ext_dc_caps;
    uint32_t capabilities;
    struct fw_caps fw_caps;
    uint32_t ring_to_svc_map;
    struct pf_capabilities *next;
};

struct qatmgr_transport
{
    int (*adf_build_sconfig)(void);
    bool (*qat_mgr_is_dev_available)(void);
    int (*adf_create_accel)(icp_accel_dev_t *accel_dev,
                            int dev_id,
                            struct qatmgr_transport *t_mgr);
    int (*adf_reinit_accel)(icp_accel_dev_t *accel_dev,
                            int dev_id,
                            struct qatmgr_transport *t_mgr);
    void (*adf_free_bundle)(struct adf_io_user_bundle *bundle);
    int (*adf_populate_bundle)(icp_accel_dev_t *accel_dev,
                               struct adf_io_user_bundle *bundle);
    void (*adf_destroy_accel)(icp_accel_dev_t *accel_dev);
    CpaBoolean (*adf_io_poll_proxy_event)(Cpa32U *dev_id, enum adf_event *event);
};

int qatmgr_query(struct qatmgr_msg_req *req,
                 struct qatmgr_msg_rsp *rsp,
                 uint16_t type);
int qatmgr_open(void);
int qatmgr_close(void);

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define BDF_DOMAIN(bdf) (bdf >> 16)
#define BDF_BUS(bdf) (bdf >> 8 & 0xFF)
#define BDF_DEV(bdf) (bdf >> 3 & 0x1F)
#define BDF_FUN(bdf) (bdf & 0x7)
/* This is the PF BDF shifted >>8 and used as an index for hashing and for
 * capability caching.
 */
#define PF(bdf) (BDF_BUS(bdf) + (BDF_DOMAIN(bdf) << 8))
#define GET_BDF(domain, bus, dev, func)                                        \
    ((domain << 16) + ((0xFF & bus) << 8) + ((0x1F & dev) << 3) + (0x07 & func))

void qat_mgr_cleanup_cfg(void);
int qat_mgr_get_vfio_dev_list(unsigned *num_devices,
                              struct qatmgr_dev_data *dev_list,
                              const unsigned list_size,
                              int keep_fd);

int qat_mgr_vfio_build_data(const struct qatmgr_dev_data dev_list[],
                            const int num_devices,
                            int policy,
                            int static_cfg);

bool qat_mgr_is_vfio_dev_available(void);

int handle_message(struct qatmgr_msg_req *req,
                   struct qatmgr_msg_rsp *rsp,
                   char **section_name,
                   unsigned long id,
                   int *index);

int release_section(int index, unsigned long id, char *name, size_t name_len);
int init_section_data_mutex(void);
int destroy_section_data_mutex(void);

int open_file_with_link_check(const char *filename, int flags);
DIR *open_dir_with_link_check(const char *dirname);
int is_qat_device(unsigned device_id);
int init_cpu_data();
void free_cpu_data();
struct pf_capabilities *find_pf_capabilities(uint32_t pf);
void add_pf_capabilities(struct pf_capabilities *caps);
char *qat_device_name(int device_id);
int qat_device_type(int device_id);
int get_num_instances(struct qatmgr_device_data *device,
                      const unsigned devid,
                      const uint32_t ring_to_svc_map,
                      const uint16_t num_instances);
int calculate_bank_number(const enum cfg_service_type instance_service,
                          const int inst_idx,
                          const uint32_t ring_to_svc_map,
                          const uint16_t num_instances);
int get_core_affinity(int node);

void qatmgr_transport_init(void);
void set_num_pfs(int32_t num_pf_devices);
int32_t get_num_pfs(void);
void set_num_section_data(int num_sec_data);
void set_section_data(struct qatmgr_section_data *sec_data);
struct qatmgr_transport *get_transport_mgr(void);
int adf_vfio_build_sconfig(void);
int adf_vfio_create_accel(icp_accel_dev_t *accel_dev,
                          int dev_id,
                          struct qatmgr_transport *t_mgr);
int adf_vfio_reinit_accel(icp_accel_dev_t *accel_dev,
                          int dev_id,
                          struct qatmgr_transport *t_mgr);
void adf_vfio_free_bundle(struct adf_io_user_bundle *bundle);
int adf_vfio_populate_bundle(icp_accel_dev_t *accel_dev,
                             struct adf_io_user_bundle *bundle);
void adf_vfio_destroy_accel(icp_accel_dev_t *accel_dev);
CpaBoolean adf_vfio_poll_proxy_event(Cpa32U *dev_id, enum adf_event *event);
#endif /* QAT_MGR_H */
