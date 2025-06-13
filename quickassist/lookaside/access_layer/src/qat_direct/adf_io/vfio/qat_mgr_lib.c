/*****************************************************************************
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
#include <sys/sysinfo.h>
#include <numa.h>

#include "icp_platform.h"
#include "qat_log.h"
#include "qat_mgr.h"
#include "adf_vfio_pf.h"
#include <sys/stat.h>

#define QAT_4XXXVF_DEVICE_ID 0x4941
#define QAT_4XXX_DEVICE_ID 0x4940
#define QAT_401XXVF_DEVICE_ID 0x4943
#define QAT_402XXVF_DEVICE_ID 0x4945
#define QAT_402XX_DEVICE_ID 0x4944
#define QAT_420XXVF_DEVICE_ID 0x4947
#define QAT_420XX_DEVICE_ID 0x4946

#define ADDITIONAL_BUF_LEN 2

#define STATIC static

STATIC struct qatmgr_section_data *section_data = NULL;
STATIC int num_section_data = 0;
icp_accel_pf_info_t pf_data[ADF_MAX_PF_DEVICES] = { 0 };
STATIC int32_t num_pfs = PF_INFO_UNINITIALISED;
static struct qatmgr_cpu_data *cpu_data = NULL;
static int num_nodes = 0;
static int num_cpus = 0;

STATIC pthread_mutex_t section_data_mutex;
/* message name within array should live at index determined by its
 * allocated memory */
static const char *qatmgr_msgtype_str[] = {
    "QATMGR_MSGTYPE_UNKNOWN",       /* string for unknown msg*/
    "QATMGR_MSGTYPE_SECTION_GET",   /* string for get section msg*/
    "QATMGR_MSGTYPE_SECTION_PUT",   /* string for put section msg*/
    "QATMGR_MSGTYPE_NUM_DEVICES",   /* string for num devices msg*/
    "QATMGR_MSGTYPE_DEVICE_INFO",   /* string for device info msg*/
    "QATMGR_MSGTYPE_DEVICE_ID",     /* string for device id msg*/
    "QATMGR_MSGTYPE_RESERVED",      /* string for reserved msg*/
    "QATMGR_MSGTYPE_INSTANCE_INFO", /* string for instance info msg*/
    "QATMGR_MSGTYPE_INSTANCE_NAME", /* string for instance name msg*/
    "QATMGR_MSGTYPE_VFIO_FILE",     /* string for vfio file path msg*/
    "QATMGR_MSGTYPE_NUM_PF_DEVS  ", /* string for pf number msg*/
    "QATMGR_MSGTYPE_PF_DEV_INFO",   /* string for pf device info msg*/
};

#define QATMGR_MSGTYPES_STR_MAX                                                \
    (sizeof(qatmgr_msgtype_str) / sizeof(qatmgr_msgtype_str[0]) - 1)

char *device_names[] = { "4xxx", "420xx" };
int device_names_size = sizeof(device_names) / sizeof(device_names[0]);

struct pf_capabilities *pf_capabilities_head = NULL;

int32_t get_num_pfs(void)
{
    return num_pfs;
}

void set_num_pfs(int32_t num_pf_devices)
{
    num_pfs = num_pf_devices;
}

void set_num_section_data(int num_sec_data)
{
    num_section_data = num_sec_data;
}

void set_section_data(struct qatmgr_section_data *sec_data)
{
    section_data = sec_data;
}

struct pf_capabilities *find_pf_capabilities(uint32_t pf)
{
    struct pf_capabilities *current = pf_capabilities_head;
    while (current)
    {
        if (current->pf == pf)
            return current;

        current = current->next;
    }

    return NULL;
}

void add_pf_capabilities(struct pf_capabilities *caps)
{
    caps->next = pf_capabilities_head;
    pf_capabilities_head = caps;
}

static void cleanup_capabilities_cache()
{
    struct pf_capabilities *current = pf_capabilities_head;
    struct pf_capabilities *next;

    while (current)
    {
        next = current->next;
        free(current);
        current = next;
    }

    pf_capabilities_head = NULL;
}

int is_qat_device(int device_id)
{
    switch (device_id)
    {
        case QAT_4XXXVF_DEVICE_ID:
        case QAT_4XXX_DEVICE_ID:
        case QAT_401XXVF_DEVICE_ID:
        case QAT_402XXVF_DEVICE_ID:
        case QAT_402XX_DEVICE_ID:
        case QAT_420XXVF_DEVICE_ID:
        case QAT_420XX_DEVICE_ID:
            return 1;
        default:
            return 0;
    }
    return 0;
}

int qat_device_type(int device_id)
{
    switch (device_id)
    {
        case QAT_4XXXVF_DEVICE_ID:
        case QAT_401XXVF_DEVICE_ID:
        case QAT_402XXVF_DEVICE_ID:
            return DEVICE_4XXXVF;
        case QAT_420XXVF_DEVICE_ID:
            return DEVICE_420XXVF;
        case QAT_420XX_DEVICE_ID:
            return DEVICE_420XX;
        case QAT_4XXX_DEVICE_ID:
        case QAT_402XX_DEVICE_ID:
            return DEVICE_4XXX;
        default:
            return 0;
    }
    return 0;
}

char *qat_device_name(int device_id)
{
    switch (device_id)
    {
        case QAT_4XXXVF_DEVICE_ID:
            return "4xxxvf";
        case QAT_401XXVF_DEVICE_ID:
            return "401xxvf";
        case QAT_402XXVF_DEVICE_ID:
            return "402xxvf";
        case QAT_420XXVF_DEVICE_ID:
            return "420xxvf";
        case QAT_420XX_DEVICE_ID:
            return "420xx";
        case QAT_4XXX_DEVICE_ID:
            return "4xxx";
        case QAT_402XX_DEVICE_ID:
            return "402xx";
        default:
            return "unknown";
    }
}

int init_section_data_mutex()
{
    if (pthread_mutex_init(&section_data_mutex, NULL) != 0)
    {
        return -1;
    }

    return 0;
}

int destroy_section_data_mutex()
{
    if (pthread_mutex_destroy(&section_data_mutex))
    {
        return -1;
    }

    return 0;
}

void free_cpu_data()
{
    int i;

    if (cpu_data)
    {
        for (i = 0; i < num_nodes; i++)
        {
            if (cpu_data[i].cpu)
            {
                free(cpu_data[i].cpu);
                cpu_data[i].cpu = NULL;
                cpu_data[i].idx = 0;
                cpu_data[i].cores_in_node = 0;
            }
        }
        free(cpu_data);
        cpu_data = NULL;
        num_nodes = 0;
    }
}

void qat_mgr_cleanup_cfg(void)
{
    /*
        Allocated memory:
        section data[num_section_data - 1]
        section_data[i].device_data[section_data[i].num_devices - 1]
        section_data[i].device_data[j].xx_instance_data
    */
    struct qatmgr_section_data *section;
    struct qatmgr_device_data *device;
    int i, j;

    if (section_data)
    {
        section = section_data;
        for (i = 0; i < num_section_data; i++, section++)
        {
            device = section->device_data;

            if (!device)
                continue;

            for (j = 0; j < section->num_devices; j++, device++)
            {
                if (device->dc_instance_data)
                {
                    free(device->dc_instance_data);
                    device->dc_instance_data = NULL;
                }

                if (device->decomp_instance_data)
                {
                    free(device->decomp_instance_data);
                    device->decomp_instance_data = NULL;
                }

                if (device->cy_instance_data)
                {
                    free(device->cy_instance_data);
                    device->cy_instance_data = NULL;
                }
            }

            free(section_data[i].device_data);
            section_data[i].device_data = NULL;
        }

        free(section_data);
        section_data = NULL;
        num_section_data = 0;
    }

    free_cpu_data();

    cleanup_capabilities_cache();
}

int open_file_with_link_check(const char *filename, int flags)
{
    int fd;
    struct stat buf;

    fd = open(filename, flags | O_NOFOLLOW);
    if (fd < 0)
    {
        qat_log(LOG_LEVEL_INFO, "Open failed on %s\n", filename);
        return fd;
    }

    if (0 != fstat(fd, &buf))
    {
        qat_log(LOG_LEVEL_ERROR, "Stat failed on %s\n", filename);
        close(fd);
        fd = -1;
        return fd;
    }

    if (buf.st_nlink > 1)
    {
        qat_log(LOG_LEVEL_ERROR, "Detected hardlink for %s\n", filename);
        close(fd);
        fd = -1;
        return fd;
    }

    return fd;
}

DIR *open_dir_with_link_check(const char *dirname)
{
    int fd;
    DIR *dir;

    fd = open(dirname, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
    {
        qat_log(LOG_LEVEL_ERROR, "1: Cannot open %s\n", dirname);
        return NULL;
    }

    dir = fdopendir(fd);
    if (NULL == dir)
    {
        close(fd);
        qat_log(LOG_LEVEL_ERROR, "2: Cannot open %s\n", dirname);
        return NULL;
    }

    return dir;
}

/*
    Calculate bank number for different device configurations.
    Note, this depends on corresponding mapping done by kernel driver.
*/
int calculate_bank_number(const enum cfg_service_type instance_service,
                          const int inst_idx,
                          const uint32_t ring_to_svc_map,
                          const uint16_t num_instances)
{
    int i, serv_type, serv_found = 0;

    /* Search for the matching service type in ring_to_svc_map */
    for (i = 0; i < num_instances; i++)
    {
        serv_type = (ring_to_svc_map >> (i * RING_PAIR_SHIFT)) & SVC_MASK;
        if (instance_service == serv_type)
        {
            if (serv_found == inst_idx)
            {
                return i;
            }
            serv_found++;
        }
    }

    return -1;
}

static int init_cpu_node(int node)
{
    int i = 0;
    for (i = 0; i < num_cpus; i++)
    {
        cpu_data[node].cpu[i] = i;
    }

    cpu_data[node].cores_in_node = num_cpus;
    cpu_data[node].idx = 0;

    return 0;
}

static int init_cpu_node_numa(int node)
{
    int i = 0;
    int j = 0;
    int err = 0;
    struct bitmask *cpus;

    cpus = numa_allocate_cpumask();
    if (!cpus)
    {
        return -1;
    }

    err = numa_node_to_cpus(node, cpus);
    if (err)
    {
        numa_bitmask_free(cpus);
        return -1;
    }

    for (i = 0; i < cpus->size; i++)
    {
        if (numa_bitmask_isbitset(cpus, i))
        {
            cpu_data[node].cpu[j++] = i;
        }
    }

    cpu_data[node].cores_in_node = j;
    cpu_data[node].idx = 0;

    numa_bitmask_free(cpus);

    return 0;
}

static int init_cpu_node_data(int node)
{
    int ret;

    cpu_data[node].cpu = calloc(num_cpus, sizeof(int));

    if (!cpu_data[node].cpu)
    {
        return -ENOMEM;
    }

    if (num_nodes > 1)
    {
        ret = init_cpu_node_numa(node);
    }
    else
    {
        ret = init_cpu_node(node);
    }

    return ret;
}

/**
 * Get next available cpu for given node.
 */
int get_core_affinity(int node)
{
    int cpu = 0;
    int index = 0;
    int cores_in_node = 0;

    index = cpu_data[node].idx;
    cores_in_node = cpu_data[node].cores_in_node;
    cpu = cpu_data[node].cpu[index];

    cpu_data[node].idx = (index + 1) % cores_in_node;

    return cpu;
}

int init_cpu_data()
{
    int ret = 0;
    int i;

    num_cpus = get_nprocs();

    if (numa_available() < 0)
    {
        num_nodes = 1;
        qat_log(LOG_LEVEL_DEBUG, "No NUMA nodes detected.\n");
    }
    else
    {
        num_nodes = numa_max_node() + 1;
        qat_log(LOG_LEVEL_DEBUG, "Detected %d NUMA nodes.\n", num_nodes);
    }

    cpu_data = calloc(num_nodes, sizeof(struct qatmgr_cpu_data));
    if (!cpu_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Unable to allocate cpu mapping data.\n");
        return -ENOMEM;
    }

    for (i = 0; i < num_nodes; i++)
    {
        ret = init_cpu_node_data(i);
        if (ret)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Unable to initialize cpu mapping data.\n");
            free_cpu_data();
            return -EAGAIN;
        }
    }
    return 0;
}

int get_num_instances(struct qatmgr_device_data *device,
                      const unsigned devid,
                      const uint32_t ring_to_svc_map,
                      const uint16_t num_instances)
{
    int serv_type, i;

    for (i = 0; i < num_instances; i++)
    {
        serv_type = (ring_to_svc_map >> (i * RING_PAIR_SHIFT)) & SVC_MASK;
        switch (serv_type)
        {
            case SYM:
                if (device->accel_capabilities &
                    ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC)
                {
                    device->services |= SERV_TYPE_SYM;
                    device->num_sym_inst++;
                }
                break;
            case ASYM:
                if (device->accel_capabilities &
                    ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
                {
                    device->services |= SERV_TYPE_ASYM;
                    device->num_asym_inst++;
                }
                break;
            case COMP:
                if (device->accel_capabilities &
                    ICP_ACCEL_CAPABILITIES_COMPRESSION)
                {
                    device->services |= SERV_TYPE_DC;
                    device->num_dc_inst++;
                }
                break;
            case DECOMP:
                if (device->accel_capabilities &
                    ICP_ACCEL_CAPABILITIES_COMPRESSION)
                {
                    device->services |= SERV_TYPE_DECOMP;
                    device->num_decomp_inst++;
                }
                break;
            case UNUSED:
                break;
            default:
                return -1;
        }
    }

    /* The num_cy_inst variable corresponds to the number of SYM or ASYM
     * instances if only one of those services is enabled. If both services are
     * enabled and the number of SYM and ASYM instances is equal, as in the
     * "sym;asym" scenario, num_cy_inst will reflect both the number of SYM and
     * ASYM instances. However, this logic is limited in the 3 concurrent
     * service scenarios introduced in Gen6, where "sym;asym;dc" and
     * "sym;asym;decomp" configurations enable an unequal number of SYM and ASYM
     * instances. This scenario is not supported with the current QATlib
     * implementation. Therefore, in these cases, num_cy_instances is assigned
     * the minimum value from the number of SYM and ASYM instances, and the
     * additional ASYM instance is not used.
     */

    if (device->num_sym_inst == 0)
        device->num_cy_inst = device->num_asym_inst;
    else if (device->num_asym_inst == 0)
        device->num_cy_inst = device->num_sym_inst;
    else
        device->num_cy_inst = (device->num_sym_inst > device->num_asym_inst)
                                  ? device->num_sym_inst
                                  : device->num_asym_inst;

    return 0;
}

STATIC void dump_message(void *ptr, char *text)
{
    struct qatmgr_msg_req *req = ptr;
    int payload_size;
    uint8_t *payload;
    int i;

    if (debug_level < 2)
        return;

    ICP_CHECK_FOR_NULL_PARAM_VOID(ptr);
    ICP_CHECK_FOR_NULL_PARAM_VOID(text);

    printf("%s\n", text);
    printf("Message type %hu\n", (unsigned short int)(req->hdr.type));
    if (req->hdr.type > 0 && req->hdr.type <= QATMGR_MSGTYPES_STR_MAX)
        printf("Message name %s\n", qatmgr_msgtype_str[req->hdr.type]);
    printf("   length %d\n", req->hdr.len);
    payload_size = req->hdr.len - sizeof(req->hdr);
    payload = (uint8_t *)req + sizeof(req->hdr);

    if (payload_size > 0 && payload_size <= MAX_PAYLOAD_SIZE)
    {
        printf("    Payload: ");
        for (i = 0; i < payload_size; i++, payload++)
        {
            printf("%02X ", *payload);
            if (i % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }
    else
    {
        qat_log(
            LOG_LEVEL_ERROR,
            "Message payload size (%d) out of range. Max payload size is %lu\n",
            payload_size,
            MAX_PAYLOAD_SIZE);
    }
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static void err_msg(struct qatmgr_msg_rsp *rsp, char *text)
{
    ICP_CHECK_FOR_NULL_PARAM_VOID(rsp);
    ICP_CHECK_FOR_NULL_PARAM_VOID(text);

    rsp->hdr.type = QATMGR_MSGTYPE_BAD;
    rsp->hdr.version = THIS_LIB_VERSION;
    snprintf(rsp->error_text, sizeof(rsp->error_text), "%s", text);
    rsp->hdr.len =
        sizeof(rsp->hdr) + ICP_ARRAY_STRLEN_SANITIZE(rsp->error_text) + 1;
}

static void build_msg_header(struct qatmgr_msg_rsp *rsp,
                             int type,
                             int payload_size)
{
    ICP_CHECK_FOR_NULL_PARAM_VOID(rsp);

    rsp->hdr.type = type;
    rsp->hdr.version = THIS_LIB_VERSION;
    rsp->hdr.len = sizeof(rsp->hdr) + payload_size;
}

STATIC int handle_get_num_devices(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  int index)
{
    struct qatmgr_section_data *section;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    rsp->num_devices = section->num_devices;
    build_msg_header(rsp, QATMGR_MSGTYPE_NUM_DEVICES, sizeof(rsp->num_devices));

    dump_message(rsp, "Response");
    return 0;
}

STATIC int handle_get_device_info(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  int index)
{
    struct qatmgr_section_data *section;
    unsigned device_num;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->device_num))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    device_num = req->device_num;
    if (device_num >= section->num_devices)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid device %d >= %d\n",
                device_num,
                section->num_devices);
        err_msg(rsp, "Invalid device number");
        return -1;
    }

    rsp->device_info.device_num = device_num;
    rsp->device_info.device_type = section->device_data[device_num].device_type;
    snprintf(rsp->device_info.device_name,
             sizeof(rsp->device_info.device_name),
             "%s",
             section->device_data[device_num].name);

    rsp->device_info.capability_mask =
        section->device_data[device_num].accel_capabilities;
    rsp->device_info.extended_capabilities =
        section->device_data[device_num].extended_capabilities;
    rsp->device_info.max_banks = section->device_data[device_num].max_banks;
    rsp->device_info.max_rings_per_bank =
        section->device_data[device_num].max_rings_per_bank;
    rsp->device_info.arb_mask = section->device_data[device_num].arb_mask;
    rsp->device_info.ring_mode = section->device_data[device_num].ring_mode;
    rsp->device_info.services = section->device_data[device_num].services;
    rsp->device_info.pkg_id = section->device_data[device_num].pkg_id;
    rsp->device_info.node_id = section->device_data[device_num].node;
    rsp->device_info.device_pci_id = section->device_data[device_num].pci_id;
    rsp->device_info.num_cy_instances =
        section->device_data[device_num].num_cy_inst;
    rsp->device_info.num_sym_instances =
        section->device_data[device_num].num_sym_inst;
    rsp->device_info.num_asym_instances =
        section->device_data[device_num].num_asym_inst;
    rsp->device_info.num_dc_instances =
        section->device_data[device_num].num_dc_inst;
    rsp->device_info.num_decomp_instances =
        section->device_data[device_num].num_decomp_inst;
    if (section->device_data[device_num].fw_caps.is_fw_caps)
    {
        rsp->device_info.fw_caps.comp_algos =
            section->device_data[device_num].fw_caps.comp_algos;
        rsp->device_info.fw_caps.cksum_algos =
            section->device_data[device_num].fw_caps.cksum_algos;
        rsp->device_info.fw_caps.deflate_caps =
            section->device_data[device_num].fw_caps.deflate_caps;
        rsp->device_info.fw_caps.lz4_caps =
            section->device_data[device_num].fw_caps.lz4_caps;
        rsp->device_info.fw_caps.lz4s_caps =
            section->device_data[device_num].fw_caps.lz4s_caps;
        rsp->device_info.fw_caps.is_fw_caps = 1;
    }

    build_msg_header(rsp, QATMGR_MSGTYPE_DEVICE_INFO, sizeof(rsp->device_info));

    dump_message(rsp, "Response");
    return 0;
}

STATIC int handle_get_device_id(struct qatmgr_msg_req *req,
                                struct qatmgr_msg_rsp *rsp,
                                int index)
{
    struct qatmgr_section_data *section;
    struct qatmgr_device_data *device_data;
    unsigned device_num;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->device_num))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    device_num = req->device_num;
    if (device_num >= section->num_devices)
    {
        qat_log(LOG_LEVEL_ERROR, "Invalid device %d\n", device_num);
        err_msg(rsp, "Invalid device number");
        return -1;
    }
    device_data = section->device_data;
    device_data += device_num;

    rsp->hdr.type = QATMGR_MSGTYPE_DEVICE_ID;
    rsp->hdr.version = THIS_LIB_VERSION;
    snprintf(
        rsp->device_id, sizeof(rsp->device_id), "%s", device_data->device_id);
    build_msg_header(rsp,
                     QATMGR_MSGTYPE_DEVICE_ID,
                     ICP_ARRAY_STRLEN_SANITIZE(rsp->device_id) + 1);
    dump_message(rsp, "Response");
    return 0;
}

static int handle_get_vfio_name(struct qatmgr_msg_req *req,
                                struct qatmgr_msg_rsp *rsp,
                                int index)
{
    struct qatmgr_section_data *section;
    struct qatmgr_device_data *device_data;
    unsigned device_num;
    size_t len;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->device_num))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    device_num = req->device_num;
    if (device_num >= section->num_devices)
    {
        qat_log(LOG_LEVEL_ERROR, "Invalid device %d\n", device_num);
        err_msg(rsp, "Invalid device number");
        return -1;
    }
    device_data = section->device_data;
    device_data += device_num;

    rsp->hdr.type = QATMGR_MSGTYPE_VFIO_FILE;
    rsp->hdr.version = THIS_LIB_VERSION;
    rsp->vfio_file.fd = device_data->group_fd;

    snprintf(rsp->vfio_file.name,
             sizeof(rsp->vfio_file.name),
             "%.*s",
             DEVICE_NAME_SIZE,
             device_data->device_file);

    len = ICP_ARRAY_STRLEN_SANITIZE(rsp->vfio_file.name);

    build_msg_header(
        rsp, QATMGR_MSGTYPE_VFIO_FILE, sizeof(rsp->vfio_file.fd) + len + 1);

    dump_message(rsp, "Response");
    return 0;
}

STATIC int handle_get_instance_name(struct qatmgr_msg_req *req,
                                    struct qatmgr_msg_rsp *rsp,
                                    int index)
{
    struct qatmgr_section_data *section;
    struct qatmgr_device_data *device;
    int instance_type;
    int instance_num;
    int device_num;
    char *inst_name;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->inst))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    instance_type = req->inst.type;
    instance_num = req->inst.num;
    device_num = req->inst.device_num;

    device = section->device_data + device_num;

    if (device_num >= section->num_devices)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid device number %d for section %d\n",
                device_num,
                index);
        err_msg(rsp, "Invalid device number");
        return -1;
    }

    if (instance_type == SERV_TYPE_DC)
    {
        if (instance_num >= device->num_dc_inst)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Bad dc instance number %d for device %d\n",
                    instance_num,
                    device_num);
            err_msg(rsp, "Invalid DC instance number");
            return -1;
        }
        snprintf(rsp->name,
                 sizeof(rsp->name),
                 "%s",
                 device->dc_instance_data[instance_num].name);
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_DECOMP)
    {
        if (instance_num >= device->num_decomp_inst)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Bad decomp instance number %d for device %d\n",
                    instance_num,
                    device_num);
            err_msg(rsp, "Invalid Decomp instance number");
            return -1;
        }
        snprintf(rsp->name,
                 sizeof(rsp->name),
                 "%s",
                 device->decomp_instance_data[instance_num].name);
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_CY)
    {
        if (instance_num >= device->num_cy_inst)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Bad cy instance number %d for device %d\n",
                    instance_num,
                    device_num);
            err_msg(rsp, "Invalid CY instance number");
            return -1;
        }
        /* When CY only or SYM;ASYM only is enabled, cpaCyInstanceGetInfo2()
         * will return the same instance name for SYM and ASYM.
         * SERV_TYPE_CY_DECOMP and SERV_TYPE_CY_DC do not apply to this logic,
         * because we have 2 CY instances created, but only 1 of them will have
         * SYM info. In this case we have to get the instance name from ASYM
         * part of both CY instances.
         */
        switch (device->services)
        {
            case SERV_TYPE_ASYM:
            case SERV_TYPE_ASYM_DC:
            case SERV_TYPE_ASYM_DECOMP:
            case SERV_TYPE_CY_DC:
            case SERV_TYPE_CY_DECOMP:
            case SERV_TYPE_ASYM_DC_DECOMP:
                inst_name = device->cy_instance_data[instance_num].asym.name;
                break;
            default:
                inst_name = device->cy_instance_data[instance_num].sym.name;
        }
        snprintf(rsp->name, sizeof(rsp->name), "%s", inst_name);
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_SYM)
    {
        if (instance_num >= device->num_sym_inst)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Bad cy.sym instance number %d for device %d\n",
                    instance_num,
                    device_num);
            err_msg(rsp, "Invalid SYM instance number");
            return -1;
        }
        snprintf(rsp->name,
                 sizeof(rsp->name),
                 "%s",
                 device->cy_instance_data[instance_num].sym.name);
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_ASYM)
    {
        if (instance_num >= device->num_asym_inst)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Bad cy.asym instance number %d for device %d\n",
                    instance_num,
                    device_num);
            err_msg(rsp, "Invalid ASYM instance number");
            return -1;
        }
        snprintf(rsp->name,
                 sizeof(rsp->name),
                 "%s",
                 device->cy_instance_data[instance_num].asym.name);
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else
    {
        qat_log(
            LOG_LEVEL_ERROR, "unsupported instance type %d\n", instance_type);
        err_msg(rsp, "Unknown instance type");
        return -1;
    }
    dump_message(rsp, "Response");
    return 0;
}

/* Function to populate instance data */
static void populate_instance_info(struct qatmgr_instance_data *instance_data,
                                   struct ring_info *info)
{
    info->accelid = instance_data->accelid;
    info->bank_number = instance_data->bank_number;
    info->is_polled = instance_data->is_polled;
    info->core_affinity = instance_data->core_affinity;
    info->num_concurrent_requests = instance_data->num_concurrent_requests;
    info->ring_tx = instance_data->ring_tx;
    info->ring_rx = instance_data->ring_rx;
}

STATIC int handle_get_instance_info(struct qatmgr_msg_req *req,
                                    struct qatmgr_msg_rsp *rsp,
                                    int index)
{
    struct qatmgr_section_data *section;
    struct qatmgr_device_data *device;
    struct qatmgr_instance_data *instance_data;
    struct qatmgr_cy_instance_data *cy_instance_data;
    int instance_type;
    int instance_num;
    int device_num;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->inst))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    instance_type = req->inst.type;
    instance_num = req->inst.num;
    device_num = req->inst.device_num;

    device = section->device_data + device_num;

    if (device_num >= section->num_devices)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid device number %d for section %d\n",
                device_num,
                index);
        err_msg(rsp, "Invalid device number");
        return -1;
    }

    switch (instance_type)
    {
        case SERV_TYPE_DC:
            if (instance_num >= device->num_dc_inst)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Bad dc instance number %d for device %d\n",
                        instance_num,
                        device_num);
                err_msg(rsp, "Invalid dc instance number");
                return -1;
            }
            instance_data = device->dc_instance_data + instance_num;
            populate_instance_info(instance_data, &rsp->instance_info.dc);
            break;

        case SERV_TYPE_DECOMP:
            if (instance_num >= device->num_decomp_inst)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Bad decomp instance number %d for device %d\n",
                        instance_num,
                        device_num);
                err_msg(rsp, "Invalid decomp instance number");
                return -1;
            }
            instance_data = device->decomp_instance_data + instance_num;
            populate_instance_info(instance_data, &rsp->instance_info.decomp);
            break;

        case SERV_TYPE_CY:
            if (instance_num >= device->num_cy_inst)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Bad cy instance number %d for section %d\n",
                        instance_num,
                        index);
                err_msg(rsp, "Invalid cy instance number");
                return -1;
            }
            cy_instance_data = device->cy_instance_data + instance_num;
            /* for CyxIsPolled CY only and SYM only this param is taken from sym
             * instance but for ASYM only from asym service. */
            switch (device->services)
            {
                case SERV_TYPE_ASYM:
                case SERV_TYPE_ASYM_DC:
                case SERV_TYPE_ASYM_DECOMP:
                case SERV_TYPE_CY_DC:
                case SERV_TYPE_CY_DECOMP:
                case SERV_TYPE_ASYM_DC_DECOMP:
                    rsp->instance_info.is_polled =
                        cy_instance_data->asym.is_polled;
                    break;
                default:
                    rsp->instance_info.is_polled =
                        cy_instance_data->sym.is_polled;
            }
            instance_data = &cy_instance_data->sym;
            populate_instance_info(instance_data, &rsp->instance_info.cy.sym);
            instance_data = &cy_instance_data->asym;
            populate_instance_info(instance_data, &rsp->instance_info.cy.asym);
            break;

        case SERV_TYPE_SYM:
            if (instance_num >= device->num_sym_inst)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Bad cy.sym instance number %d for section %d\n",
                        instance_num,
                        index);
                err_msg(rsp, "Invalid sym instance number");
                return -1;
            }
            cy_instance_data = device->cy_instance_data + instance_num;
            instance_data = &cy_instance_data->sym;
            populate_instance_info(instance_data, &rsp->instance_info.cy.sym);
            break;

        case SERV_TYPE_ASYM:
            if (instance_num >= device->num_asym_inst)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Bad cy.asym instance number %d for section %d\n",
                        instance_num,
                        index);
                err_msg(rsp, "Invalid asym instance number");
                return -1;
            }
            cy_instance_data = device->cy_instance_data + instance_num;
            instance_data = &cy_instance_data->asym;
            populate_instance_info(instance_data, &rsp->instance_info.cy.asym);
            break;
        default:
            qat_log(LOG_LEVEL_ERROR,
                    "Unsupported instance type %d\n",
                    instance_type);
            err_msg(rsp, "Unknown instance type");
            return -1;
    }
    build_msg_header(
        rsp, QATMGR_MSGTYPE_INSTANCE_INFO, sizeof(rsp->instance_info));
    dump_message(rsp, "Response");
    return 0;
}

int release_section(int index, unsigned long id, char *name, size_t name_len)
{
    ICP_CHECK_FOR_NULL_PARAM(name);

    /*
     * In standalone mode, id is the process id of the client. In managed
     * mode, id is actually the thread id of the qatmgr thread handling the
     * socket for a specific client process, so it can be considered a proxy
     * for the client process id.
     */
    if (index < 0 || index >= num_section_data)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid section index %d for process %lu, section %s\n",
                index,
                id,
                name);
        return -1;
    }
    if (name_len !=
            ICP_ARRAY_STRLEN_SANITIZE(section_data[index].section_name) ||
        ICP_STRNCMP_CONST(name, section_data[index].section_name))
    {
        qat_log(LOG_LEVEL_ERROR,
                "Incorrect section name %s, expected %s\n",
                name,
                section_data[index].section_name);
        return -1;
    }
    if (section_data[index].assigned_id != id)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Incorrect process %lu for section %s. Expected %lu\n",
                id,
                name,
                section_data[index].assigned_id);
        return -1;
    }
    qat_log(LOG_LEVEL_DEBUG, "Released section %s\n", name);
    section_data[index].assigned_id = 0;
    return 0;
}

STATIC int get_section(unsigned long id, char **derived_section_name)
{
    int i;
    int assigned = 0;

    if (pthread_mutex_lock(&section_data_mutex))
    {
        qat_log(LOG_LEVEL_ERROR, "Unable to lock section_data mutex\n");
        return -2;
    }

    for (i = 0; i < num_section_data; i++)
    {
        if (section_data[i].assigned_id)
            continue; /* Assigned to another process */

        section_data[i].assigned_id = id;
        assigned = 1;
        break;
    }

    if (pthread_mutex_unlock(&section_data_mutex))
    {
        qat_log(LOG_LEVEL_ERROR, "Unable to unlock section_data mutex\n");
        return -2;
    }

    if (assigned)
    {
        qat_log(
            LOG_LEVEL_DEBUG, "Got section %s\n", section_data[i].section_name);
        if (derived_section_name)
            *derived_section_name = section_data[i].section_name;
        return i;
    }

    return -1;
}

STATIC int handle_section_request(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  char **section_name,
                                  unsigned long id_to_assign,
                                  int *index)
{
    int sec;
    char *derived_name;
    static pid_t pid = 0;
    int name_buf_size;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);
    ICP_CHECK_FOR_NULL_PARAM(index);

    if (req->hdr.len !=
        sizeof(req->hdr) + ICP_ARRAY_STRLEN_SANITIZE(req->name) + 1)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (pid != getpid())
    {
        pid = getpid();
        *index = -1;
        if (*section_name)
            free(*section_name);
        *section_name = NULL;
    }

    if (*section_name != NULL || *index != -1)
    {
        qat_log(LOG_LEVEL_ERROR, "Section already allocated\n");
        err_msg(rsp, "Section already allocated");
        return -1;
    }

    sec = get_section(id_to_assign, &derived_name);
    if (sec < 0)
    {
        qat_log(LOG_LEVEL_ERROR, "Couldn't get section %s\n", req->name);
        if (sec == -2)
            err_msg(rsp, "Internal error");
        else
            err_msg(rsp, "No section available");
        return sec;
    }

    *index = sec;
    rsp->hdr.type = QATMGR_MSGTYPE_SECTION_GET;
    rsp->hdr.version = THIS_LIB_VERSION;
    snprintf(rsp->name, sizeof(rsp->name), "%s", derived_name);
    rsp->hdr.len = sizeof(rsp->hdr) + ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1;

    name_buf_size = ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + ADDITIONAL_BUF_LEN;
    *section_name = malloc(name_buf_size);
    if (!*section_name)
    {
        qat_log(LOG_LEVEL_ERROR, "Memory allocation failed\n");
        err_msg(rsp, "malloc failed");
        return -1;
    }
    qat_log(LOG_LEVEL_DEBUG,
            "Allocated section %s at %p\n",
            rsp->name,
            *section_name);

    if (name_buf_size < strnlen(rsp->name, sizeof(rsp->name)))
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to copy section name\n");
        free(*section_name);
        return -1;
    }
    snprintf(*section_name, name_buf_size, "%s", rsp->name);
    dump_message(rsp, "Response");
    return 0;
}

STATIC int handle_section_release(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  char **section_name,
                                  unsigned long id,
                                  int *index)
{
    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);
    ICP_CHECK_FOR_NULL_PARAM(index);
    ICP_CHECK_FOR_NULL_PARAM(section_name);

    if (req->hdr.len !=
        sizeof(req->hdr) + ICP_ARRAY_STRLEN_SANITIZE(req->name) + 1)
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    if (*section_name == NULL)
    {
        qat_log(LOG_LEVEL_ERROR, "Section not allocated\n");
        err_msg(rsp, "Section not allocated");
        return -1;
    }
    if (release_section(
            *index, id, req->name, ICP_ARRAY_STRLEN_SANITIZE(req->name)))
    {
        err_msg(rsp, "Failed to release section");
    }
    else
    {
        qat_log(LOG_LEVEL_DEBUG, "Section %s released\n", req->name);
        build_msg_header(rsp, QATMGR_MSGTYPE_SECTION_PUT, 0);
        if (*section_name)
        {
            free(*section_name);
            *section_name = NULL;
            *index = -1;
        }
    }
    dump_message(rsp, "Response");
    return 0;
}

static int handle_get_num_pf_devices(struct qatmgr_msg_req *req,
                                     struct qatmgr_msg_rsp *rsp)
{
    int32_t num_devices;
    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    num_devices = get_num_pfs();
    if (num_devices == PF_INFO_UNINITIALISED)
    {
        num_devices = adf_vfio_init_pfs_info(
            pf_data, sizeof(pf_data) / sizeof(pf_data[0]));
        set_num_pfs(num_devices);
    }

    if (num_devices < 0 || num_devices > ADF_MAX_PF_DEVICES)
    {
        err_msg(rsp, "Unable to init pfs info");
        qat_log(LOG_LEVEL_ERROR, "Invalid number Pfs\n");
        return -1;
    }

    /* num_devices will be a positive number and less then ADF_MAX_PF_DEVICES */
    rsp->num_devices = num_devices;
    build_msg_header(rsp, QATMGR_MSGTYPE_NUM_PF_DEVS, sizeof(rsp->num_devices));

    dump_message(rsp, "Response");
    return 0;
}

static int handle_get_pf_device_info(struct qatmgr_msg_req *req,
                                     struct qatmgr_msg_rsp *rsp)
{
    uint16_t device_num;
    int32_t num_devices;
    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    /* Use header + additional info length to retrieve PF device information */
    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->device_num))
    {
        qat_log(LOG_LEVEL_ERROR, "Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    dump_message(req, "Request");

    num_devices = get_num_pfs();
    if (num_devices == PF_INFO_UNINITIALISED)
    {
        num_devices = adf_vfio_init_pfs_info(
            pf_data, sizeof(pf_data) / sizeof(pf_data[0]));
        set_num_pfs(num_devices);
    }

    if (num_devices < 0 || num_devices > ADF_MAX_PF_DEVICES)
    {
        err_msg(rsp, "Unable to init pfs info");
        qat_log(LOG_LEVEL_ERROR, "Invalid number Pfs\n");
        return -1;
    }

    device_num = req->device_num;

    if (device_num >= num_devices)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid device number %d from %d devices\n",
                device_num,
                num_devices);
        err_msg(rsp, "Invalid device number");
        return -1;
    }

    memcpy(&rsp->pf_info, &pf_data[device_num], sizeof(rsp->pf_info));
    build_msg_header(rsp, QATMGR_MSGTYPE_PF_DEV_INFO, sizeof(rsp->pf_info));

    dump_message(rsp, "Response");
    return 0;
}

int handle_message(struct qatmgr_msg_req *req,
                   struct qatmgr_msg_rsp *rsp,
                   char **section_name,
                   unsigned long id,
                   int *index)
{
    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);
    ICP_CHECK_FOR_NULL_PARAM(index);
    ICP_CHECK_FOR_NULL_PARAM(section_name);
    memset(&(rsp->device_info.fw_caps), '\0', sizeof(rsp->device_info.fw_caps));

    if (req->hdr.version != THIS_LIB_VERSION)
    {
        char qatlib_ver_str[VER_STR_LEN];
        char qatmgr_ver_str[VER_STR_LEN];
        VER_STR(req->hdr.version, qatlib_ver_str);
        VER_STR(THIS_LIB_VERSION, qatmgr_ver_str);

        qat_log(LOG_LEVEL_ERROR,
                "qatmgr v%s received msg from incompatible qatlib v%s\n",
                qatmgr_ver_str,
                qatlib_ver_str);
        err_msg(rsp, "Incompatible. qatmgr received msg vX from qatlib vY\n");
        return -1;
    }

    switch (req->hdr.type)
    {
        case QATMGR_MSGTYPE_SECTION_GET:
            return handle_section_request(req, rsp, section_name, id, index);
        case QATMGR_MSGTYPE_SECTION_PUT:
            return handle_section_release(req, rsp, section_name, id, index);
        case QATMGR_MSGTYPE_NUM_DEVICES:
            return handle_get_num_devices(req, rsp, *index);
        case QATMGR_MSGTYPE_DEVICE_INFO:
            return handle_get_device_info(req, rsp, *index);
        case QATMGR_MSGTYPE_DEVICE_ID:
            return handle_get_device_id(req, rsp, *index);
        case QATMGR_MSGTYPE_INSTANCE_INFO:
            return handle_get_instance_info(req, rsp, *index);
        case QATMGR_MSGTYPE_INSTANCE_NAME:
            return handle_get_instance_name(req, rsp, *index);
        case QATMGR_MSGTYPE_VFIO_FILE:
            return handle_get_vfio_name(req, rsp, *index);
        case QATMGR_MSGTYPE_NUM_PF_DEVS:
            return handle_get_num_pf_devices(req, rsp);
        case QATMGR_MSGTYPE_PF_DEV_INFO:
            return handle_get_pf_device_info(req, rsp);
        default:
            err_msg(rsp, "Unknown message");
    }

    return -1;
}

