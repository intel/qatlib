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
#include <libgen.h>
#include <limits.h>
#include <search.h>
#include <numa.h>

#include "adf_pfvf_vf_msg.h"
#include "icp_accel_devices.h"
#include "icp_platform.h"
#include "qat_log.h"
#include "qat_mgr.h"
#include "vfio_lib.h"
#include "adf_vfio_pf.h"

#define IOMMUGROUP_DEV_DIR "/sys/kernel/iommu_groups/%.*s/devices/"
#define DEVVFIO_DIR "/dev/vfio"

#define DEVICE_FILE IOMMUGROUP_DEV_DIR "%.*s/device"
#define VENDOR_FILE IOMMUGROUP_DEV_DIR "%.*s/vendor"
#define NUMA_NODE IOMMUGROUP_DEV_DIR "%.*s/numa_node"

#define SYSFS_VF_DIR "/sys/bus/pci/devices"

#define SYSFS_VF_UEVENT "physfn/uevent"
#define PCI_DEV_SLOT_NAME "PCI_SLOT_NAME"

#define PF_DEVICE_FORMAT PCI_DEV_SLOT_NAME"=%s"

#define VFIO_ENTRY "vfio"
#define VFIO_NOIOMMU "noiommu-"

extern icp_accel_pf_info_t pf_data[ADF_MAX_PF_DEVICES];

/*
 * Instead of the default sort order
 *  3d:01.0, 3d:01.1, ... 3d:02.7, 3f:01.0 ... 3f:02.7, da:01.0 ... da:02.7
 * we want all the equivalent device/function entries for each of the PF
 * devices together to facilitate getting devices for policy 0.
 *  3d:01.0, 3f:01.0, da:01.0, 3d:01.1 ...
 */
static int bdf_compare(const void *a, const void *b)
{
    struct qatmgr_dev_data *dev_a = (struct qatmgr_dev_data *)a;
    struct qatmgr_dev_data *dev_b = (struct qatmgr_dev_data *)b;

    if (BDF_FUN(dev_a->bdf) < BDF_FUN(dev_b->bdf))
        return -1;
    if (BDF_FUN(dev_a->bdf) > BDF_FUN(dev_b->bdf))
        return 1;
    if (BDF_DEV(dev_a->bdf) < BDF_DEV(dev_b->bdf))
        return -1;
    if (BDF_DEV(dev_a->bdf) > BDF_DEV(dev_b->bdf))
        return 1;
    if (BDF_BUS(dev_a->bdf) > BDF_BUS(dev_b->bdf))
        return 1;
    if (BDF_BUS(dev_a->bdf) < BDF_BUS(dev_b->bdf))
        return -1;
    return 0;
}

/* Filter the dot(.) entries from the given file path */
static int filter_vfio_files(const struct dirent *entry)
{
    return entry->d_name[0] != '.';
}

int qat_mgr_get_vfio_dev_list(unsigned *num_devices,
                              struct qatmgr_dev_data *dev_list,
                              const unsigned list_size,
                              int keep_fd)
{
    struct dirent **devvfio_dir;
    struct dirent **sysdevice_dir;
    FILE *sysfile;
    int sysfile_fd;
    struct dirent *vfio_entry;
    struct dirent *device_entry;
    int num_devs = 0;
    unsigned device, vendor;
    char filename[256];
    char devices_dir_name[256];
    int vfiofile = -1;
    char *bdfname;
    unsigned domain, bus, dev, func;
    int found = 0;
    int numa_node;
    uint32_t vfio_dir_name_len = 0, device_dir_name_len = 0;
    uint32_t buf_size = 0, str_len = 0;
    int num_vfio_group, num_vfio_device, i, j;
    char *vfio_file_name = NULL;

    if (!dev_list || !list_size || !num_devices)
        return -EINVAL;

    *num_devices = 0;

    num_vfio_group =
        scandir(DEVVFIO_DIR, &devvfio_dir, filter_vfio_files, alphasort);
    if (num_vfio_group < 0)
    {
        return -EIO;
    }

    /* For each <group> entry in /dev/vfio/ */
    for (i = 0; i < num_vfio_group; i++)
    {
        vfio_entry = devvfio_dir[i];

        /* /dev/vfio/vfio is special entry, should be skipped */
        if (!ICP_STRNCMP_CONST(vfio_entry->d_name, VFIO_ENTRY))
            continue;

        /*
         * A vfio device may be visible but not available.
         * It might, for example, be assigned to a virtual machine.
         * Alternatively, it could be used by another process using
         * a static configuration.
         * In either case, if the device cannot be opened, it should be
         * excluded from the list.
         */
        buf_size = sizeof(filename) - (sizeof(DEVVFIO_DIR) - 1) - 1;
        str_len = strnlen(vfio_entry->d_name, sizeof(vfio_entry->d_name));
        if (buf_size <= str_len)
        {
            qat_log(LOG_LEVEL_ERROR, "Failed to copy device file name\n");
            continue;
        }
        snprintf(filename,
                 sizeof(filename),
                 DEVVFIO_DIR "/%.*s",
                 VFIO_FILE_SIZE - 1,
                 vfio_entry->d_name);

        vfiofile = open_file_with_link_check(filename, O_RDWR);
        if (vfiofile < 0)
            continue;

        if (!keep_fd)
        {
            close(vfiofile);
            vfiofile = -1;
        }

        /*
         * For noiommu, the file name has the format of noiommu-<group> in
         * /dev/vfio. Remove the noiommu- prefix when accessing
         * /sys/kernel/iommu-groups/<group>/ directory.
         */
        vfio_file_name = vfio_entry->d_name;
        if (!ICP_STRNCMP(vfio_file_name, VFIO_NOIOMMU, strlen(VFIO_NOIOMMU)))
            vfio_file_name = vfio_entry->d_name + strlen(VFIO_NOIOMMU);

        /* open dir /sys/kernel/iommu_groups/<group>/devices/ */
        buf_size = sizeof(devices_dir_name) - (sizeof(IOMMUGROUP_DEV_DIR) - 1) +
                   STR_FORMAT_SPECIFIER_LEN;
        if (buf_size <= str_len)
        {
            qat_log(LOG_LEVEL_ERROR, "Failed to copy device directory name\n");
            if (vfiofile != -1)
            {
                close(vfiofile);
            }
            continue;
        }
        snprintf(devices_dir_name,
                 sizeof(devices_dir_name),
                 IOMMUGROUP_DEV_DIR,
                 VFIO_FILE_SIZE - 1,
                 vfio_file_name);

        num_vfio_device = scandir(
            devices_dir_name, &sysdevice_dir, filter_vfio_files, alphasort);
        if (num_vfio_device < 0)
        {
            if (vfiofile != -1)
            {
                close(vfiofile);
            }
            continue;
        }

        found = 0;
        /* For each device in this group. Should only be one. */
        for (j = 0; j < num_vfio_device; j++)
        {
            device_entry = sysdevice_dir[j];

            /* Open /sys/kernel/iommu_groups/<group>/devices/<device>/device */
            vfio_dir_name_len =
                strnlen(vfio_entry->d_name, sizeof(vfio_entry->d_name));
            device_dir_name_len =
                strnlen(device_entry->d_name, sizeof(device_entry->d_name));
            buf_size = sizeof(filename) - (sizeof(DEVICE_FILE) - 1) +
                       (NUM_STR_FORMAT_SPECIFIER * STR_FORMAT_SPECIFIER_LEN);
            str_len = vfio_dir_name_len + device_dir_name_len;

            if (buf_size <= str_len)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to copy device file name\n");
                break;
            }
            snprintf(filename,
                     sizeof(filename),
                     DEVICE_FILE,
                     VFIO_FILE_SIZE,
                     vfio_file_name,
                     (buf_size - VFIO_FILE_SIZE - 1),
                     device_entry->d_name);

            sysfile_fd = open_file_with_link_check(filename, O_RDONLY);
            if (sysfile_fd < 0)
                break;

            sysfile = fdopen(sysfile_fd, "r");
            if (!sysfile)
            {
                close(sysfile_fd);
                break;
            }
            device = 0;
            if (fscanf(sysfile, "%x", &device) != 1)
            {
                qat_log(LOG_LEVEL_INFO,
                        "Failed to read device from %s\n",
                        filename);
                /*
                 * If the fscanf fails, the check of device ids below will fail
                 * and break out of the loop at that point.
                 */
            }
            fclose(sysfile);
            qat_log(LOG_LEVEL_INFO, "Checking %s\n", filename);
            if (!is_qat_device(device))
                break;

            buf_size = sizeof(filename) - (sizeof(VENDOR_FILE) - 1) +
                       (NUM_STR_FORMAT_SPECIFIER * STR_FORMAT_SPECIFIER_LEN);
            if (buf_size <= str_len)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to copy vendor file name\n");
                break;
            }
            snprintf(filename,
                     sizeof(filename),
                     VENDOR_FILE,
                     VFIO_FILE_SIZE,
                     vfio_file_name,
                     (buf_size - VFIO_FILE_SIZE - 1),
                     device_entry->d_name);

            sysfile_fd = open_file_with_link_check(filename, O_RDONLY);
            if (sysfile_fd < 0)
                break;

            sysfile = fdopen(sysfile_fd, "r");
            if (!sysfile)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to open %s\n", filename);
                close(sysfile_fd);
                break;
            }
            vendor = 0;
            if (fscanf(sysfile, "%x", &vendor) != 1)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Failed to read vendor from %s\n",
                        filename);
                /*
                 * If the fscanf fails, the check of vendor id below will fail
                 * and break out of the loop at that point.
                 */
            }
            fclose(sysfile);
            if (vendor != INTEL_VENDOR_ID)
                break;

            /* Extract the BDF from the file name */
            bdfname = basename(device_entry->d_name);
            if (sscanf(bdfname, "%x:%x:%x.%x", &domain, &bus, &dev, &func) != 4)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to scan BDF string\n");
                break;
            }
            dev_list[num_devs].bdf = GET_BDF(domain, bus, dev, func);
            buf_size = sizeof(dev_list[num_devs].vfio_file) -
                       (sizeof(DEVVFIO_DIR) - 1) - 1;
            str_len = strnlen(vfio_entry->d_name, sizeof(vfio_entry->d_name));
            if (buf_size <= str_len)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to copy device file name\n");
                break;
            }
            snprintf(dev_list[num_devs].vfio_file,
                     sizeof(dev_list[num_devs].vfio_file),
                     DEVVFIO_DIR "/%.*s",
                     buf_size - 1,
                     vfio_entry->d_name);

            if (j + 1 < num_vfio_device)
            {
                qat_log(LOG_LEVEL_INFO,
                        "Multiple vfio devices in group %s. Ignored\n",
                        vfio_entry->d_name);
                break;
            }

            buf_size = sizeof(filename) - (sizeof(NUMA_NODE) - 1) +
                       (NUM_STR_FORMAT_SPECIFIER * STR_FORMAT_SPECIFIER_LEN);
            if (buf_size <= str_len)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to copy Numa node\n");
                break;
            }
            snprintf(filename,
                     sizeof(filename),
                     NUMA_NODE,
                     VFIO_FILE_SIZE,
                     vfio_file_name,
                     (buf_size - VFIO_FILE_SIZE - 1),
                     device_entry->d_name);

            sysfile_fd = open_file_with_link_check(filename, O_RDONLY);
            if (sysfile_fd < 0)
                break;

            sysfile = fdopen(sysfile_fd, "r");
            if (!sysfile)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to open %s\n", filename);
                close(sysfile_fd);
                break;
            }
            numa_node = 0;
            if (fscanf(sysfile, "%d", &numa_node) != 1)
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Failed to read numa node from %s\n",
                        filename);
            }
            fclose(sysfile);
            /* numa_node may be reported as -1 on VM */
            if (numa_node < 0)
                numa_node = 0;

            dev_list[num_devs].numa_node = numa_node;

            found = 1;

            dev_list[num_devs].devid = device;

            if (keep_fd)
                dev_list[num_devs].group_fd = vfiofile;
            else
                dev_list[num_devs].group_fd = -1;

            num_devs++;
            break;
        }

        for (j = 0; j < num_vfio_device; j++)
        {
            free(sysdevice_dir[j]);
        }
        free(sysdevice_dir);

        if (!found && vfiofile != -1)
        {
            close(vfiofile);
        }

        if (num_devs >= list_size)
            break;
    }

    for (i = 0; i < num_vfio_group; i++)
    {
        free(devvfio_dir[i]);
    }
    free(devvfio_dir);

    *num_devices = num_devs;

    if (!num_devs)
        qat_log(LOG_LEVEL_ERROR, "No devices found\n");

    qsort(dev_list, *num_devices, sizeof(dev_list[0]), bdf_compare);

    return 0;
}

STATIC int qat_mgr_get_device_capabilities(
    struct qatmgr_device_data *device_data,
    int dev_id,
    bool *compatible,
    uint32_t *ext_dc_caps,
    uint32_t *capabilities,
    uint32_t *ring_to_svc_map)
{
    int ret;
    vfio_dev_info_t vfio_dev;
    *compatible = CPA_TRUE;
    ret = open_vfio_dev(device_data->device_file,
                        device_data->device_id,
                        device_data->group_fd,
                        dev_id,
                        &vfio_dev);
    if (ret)
    {
        qat_log(LOG_LEVEL_ERROR, "Cannot open vfio device\n");
        return ret;
    }

    ret = adf_vf2pf_check_compat_version(&vfio_dev.pfvf);
    if (ret)
    {
        close_vfio_dev(&vfio_dev);
        device_data->group_fd = -1;
        if (adf_vf2pf_available())
        {
            qat_log(LOG_LEVEL_ERROR, "Comms incompatible between VF and PF\n");
            *compatible = CPA_FALSE;
        }
        return ret;
    }

    ret = adf_vf2pf_get_ring_to_svc(&vfio_dev.pfvf);
    if (ret)
    {
        qat_log(LOG_LEVEL_ERROR, "Cannot query device ring to service map\n");
        close_vfio_dev(&vfio_dev);
        device_data->group_fd = -1;
        return ret;
    }
    else
    {
        /* Some earlier kernels returned an invalid map of 0. It's more robust
         * to assume the default map in this case.
         */
        if (vfio_dev.pfvf.ring_to_svc_map == 0)
        {
            vfio_dev.pfvf.ring_to_svc_map = DEFAULT_RING_TO_SRV_MAP;
            qat_log(
                LOG_LEVEL_DEBUG,
                "Kernel reported ring_to_svc_map of 0, so assume default\n");
        }
    }

    ret = adf_vf2pf_get_capabilities(&vfio_dev.pfvf);
    if (ret)
    {
        qat_log(LOG_LEVEL_ERROR, "Cannot query device capabilities\n");
        close_vfio_dev(&vfio_dev);
        device_data->group_fd = -1;
        return ret;
    }

    *ext_dc_caps = vfio_dev.pfvf.ext_dc_caps;
    *capabilities = vfio_dev.pfvf.capabilities;
    *ring_to_svc_map = vfio_dev.pfvf.ring_to_svc_map;
    if (vfio_dev.pfvf.fw_caps.is_fw_caps)
    {
        device_data->fw_caps.comp_algos = vfio_dev.pfvf.fw_caps.comp_algos;
        device_data->fw_caps.cksum_algos = vfio_dev.pfvf.fw_caps.cksum_algos;
        device_data->fw_caps.deflate_caps = vfio_dev.pfvf.fw_caps.deflate_caps;
        device_data->fw_caps.lz4_caps = vfio_dev.pfvf.fw_caps.lz4_caps;
        device_data->fw_caps.lz4s_caps = vfio_dev.pfvf.fw_caps.lz4s_caps;
        device_data->fw_caps.is_fw_caps = 1;
    }

    close_vfio_dev(&vfio_dev);
    device_data->group_fd = -1;
    return 0;
}

static uint16_t bdf_pf(const unsigned vf_bdf)
{
    uint16_t pf_bdf = 0;
    unsigned int domain, bus, dev, func;
    FILE *fp = NULL;
    char dev_path[QATMGR_MAX_STRLEN] = { '\0' };
    char dev_info[QATMGR_MAX_STRLEN] = { '\0' };
    char pci_slot_name[DEVICE_NAME_SIZE] = { '\0' };

    snprintf(dev_path,
             sizeof(dev_path),
             "%s/%04x:%02x:%02x.%1x/%s",
             SYSFS_VF_DIR,
             BDF_DOMAIN(vf_bdf),
             BDF_BUS(vf_bdf),
             BDF_DEV(vf_bdf),
             BDF_FUN(vf_bdf),
             SYSFS_VF_UEVENT);

    fp = fopen(dev_path, "r");
    if (fp == NULL)
    {
        qat_log(
            LOG_LEVEL_ERROR, "Failed to open VF sysfs file : %s\n", dev_path);
        return 0;
    }

    while (fgets(dev_info, sizeof(dev_info), fp) != NULL)
    {
        if (strstr(dev_info, PCI_DEV_SLOT_NAME) != NULL)
        {
            sscanf(dev_info, PF_DEVICE_FORMAT, pci_slot_name);
            sscanf(pci_slot_name, "%x:%x:%x.%x", &domain, &bus, &dev, &func);
            pf_bdf = ((0xFF & bus) << 8) + ((0x1F & dev) << 3) + (0x07 & func);
            break;
        }
    }
    fclose(fp);
    return pf_bdf;
}

/**
 * Search for PF index from pf_info data for given vf_bdf
 * returns 0 on success and -1 on failure. If pf_info array
 * is empty (if qatlib is running inside VM) then assigns max value of pkg_id
 * and returns 0
 */
static int get_pkg_id(unsigned vf_bdf, int32_t *vf_pkg_id)
{
    int32_t pkg_id = 0;
    uint16_t pf_bdf = 0;
    uint16_t domain;
    int32_t num_pfs;

    num_pfs = get_num_pfs();
    if (!num_pfs)
    {
        *vf_pkg_id = VM_PACKAGE_ID_NONE;
        return 0;
    }

    /* get PF BDF id using VF BDF id */
    pf_bdf = bdf_pf(vf_bdf);
    if (!pf_bdf)
        return -1;
    domain = BDF_DOMAIN(vf_bdf);

    for (pkg_id = 0; pkg_id < num_pfs; pkg_id++)
    {
        if (pf_data[pkg_id].bdf == pf_bdf && pf_data[pkg_id].domain == domain)
        {
            *vf_pkg_id = pkg_id;
            return 0;
        }
    }

    return -1;
}

int qat_mgr_vfio_build_data(const struct qatmgr_dev_data dev_list[],
                            const int num_vf_devices,
                            int policy,
                            int static_cfg)
{
    int i, j, k;
    struct qatmgr_section_data *section;
    struct qatmgr_instance_data *dc_inst;
    struct qatmgr_instance_data *decomp_inst;
    struct qatmgr_cy_instance_data *cy_inst;
    struct qatmgr_device_data *device_data;
    int num_vf_groups;
    int vf_idx = 0;
    int num_vfs_this_section;
    int pf = 0;
    unsigned devid;
    char pf_str[10];
    ENTRY pf_entry = { pf_str, NULL };
    int pfs_per_vf_group[ADF_MAX_DEVICES] = { 0 };
    uint32_t ext_dc_caps, capabilities;
    uint32_t ring_to_svc_map;
    bool compatible;
    bool vm = false;
    int ret;
    struct pf_capabilities *cached_capabilities;
    int section_num_sym_inst = 0;
    int section_num_asym_inst = 0;
    int section_num_dc_inst = 0;
    int32_t vf_pkg_id = 0;
    int section_num_decomp_inst = 0;
    int32_t num_pfs;
    int num_section_data = 0;

    if (!num_vf_devices)
        return -EINVAL;

    num_pfs = get_num_pfs();
    if (num_pfs == PF_INFO_UNINITIALISED)
    {
        num_pfs = adf_vfio_init_pfs_info(pf_data,
                                         sizeof(pf_data) / sizeof(pf_data[0]));
        set_num_pfs(num_pfs);
    }

    if (num_pfs < 0 || num_pfs > ADF_MAX_PF_DEVICES)
    {
        qat_log(LOG_LEVEL_ERROR, "Invalid number Pfs\n");
        return -1;
    }

    if (!num_pfs)
    {
        vm = true;
        qat_log(LOG_LEVEL_DEBUG,
                "Unable to find pfs in the system, assuming "
                "qat_mgr_lib is running inside VM\n");
    }

    ret = init_cpu_data();
    if (ret)
    {
        return ret;
    }

    /*
     * A VF group is a set of VFs with the same device/function
     * but from different PFs.
     * The dev_list is sorted so that each VF in a group are consecutive.
     * We know we have a new group when we find a PF that already exists in
     * the first group.
     */
    if (!static_cfg)
    {
        num_vf_groups = 1;

        /* Create hash table for mapping devices */
        if (hcreate(ADF_MAX_DEVICES) == 0)
        {
            qat_log(LOG_LEVEL_ERROR, "Error while creating hash table\n");
            free_cpu_data();
            return -ENOMEM;
        }

        /* Count VF groups */
        for (i = 0; i < num_vf_devices; i++)
        {
            /* Convert PF address to int - take node into account */
            pf = PF(dev_list[i].bdf);
            /* Convert address to string to use as hash table key */
            snprintf(pf_str, sizeof(pf_str), "%d", pf);
            /* Check if pf is already in the hash table */
            if (hsearch(pf_entry, FIND) != NULL)
            {
                /* Device already in hash table - increment vf groups */
                num_vf_groups++;
                /* Need to create new hash table */
                hdestroy();
                if (hcreate(ADF_MAX_DEVICES) == 0)
                {
                    qat_log(LOG_LEVEL_ERROR,
                            "Error while creating hash table\n");
                    free_cpu_data();
                    return -ENOMEM;
                }
            }
            pfs_per_vf_group[num_vf_groups - 1]++;

            /* Insert device to hash table */
            if (hsearch(pf_entry, ENTER) == NULL)
            {
                qat_log(LOG_LEVEL_ERROR, "No space left in hash table\n");
                free_cpu_data();
                return -ENOMEM;
            }
        }
        qat_log(LOG_LEVEL_DEBUG, "num_vf_groups %d\n", num_vf_groups);
        /* Destroy hash table */
        hdestroy();

        /*
         * For policy 0, each process will get a VF from each PF so there can
         * be a max of num_vf_groups processes.
         * For policy <n>, each process will get <n> VFs so there can be
         * a max of num_vf_devices / <n> processes.
         */
        if (policy == 0)
        {
            num_section_data = num_vf_groups;
        }
        else
        {
            num_section_data = num_vf_devices / policy;
        }

        if (num_section_data <= 0)
        {
            qat_log(LOG_LEVEL_ERROR,
                    "Policy %d is greater than the number of "
                    "available devices %d\n",
                    policy,
                    num_vf_devices);
            free_cpu_data();
            return -EINVAL;
        }
        qat_log(LOG_LEVEL_DEBUG, "num_section_data %d\n", num_section_data);
    }
    else if (num_vf_devices >= policy)
    {
        num_section_data = 1;
    }
    else
    {
        qat_log(LOG_LEVEL_ERROR,
                "Policy %d is incompatible with the number of "
                "available devices %d\n",
                policy,
                num_vf_devices);
        free_cpu_data();
        return -EINVAL;
    }

    section = calloc(num_section_data, sizeof(struct qatmgr_section_data));
    if (!section)
    {
        qat_log(LOG_LEVEL_ERROR, "Malloc failed for section data\n");
        free_cpu_data();
        return -EAGAIN;
    }

    set_section_data(section);
    set_num_section_data(num_section_data);
    for (i = 0; i < num_section_data; i++, section++)
    {
        snprintf(section->section_name,
                 sizeof(section->section_name),
                 "SSL_INT_%d",
                 i);
        snprintf(section->base_name, sizeof(section->base_name), "SSL");
        section->assigned_id = 0;

        if (policy)
        {
            num_vfs_this_section = policy;
            if (num_vfs_this_section > num_vf_devices - vf_idx)
                num_vfs_this_section = num_vf_devices - vf_idx;
        }
        else
        {
            /*
             * Policy 0, one VF from each different PF.
             * Use cached number of PFs.
             */
            num_vfs_this_section = pfs_per_vf_group[i];
        }
        section->num_devices = num_vfs_this_section;

        /* Create device data */
        section->device_data =
            calloc(num_vfs_this_section, sizeof(struct qatmgr_device_data));
        if (!section->device_data)
        {
            qat_log(LOG_LEVEL_ERROR, "Malloc failed for device data\n");
            qat_mgr_cleanup_cfg();
            return -EAGAIN;
        }

        section_num_sym_inst = 0;
        section_num_asym_inst = 0;
        section_num_dc_inst = 0;
        section_num_decomp_inst = 0;

        device_data = section->device_data;
        for (j = 0; j < num_vfs_this_section; j++, device_data++, vf_idx++)
        {
            ring_to_svc_map = DEFAULT_RING_TO_SRV_MAP;
            qat_log(LOG_LEVEL_DEBUG,
                    "section %d, BDF %X\n",
                    i,
                    dev_list[vf_idx].bdf);
            snprintf(device_data->device_id,
                     sizeof(device_data->device_id),
                     "%04x:%02x:%02x.%01x",
                     BDF_DOMAIN(dev_list[vf_idx].bdf),
                     BDF_BUS(dev_list[vf_idx].bdf),
                     BDF_DEV(dev_list[vf_idx].bdf),
                     BDF_FUN(dev_list[vf_idx].bdf));
            snprintf(device_data->device_file,
                     sizeof(device_data->device_file),
                     "%.*s",
                     VFIO_FILE_SIZE,
                     dev_list[vf_idx].vfio_file);

            device_data->group_fd = dev_list[vf_idx].group_fd;
            device_data->accelid = j;
            device_data->node = dev_list[vf_idx].numa_node;
            device_data->ring_mode = ADF_RING_WQ_MODE;

            if (get_pkg_id(dev_list[vf_idx].bdf, &vf_pkg_id))
            {
                qat_log(LOG_LEVEL_ERROR,
                        "Failed to find pkg_id for the device\n");
                qat_mgr_cleanup_cfg();
                return -EAGAIN;
            }

            /* since sample code uses package id for gathering info from devices
             * this overrides pkg id to accel id if qatlib is running on VM */
            if (vf_pkg_id == VM_PACKAGE_ID_NONE)
            {
                vf_pkg_id = device_data->accelid;
            }

            device_data->pkg_id = vf_pkg_id;
            devid = dev_list[vf_idx].devid;

                device_data->max_banks = 4;
                device_data->max_rings_per_bank = 2;
                device_data->arb_mask = 0x01;
#ifndef ENABLE_DC
                device_data->accel_capabilities =
                    ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
                    ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
                    ICP_ACCEL_CAPABILITIES_CIPHER |
                    ICP_ACCEL_CAPABILITIES_AUTHENTICATION |
                    ICP_ACCEL_CAPABILITIES_CRYPTO_SHA3 |
                    ICP_ACCEL_CAPABILITIES_SHA3_EXT |
                    ICP_ACCEL_CAPABILITIES_HKDF |
                    ICP_ACCEL_CAPABILITIES_ECEDMONT |
                    ICP_ACCEL_CAPABILITIES_CHACHA_POLY |
                    ICP_ACCEL_CAPABILITIES_AESGCM_SPC |
                    ICP_ACCEL_CAPABILITIES_AES_V2;
                device_data->extended_capabilities = 0x0;
#else
            /* For Legacy Chaining we set the following
             * AUTHENTICATION and Bit 21
             * Bit 21 used to enabling the hash then compress
             * chaining support.
             */
            device_data->accel_capabilities =
                ICP_ACCEL_CAPABILITIES_COMPRESSION |
                ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY64 |
                ICP_ACCEL_CAPABILITIES_LZ4_COMPRESSION |
                ICP_ACCEL_CAPABILITIES_LZ4S_COMPRESSION |
                ICP_ACCEL_CAPABILITIES_AUTHENTICATION |
                ICP_ACCEL_CAPABILITIES_CRYPTO_SHA3 |
                ICP_ACCEL_CAPABILITIES_SHA3_EXT;

            device_data->extended_capabilities = BIT(21) | BIT(0);
#endif
            /**
             * Send query to get capabilities from PF.
             * qat_mgr_get_device_capabilities will open device, initialize
             * VF2PF communication, query capabilities and close device.
             *
             * Before first query, we don't know if PF is supporting VF2PF (1st
             * call to adf_vf2pf_available will report availability of VF2PF),
             * in case where PF is not supporting VF2PF, consecutive calls to
             * adf_vf2pf_available will report lack of VF2PF and hardcoded
             * "fallback" capabilities defined above will be used.
             */

            cached_capabilities = NULL;
            if (!vm)
            {
                /**
                 * If running on a host, it can be assumed that all devices with
                 * the same domain+bus are VFs from the same PF and so have the
                 * same capabilities. So it's an optimization to query the
                 * capabilities of only one VF and cache them to populate the
                 * other VFs.
                 */
                pf = PF(dev_list[vf_idx].bdf);
                cached_capabilities = find_pf_capabilities(pf);
            }

            if (cached_capabilities)
            {
                device_data->accel_capabilities =
                    cached_capabilities->capabilities;
                device_data->extended_capabilities =
                    cached_capabilities->ext_dc_caps;

                if (cached_capabilities->fw_caps.is_fw_caps)
                {
                    device_data->fw_caps.comp_algos =
                        cached_capabilities->fw_caps.comp_algos;
                    device_data->fw_caps.cksum_algos =
                        cached_capabilities->fw_caps.cksum_algos;
                    device_data->fw_caps.deflate_caps =
                        cached_capabilities->fw_caps.deflate_caps;
                    device_data->fw_caps.lz4_caps =
                        cached_capabilities->fw_caps.lz4_caps;
                    device_data->fw_caps.lz4s_caps =
                        cached_capabilities->fw_caps.lz4s_caps;
                    device_data->fw_caps.is_fw_caps =
                        cached_capabilities->fw_caps.is_fw_caps;
                }
                ring_to_svc_map = cached_capabilities->ring_to_svc_map;
            }
            else if (adf_vf2pf_available())
            {
                ret = qat_mgr_get_device_capabilities(device_data,
                                                      devid,
                                                      &compatible,
                                                      &ext_dc_caps,
                                                      &capabilities,
                                                      &ring_to_svc_map);
                if (0 == ret)
                {
                    /*
                     * Override the ecEdMont capability
                     * reported by the kernel. The reason for this is that
                     * some kernel drivers don't report this capability
                     * even though it is present in all devices that have asym.
                     */
                    if (capabilities & ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
                        capabilities |= ICP_ACCEL_CAPABILITIES_ECEDMONT;

                    /*
		     * QAT silicon is not spec compliant for ZUC-256, due to
		     * late changes to that spec. So prevent it from being used.
		     */
                    capabilities &= ~ICP_ACCEL_CAPABILITIES_ZUC_256;
                    device_data->accel_capabilities = capabilities;
                    device_data->extended_capabilities = ext_dc_caps;
                }
                else if (!compatible)
                {
                    qat_log(LOG_LEVEL_ERROR,
                            "Detected not compatible PF driver\n");
                    qat_mgr_cleanup_cfg();
                    return ret;
                }

                if (0 == ret && !vm)
                {
                    cached_capabilities =
                        calloc(1, sizeof(struct pf_capabilities));
                    if (!cached_capabilities)
                    {
                        qat_log(LOG_LEVEL_ERROR,
                                "Malloc failed for capabilities cache\n");
                        qat_mgr_cleanup_cfg();
                        return -EAGAIN;
                    }
                    cached_capabilities->pf = pf;
                    cached_capabilities->capabilities = capabilities;
                    cached_capabilities->ext_dc_caps = ext_dc_caps;
                    cached_capabilities->ring_to_svc_map = ring_to_svc_map;
                    if (device_data->fw_caps.is_fw_caps)
                    {
                        cached_capabilities->fw_caps.comp_algos =
                            device_data->fw_caps.comp_algos;
                        cached_capabilities->fw_caps.cksum_algos =
                            device_data->fw_caps.cksum_algos;
                        cached_capabilities->fw_caps.deflate_caps =
                            device_data->fw_caps.deflate_caps;
                        cached_capabilities->fw_caps.lz4_caps =
                            device_data->fw_caps.lz4_caps;
                        cached_capabilities->fw_caps.lz4s_caps =
                            device_data->fw_caps.lz4s_caps;
                        cached_capabilities->fw_caps.is_fw_caps = 1;
                    }
                    add_pf_capabilities(cached_capabilities);
                }
            }

            snprintf(device_data->name,
                     sizeof(device_data->name),
                     "%s",
                     qat_device_name(devid));
            device_data->device_type = qat_device_type(devid);
            device_data->pci_id = devid;

            /* Populate service configuration for a device and
             * determine the number of instances per device
             */
            ret = get_num_instances(
                device_data, devid, ring_to_svc_map, INSTANCES_PER_DEVICE);
            if (ret)
            {
                qat_log(LOG_LEVEL_ERROR, "Detected unknown service\n");
                qat_mgr_cleanup_cfg();
                return -1;
            }

            if (device_data->num_dc_inst)
            {
                /* Create DC instance data */
                device_data->dc_instance_data =
                    calloc(device_data->num_dc_inst,
                           sizeof(struct qatmgr_instance_data));
                if (!device_data->dc_instance_data)
                {
                    qat_log(LOG_LEVEL_ERROR,
                            "Malloc failed for dc instance data\n");
                    qat_mgr_cleanup_cfg();
                    return -EAGAIN;
                }
            }

            if (device_data->num_decomp_inst)
            {
                /* Create decompression instance data */
                device_data->decomp_instance_data =
                    calloc(device_data->num_decomp_inst,
                           sizeof(struct qatmgr_instance_data));
                if (!device_data->decomp_instance_data)
                {
                    qat_log(
                        LOG_LEVEL_ERROR,
                        "Memory allocation failed for decomp instance data\n");
                    qat_mgr_cleanup_cfg();
                    return -EAGAIN;
                }
            }

            /* SYM and ASYM are stored inside CY instance data */
            if (device_data->num_cy_inst)
            {
                device_data->cy_instance_data =
                    calloc(device_data->num_cy_inst,
                           sizeof(struct qatmgr_cy_instance_data));
                if (!device_data->cy_instance_data)
                {
                    qat_log(LOG_LEVEL_ERROR,
                            "Malloc failed for cy instance data\n");
                    qat_mgr_cleanup_cfg();
                    return -EAGAIN;
                }
            }

            /* populate instance data */
            cy_inst = device_data->cy_instance_data;
            for (k = 0; k < device_data->num_asym_inst; k++, cy_inst++)
            {
                snprintf(cy_inst->asym.name,
                         sizeof(cy_inst->asym.name),
                         "asym%d",
                         section_num_asym_inst++);
                cy_inst->asym.accelid = device_data->accelid;
                cy_inst->asym.service_type = SERV_TYPE_ASYM;

                    cy_inst->asym.bank_number = calculate_bank_number(
                        ASYM, k, ring_to_svc_map, INSTANCES_PER_DEVICE);
                    if (cy_inst->asym.bank_number < 0)
                    {
                        qat_log(LOG_LEVEL_ERROR,
                                "Cannot find bank number for asym instance\n");
                        qat_mgr_cleanup_cfg();
                        return -1;
                    }
                    cy_inst->asym.ring_tx = 0;
                    cy_inst->asym.ring_rx = 1;
                cy_inst->asym.is_polled = 1;
                cy_inst->asym.num_concurrent_requests = 64;
                cy_inst->asym.core_affinity =
                    get_core_affinity(device_data->node);
            }

            cy_inst = device_data->cy_instance_data;
            for (k = 0; k < device_data->num_sym_inst; k++, cy_inst++)
            {
                snprintf(cy_inst->sym.name,
                         sizeof(cy_inst->sym.name),
                         "sym%d",
                         section_num_sym_inst++);
                cy_inst->sym.accelid = device_data->accelid;
                cy_inst->sym.service_type = SERV_TYPE_SYM;

                    cy_inst->sym.bank_number = calculate_bank_number(
                        SYM, k, ring_to_svc_map, INSTANCES_PER_DEVICE);
                    if (cy_inst->sym.bank_number < 0)
                    {
                        qat_log(LOG_LEVEL_ERROR,
                                "Cannot find bank number for sym instance\n");
                        qat_mgr_cleanup_cfg();
                        return -1;
                    }
                    cy_inst->sym.ring_tx = 0;
                    cy_inst->sym.ring_rx = 1;
                cy_inst->sym.is_polled = 1;
                cy_inst->sym.num_concurrent_requests = 512;
                cy_inst->sym.core_affinity =
                    get_core_affinity(device_data->node);
            }

            dc_inst = device_data->dc_instance_data;
            for (k = 0; k < device_data->num_dc_inst; k++, dc_inst++)
            {
                snprintf(dc_inst->name,
                         sizeof(dc_inst->name),
                         "dc%d",
                         section_num_dc_inst++);
                dc_inst->accelid = device_data->accelid;
                dc_inst->service_type = SERV_TYPE_DC;

                    dc_inst->bank_number = calculate_bank_number(
                        COMP, k, ring_to_svc_map, INSTANCES_PER_DEVICE);
                    if (dc_inst->bank_number < 0)
                    {
                        qat_log(LOG_LEVEL_ERROR,
                                "Cannot find bank number for dc instance\n");
                        qat_mgr_cleanup_cfg();
                        return -1;
                    }
                    dc_inst->ring_tx = 0;
                    dc_inst->ring_rx = 1;
                dc_inst->is_polled = 1;
                dc_inst->num_concurrent_requests = MAX_NUM_CONCURRENT_REQUEST;
                dc_inst->core_affinity = get_core_affinity(device_data->node);
            }

            /* This will execute only if decomp configuration service
             * is enabled. If not then num_decomp_inst must be zero.*/
            decomp_inst = device_data->decomp_instance_data;
            for (k = 0; k < device_data->num_decomp_inst; k++, decomp_inst++)
            {
                snprintf(decomp_inst->name,
                         sizeof(decomp_inst->name),
                         "decomp%d",
                         section_num_decomp_inst++);
                decomp_inst->accelid = device_data->accelid;
                decomp_inst->service_type = SERV_TYPE_DECOMP;

                decomp_inst->bank_number = calculate_bank_number(
                    DECOMP, k, ring_to_svc_map, INSTANCES_PER_DEVICE);
                decomp_inst->ring_tx = 0;
                decomp_inst->ring_rx = 1;

                decomp_inst->is_polled = 1;
                decomp_inst->num_concurrent_requests =
                    MAX_NUM_CONCURRENT_REQUEST;
                decomp_inst->core_affinity =
                    get_core_affinity(device_data->node);
            }
        }
    }

    return 0;
}

bool qat_mgr_is_vfio_dev_available(void)
{
    struct dirent **devvfio_dir;
    struct dirent **sysdevice_dir;
    struct dirent *vfio_entry;
    struct dirent *device_entry;
    FILE *sysfile;
    int sysfile_fd;
    char devices_dir_name[256];
    bool dev_found = false;
    char filename[256];
    unsigned int device;
    uint32_t vfio_dir_name_len, device_dir_name_len;
    uint32_t buf_size = 0, str_len = 0;
    int num_vfio_group, num_vfio_device, i, j;
    char *vfio_file_name = NULL;

    num_vfio_group =
        scandir(DEVVFIO_DIR, &devvfio_dir, filter_vfio_files, alphasort);
    if (num_vfio_group < 0)
    {
        return false;
    }

    /* For each <group> entry in /dev/vfio/ */
    for (i = 0; i < num_vfio_group; i++)
    {
        vfio_entry = devvfio_dir[i];

        /* If any QAT device was found, quit immediately */
        if (dev_found)
            break;

        /* /dev/vfio/vfio is special entry, should be skipped */
        if (!ICP_STRNCMP_CONST(vfio_entry->d_name, VFIO_ENTRY))
            continue;

        /*
         * For noiommu, the file name has the format of noiommu-<group> in
         * /dev/vfio. Remove the noiommu- prefix when accessing
         * /sys/kernel/iommu-groups/<group>/ directory.
         */
        vfio_file_name = vfio_entry->d_name;
        if (!ICP_STRNCMP(vfio_file_name, VFIO_NOIOMMU, strlen(VFIO_NOIOMMU)))
            vfio_file_name = vfio_entry->d_name + strlen(VFIO_NOIOMMU);

        /* open dir /sys/kernel/iommu_groups/<group>/devices/ */
        buf_size = sizeof(devices_dir_name) - (sizeof(IOMMUGROUP_DEV_DIR) - 1) +
                   STR_FORMAT_SPECIFIER_LEN;
        str_len = strnlen(vfio_entry->d_name, sizeof(vfio_entry->d_name));
        if (buf_size <= str_len)
        {
            qat_log(LOG_LEVEL_ERROR, "Failed to copy device file name\n");
            continue;
        }
        snprintf(devices_dir_name,
                 sizeof(devices_dir_name),
                 IOMMUGROUP_DEV_DIR,
                 buf_size - 1,
                 vfio_file_name);

        num_vfio_device = scandir(
            devices_dir_name, &sysdevice_dir, filter_vfio_files, alphasort);
        if (num_vfio_device < 0)
        {
            continue;
        }

        /* For each device in this group. Should only be one. */
        for (j = 0; j < num_vfio_device; j++)
        {
            device_entry = sysdevice_dir[j];

            /* Open /sys/kernel/iommu_groups/<group>/devices/<device>/device */
            vfio_dir_name_len =
                strnlen(vfio_entry->d_name, sizeof(vfio_entry->d_name));
            device_dir_name_len =
                strnlen(device_entry->d_name, sizeof(device_entry->d_name));

            buf_size = sizeof(filename) - (sizeof(DEVICE_FILE) - 1) +
                       (NUM_STR_FORMAT_SPECIFIER * STR_FORMAT_SPECIFIER_LEN);
            str_len = vfio_dir_name_len + device_dir_name_len;
            if (buf_size <= str_len)
            {
                qat_log(LOG_LEVEL_ERROR, "Failed to copy device file name\n");
                break;
            }
            snprintf(filename,
                     sizeof(filename),
                     DEVICE_FILE,
                     VFIO_FILE_SIZE,
                     vfio_file_name,
                     (buf_size - VFIO_FILE_SIZE - 1),
                     device_entry->d_name);

            sysfile_fd = open_file_with_link_check(filename, O_RDONLY);
            if (sysfile_fd < 0)
                break;

            sysfile = fdopen(sysfile_fd, "r");
            if (!sysfile)
            {
                close(sysfile_fd);
                break;
            }
            device = 0;
            if (fscanf(sysfile, "%x", &device) != 1)
            {
                qat_log(LOG_LEVEL_INFO,
                        "Failed to read device from %s\n",
                        filename);
                /*
                 * If the fscanf fails, the check of device ids below will fail
                 * and we will check next dev.
                 */
            }
            fclose(sysfile);
            qat_log(LOG_LEVEL_INFO, "Checking %s\n", filename);
            if (is_qat_device(device))
            {
                dev_found = true;
                break;
            }
        }

        for (j = 0; j < num_vfio_device; j++)
        {
            free(sysdevice_dir[j]);
        }
        free(sysdevice_dir);
    }

    for (i = 0; i < num_vfio_group; i++)
    {
        free(devvfio_dir[i]);
    }
    free(devvfio_dir);

    return dev_found;
}
