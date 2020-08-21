/*****************************************************************************
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <sys/sysinfo.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include "icp_accel_devices.h"
#include "icp_platform.h"
#include "qat_mgr.h"

#define INTEL_VENDOR_ID 0x8086
#define QAT_4XXXVF_DEVICE_ID 0x4941


#define IOMMUGROUP_DEV_DIR "/sys/kernel/iommu_groups/%s/devices/"
#define DEVVFIO_DIR "/dev/vfio"
#define DEVICE_GROUP "qat"

#define DEVICE_FILE IOMMUGROUP_DEV_DIR "%s/device"
#define VENDOR_FILE IOMMUGROUP_DEV_DIR "%s/vendor"

#ifdef ADF_ERROR
#undef ADF_ERROR
#endif
#define ADF_ERROR(format, args...) pr_err(format, ##args)

static struct qatmgr_section_data *section_data = NULL;
static int num_section_data = 0;


int debug_level = 0;

int pr_err(const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vfprintf(stderr, fmt, args);
    va_end(args);

    return ret;
}

int pr_info(const char *fmt, ...)
{
    va_list args;
    int ret;

    if (debug_level < 1)
        return 1;

    va_start(args, fmt);
    ret = vprintf(fmt, args);
    va_end(args);

    return ret;
}

int pr_dbg(const char *fmt, ...)
{
    va_list args;
    int ret;

    if (debug_level < 2)
        return 1;

    va_start(args, fmt);
    ret = vprintf(fmt, args);
    va_end(args);

    return ret;
}

static int is_qat_device(int device_id)
{
    if (device_id == QAT_4XXXVF_DEVICE_ID)
        return 1;

    return 0;
}

static int qat_device_type(int device_id)
{
    if (device_id == QAT_4XXXVF_DEVICE_ID)
        return DEVICE_4XXXVF;

    return 0;
}

static char *qat_device_name(int device_id)
{
    if (device_id == QAT_4XXXVF_DEVICE_ID)
        return "4xxxvf";

    return "unknown";
}


static int bit_is_set(uint32_t bitmap[], unsigned index)
{
    const int bits = CHAR_BIT * sizeof(uint32_t);
    return bitmap[index / bits] & (1 << (index % bits));
}

static void set_bit(uint32_t bitmap[], unsigned index)
{
    const int bits = CHAR_BIT * sizeof(uint32_t);
    bitmap[index / bits] |= (1 << (index % bits));
}

void qat_mgr_cleanup_cfg(void)
{
    int i;

    if (section_data)
    {
        for (i = 0; i < num_section_data; i++)
        {
            free(section_data[i].device_data);
            section_data[i].device_data = NULL;

            free(section_data[i].dc_instance_data);
            section_data[i].dc_instance_data = NULL;

            free(section_data[i].cy_instance_data);
            section_data[i].cy_instance_data = NULL;
        }

        free(section_data);
        section_data = NULL;
        num_section_data = 0;
    }
}

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

int qat_mgr_get_dev_list(unsigned *num_devices,
                         struct qatmgr_dev_data *dev_list,
                         const unsigned list_size,
                         int keep_fd)
{
    DIR *devvfio_dir;
    DIR *sysdevice_dir;
    FILE *sysfile;
    struct dirent *vfio_entry;
    struct dirent *device_entry;
    int num_devs = 0;
    unsigned device, vendor;
    char filename[256];
    char devices_dir_name[256];
    int vfiofile = -1;
    char *bdfname;
    unsigned node, bus, dev, func;
    int found = 0;
    struct stat buf;
    int status;

    if (!dev_list || !list_size || !num_devices)
        return -EINVAL;

    *num_devices = 0;

    status = lstat(DEVVFIO_DIR, &buf);
    if (status != 0)
    {
        pr_err("Stat cannot open %s\n", DEVVFIO_DIR);
        return -EIO;
    }
    if (S_ISLNK(buf.st_mode))
    {
        pr_err("Link detected for file %s\n", DEVVFIO_DIR);
        return -EIO;
    }

    devvfio_dir = opendir(DEVVFIO_DIR);
    if (devvfio_dir == NULL)
    {
        pr_err("Cannot open %s\n", DEVVFIO_DIR);
        return -EIO;
    }

    /* For each <group> entry in /dev/vfio/ */
    while ((vfio_entry = readdir(devvfio_dir)) != NULL)
    {
        if (vfio_entry->d_name[0] == '.')
            continue;

        /*
         * A vfio device may be visible but not available.
         * It might, for example, be assigned to a virtual machine.
         * Alternatively, it could be used by another process using
         * a static configuration.
         * In either case, if the device cannot be opened, it should be
         * excluded from the list.
         */
        if (snprintf(filename,
                     sizeof(filename),
                     DEVVFIO_DIR "/%s",
                     vfio_entry->d_name) >= sizeof(filename))
        {
            pr_err("Filename %s truncated\n", filename);
            continue;
        }

        status = lstat(filename, &buf);
        if (status != 0)
        {
            pr_err("Stat cannot open %s\n", filename);
            continue;
        }
        if (S_ISLNK(buf.st_mode) || buf.st_nlink > 1)
        {
            pr_err("Link detected for file %s\n", filename);
            continue;
        }

        vfiofile = open(filename, O_RDWR);
        if (vfiofile < 0)
            continue;

        if (!keep_fd)
        {
            close(vfiofile);
            vfiofile = -1;
        }

        /* open dir /sys/kernel/iommu_groups/<group>/devices/ */
        if (snprintf(devices_dir_name,
                     sizeof(devices_dir_name),
                     IOMMUGROUP_DEV_DIR,
                     vfio_entry->d_name) >= sizeof(devices_dir_name))
        {
            pr_err("Filename truncated\n");
            if (vfiofile != -1)
            {
                close(vfiofile);
                vfiofile = -1;
            }
            continue;
        }

        status = lstat(devices_dir_name, &buf);
        if (status != 0)
        {
            if (vfiofile != -1)
            {
                close(vfiofile);
                vfiofile = -1;
            }
            continue;
        }
        if (S_ISLNK(buf.st_mode))
        {
            if (vfiofile != -1)
            {
                close(vfiofile);
                vfiofile = -1;
            }
            continue;
        }

        sysdevice_dir = opendir(devices_dir_name);
        if (sysdevice_dir == NULL)
        {
            if (vfiofile != -1)
            {
                close(vfiofile);
                vfiofile = -1;
            }
            continue;
        }

        found = 0;
        /* For each device in this group. Should only be one. */
        while ((device_entry = readdir(sysdevice_dir)) != NULL)
        {
            if (device_entry->d_name[0] == '.')
                continue;

            /* Open /sys/kernel/iommu_groups/<group>/devices/<device>/device */
            if (snprintf(filename,
                         sizeof(filename),
                         DEVICE_FILE,
                         vfio_entry->d_name,
                         device_entry->d_name) >= sizeof(filename))
            {
                pr_err("Filename truncated\n");
                break;
            }

            status = lstat(filename, &buf);
            if (status != 0)
            {
                pr_err("Stat cannot open %s\n", filename);
                break;
            }
            if (S_ISLNK(buf.st_mode) || buf.st_nlink > 1)
            {
                pr_err("Link detected for file %s\n", filename);
                break;
            }

            sysfile = fopen(filename, "r");
            if (!sysfile)
                break;
            device = 0;
            if (fscanf(sysfile, "%x", &device) != 1)
            {
                pr_info("Failed to read device from %s\n", filename);
                /*
                 * If the fscanf fails, the check of device ids below will fail
                 * and break out of the loop at that point.
                 */
            }
            fclose(sysfile);
            pr_info("Checking %s\n", filename);
            if (!is_qat_device(device))
                break;

            if (snprintf(filename,
                         sizeof(filename),
                         VENDOR_FILE,
                         vfio_entry->d_name,
                         device_entry->d_name) >= sizeof(filename))
            {
                pr_err("Filename truncated\n");
                break;
            }

            status = lstat(filename, &buf);
            if (status != 0)
            {
                pr_err("Stat cannot open %s\n", filename);
                break;
            }
            if (S_ISLNK(buf.st_mode) || buf.st_nlink > 1)
            {
                pr_err("Link detected for file %s\n", filename);
                break;
            }

            sysfile = fopen(filename, "r");
            if (!sysfile)
            {
                pr_err("Failed to open %s\n", filename);
                break;
            }
            vendor = 0;
            if (fscanf(sysfile, "%x", &vendor) != 1)
            {
                pr_err("Failed to read vendor from %s\n", filename);
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
            if (sscanf(bdfname, "%x:%x:%x.%x", &node, &bus, &dev, &func) != 4)
            {
                pr_info("Failed to scan BDF string\n");
                break;
            }
            dev_list[num_devs].bdf = (node << 16) + ((0xFF & bus) << 8) +
                                     ((0x1F & dev) << 3) + (0x07 & func);
            if (snprintf(dev_list[num_devs].vfio_file,
                         sizeof(dev_list[num_devs].vfio_file),
                         DEVVFIO_DIR "/%s",
                         vfio_entry->d_name) >=
                sizeof(dev_list[num_devs].vfio_file))
            {
                pr_err("Filename truncated\n");
                break;
            }

            if (readdir(sysdevice_dir))
            {
                pr_err("Multiple vfio devices in group %s. Ignored\n",
                       vfio_entry->d_name);
                break;
            }

            found = 1;

            dev_list[num_devs].devid = device;

            if (keep_fd)
                dev_list[num_devs].group_fd = vfiofile;
            else
                dev_list[num_devs].group_fd = -1;

            num_devs++;
        }

        if (!found && vfiofile != -1)
        {
            close(vfiofile);
            vfiofile = -1;
        }

        closedir(sysdevice_dir);
        if (num_devs >= list_size)
            break;
    }
    closedir(devvfio_dir);

    *num_devices = num_devs;

    qsort(dev_list, *num_devices, sizeof(dev_list[0]), bdf_compare);

    return 0;
}

int qat_mgr_build_data(const struct qatmgr_dev_data dev_list[],
                       const int num_devices,
                       int policy,
                       int static_cfg)
{
    int i, j;
    struct qatmgr_section_data *section;
    struct qatmgr_instance_data *dc_inst;
    struct qatmgr_cy_instance_data *cy_inst;
    struct qatmgr_device_data *device_data;
    int num_vf_groups;
    int vf_idx = 0;
    int num_vfs_this_section;
    int num_procs;
    int core = 0;
    uint32_t bus_map[256 / sizeof(uint32_t)];
    int bus;
    unsigned devid;

    if (!num_devices)
        return -EINVAL;

    num_procs = get_nprocs();

    /*
     * A VF group is a set of VFs with the same device/function
     * but from different PFs.
     * The dev_list is sorted so that each VF in a group are consecutive.
     * We know we have a new group when we find a bus that already exists in
     * the first group.
     */
    if (!static_cfg)
    {
        num_vf_groups = 1;
        memset(bus_map, 0, sizeof(bus_map));
        for (i = 0; i < num_devices; i++)
        {
            bus = BDF_BUS(dev_list[i].bdf);
            /* Has this bus number been seen already? */
            if (bit_is_set(bus_map, bus))
            {
                num_vf_groups++;
                memset(bus_map, 0, sizeof(bus_map));
            }
            set_bit(bus_map, bus);
        }
        pr_dbg("num_vf_groups %d\n", num_vf_groups);

        /*
         * For policy 0, each process will get a VF from each PF so there will
         * be num_vf_groups processes.
         * For policy <n>, each process will get <n> VFs so there will be
         * num_devices / <n> processes.
         */
        if (policy == 0)
        {
            num_section_data = num_vf_groups;
        }
        else
        {
            num_section_data = num_devices / policy;
            if (num_devices % policy)
                num_section_data++;
        }

        if (num_section_data <= 0)
        {
            pr_err("num_section_data is less or equal 0: %d\n",
                   num_section_data);
            return -EINVAL;
        }
        pr_dbg("num_section_data %d\n", num_section_data);
    }
    else if (num_devices >= policy)
    {
        num_section_data = 1;
    }
    else
    {
        pr_err("Policy %d is incompatible with the number of "
               "available devices %d\n",
               policy,
               num_devices);
        return -EINVAL;
    }

    section_data = calloc(num_section_data, sizeof(struct qatmgr_section_data));
    if (!section_data)
    {
        pr_err("Malloc failed for section data\n");
        qat_mgr_cleanup_cfg();
        return -EAGAIN;
    }

    section = section_data;
    for (i = 0; i < num_section_data; i++, section++)
    {
        snprintf(section->section_name,
                 sizeof(section->section_name),
                 "SSL_INT_%d",
                 i);
        snprintf(section->base_name, sizeof(section->base_name), "SSL");
        section->assigned_tid = 0;

        if (policy)
        {
            num_vfs_this_section = policy;
            if (num_vfs_this_section > num_devices - vf_idx)
                num_vfs_this_section = num_devices - vf_idx;
        }
        else
        {
            /*
             * Policy 0, one VF from each different PF.
             * Count the number of different PF from here.
             * Not all sectons necessarily have the same number of VFs.
             */
            num_vfs_this_section = 0;
            memset(bus_map, 0, sizeof(bus_map));
            for (j = vf_idx; j < num_devices; j++)
            {
                bus = BDF_BUS(dev_list[j].bdf);
                /* Has this bus number been seen already? */
                if (bit_is_set(bus_map, bus))
                    break;
                num_vfs_this_section++;
                set_bit(bus_map, bus);
            }
        }
        section->num_devices = num_vfs_this_section;

        /* Create device data */
        section->device_data =
            calloc(num_vfs_this_section, sizeof(struct qatmgr_device_data));
        if (!section->device_data)
        {
            pr_err("Malloc failed for device data\n");
            qat_mgr_cleanup_cfg();
            return -EAGAIN;
        }

        device_data = section->device_data;
        for (j = 0; j < num_vfs_this_section; j++, device_data++, vf_idx++)
        {
            pr_dbg("section %d, BDF %X\n", i, dev_list[vf_idx].bdf);
            snprintf(device_data->device_id,
                     sizeof(device_data->device_id),
                     "%04x:%02x:%02x.%01x",
                     BDF_NODE(dev_list[vf_idx].bdf),
                     BDF_BUS(dev_list[vf_idx].bdf),
                     BDF_DEV(dev_list[vf_idx].bdf),
                     BDF_FUN(dev_list[vf_idx].bdf));
            snprintf(device_data->device_file,
                     sizeof(device_data->device_file),
                     "%s",
                     dev_list[vf_idx].vfio_file);
            device_data->group_fd = dev_list[vf_idx].group_fd;
            device_data->accelid = j;
            device_data->node = BDF_NODE(dev_list[vf_idx].bdf);

            devid = dev_list[vf_idx].devid;

                device_data->max_banks = 4;
                device_data->max_rings_per_bank = 2;
                device_data->arb_mask = 0x01;
                device_data->accel_capabilities =
                    ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
                    ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
                    ICP_ACCEL_CAPABILITIES_CIPHER |
                    ICP_ACCEL_CAPABILITIES_AUTHENTICATION |
                    ICP_ACCEL_CAPABILITIES_CRYPTO_SHA3 |
                    ICP_ACCEL_CAPABILITIES_HKDF |
                    ICP_ACCEL_CAPABILITIES_ECEDMONT |
                    ICP_ACCEL_CAPABILITIES_AESGCM_SPC;
                device_data->extended_capabilities = 0x0;
            snprintf(device_data->name,
                     sizeof(device_data->name),
                     "%s",
                     qat_device_name(devid));
            device_data->device_type = qat_device_type(devid);

            device_data->services = SERV_TYPE_CY;
        }

        section->num_cy_inst = 2;
        section->num_sym_inst = 2;
        section->num_asym_inst = 2;
        section->num_dc_inst = 0;

        if (section->num_dc_inst)
        {
            /* Create and populate instance data */
            section->dc_instance_data = calloc(
                section->num_dc_inst,
                num_vfs_this_section * sizeof(struct qatmgr_instance_data));
            if (!section->dc_instance_data)
            {
                pr_err("Malloc failed for dc instance data\n");
                qat_mgr_cleanup_cfg();
                return -EAGAIN;
            }

            dc_inst = section->dc_instance_data;
            for (j = 0; j < section->num_dc_inst * num_vfs_this_section;
                 j++, dc_inst++)
            {
                snprintf(dc_inst->name, sizeof(dc_inst->name), "dc%d", j);
                dc_inst->accelid = j / section->num_dc_inst;
                dc_inst->service_type = SERV_TYPE_DC;
                dc_inst->bank_number = 0;

                devid = dev_list[dc_inst->accelid].devid;
                    dc_inst->ring_tx = 0 + j % section->num_dc_inst;
                    dc_inst->ring_rx = 1 + j % section->num_dc_inst;
                dc_inst->is_polled = 1;
                dc_inst->num_concurrent_requests = 512;
                dc_inst->core_affinity = core;
                core = (core + 1) % num_procs;
            }
        }

        if (section->num_cy_inst)
        {
            section->cy_instance_data = calloc(
                section->num_cy_inst,
                num_vfs_this_section * sizeof(struct qatmgr_cy_instance_data));
            if (!section->cy_instance_data)
            {
                pr_err("Malloc failed for cy instance data\n");
                qat_mgr_cleanup_cfg();
                return -EAGAIN;
            }

            cy_inst = section->cy_instance_data;
            for (j = 0; j < section->num_cy_inst * num_vfs_this_section;
                 j++, cy_inst++)
            {
                snprintf(cy_inst->asym.name,
                         sizeof(cy_inst->asym.name),
                         "asym%d",
                         j);
                cy_inst->asym.accelid = j / section->num_cy_inst;
                cy_inst->asym.service_type = SERV_TYPE_ASYM;

                devid = dev_list[cy_inst->asym.accelid].devid;

                    cy_inst->asym.bank_number = (j % section->num_cy_inst) * 2;
                    cy_inst->asym.ring_tx = 0;
                    cy_inst->asym.ring_rx = 1;
                cy_inst->asym.is_polled = 1;
                cy_inst->asym.num_concurrent_requests = 64;
                cy_inst->asym.core_affinity = core;
                core = (core + 1) % num_procs;

                snprintf(
                    cy_inst->sym.name, sizeof(cy_inst->sym.name), "sym%d", j);
                cy_inst->sym.accelid = j / section->num_cy_inst;
                cy_inst->sym.service_type = SERV_TYPE_SYM;

                    cy_inst->sym.bank_number =
                        (j % section->num_cy_inst) * 2 + 1;
                    cy_inst->sym.ring_tx = 0;
                    cy_inst->sym.ring_rx = 1;
                cy_inst->sym.is_polled = 1;
                cy_inst->sym.num_concurrent_requests = 512;
                cy_inst->sym.core_affinity = core;
                core = (core + 1) % num_procs;
            }
        }
    }

    return 0;
}

bool qat_mgr_is_dev_available()
{
    bool dev_found = false;
    char filename[256];
    DIR *devvfio_dir;
    struct dirent *vfio_entry;
    struct stat buf;
    int status;

    status = stat(DEVVFIO_DIR, &buf);
    if (status != 0)
    {
        pr_err("Stat cannot open %s\n", DEVVFIO_DIR);
        return false;
    }
    if (S_ISLNK(buf.st_mode))
    {
        pr_err("Link detected for file %s\n", DEVVFIO_DIR);
        return false;
    }

    devvfio_dir = opendir(DEVVFIO_DIR);

    if (devvfio_dir == NULL)
    {
        pr_err("Cannot open %s\n", DEVVFIO_DIR);
        return false;
    }

    /* For each <group> entry in /dev/vfio/ */
    while ((vfio_entry = readdir(devvfio_dir)) != NULL)
    {
        struct stat info;
        struct group *grp;

        if (vfio_entry->d_name[0] == '.')
            continue;

        if (snprintf(filename,
                     sizeof(filename),
                     DEVVFIO_DIR "/%s",
                     vfio_entry->d_name) >= sizeof(filename))
        {
            pr_err("Filename %s truncated\n", filename);
            continue;
        }

        if (stat(filename, &info) != 0)
        {
            continue;
        }

        grp = getgrgid(info.st_gid);

        if (ICP_STRNCMP_CONST(grp->gr_name, DEVICE_GROUP) == 0)
        {
            dev_found = true;
            break;
        }
    }

    return dev_found;
}

void dump_message(void *ptr, char *text)
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
    printf("Message type %d\n", req->hdr.type);
    printf("   length %d\n", req->hdr.len);
    payload_size = req->hdr.len - sizeof(req->hdr);
    payload = (uint8_t *)req + sizeof(req->hdr);
    if (payload_size > 0)
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
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static void err_msg(struct qatmgr_msg_rsp *rsp, char *text)
{
    rsp->hdr.type = QATMGR_MSGTYPE_BAD;
    rsp->hdr.version = 0;
    strncpy(rsp->error_text, text, sizeof(rsp->error_text) - 1);
    rsp->hdr.len =
        sizeof(rsp->hdr) + ICP_ARRAY_STRLEN_SANITIZE(rsp->error_text) + 1;
}

static void build_msg_header(struct qatmgr_msg_rsp *rsp,
                             int type,
                             int payload_size)
{
    ICP_CHECK_FOR_NULL_PARAM_VOID(rsp);

    rsp->hdr.type = type;
    rsp->hdr.version = 0;
    rsp->hdr.len = sizeof(rsp->hdr) + payload_size;
}

static int handle_get_num_devices(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  int index)
{
    struct qatmgr_section_data *section;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr))
    {
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    rsp->num_devices = section->num_devices;
    build_msg_header(rsp, QATMGR_MSGTYPE_NUM_DEVICES, sizeof(rsp->num_devices));

    dump_message(rsp, "QATMGR_MSGTYPE_NUM_DEVICES");
    return 0;
}

static int handle_get_device_info(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  int index)
{
    struct qatmgr_section_data *section;
    unsigned device_num;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->device_num))
    {
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    device_num = req->device_num;
    if (device_num >= section->num_devices)
    {
        pr_err("Invalid device %d >= %d\n", device_num, section->num_devices);
        err_msg(rsp, "Invalid device number");
        return -1;
    }

    rsp->device_info.device_num = device_num;
    rsp->device_info.device_type = section->device_data[device_num].device_type;
    ICP_STRNCPY(rsp->device_info.device_name,
                section->device_data[device_num].name,
                sizeof(rsp->device_info.device_name));
    rsp->device_info.capability_mask =
        section->device_data[device_num].accel_capabilities;
    rsp->device_info.extended_capabilities =
        section->device_data[device_num].extended_capabilities;
    rsp->device_info.max_banks = section->device_data[device_num].max_banks;
    rsp->device_info.max_rings_per_bank =
        section->device_data[device_num].max_rings_per_bank;
    rsp->device_info.arb_mask = section->device_data[device_num].arb_mask;
    rsp->device_info.services = section->device_data[device_num].services;
    rsp->device_info.pkg_id = section->device_data[device_num].accelid;
    rsp->device_info.node_id = section->device_data[device_num].node;
    build_msg_header(rsp, QATMGR_MSGTYPE_DEVICE_INFO, sizeof(rsp->device_info));

    dump_message(rsp, "QATMGR_MSGTYPE_DEVICE_INFO");
    return 0;
}

static int handle_get_device_id(struct qatmgr_msg_req *req,
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
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    device_num = req->device_num;
    if (device_num >= section->num_devices)
    {
        pr_err("Invalid device %d\n", device_num);
        err_msg(rsp, "Invalid device number");
        return -1;
    }
    device_data = section->device_data;
    device_data += device_num;

    rsp->hdr.type = QATMGR_MSGTYPE_DEVICE_ID;
    rsp->hdr.version = 0;
    strncpy(rsp->device_id, device_data->device_id, sizeof(rsp->device_id));
    build_msg_header(rsp,
                     QATMGR_MSGTYPE_DEVICE_ID,
                     ICP_ARRAY_STRLEN_SANITIZE(rsp->device_id) + 1);
    dump_message(rsp, "QATMGR_MSGTYPE_DEVICE_ID");
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
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    device_num = req->device_num;
    if (device_num >= section->num_devices)
    {
        pr_err("Invalid device %d\n", device_num);
        err_msg(rsp, "Invalid device number");
        return -1;
    }
    device_data = section->device_data;
    device_data += device_num;

    rsp->hdr.type = QATMGR_MSGTYPE_VFIO_FILE;
    rsp->hdr.version = 0;
    rsp->vfio_file.fd = device_data->group_fd;

    strncpy(rsp->vfio_file.name,
            device_data->device_file,
            sizeof(rsp->vfio_file.name));

    len = ICP_ARRAY_STRLEN_SANITIZE(rsp->vfio_file.name);

    build_msg_header(
        rsp, QATMGR_MSGTYPE_VFIO_FILE, sizeof(rsp->vfio_file.fd) + len + 1);

    dump_message(rsp, "QATMGR_MSGTYPE_VFIO_FILE");
    return 0;
}

static int handle_get_section_info(struct qatmgr_msg_req *req,
                                   struct qatmgr_msg_rsp *rsp,
                                   int index)
{
    struct qatmgr_section_data *section;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr))
    {
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    rsp->section_info.num_cy_instances = section->num_cy_inst;
    rsp->section_info.num_dc_instances = section->num_dc_inst;
    build_msg_header(
        rsp, QATMGR_MSGTYPE_SECTION_INFO, sizeof(rsp->section_info));

    dump_message(rsp, "QATMGR_MSGTYPE_SECTION_INFO");
    return 0;
}

static int handle_get_instance_name(struct qatmgr_msg_req *req,
                                    struct qatmgr_msg_rsp *rsp,
                                    int index)
{
    struct qatmgr_section_data *section;
    int instance_type;
    int instance_num;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->inst))
    {
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    instance_type = req->inst.type;
    instance_num = req->inst.num;

    if (instance_type == SERV_TYPE_DC)
    {
        if (instance_num < 0 || instance_num >= section->num_dc_inst)
        {
            pr_err("Bad dc instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid DC instance number");
            return -1;
        }
        strncpy(rsp->name, section->dc_instance_data->name, sizeof(rsp->name));
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_CY)
    {
        if (instance_num < 0 || instance_num >= section->num_cy_inst)
        {
            pr_err("Bad cy instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid CY instance number");
            return -1;
        }
        strncpy(
            rsp->name, section->cy_instance_data->sym.name, sizeof(rsp->name));
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_SYM)
    {
        if (instance_num < 0 || instance_num >= section->num_sym_inst)
        {
            pr_err("Bad cy.sym instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid SYM instance number");
            return -1;
        }
        strncpy(
            rsp->name, section->cy_instance_data->sym.name, sizeof(rsp->name));
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else if (instance_type == SERV_TYPE_ASYM)
    {
        if (instance_num < 0 || instance_num >= section->num_asym_inst)
        {
            pr_err("Bad cy.asym instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid ASYM instance number");
            return -1;
        }
        strncpy(
            rsp->name, section->cy_instance_data->asym.name, sizeof(rsp->name));
        build_msg_header(rsp,
                         QATMGR_MSGTYPE_INSTANCE_NAME,
                         ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1);
    }
    else
    {
        pr_err("unsupported instance type %d\n", instance_type);
        err_msg(rsp, "Unknown instance type");
        return -1;
    }
    dump_message(rsp, "QATMGR_MSGTYPE_INSTANCE_NAME");
    return 0;
}

static int handle_get_instance_info(struct qatmgr_msg_req *req,
                                    struct qatmgr_msg_rsp *rsp,
                                    int index)
{
    struct qatmgr_section_data *section;
    struct qatmgr_instance_data *instance_data;
    struct qatmgr_cy_instance_data *cy_instance_data;
    int instance_type;
    int instance_num;
    int device_num;

    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (req->hdr.len != sizeof(req->hdr) + sizeof(req->inst))
    {
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Bad index\n");
        err_msg(rsp, "Invalid index");
        return -1;
    }
    section = section_data + index;

    instance_type = req->inst.type;
    instance_num = req->inst.num;
    device_num = req->inst.device_num;

    if (device_num >= section->num_devices)
    {
        pr_err("Invalid device number %d for section %d\n", device_num, index);
        err_msg(rsp, "Invalid device number");
        return -1;
    }

    if (instance_type == SERV_TYPE_DC)
    {
        if (instance_num < 0 || instance_num >= section->num_dc_inst)
        {
            pr_err("Bad dc instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid DC instance number");
            return -1;
        }
        instance_data = section->dc_instance_data + instance_num +
                        device_num * section->num_dc_inst;
        rsp->instance_info.dc.accelid = instance_data->accelid;
        rsp->instance_info.dc.bank_number = instance_data->bank_number;
        rsp->instance_info.dc.is_polled = instance_data->is_polled;
        rsp->instance_info.dc.core_affinity = instance_data->core_affinity;
        rsp->instance_info.dc.num_concurrent_requests =
            instance_data->num_concurrent_requests;
        rsp->instance_info.dc.ring_tx = instance_data->ring_tx;
        rsp->instance_info.dc.ring_rx = instance_data->ring_rx;

        build_msg_header(
            rsp, QATMGR_MSGTYPE_INSTANCE_INFO, sizeof(rsp->instance_info));
    }
    else if (instance_type == SERV_TYPE_CY)
    {
        if (instance_num < 0 || instance_num >= section->num_cy_inst)
        {
            pr_err("Bad cy instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid CY instance number");
            return -1;
        }
        cy_instance_data = section->cy_instance_data + instance_num +
                           device_num * section->num_cy_inst;
        instance_data = &cy_instance_data->sym;
        rsp->instance_info.cy.sym.accelid = instance_data->accelid;
        rsp->instance_info.cy.sym.bank_number = instance_data->bank_number;
        rsp->instance_info.cy.sym.is_polled = instance_data->is_polled;
        rsp->instance_info.cy.sym.core_affinity = instance_data->core_affinity;
        rsp->instance_info.cy.sym.num_concurrent_requests =
            instance_data->num_concurrent_requests;
        rsp->instance_info.cy.sym.ring_tx = instance_data->ring_tx;
        rsp->instance_info.cy.sym.ring_rx = instance_data->ring_rx;

        instance_data = &cy_instance_data->asym;
        rsp->instance_info.cy.asym.accelid = instance_data->accelid;
        rsp->instance_info.cy.asym.bank_number = instance_data->bank_number;
        rsp->instance_info.cy.asym.is_polled = instance_data->is_polled;
        rsp->instance_info.cy.asym.core_affinity = instance_data->core_affinity;
        rsp->instance_info.cy.asym.num_concurrent_requests =
            instance_data->num_concurrent_requests;
        rsp->instance_info.cy.asym.ring_tx = instance_data->ring_tx;
        rsp->instance_info.cy.asym.ring_rx = instance_data->ring_rx;
        build_msg_header(
            rsp, QATMGR_MSGTYPE_INSTANCE_INFO, sizeof(rsp->instance_info));
    }
    else if (instance_type == SERV_TYPE_SYM)
    {
        if (instance_num < 0 || instance_num >= section->num_sym_inst)
        {
            pr_err("Bad cy.sym instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid SYM instance number");
            return -1;
        }
        cy_instance_data = section->cy_instance_data + instance_num +
                           device_num * section->num_cy_inst;
        instance_data = &cy_instance_data->sym;
        rsp->instance_info.cy.sym.accelid = instance_data->accelid;
        rsp->instance_info.cy.sym.bank_number = instance_data->bank_number;
        rsp->instance_info.cy.sym.is_polled = instance_data->is_polled;
        rsp->instance_info.cy.sym.core_affinity = instance_data->core_affinity;
        rsp->instance_info.cy.sym.num_concurrent_requests =
            instance_data->num_concurrent_requests;
        rsp->instance_info.cy.sym.ring_tx = instance_data->ring_tx;
        rsp->instance_info.cy.sym.ring_rx = instance_data->ring_rx;
        build_msg_header(
            rsp, QATMGR_MSGTYPE_INSTANCE_INFO, sizeof(rsp->instance_info));
    }
    else if (instance_type == SERV_TYPE_ASYM)
    {
        if (instance_num < 0 ||
            instance_num >= section_data[index].num_asym_inst)
        {
            pr_err("Bad cy.asym instance number %d for section %d\n",
                   instance_num,
                   index);
            err_msg(rsp, "Invalid ASYM instance number");
            return -1;
        }
        cy_instance_data = section->cy_instance_data + instance_num +
                           device_num * section->num_cy_inst;
        instance_data = &cy_instance_data->asym;
        rsp->instance_info.cy.asym.accelid = instance_data->accelid;
        rsp->instance_info.cy.asym.bank_number = instance_data->bank_number;
        rsp->instance_info.cy.asym.is_polled = instance_data->is_polled;
        rsp->instance_info.cy.asym.core_affinity = instance_data->core_affinity;
        rsp->instance_info.cy.asym.num_concurrent_requests =
            instance_data->num_concurrent_requests;
        rsp->instance_info.cy.asym.ring_tx = instance_data->ring_tx;
        rsp->instance_info.cy.asym.ring_rx = instance_data->ring_rx;
        build_msg_header(
            rsp, QATMGR_MSGTYPE_INSTANCE_INFO, sizeof(rsp->instance_info));
    }
    else
    {
        pr_err("Unsupported instance type %d\n", instance_type);
        err_msg(rsp, "Unknown instance type");
        return -1;
    }

    dump_message(rsp, "QATMGR_MSGTYPE_INSTANCE_INFO");
    return 0;
}

int release_section(int index, pthread_t tid, char *name, size_t name_len)
{
    ICP_CHECK_FOR_NULL_PARAM(name);

    if (index < 0 || index >= num_section_data)
    {
        pr_err("Invalid section index %d for thread %lu, section %s\n",
               index,
               tid,
               name);
        return -1;
    }
    if (name_len !=
            ICP_ARRAY_STRLEN_SANITIZE(section_data[index].section_name) ||
        strncmp(name, section_data[index].section_name, name_len))
    {
        pr_err("Incorrect section name %s, expected %s\n",
               name,
               section_data[index].section_name);
        return -1;
    }
    if (section_data[index].assigned_tid != tid)
    {
        pr_err("Incorrect thread %lu for section %s. Expected %lu\n",
               tid,
               name,
               section_data[index].assigned_tid);
        return -1;
    }
    pr_info("Released section %s\n", name);
    section_data[index].assigned_tid = 0;
    return 0;
}

static int get_section(pthread_t tid, char **derived_section_name)
{
    int i;

    for (i = 0; i < num_section_data; i++)
    {
        if (section_data[i].assigned_tid)
            continue; /* Assigned to another thread */

        section_data[i].assigned_tid = tid;
        pr_dbg("Got section %s\n", section_data[i].section_name);
        if (derived_section_name)
            *derived_section_name = section_data[i].section_name;
        return i;
    }
    return -1;
}

static int handle_section_request(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  char **section_name,
                                  pid_t tid,
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
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }
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
        pr_err("Section already allocated\n");
        err_msg(rsp, "Section already allocated");
        return -1;
    }

    sec = get_section(tid, &derived_name);
    if (sec < 0)
    {
        pr_err("Couldn't get secton %s\n", req->name);
        err_msg(rsp, "No section available");
        return -1;
    }

    *index = sec;
    rsp->hdr.type = QATMGR_MSGTYPE_SECTION_GET;
    rsp->hdr.version = 0;
    strncpy(rsp->name, derived_name, sizeof(rsp->name));
    rsp->name[sizeof(rsp->name) - 1] = '\0';
    rsp->hdr.len = sizeof(rsp->hdr) + ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1;

    name_buf_size = ICP_ARRAY_STRLEN_SANITIZE(rsp->name) + 1;
    *section_name = malloc(name_buf_size);
    if (!*section_name)
    {
        pr_err("Memory allocation failed\n");
        err_msg(rsp, "malloc failed");
        return -1;
    }
    pr_dbg("Allocated section %s at %p\n", rsp->name, *section_name);
    strncpy(*section_name, rsp->name, name_buf_size);

    return 0;
}

static int handle_section_release(struct qatmgr_msg_req *req,
                                  struct qatmgr_msg_rsp *rsp,
                                  char **section_name,
                                  pid_t tid,
                                  int *index)
{
    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);
    ICP_CHECK_FOR_NULL_PARAM(index);
    ICP_CHECK_FOR_NULL_PARAM(section_name);

    if (req->hdr.len !=
        sizeof(req->hdr) + ICP_ARRAY_STRLEN_SANITIZE(req->name) + 1)
    {
        pr_err("Bad length\n");
        err_msg(rsp, "Inconsistent length");
        return -1;
    }

    if (*section_name == NULL)
    {
        pr_err("Section not allocated\n");
        err_msg(rsp, "Section not allocated");
        return -1;
    }
    if (release_section(
            *index, tid, req->name, ICP_ARRAY_STRLEN_SANITIZE(req->name)))
    {
        err_msg(rsp, "Failed to release section");
    }
    else
    {
        pr_dbg("Section %s released\n", req->name);
        build_msg_header(rsp, QATMGR_MSGTYPE_SECTION_PUT, 0);
        if (*section_name)
        {
            free(*section_name);
            *section_name = NULL;
            *index = -1;
        }
    }
    return 0;
}

int handle_message(struct qatmgr_msg_req *req,
                   struct qatmgr_msg_rsp *rsp,
                   char **section_name,
                   pid_t tid,
                   int *index)
{
    ICP_CHECK_FOR_NULL_PARAM(req);
    ICP_CHECK_FOR_NULL_PARAM(rsp);
    ICP_CHECK_FOR_NULL_PARAM(index);
    ICP_CHECK_FOR_NULL_PARAM(section_name);

    dump_message(req, "Request");

    switch (req->hdr.type)
    {
        case QATMGR_MSGTYPE_SECTION_GET:
            return handle_section_request(req, rsp, section_name, tid, index);
        case QATMGR_MSGTYPE_SECTION_PUT:
            return handle_section_release(req, rsp, section_name, tid, index);
        case QATMGR_MSGTYPE_NUM_DEVICES:
            return handle_get_num_devices(req, rsp, *index);
        case QATMGR_MSGTYPE_DEVICE_INFO:
            return handle_get_device_info(req, rsp, *index);
        case QATMGR_MSGTYPE_DEVICE_ID:
            return handle_get_device_id(req, rsp, *index);
        case QATMGR_MSGTYPE_SECTION_INFO:
            return handle_get_section_info(req, rsp, *index);
        case QATMGR_MSGTYPE_INSTANCE_INFO:
            return handle_get_instance_info(req, rsp, *index);
        case QATMGR_MSGTYPE_INSTANCE_NAME:
            return handle_get_instance_name(req, rsp, *index);
        case QATMGR_MSGTYPE_VFIO_FILE:
            return handle_get_vfio_name(req, rsp, *index);
        default:
            err_msg(rsp, "Unknown message");
    }

    return -1;
}
