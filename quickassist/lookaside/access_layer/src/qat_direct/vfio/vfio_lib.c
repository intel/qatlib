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
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/pci_regs.h>
#include <linux/vfio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "adf_pfvf_vf_msg.h"
#include "vfio_lib.h"
#include "icp_platform.h"
#include "qat_log.h"

static int container_fd = -1;
static int container_fd_ref = 0;

#define VFIO_GET_REGION_ADDR(x) ((uint64_t)x << 40ULL)

/* PMISC BAR number */
#define ADF_PMISC_BAR 1

static int pci_vfio_set_command(int dev_fd, int command, bool op)
{
    uint16_t reg;
    int ret;

    ret =
        pread(dev_fd,
              &reg,
              sizeof(reg),
              VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) + PCI_COMMAND);
    if (ret != sizeof(reg))
    {
        ADF_ERROR("Cannot read command from PCI config space!\n");
        return -1;
    }

    if (op)
        /* set the bit */
        reg |= command;
    else
        reg &= ~(command);

    ret = pwrite(dev_fd,
                 &reg,
                 sizeof(reg),
                 VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
                     PCI_COMMAND);

    if (ret != sizeof(reg))
    {
        ADF_ERROR("Cannot write command to PCI config space!\n");
        return -1;
    }

    return 0;
}

static void init_bar(pcs_t *pcs)
{
    ICP_CHECK_FOR_NULL_PARAM_VOID(pcs);
    memset(pcs, 0, sizeof(pcs_t));
}

static void add_bar(pcs_t *pcs, void *ptr, const size_t size)
{
    size_t idx = 0;

    ICP_CHECK_FOR_NULL_PARAM_VOID(pcs);
    ICP_CHECK_FOR_NULL_PARAM_VOID(ptr);

    idx = pcs->nr_bar;
    if (idx >= MAX_BAR_NR)
    {
        ADF_ERROR("add_bar: invalid idx %d\n", idx);
        return;
    }

    pcs->bar[idx].ptr = ptr;
    pcs->bar[idx].size = size;
    pcs->nr_bar += 1;
}

static void remove_and_close_group(vfio_dev_info_t *dev)
{
    int ret = 0;
    ICP_CHECK_FOR_NULL_PARAM_VOID(dev);

    ret = ioctl(
        dev->vfio_group_fd, VFIO_GROUP_UNSET_CONTAINER, dev->vfio_container_fd);
    if (ret)
    {
        ADF_ERROR("VFIO_GROUP_UNSET_CONTAINER ioctl failed\n");
    }
    --container_fd_ref;
    close(dev->vfio_group_fd);
    dev->vfio_group_fd = -1;

    if (!container_fd_ref)
    {
        close(container_fd);
        container_fd = -1;
    }
}

int open_vfio_dev(const char *vfio_file,
                  const char *bdf,
                  int group_fd,
                  unsigned int pci_id,
                  vfio_dev_info_t *dev)
{
    int i;
    int ret;
    int already_enabled = 0;
    static pid_t pid = 0;

    struct vfio_group_status group_status = {.argsz = sizeof(group_status)};
    struct vfio_device_info device_info = {.argsz = sizeof(device_info)};

    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(dev, -1);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(vfio_file, -1);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(bdf, -1);

    init_bar(&dev->pcs);

    if (container_fd >= 0 && pid != getpid())
    {
        /* Child process inherited fd from parent */
        close(container_fd);
        container_fd = -1;
        container_fd_ref = 0;
    }

    if (container_fd < 0)
    {
        /* Create a new container */
        container_fd = open("/dev/vfio/vfio", O_RDWR);
        pid = getpid();

        ret = ioctl(container_fd, VFIO_GET_API_VERSION);
        if (VFIO_API_VERSION != ret)
        {
            ADF_ERROR("VFIO_GET_API_VERSION ioctl failed\n");
            return -1;
        }

        ret = ioctl(container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU);
        if (!ret)
        {
            ADF_ERROR("VFIO_CHECK_EXTENSION ioctl failed\n");
            return -1;
        }
    }
    else
    {
        already_enabled = 1;
    }

    dev->vfio_container_fd = container_fd;
    if (group_fd >= 0)
    {
        dev->vfio_group_fd = group_fd;
    }
    else
    {
        dev->vfio_group_fd = open(vfio_file, O_RDWR);
        if (dev->vfio_group_fd < 0)
        {
            ADF_ERROR("Cannot open %s\n", vfio_file);
            return -1;
        }
    }

    /* Test the group is viable and available */
    ret = ioctl(dev->vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
    if (ret)
    {
        ADF_ERROR("VFIO_GROUP_GET_STATUS ioctl failed\n");
        close(dev->vfio_group_fd);
        return -1;
    }

    if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE))
    {
        ADF_ERROR("Group is not viable (ie, not all devices bound for vfio)\n");
        close(dev->vfio_group_fd);
        return -1;
    }

    /* Add the group to the container */
    ret = ioctl(
        dev->vfio_group_fd, VFIO_GROUP_SET_CONTAINER, &dev->vfio_container_fd);
    if (ret)
    {
        ADF_ERROR("VFIO_GROUP_SET_CONTAINER ioctl failed\n");
        close(dev->vfio_group_fd);
        return -1;
    }
    container_fd_ref++;

    if (!already_enabled)
    {
        ret = ioctl(dev->vfio_container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
        if (ret)
        {
            ADF_ERROR("VFIO_SET_IOMMU ioctl failed\n");
            remove_and_close_group(dev);

            return -1;
        }
    }

    /* Get a file descriptor for the device */
    dev->vfio_dev_fd = ioctl(dev->vfio_group_fd, VFIO_GROUP_GET_DEVICE_FD, bdf);
    if (dev->vfio_dev_fd < 0)
    {
        ADF_ERROR("VFIO_GROUP_GET_DEVICE_FD ioctl failed\n");
        remove_and_close_group(dev);
        return -1;
    }

    if (pci_vfio_set_command(dev->vfio_dev_fd, PCI_COMMAND_MEMORY, true))
    {
        ADF_ERROR("Cannot enable memory access!\n");
        close(dev->vfio_dev_fd);
        remove_and_close_group(dev);

        return -1;
    }

    /* Test and setup the device */
    ret = ioctl(dev->vfio_dev_fd, VFIO_DEVICE_GET_INFO, &device_info);
    if (ret)
    {
        ADF_ERROR("VFIO_DEVICE_GET_INFO ioctl failed\n");
        close(dev->vfio_dev_fd);
        remove_and_close_group(dev);
        return -1;
    }

    for (i = 0; i < device_info.num_regions; i++)
    {
        struct vfio_region_info reg = {.argsz = sizeof(reg)};

        reg.index = i;

        /* Setup mappings... read/write offsets, mmaps
         * For PCI devices, config space is a region */
        ret = ioctl(dev->vfio_dev_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
        if (ret)
        {
            if (!reg.size)
            {
                ADF_DEBUG("VFIO_DEVICE_GET_REGION_INFO ioctl failed, "
                          "detected zero sized region, "
                          "unimplemented PCI BAR possible\n");
            }
            else
            {
                ADF_ERROR("VFIO_DEVICE_GET_REGION_INFO ioctl failed\n");
            }
        }
        /* skip non-mmapable BARs */
        if ((reg.flags & VFIO_REGION_INFO_FLAG_MMAP) == 0)
        {
            continue;
        }

        if (reg.flags & VFIO_REGION_INFO_FLAG_WRITE)
        {
            void *ptr = mmap(NULL,
                             reg.size,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED,
                             dev->vfio_dev_fd,
                             reg.offset);

            if (MAP_FAILED != ptr)
            {
                add_bar(&dev->pcs, ptr, reg.size);
            }
        }
    }

    if (pci_vfio_set_command(dev->vfio_dev_fd, PCI_COMMAND_MASTER, true))
    {
        ADF_ERROR("Fail to set BME.\n");
        close_vfio_dev(dev);

        return -1;
    }

    /* Gratuitous device reset and go... */
    ret = ioctl(dev->vfio_dev_fd, VFIO_DEVICE_RESET);
    if (ret)
    {
        ADF_ERROR("VFIO_DEVICE_RESET ioctl failed\n");
        close_vfio_dev(dev);

        return -1;
    }

    /* Init VF2PF communication */
    dev->pfvf = adf_init_pfvf_dev_data(dev->pcs.bar[ADF_PMISC_BAR].ptr, pci_id);

    return 0;
}

void close_vfio_dev(vfio_dev_info_t *dev)
{
    int idx;
    pcs_t *pcs;

    ICP_CHECK_FOR_NULL_PARAM_VOID(dev);

    pcs = &dev->pcs;
    for (idx = pcs->nr_bar - 1; idx >= 0; idx--)
        (void)munmap(pcs->bar[idx].ptr, pcs->bar[idx].size);
    pcs->nr_bar = 0;

    pci_vfio_set_command(dev->vfio_dev_fd, PCI_COMMAND_MEMORY, false);

    pci_vfio_set_command(dev->vfio_dev_fd, PCI_COMMAND_MASTER, false);

    close(dev->vfio_dev_fd);
    dev->vfio_dev_fd = -1;
    remove_and_close_group(dev);
}
