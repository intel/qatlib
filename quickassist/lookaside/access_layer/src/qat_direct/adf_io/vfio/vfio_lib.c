/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "adf_pfvf_vf_msg.h"
#include "vfio_lib.h"
#include "icp_platform.h"
#include "qat_log.h"

static int container_fd = -1;
static int container_fd_ref = 0;

/* PMISC BAR number */
#define ADF_PMISC_BAR 1

#define IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + sizeof(int))

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
        ADF_ERROR("add_bar: invalid idx %lu\n", idx);
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
    if (container_fd_ref)
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

    struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
    struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
    struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info),
                                          .index = VFIO_PCI_MSI_IRQ_INDEX };
    char irq_set_buf[IRQ_SET_BUF_LEN];
    struct vfio_irq_set *irq_set;
    int *fd_ptr;
    int evtfd;

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
            ADF_DEBUG("Cannot open %s\n", vfio_file);
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
        if (strstr(vfio_file, "noiommu"))
            ret = ioctl(dev->vfio_container_fd, VFIO_SET_IOMMU,
                        VFIO_NOIOMMU_IOMMU);
        else
            ret = ioctl(dev->vfio_container_fd, VFIO_SET_IOMMU,
                        VFIO_TYPE1_IOMMU);

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
        ADF_DEBUG("VFIO_GROUP_GET_DEVICE_FD ioctl failed\n");
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
        struct vfio_region_info reg = { .argsz = sizeof(reg) };

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

    /* Init VF2PF communication */
    dev->pfvf = adf_init_pfvf_dev_data(dev->pcs.bar[ADF_PMISC_BAR].ptr, pci_id);

    /* Setup IRQ with eventfd */
    if (ioctl(dev->vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info) < 0)
    {
        ADF_ERROR("VFIO_DEVICE_GET_IRQ_INFO failed %s\n", strerror(errno));
        close_vfio_dev(dev);
        return -1;
    }

    if (!(irq_info.flags & VFIO_IRQ_INFO_EVENTFD))
    {
        ADF_ERROR("Device interrupt doesn't support eventfd\n");
        close_vfio_dev(dev);
        return -1;
    }

    evtfd = eventfd(0, EFD_NONBLOCK);
    if (evtfd < 0)
    {
        ADF_ERROR("eventfd failed %s\n", strerror(errno));
        close_vfio_dev(dev);
        return -1;
    }

    irq_set = (struct vfio_irq_set *)irq_set_buf;
    irq_set->argsz = IRQ_SET_BUF_LEN;
    irq_set->count = 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = VFIO_PCI_MSI_IRQ_INDEX;
    irq_set->start = 0;
    fd_ptr = (int *)&irq_set->data;
    *fd_ptr = evtfd;

    ret = ioctl(dev->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
    if (ret)
    {
        ADF_ERROR("VFIO_DEVICE_SET_IRQS failed %s\n", strerror(errno));
        close(evtfd);
        dev->event_fd = -1;
        close_vfio_dev(dev);
        return -1;
    }
    dev->event_fd = evtfd;

    return 0;
}

void close_vfio_dev(vfio_dev_info_t *dev)
{
    int idx;
    pcs_t *pcs;
    int ret = 0;

    ICP_CHECK_FOR_NULL_PARAM_VOID(dev);

    pcs = &dev->pcs;
    for (idx = pcs->nr_bar - 1; idx >= 0; idx--)
    {
        ret = munmap(pcs->bar[idx].ptr, pcs->bar[idx].size);
        if (ret)
        {
            ADF_ERROR("close_vfio_dev : munmap error for idx = %d\n", idx);
        }
    }
    pcs->nr_bar = 0;

    /* Close event fd if it was opened */
    if (dev->event_fd >= 0)
    {
        close(dev->event_fd);
        dev->event_fd = -1;
    }

    pci_vfio_set_command(dev->vfio_dev_fd, PCI_COMMAND_MEMORY, false);

    pci_vfio_set_command(dev->vfio_dev_fd, PCI_COMMAND_MASTER, false);

    close(dev->vfio_dev_fd);
    dev->vfio_dev_fd = -1;
    remove_and_close_group(dev);
}
