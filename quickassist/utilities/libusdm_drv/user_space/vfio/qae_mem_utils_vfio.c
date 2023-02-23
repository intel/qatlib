/***************************************************************************
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
 ***************************************************************************/
/**
 ****************************************************************************
 * @file qae_mem_utils_vfio.c
 *
 * This file provides for Linux user space memory allocation. It uses
 * a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the QuickAssist libaries and their users
 *
 ***************************************************************************/
#include <linux/vfio.h>
#include "qae_mem_utils_common.h"

/* Check for process pid caching availibility */
#ifdef MADV_WIPEONFORK
#define CACHE_PID
#endif

#ifdef CACHE_PID
STATIC void *cache_pid = NULL;
#endif

/**************************************************************************
                                   macro
**************************************************************************/

#ifdef __x86_64__
#define IOVA_BITS 39
#else
#define IOVA_BITS 32
#endif

#define SLAB_BITS 21
#define IOVA_IDX(iova)                                                         \
    ((iova >> SLAB_BITS) & ((1 << (IOVA_BITS - SLAB_BITS)) - 1))
#define IOVA_SLAB_SIZE (1 << SLAB_BITS)
/* Don't use null IOVA */
#define FIRST_IOVA IOVA_SLAB_SIZE
#define NUM_IOVA_SLABS (1 << (IOVA_BITS - SLAB_BITS))
#define MAX_IOVA ((1ll << IOVA_BITS) - IOVA_SLAB_SIZE)

/**************************************************************************
    static variable
**************************************************************************/
int g_fd = 0;
int g_strict_node = 0;
STATIC int vfio_container_fd = -1;
STATIC pid_t vfio_pid = 0;
static int vfio_container_ref = 0;

/*
 * Each IOVA_SLAB represents a set of memory pages of size 2MB that
 * are contiguous from the viewpoint of the IO device.
 * The iova_used bitmap identifies the IOVA slabs that have been used.
 */
static uint32_t iova_used[NUM_IOVA_SLABS / (CHAR_BIT * sizeof(uint32_t))] = {0};
static uint64_t next_iova = FIRST_IOVA;

/**************************************************************************
                                  function
**************************************************************************/

static unsigned int bit_is_set(uint32_t used[], unsigned index)
{
    const int bits = CHAR_BIT * sizeof(uint32_t);
    return used[index / bits] & (1 << (index % bits));
}

static void set_bit(uint32_t used[], unsigned index)
{
    const int bits = CHAR_BIT * sizeof(uint32_t);
    used[index / bits] |= (1 << (index % bits));
}

static void clear_bit(uint32_t used[], unsigned index)
{
    const int bits = CHAR_BIT * sizeof(uint32_t);
    used[index / bits] &= ~(1 << (index % bits));
}

static int iova_reserve(uint64_t iova, uint32_t size)
{
    unsigned slab = IOVA_IDX(iova);
    int count;
    int num_slabs = div_round_up(size, IOVA_SLAB_SIZE);

    if (iova + size - IOVA_SLAB_SIZE > MAX_IOVA)
        return 1;

    /* Reserve a range of IOVA */
    for (count = 0; count < num_slabs; count++, slab++)
    {
        if (bit_is_set(iova_used, slab))
            break;
        set_bit(iova_used, slab);
    }
    if (count < num_slabs)
    {
        /* If the complete range couldn't be reserved, revert */
        while (count-- > 0)
        {
            slab--;
            clear_bit(iova_used, slab);
        }
        return 1;
    }

    return 0;
}

static void iova_release(uint64_t iova, uint32_t size)
{
    unsigned slab = IOVA_IDX(iova);
    int count;
    int num_slabs = (size + (1 << SLAB_BITS) - 1) >> SLAB_BITS;

    for (count = 0; count < num_slabs; count++, slab++)
        clear_bit(iova_used, slab);
}

static inline int dma_map_slab(const void *virt,
                               const uint64_t iova,
                               const size_t size)
{
    int ret = 0;
    struct vfio_iommu_type1_dma_map dma_map = {.argsz = sizeof(dma_map),
                                               .flags = VFIO_DMA_MAP_FLAG_READ |
                                                        VFIO_DMA_MAP_FLAG_WRITE,
                                               .vaddr = (uintptr_t)virt,
                                               .iova = (uintptr_t)iova,
                                               .size = size};

    if (mem_ioctl(vfio_container_fd, VFIO_IOMMU_MAP_DMA, &dma_map) &&
        errno != EEXIST)
    {
        CMD_ERROR("%s:%d VFIO_IOMMU_MAP_DMA failed va=%llx iova=%llx size=%lx "
                  "-- errno=%d\n",
                  __func__,
                  __LINE__,
                  dma_map.vaddr,
                  dma_map.iova,
                  dma_map.size,
                  errno);
        ret = 1;
    }

    return ret;
}

static inline int dma_unmap_slab(const uint64_t iova, const size_t size)
{
    int ret = 0;
    struct vfio_iommu_type1_dma_unmap dma_umap = {
        .argsz = sizeof(dma_umap), .iova = (uintptr_t)iova, .size = size};

    ret = mem_ioctl(vfio_container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_umap);
    if (ret)
        CMD_ERROR(
            "%s:%d VFIO_IOMMU_UMAP_DMA failed iova=%llx size%lx -- errno=%d\n",
            __func__,
            __LINE__,
            dma_umap.iova,
            dma_umap.size,
            errno);

    return ret;
}

static inline void ioctl_free_slab(const int fd, dev_mem_info_t *memInfo)
{
    UNUSED(fd);

    iova_release(memInfo->phy_addr, memInfo->size);

    if (vfio_container_fd < 0)
        return;

    dma_unmap_slab(memInfo->phy_addr, memInfo->size);
}

API_LOCAL
void __qae_finish_free_slab(const int fd, dev_mem_info_t *slab)
{
    ioctl_free_slab(fd, slab);
}

/**************************************
 * Memory functions
 *************************************/

static inline int qaeInitProcess(void)
{
    if (check_pid())
    {
        __qae_ResetControl();
        memset(&iova_used, 0, sizeof(iova_used));
        next_iova = FIRST_IOVA;
    }
    return 0;
}

API_LOCAL
int __qae_open()
{
    return qaeInitProcess();
}

API_LOCAL
int __qae_free_special(void)
{
#ifdef CACHE_PID
    int ret = 0;
    if (cache_pid != NULL)
    {
        ret = qae_munmap(cache_pid, getpagesize());
        if (ret)
        {
            CMD_ERROR("%s:%d munmap call for cache failed, ret = %d\n",
                      __func__,
                      __LINE__,
                      ret);
        }
        cache_pid = NULL;
    }
#endif
    return 0;
}

uint64_t allocate_iova(const uint32_t size, uint32_t alignment)
{
    uint64_t iova;
    unsigned tryCount;

    /* IOVA alignment must be minimum of IOVA_SLAB_SIZE but may be greater */
    alignment = round_up(alignment, IOVA_SLAB_SIZE);
    iova = round_up(next_iova, alignment);
    for (tryCount = 0; tryCount < MAX_IOVA / alignment; tryCount++)
    {
        if (iova_reserve(iova, size))
        {
            /* Couldn't reserve at that iova */
            iova += alignment;
            if (iova > MAX_IOVA)
                iova = round_up(FIRST_IOVA, alignment);
        }
        else
        {
            next_iova = iova + round_up(size, IOVA_SLAB_SIZE);
            if (next_iova > MAX_IOVA)
                next_iova = FIRST_IOVA;
            return iova;
        }
    }

    return 0;
}

static inline void *mmap_alloc(const size_t size)
{
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    void *ptr = NULL;

    ptr = qae_mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);

    if (qae_madvise(ptr, size, MADV_DONTFORK))
    {
        munmap(ptr, size);
        ptr = MAP_FAILED;
    }

    return (ptr == MAP_FAILED) ? NULL : ptr;
}

static inline dev_mem_info_t *ioctl_alloc_slab(const int fd,
                                               const size_t size_r,
                                               const uint32_t alignment,
                                               const int node,
                                               enum slabType type)
{
    dev_mem_info_t *slab = NULL;
    size_t size = round_up(size_r, PAGE_SIZE);
    UNUSED(node);
    UNUSED(fd);

    if (SMALL == type)
        slab = mmap_alloc(size);
    else
        slab = mmap_alloc(getpagesize());

    if (NULL == slab)
    {
        CMD_ERROR("%s:%d mmap memory failed\n", __func__, __LINE__);
        return NULL;
    }

    if (SMALL == type)
        slab->virt_addr = slab;
    else
    {
        slab->virt_addr = mmap_alloc(size);

        if (NULL == slab->virt_addr)
        {
            CMD_ERROR("%s:%d mmap failed for large memory allocation\n",
                      __func__,
                      __LINE__);
            qae_munmap(slab, getpagesize());
            return NULL;
        }
    }

    slab->size = size;
    slab->phy_addr = allocate_iova(size, alignment);
    if (!slab->phy_addr)
    {
        CMD_ERROR("%s:%d cannot map 0x%p to iova\n",
                  __func__,
                  __LINE__,
                  slab->virt_addr);
        goto error;
    }

    slab->type = type;

    /* Defer IOMMU map until container is registered. */
    if (vfio_container_fd < 0)
        return slab;

    if (dma_map_slab(slab->virt_addr, slab->phy_addr, slab->size))
        goto error;

    return slab;

error:
    iova_release(slab->phy_addr, slab->size);
    if (SMALL == type)
    {
        qae_munmap(slab, slab->size);
    }
    else
    {
        qae_munmap(slab->virt_addr, slab->size);
        qae_munmap(slab, getpagesize());
    }
    return NULL;
}

API_LOCAL
dev_mem_info_t *__qae_alloc_slab(const int fd,
                                 const size_t size,
                                 const uint32_t alignment,
                                 const int node,
                                 enum slabType type)
{
    dev_mem_info_t *slab = NULL;

    slab = ioctl_alloc_slab(fd, size, alignment, node, type);

    /* Store a slab into the hash table for a fast lookup. */
    if (slab)
        add_slab_to_hash(slab);

    return slab;
}

static int dma_map_slabs(dev_mem_info_t *pList)
{
    dev_mem_info_t *slab;

    for (slab = pList; slab != NULL; slab = slab->pNext_user)
    {
        if (dma_map_slab(slab->virt_addr, slab->phy_addr, slab->size))
            return 1;
    }
    return 0;
}

static int dma_unmap_slabs(dev_mem_info_t *pList)
{
    dev_mem_info_t *slab;

    for (slab = pList; slab != NULL; slab = slab->pNext_user)
    {
        if (dma_unmap_slab(slab->phy_addr, slab->size))
            return 1;
    }
    return 0;
}

#ifdef VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE
static void filter_range(
    uint64_t *next_start,
    struct vfio_iommu_type1_info_cap_iova_range *iova_range)
{
    unsigned i;
    uint64_t next = *next_start;

    if (iova_range)
    {
        for (i = 0; i < iova_range->nr_iovas; i++)
        {
            /* Exclude any IOVA from the previous end to this start */
            while (next < MIN(iova_range->iova_ranges[i].start, MAX_IOVA))
            {
                set_bit(iova_used, IOVA_IDX(next));
                next += IOVA_SLAB_SIZE;
            }
            if (iova_range->iova_ranges[i].end >= MAX_IOVA)
                break;
            next = (iova_range->iova_ranges[i].end + 1) & ~(IOVA_SLAB_SIZE - 1);
        }
        *next_start = next;
    }
}
#endif

#ifdef VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE
static int filter_dma_ranges(int fd)
{

    uint64_t next_start = 0;
    struct vfio_iommu_type1_info *iommu_info;
    struct vfio_info_cap_header *cap_header;
    struct vfio_iommu_type1_info_cap_iova_range *iova_range = NULL;

#define INFO_SIZE 0x1000
    iommu_info = calloc(1, INFO_SIZE);
    if (!iommu_info)
    {
        CMD_ERROR(
            "%s:%d Allocaton failed for iommu_info\n", __func__, __LINE__);
        return -1;
    }

    iommu_info->argsz = INFO_SIZE;
    if (mem_ioctl(fd, VFIO_IOMMU_GET_INFO, iommu_info))
    {
        CMD_ERROR("%s:%d VFIO_IOMMU_GET_INFO ioctl failed %d\n",
                  __func__,
                  __LINE__,
                  errno);
        free(iommu_info);
        return -1;
    }

    if (iommu_info->flags & VFIO_IOMMU_INFO_CAPS)
    {
        if (!iommu_info->cap_offset)
        {
            CMD_ERROR("%s:%d Not enough space to return IOMMU capabilities. "
                      "Increase INFO_SIZE\n",
                      __func__,
                      __LINE__);
            free(iommu_info);
            return -1;
        }

        cap_header =
            (typeof(cap_header))((char *)iommu_info + iommu_info->cap_offset);
        while (cap_header)
        {
            if (cap_header->id == VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE)
            {
                if (iova_range)
                {
                    CMD_DEBUG("%s:%d Unexpected second INFO_CAP_IOVA_RANGE\n",
                              __func__,
                              __LINE__);
                }
                iova_range =
                    (struct vfio_iommu_type1_info_cap_iova_range *)cap_header;
                filter_range(&next_start, iova_range);
            }
            if (cap_header->next)
                cap_header =
                    (typeof(cap_header))((char *)iommu_info + cap_header->next);
            else
                cap_header = NULL;
        }
    }

    free(iommu_info);
    return 0;
}
#else
static int filter_dma_ranges(int fd)
{
    UNUSED(fd);
    return 0;
}
#endif

int qaeRegisterDevice(int fd)
{
    int ret = 0;
    pid_t pid = getpid();

    if (filter_dma_ranges(fd))
        return -1;

    if (qaeInitProcess())
    {
        CMD_ERROR("Failed to init qae process \n");
        return -1;
    }

    if (pid != vfio_pid)
    {
        vfio_pid = pid;
        vfio_container_fd = -1;
        vfio_container_ref = 0;
    }

    if (vfio_container_fd < 0)
    {
        vfio_container_fd = fd;
        /* Map any slabs that were allocated before qaeRegisterDevice. */
        if (dma_map_slabs(__qae_pUserMemListHead))
            ret = 1;
        if (dma_map_slabs(__qae_pUserLargeMemListHead))
            ret = 1;
        if (dma_map_slabs(__qae_pUserCacheHead))
            ret = 1;

        if (ret)
        {
            vfio_container_fd = -1;
            return 1;
        }
    }

    if (fd == vfio_container_fd)
    {
        vfio_container_ref++;
    }
    else
    {
        CMD_ERROR("%s:%d Invalid container fd %d != %d\n",
                  __func__,
                  __LINE__,
                  fd,
                  vfio_container_fd);
        ret = 1;
    }

    return ret;
}

int qaeUnregisterDevice(int fd)
{
    int ret = 0;
    pid_t pid = getpid();

    if (vfio_container_ref <= 0 || vfio_container_fd != fd)
        return 1;

    if (pid != vfio_pid)
        return 0;

    if (--vfio_container_ref == 0)
    {
        if (dma_unmap_slabs(__qae_pUserMemListHead))
            ret = 1;
        if (dma_unmap_slabs(__qae_pUserLargeMemListHead))
            ret = 1;
        if (dma_unmap_slabs(__qae_pUserCacheHead))
            ret = 1;
        vfio_container_fd = -1;
    }
    return ret;
}
