/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
/**
 ****************************************************************************
 * @file qae_mem_hugepage_utils_vfio.c
 *
 * This file provides dummy huge page utilities for Linux user space memory
 * allocation with huge page not supported for vfio.
 *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>
#include <limits.h>

#include "qae_mem_hugepage_utils.h"
#include "qae_mem_user_utils.h"
#include "qae_mem_utils_common.h"
#include "qae_mem_utils.h"
#include "qae_mem_sysfs_utils.h"
#include "qae_page_table_common.h"
#ifdef ICP_THREAD_SPECIFIC_USDM
#include "qae_mem_multi_thread.h"
#endif

static bool g_hugepages_enabled = false;
static size_t g_num_hugepages = 0;
/* hugepages allocated by this process */
static size_t g_alloc_hugepages = 0;
extern int vfio_container_fd;
extern int g_noiommu_enabled;

#define UMASK_OWNER_ONLY  0077
#define HUGEPAGE_FILE_DIR "/dev/hugepages/qat/qat-usdm.XXXXXX"
#define HUGEPAGE_FILE_LEN (sizeof(HUGEPAGE_FILE_DIR))

/* The pfn (page frame number) are bits 0-54 of page. */
#define PFN_MASK 0x7fffffffffffffULL
#define PAGEMAP_FILE "/proc/self/pagemap"

static inline void reset_hp(const int limit)
{
    g_num_hugepages = limit;
    g_alloc_hugepages = 0;
}

static inline void inc_hp(void)
{
    g_num_hugepages--;
    g_alloc_hugepages++;
}

static inline void dec_hp(void)
{
    g_num_hugepages++;
    g_alloc_hugepages--;
}

/*
 * Use linux system page map file (proc/self/pagemap) to get the physical
 * address. Called in the vfio noiommu mode for virtual to physical address
 * translation.
 */
STATIC int mem_virt2phy(const void *virtaddr, uint64_t *physaddr_ptr)
{
    int fd, retval;
    uint64_t page;
    unsigned long virt_pfn;
    int page_size;
    off_t offset;

    *physaddr_ptr = 0;

    /* standard page size */
    page_size = getpagesize();

    fd = qae_open(PAGEMAP_FILE, O_RDONLY);
    if (fd < 0)
    {
        CMD_ERROR("%s(): could not open %s: %s\n",
                  __func__,
                  PAGEMAP_FILE,
                  strerror(errno));
        return -EPERM;
    }

    virt_pfn = (unsigned long)virtaddr / page_size;
    offset = sizeof(uint64_t) * virt_pfn;
    if (qae_lseek(fd, offset, SEEK_SET) == (off_t) -1)
    {
        CMD_ERROR(
            "%s(): seek failure in %s: %d\n", __func__, PAGEMAP_FILE, errno);
        close(fd);
        return -EINVAL;
    }

    retval = qae_read(fd, &page, sizeof(page));
    if (retval < 0)
    {
        CMD_ERROR(
            "%s(): could not read %s: %d\n", __func__, PAGEMAP_FILE, errno);
        close(fd);
        return retval;
    }
    else if (retval != sizeof(page))
    {
       CMD_ERROR("%s(): read %d bytes from %s "
                "but expected %zu:\n",
                __func__, retval, PAGEMAP_FILE, sizeof(page));
       close(fd);
       return -EINVAL;
    }

    if (qae_close(fd))
    {
        CMD_ERROR("%s(): closing %s failed: %s\n",
                  __func__, PAGEMAP_FILE, strerror(errno));
    }

    if ((page & PFN_MASK) == 0)
        return -EINVAL;

    *physaddr_ptr = ((page & PFN_MASK) * page_size)
                        + ((unsigned long)virtaddr % page_size);

    return 0;
}

API_LOCAL
int __qae_vfio_init_hugepages()
{
    int ret = 0;
    /* QAT_MAX_2M_HPG_PER_PROCESS controls hugepage mode:
     * NULL/empty/zero -> 4K; positive value -> 2M with budget.
     *
     * Read config *before* touching state, so a failure (e.g. sysfs check
     * returning -EINVAL on re-init) leaves the previously-configured
     * g_num_hugepages / g_hugepages_enabled intact.
     */
    int budget = __qae_hugepage_config_init();

    if (budget < 0)
    {
        CMD_ERROR("%s:%d Hugepages are not configured on system, ret = %d\n",
                  __func__,
                  __LINE__,
                  budget);
        return budget;
    }

    reset_hp(budget);

    if (g_num_hugepages > 0)
    {
        g_hugepages_enabled = true;
        __qae_set_free_page_table_fptr(free_page_table_hpg);
        __qae_set_loadaddr_fptr(load_addr_hpg);
        __qae_set_loadkey_fptr(load_key_hpg);
        __qae_set_storemmap_fptr(store_mmap_range_hpg);
        CMD_DEBUG("%s:%d 2MB huge page mode enabled.\n", __func__, __LINE__);
    }
    else
    {
        g_hugepages_enabled = false;
        __qae_set_free_page_table_fptr(free_page_table);
        __qae_set_loadaddr_fptr(load_addr);
        __qae_set_loadkey_fptr(load_key);
        __qae_set_storemmap_fptr(store_mmap_range);
        CMD_DEBUG("%s:%d 4K page mode.\n", __func__, __LINE__);
    }
    return ret;
}

API_LOCAL
int __qae_hugepage_enabled()
{
    return g_hugepages_enabled;
}

STATIC void *__qae_vfio_hugepage_mmap_addr(const size_t size)
{
    void *addr = NULL;
    int ret = 0;
    int hpg_fd;
    mode_t old_umask;
    char hpg_fname[HUGEPAGE_FILE_LEN];

    old_umask = umask(UMASK_OWNER_ONLY);

    /*
     * for every mapped huge page there will be a separate file descriptor
     * created from a temporary file, we should NOT close fd explicitly, it
     * will be reclaimed by the OS when the process gets terminated, and
     * meanwhile the huge page binding to the fd will be released, this could
     * guarantee the memory cleanup order between user buffers and ETR.
     */
    snprintf(hpg_fname, sizeof(HUGEPAGE_FILE_DIR), "%s", HUGEPAGE_FILE_DIR);
    hpg_fd = qae_mkstemp(hpg_fname);

    if (hpg_fd < 0)
    {
        CMD_ERROR("%s:%d mkstemp(%s) for hpg_fd failed\n",
                  __func__,
                  __LINE__,
                  hpg_fname);
        return NULL;
    }

    umask(old_umask);
    unlink(hpg_fname);

    addr = qae_mmap(NULL,
                    size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB,
                    hpg_fd,
                    0);

    if (MAP_FAILED == addr)
    {
        CMD_ERROR("%s:%d qae_mmap(%s) for hpg_fd failed\n",
                  __func__,
                  __LINE__,
                  hpg_fname);
        close(hpg_fd);
        return NULL;
    }

    ret = qae_madvise(addr, size, MADV_DONTFORK);
    if (0 != ret)
    {
        qae_munmap(addr, size);
        CMD_ERROR("%s:%d qae_madvise(%s) for hpg_fd failed\n",
                  __func__,
                  __LINE__,
                  hpg_fname);
        close(hpg_fd);
        return NULL;
    }

    ((dev_mem_info_t *)addr)->hpg_fd = hpg_fd;

    return addr;
}

API_LOCAL
dev_mem_info_t *__qae_vfio_hugepage_alloc_slab(const int fd,
                                               const size_t size,
                                               const int node,
                                               enum slabType type,
                                               const uint32_t alignment)
{
    dev_mem_info_t *slab = NULL;
    int free_hp = 0;
    int ret = 0;
    UNUSED(fd);

    if (!g_num_hugepages)
    {
        CMD_ERROR("%s:%d Process quota for 2M Huge pages exhausted\n",
                  __func__,
                  __LINE__);
        return NULL;
    }

    free_hp = __qae_read_free_hugepages();
    if (free_hp <= 0)
    {
        if (!g_alloc_hugepages)
            CMD_ERROR("%s:%d 2M huge pages configured but consumed by "
                      "other processes\n",
                      __func__,
                      __LINE__);
        else
            CMD_ERROR(
                "%s:%d System 2M Huge pages exhausted\n", __func__, __LINE__);
        return NULL;
    }

    slab = __qae_vfio_hugepage_mmap_addr(size);
    if (!slab)
    {
        CMD_ERROR("%s:%d mmap on huge page memory allocation failed\n",
                  __func__,
                  __LINE__);
        return NULL;
    }

    inc_hp();
    slab->nodeId = node;
    slab->size = size;
    slab->type = type;
    slab->virt_addr = slab;

    if (!g_noiommu_enabled)
        slab->phy_addr = allocate_iova(size, alignment);
    else
        ret = mem_virt2phy(slab->virt_addr, &slab->phy_addr);

    if (ret || !slab->phy_addr)
    {
        CMD_ERROR("%s:%d cannot map 0x%p to iova, ret:%d, noiommu_enabled:%d\n",
                  __func__,
                  __LINE__,
                  slab->virt_addr, ret, g_noiommu_enabled);
        goto error;
    }

    /* Defer IOMMU map until container is registered. */
    if (vfio_container_fd < 0)
    {
#ifdef ICP_THREAD_SPECIFIC_USDM
        /* Save the slab in a TMP list for the deferred pinning. */
        slab->flag_pinned = NOT_PINNED;
        save_slab_to_tmp_list(slab);
#endif
        /* This is required for adding into hash table.*/
        return slab;
    }

#ifdef ICP_THREAD_SPECIFIC_USDM
    /* In the case of thread specific implementation, the slabs that are
     * allocated from different threads should be kept in a global array
     * for getting the slab information at the time of pinning and
     * un-pinning which is done in qaeRegisterDevice()/qaeUnregisterDevice()
     * functions.
     * NOTE: A new variable 'flag_pinned' is introduced. As the TMP list is
     * being employed to keep all the slabs, we need a marker to later
     * identify among the slabs in the TMP list that are already pinned!
     * The pinning will take place for the slab in
     * __qae_vfio_hugepage_alloc_slab itself if there is a vfio_container_fd
     * active). This flag is required to skip those slabs while doing deferred
     * pinning at the qaeRegisterDevice() time.
     */
    save_slab_to_tmp_list(slab);
#endif

    if (dma_map_slab(slab->virt_addr, slab->phy_addr, slab->size))
        goto error;

#ifdef ICP_THREAD_SPECIFIC_USDM
    slab->flag_pinned = PINNED;
#endif

    return slab;

error:
    dec_hp();
    if (!g_noiommu_enabled && slab->phy_addr)
        iova_release(slab->phy_addr, slab->size);

#ifdef ICP_THREAD_SPECIFIC_USDM
    remove_slab_from_tmp_list(slab);
#endif

    qae_munmap(slab, size);

    return NULL;
}

API_LOCAL
void __qae_vfio_hugepage_free_slab(dev_mem_info_t *memInfo)
{
    close(memInfo->hpg_fd);

    dec_hp();
    if (!g_noiommu_enabled)
        iova_release(memInfo->phy_addr, memInfo->size);

    if (vfio_container_fd < 0)
        return;

    dma_unmap_slab(memInfo->phy_addr, memInfo->size);
#ifdef ICP_THREAD_SPECIFIC_USDM
    memInfo->flag_pinned = NOT_PINNED;
#endif
}

