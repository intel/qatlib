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
#include "qae_page_table_common.h"
#ifdef ICP_THREAD_SPECIFIC_USDM
#include "qae_mem_multi_thread.h"
#endif

static bool g_hugepages_enabled = false;
static size_t g_num_hugepages = 0;
static const char sys_dir_path[] = "/sys/kernel/mm/hugepages";
extern int vfio_container_fd;
extern int g_noiommu_enabled;

#define HUGEPAGE_FILE_DIR "/dev/hugepages/qat-usdm.XXXXXX"
#define HUGEPAGE_FILE_LEN (sizeof(HUGEPAGE_FILE_DIR))
#define HUGEPAGE_SYS_NODE "hugepages-2048kB"
#define HUGEPAGE_SOCKET_PATH_SIZE 50
#define HUGEPAGE_SYSFS_PATH_SIZE HUGEPAGE_SOCKET_PATH_SIZE + 32

/* The pfn (page frame number) are bits 0-54 of page. */
#define PFN_MASK 0x7fffffffffffffULL
#define PAGEMAP_FILE "/proc/self/pagemap"

/* Parse a sysfs (or other) file containing one integer value */
static int parse_sysfs_value(const char *filename, unsigned long *val)
{
    FILE *f;
    char buf[BUFSIZ];
    char *end = NULL;

    if ((f = qae_fopen(filename, "r")) == NULL)
    {
        CMD_ERROR("%s(): qae_fopen failed for %s\n", __func__, filename);
        return -1;
    }

    if (qae_fgets(buf, sizeof(buf), f) == NULL)
    {
        CMD_ERROR(
            "%s(): qae_fgets failed for sysfs value %s\n", __func__, filename);
        fclose(f);
        return -1;
    }
    *val = strtoul(buf, &end, 0);
    if ((buf[0] == '\0') || (end == NULL) || (*end != '\n'))
    {
        CMD_ERROR("%s(): cannot parse sysfs value %s\n", __func__, filename);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int get_num_hugepages_per_system(const char *subdir)
{
    char path[HUGEPAGE_SYSFS_PATH_SIZE] = { '\0' };
    char socketpath[HUGEPAGE_SOCKET_PATH_SIZE] = { '\0' };
    DIR *socketdir;
    unsigned long num_pages = 0;
    const char nr_hp_file[] = "nr_hugepages";

    snprintf(socketpath, sizeof(socketpath), "%s/%s", sys_dir_path, subdir);

    socketdir = qae_opendir(socketpath);
    if (socketdir)
    {
        closedir(socketdir);
    }
    else
    {
        if (g_hugepages_enabled)
            return -EIO;
        /*
         * HUGETLBFS is not configured in kernel.
         * Number of hugepages should be 0
         */
        g_num_hugepages = 0;
        return 0;
    }

    snprintf(path, sizeof(path), "%s/%s", socketpath, nr_hp_file);
    if (parse_sysfs_value(path, &num_pages) < 0)
        return -EIO;

    g_num_hugepages = num_pages;

    return 0;
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
        return retval;
    }
    else if (retval != sizeof(page))
    {
       CMD_ERROR("%s(): read %d bytes from %s "
                "but expected %zu:\n",
                __func__, retval, PAGEMAP_FILE, sizeof(page));
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
    if (get_num_hugepages_per_system(HUGEPAGE_SYS_NODE))
        return -EIO;

    if (g_num_hugepages > 0)
    {
        g_hugepages_enabled = true;
        __qae_set_free_page_table_fptr(free_page_table_hpg);
        __qae_set_loadaddr_fptr(load_addr_hpg);
        __qae_set_loadkey_fptr(load_key_hpg);
    }
    else
    {
        g_hugepages_enabled = false;
        __qae_set_free_page_table_fptr(free_page_table);
        __qae_set_loadaddr_fptr(load_addr);
        __qae_set_loadkey_fptr(load_key);
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
    char hpg_fname[HUGEPAGE_FILE_LEN];

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
    int ret = 0;
    UNUSED(fd);

    if (get_num_hugepages_per_system(HUGEPAGE_SYS_NODE))
        return NULL;

    if (!g_num_hugepages)
    {
        CMD_ERROR("%s:%d mmap: exceeded max huge pages allocations for this "
                  "process.\n",
                  __func__,
                  __LINE__);
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
    if (!g_noiommu_enabled)
        iova_release(slab->phy_addr, slab->size);

    qae_munmap(slab, size);

    return NULL;
}

API_LOCAL
void __qae_vfio_hugepage_free_slab(dev_mem_info_t *memInfo)
{
    close(memInfo->hpg_fd);

    iova_release(memInfo->phy_addr, memInfo->size);

    if (vfio_container_fd < 0)
        return;

    dma_unmap_slab(memInfo->phy_addr, memInfo->size);
#ifdef ICP_THREAD_SPECIFIC_USDM
    memInfo->flag_pinned = NOT_PINNED;
#endif
}

