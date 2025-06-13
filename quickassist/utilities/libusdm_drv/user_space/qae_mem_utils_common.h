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
 * @file qae_mem_utils_common.h
 *
 * This file provides for Linux user space memory allocation. It uses
 * a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the  quick assist sample code
 *
 ***************************************************************************/

#ifndef QAE_MEM_UTILS_COMMON_H
#define QAE_MEM_UTILS_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#ifndef ICP_WITHOUT_THREAD
#include <pthread.h>
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include "qae_mem.h"
#include "qae_mem_utils.h"
#include "qae_mem_user_utils.h"
#include "qae_page_table_common.h"
#include "qae_mem_hugepage_utils.h"

/* Maximum cached memory size, 8 Mb by default */
#define MAX_CACHE_DEPTH_MB (0x800000)

/* Maximum supported alignment is 4M. */
#define QAE_MAX_PHYS_ALIGN (0x400000ULL)

/* Maximum supported allocation is 64M for vfio. */
#define QAE_MAX_ALLOC_SIZE (0x4000000ULL)

#ifdef MADV_WIPEONFORK
#define CACHE_PID
#endif

#ifdef CACHE_PID
extern void *cache_pid;
#endif

typedef struct
{
    dev_mem_info_t *head;
    dev_mem_info_t *tail;
} slab_list_t;

/* User space page table for fast virtual to physical address translation */
extern page_table_t g_page_table;
extern const uint64_t __qae_bitmask[65];
extern int g_fd;
extern uint32_t normalAllocations_g;

extern free_page_table_fptr_t free_page_table_fptr;
extern load_addr_fptr_t load_addr_fptr;
extern load_key_fptr_t load_key_fptr;

API_LOCAL
int __qae_open(void);

API_LOCAL
void *__qae_mem_alloc(block_ctrl_t *block_ctrl, size_t size, size_t align);

API_LOCAL
bool __qae_mem_free(block_ctrl_t *block_ctrl, void *block, bool secure_free);

API_LOCAL
void __qae_finish_free_slab(const int fd, dev_mem_info_t *slab);

API_LOCAL
void *__qae_alloc_addr(size_t size,
                       const int node,
                       const size_t phys_alignment_byte);
API_LOCAL
void __qae_free_addr(void **p_va, bool secure_free);

API_LOCAL
uint64_t allocate_iova(const uint32_t size, uint32_t alignment);

API_LOCAL
void iova_release(uint64_t iova, uint32_t size);

API_LOCAL
int dma_map_slab(const void *virt, const uint64_t iova, const size_t size);

API_LOCAL
int dma_unmap_slab(const uint64_t iova, const size_t size);

API_LOCAL
void __qae_memFreeNUMA(void **ptr, bool secure_free);

static inline size_t div_round_up(const size_t n, const size_t d)
{
    return (n + d - 1) / d;
}

static inline size_t round_up(const size_t n, const size_t s)
{
    return ((n + s - 1) / s) * s;
}

/* mem_ctzll function
 * input: a 64-bit bitmap window
 * output: number of contiguous 0s from least significant bit position
 * __GNUC__ predefined macro and __builtin_ctz() are supported by Intel C
 */
static inline int32_t mem_ctzll(uint64_t bitmap_window)
{
    if (bitmap_window)
    {
#ifdef __GNUC__
        return __builtin_ctzll(bitmap_window);
#else
#error "Undefined built-in function"
#endif
    }
    return QWORD_WIDTH;
}

/* clear_bitmap function
 * clear the BITMAP_LENx64-bit bitmap from pos
 * for len length
 * input : map - pointer to the bitmap
 *         pos - bit position
 *         len - number of contiguous bits
 */
static inline void clear_bitmap(uint64_t *bitmap,
                                const size_t index,
                                size_t len)
{
    size_t qword = index / QWORD_WIDTH;
    const size_t offset = index % QWORD_WIDTH;
    size_t num;

    if (offset > 0)
    {
        const size_t width = MIN(len, QWORD_WIDTH - offset);
        const uint64_t mask = __qae_bitmask[width] << offset;

        /* Clear required bits */
        bitmap[qword] &= ~mask;

        len -= width;
        qword += 1;
    }

    num = len / QWORD_WIDTH;
    len %= QWORD_WIDTH;

    while (num--)
    {
        bitmap[qword++] = 0;
    }

    /* Clear remaining bits */
    bitmap[qword] &= ~__qae_bitmask[len];
}

/* set_bitmap function
 * set the BITMAP_LENx64-bit bitmap from pos
 * for len length
 * input : map - pointer to the bitmap
 *         pos - bit position
 *         len - number of contiguous bits
 */
static inline void set_bitmap(uint64_t *bitmap, const size_t index, size_t len)
{
    size_t qword = index / QWORD_WIDTH;
    const size_t offset = index % QWORD_WIDTH;
    size_t num;

    if (offset > 0)
    {
        const size_t width = MIN(len, QWORD_WIDTH - offset);
        const uint64_t mask = __qae_bitmask[width] << offset;

        /* Set required bits */
        bitmap[qword] |= mask;

        len -= width;
        qword += 1;
    }

    num = len / QWORD_WIDTH;
    len %= QWORD_WIDTH;

    while (num--)
    {
        bitmap[qword++] = ~0ULL;
    }

    /* Set remaining bits */
    bitmap[qword] |= __qae_bitmask[len];
}

#ifdef CACHE_PID
static inline void uncache_process_id(void)
{
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
}
static inline int cache_process_id(void)
{
    if (!cache_pid)
    {
        int page_size = getpagesize();

        cache_pid = qae_mmap(NULL,
                             page_size,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANON,
                             -1,
                             0);
        if (cache_pid == NULL)
        {
            CMD_ERROR(
                "%s:%d Unable to mmap aligned memory \n", __func__, __LINE__);
            return -ENOMEM;
        }

        if (qae_madvise(cache_pid, page_size, MADV_WIPEONFORK))
        {

            CMD_ERROR(
                "%s:%d Unable to update page properties\n", __func__, __LINE__);
            qae_munmap(cache_pid, page_size);
            close(g_fd);
            g_fd = -1;
            cache_pid = NULL;
            return -ENOMEM;
        }
    }

    *((pid_t *)cache_pid) = getpid();
    return 0;
}
#endif /* CACHE_PID */

#ifndef CACHE_PID
static inline int check_pid(void)
{
    static pid_t pid = 0;

    if (pid != getpid())
    {
        pid = getpid();
        return 1;
    }
    return 0;
}
#endif /* !CACHE_PID */

static inline int is_new_process()
{
    /* Check if it is a new process or child. */
#ifdef CACHE_PID
    const int is_new_pid =
        cache_pid == NULL || (cache_pid != NULL && *((pid_t *)cache_pid) == 0);
#else
    const int is_new_pid = check_pid();
#endif
    return is_new_pid;
}

#endif /* QAE_MEM_UTILS_COMMON_H */
