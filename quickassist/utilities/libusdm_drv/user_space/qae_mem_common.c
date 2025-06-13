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
 * @file qae_mem_common.c
 *
 * This file provides for Linux user space memory allocation. It uses
 * a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the  quick assist sample code
 *
 ***************************************************************************/

#include "qae_mem_lib_utils.h"
#include "qae_mem_utils_common.h"

/* Maximum supported alignment is 4M. */
#define QAE_MAX_PHYS_ALIGN (0x400000ULL)

/* Current cached memory size. */
size_t g_cache_size = 0;
/* Maximum cached memory size, 8 Mb by default */
size_t g_max_cache = MAX_CACHE_DEPTH_MB;
/* The maximum number we allow to search for available size */
size_t g_max_lookup_num = 10;

/* User space page table for fast virtual to physical address translation */
page_table_t g_page_table = { { { 0 } } };
/* User space hash for fast slab searching */
slab_list_t g_slab_list[PAGE_SIZE] = { { 0 } };

#ifndef ICP_WITHOUT_THREAD
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

API_LOCAL dev_mem_info_t *__qae_pUserCacheHead = NULL;
API_LOCAL dev_mem_info_t *__qae_pUserCacheTail = NULL;
API_LOCAL dev_mem_info_t *__qae_pUserMemListHead = NULL;
API_LOCAL dev_mem_info_t *__qae_pUserMemListTail = NULL;
API_LOCAL dev_mem_info_t *__qae_pUserLargeMemListHead = NULL;
API_LOCAL dev_mem_info_t *__qae_pUserLargeMemListTail = NULL;

free_page_table_fptr_t free_page_table_fptr = free_page_table;
load_key_fptr_t load_key_fptr = load_key;

API_LOCAL
dev_mem_info_t *__qae_userMemLookupBySize(size_t size,
                                          int node,
                                          void **block,
                                          const size_t align)
{
    dev_mem_info_t *pCurr = NULL;
    size_t link_num = 0;

    for (pCurr = __qae_pUserMemListHead; pCurr != NULL;
         pCurr = pCurr->pNext_user)
    {
        if (g_strict_node && (pCurr->nodeId != node))
        {
            continue;
        }
        *block = __qae_mem_alloc((block_ctrl_t *)pCurr, size, align);
        if (NULL != *block)
        {
            return pCurr;
        }
        /* Prevent from visiting whole chain, because after the first
         * several node, the chance to get one is very small.
         * Another consideration is to prevent new allocation from old
         * link, so that the old link could be released
         */
        link_num++;
        if (link_num >= g_max_lookup_num)
        {
            break;
        }
    }
    return NULL;
}

/* translate a physical address to a virtual address */
void *qaePhysToVirtNUMA(uint64_t physAddress)
{
    int status;
    dev_mem_info_t *slab;
    uintptr_t offset;
    void *ret = NULL;

    status = mem_mutex_lock(&mutex);
    if (status)
    {
        CMD_ERROR("%s:%d Error on thread mutex lock %s\n",
                  __func__,
                  __LINE__,
                  strerror(status));
        return NULL;
    }

    /* find slab from physical address without using hash lookup */
    for (slab = __qae_pUserMemListHead; slab != NULL; slab = slab->pNext_user)
    {
        offset = (uintptr_t)physAddress - (uintptr_t)slab->phy_addr;
        if (offset < slab->size)
        {
            ret = (void *)((uintptr_t)slab->virt_addr + offset);
            break;
        }
    }

    status = mem_mutex_unlock(&mutex);
    if (status)
    {
        CMD_ERROR("%s:%d Error on thread mutex unlock %s\n",
                  __func__,
                  __LINE__,
                  strerror(status));
        return NULL;
    }

    return ret;
}

static int32_t memoryRemap(dev_mem_info_t *head)
{
    // NOT SUPPORTED
    if (NULL != head)
    {
        CMD_ERROR("%s:%d not supported \n", __func__, __LINE__);
        return -EIO;
    }

    return 0;
}

void qaeAtFork()
{
    int ret = 0;
    int32_t status0 = 0;
    int32_t status1 = 0;
    int32_t status2 = 0;

    ret = mem_mutex_lock(&mutex);
    if (unlikely(ret))
    {
        CMD_ERROR(
            "%s:%d Error(%d) on thread mutex lock \n", __func__, __LINE__, ret);
        return;
    }

    status0 = memoryRemap(__qae_pUserCacheHead);
    status1 = memoryRemap(__qae_pUserMemListHead);
    status2 = memoryRemap(__qae_pUserLargeMemListHead);

    ret = mem_mutex_unlock(&mutex);
    if (unlikely(ret))
    {
        CMD_ERROR("%s:%d Error on thread mutex unlock %s\n",
                  __func__,
                  __LINE__,
                  strerror(ret));
        goto fork_exit;
    }

fork_exit:
    if (unlikely(status0))
    {
        CMD_ERROR(
            "%s:%d Failed to remap memory allocations \n", __func__, __LINE__);
    }
    if (unlikely(status1))
    {
        CMD_ERROR(
            "%s:%d Failed to remap memory allocations \n", __func__, __LINE__);
    }
    if (unlikely(status2))
    {
        CMD_ERROR("%s:%d Failed to remap large memory allocations \n",
                  __func__,
                  __LINE__);
    }
    return;
}

API_LOCAL
void __qae_free_slab(const int fd, dev_mem_info_t *slab)
{
    dev_mem_info_t memInfo;
    int ret = 0;

    del_slab_from_hash(slab);

    memcpy(&memInfo, slab, sizeof(dev_mem_info_t));
    /* Need to disconnect from original chain */
    ret = qae_munmap(memInfo.virt_addr, memInfo.size);
    if (ret)
    {
        CMD_ERROR("%s:%d munmap failed, ret = %d\n", __func__, __LINE__, ret);
    }
    if (LARGE == memInfo.type)
    {
        ret = qae_munmap(slab, getpagesize());
        if (ret)
        {
            CMD_ERROR(
                "%s:%d munmap failed, ret = %d\n", __func__, __LINE__, ret);
        }
    }

    __qae_finish_free_slab(fd, &memInfo);
}

API_LOCAL
dev_mem_info_t *__qae_find_slab(const int fd,
                                const size_t size,
                                const int node,
                                void **addr,
                                const size_t align)
{
    dev_mem_info_t *slab = __qae_userMemLookupBySize(size, node, addr, align);

    if (NULL == slab)
    {
        slab = pop_slab(node);
        if (NULL != slab)
        {
            *addr = init_slab_and_alloc((block_ctrl_t *)slab, size, align);
            if (NULL == *addr)
            {
                CMD_ERROR("%s:%d Memory allocation failed Virtual address: %p "
                          " Size: %zu \n",
                          __func__,
                          __LINE__,
                          slab,
                          size);
                __qae_free_slab(fd, slab);
                return NULL;
            }
        }
    }
    return slab;
}

API_LOCAL
void __qae_ResetControl(void)
{
    /* Reset all control structures. */
    free_page_table_fptr(&g_page_table);
    memset(&g_page_table, 0, sizeof(g_page_table));
    memset(&g_slab_list, 0, sizeof(g_slab_list));
    g_cache_size = 0;

    __qae_pUserCacheHead = NULL;
    __qae_pUserCacheTail = NULL;
    __qae_pUserMemListHead = NULL;
    __qae_pUserMemListTail = NULL;
    __qae_pUserLargeMemListHead = NULL;
    __qae_pUserLargeMemListTail = NULL;
}

int32_t qaeMemInit()
{
    int32_t fd_status = 0;
    int32_t status = 0;

    status = mem_mutex_lock(&mutex);
    if (status)
    {
        CMD_ERROR("%s:%d Error on thread mutex lock %s\n",
                  __func__,
                  __LINE__,
                  strerror(status));
        return -EIO;
    }

    fd_status = __qae_open();

    status = mem_mutex_unlock(&mutex);
    if (status)
    {
        CMD_ERROR("%s:%d Error on thread mutex unlock %s\n",
                  __func__,
                  __LINE__,
                  strerror(status));
        return -EIO;
    }
    return fd_status;
}

API_LOCAL
void __qae_destroyList(const int fd, dev_mem_info_t *pList)
{
    dev_mem_info_t *pCurr = pList;

    while (pCurr)
    {
        dev_mem_info_t *next = pCurr->pNext_user;
        __qae_free_slab(fd, pCurr);
        pCurr = next;
    }
}

API_LOCAL
void __qae_reset_cache(const int fd)
{
    dev_mem_info_t *slab = NULL;
    do
    {
        slab = pop_slab(NUMA_ANY_NODE);
        if (NULL != slab)
            __qae_free_slab(fd, slab);
    } while (slab != NULL);
}

void qaeMemDestroy(void)
{
    int ret = 0;

    /* Free all of the chains */
    ret = mem_mutex_lock(&mutex);
    if (unlikely(ret))
    {
        CMD_ERROR(
            "%s:%d Error(%d) on thread mutex lock \n", __func__, __LINE__, ret);
        return;
    }

    /* release all control buffers */
    free_page_table_fptr(&g_page_table);
    __qae_reset_cache(g_fd);
    __qae_destroyList(g_fd, __qae_pUserMemListHead);
    __qae_destroyList(g_fd, __qae_pUserLargeMemListHead);

    __qae_pUserCacheHead = NULL;
    __qae_pUserCacheTail = NULL;
    __qae_pUserMemListHead = NULL;
    __qae_pUserMemListTail = NULL;
    __qae_pUserLargeMemListHead = NULL;
    __qae_pUserLargeMemListTail = NULL;

    __qae_free_special();

    ret = mem_mutex_unlock(&mutex);
    if (unlikely(ret))
    {
        CMD_ERROR("%s:%d Error(%d) on thread mutex unlock\n",
                  __func__,
                  __LINE__,
                  ret);
    }
}

API_LOCAL
void *__qae_alloc_addr(size_t size,
                       const int node,
                       const size_t phys_alignment_byte)
{
    dev_mem_info_t *p_ctrl_blk = NULL;
    void *pVirtAddress = NULL;
    size_t allocate_pages = 0;
    enum slabType mem_type = SMALL;

    const size_t phys_align_unit = phys_alignment_byte / UNIT_SIZE;
    const size_t reserved = div_round_up(sizeof(block_ctrl_t), UNIT_SIZE);
    /* calculate units needed */
    const size_t requested_pages = div_round_up(size, UNIT_SIZE) + reserved;

    if (0 != __qae_open())
        return NULL;

    if (requested_pages > QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE / UNIT_SIZE ||
        phys_alignment_byte >= QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE)
    {
        mem_type = LARGE;
        /* Huge page and Large memory are mutually exclusive
         * Since Large slabs are NOT 2 MB aligned, but huge
         * pages are always 2 MB aligned.
         */
        if (__qae_hugepage_enabled())
            return NULL;
        size = MAX(size, phys_alignment_byte);
        allocate_pages = div_round_up(size, UNIT_SIZE);
    }
    else
    {
        allocate_pages = QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE / UNIT_SIZE;
        if (__qae_hugepage_enabled())
            mem_type = HUGE_PAGE;

        p_ctrl_blk =
            __qae_find_slab(g_fd, size, node, &pVirtAddress, phys_align_unit);

        if (p_ctrl_blk)
        {
            p_ctrl_blk->allocations += 1;
            return pVirtAddress;
        }
    }

    /* Try to allocate memory as much as possible */
    p_ctrl_blk = __qae_alloc_slab(
        g_fd, allocate_pages * UNIT_SIZE, phys_alignment_byte, node, mem_type);
    if (NULL == p_ctrl_blk)
        return NULL;

    store_mmap_range(&g_page_table,
                     p_ctrl_blk->virt_addr,
                     p_ctrl_blk->phy_addr,
                     p_ctrl_blk->size,
                     __qae_hugepage_enabled());

    if (LARGE == mem_type)
    {
        p_ctrl_blk->allocations = 1;

        ADD_ELEMENT_TO_HEAD_LIST(p_ctrl_blk,
                                 __qae_pUserLargeMemListHead,
                                 __qae_pUserLargeMemListTail,
                                 _user);

        pVirtAddress = p_ctrl_blk->virt_addr;
    }
    else
    {
        p_ctrl_blk->allocations = 1;

        if ((uintptr_t)p_ctrl_blk->virt_addr % QAE_PAGE_SIZE)
        {
            CMD_ERROR("%s:%d Bad virtual address alignment %lux %x %lux\n",
                      __func__,
                      __LINE__,
                      (uintptr_t)p_ctrl_blk->virt_addr,
                      QAE_NUM_PAGES_PER_ALLOC,
                      QAE_PAGE_SIZE);
            __qae_free_slab(g_fd, p_ctrl_blk);

            return NULL;
        }
        pVirtAddress = init_slab_and_alloc(
            (block_ctrl_t *)p_ctrl_blk, size, phys_align_unit);
        if (NULL == pVirtAddress)
        {
            CMD_ERROR("%s:%d Memory allocation failed Virtual address: %p "
                      " Size: %zu \n",
                      __func__,
                      __LINE__,
                      p_ctrl_blk,
                      size);
            __qae_free_slab(g_fd, p_ctrl_blk);

            return NULL;
        }
    }
    return pVirtAddress;
}

void *qaeMemAllocNUMA(size_t size, int node, size_t phys_alignment_byte)
{
    void *pVirtAddress = NULL;
    int ret = 0;

    if (!size)
    {
        CMD_ERROR("%s:%d Size cannot be zero \n", __func__, __LINE__);
        return NULL;
    }

    if (size > QAE_MAX_ALLOC_SIZE)
    {
        CMD_ERROR(
            "%s:%d Size cannot exceed 64M for vfio\n", __func__, __LINE__);
        return NULL;
    }

    if (!phys_alignment_byte || phys_alignment_byte > QAE_MAX_PHYS_ALIGN ||
        (phys_alignment_byte & (phys_alignment_byte - 1)))
    {
        CMD_ERROR("%s:%d Invalid alignment parameter %zu. It must be non zero, "
                  "not more than %llu and multiple of 2 \n",
                  __func__,
                  __LINE__,
                  phys_alignment_byte,
                  QAE_MAX_PHYS_ALIGN);
        return NULL;
    }

    ret = mem_mutex_lock(&mutex);
    if (unlikely(ret))
    {
        CMD_ERROR("%s:%d Error on thread mutex lock %s\n",
                  __func__,
                  __LINE__,
                  strerror(ret));
        return NULL;
    }

    pVirtAddress = __qae_alloc_addr(size, node, phys_alignment_byte);

    ret = mem_mutex_unlock(&mutex);
    if (unlikely(ret))
    {
        CMD_ERROR("%s:%d Error on thread mutex unlock %s\n",
                  __func__,
                  __LINE__,
                  strerror(ret));
        return NULL;
    }
    return pVirtAddress;
}

API_LOCAL
void __qae_free_addr(void **p_va, bool secure_free)
{
    dev_mem_info_t *p_ctrl_blk = NULL;

    if (0 != __qae_open())
        return;

    if ((p_ctrl_blk = find_slab_in_hash(*p_va)) == NULL)
    {
        CMD_ERROR("%s:%d Unable to free as lookup failed on address (%p) "
                  "provided \n",
                  __func__,
                  __LINE__,
                  *p_va);
        return;
    }
    if (SMALL == p_ctrl_blk->type || HUGE_PAGE == p_ctrl_blk->type)
    {
        if (__qae_mem_free((block_ctrl_t *)p_ctrl_blk, *p_va, secure_free))
        {
            p_ctrl_blk->allocations -= 1;
        }
        else
        {
            /*Skip push_slab(p_ctrl_blk)) and return when mem_free fails */
            CMD_ERROR("%s:%d mem_free returned false  (%p) "
                      "provided \n",
                      __func__,
                      __LINE__,
                      *p_va);
            *p_va = NULL;
            return;
        }
        if (p_ctrl_blk->allocations)
        {
            *p_va = NULL;
            return;
        }

        REMOVE_ELEMENT_FROM_LIST(
            p_ctrl_blk, __qae_pUserMemListHead, __qae_pUserMemListTail, _user);
        if (0 != push_slab(p_ctrl_blk))
            __qae_free_slab(g_fd, p_ctrl_blk);
    }
    else
    {
        REMOVE_ELEMENT_FROM_LIST(p_ctrl_blk,
                                 __qae_pUserLargeMemListHead,
                                 __qae_pUserLargeMemListTail,
                                 _user);
        __qae_free_slab(g_fd, p_ctrl_blk);
    }
    *p_va = NULL;
}

/* __qae_memFreeNUMA function
 * Frees memory pointed by ptr.
 * ptr refers to memory allocated by qaeMemAllocNUMA function.
 * secure_free is a boolean to perform memory free secured or not.
 */
API_LOCAL
void __qae_memFreeNUMA(void **ptr, bool secure_free)
{
    int ret = 0;

    if (NULL == ptr)
    {
        CMD_ERROR(
            "%s:%d Input parameter cannot be NULL \n", __func__, __LINE__);
        return;
    }
    if (NULL == *ptr)
    {
        CMD_ERROR(
            "%s:%d Address to be freed cannot be NULL \n", __func__, __LINE__);
        return;
    }
    ret = mem_mutex_lock(&mutex);
    if (ret)
    {
        CMD_ERROR("%s:%d Error on thread mutex lock %s\n",
                  __func__,
                  __LINE__,
                  strerror(ret));
        return;
    }

    __qae_free_addr(ptr, secure_free);

    ret = mem_mutex_unlock(&mutex);
    if (ret)
    {
        CMD_ERROR("%s:%d Error on thread mutex unlock %s\n",
                  __func__,
                  __LINE__,
                  strerror(ret));
    }
    return;
}
