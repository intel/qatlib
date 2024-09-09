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
 * @file qae_mem_multi_thread_utils.c
 *
 * This file provides for thread specific Linux user space memory allocation.
 * It uses a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the quick assist sample code
 *
 * Each thread handles its own memory allocator information. Thread local
 * storage is used to hold all slab memory allocator information for each
 * thread.
 *
 ***************************************************************************/

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
#include "qae_mem_utils_common.h"
#include "qae_mem_multi_thread.h"
#include "qae_mem_hugepage_utils.h"
#include <sys/syscall.h>

/**************************************************************************
                                   macro
**************************************************************************/

#ifdef __CLANG_FORMAT__
/* clang-format off */
#endif
/* User space page table for fast virtual to physical address translation */
page_table_t g_page_table = { { { 0 } } };

slab_list_t g_slab_tmp_list = { 0 };
pthread_mutex_t mutex_tmp_list = PTHREAD_MUTEX_INITIALIZER;

#ifdef __CLANG_FORMAT__
/* clang-format on */
#endif

pthread_key_t qae_key;
pthread_once_t qae_key_once = PTHREAD_ONCE_INIT;
__thread int qae_mem_inited = 0;

free_page_table_fptr_t free_page_table_fptr = free_page_table;
load_key_fptr_t load_key_fptr = load_key;

void qae_mem_destroy_t(void *thread_key);

static void qae_make_key()
{
    pthread_key_create(&qae_key, qae_mem_destroy_t);
}

API_LOCAL
dev_mem_info_t *__qae_userMemLookupBySize(size_t size,
                                          int node,
                                          void **block,
                                          const size_t align,
                                          qae_mem_info_t *tls_ptr)
{
    dev_mem_info_t *pCurr = NULL;
    size_t link_num = 0;

    for (pCurr = tls_ptr->pUserMemListHead; pCurr != NULL;
         pCurr = pCurr->pNext_user)
    {
        if (tls_ptr->g_strict_node && (pCurr->nodeId != node))
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
        if (link_num >= tls_ptr->g_max_lookup_num)
        {
            break;
        }
    }
    return NULL;
}

/* translate a physical address to a virtual address */
void *qaePhysToVirtNUMA(uint64_t physAddress)
{
    dev_mem_info_t *slab;
    uintptr_t offset;
    void *ret = NULL;
    qae_mem_info_t *tls_ptr;
    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);
    /* find slab from physical address without using hash lookup */
    for (slab = tls_ptr->pUserMemListHead; slab != NULL;
         slab = slab->pNext_user)
    {
        offset = (uintptr_t)physAddress - (uintptr_t)slab->phy_addr;
        if (offset < slab->size)
        {
            ret = (void *)((uintptr_t)slab->virt_addr + offset);
            break;
        }
    }
    return ret;
}

void qaeAtFork()
{
    return;
}

API_LOCAL
void __qae_free_slab(const int fd,
                     dev_mem_info_t *slab,
                     qae_mem_info_t *tls_ptr)
{
    dev_mem_info_t memInfo;
    int ret = 0;

    del_slab_from_hash(slab, tls_ptr);
    /* Remove the slab from TMP list as well */
    remove_slab_from_tmp_list(slab);

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
                                const size_t align,
                                qae_mem_info_t *tls_ptr)
{
    dev_mem_info_t *slab =
        __qae_userMemLookupBySize(size, node, addr, align, tls_ptr);

    if (NULL == slab)
    {
        slab = pop_slab(node, tls_ptr);
        if (NULL != slab)
        {
            *addr =
                init_slab_and_alloc((block_ctrl_t *)slab, size, align, tls_ptr);
            if (NULL == *addr)
            {
                CMD_ERROR("%s:%d Memory allocation failed Virtual address: %p "
                          " Size: %zu \n",
                          __func__,
                          __LINE__,
                          slab,
                          size);
                __qae_free_slab(fd, slab, tls_ptr);
                return NULL;
            }
        }
    }
    return slab;
}

static void qae_mem_init_t(void)
{
    qae_mem_info_t *tls_ptr;
    pthread_once(&qae_key_once, qae_make_key);

    if ((tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key)) == NULL)
    {
        tls_ptr = malloc(sizeof(qae_mem_info_t));
        /* Reset all control structures. */
        memset(tls_ptr, 0, sizeof(qae_mem_info_t));
        pthread_setspecific(qae_key, (void *)tls_ptr);
    }
    /* Set this to 0, because mmap doesn't provide NUMA aware memory */
    tls_ptr->g_strict_node = 0;
    tls_ptr->g_max_lookup_num = 10;
    /* MAX cache size per thread */
    tls_ptr->g_max_cache = MAX_CACHE_DEPTH_MB;
    tls_ptr->thd_process_id = syscall(__NR_gettid);

    qae_mem_inited = 1;
}

int32_t qaeMemInit()
{
    int32_t fd_status = 0;
    int32_t status = 0;

    if (!is_new_process())
    {
        /* Return if it is an existing process. */
        return status;
    }

    qae_key = 0;
    qae_mem_inited = 0;
    qae_key_once = PTHREAD_ONCE_INIT;

    fd_status = __qae_open();

    return fd_status;
}

API_LOCAL
void __qae_destroyList(const int fd, dev_mem_info_t *pList, void *thread_key)
{
    dev_mem_info_t *pCurr = pList;

    while (pCurr)
    {
        dev_mem_info_t *next = pCurr->pNext_user;
        __qae_free_slab(fd, pCurr, (qae_mem_info_t *)thread_key);
        pCurr = next;
    }
}

API_LOCAL
void __qae_reset_cache(const int fd, void *thread_key)
{

    dev_mem_info_t *slab = NULL;
    do
    {
        slab = pop_slab(NUMA_ANY_NODE, (qae_mem_info_t *)thread_key);
        if (NULL != slab)
            __qae_free_slab(fd, slab, (qae_mem_info_t *)thread_key);
    } while (slab != NULL);
}

void qaeMemDestroy(void)
{
    qae_mem_info_t *tls_ptr = NULL;

    free_page_table_fptr(&g_page_table);

    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);
    if (tls_ptr && qae_mem_inited)
    {
        __qae_reset_cache(g_fd, (void *)tls_ptr);
        __qae_destroyList(g_fd, tls_ptr->pUserMemListHead, (void *)tls_ptr);
        __qae_destroyList(
            g_fd, tls_ptr->pUserLargeMemListHead, (void *)tls_ptr);
        free(tls_ptr);
        pthread_setspecific(qae_key, NULL);
    }

    __qae_free_special();

    qae_mem_inited = 0;
    pthread_key_delete(qae_key);
}

void qae_mem_destroy_t(void *thread_key)
{
    qae_mem_info_t *tls_ptr;
    tls_ptr = (qae_mem_info_t *)thread_key;
    /* release all control buffers */
    __qae_reset_cache(g_fd, thread_key);
    __qae_destroyList(g_fd, tls_ptr->pUserMemListHead, thread_key);
    __qae_destroyList(g_fd, tls_ptr->pUserLargeMemListHead, thread_key);

    free(thread_key);
    qae_mem_inited = 0;
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
    qae_mem_info_t *tls_ptr;
    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);

    const size_t phys_align_unit = phys_alignment_byte / UNIT_SIZE;
    const size_t reserved = div_round_up(sizeof(block_ctrl_t), UNIT_SIZE);
    /* calculate units needed */
    const size_t requested_pages = div_round_up(size, UNIT_SIZE) + reserved;

    if (tls_ptr == NULL)
    {
        CMD_ERROR("error, unable to initialise slab allocator\n");
        return NULL;
    }

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

        p_ctrl_blk = __qae_find_slab(
            g_fd, size, node, &pVirtAddress, phys_align_unit, tls_ptr);

        if (p_ctrl_blk)
        {
            p_ctrl_blk->allocations += 1;
            return pVirtAddress;
        }
    }

    /* Try to allocate memory as much as possible */
    p_ctrl_blk = __qae_alloc_slab(g_fd,
                                  allocate_pages * UNIT_SIZE,
                                  phys_alignment_byte,
                                  node,
                                  mem_type,
                                  tls_ptr);
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
                                 tls_ptr->pUserLargeMemListHead,
                                 tls_ptr->pUserLargeMemListTail,
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
            __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);

            return NULL;
        }
        pVirtAddress = init_slab_and_alloc(
            (block_ctrl_t *)p_ctrl_blk, size, phys_align_unit, tls_ptr);
        if (NULL == pVirtAddress)
        {
            CMD_ERROR("%s:%d Memory allocation failed Virtual address: %p "
                      " Size: %zu \n",
                      __func__,
                      __LINE__,
                      p_ctrl_blk,
                      size);
            __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);

            return NULL;
        }
    }
    return pVirtAddress;
}

void *qaeMemAllocNUMA(size_t size, int node, size_t phys_alignment_byte)
{
    void *pVirtAddress = NULL;

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

    if (0 != qaeMemInit())
        return NULL;

    if (!qae_mem_inited)
    {
        qae_mem_init_t();
    }

    pVirtAddress = __qae_alloc_addr(size, node, phys_alignment_byte);
    return pVirtAddress;
}

API_LOCAL
void __qae_free_addr(void **p_va, bool secure_free)
{
    dev_mem_info_t *p_ctrl_blk = NULL;
    qae_mem_info_t *tls_ptr;

    tls_ptr = (qae_mem_info_t *)pthread_getspecific(qae_key);
    if (!tls_ptr)
    {
        CMD_ERROR("%s:%d No memory alloc info found \n", __func__, __LINE__);
        return;
    }

    if ((p_ctrl_blk = find_slab_in_hash(*p_va, tls_ptr)) == NULL)
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

        REMOVE_ELEMENT_FROM_LIST(p_ctrl_blk,
                                 tls_ptr->pUserMemListHead,
                                 tls_ptr->pUserMemListTail,
                                 _user);
        if (0 != push_slab(p_ctrl_blk, tls_ptr))
            __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);
    }
    else
    {
        REMOVE_ELEMENT_FROM_LIST(p_ctrl_blk,
                                 tls_ptr->pUserLargeMemListHead,
                                 tls_ptr->pUserLargeMemListTail,
                                 _user);
        __qae_free_slab(g_fd, p_ctrl_blk, tls_ptr);
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
    __qae_free_addr(ptr, secure_free);

    return;
}
