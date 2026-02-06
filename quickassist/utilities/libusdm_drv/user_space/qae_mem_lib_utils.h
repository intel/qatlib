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
 * @file qae_mem_lib_utils.h
 *
 * This file provides for Linux user space memory allocation. It uses
 * a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the  quick assist sample code
 *
 ***************************************************************************/

#ifndef QAE_MEM_COMMON_H
#define QAE_MEM_COMMON_H

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
#include "qae_mem_utils_common.h"

extern int g_strict_node;
/* Current cached memory size. */
extern size_t g_cache_size;
/* Maximum cached memory size, 8 Mb by default */
extern size_t g_max_cache;

/* User space hash for fast slab searching */
extern slab_list_t g_slab_list[PAGE_SIZE];

extern dev_mem_info_t *__qae_pUserCacheHead;
extern dev_mem_info_t *__qae_pUserCacheTail;
extern dev_mem_info_t *__qae_pUserMemListHead;
extern dev_mem_info_t *__qae_pUserMemListTail;
extern dev_mem_info_t *__qae_pUserLargeMemListHead;
extern dev_mem_info_t *__qae_pUserLargeMemListTail;

extern uint32_t numaAllocations_g;

API_LOCAL
void __qae_ResetControl(void);

API_LOCAL
dev_mem_info_t *__qae_userMemLookupBySize(size_t size,
                                          int node,
                                          void **block,
                                          const size_t align);

API_LOCAL
void __qae_free_slab(const int fd, dev_mem_info_t *slab);

API_LOCAL
dev_mem_info_t *__qae_find_slab(const int fd,
                                const size_t size,
                                const int node,
                                void **addr,
                                const size_t align);
API_LOCAL
int __qae_open(void);

API_LOCAL
void __qae_destroyList(const int fd, dev_mem_info_t *pList);

API_LOCAL
void __qae_reset_cache(const int fd);

API_LOCAL
int __qae_free_special(void);

API_LOCAL
dev_mem_info_t *__qae_alloc_slab(const int fd,
                                 const size_t size,
                                 const uint32_t alignment,
                                 const int node,
                                 enum slabType type);

static inline void add_slab_to_hash(dev_mem_info_t *slab)
{
    const size_t key = get_key(slab->phy_addr);

    ADD_ELEMENT_TO_HEAD_LIST(
        slab, g_slab_list[key].head, g_slab_list[key].tail, _user_hash);
}
static inline void del_slab_from_hash(dev_mem_info_t *slab)
{
    const size_t key = get_key(slab->phy_addr);

    REMOVE_ELEMENT_FROM_LIST(
        slab, g_slab_list[key].head, g_slab_list[key].tail, _user_hash);
}

static inline dev_mem_info_t *find_slab_in_hash(void *virt_addr)
{
    const size_t key = load_key_fptr(&g_page_table, virt_addr);
    dev_mem_info_t *slab = g_slab_list[key].head;

    while (slab)
    {
        uintptr_t offs = (uintptr_t)virt_addr - (uintptr_t)slab->virt_addr;
        if (offs < slab->size)
            return slab;
        slab = slab->pNext_user_hash;
    }

    return NULL;
}

static inline void *init_slab_and_alloc(block_ctrl_t *slab,
                                        const size_t size,
                                        const size_t phys_align_unit)
{
    const size_t last = slab->mem_info.size / CHUNK_SIZE;
    dev_mem_info_t *p_ctrl_blk = &slab->mem_info;
    const size_t reserved = div_round_up(sizeof(block_ctrl_t), UNIT_SIZE);
    void *virt_addr = NULL;

    /* initialise the bitmap to 1 for reserved blocks */
    set_bitmap(slab->bitmap, 0, reserved);
    /* make a barrier to stop search at the end of the bitmap */
    slab->bitmap[last] = QWORD_ALL_ONE;

    virt_addr = __qae_mem_alloc(slab, size, phys_align_unit);
    if (NULL != virt_addr)
    {
        ADD_ELEMENT_TO_HEAD_LIST(
            p_ctrl_blk, __qae_pUserMemListHead, __qae_pUserMemListTail, _user);
    }
    return virt_addr;
}

static inline int push_slab(dev_mem_info_t *slab)
{
    if (g_cache_size + slab->size <= g_max_cache)
    {
        g_cache_size += slab->size;
        ADD_ELEMENT_TO_HEAD_LIST(
            slab, __qae_pUserCacheHead, __qae_pUserCacheTail, _user);
        return 0;
    }
    return -ENOMEM;
}

static inline dev_mem_info_t *pop_slab(const int node)
{
    dev_mem_info_t *slab = NULL;

    for (slab = __qae_pUserCacheHead; slab != NULL; slab = slab->pNext_user)
    {
        if (node != NUMA_ANY_NODE)
            if (g_strict_node && (node != slab->nodeId))
                continue;

        g_cache_size -= slab->size;
        REMOVE_ELEMENT_FROM_LIST(
            slab, __qae_pUserCacheHead, __qae_pUserCacheTail, _user);
        return slab;
    }
    return NULL;
}

#endif /* QAE_MEM_COMMON_H */
