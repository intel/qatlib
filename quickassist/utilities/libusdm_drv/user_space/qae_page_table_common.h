/*******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 * @file qae_page_table_common.h
 *
 * This file provides user-space page tables (similar to Intel x86/x64
 * page tables) for fast virtual to physical address translation. Essentially,
 * this is an implementation of the trie data structure optimized for the x86 HW
 * constraints.
 * Memory required:
 *  - 8 Mb to cover 4 Gb address space.
 * I.e. if only 1 Gb is used it will require additional 2 Mb.
 *
 ******************************************************************************/

#ifndef QAE_PAGE_TABLE_COMMON_H
#define QAE_PAGE_TABLE_COMMON_H

#include <strings.h>
#include "qae_page_table_defs.h"
#include <string.h>
#include "qae_mem_user_utils.h"

API_LOCAL
void __qae_set_free_page_table_fptr(free_page_table_fptr_t fp);

API_LOCAL
void __qae_set_loadaddr_fptr(load_addr_fptr_t fp);

API_LOCAL
void __qae_set_loadkey_fptr(load_key_fptr_t fp);

static inline void *qae_memzero(void *const ptr, const size_t count)
{
    uint32_t lim = 0;
    volatile unsigned char *volatile dstPtr = ptr;

    while (lim < count)
    {
        dstPtr[lim++] = '\0';
    }
    return (void *)dstPtr;
}

/*
 *  Fills a memory zone with 0,
 *  returns pointer to the memory zone.
 */
static inline void *qae_memzero_explicit(void *const ptr, const size_t count)
{
    if (!ptr)
    {
        return NULL;
    }
#ifdef __STDC_LIB_EXT1__
    errno_t result =
        memset_s(ptr, sizeof(ptr), 0, count); /* Supported on C11 standard */
    if (result != 0)
    {
        return NULL;
    }
    return ptr;
#endif /* __STDC_LIB_EXT1__ */
    return qae_memzero(ptr, count); /* Platform-independent secure memset */
}

static inline void *next_level(page_table_t *volatile *ptr)
{
    page_table_t *old_ptr = *ptr;
    page_table_t *new_ptr;

    if (NULL != old_ptr)
        return old_ptr;

    new_ptr = mmap(NULL,
                   sizeof(page_table_t),
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1,
                   0);
    if ((void *)-1 == new_ptr)
        return NULL;

    if (!__sync_bool_compare_and_swap(ptr, NULL, new_ptr))
        munmap(new_ptr, sizeof(page_table_t));

    return *ptr;
}

static inline void free_page_level(page_table_t *const level, const size_t iter)
{
    size_t i = 0;

    if (0 == iter)
        return;

    for (i = 0; i < LEVEL_SIZE; ++i)
    {
        page_table_t *pt = level->next[i].pt;
        if (NULL != pt)
        {
            free_page_level(pt, iter - 1);
            munmap(pt, sizeof(page_table_t));
        }
    }
}

static inline void free_page_table(page_table_t *const table)
{
    /* There are 1+4 levels in 64-bit page table for 4KB pages. */
    free_page_level(table, 4);
    /* Reset global root table. */
    memset(table, 0, sizeof(page_table_t));
}

static inline void store_addr(page_table_t *level,
                              uintptr_t virt,
                              uint64_t phys)
{
    page_index_t id;

    id.addr = virt;

    level = next_level(&level->next[id.pg_entry.idxl4].pt);
    if (NULL == level)
        return;

    level = next_level(&level->next[id.pg_entry.idxl3].pt);
    if (NULL == level)
        return;

    level = next_level(&level->next[id.pg_entry.idxl2].pt);
    if (NULL == level)
        return;

    level = next_level(&level->next[id.pg_entry.idxl1].pt);
    if (NULL == level)
        return;

    level->next[id.pg_entry.idxl0].pa = phys;
}

static inline void store_addr_hpg(page_table_t *level,
                                  uintptr_t virt,
                                  uint64_t phys)
{
    page_index_t id;

    id.addr = virt;

    level = next_level(&level->next[id.hpg_entry.idxl4].pt);
    if (NULL == level)
        return;

    level = next_level(&level->next[id.hpg_entry.idxl3].pt);
    if (NULL == level)
        return;

    level = next_level(&level->next[id.hpg_entry.idxl2].pt);
    if (NULL == level)
        return;

    level->next[id.hpg_entry.idxl1].pa = phys;
}

static inline uint64_t get_key(const uint64_t phys)
{
    /* For 4KB page: use bits 20-31 of a physical address as a hash key.
     * It provides a good distribution for 1Mb/2Mb slabs and a moderate
     * distribution for 128Kb/256Kb/512Kbslabs.
     */
    return (phys >> 20) & ~QAE_PAGE_MASK;
}

static inline void store_mmap_range(page_table_t *p_level,
                                    void *p_virt,
                                    uint64_t p_phys,
                                    size_t p_size,
                                    int hp_en)
{
    size_t offset;
    size_t page_size = PAGE_SIZE;
    uint64_t page_mask = QAE_PAGE_MASK;
    store_addr_fptr_t store_addr_ptr = store_addr;
    const uintptr_t virt = (uintptr_t)p_virt;

    if (hp_en)
    {
        page_size = HUGEPAGE_SIZE;
        page_mask = HUGEPAGE_MASK;
        store_addr_ptr = store_addr_hpg;
    }
    /* Store the key into the physical address itself,
     * for 4KB pages: 12 lower bits are always 0 (physical page addresses
     * are 4KB-aligned).
     * for 2MB pages: 21 lower bits are always 0 (physical page addresses
     * are 2MB-aligned)
     */
    p_phys = (p_phys & page_mask) | get_key(p_phys);
    for (offset = 0; offset < p_size; offset += page_size)
    {
        store_addr_ptr(p_level, virt + offset, p_phys + offset);
    }
}

static inline uint64_t load_addr(page_table_t *level, void *virt)
{
    page_index_t id;
    uint64_t phy_addr;

    id.addr = (uintptr_t)virt;

    level = level->next[id.pg_entry.idxl4].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.pg_entry.idxl3].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.pg_entry.idxl2].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.pg_entry.idxl1].pt;
    if (NULL == level)
        return 0;

    phy_addr = level->next[id.pg_entry.idxl0].pa;
    if (0 == phy_addr)
        return 0;
    return (phy_addr & QAE_PAGE_MASK) | id.pg_entry.offset;
}

static inline uint64_t load_addr_hpg(page_table_t *level, void *virt)
{
    page_index_t id;
    uint64_t phy_addr;

    id.addr = (uintptr_t)virt;

    level = level->next[id.hpg_entry.idxl4].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.hpg_entry.idxl3].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.hpg_entry.idxl2].pt;
    if (NULL == level)
        return 0;

    phy_addr = level->next[id.hpg_entry.idxl1].pa;
    if (0 == phy_addr)
        return 0;
    return (phy_addr & HUGEPAGE_MASK) | id.hpg_entry.offset;
}

static inline uint64_t load_key(page_table_t *level, void *virt)
{
    page_index_t id;
    uint64_t phy_addr;

    id.addr = (uintptr_t)virt;

    level = level->next[id.pg_entry.idxl4].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.pg_entry.idxl3].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.pg_entry.idxl2].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.pg_entry.idxl1].pt;
    if (NULL == level)
        return 0;

    phy_addr = level->next[id.pg_entry.idxl0].pa;
    return phy_addr & ~QAE_PAGE_MASK;
}

static inline uint64_t load_key_hpg(page_table_t *level, void *virt)
{
    page_index_t id;
    uint64_t phy_addr;

    id.addr = (uintptr_t)virt;

    level = level->next[id.hpg_entry.idxl4].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.hpg_entry.idxl3].pt;
    if (NULL == level)
        return 0;

    level = level->next[id.hpg_entry.idxl2].pt;
    if (NULL == level)
        return 0;

    phy_addr = level->next[id.hpg_entry.idxl1].pa;
    /* The hash key is of 4KB long for both normal page and huge page */
    return phy_addr & ~QAE_PAGE_MASK;
}

static inline void free_page_table_hpg(page_table_t *const table)
{
    /* There are 1+3 levels in 64-bit page table for 2MB hugepages. */
    free_page_level(table, 3);
    /* Reset global root table. */
    memset(table, 0, sizeof(page_table_t));
}

#endif /* QAE_PAGE_TABLE_COMMON_H */
