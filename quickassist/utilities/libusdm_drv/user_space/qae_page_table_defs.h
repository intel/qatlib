/*******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 * @file qae_page_table_defs.h
 *
 * This file provides user-space page tables definitions.
 *
 ******************************************************************************/

#ifndef QAE_PAGE_TABLE_DEFS_H
#define QAE_PAGE_TABLE_DEFS_H

#define __STDC_WANT_LIB_EXT1__ 1
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>

#include <sys/param.h>

#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif
#define PAGE_SIZE (0x1000)
#define PAGE_SHIFT (12)

#include <stddef.h>

#define QAE_PAGE_MASK (~(PAGE_SIZE - 1))
#define LEVEL_SIZE (PAGE_SIZE / sizeof(uint64_t))

#define HUGEPAGE_SIZE (0x200000)
#define HUGEPAGE_SHIFT (21)
#define HUGEPAGE_MASK (~(HUGEPAGE_SIZE - 1))

typedef struct
{
    uint64_t offset : 12;
    uint64_t idxl0 : 9;
    uint64_t idxl1 : 9;
    uint64_t idxl2 : 9;
    uint64_t idxl3 : 9;
    uint64_t idxl4 : 9;
} page_entry_t;

typedef struct
{
    uint64_t offset : 21;
    uint64_t idxl1 : 9;
    uint64_t idxl2 : 9;
    uint64_t idxl3 : 9;
    uint64_t idxl4 : 9;
} hugepage_entry_t;

typedef union {
    uint64_t addr;
    page_entry_t pg_entry;
    hugepage_entry_t hpg_entry;
} page_index_t;

typedef struct page_table_t
{
    union {
        uint64_t pa;
        struct page_table_t *pt;
    } next[LEVEL_SIZE];
} page_table_t;

typedef void (*free_page_table_fptr_t)(page_table_t *const table);
typedef void (*store_addr_fptr_t)(page_table_t *, uintptr_t, uint64_t);
typedef uint64_t (*load_addr_fptr_t)(page_table_t *, void *);
typedef uint64_t (*load_key_fptr_t)(page_table_t *, void *);

#endif /* QAE_PAGE_TABLE_DEFS_H */
