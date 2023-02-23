/*******************************************************************************
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
