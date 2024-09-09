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
 * @file qae_mem_utils_common.c
 *
 * This file provides for Linux user space memory allocation. It uses
 * a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the  quick assist sample code
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
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include "qae_mem.h"
#include "qae_mem_utils.h"
#include "qae_mem_user_utils.h"
#include "qae_mem_utils_common.h"


load_addr_fptr_t load_addr_fptr = load_addr;

const uint64_t __qae_bitmask[65] = {
    0x0000000000000000ULL, 0x0000000000000001ULL, 0x0000000000000003ULL,
    0x0000000000000007ULL, 0x000000000000000fULL, 0x000000000000001fULL,
    0x000000000000003fULL, 0x000000000000007fULL, 0x00000000000000ffULL,
    0x00000000000001ffULL, 0x00000000000003ffULL, 0x00000000000007ffULL,
    0x0000000000000fffULL, 0x0000000000001fffULL, 0x0000000000003fffULL,
    0x0000000000007fffULL, 0x000000000000ffffULL, 0x000000000001ffffULL,
    0x000000000003ffffULL, 0x000000000007ffffULL, 0x00000000000fffffULL,
    0x00000000001fffffULL, 0x00000000003fffffULL, 0x00000000007fffffULL,
    0x0000000000ffffffULL, 0x0000000001ffffffULL, 0x0000000003ffffffULL,
    0x0000000007ffffffULL, 0x000000000fffffffULL, 0x000000001fffffffULL,
    0x000000003fffffffULL, 0x000000007fffffffULL, 0x00000000ffffffffULL,
    0x00000001ffffffffULL, 0x00000003ffffffffULL, 0x00000007ffffffffULL,
    0x0000000fffffffffULL, 0x0000001fffffffffULL, 0x0000003fffffffffULL,
    0x0000007fffffffffULL, 0x000000ffffffffffULL, 0x000001ffffffffffULL,
    0x000003ffffffffffULL, 0x000007ffffffffffULL, 0x00000fffffffffffULL,
    0x00001fffffffffffULL, 0x00003fffffffffffULL, 0x00007fffffffffffULL,
    0x0000ffffffffffffULL, 0x0001ffffffffffffULL, 0x0003ffffffffffffULL,
    0x0007ffffffffffffULL, 0x000fffffffffffffULL, 0x001fffffffffffffULL,
    0x003fffffffffffffULL, 0x007fffffffffffffULL, 0x00ffffffffffffffULL,
    0x01ffffffffffffffULL, 0x03ffffffffffffffULL, 0x07ffffffffffffffULL,
    0x0fffffffffffffffULL, 0x1fffffffffffffffULL, 0x3fffffffffffffffULL,
    0x7fffffffffffffffULL, 0xffffffffffffffffULL,
};

/* bitmap_read function
 * reads a 64-bit window from a BITMAP_LENx64-bit bitmap
 * starting from window_pos (0 <-> BITMAP_LENx64 -1)
 * map points to the BITMAP_LENx64 bit map area
 * returns the 64-bit window from the BITMAP_LENx64 bitmap.
 * Each bit represents a 1k block in the 2 Meg buffer
 */
STATIC uint64_t bitmap_read(uint64_t *map, size_t window_pos)
{
    uint64_t quad_word_window = 0ULL;
    uint64_t next_quad_word = 0ULL;
    size_t quad_word_pos = 0;
    size_t bit_pos = 0;

    quad_word_pos = window_pos / QWORD_WIDTH;

    if (quad_word_pos >= BITMAP_LEN)
    {
        return QWORD_ALL_ONE;
    }
    bit_pos = window_pos % QWORD_WIDTH;

    quad_word_window = map[quad_word_pos];

    if (0 == bit_pos)
    {
        return quad_word_window;
    }

    /* it is safe to read the next quad word because
     * there is always a barrier at the end */
    next_quad_word = map[quad_word_pos + 1];

    quad_word_window >>= bit_pos;
    next_quad_word <<= QWORD_WIDTH - bit_pos;
    quad_word_window |= next_quad_word;

    return quad_word_window;
}

/* mem_alloc function
 * mem_alloc allocates memory with min. size = UNIT_SIZE
 * block_ctrl points to a block_ctrl_t structure with virtual address
 * size is the requested number of bytes
 * minimum allocation size is UNIT_SIZE
 * returns a pointer to the newly allocated block
 * input: block_ctrl - pointer to the memory control block
 *        size - size requested in bytes
 * output: pointer to the allocated area
 */
API_LOCAL
void *__qae_mem_alloc(block_ctrl_t *block_ctrl, size_t size, size_t align)
{
    uint64_t *bitmap = NULL;
    size_t window_pos = 0;
    void *retval = NULL;
    size_t blocks_found = 0;
    uint64_t bitmap_window = 0ULL;
    size_t blocks_required = 0ULL;
    size_t first_block = 0;
    size_t width = 0;
    size_t width_ones = 0;

    if (NULL == block_ctrl || 0 == size)
    {
        CMD_ERROR(" %s:%d invalid control block or size provided "
                  "block_ctrl = %p and size = %zu \n",
                  __func__,
                  __LINE__,
                  block_ctrl,
                  size);
        return retval;
    }

    bitmap = block_ctrl->bitmap;

    blocks_required = div_round_up(size, UNIT_SIZE);

    window_pos = 0;
    first_block = window_pos;

    do
    {
        /* read 64-bit bitmap window from window_pos (0-BITMAP_LEN*64) */
        bitmap_window = bitmap_read(bitmap, window_pos);
        /* find number of contiguous 0s from right */
        width = mem_ctzll(bitmap_window);

        /* increment number of blocks found with number of contig. 0s
           in bitmap window */
        blocks_found += width;
        /* check if a fit is found */
        if (blocks_found >= blocks_required)
        {
            /* calculate return address from virtual address and
               first block number */
            retval = (uint8_t *)(block_ctrl) + first_block * UNIT_SIZE;
            if (first_block + blocks_required > BITMAP_LEN * QWORD_WIDTH)
            {
                CMD_ERROR("%s:%d Allocation error - Required blocks exceeds "
                          "bitmap window. Block index = %zu, Blocks required"
                          " = %zu and Bitmap window = %ld \n",
                          __func__,
                          __LINE__,
                          first_block,
                          blocks_required,
                          (BITMAP_LEN * QWORD_WIDTH));
                return NULL;
            }
            /* save length in the reserved area right after the bitmap  */
            block_ctrl->sizes[first_block] = (uint16_t)blocks_required;
            /* set bit maps from bit position (0<->BITMAP_LEN*64 -1) =
             * first_block(0<->BITMAP_LEN*64-1)
             * with blocks_required length in bitmap
             */
            set_bitmap(bitmap, first_block, blocks_required);
            break;
        }
        else
        {
            /* Did not find fit. Check if bitmap_window has at least a 1*/
            if (bitmap_window)
            {
                /* This field of contiguous 0s is not big enough, so need
                 * to jump past those 0s and the adjacent 1s and
                 * restart the search at next 0.
                 */
                /* move past the zeros to where the 1s start */
                bitmap_window >>= width;
                /* count the 1s */
                width_ones = mem_ctzll(~bitmap_window);
                /* Set position from which to read next window */
                window_pos += width + width_ones;
                /* Align position if necessary*/
                if (align && window_pos % align)
                {
                    window_pos += align - window_pos % align;
                }
                /* Reset previous search results */
                first_block = window_pos;
                blocks_found = 0;
            }
            else
            {
                /* bit field of 0s is contiguous, but fit not found yet
                 * move window_pos an search more 0s */
                window_pos += width;
            }
        }
    } while (window_pos < BITMAP_LEN * QWORD_WIDTH);
    return retval;
}

/*
 * deallocates previously allocated blocks
 * block_ctrl is a pointer to block_ctrl_t structure
 * block is a result from a previous mem_alloc call
 * secure_free is a boolean to perform memory free secured or not
 */
API_LOCAL
bool __qae_mem_free(block_ctrl_t *block_ctrl, void *block, bool secure_free)
{
    size_t first_block = 0;
    uint32_t length = 0;
    uint8_t *start_of_block = block;
    uint64_t *bitmap = NULL;

    if (NULL == block_ctrl || NULL == block)
    {
        CMD_ERROR("%s:%d One of the parameters is NULL. block_ctrl = %p "
                  "block = %p\n",
                  __func__,
                  __LINE__,
                  block_ctrl,
                  block);
        return false;
    }

    if ((uintptr_t)block % UNIT_SIZE)
    {
        CMD_ERROR("%s:%d Block address(%p) must be multiple of Unit size(%d)\n",
                  __func__,
                  __LINE__,
                  block,
                  UNIT_SIZE);
        return false;
    }

    bitmap = block_ctrl->bitmap;

    /* find start of block in block numbers using the address of start of
     * buffer and block retrieve first_block and length of block from integer
     * at the start of block
     */
    first_block =
        ((uintptr_t)start_of_block - (uintptr_t)block_ctrl) / UNIT_SIZE;
    length = block_ctrl->sizes[first_block];

    if (!length)
    {
        CMD_ERROR("%s:%d Invalid block address provided - "
                  "Block index = %zu. "
                  "Possibly double free.\n",
                  __func__,
                  __LINE__,
                  first_block);

        return false;
    }

    if (length + first_block > BITMAP_LEN * QWORD_WIDTH)
    {
        CMD_ERROR("%s:%d Invalid block address provided - "
                  "block length exceeds bitmap window. block index = %zu "
                  "and block length: %d\n",
                  __func__,
                  __LINE__,
                  first_block,
                  length);
        return false;
    }

    block_ctrl->sizes[first_block] = 0;
    /* clear bitmap from bitmap position (0<->BITMAP_LEN*64 - 1) for length*/
    clear_bitmap(bitmap, first_block, length);

    if (secure_free)
    {
#ifndef ICP_DISABLE_SECURE_MEM_FREE
        qae_memzero_explicit(block, length * UNIT_SIZE);
#endif
    }

    return true;
}

/**************************************
 * Memory functions
 *************************************/
void *qaeMemAlloc(size_t memsize)
{
    void *memPtr = NULL;
    memPtr = calloc(memsize, sizeof(uint8_t));
    return memPtr;
}

void qaeMemFree(void **ptr)
{
    if ((!ptr) || !(*ptr))
    {
        CMD_ERROR("%s:%d Trying to Free NULL Pointer\n", __func__, __LINE__);
        return;
    }
    free(*ptr);
    *ptr = NULL;
}

/*translate a virtual address to a physical address */
uint64_t qaeVirtToPhysNUMA(void *pVirtAddress)
{
    return load_addr_fptr(&g_page_table, pVirtAddress);
}

void qaeMemFreeNUMA(void **ptr)
{
    __qae_memFreeNUMA(ptr, true);
    return;
}

void qaeMemFreeNonZeroNUMA(void **ptr)
{
    __qae_memFreeNUMA(ptr, false);
    return;
}
