/**
 * @file OsalUsrKrnProxy.c (linux user space)
 *
 * @brief Implementation for NUMA.
 *
 *
 * @par
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
 */

#include "Osal.h"
#include "OsalOsTypes.h"
#include "OsalDevDrv.h"
#include "OsalDevDrvCommon.h"

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
#include <signal.h>

/* The maximum number we allow to search for available size */
#define MAX_LOOKUP_NUM 10

/* the maximum retry to wait for memcpy ready */
#define MAX_MEMCPY_WAITNUM 100

#define BITMAP_LEN 8
#define QWORD_WIDTH (8 * sizeof(UINT64))
#define DWORD_WIDTH (8 * sizeof(UINT32))
#define WORD_WIDTH (8 * sizeof(UINT16))

#define QWORD_ALL_ONE 0xFFFFFFFFFFFFFFFFULL
#define QWORD_MSB_SET 0x8000000000000000ULL
#define LOWER_WORD_ALL_ONE 0xFFFFUL

#define MMAP_FLAGS MAP_PRIVATE

#ifndef __off_t
typedef off_t __off_t;
#endif

static int fd = -1;
static int fdp = -1;
static int strict_node = 1;

#ifndef ICP_WITHOUT_THREAD
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_page = PTHREAD_MUTEX_INITIALIZER;
#endif
static dev_mem_info_t *pUserMemList = NULL;
static dev_mem_info_t *pUserMemListHead = NULL;

static dev_mem_info_t *pUserLargeMemList = NULL;
static dev_mem_info_t *pUserLargeMemListHead = NULL;

static dev_mem_info_t *pUserMemListPage = NULL;
static dev_mem_info_t *pUserMemListHeadPage = NULL;

static INT32 ctzll(UINT64 bitmap_window)
{
    UINT64 mask = 1ULL;
    UINT32 retval = 0;
    while (!(mask & bitmap_window))
    {
        ++retval;
        mask <<= 1;
    }
    return retval;
}
/*
 * reads a 64-bit window from a 8x64-bit bitmap
 * starting from window_pos (0 - 510 )
 * map points to the 8x64 bit map area
 * returns the 64-bit window from the 8x64 bitmap.
 */

static UINT64 bitmap_read(UINT64 *map, size_t window_pos)
{
    UINT64 quad_word_window = 0ULL;
    UINT64 next_quad_word = 0ULL;
    size_t quad_word_pos = BITMAP_LEN - window_pos / QWORD_WIDTH - 1;
    size_t bit_pos = window_pos % QWORD_WIDTH;

    quad_word_window = map[quad_word_pos];

    if (0 == bit_pos)
    {
        return quad_word_window;
    }

    if (0 == quad_word_pos)
    {
        next_quad_word = QWORD_ALL_ONE;
    }
    else
    {
        next_quad_word = map[quad_word_pos - 1];
    }

    quad_word_window >>= bit_pos;
    next_quad_word &= ((1ULL << bit_pos) - 1);
    next_quad_word <<= QWORD_WIDTH - bit_pos;
    quad_word_window |= next_quad_word;

    return quad_word_window;
}
/*
 * modify the 8x64-bit bitmap from pos
 * for len length
 * if set nonzero bits from pos for len length are set to 1
 * otherwise they are cleared to zero
 */
static void modify_bitmap(UINT64 *map, size_t pos, size_t len, UINT32 set)
{
    size_t window = 0;
    size_t bitfield_pos = 0;
    size_t bitfield_len = 0;
    UINT64 mask = 0ULL;
    while (len > 0)
    {
        window = BITMAP_LEN - pos / QWORD_WIDTH - 1;
        bitfield_pos = pos % QWORD_WIDTH;
        if (len + bitfield_pos >= QWORD_WIDTH)
        {
            bitfield_len = QWORD_WIDTH - bitfield_pos;
            mask = ((1ULL << bitfield_pos) - 1);
        }
        else
        {
            bitfield_len = len;
            mask = ((1ULL << bitfield_pos) - 1) |
                   ~((1ULL << (bitfield_pos + bitfield_len)) - 1);
        }
        if (set)
        {
            map[window] |= ~mask;
        }
        else
        {
            map[window] &= mask;
        }
        len -= bitfield_len;
        pos += bitfield_len;
    }
}
/*
 * mem_alloc allocates memory with min. size = PAGE_SIZE
 * map points to a dev_mem_info_t structure with virtual address
 * size is the requested number of bytes
 * minimum allocation size is PAGE_SIZE
 * the first unsigned int of the allocated block has
 * the starting block number in the upper
 * and the size in PAGE_SIZE in the lower 16 bits.
 * returns a pointer to the newly allocated block that
 * points to the memory area after this unsigned integer
 */
static void *mem_alloc(void *map, size_t size)
{
    UINT64 *bitmap = NULL;
    INT32 window_pos = 0;
    UINT32 *retval = NULL;
    INT32 blocks_found = 0;
    UINT64 bitmap_window = 0ULL;
    UINT32 blocks_required = 0ULL;
    UINT32 first_block = 1;

    if (NULL == map || 0 == size)
    {
        return retval;
    }

    bitmap = (UINT64 *)((UINT8 *)map + USER_MEM_128BYTE_OFFSET);
    /* increase size to make room for an integer to hold first block/length
     * info*/
    size += sizeof(UINT32);

    blocks_required =
        size % PAGE_SIZE ? size / PAGE_SIZE + 1 : size / PAGE_SIZE;
    do
    {
        INT32 width = 0;

        /* read 64-bit bitmap window from window_pos (0-510) */
        bitmap_window = bitmap_read(bitmap, window_pos);

        /* check if there is at least a 1 in bitmap window */
        if (bitmap_window)
        {
            /* find number of contiguous 0s from right */
            width = ctzll(bitmap_window);
        }
        else
        {
            /* bitmap window is 0 there are 64 contiguous 0s*/
            width = QWORD_WIDTH;
        }
        /* increment number of blocks found with number of contig. 0s in bitmap
         * window */
        blocks_found += width;
        /* check if a fit is found */
        if (blocks_found >= blocks_required)
        {
            /* calculate return address from virtual address and first block
             * number */
            retval = (UINT32 *)(((dev_mem_info_t *)map)->virt_addr) +
                     (first_block)*PAGE_SIZE / sizeof(UINT32);
            /* save first block number and length in the first integer of the
             * block
             * and increment pointer
             */
            *retval++ = (first_block << WORD_WIDTH) |
                        (blocks_required & LOWER_WORD_ALL_ONE);
            /* set bit maps from bit position (0-510) = first_block(1-511) - 1
             * with blocks_required length in bitmap
             */
            modify_bitmap(bitmap, first_block - 1, blocks_required, 1);
            break;
        }
        else
        {
            /* did not find fit check if bitmap_window has at least a 1*/
            if (bitmap_window)
            {
                /* bit field of 0s not contiguous, clear blocks_found adjust
                 * first_block
                 * and window_pos
                 */
                blocks_found = 0;
                window_pos += width + 1;
                first_block = window_pos + 1;
            }
            else
            {
                /* bit field of 0s is contiguous, but fit not found yet
                 * move window_pos an search more 0s */
                window_pos += width;
            }
        }
    } while (window_pos < BITMAP_LEN * QWORD_WIDTH - 1);

    return retval;
}
/*
 * deallocates previously allocated blocks
 * map is a pointer to dev_mem_info_t structure
 * block is returned by ia previous mem_alloc call
 */
static void mem_free(void *map, void *block)
{
    UINT32 first_block = 0;
    UINT32 length = 0;
    UINT32 *start_of_block = block;
    UINT64 *bitmap = (UINT64 *)((UINT8 *)map + USER_MEM_128BYTE_OFFSET);
    if (NULL == block)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Block address is zero \n");

        return;
    }
    /* find start of block that is one integer back from user area */
    --start_of_block;

    /* retrieve first_block and length of block from integer at the start of
     * block */
    first_block = *start_of_block >> WORD_WIDTH;
    length = *start_of_block & LOWER_WORD_ALL_ONE;

    if (!first_block || first_block > BITMAP_LEN * QWORD_WIDTH - 1 ||
        length + first_block > BITMAP_LEN * QWORD_WIDTH)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Invalid block first block: %d length: %d\n",
                first_block,
                length);

        return;
    }
    /* clear bitmap from bitmap position (0-510) = first_block(1-511) - 1 for
     * length */
    modify_bitmap(bitmap, first_block - 1, length, 0);
}

OSAL_STATUS userMemListAdd(dev_mem_info_t *pMemInfo)
{
#ifndef ICP_WITHOUT_THREAD
    int ret = 0;

    ret = pthread_mutex_lock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return OSAL_FAIL;
    }
#endif
    ADD_ELEMENT_TO_HEAD_OF_LIST(pMemInfo, pUserMemList, pUserMemListHead);
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);

        return OSAL_FAIL;
    }
#endif
    return OSAL_SUCCESS;
}

static OSAL_STATUS userLargeMemListAdd(dev_mem_info_t *pMemInfo)
{
#ifndef ICP_WITHOUT_THREAD
    int ret = 0;

    ret = pthread_mutex_lock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return OSAL_FAIL;
    }
#endif
    ADD_ELEMENT_TO_HEAD_OF_LIST(
        pMemInfo, pUserLargeMemList, pUserLargeMemListHead);
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);

        return OSAL_FAIL;
    }
#endif
    return OSAL_SUCCESS;
}

OSAL_STATUS userMemListAddPage(dev_mem_info_t *pMemInfo)
{
#ifndef ICP_WITHOUT_THREAD
    int ret = 0;

    ret = pthread_mutex_lock(&mutex_page);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return OSAL_FAIL;
    }
#endif
    ADD_ELEMENT_TO_END_OF_LIST(
        pMemInfo, pUserMemListPage, pUserMemListHeadPage);
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex_page);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);

        return OSAL_FAIL;
    }
#endif
    return OSAL_SUCCESS;
}

void userMemListFree(dev_mem_info_t *pMemInfo)
{
    dev_mem_info_t *pCurr = NULL;
    int done = 0;

    for (pCurr = pUserLargeMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if (pCurr == pMemInfo)
        {
            REMOVE_ELEMENT_FROM_LIST(
                pCurr, pUserLargeMemList, pUserLargeMemListHead);
            done = 1;
            break;
        }
    }

    for (pCurr = pUserMemListHead; (pCurr != NULL) && (done == 0);
         pCurr = pCurr->pNext)
    {
        if (pCurr == pMemInfo)
        {
            REMOVE_ELEMENT_FROM_LIST(pCurr, pUserMemList, pUserMemListHead);
            break;
        }
    }
}

void userMemListFreePage(dev_mem_info_t *pMemInfo)
{
    dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserMemListHeadPage; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if (pCurr == pMemInfo)
        {
            REMOVE_ELEMENT_FROM_LIST(
                pCurr, pUserMemListPage, pUserMemListHeadPage);
            break;
        }
    }
}

dev_mem_info_t *userMemLookupBySize(UINT32 size, UINT32 node, void **block)
{
    dev_mem_info_t *pCurr = NULL;
    int link_num = 0;
    /* Search from new to old */
    for (pCurr = pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if (strict_node && (pCurr->nodeId != node))
        {
            continue;
        }
        if (pCurr->available_size >= size + sizeof(UINT32))
        {
            *block = mem_alloc(pCurr, size);
            if (*block != NULL)
            {
                return pCurr;
            }
        }
        /* Prevent from visiting whole chain, because after the first
         * several node, the chance to get one is very small.
         * Another consideration is to prevent new allocation from old
         * link, so that the old link could be released
         */
        link_num++;
        if (link_num >= MAX_LOOKUP_NUM)
        {
            break;
        }
    }
    return NULL;
}

dev_mem_info_t *userMemLookupByVirtAddr(void *virt_addr)
{
    dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if ((UARCH_INT)pCurr->virt_addr <= (UARCH_INT)virt_addr &&
            ((UARCH_INT)pCurr->virt_addr + pCurr->size) > (UARCH_INT)virt_addr)
        {
            return pCurr;
        }
    }
    return NULL;
}

static dev_mem_info_t *userLargeMemLookupByVirtAddr(void *virt_addr)
{
    dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserLargeMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if ((UARCH_INT)pCurr->virt_addr <= (UARCH_INT)virt_addr &&
            ((UARCH_INT)pCurr->virt_addr + pCurr->size) > (UARCH_INT)virt_addr)
        {
            return pCurr;
        }
    }
    return NULL;
}

dev_mem_info_t *userMemLookupByVirtAddrPage(void *virt_addr)
{
    dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserMemListHeadPage; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if ((UARCH_INT)pCurr->virt_addr == (UARCH_INT)virt_addr)
        {
            return pCurr;
        }
    }
    return NULL;
}

OSAL_PUBLIC OSAL_STATUS osalMemInitialize(char *path)
{
    char mem_path[DEV_PATH_SIZE] = "";
    char mempage_path[DEV_PATH_SIZE] = "";

    if (fd > 0 && fdp > 0)
    {
        return OSAL_SUCCESS;
    }

    if (path != NULL)
    {
        size_t dev_mem_name_page_len = 0;
        size_t offs = 0;
        size_t os_dev_dir_len = 0;
        size_t path_len = 0;

        // Look only at the first DEV_PATH_SIZE characters for a null byte.
        path_len = OSAL_OS_GET_STRING_LENGTH(path, DEV_PATH_SIZE);
        os_dev_dir_len = sizeof(OS_DEV_DIRECTORY) - 1;
        dev_mem_name_page_len = sizeof(DEV_MEM_NAME_PAGE) - 1;

        if (path_len + os_dev_dir_len + dev_mem_name_page_len > DEV_PATH_SIZE)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "path to device is greater that max length %d\n",
                    fd);

            return OSAL_FAIL;
        }

        offs = snprintf(mem_path, sizeof(mem_path), "%s", OS_DEV_DIRECTORY);
        offs = MIN(offs, sizeof(mem_path));
        offs += snprintf(mem_path + offs, sizeof(mem_path) - offs, "%s", path);
        offs = MIN(offs, sizeof(mem_path));
        offs += snprintf(
            mem_path + offs, sizeof(mem_path) - offs, "%s", DEV_MEM_NAME);

        offs = snprintf(
            mempage_path, sizeof(mempage_path), "%s", OS_DEV_DIRECTORY);
        offs = MIN(offs, sizeof(mempage_path));
        offs += snprintf(
            mempage_path + offs, sizeof(mempage_path) - offs, "%s", path);
        offs = MIN(offs, sizeof(mempage_path));
        offs += snprintf(mempage_path + offs,
                         sizeof(mempage_path) - offs,
                         "%s",
                         DEV_MEM_NAME_PAGE);
    }

    fd = open((path) ? mem_path : DEV_MEM_PATH, O_RDWR);
    if (fd < 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "unable to open %s %d\n",
                (path) ? mem_path : DEV_MEM_PATH,
                fd);
        return OSAL_FAIL;
    }

    fdp = open((path) ? mempage_path : DEV_MEM_PAGE_PATH, O_RDWR);
    if (fdp < 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "unable to open %s %d\n",
                (path) ? mempage_path : DEV_MEM_PAGE_PATH,
                fdp);
        close(fd);
        fd = -1;
        return OSAL_FAIL;
    }
    return OSAL_SUCCESS;
}

OSAL_PUBLIC void osalMemDestroy()
{
    if (fd > 0)
    {
        close(fd);
        fd = -1;
    }
    if (fdp > 0)
    {
        close(fdp);
        fdp = -1;
    }
}

OSAL_PUBLIC void *osalMemAllocContiguousNUMA(UINT32 size,
                                             UINT32 node,
                                             UINT32 alignment)
{
    int ret = 0;
    dev_mem_info_t *pMemInfo = NULL;
    void *pVirtAddress = NULL;
    void *pOriginalAddress = NULL;
    UARCH_INT padding = 0;
    UARCH_INT aligned_address = 0;
    int requested_pages = 0;
    int full_size = 0;
    int allocate_pages = 0;
    UARCH_INT offset = 0;
    int mmap_size = 0;
    int alloc_size = 0;
    int large_memory = 0;
    UINT8 *bitmask = NULL;

    if (size == 0 || alignment == 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Invalid size or alignment parameter \n");

        return NULL;
    }
    if (fd < 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Memory file handle %d is not ready\n",
                fd);

        return NULL;
    }

    if (alignment == sizeof(UINT32) || alignment == sizeof(UINT16))
    {
        alignment = 0;
    }
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_lock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return NULL;
    }
#endif
    if ((pMemInfo = userMemLookupBySize(
             size + alignment, node, &pOriginalAddress)) != NULL)
    {
        padding = alignment ? (UARCH_INT)pOriginalAddress % alignment : 0;
        aligned_address = ((UARCH_INT)pOriginalAddress) + (alignment - padding);
        pMemInfo->available_size -=
            (*((UINT32 *)pOriginalAddress - 1) & LOWER_WORD_ALL_ONE) *
            PAGE_SIZE;
        pMemInfo->allocations += 1;
#ifndef ICP_WITHOUT_THREAD
        ret = pthread_mutex_unlock(&mutex);
        if (ret)
        {
            osalMemFreeNUMA(pMemInfo);
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "pthread_mutex_unlock(): Failed to unlock mutex, ret = "
                    "%d \n",
                    ret);

            return NULL;
        }
#endif
        return (void *)aligned_address;
    }
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);

        return NULL;
    }
#endif
    /* full size means header size plus requested size */
    full_size = size + sizeof(UINT32) + alignment;
    /* calculate pages needed */
    requested_pages = full_size % PAGE_SIZE ? ((full_size / PAGE_SIZE) + 1)
                                            : (full_size) / PAGE_SIZE;

    if (requested_pages > NUM_PAGES_PER_ALLOC - 1)
    {
        large_memory = 1;
        allocate_pages =
            size % PAGE_SIZE ? size / PAGE_SIZE + 1 : size / PAGE_SIZE;
    }
    else
    {
        allocate_pages = NUM_PAGES_PER_ALLOC;
    }

    /* calculate how many memory for allocation*/
    if (alloc_size == 0)
    {
        alloc_size = allocate_pages * PAGE_SIZE;
    }

    pMemInfo = calloc(USER_MEM_128BYTE_OFFSET + BITMAP_LEN * sizeof(UINT64),
                      sizeof(UINT8));
    if (NULL == pMemInfo)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "unable to allocate pMemInfo buffer\n");

        return NULL;
    }

    pMemInfo->allocations = 0;
    pMemInfo->nodeId = node;
    pMemInfo->size = alloc_size;

    /* Try to allocate memory as much as possible */
    ret = ioctl(fd, DEV_MEM_IOC_MEMALLOC, pMemInfo);
    if (ret != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "ioctl memory alloc failed, ret = %d\n",
                ret);

        free(pMemInfo);
        return NULL;
    }

    if (node != pMemInfo->nodeId)
    {
        strict_node = 0;
    }

    if (large_memory)
    {
        mmap_size = pMemInfo->size;
        /* When uses really wants to mmap 0x2*NUM_PAGES_PER_ALLOC
         * We have to do some fixup
         */
        if ((mmap_size / PAGE_SIZE) == DOUBLE_NUM_PAGES_PER_ALLOC)
            mmap_size = PAGE_SIZE * ICP_MMAP_DOUBLE_NUM_PAGES;
    }
    else
    {
        /* Use double size to call mmap, so that we can get aligned
         * virtual address
         */
        mmap_size = 0x2 * pMemInfo->size;
    }

    pMemInfo->mmap_size = mmap_size;
    pMemInfo->fvirt_addr = mmap((caddr_t)0,
                                mmap_size,
                                PROT_READ | PROT_WRITE,
                                MAP_SHARED,
                                fd,
                                (pMemInfo->id * getpagesize()));

    if (pMemInfo->fvirt_addr == (caddr_t)MAP_FAILED)
    {
        osalLog(OSAL_LOG_LVL_ERROR, OSAL_LOG_DEV_STDOUT, "mmap failed\n");

        ret = ioctl(fd, DEV_MEM_IOC_MEMFREE, pMemInfo);
        if (ret != 0)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "ioctl DEV_MEM_IOC_MEMFREE call failed, ret = %d\n",
                    ret);
        }
        free(pMemInfo);
        return NULL;
    }

/* available size needs to substract current size and header */
/* As DMA remapping may add extra page, so we need to use alloc_size
   instead of the size in pMemInfo structure */
#ifdef ICP_SRIOV
    /* Save one page for IORemapping */
    alloc_size -= PAGE_SIZE;
#endif
    pMemInfo->allocations = 1;
    if (large_memory)
    {
        pMemInfo->available_size = alloc_size - size - USER_MEM_128BYTE_OFFSET;
        pMemInfo->virt_addr = pMemInfo->fvirt_addr;
        pMemInfo->fvirt_addr = 0;
        userLargeMemListAdd(pMemInfo);
        pVirtAddress =
            (void *)((UARCH_INT)pMemInfo->virt_addr + USER_MEM_128BYTE_OFFSET);
    }
    else
    {
        /* Save some space for memory info block*/
        offset = ((UARCH_INT)pMemInfo->fvirt_addr + pMemInfo->size) %
                 (pMemInfo->size);
        pMemInfo->virt_addr =
            (void *)((UARCH_INT)pMemInfo->fvirt_addr + pMemInfo->size - offset);
        if ((UARCH_INT)pMemInfo->virt_addr % PAGE_SIZE)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "Bad virtual address alignment %p %x %x\n",
                    pMemInfo->virt_addr,
                    NUM_PAGES_PER_ALLOC,
                    PAGE_SIZE);
            ioctl(fd, DEV_MEM_IOC_MEMFREE, pMemInfo);
            free(pMemInfo);
            return NULL;
        }

        memcpy(pMemInfo->virt_addr, pMemInfo, sizeof(dev_mem_info_t));
        bitmask = (UINT8 *)pMemInfo;
        *(UINT64 *)(bitmask + USER_MEM_128BYTE_OFFSET) = QWORD_MSB_SET;
        pVirtAddress = mem_alloc(pMemInfo, size + alignment);
        if (NULL == pVirtAddress)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "Memory allocation failed Virtual address: %p Size: %x \n",
                    pMemInfo->virt_addr,
                    size + alignment);
            ioctl(fd, DEV_MEM_IOC_MEMFREE, pMemInfo);
            free(pMemInfo);
            return NULL;
        }
        pMemInfo->available_size =
            alloc_size -
            ((*((UINT32 *)pVirtAddress - 1) & LOWER_WORD_ALL_ONE) + 1) *
                PAGE_SIZE;
        userMemListAdd(pMemInfo);

        padding = alignment ? (UARCH_INT)pVirtAddress % alignment : 0;
        aligned_address = ((UARCH_INT)pVirtAddress) - padding + alignment;
        pVirtAddress = (void *)aligned_address;
    }
    return pVirtAddress;
}

OSAL_PUBLIC void *osalMemAllocPage(UINT32 node, UINT64 *physAddr)
{
    int ret = 0;
    dev_mem_info_t *pMemInfo = NULL;

    if (fd < 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Memory file handle is not ready\n",
                fd);
        return NULL;
    }

    pMemInfo = malloc(sizeof(dev_mem_info_t));
    if (NULL == pMemInfo)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "unable to allocate pMemInfo buffer\n",
                fd);

        return NULL;
    }

    pMemInfo->nodeId = node;
    pMemInfo->size = getpagesize();

    ret = ioctl(fdp, DEV_MEM_IOC_MEMALLOCPAGE, pMemInfo);
    if (ret != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "ioctl call failed, ret = %d\n",
                ret);

        free(pMemInfo);
        return NULL;
    }

    pMemInfo->virt_addr = mmap(NULL,
                               pMemInfo->size,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE,
                               fdp,
                               (__off_t)pMemInfo->id * getpagesize());
    if (pMemInfo->virt_addr == MAP_FAILED)
    {
        osalStdLog("Errno: %d\n", errno);
        osalLog(OSAL_LOG_LVL_ERROR, OSAL_LOG_DEV_STDOUT, "mmap failed\n");

        ret = ioctl(fd, DEV_MEM_IOC_MEMFREEPAGE, pMemInfo);
        if (ret != 0)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "ioctl call failed, ret = %d\n",
                    ret);
        }
        free(pMemInfo);
        return NULL;
    }

    userMemListAddPage(pMemInfo);
    *physAddr = pMemInfo->phy_addr;
    return pMemInfo->virt_addr;
}

OSAL_PUBLIC void osalMemFreeNUMA(void *pVirtAddress)
{
    int ret = 0;
    dev_mem_info_t *pMemInfo = NULL;

    if (NULL == pVirtAddress)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Invalid virtual address\n");

        return;
    }
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_lock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return;
    }
#endif
    if ((pMemInfo = userMemLookupByVirtAddr(pVirtAddress)) != NULL)
    {
        pMemInfo->allocations -= 1;
        if (pMemInfo->allocations != 0)
        {
            UINT32 *blockAddress =
                (UINT32 *)((UARCH_INT)pVirtAddress & ~(PAGE_SIZE - 1));
            pMemInfo->available_size +=
                (*blockAddress & LOWER_WORD_ALL_ONE) * PAGE_SIZE;
            mem_free(pMemInfo, ++blockAddress);
#ifndef ICP_WITHOUT_THREAD
            ret = pthread_mutex_unlock(&mutex);
            if (ret)
            {
                osalMemFreeNUMA(pMemInfo);
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDOUT,
                        "pthread_mutex_unlock(): Failed to unlock mutex, "
                        "ret = %d \n",
                        ret);
            }
#endif
            return;
        }
    }
    else
    {
        if ((pMemInfo = userLargeMemLookupByVirtAddr(pVirtAddress)) == NULL)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "userMemLookupByVirtAddr failed\n");

#ifndef ICP_WITHOUT_THREAD
            ret = pthread_mutex_unlock(&mutex);
            if (ret)
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDOUT,
                        "pthread_mutex_unlock(): Failed to unlock mutex, "
                        "ret = %d \n",
                        ret);
            }
#endif
            return;
        }
    }

    if (pMemInfo->fvirt_addr)
    {
        ret = munmap(pMemInfo->fvirt_addr, pMemInfo->mmap_size);
    }
    else
    {
        ret = munmap(pMemInfo->virt_addr, pMemInfo->mmap_size);
    }
    if (ret != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "munmap failed, ret = %d\n",
                ret);
    }

    ret = ioctl(fd, DEV_MEM_IOC_MEMFREE, pMemInfo);
    if (ret != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "ioctl call failed, ret = %d\n",
                ret);
    }

    userMemListFree(pMemInfo);
    free(pMemInfo);
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);
    }
#endif
    return;
}

OSAL_PUBLIC void osalMemFreePage(void *pVirtAddress)
{
    int ret = 0;
    dev_mem_info_t *pMemInfo = NULL;

    if (NULL == pVirtAddress)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Invalid virtual address\n");

        return;
    }
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_lock(&mutex_page);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return;
    }
#endif
    pMemInfo = userMemLookupByVirtAddrPage(pVirtAddress);

    if (pMemInfo == NULL)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "userMemLookupByVirtAddrPage failed \n");

#ifndef ICP_WITHOUT_THREAD
        ret = pthread_mutex_unlock(&mutex_page);
        if (ret)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "pthread_mutex_unlock(): Failed to unlock mutex, ret = "
                    "%d \n",
                    ret);
        }
#endif
        return;
    }

    ret = munmap(pMemInfo->virt_addr, getpagesize());
    if (ret != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "munmap failed, ret = %d\n",
                ret);
    }

    ret = ioctl(fdp, DEV_MEM_IOC_MEMFREEPAGE, pMemInfo);
    if (ret != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "ioctl call failed, ret = %d\n",
                ret);
    }
    userMemListFreePage(pMemInfo);
    free(pMemInfo);
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex_page);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);
    }
#endif
    return;
}

UINT64
osalVirtToPhysNUMA(void *pVirtAddress)
{
    dev_mem_info_t *pMemInfo = NULL;
    UARCH_INT offset = 0;
    UINT64 phy_address = 0;
#ifndef ICP_WITHOUT_THREAD
    int ret = 0;
#endif

    OSAL_LOCAL_ENSURE(pVirtAddress != NULL,
                      "osalVirtToPhysNUMA():   Null virtual address pointer",
                      0);

/* Firstly search the large memory tree */
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_lock(&mutex);
    if (ret)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_lock(): Failed to lock mutex, ret = %d \n",
                ret);

        return (UINT64)0;
    }
#endif
    if ((pMemInfo = userLargeMemLookupByVirtAddr(pVirtAddress)) != NULL)
    {
#ifndef ICP_WITHOUT_THREAD
        ret = pthread_mutex_unlock(&mutex);
        if (ret)
        {
            osalMemFreeNUMA(pMemInfo);
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "pthread_mutex_unlock(): Failed to unlock mutex, ret = "
                    "%d \n",
                    ret);

            return (UINT64)0;
        }
#endif
        return (UINT64)(pMemInfo->phy_addr + (UARCH_INT)pVirtAddress -
                        (UARCH_INT)pMemInfo->virt_addr);
    }
    pMemInfo = userMemLookupByVirtAddr(pVirtAddress);
#ifndef ICP_WITHOUT_THREAD
    ret = pthread_mutex_unlock(&mutex);
    if (ret)
    {
        if (NULL != pMemInfo)
        {
            osalMemFreeNUMA(pMemInfo);
        }
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "pthread_mutex_unlock(): Failed to unlock mutex, ret = %d \n",
                ret);

        return (UINT64)0;
    }
#endif
    if (NULL == pMemInfo)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "Invalid block address %p !\n",
                pVirtAddress);

        return (UINT64)0;
    }

    offset = (UARCH_INT)pVirtAddress - (UARCH_INT)(pMemInfo->virt_addr);
    phy_address = pMemInfo->phy_addr;

    return (UINT64)(phy_address + offset);
}

#ifndef ICP_WITHOUT_IOMMU
int osalIOMMUMap(UINT64 phaddr, UINT64 iova, size_t size)
{
    dev_iommu_info_t info = {phaddr, iova, size};
    return ioctl(fd, DEV_MEM_IOC_IOMMUMAP, &info);
}

int osalIOMMUUnmap(UINT64 iova, size_t size)
{
    dev_iommu_info_t info = {0, iova, size};
    return ioctl(fd, DEV_MEM_IOC_IOMMUUNMAP, &info);
}

UINT64 osalIOMMUVirtToPhys(UINT64 iova)
{
    dev_iommu_info_t info = {0, iova, 0};
    return (ioctl(fd, DEV_MEM_IOC_IOMMUVTOP, &info) == 0) ? info.phaddr : 0;
}

size_t osalIOMMUgetRemappingSize(size_t size)
{
    int pages = (size >> PAGE_SHIFT) + 1;
    size_t new_size = (pages * PAGE_SIZE);
    return new_size;
}
#else
int osalIOMMUMap(UINT64 phaddr, UINT64 iova, size_t size)
{
    return 0;
}

int osalIOMMUUnmap(UINT64 iova, size_t size)
{
    return 0;
}

UINT64 osalIOMMUVirtToPhys(UINT64 iova)
{
    return iova;
}

size_t osalIOMMUgetRemappingSize(size_t size)
{
    return size;
}
#endif
