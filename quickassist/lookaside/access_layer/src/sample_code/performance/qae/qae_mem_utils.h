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
*****************************************************************************
* @file qae_mem_utils.h
*
* This file provides linux kernel memory allocation for quick assist API
*
*****************************************************************************/
#ifndef QAE_MEM_UTILS_H_
#define QAE_MEM_UTILS_H_
#include "cpa.h"

/*define types which need to vary between 32 and 64 bit*/
#ifdef __x86_64__
#define QAE_UINT Cpa64U
#define QAE_INT Cpa64S
#else
#define QAE_UINT Cpa32U
#define QAE_INT Cpa32S
#endif

#define QAE_PHYS_ADDR CpaPhysicalAddr

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      Framework aligned memory structure.
 * @description
 *      This structure is used to assist the framework in allocating aligned
 *      memory
 ****************************************************************************/
typedef struct qae_mem_alloc_info_s
{
    void *mAllocMemPtr; /* memory addr returned by the kernel */
    Cpa32U mSize;       /* allocated size */

} qae_mem_alloc_info_t;

/**
 *****************************************************************************
 * @ingroup qaeMemUtils
 *      user space memory info.
 * @description
 *      This structure is used to store info on aligned user space memory
 *      memory
 ****************************************************************************/
#pragma pack(push)
#pragma pack(1)
typedef struct dev_mem_info_s
{
    union {
        struct dev_mem_info_s *pPrev;
        uint64_t padding_pPrev;
    };
    union {
        struct dev_mem_info_s *pNext;
        uint64_t padding_pNext;
    };
    uint32_t id;
    /* Id of this block */
    uint32_t nodeId;
    /* Node id for NUMA */
    uint32_t size;
    /* Size of this block (bytes) */
    uint32_t available_size;
    /* Available size remained on the page */
    uint16_t allocations;
    /* Counter keeping track of number of allocations */
    union {
        void *kmalloc_ptr;
        uint64_t padding_kmalloc_ptr;
    };
    /* Pointer to mem originally returned by kmalloc */
    union {
        int32_t *kmalloc_area;
        uint64_t padding_kamalloc_area;
    };
    /* Pointer to kmalloc'd area rounded up to a page boundary */
    uint64_t phy_addr;
    /* Physical address of the kmalloced area */
    union {
        void *virt_addr;
        uint64_t padding_virt_addr;
    };
    /* Base address in user space - i.e. virtual address */
} dev_mem_info_t;
#pragma pack(pop)

/**
 *****************************************************************************
 * @ingroup qaeMemUtils
 *      array structure
 * @description
 *      This structure is used to copy chunks of data read from files
 *      from user to kernel space
 ****************************************************************************/
typedef struct dev_mem_file_s
{
    unsigned char data[2048];
    unsigned int size;
} dev_mem_file_t;

/**
 *****************************************************************************
 * @ingroup qaeMemUtils
 *      user space memory list pointer structure.
 * @description
 *      This structure is used to assist in allocating aligned
 *      memory
 ****************************************************************************/
typedef struct user_proc_mem_list_s
{
    unsigned int pid;
    unsigned int allocs_nr;
    unsigned int max_id;
    dev_mem_info_t *freed_head;
    dev_mem_info_t *freed_tail;
    dev_mem_info_t *head;
    dev_mem_info_t *tail;
    struct user_proc_mem_list_s *pPrev;
    struct user_proc_mem_list_s *pNext;
} user_proc_mem_list_t;

/**
 *****************************************************************************
 * @ingroup qaeMemUtils
 *      user space memory list pointer structure.
 * @description
 *      This structure is used to assist in allocating aligned
 *      memory
 ****************************************************************************/
typedef struct user_mem_dev_s
{
    user_proc_mem_list_t *head;
    user_proc_mem_list_t *tail;
} user_mem_dev_t;

#define ENSURE_NOT_NULL(ptr, str, status)                                      \
                                                                               \
    do                                                                         \
    {                                                                          \
        if (ptr == NULL)                                                       \
        {                                                                      \
            printk("%s\n", str);                                               \
            return status;                                                     \
        }                                                                      \
                                                                               \
    } while (0);

#define ENSURE_NOT_NULL_RETURN_VOID(ptr, str)                                  \
    do                                                                         \
    {                                                                          \
        if (ptr == NULL)                                                       \
        {                                                                      \
            printk("%s\n", str);                                               \
            return;                                                            \
        }                                                                      \
    } while (0);

#define ADD_ELEMENT_TO_END_OF_LIST(elementtoadd, currentptr, headptr)          \
    do                                                                         \
    {                                                                          \
        if (NULL == currentptr)                                                \
        {                                                                      \
            currentptr = elementtoadd;                                         \
            elementtoadd->pNext = NULL;                                        \
            elementtoadd->pPrev = NULL;                                        \
            headptr = currentptr;                                              \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            elementtoadd->pPrev = currentptr;                                  \
            currentptr->pNext = elementtoadd;                                  \
            elementtoadd->pNext = NULL;                                        \
            currentptr = elementtoadd;                                         \
        }                                                                      \
    } while (0);

#define REMOVE_ELEMENT_FROM_LIST(elementtoremove, currentptr, headptr)         \
    do                                                                         \
    {                                                                          \
        /*If the previous pointer is not NULL*/                                \
        if (NULL != elementtoremove->pPrev)                                    \
        {                                                                      \
            elementtoremove->pPrev->pNext = elementtoremove->pNext;            \
            if (elementtoremove->pNext)                                        \
            {                                                                  \
                elementtoremove->pNext->pPrev = elementtoremove->pPrev;        \
            }                                                                  \
            else                                                               \
            {                                                                  \
                currentptr = elementtoremove->pPrev;                           \
            }                                                                  \
        }                                                                      \
        else if (NULL != elementtoremove->pNext)                               \
        {                                                                      \
            elementtoremove->pNext->pPrev = NULL;                              \
            headptr = elementtoremove->pNext;                                  \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            currentptr = NULL;                                                 \
            headptr = NULL;                                                    \
        }                                                                      \
    } while (0)

/* IOCTL number for use between the kernel and the user space application */
#define DEV_MEM_MAGIC 'q'
#define DEV_MEM_CMD_MEMALLOC (0)
#define DEV_MEM_CMD_MEMFREE (1)
#define DEV_MEM_CMD_CORPUS (2)

/* IOCTL commands for requesting kernel memory */
#define DEV_MEM_IOC_MEMALLOC                                                   \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMALLOC, dev_mem_info_t)

#define DEV_MEM_IOC_MEMFREE                                                    \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMFREE, dev_mem_info_t)

#define DEV_MEM_IOC_CORPUS                                                     \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_CORPUS, dev_mem_file_t)

#ifdef BLOCKOUT
dev_mem_info_t *userMemAlloc(user_mem_dev_t *dev,
                             Cpa32U sizeInBytes,
                             Cpa32U node,
                             Cpa32U pid);
dev_mem_info_t *userMemGetInfo(user_mem_dev_t *dev, Cpa32U id, Cpa32U pid);
void userMemFree(user_mem_dev_t *dev, Cpa32U id, Cpa32U pid);

void userMemFreeAllPid(user_mem_dev_t *dev, Cpa32U pid);
void userMemFreeAll(user_mem_dev_t *dev);
#endif
/**
 *****************************************************************************
 * @ingroup quicksssistExtension_MemoryManagement
 *      qaeMemAlloc
 *
 * @description
 *      allocates memsize bytes of memory
 *
 *
 * @param[in] memsize, the amount of memory in bytes to be allocated
 *
 * @retval pointer to the allocated memory
 *
 * @pre
 *      none
 * @post
 *      memory is allocated
 *
 *****************************************************************************/
void *qaeMemAlloc(Cpa32U memsize);

/**
 *****************************************************************************
 * @ingroup quicksssistExtension_MemoryManagement
 *      qaeMemAllocNUMA
 *
 * @description
 *      allocates contiguous memory local to the cpu(node) of memsize bytes
 *
 *
 * @param[in] memsize, the amount of memory in bytes to be allocated
 *
 * @retval pointer to the allocated memory
 *
 * @pre
 *      none
 * @post
 *      memory is allocated
 *
 *****************************************************************************/
void *qaeMemAllocNUMA(Cpa32U size, Cpa32U node, Cpa32U alignment);

/**
 *****************************************************************************
 * @ingroup quicksssistExtension_MemoryManagement
 *      qaeVirtToPhysNUMA
 *
 * @description
 *      Converts a virtual address to a physical one
 *
 *
 * @param[in] pVirtAddr pointer to the virtual address
 *
 * @retval pointer to the physical address
 *
 * @pre
 *      none
 * @post
 *      memory is allocated
 *
 *****************************************************************************/

QAE_PHYS_ADDR qaeVirtToPhysNUMA(void *pVirtAddr);
/**
 *****************************************************************************
 * @ingroup quicksssistExtension_MemoryManagement
 *      qaeMemFreeNUMA
 *
 * @description
 *      frees memory allocated by the qaeMemAllocNUMA function
 *
 *
 * @param[in] pointer to the memory to be freed
 *
 * @retval none
 *
 * @pre
 *      none
 * @post
 *      memory is freed
 *
 *****************************************************************************/
void qaeMemFreeNUMA(void **ptr);

/**
 *****************************************************************************
 * @ingroup quicksssistExtension_MemoryManagement
 *      qaeMemFree
 *
 * @description
 *      frees memory allocated by the qaeMemAlloc function
 *
 *
 * @param[in] pointer to the memory to be freed
 *
 * @retval none
 *
 * @pre
 *      none
 * @post
 *      memory is freed
 *
 *****************************************************************************/
void qaeMemFree(void **ptr);

void printMemAllocations(void);

#endif
