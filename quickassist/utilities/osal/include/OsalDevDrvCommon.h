/**
 * @file OsalDevDrvCommon.h
 *
 * @brief Common device driver and macro types
 *
 *
 * @par
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 */

#ifndef OSAL_DEV_DRV_COMMON_H
#define OSAL_DEV_DRV_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "OsalOsTypes.h"
#pragma pack(push) /* Push the current alignment on the stack */
#pragma pack(1)    /* Force alignment on 1 byte to support 32                  \
                      bits user space on 64 bits kernels */
/* Number of allocated pages for memory managements
 * For kernel which can allocate 4M, then value can be 512
 * So that the performance can be improved
 * For legacy old kernel, the value can be 32, that is 128k
 */
#ifndef ICP_NUM_PAGES_PER_ALLOC
#ifndef ICP_SRIOV
#define NUM_PAGES_PER_ALLOC 512
#else
#define NUM_PAGES_PER_ALLOC 256
#endif
#else
#define NUM_PAGES_PER_ALLOC 32
#endif
#define DOUBLE_NUM_PAGES_PER_ALLOC (0x2 * NUM_PAGES_PER_ALLOC)

/* magic used to identify double length
 * Need to bigger than 2 of ICP_NUM_PAGES_PER_ALLOC
 * The reason is that we will mmap 2*ICP_NUM_PAGES_PER_ALLOC
 * to achieve page alignment, and this macro is used when
 * user really wants to mmap 2*ICP_NUM_PAGES_PER_ALLOC pages
 */
#define ICP_MMAP_DOUBLE_NUM_PAGES 2048

typedef struct dev_mem_info_s
{
    uint32_t id;
    /* Id of this block */
    uint32_t nodeId;
    /* Node id for NUMA */
    uint32_t size;
    /* Size of this block (bytes) */
    uint32_t mmap_size;
    /* Size used to call mmap (bytes) */
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
        uint64_t padding_kmalloc_area;
    };
    /* Pointer to kmalloc'd area rounded up to a page boundary */
    UINT64 phy_addr;
    /* Physical address of the kmalloced area */
    union {
        void *virt_addr;
        uint64_t padding_virt_addr;
    };
    /* Base address in user space - i.e. virtual address */
    union {
        void *fvirt_addr;
        uint64_t padding_fvirt_addr;
    };
    /* virtual address return from mmap, and it is saved for munmap*/
    /* Please be noted that padding should be used to make the same
       structure size for both 32 bit and 64 bit
     */
    union {
        struct dev_mem_info_s *pPrev;
        uint64_t padding_pPrev;
    };
    union {
        struct dev_mem_info_s *pNext;
        uint64_t padding_pNext;
    };
} dev_mem_info_t;

typedef struct dev_iommu_info_s
{
    uint64_t phaddr;
    uint64_t iova;
    uint64_t size;
} dev_iommu_info_t;
#pragma pack(pop) /* Restore Previous alignment */

typedef struct user_proc_mem_list_s
{
    uint32_t pid;
    uint32_t allocs_nr;
    uint32_t max_id;
    dev_mem_info_t *freed_head;
    dev_mem_info_t *freed_tail;
    dev_mem_info_t *head;
    dev_mem_info_t *tail;
    struct user_proc_mem_list_s *pPrev;
    struct user_proc_mem_list_s *pNext;
} user_proc_mem_list_t;

typedef struct user_mem_dev_s
{
    user_proc_mem_list_t *head;
    user_proc_mem_list_t *tail;
} user_mem_dev_t;

#define ADD_ELEMENT_TO_HEAD_OF_LIST(elementtoadd, currentptr, headptr)         \
    do                                                                         \
    {                                                                          \
        if (NULL == currentptr)                                                \
        {                                                                      \
            currentptr = elementtoadd;                                         \
            elementtoadd->pNext = NULL;                                        \
            elementtoadd->pPrev = NULL;                                        \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            elementtoadd->pNext = headptr;                                     \
            elementtoadd->pPrev = NULL;                                        \
            headptr->pPrev = elementtoadd;                                     \
        }                                                                      \
        headptr = elementtoadd;                                                \
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
#define DEV_MEM_MAGIC 'm'
#define DEV_MEM_CMD_MEMALLOC (0)
#define DEV_MEM_CMD_MEMFREE (1)
#define DEV_MEM_CMD_IOMMUMAP (2)
#define DEV_MEM_CMD_IOMMUUNMAP (3)
#define DEV_MEM_CMD_IOMMUVTOP (4)

/* IOCTL commands for requesting kernel memory */
#define DEV_MEM_IOC_MEMALLOC                                                   \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMALLOC, dev_mem_info_t)

#define DEV_MEM_IOC_MEMFREE                                                    \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMFREE, dev_mem_info_t)

#define DEV_MEM_IOC_IOMMUMAP                                                   \
    _IOR(DEV_MEM_MAGIC, DEV_MEM_CMD_IOMMUMAP, dev_iommu_info_t)

#define DEV_MEM_IOC_IOMMUUNMAP                                                 \
    _IOR(DEV_MEM_MAGIC, DEV_MEM_CMD_IOMMUUNMAP, dev_iommu_info_t)

#define DEV_MEM_IOC_IOMMUVTOP                                                  \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_IOMMUVTOP, dev_iommu_info_t)

/* IOCTL number for use between the kernel and the user space application */
#define DEV_MEM_MAGIC_PAGE 'p'
#define DEV_MEM_CMD_MEMALLOCPAGE (0)
#define DEV_MEM_CMD_MEMFREEPAGE (1)

/* IOCTL commands for requesting kernel memory */
#define DEV_MEM_IOC_MEMALLOCPAGE                                               \
    _IOWR(DEV_MEM_MAGIC_PAGE, DEV_MEM_CMD_MEMALLOCPAGE, dev_mem_info_t)

#define DEV_MEM_IOC_MEMFREEPAGE                                                \
    _IOWR(DEV_MEM_MAGIC_PAGE, DEV_MEM_CMD_MEMFREEPAGE, dev_mem_info_t)

#define DEV_PATH_SIZE 60
#define DEV_NAME_SIZE 20
#define OS_DEV_DIRECTORY "/dev/"
#define DEV_MEM_NAME "icp_dev_mem"
#define DEV_MEM_NAME_PAGE "icp_dev_mem_page"
#define DEV_MEM_PATH "/dev/icp_dev_mem"
#define DEV_MEM_PAGE_PATH "/dev/icp_dev_mem_page"
/**
 *******************************************************************************
 * @ingroup Osal
 *
 * @brief  This macro checks if a parameter is within a specified range
 *
 * @param[in] param                 Parameter
 * @param[in] min                   Parameter must be greater than OR equal to
 *                                  min
 * @param[in] max                   Parameter must be less than max
 *
 * @return OSAL_FAIL                Parameter is outside range
 * @return void                     Parameter is within range
 ******************************************************************************/
#define OSAL_CHECK_PARAM_RANGE(param, min, max)                                \
    do                                                                         \
    {                                                                          \
        if (((param) < (min)) || ((param) >= (max)))                           \
        {                                                                      \
            osalLog(OSAL_LOG_LVL_WARNING,                                      \
                    OSAL_LOG_DEV_STDOUT,                                       \
                    "param is outside valid range\n");                         \
            return OSAL_FAIL;                                                  \
        }                                                                      \
    } while (0)

dev_mem_info_t *userMemAlloc(user_mem_dev_t *dev,
                             UINT32 sizeInBytes,
                             UINT32 node,
                             UINT32 pid);
dev_mem_info_t *userMemGetInfo(user_mem_dev_t *dev, UINT32 id, UINT32 pid);
void userMemFree(user_mem_dev_t *dev, UINT32 id, UINT32 pid);

dev_mem_info_t *userMemAllocPage(user_mem_dev_t *dev, UINT32 node, UINT32 pid);
dev_mem_info_t *userMemGetInfoPage(user_mem_dev_t *dev, UINT32 id, UINT32 pid);
void userMemFreePage(user_mem_dev_t *dev, UINT32 id, UINT32 pid);

void userMemFreeAllPid(user_mem_dev_t *dev, UINT32 pid);
void userMemFreeAll(user_mem_dev_t *dev);
void userMemFreeAllPagePid(user_mem_dev_t *dev, UINT32 pid);
void userMemFreeAllPage(user_mem_dev_t *dev);

#ifdef __cplusplus
}
#endif
#endif
