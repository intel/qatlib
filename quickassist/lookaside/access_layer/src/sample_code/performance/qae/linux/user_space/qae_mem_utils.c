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
 *****************************************************************************
 * @file qae_mem_utils.c
 *
 * This file provides provide for Linux user space memory allocation. It uses
 * a driver that allocates the memory in kernel memory space (to ensure
 * physically contiguous memory) and maps it to
 * user space for use by the  quick assist sample code
 *
 *****************************************************************************/

#include "qae_mem.h"

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
#include <pthread.h>
#ifdef SAL_IOMMU_CODE
#include <icp_sal_iommu.h>
#endif

#define QAE_MEM "/dev/usdm_drv"
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define USER_MEM_128BYTE_OFFSET (128)
#define MAGIC_NUM 0xABCD12345678ECDFUL

static pthread_mutex_t mutex_g = PTHREAD_MUTEX_INITIALIZER;
static qae_dev_mem_info_t *pUserMemList = NULL;
static qae_dev_mem_info_t *pUserMemListHead = NULL;

static int fd = 0;

/**************************************
 * Memory functions
 *************************************/
CpaStatus qaeMemInit(void)
{
    fd = open(QAE_MEM, O_RDWR);
    if (fd < 0)
    {
        printf("unable to open %s %d\n", QAE_MEM, fd);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

void qaeMemDestroy(void)
{
    close(fd);
}

void *qaeMemAlloc(Cpa32U memsize)
{
    QAE_UINT *memPtr = NULL;
    memPtr = malloc(memsize);
    return memPtr;
}

static CpaStatus userMemListAdd(qae_dev_mem_info_t *pMemInfo)
{
    int ret = 0;
    ret = pthread_mutex_lock(&mutex_g);
    if (0 != ret)
    {
        printf("Error(%d) on thread mutex lock\n", ret);
        return CPA_STATUS_FAIL;
    }
    ADD_ELEMENT_TO_END_OF_LIST(pMemInfo, pUserMemList, pUserMemListHead);
    ret = pthread_mutex_unlock(&mutex_g);
    if (0 != ret)
    {
        printf("Error(%d) on thread mutex unlock\n", ret);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

static void userMemListFree(qae_dev_mem_info_t *pMemInfo)
{
    qae_dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if (pCurr == pMemInfo)
        {
            REMOVE_ELEMENT_FROM_LIST(pCurr, pUserMemList, pUserMemListHead);
            break;
        }
    }
}

static qae_dev_mem_info_t *userMemLookupBySize(Cpa32U size)
{
    qae_dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if (pCurr->available_size >= size)
        {
            return pCurr;
        }
    }
    return NULL;
}

static qae_dev_mem_info_t *userMemLookupByVirtAddr(void *virt_addr)
{
    qae_dev_mem_info_t *pCurr = NULL;

    for (pCurr = pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext)
    {
        if ((QAE_UINT)pCurr->virt_addr <= (QAE_UINT)virt_addr &&
            ((QAE_UINT)pCurr->virt_addr + pCurr->size) > (QAE_UINT)virt_addr)
        {
            return pCurr;
        }
    }
    return NULL;
}

void *qaeMemAllocNUMA(Cpa32U size, Cpa32U node, Cpa32U alignment)
{
    int ret = 0;
    qae_dev_mem_info_t *pMemInfo = NULL;
    void *pVirtAddress = NULL;
    void *pOriginalAddress = NULL;
    QAE_UINT padding = 0;
    QAE_UINT aligned_address = 0;
    uint64_t magic = MAGIC_NUM;

    if (size == 0 || alignment == 0)
    {
        printf("Invalid size or alignment parameter\n");
        return NULL;
    }
    if (fd < 0)
    {
        printf("Memory file handle is not ready\n");
        return NULL;
    }

    ret = pthread_mutex_lock(&mutex_g);
    if (0 != ret)
    {
        printf("Error(%d) on thread mutex lock\n", ret);
        return NULL;
    }

    if ((pMemInfo = userMemLookupBySize(size + alignment)) != NULL)
    {
        pOriginalAddress =
            (void *)((QAE_UINT)pMemInfo->virt_addr +
                     (QAE_UINT)(pMemInfo->size - pMemInfo->available_size));
        padding = (QAE_UINT)pOriginalAddress % alignment;
        aligned_address = ((QAE_UINT)pOriginalAddress) - padding + alignment;
        pMemInfo->available_size -=
            (size + (aligned_address - (QAE_UINT)pOriginalAddress));
        pMemInfo->allocations += 1;
        ret = pthread_mutex_unlock(&mutex_g);
        if (0 != ret)
        {
            printf("Error(%d) on thread mutex lock\n", ret);
            return NULL;
        }
        return (void *)aligned_address;
    }
    pMemInfo = malloc(sizeof(qae_dev_mem_info_t));
    if (NULL == pMemInfo)
    {
        printf("unable to allocate pMemInfo buffer\n");
        pthread_mutex_unlock(&mutex_g);
        return NULL;
    }

    pMemInfo->allocations = 0;

    pMemInfo->size = USER_MEM_128BYTE_OFFSET + size;
    pMemInfo->size = pMemInfo->size % PAGE_SIZE
                         ? ((pMemInfo->size / PAGE_SIZE) + 1) * PAGE_SIZE
                         : pMemInfo->size;
#ifdef SAL_IOMMU_CODE
    pMemInfo->size = icp_sal_iommu_get_remap_size(pMemInfo->size);
#endif
    pMemInfo->nodeId = node;
    ret = ioctl(fd, DEV_MEM_IOC_MEMALLOC, pMemInfo);
    if (ret != 0)
    {
        printf("ioctl call failed, ret = %d\n", ret);
        free(pMemInfo);
        pthread_mutex_unlock(&mutex_g);
        return NULL;
    }

    pMemInfo->virt_addr = mmap((caddr_t)0,
                               pMemInfo->size,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED,
                               fd,
                               (pMemInfo->id * getpagesize()));

    if (pMemInfo->virt_addr == (caddr_t)MAP_FAILED)
    {
        printf("mmap failed\n");
        ret = ioctl(fd, DEV_MEM_IOC_MEMFREE, pMemInfo);
        if (ret != 0)
        {
            printf("ioctl call failed, ret = %d\n", ret);
        }
        free(pMemInfo);
        pthread_mutex_unlock(&mutex_g);
        return NULL;
    }
    pMemInfo->available_size = pMemInfo->size - size - USER_MEM_128BYTE_OFFSET;
    pMemInfo->allocations = 1;
    memcpy(pMemInfo->virt_addr, pMemInfo, sizeof(qae_dev_mem_info_t));
    memcpy(pMemInfo->virt_addr, &magic, sizeof(uint64_t));
    pVirtAddress =
        (void *)((QAE_UINT)pMemInfo->virt_addr + USER_MEM_128BYTE_OFFSET);
    /* Free mutex as lock is re-acquired in userMemListAdd */
    pthread_mutex_unlock(&mutex_g);
    if (CPA_STATUS_SUCCESS != userMemListAdd(pMemInfo))
    {
        printf("Error on mem list add\n");
        return NULL;
    }
    return pVirtAddress;
}

void qaeMemFreeNUMA(void **ptr)
{
    int ret = 0;
    qae_dev_mem_info_t *pMemInfo = NULL;
    void *pVirtAddress = NULL;

    if (NULL == ptr)
    {
        printf("Invalid virtual address\n");
        return;
    }
    pVirtAddress = *ptr;
    if (pVirtAddress == NULL)
    {
        printf("Invalid virtual address\n");
        return;
    }
    ret = pthread_mutex_lock(&mutex_g);
    if (0 != ret)
    {
        printf("Error(%d) on thread mutex lock\n", ret);
        return;
    }
    if ((pMemInfo = userMemLookupByVirtAddr(pVirtAddress)) != NULL)
    {
        pMemInfo->allocations -= 1;
        if (pMemInfo->allocations != 0)
        {
            *ptr = NULL;
            ret = pthread_mutex_unlock(&mutex_g);
            if (0 != ret)
            {
                printf("Error(%d) on thread mutex unlock\n", ret);
                return;
            }
            return;
        }
    }
    else
    {
        printf("userMemLookupByVirtAddr failed\n");
        ret = pthread_mutex_unlock(&mutex_g);
        if (0 != ret)
        {
            printf("Error(%d) on thread mutex unlock\n", ret);
            return;
        }
        return;
    }

    ret = munmap(pMemInfo->virt_addr, pMemInfo->size);
    if (ret != 0)
    {
        printf("munmap failed, ret = %d\n", ret);
    }

    ret = ioctl(fd, DEV_MEM_IOC_MEMFREE, pMemInfo);
    if (ret != 0)
    {
        printf("ioctl call failed, ret = %d\n", ret);
    }
    userMemListFree(pMemInfo);
    free(pMemInfo);
    *ptr = NULL;
    ret = pthread_mutex_unlock(&mutex_g);
    if (0 != ret)
    {
        printf("Error(%d) on thread mutex lock\n", ret);
        return;
    }
    return;
}

void qaeMemFree(void **ptr)
{
    if (NULL == ptr || NULL == *ptr)
    {
        printf("ERROR, Trying to Free NULL Pointer\n");
        return;
    }
    free(*ptr);
    *ptr = NULL;
}

/* NEW_1_4_CODE_WITH_MAGIC causes a
 * performance penalty. The #else code can cause
 * instability if used for a prolonged period.
 *
 * If you want stability with less performance then comment in the
 * NEW_1_4_CODE_WITH_MAGIC*/

#define NEW_1_4_CODE_WITH_MAGIC
#ifdef NEW_1_4_CODE_WITH_MAGIC
/*run less performance more stable virt2Phys function*/
QAE_PHYS_ADDR qaeVirtToPhysNUMA(void *pVirtAddress)
{
    qae_dev_mem_info_t *pMemInfo = NULL;
    void *pVirtPageAddress = NULL;
    QAE_UINT offset = 0;
    uint64_t *magic;

    if (pVirtAddress == NULL)
    {
        printf("qaeVirtToPhysNUMA():   Null virtual address pointer\n");
        return (QAE_PHYS_ADDR)0;
    }
    pVirtPageAddress = ((int *)((((QAE_UINT)pVirtAddress)) & (PAGE_MASK)));

    offset = (QAE_UINT)pVirtAddress - (QAE_UINT)pVirtPageAddress;
    do
    {
        pMemInfo = (qae_dev_mem_info_t *)pVirtPageAddress;
        magic = (uint64_t *)pMemInfo;
        if ((MAGIC_NUM == *magic) && (pMemInfo->virt_addr == pVirtPageAddress))
        {
            break;
        }
        pVirtPageAddress = (void *)((QAE_UINT)pVirtPageAddress - PAGE_SIZE);

        offset += PAGE_SIZE;
    } while (pMemInfo->virt_addr != pVirtPageAddress);
    return (QAE_PHYS_ADDR)(pMemInfo->phy_addr + offset);
}
#else
/*run higher performance vitr2Phys function, also could cause memory
 * corruption*/
QAE_PHYS_ADDR qaeVirtToPhysNUMA(void *pVirtAddress)
{
    qae_dev_mem_info_t *pMemInfo = NULL;
    void *pVirtPageAddress = NULL;
    QAE_UINT offset = 0;
    if (pVirtAddress == NULL)
    {
        printf("qaeVirtToPhysNUMA():   Null virtual address pointer\n");
        return (QAE_PHYS_ADDR)0;
    }

    pVirtPageAddress = ((int *)((((QAE_UINT)pVirtAddress)) & (PAGE_MASK)));

    offset = (QAE_UINT)pVirtAddress - (QAE_UINT)pVirtPageAddress;

    do
    {
        pMemInfo = (qae_dev_mem_info_t *)pVirtPageAddress;
        if (pMemInfo->virt_addr == pVirtPageAddress)
        {
            break;
        }
        pVirtPageAddress = (void *)((QAE_UINT)pVirtPageAddress - PAGE_SIZE);

        offset += PAGE_SIZE;
    } while (pMemInfo->virt_addr != pVirtPageAddress);
    return (QAE_PHYS_ADDR)(pMemInfo->phy_addr + offset);
}
#endif
