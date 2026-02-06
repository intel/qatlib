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
* This file provides linux kernel memory allocation for quick assist API
*
*****************************************************************************/

#include "qae_mem_utils.h"
#ifdef SAL_IOMMU_CODE
#include <icp_sal_iommu.h>
#endif
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/io.h>

/* Maximum memory can be allocated by kmalloc*/
#define QAE_MEM_SIZE_LIMIT (1024 * 4096)

/* return amount of padding based on padSize a and alignment b*/
#define MEM_PADDING(a, b) ((b - (a % b)) % b)

#define IS_VMALLOC_ADDR(addr)                                                  \
    (((QAE_UINT)(addr) >= VMALLOC_START) && ((QAE_UINT)(addr) < VMALLOC_END))

Cpa32U numaAllocations_g = 0;
Cpa32U normalAllocations_g = 0;

/**************************************
 * Memory functions
 *************************************/
void *qaeMemAlloc(Cpa32U memsize)
{
    if (memsize > QAE_MEM_SIZE_LIMIT)
    {
        return (vmalloc(memsize));
    }
    normalAllocations_g++;
    return (kmalloc(memsize, GFP_KERNEL));
}

void *qaeMemAllocNUMA(Cpa32U size, Cpa32U node, Cpa32U alignment)
{
    void *ptr = NULL;
    uint64_t phys_ptr = 0;
    void *pRet = NULL;
    Cpa32U alignment_offset = 0;

    qae_mem_alloc_info_t memInfo = {0};

    if (size == 0 || alignment < 1)
    {
        printk(" size or alignment are zero \n");
        return NULL;
    }
    /*alignment should be 1,2,4,8....*/
    if (alignment & (alignment - 1))
    {
        printk("Expecting alignment of a power of \
                two but did not get one\n");
        return NULL;
    }

    // add the alignment and the struct size to the buffer size
    memInfo.mSize = size + alignment + sizeof(qae_mem_alloc_info_t);
#ifdef SAL_IOMMU_CODE
    memInfo.mSize = icp_sal_iommu_get_remap_size(memInfo.mSize);
#endif

    /*allocate contiguous memory*/
    ptr = kmalloc_node(memInfo.mSize, GFP_KERNEL, node);

    if (ptr == NULL)
    {
        printk("failed to allocate memory\n");
        return NULL;
    }

    // store the base address into the struct
    memInfo.mAllocMemPtr = ptr;
    phys_ptr = virt_to_phys(ptr);
#ifdef SAL_IOMMU_CODE
    if (icp_sal_iommu_map(phys_ptr, phys_ptr, memInfo.mSize))
    {
        printk("failed to iommu remap\n");
        kfree(ptr);
        return NULL;
    }
#endif
    // add the size of the struct to the return pointer
    pRet = (char *)memInfo.mAllocMemPtr + sizeof(qae_mem_alloc_info_t);
    // compute the offset from the lignement
    alignment_offset = (QAE_UINT)pRet % alignment;
    // in order to obtain the pointer to the buffer add the alignment and
    // subtract the offset, now we have the return pointer aligned
    pRet = (char *)pRet + (alignment - alignment_offset);
    // copy the struct immediately before the buffer pointer
    memcpy((void *)((char *)pRet - sizeof(qae_mem_alloc_info_t)),
           (void *)(&memInfo),
           sizeof(qae_mem_alloc_info_t));
    // increment the NUMA allocations counter
    numaAllocations_g++;

    return pRet;
}

void qaeMemFreeNUMA(void **ptr)
{
    qae_mem_alloc_info_t *memInfo = NULL;
    if (ptr == NULL || *ptr == NULL)
    {
        return;
    }
    memInfo =
        (qae_mem_alloc_info_t *)((Cpa8S *)*ptr - sizeof(qae_mem_alloc_info_t));

    if (memInfo->mSize == 0 || memInfo->mAllocMemPtr == NULL)
    {
        printk("Detected the corrupted data: memory leak!\n");
        printk("Size: %d, memPtr: %p\n", memInfo->mSize, memInfo->mAllocMemPtr);
        return;
    }
#ifdef SAL_IOMMU_CODE
    if (icp_sal_iommu_unmap(virt_to_phys(memInfo->mAllocMemPtr),
                            memInfo->mSize))
    {
        printk("failed to iommu unmap\n");
    }
#endif
    kfree(memInfo->mAllocMemPtr);
    numaAllocations_g--;
    *ptr = NULL;
}

void qaeMemFree(void **ptr)
{
    if (ptr == NULL || *ptr == NULL)
    {
        return;
    }
    if (IS_VMALLOC_ADDR(*ptr))
    {
        vfree(*ptr);
        return;
    }
    kfree(*ptr);
    normalAllocations_g--;
    *ptr = NULL;
}

QAE_PHYS_ADDR qaeVirtToPhysNUMA(void *ptr)
{
    return (QAE_PHYS_ADDR)(QAE_UINT)virt_to_phys(ptr);
}

void printMemAllocations()
{
    printk("NUMA Allocations %d\n", numaAllocations_g);
    printk("Normal Allocations %d\n", normalAllocations_g);
}
