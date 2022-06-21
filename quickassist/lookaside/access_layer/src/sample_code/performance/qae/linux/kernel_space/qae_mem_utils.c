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
        printk("Detected the corrupted data: memory leak!! \n");
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
