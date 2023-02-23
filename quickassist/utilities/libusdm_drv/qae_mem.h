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
 ***************************************************************************
 * @file qae_mem.h
 *
 * This file provides linux/FreeBSD memory allocation for quick assist API
 *
 ****************************************************************************/
#ifndef QAE_MEM_H_
#define QAE_MEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *       qaeMemAlloc
 *
 * @brief
 *      When used in user space, allocates memsize bytes of virtual memory.
 *      When used in kernel space, allocates memsize bytes of contigous and
 *      pinned memory.
 *
 * @param[in] memsize - the amount of memory in bytes to be allocated
 *
 * @retval pointer to the allocated memory or NULL if the allocation failed
 *
 * @pre
 *      none
 * @post
 *      memory is allocated and the pointer to the allocated memory location
 *      is returned
 *
 ****************************************************************************/
void *qaeMemAlloc(size_t memsize);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeMemFree
 *
 * @brief
 *      Frees memory allocated by the qaeMemAlloc function.
 *      Applicable for both user and kernel spaces.
 *
 * @param[in] ptr - Address of the pointer to the memory to be freed
 *
 * @retval none
 *
 * @pre
 *      *ptr points to memory previously allocated by qaeMemAlloc
 * @post
 *      memory is freed and pointer value is set to NULL
 *
 ****************************************************************************/
void qaeMemFree(void **ptr);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeMemAllocNUMA
 *
 * @brief
 *      Allocates and returns virtual memory mapped to pinned, contiguous
 *      physical memory aligned to phys_alignment_byte. This API enables
 *      user to choose a CPU node nearest to QAT device. This API is applicable
 *      for both user and kernel spaces. Based on the address space used,
 *      memory mapped from corresponding virtual address space will be returned.
 *
 * @param[in] size - A non-zero value representing the amount of memory in
 *                   bytes to be allocated.It cannot exceed 4MB
 * @param[in] node - NUMA node
 * @param[in] phys_alignment_byte - A non-zero value representing memory
 *                                  boundary alignment in bytes. It must
 *                                  be in powers of 2 not exceeding 4MB.
 *
 * @retval pointer to the allocated memory or NULL if the allocation failed
 *
 * @pre
 *      none
 * @post
 *      memory is allocated and pointer to the allocated memory is returned
 *
 ****************************************************************************/
void *qaeMemAllocNUMA(size_t size, int node, size_t phys_alignment_byte);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeMemFreeNUMA
 *
 * @brief
 *      Frees memory allocated by the qaeMemAllocNUMA function.
 *      Applicable for both user and kernel spaces.
 *
 * @param[in] ptr - Address of pointer to the memory to be freed
 *
 * @retval none
 *
 * @pre
 *      *ptr points to memory previously allocated by qaeMemAllocNUMA
 * @post
 *      memory is freed and the pointer value is set to NULL
 *
 ****************************************************************************/
void qaeMemFreeNUMA(void **ptr);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeMemFreeNonZeroNUMA
 *
 * @brief
 *      Frees memory allocated by qaeMemAllocNUMA function.
 *      Does not clear the memory region before freeing unlike other API.
 *      Applicable for user space only.
 *
 * @param[in] ptr - Address of pointer to the memory to be freed
 *
 * @retval none
 *
 * @pre
 *      *ptr points to memory previously allocated by qaeMemAllocNUMA
 * @post
 *      memory is freed and the pointer value is set to NULL
 *
 ****************************************************************************/
void qaeMemFreeNonZeroNUMA(void **ptr);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeVirtToPhysNUMA
 *
 * @brief
 *      Converts a virtual address provided by qaeMemAllocNUMA to a
 *      physical one. Applicable for both user and kernel spaces.
 *
 * @param[in] pVirtAddr - pointer to the virtual address
 *
 * @retval pointer to the physical address or 0(NULL) on error
 *
 * @pre
 *      pVirtAddr points to  memory previously allocated by qaeMemAllocNUMA
 * @post
 *      Appropriate physical address is provided
 *
 ****************************************************************************/
uint64_t qaeVirtToPhysNUMA(void *pVirtAddr);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaePhysToVirtNUMA
 *
 * @brief
 *      Translates a physical address to a virtual one of a memory allocated
 *      by qaeMemAllocNUMA() function. Applicable for user space.
 *
 * @param[in] physAddress - physical address
 *
 * @retval pointer to the virtual address or 0 (NULL) on error
 *
 * @pre
 *      physAddress points to memory previously allocated by qaeMemAllocNUMA
 * @post
 *      Appropriate virtual address is provided
 *
 ****************************************************************************/
void *qaePhysToVirtNUMA(uint64_t physAddress);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeRegisterDevice
 *
 * @brief
 *      Registers a vfio device file descriptor
 *
 * @param[in] fd - file descriptor
 *
 * @retval  0 on success
 *
 * @pre
 *     none
 *
 * @post
 *
 ****************************************************************************/
int qaeRegisterDevice(int fd);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeUnregisterDevice
 *
 * @brief
 *      Unregisters a vfio device file descriptor
 *
 * @param[in] fd - file descriptor
 *
 * @retval  0 on success
 *
 * @pre
 *     none
 *
 * @post
 *
 ****************************************************************************/
int qaeUnregisterDevice(int fd);


#ifndef __KERNEL__
/*! Define a constant for user space to select any available NUMA node */
#define NUMA_ANY_NODE (-1)

/**
 ***************************************************************************
 * @ingroup CommonMemoryDriver
 *      qaeAtFork
 *
 * @brief
 *      Must be called when child process is forked to adjust the kernel
 *      memory map page.
 *
 * @param[in]  - none
 *
 * @retval none
 *
 ****************************************************************************/
void qaeAtFork(void);
#endif

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* #ifndef QAE_MEM_H_ */
