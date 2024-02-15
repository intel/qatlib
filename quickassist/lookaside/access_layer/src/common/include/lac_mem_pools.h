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
 * @file lac_mem_pools.h
 *
 * @defgroup LacMemPool     Memory Pool Mgmt
 *
 * @ingroup LacCommon
 *
 * Memory Pool creation and mgmt functions
 *
 * @lld_start
 * @lld_overview
 *     This component is designed as a set of utility functions for the
 * creation of pre-allocated memory pools. Each pool will be created using OS
 * memory with a user specified number of elements, element size and element
 * alignment(alignment is at byte granularity).
 * @lld_dependencies
 *     These utilities rely on OSAL for locking mechanisms and memory allocation
 * @lld_initialisation
 *     Pool creation needs to be done by each component. There is no specific
 * initialisation required for this feature.
 * @lld_module_algorithms
 *     The following is a diagram of how the memory is laid out for each block
 * in a pool. Each element must be aligned on the boundary requested for in the
 * create call.  In order to hide the management of the pools from the user,
 * the memory block data is hidden prior to the
 * data pointer. This way it can be accessed easily on a free call with pointer
 * arithmetic. The Padding at the start is simply there for alignment and is
 * unused in the pools.
 *
 *   -------------------------------------------------------
 *
 *   |Padding  |lac_mem_blk_t |        client memory       |
 *
 * @lld_process_context
 * @lld_end
 ***************************************************************************/

/**
 *******************************************************************************
 * @ingroup LacMemPool
 *
 *
 ******************************************************************************/

/***************************************************************************/

#ifndef LAC_MEM_POOLS_H
#define LAC_MEM_POOLS_H

#include "cpa.h"
#include "lac_common.h"

#ifdef __LP64__
typedef unsigned int atomic_int __attribute__((mode(TI)));
#else
typedef unsigned int atomic_int __attribute__((mode(DI)));
#endif

typedef union {
    struct
    {
        unsigned long ctr;
        void *ptr;
    };
    atomic_int atomic;
} pointer_t;

typedef struct
{
    volatile pointer_t top;
} lock_free_stack_t;

typedef LAC_ARCH_UINT lac_memory_pool_id_t;
/**< @ingroup LacMemPool
 *   Pool ID type to be used by all clients */

/**< @ingroup LacMemPool
 *     This structure is used to link each memory block in the created pool
 *     together and contain the necessary information for deletion of the block
 */
typedef struct lac_mem_blk_s
{
    struct lac_mem_blk_s *pNext;
    /**< link to next block in the pool */
    CpaPhysicalAddr physDataPtr;
    /**< physical address of data pointer for client */
    void *pMemAllocPtr;
    /**<  virtual address of the memory block actually allocated */
    CpaBoolean isInUse;
    /**< indicates if the pool item is in use */
    struct lac_mem_pool_hdr_s *pPoolID;
    /**< identifier of the pool that this block was allocated from */
    Cpa64U opaque;
    /**< opaque data */
} lac_mem_blk_t;

typedef struct lac_memblk_bucket_s
{
    lac_mem_blk_t **mem_blk;
    Cpa32U startIndex;
    /**< records the start index of the array */
    Cpa32U numBucketBlks;
    /**< the number of used memblk */
    Cpa32U numBlksInRing;
    /**< the number of memblk which has been put in the ring */
} lac_memblk_bucket_t;

#define LAC_MEM_POOLS_NAME_SIZE 16
/**< @ingroup LacMemPool
 * 16 bytes including '\\0' terminator to prevent padding in the structure */

/**< @ingroup LacMemPool
 *     This structure is used to manage each pool created using this utility
 * feature. The client will maintain a pointer (identifier) to the created
 * structure per pool.
 */
typedef struct lac_mem_pool_hdr_s
{
    lock_free_stack_t stack;
    char poolName[LAC_MEM_POOLS_NAME_SIZE]; /*16 bytes of a pool name */
    /**< up to 16 bytes of a pool name */
    unsigned int numElementsInPool;
    /**< number of elements in the Pool */
    unsigned int blkSizeInBytes;
    /**< Block size in bytes */
    unsigned int blkAlignmentInBytes;
    /**< block alignment in bytes */
    lac_mem_blk_t **trackBlks;
    /* An array of mem block pointers to track the allocated entries in pool */
    volatile size_t availBlks;
    /* Number of blocks available for allocation in this pool */
    CpaBoolean active;
    /* Indicate the pool is available for allocation */
    OsalAtomic sync;
    /* Prevent concurrent access to the pool */
} lac_mem_pool_hdr_t;

#define LAC_MEM_POOL_BLK_GET_OPAQUE(entry)                                     \
    (((lac_mem_blk_t *)((LAC_ARCH_UINT)entry - sizeof(lac_mem_blk_t)))->opaque)

#define LAC_MEM_POOL_BLK_SET_OPAQUE(entry, value)                              \
    (((lac_mem_blk_t *)((LAC_ARCH_UINT)entry - sizeof(lac_mem_blk_t)))         \
         ->opaque = value)

#define LAC_MEM_POOL_VIRT_TO_PHYS(pVirtAddr)                                   \
    (((lac_mem_blk_t *)((LAC_ARCH_UINT)pVirtAddr - sizeof(lac_mem_blk_t)))     \
         ->physDataPtr)
/**< @ingroup LacMemPool
 *   macro for retrieving the physical address of the memory block. */

#define LAC_MEM_POOL_INIT_POOL_ID 0
/**< @ingroup LacMemPool
 * macro which defines the valid initialisation value for a pool ID. This is
 * used as a level of abstraction for the user of this interface */

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function creates a memory pool containing a specified number of
 * elements of specific size and byte alignment. This function is not reentrant
 * or thread safe and is only intended to be called during initialisation.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[out] poolID               on successful creation of a pool this will
 *                                  be the ID used for all subsequent accesses
 * @param[in] poolName              The name of the memory pool
 * @param[in] numElementsInPool     number of elements to provision in the pool
 * @param[in] blkSizeInBytes        size in bytes of each element in the pool
 * @param[in] blkAlignmentInBytes   byte alignment required for each element
 * @param[in] trackMemory           track the memory in use by this pool
 * @param[in] node                  node to allocate from
 *
 * @retval CPA_STATUS_INVALID_PARAM  invalid input parameter
 * @retval CPA_STATUS_RESOURCE       error in provisioning resources
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 *
 ******************************************************************************/
CpaStatus Lac_MemPoolCreate(lac_memory_pool_id_t *poolID,
                            char *poolName,
                            unsigned int numElementsInPool,
                            unsigned int blkSizeInBytes,
                            unsigned int blkAlignmentInBytes,
                            CpaBoolean trackMemory,
                            Cpa32U node);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function will destroy the memory pool in it's current state. All memory
 * blocks which have been returned to the memory pool will be de-allocated and
 * the pool indetifier will be freed and assigned to NULL. It is the
 * responsibility of the pool creators to return all memory before a destroy or
 * memory will be leaked.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      No

 * @param[in] poolID  Pointer to the memory pool to destroy
 *
 ******************************************************************************/
void Lac_MemPoolDestroy(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function enables the allocation of a block from a previously created
 * memory pool.
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No

 * @param[in] poolID  Pointer to the memory pool to enable.
 *
 ******************************************************************************/
void Lac_MemPoolEnable(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function prevents the allocation of a block from a previously created
 * memory pool.
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No

 * @param[in] poolID  Pointer to the memory pool to disable.
 *
 ******************************************************************************/
void Lac_MemPoolDisable(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function allocates a block from the pool which has been previously
 * created. It does not check the validity of the pool Id prior to accessing the
 * pool. It is up to the calling code to ensure the value is correct.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 * @param[in] poolID  ID of the pool to allocate memory from
 *
 * @retval pointer to the memory which has been allocated from the pool
 *
 ******************************************************************************/
void *Lac_MemPoolEntryAlloc(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function de-allocates the memory passed in back to the pool from which
 * it was allocated.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 * @param[in] entry   memory address of the block to be freed
 *
 ******************************************************************************/
void Lac_MemPoolEntryFree(void *entry);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function returns the number of available entries in a particular pool
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] poolID  ID of the pool
 *
 * @retval number of elements left for allocation from the pool
 *
 ******************************************************************************/
unsigned int Lac_MemPoolAvailableEntries(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function displays the stats associated with the memory pools
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 ******************************************************************************/
void Lac_MemPoolStatsShow(void);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function initialises the physical addresses of the symmetric cookie
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] poolID   ID of the pool
 *
 * @retval CPA_STATUS_FAIL           function failed
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 *
 ******************************************************************************/
CpaStatus Lac_MemPoolInitSymCookiesPhyAddr(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function populates all PKE requests with instance constant parameters
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] poolID   ID of the pool
 * @param[in] instanceHandle   instanceHandle
 *
 * @retval CPA_STATUS_FAIL           function failed
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 *
 ******************************************************************************/
CpaStatus Lac_MemPoolInitAsymCookies(lac_memory_pool_id_t poolID,
                                     CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function initialises the physical addresses of the compression cookie
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] poolID   ID of the pool
 *
 * @retval CPA_STATUS_FAIL           function failed
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 *
 ******************************************************************************/
CpaStatus Lac_MemPoolInitDcCookiePhyAddr(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function setting the opaque field in each cookie buffer to
 * ICP_ADF_INVALID_SEND_SEQ.
 *
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      No
 * @param[in] poolID   ID of the pool
 *
 * @retval CPA_STATUS_FAIL           function failed
 * @retval CPA_STATUS_SUCCESS        function executed successfully
 *
 ******************************************************************************/
CpaStatus Lac_MemPoolInitDcCookies(lac_memory_pool_id_t poolID);

/**
 *******************************************************************************
 * @ingroup LacMemPool
 * This function gets the sync lock of the memory pool to prevent concurrent
 * access to it.
 *
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 * @param[in] poolID   ID of the pool
 *
 * @retval CPA_FALSE          function failed
 * @retval CPA_TRUE           function executed successfully
 *
 ******************************************************************************/
CpaBoolean Lac_MemPoolTestAndGet(lac_memory_pool_id_t poolID);

#endif /*LAC_MEM_POOLS_H*/
