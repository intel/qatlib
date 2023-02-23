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
#if defined(__KERNEL__)
#include <asm/page.h>
#include <linux/io.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/atomic.h>

#if (KERNEL_VERSION(2, 6, 38) >= LINUX_VERSION_CODE)
#define kstrtoll strict_strtoll
#endif /* KERNEL_VERSION */
#endif /* __KERNEL__ */

#define USDM_MOD "usdm_drv: "

#define mm_err(...) pr_err(USDM_MOD __VA_ARGS__)

#define mm_info(...) pr_info(USDM_MOD __VA_ARGS__)

#define mm_warning(...) pr_warn(USDM_MOD __VA_ARGS__)

/*define types which need to vary between 32 and 64 bit*/
#define QAE_PAGE_SHIFT 12
#define QAE_PAGE_SIZE (1UL << QAE_PAGE_SHIFT)

/* QAE_NUM_PAGES_PER_ALLOC can be defined as 32 pages when library
is built, default is 512 */
#ifndef QAE_NUM_PAGES_PER_ALLOC
#define QAE_NUM_PAGES_PER_ALLOC 512
#endif

#define STATIC static
#define UNUSED(x) (void)(x)

#define QAE_PHYS_ADDR uint64_t

#define QAE_MEM_ZALLOC_GEN(size) kzalloc(size, GFP_KERNEL)
#define QAE_MEM_FREE(ptr)                                                      \
    do                                                                         \
    {                                                                          \
        if (ptr)                                                               \
        {                                                                      \
            kfree(ptr);                                                        \
            ptr = NULL;                                                        \
        }                                                                      \
    } while (0)

/* Defining Max Size limit to be used, to allocate using kmalloc as 4MB */
#define QAE_MEM_SIZE_LIMIT (1024 * 4096)

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
    size_t mSize;       /* allocated size */

} qae_mem_alloc_info_t;

enum slabType
{
    SMALL = 0,
    LARGE = 1,
    HUGE_PAGE = 2,
};

/* User space memory information structure. */
typedef struct dev_mem_info_s
{
    int64_t nodeId; /* shared b/w user/kernel */
    /* Node id for NUMA */
    uint64_t size; /* shared b/w user/kernel */
    /* Size of this block (bytes) */
    enum slabType type;
    /* Slab for normal memory or large memory */
    uint32_t allocations; /* user space only */
    /* Huge page file descriptor */
    int64_t hpg_fd; /* user space only */
    /* The huge page file descriptor of each slab */
    uint64_t phy_addr; /* shared b/w user/kernel */
    /* Physical address of the kmalloced area */
    union {
        void *virt_addr; /* user space only */
        uint64_t padding_virt;
    };
    /* Base address in user space - i.e. virtual address */
    union {
        struct dev_mem_info_s *pPrev_user; /* user space only */
        uint64_t padding_prevu;
    };
    union {
        struct dev_mem_info_s *pNext_user; /* user space only */
        uint64_t padding_nextu;
    };
    union {
        struct dev_mem_info_s *pPrev_user_hash; /* user space only */
        uint64_t padding_prevuh;
    };
    union {
        struct dev_mem_info_s *pNext_user_hash; /* user space only */
        uint64_t padding_nextuh;
    };
} dev_mem_info_t;

typedef struct user_page_info_s
{
    /* Use 64-bit unsigned to support 32bit application on
     * a 64-bit kernel */
    uint64_t virt_addr;
    /* physical address shared b/w user/kernel */
    uint64_t phy_addr;
    uint64_t size;
} user_page_info_t;

/* size of allocation unit */
#define UNIT_SIZE 1024
#define QAE_KBYTE 1024
#define QWORD_WIDTH (8 * sizeof(uint64_t))
#define QWORD_ALL_ONE 0xFFFFFFFFFFFFFFFFULL

/*
Bitmap is used to keep track the allocation of each block
Each 1k block is represented by one bit allocated(1)/free(0)
BITMAP_LEN is a macro the represents the number of 64-bit quad words
that make up the bitmap
with 512 pages of 4k page and 1k units this value is 32
 */
#define CHUNK_SIZE (UNIT_SIZE * QWORD_WIDTH)

#define BITMAP_LEN (QAE_NUM_PAGES_PER_ALLOC * QAE_PAGE_SIZE / CHUNK_SIZE)

#define BLOCK_SIZES (BITMAP_LEN * QWORD_WIDTH)

/*block control structure */
typedef struct block_ctrl_s
{
    dev_mem_info_t mem_info; /* memory device info type */
    /* adding an extra element at the end to make a barrier */
    uint64_t bitmap[BITMAP_LEN + 1]; /* bitmap each bit represents a 1k block */
    uint16_t sizes[BLOCK_SIZES]; /* Holds the size of each allocated block */
} block_ctrl_t;

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

#ifdef __KERNEL__
/* Kernel space memory information structure. */
typedef struct kdev_mem_info_s
{
    void *kmalloc_ptr; /* kernel space only (small slab) */
    /* Pointer to mem originally returned by kmalloc */
    void *huge_mem_ctrl;
    uint64_t size;
    /* Slab size */
    atomic_t mmap_ref;
    /* Mapped pages counter */
    uint64_t phy_addr; /* shared b/w user/kernel */
    /* Physical address of the kmalloc'ed area */
    struct kdev_mem_info_s *pPrev_kernel;
    struct kdev_mem_info_s *pNext_kernel;
    struct kdev_mem_info_s *pPrev_kernel_hash;
    struct kdev_mem_info_s *pNext_kernel_hash;
} kdev_mem_info_t;

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
    int pid;
    uint64_t allocs_nr;
    uint64_t hugepages_nr;
    kdev_mem_info_t *head;
    kdev_mem_info_t *tail;
    kdev_mem_info_t *hugepage_head;
    kdev_mem_info_t *hugepage_tail;
    struct user_proc_mem_list_s *pPrev_user;
    struct user_proc_mem_list_s *pNext_user;
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
#endif /* __KERNEL__ */

/*
 ******************************************************************************
 * @ingroup ADD_ELEMENT_TO_HEAD_LIST
 *      insert element at the head of a linked list
 * @description
 *      inserts a new element at the head of a
 *      double linked list in user or kernel mode
 *      depending on mode parameter
 *      elementToAdd - ptr to the new element
 *      headPtr - ptr to the first element in list
 *      tailPtr - ptr to the last element int the list
 *      mode - _kernel or _user
 ******************************************************************************/

#define ADD_ELEMENT_TO_HEAD_LIST(elementToAdd, headPtr, tailPtr, mode)         \
    do                                                                         \
    {                                                                          \
        elementToAdd->pPrev##mode = NULL;                                      \
        if (NULL == headPtr)                                                   \
        {                                                                      \
            tailPtr = elementToAdd;                                            \
            elementToAdd->pNext##mode = NULL;                                  \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            elementToAdd->pNext##mode = headPtr;                               \
            headPtr->pPrev##mode = elementToAdd;                               \
        }                                                                      \
        headPtr = elementToAdd;                                                \
    } while (0)

/*
 ******************************************************************************
 * @ingroup ADD_ELEMENT_TO_END_LIST
 *      insert element at the end of a linked list
 * @description
 *      inserts a new element at the head of a
 *      double linked list in user or kernel mode
 *      depending on mode parameter
 *      elementToAdd - ptr to the new element
 *      headPtr - ptr to the first element in list
 *      tailPtr - ptr to the last element int the list
 *      mode - _kernel or _user
 ******************************************************************************/

#define ADD_ELEMENT_TO_END_LIST(elementToAdd, headPtr, tailPtr, mode)          \
    do                                                                         \
    {                                                                          \
        elementToAdd->pNext##mode = NULL;                                      \
        if (NULL == tailPtr)                                                   \
        {                                                                      \
            headPtr = elementToAdd;                                            \
            elementToAdd->pPrev##mode = NULL;                                  \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            elementToAdd->pPrev##mode = tailPtr;                               \
            tailPtr->pNext##mode = elementToAdd;                               \
        }                                                                      \
        tailPtr = elementToAdd;                                                \
    } while (0)

/*
 ******************************************************************************
 * @ingroup REMOVE_ELEMENT_FROM_LIST
 *      remove element at the end of a linked list
 * @description
 *      removes an element from a
 *      double linked list in user or kernel mode
 *      depending on mode parameter
 *      elementToREmove - ptr to the new element
 *      headPtr - ptr to the first element in list
 *      tailPtr - ptr to the last element int the list
 *      mode - _kernel or _user
 ******************************************************************************/

#define REMOVE_ELEMENT_FROM_LIST(elementToRemove, headPtr, tailPtr, mode)      \
    do                                                                         \
    {                                                                          \
        if (NULL != elementToRemove->pPrev##mode)                              \
        {                                                                      \
            elementToRemove->pPrev##mode->pNext##mode =                        \
                elementToRemove->pNext##mode;                                  \
            if (NULL != elementToRemove->pNext##mode)                          \
            {                                                                  \
                elementToRemove->pNext##mode->pPrev##mode =                    \
                    elementToRemove->pPrev##mode;                              \
            }                                                                  \
            else                                                               \
            {                                                                  \
                tailPtr = elementToRemove->pPrev##mode;                        \
            }                                                                  \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            if (NULL != elementToRemove->pNext##mode)                          \
            {                                                                  \
                elementToRemove->pNext##mode->pPrev##mode = NULL;              \
                headPtr = elementToRemove->pNext##mode;                        \
            }                                                                  \
            else                                                               \
            {                                                                  \
                headPtr = NULL;                                                \
                tailPtr = NULL;                                                \
            }                                                                  \
        }                                                                      \
    } while (0)

/* IOCTL number for use between the kernel and the user space application */
#define DEV_MEM_MAGIC 'q'
#define DEV_MEM_CMD_MEMALLOC (0)
#define DEV_MEM_CMD_MEMFREE (1)
#define DEV_MEM_CMD_RELEASE (2)
#define DEV_MEM_CMD_UNREGISTER (3)
#define DEV_MEM_CMD_GET_NUM_HPT (4)
#define DEV_MEM_CMD_GET_USER_PAGE (5)
#define DEV_MEM_CMD_HUGEPAGE_IOMMU_UNMAP (6)

/* IOCTL commands for requesting kernel memory */
#define DEV_MEM_IOC_MEMALLOC                                                   \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMALLOC, dev_mem_info_t)

#define DEV_MEM_IOC_MEMFREE                                                    \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMFREE, dev_mem_info_t)

#define DEV_MEM_IOC_RELEASE _IO(DEV_MEM_MAGIC, DEV_MEM_CMD_RELEASE)

#define DEV_MEM_IOC_UNREGISTER                                                 \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_UNREGISTER, dev_mem_info_t)

#define DEV_MEM_IOC_GET_NUM_HPT                                                \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_GET_NUM_HPT, uint32_t)

#define DEV_MEM_IOC_GET_USER_PAGE                                              \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_GET_USER_PAGE, user_page_info_t)

#define DEV_MEM_IOC_HUGEPAGE_IOMMU_UNMAP                                       \
    _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_HUGEPAGE_IOMMU_UNMAP, user_page_info_t)
/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *       qaeMemInit
 *
 * @description
 *        Initialize the user-space allocator, opening the device driver
 *        used to communicate with the kernel-space.
 *
 * @param[in] path - path to the specific device
 *
 * @retval 0 if the open of the device was successful and
 *         non-zero otherwise
 * @pre
 *       none
 * @post
 *       Allocator is initialized
 *
 ****************************************************************************/
int32_t qaeMemInit(void);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *      qaeMemDestroy
 *
 * @description
 *      Release the user-space allocator. It closes the file descriptor
 *      associated with the device driver
 *
 * @param[in] none
 *
 * @retval none
 *
 * @pre
 *        The user space allocator is initialized using qaeMemInit
 * @post
 *        The user-space allocator is released
 *
 ****************************************************************************/
void qaeMemDestroy(void);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *       qaeIOMMUInit
 *
 * @description
 *        Function creates iommu domain. Applicable when IOMMU is enabled
 *
 * @param[in] none
 *
 * @retval 0 - if successful.
 *         non-zero - otherwise
 *
 * @pre
 *       IOMMU is enabled.
 * @post
 *       iommu domain created
 *
 ****************************************************************************/
int32_t qaeIOMMUInit(void);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *       qaeIOMMUExit
 *
 * @description
 *        Function removes iommu domain. Applicable when IOMMU is enabled
 *
 * @param[in] none
 *
 * @retval none
 *
 * @pre
 *      IOMMU is enabled and an iommu domain is created using qaeIOMMUInit
 * @post
 *      iommu domain removed
 *
 ****************************************************************************/
void qaeIOMMUExit(void);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *      qaeIOMMUgetRemappingSize
 *
 * @description
 *      Function calculates size for remapping when IOMMU is enabled.
 *      Before calling any of the qaeMemAlloc functions, this function can be
 *      used to calculate the actual size of memory to be allocated.
 *      The remapping size is at least PAGE_SIZE.
 *
 * @param[in] size - Actual size of the memory to be allocated
 *
 * @retval Remapping size
 *
 * @pre
 *     IOMMU is enabled and an iommu domain is created using qaeIOMMUInit.
 * @post
 *     Remapping size provided.
 *
 ****************************************************************************/
size_t qaeIOMMUgetRemappingSize(size_t size);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *      qaeIOMMUMap
 *
 * @description
 *      Function adds mapping from io virtual address to a physical address.
 *      Applicable when IOMMU is enabled
 *
 * @param[in] phaddr - Host physical address.
 * @param[in] iova - IO virtual address.
 * @param[in] size - Memory size to be remapped obtained from
 *                   qaeIOMMUgetRemappingSize() function.
 *
 * @retval CPA_STATUS_SUCCESS - if successful.
 *         CPA_STATUS_UNSUPPORTED - if not supported
 *         CPA_STATUS_FAIL - otherwise
 *
 * @pre
 *      An iommu domain is created using qaeIOMMUInit. iova points to
 *      previously allocated memory. phaddr is already obtained using
 *      iova using virt_to_phys or similar functions. size is calculated
 *      using qaeIOMMUgetRemappingSize function.
 * @post
 *      IO virtual address mapped
 ****************************************************************************/
int32_t qaeIOMMUMap(uint64_t phaddr, uint64_t iova, size_t size);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *       qaeIOMMUUnmap
 *
 * @description
 *        Function removes mapping from io virtual address to a physical
 *        address. Applicable when IOMMU is enabled
 *
 * @param[in] iova - IO virtual address.
 * @param[in] size - Memory size to be unmapped
 *
 * @retval CPA_STATUS_SUCCESS - if successful.
 *         CPA_STATUS_UNSUPPORTED - if not supported
 *         CPA_STATUS_FAIL - otherwise
 *
 * @pre
 *      An iommu domain is created using qaeIOMMUInit. iova points to
 *      previously allocated memory.
 * @post
 *       IO virtual address unmapped
 ****************************************************************************/
int32_t qaeIOMMUUnmap(uint64_t iova, size_t size);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *      qaeIOMMUVirtToPhys
 *
 * @description
 *      Function translates io virtual address to a physical address.
 *      Applicable when IOMMU is enabled.
 *
 * @param[in] iova, IO virtual address
 *
 * @retval host physical address - if successful
 *         NULL Otherwise
 *
 * @pre
 *      An iommu domain is created using qaeIOMMUInit. iova points to
 *      previously allocated memory.
 * @post
 *       virtual address is translated to physical address
 *
 ****************************************************************************/
uint64_t qaeIOMMUVirtToPhys(uint64_t iova);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *       qaeIOMMUAttachDev
 *
 * @description
 *      This function attaches a pci dev (VF) to an iommu domain.
 *      Applicable when IOMMU/SRIOV are enabled and after the driver bringup
 *      in Host is succesful.
 *
 * @param[in] dev, Device to be attached
 *
 * @retval CPA_STATUS_SUCCESS - if successful
 *         CPA_STATUS_UNSUPPORTED - if not supported
 *         CPA_STATUS_FAIL - otherwise
 *
 * @pre
 *      An iommu domain is created using qaeIOMMUInit. Driver bringup
 *      in Host is succesful.
 * @post
 *       device is attached
 *
 ****************************************************************************/
int32_t qaeIOMMUAttachDev(void *dev);

/*****************************************************************************
 * * @ingroup CommonMemoryDriver
 *       qaeIOMMUDetachDev
 *
 * @description
 *        Function detaches pci dev to iommu domain
 *
 * @param[in] dev, Device to be detached
 *
 * @retval none
 *
 * @pre
 *      An iommu domain is created using qaeIOMMUInit, Driver bringup
 *      in Host is succesful and dev is already
 *      attached using qaeIOMMUAttachDev
 * @post
 *      Device is detached
 *
 ****************************************************************************/
void qaeIOMMUDetachDev(void *dev);

/**
 *****************************************************************************
 * @ingroup CommonMemoryDriver
 *     printMemAllocations
 *
 *  @description
 *     Prints only the overall count of NUMA and non-NUMA memory allocations
 *     performed. This doesn't provide other details like the allocation
 *     sizes, pointers etc.
 *
 * @retval none
 *
 * @pre
 *       The user space allocator is initialized using qaeMemInit
 * @post
 *       memory allocation count printed
 *
 ****************************************************************************/
void printMemAllocations(void);

#ifndef __KERNEL__
#ifdef ICP_WITHOUT_THREAD
#define mem_mutex_lock(x) (0)
#define mem_mutex_unlock(x) (0)
#else
#define mem_mutex_lock(x) pthread_mutex_lock(x)
#define mem_mutex_unlock(x) pthread_mutex_unlock(x)
#endif

#define mem_ioctl(fd, cmd, pMemInfo) ioctl(fd, cmd, pMemInfo)
#define qae_open(file, options) open(file, options)
#define qae_lseek(fd, offset, whence) lseek(fd, offset, whence)
#define qae_read(fd, buf, nbytes) read(fd, buf, nbytes)
#define qae_mmap(addr, length, prot, flags, fd, offset)                        \
    mmap(addr, length, prot, flags, fd, offset)
#define qae_munmap(addr, length) munmap(addr, length)
#define qae_madvise(addr, len, advice) madvise(addr, len, advice)
#define qae_mkstemp(template) mkstemp(template)
#endif

#if defined(__KERNEL__)
#if defined(ICP_ADF_IOMMU)
int icp_adf_iommu_map(void *iova, void *phaddr, size_t size);
int icp_adf_iommu_unmap(void *iova, size_t size);
size_t icp_adf_iommu_get_remapping_size(size_t size);
static inline int icp_iommu_map(void **iova, void *vaddr, size_t size)
{
    void *phaddr = (void *)virt_to_phys(vaddr);
    *iova = phaddr;
    return icp_adf_iommu_map(*iova, phaddr, size);
}
static inline int icp_iommu_unmap(void *iova, size_t size)
{
    return icp_adf_iommu_unmap(iova, size);
}
static inline size_t icp_iommu_get_remapping_size(size_t size)
{
    return icp_adf_iommu_get_remapping_size(size);
}
#elif defined(ICP_OSAL_IOMMU)
int osalIOMMUMap(uint64_t iova, uint64_t phaddr, size_t size);
static inline int icp_iommu_map(void **iova, void *vaddr, size_t size)
{
    void *phaddr = (void *)virt_to_phys(vaddr);
    *iova = phaddr;
    return osalIOMMUMap((uintptr_t)*iova, phaddr, size);
}

int osalIOMMUUnmap(uint64_t iova, size_t size);
static inline int icp_iommu_unmap(void *iova, size_t size)
{
    return osalIOMMUUnmap((uintptr_t)iova, size);
}
uint64_t osalIOMMUVirtToPhys(uint64_t iova);
static inline uint64_t icp_iommu_virt_to_phys(void *iova)
{
    return osalIOMMUVirtToPhys((uintptr_t)iova);
}
size_t osalIOMMUgetRemappingSize(size_t size);
static inline size_t icp_iommu_get_remapping_size(size_t size)
{
    return osalIOMMUgetRemappingSize(size);
}
#elif defined(ICP_QDM_IOMMU)
int qdm_iommu_map(void **iova, void *vaddr, size_t size);
int qdm_iommu_unmap(void *iova, size_t size);
int qdm_hugepage_iommu_map(void **iova, void *va_page, size_t size);
static inline int icp_iommu_map(void **iova, void *vaddr, size_t size)
{
    return qdm_iommu_map(iova, vaddr, size);
}
static inline int icp_iommu_unmap(void *iova, size_t size)
{
    return qdm_iommu_unmap(iova, size);
}
static inline int icp_hugepage_iommu_map(void **iova,
                                         void *va_page,
                                         size_t size)
{
    return qdm_hugepage_iommu_map(iova, va_page, size);
}
static inline int icp_hugepage_iommu_unmap(void *iova, size_t size)
{
    return qdm_iommu_unmap(iova, size);
}
static inline size_t icp_iommu_get_remapping_size(size_t size)
{
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}
#else
#define ICP_IOMMU_DISABLED
static inline int icp_iommu_map(void **iova, void *vaddr, size_t size)
{
    *iova = (void *)(uintptr_t)virt_to_phys(vaddr);
    return 0;
}

static inline int icp_iommu_unmap(void *iova, size_t size)
{
    return 0;
}

static inline int icp_hugepage_iommu_map(void **iova,
                                         void *va_page,
                                         size_t size)
{
    *iova = (void *)(uintptr_t)page_to_phys((struct page *)va_page);
    return 0;
}
static inline int icp_hugepage_iommu_unmap(void *iova, size_t size)
{
    return 0;
}
static inline size_t icp_iommu_get_remapping_size(size_t size)
{
    return (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}
#endif
#endif
#endif
