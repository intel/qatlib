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
 ****************************************************************************
 * @file qae_mem_hugepage_utils.h
 *
 * This file provides API for utilities of Linux/FreeBSD user space memory
 * allocation with huge page enabled.
 *
 ***************************************************************************/
#ifndef QAE_MEM_HUGEPAGE_UTILS_H
#define QAE_MEM_HUGEPAGE_UTILS_H
#include "qae_mem_utils.h"
#include "qae_mem_user_utils.h"

API_LOCAL
uint64_t __qae_hugepage_virt2phy(const int fd,
                                 const void *virtaddr,
                                 const size_t size);

API_LOCAL
void *__qae_hugepage_mmap_phy_addr(const size_t len);

API_LOCAL
int __qae_hugepage_iommu_unmap(const int fd, const dev_mem_info_t *memInfo);

API_LOCAL
dev_mem_info_t *__qae_hugepage_alloc_slab(const int fd,
                                          const size_t size,
                                          const int node,
                                          enum slabType type);
API_LOCAL
dev_mem_info_t *__qae_vfio_hugepage_alloc_slab(const int fd,
                                               const size_t size,
                                               const int node,
                                               enum slabType type,
                                               const uint32_t alignment);

API_LOCAL
void __qae_hugepage_free_slab(const dev_mem_info_t *memInfo);

API_LOCAL
void __qae_vfio_hugepage_free_slab(dev_mem_info_t *memInfo);

API_LOCAL
int __qae_init_hugepages(const int fd);

API_LOCAL
int __qae_vfio_init_hugepages(void);

API_LOCAL
int __qae_hugepage_enabled(void);
#endif
