/**
 * @file OsalDevDrv.h
 *
 * @brief Device driver macros and data types
 *
 *
 * @par
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

#ifndef OSAL_DEV_DRV_H
#define OSAL_DEV_DRV_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define USER_MEM_64BYTE_OFFSET 64
#define USER_MEM_128BYTE_OFFSET 128

#define FREE(ptr) osalMemFree(ptr)

#ifdef __cplusplus
}
#endif

#endif
