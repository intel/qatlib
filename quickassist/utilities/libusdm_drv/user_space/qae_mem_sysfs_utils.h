/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
/*
 ****************************************************************************
 * @file qae_mem_sysfs_utils.h
 *
 * sysfs helpers for reading hugepage counters and initialising the
 * per-process hugepage configuration from environment variables.
 *
 ***************************************************************************/
#ifndef QAE_MEM_SYSFS_UTILS_H
#define QAE_MEM_SYSFS_UTILS_H

#include <stdint.h>

/* sysfs paths for 2MB hugepage counters. */
#define SYSFS_2M_HUGEPAGES_DIR "/sys/kernel/mm/hugepages/hugepages-2048kB"
#define SYSFS_2M_FREE_HUGEPAGES                                                \
    "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages"
#define SYSFS_2M_NR_HUGEPAGES                                                  \
    "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"

/*
 * __qae_hugepage_config_init - configure hugepage mode and set per-process
 * budget.
 *
 * Reads QAT_MAX_2M_HPG_PER_PROCESS and validates against sysfs nr_hugepages.
 *
 * Returns the env variable value as budget on success, 0 if no env var is
 * set or env var is zero, or -EINVAL on error (env non-zero but system has
 * no hugepages configured).
 * The caller must propagate the error rather than silently falling back.
 */
int __qae_hugepage_config_init(void);

/*
 * __qae_read_free_hugepages - read current free 2M hugepage count
 * from sysfs.
 *
 * Returns no. of free hugepages value or negative errno on error.
 */
int __qae_read_free_hugepages(void);

/*
 * parse_sysfs_value - read one unsigned long integer from a sysfs file.
 *
 * @filename: full path to the sysfs file
 * @val:      output pointer, set on success
 *
 * Returns 0 on success, negative errno on error.
 */
int parse_sysfs_value(const char *filename, unsigned long *val);

#endif /* QAE_MEM_SYSFS_UTILS_H */
