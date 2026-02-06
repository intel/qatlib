/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/******************************************************************************
 * @file icp_adf_debug.h
 *
 * @description
 *      This header file that contains the prototypes and definitions required
 *      for ADF debug feature.
 *
 *****************************************************************************/
#ifndef ICP_ADF_DEBUG_H
#define ICP_ADF_DEBUG_H

/*
 * adf_proc_type_t
 * Type of proc file. Simple for files where read funct
 * prints less than page size (4kB) and seq type for files
 * where read function needs to print more that page size.
 */
typedef enum adf_proc_type_e
{
    ADF_PROC_SIMPLE = 1,
    ADF_PROC_SEQ
} adf_proc_type_t;

/*
 * debug_dir_info_t
 * Struct which is used to hold information about a debug directory
 * under the proc filesystem.
 * Client should only set name and parent fields.
 */
typedef struct debug_dir_info_s
{
    char *name;
    struct debug_dir_info_s *parent;
    /* The below fields are used internally by the driver */
    struct debug_dir_info_s *dirChildListHead;
    struct debug_dir_info_s *dirChildListTail;
    struct debug_dir_info_s *pNext;
    struct debug_dir_info_s *pPrev;
    struct debug_file_info_s *fileListHead;
    struct debug_file_info_s *fileListTail;
    void *proc_entry;
} debug_dir_info_t;

/*
 * Read handle type for simple proc file
 * Function is called only once and can print up to 4kB (size)
 * Function should return number of bytes printed.
 */
typedef int (*file_read)(void *private_data, char *buff, int size);

/*
 * Read handle type for sequential proc file
 * Function can be called more than once. It will be called until the
 * return value is not 0. offset should be used to mark the starting
 * point for next step. In one go function can print up to 4kB (size).
 * Function should return 0 (zero) if all info is printed or
 * offset from where to start in next step.
 */
typedef int (*file_read_seq)(void *private_data,
                             char *buff,
                             int size,
                             int offset);

/*
 * debug_file_info_t
 * Struct which is used to hold information about a debug file
 * under the proc filesystem.
 * Client should only set name, type, private_data, parent fields,
 * and read or seq_read pointers depending on type used.
 */
typedef struct debug_file_info_s
{
    char *name;
    struct debug_dir_info_s *parent;
    adf_proc_type_t type;
    file_read read;
    file_read_seq seq_read;
    void *private_data;
    /* The below fields are used internally by the driver */
    struct debug_file_info_s *pNext;
    struct debug_file_info_s *pPrev;
    void *page;
    Cpa32U offset;
    void *proc_entry;
} debug_file_info_t;

#endif /* ICP_ADF_DEBUG_H */
