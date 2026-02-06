/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef VFIO_LIB_H
#define VFIO_LIB_H

#include "adf_pfvf_proto.h"

/* Common typedefs */

#define MAX_BAR_NR (0x10)
#define VFIO_GET_REGION_ADDR(x) ((uint64_t)x << 40ULL)

typedef struct
{
    size_t nr_bar;
    struct
    {
        void *ptr;
        size_t size;
    } bar[MAX_BAR_NR];
} pcs_t;

typedef struct
{
    int vfio_container_fd;
    int vfio_dev_fd;
    int vfio_group_fd;
    int event_fd;
    pcs_t pcs;
    struct adf_pfvf_dev_data pfvf;
} vfio_dev_info_t;

/* Function prototypes */

int open_vfio_dev(const char *vfio_file,
                  const char *bdf,
                  int group_fd,
                  unsigned int pci_id,
                  vfio_dev_info_t *dev);
void close_vfio_dev(vfio_dev_info_t *dev);
#endif
