/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/
#ifndef ADF_VFIO_PF_H
#define ADF_VFIO_PF_H

#include "cpa_types.h"
#include "icp_accel_devices.h"

/**
 * @description
 *     Scans qat driver sysfs entries for PFs.
 *
 * @param pf_info     Pointer to array of icp_accel_pf_info_t structs.
 * @param pf_info_len PF array length.
 *
 * @retval            Number of PFs if the function executed successfully.
 * @retval            CPA_STATUS_INVALID_PARAM if function failed.
 */
Cpa32S adf_vfio_init_pfs_info(icp_accel_pf_info_t *pf_info, size_t pf_info_len);

#endif
