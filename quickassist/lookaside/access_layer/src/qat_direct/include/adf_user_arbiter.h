/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/*****************************************************************************
 * @file adf_user_arbiter.h
 *
 * @description
 *      This file contains the arbiter related interfaces
 *
 *****************************************************************************/
#ifndef ADF_USER_ARBITER_H
#define ADF_USER_ARBITER_H

#include <adf_platform_common.h>
#include <icp_platform.h>

#define ICP_ARB_REG_SLOT 0x1000
#define ICP_ARB_RINGSRVARBEN_OFFSET_START 0x19C

#define READ_CSR_ARB_RINGSRVARBEN(csr_base_addr, index)                        \
    ICP_ADF_CSR_RD(csr_base_addr,                                              \
                   ICP_ARB_RINGSRVARBEN_OFFSET_START +                         \
                       ICP_ARB_REG_SLOT * index)

#define WRITE_CSR_ARB_RINGSRVARBEN(csr_base_addr, index, value)                \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   ICP_ARB_RINGSRVARBEN_OFFSET_START +                         \
                       ICP_ARB_REG_SLOT * index,                               \
                   value)

static __inline__ void adf_update_ring_arb_enable(adf_dev_ring_handle_t *ring)
{
    int32_t status;

    /* Lock the register to enable/disable arbiter */
    status = ICP_MUTEX_LOCK(&ring->bank_data->user_bank_lock);
    if (status)
    {
        ADF_ERROR("Failed to lock bank with error %d\n", status);
        return;
    }

    WRITE_CSR_ARB_RINGSRVARBEN(
        ring->csr_addr, 0, ring->bank_data->ring_mask & 0xFF);
    ICP_MUTEX_UNLOCK(&ring->bank_data->user_bank_lock);
}

#define adf_update_ring_arb_disable adf_update_ring_arb_enable

#endif /* ADF_USER_ARBITER_H */
