/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#include "cpa.h"
#include "adf_platform_common.h"
#include "adf_platform_acceldev_common.h"
#include "adf_dev_ring_ctl.h"
#include "adf_io_ring.h"
#include "icp_platform.h"

#define STATIC static

STATIC inline void update_ring(Cpa32U *csr_base_addr,
                               Cpa32U bank_offset,
                               Cpa32U bank_ring_mask,
                               Cpa32U arb_mask)
{
    Cpa32U arben, arben_tx, arben_rx;
    Cpa32U shift;

    ICP_CHECK_FOR_NULL_PARAM_VOID(csr_base_addr);

    shift = __builtin_popcount(arb_mask);
    arben_tx = bank_ring_mask & arb_mask;
    arben_rx = (bank_ring_mask >> shift) & arb_mask;
    arben = arben_tx & arben_rx;

    ICP_ADF_CSR_WR(
        csr_base_addr, bank_offset + ICP_RING_CSR_RING_SRV_ARB_EN, arben);
}

CpaStatus adf_io_reserve_ring(Cpa16U accel_id, Cpa16U bank_nr, Cpa16U ring_nr)
{
    return CPA_STATUS_SUCCESS;
}

CpaStatus adf_io_release_ring(Cpa16U accel_id, Cpa16U bank_nr, Cpa16U ring_nr)
{
    return CPA_STATUS_SUCCESS;
}

CpaStatus adf_io_enable_ring(adf_dev_ring_handle_t *ring)
{
    Cpa32U bank_ring_mask;

    ICP_CHECK_FOR_NULL_PARAM(ring);

    /* For ring configured in UQ mode, the request ring CSRs are internally
     * managed by HW and will not be accessible by SW
     */

    if (!ring->csr_addr || !ring->bank_data || !ring->accel_dev)
        return CPA_STATUS_FAIL;

    bank_ring_mask = ring->bank_data->ring_mask;
    bank_ring_mask |= 1 << ring->ring_num;
    update_ring(ring->csr_addr,
                ring->bank_offset,
                bank_ring_mask,
                ring->accel_dev->arb_mask);

    return CPA_STATUS_SUCCESS;
}

CpaStatus adf_io_disable_ring(adf_dev_ring_handle_t *ring)
{
    Cpa32U bank_ring_mask;

    ICP_CHECK_FOR_NULL_PARAM(ring);

    /* For ring configured in UQ mode, the request ring CSRs are internally
     * managed by HW and will not be accessible by SW
     */

    if (!ring->csr_addr || !ring->bank_data || !ring->accel_dev)
        return CPA_STATUS_FAIL;

    bank_ring_mask = ring->bank_data->ring_mask;
    bank_ring_mask &= ~(1 << ring->ring_num);
    update_ring(ring->csr_addr,
                ring->bank_offset,
                bank_ring_mask,
                ring->accel_dev->arb_mask);

    return CPA_STATUS_SUCCESS;
}
