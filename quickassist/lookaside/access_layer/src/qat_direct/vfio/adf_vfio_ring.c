/***************************************************************************
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
 ***************************************************************************/
#include "cpa.h"
#include "adf_platform_common.h"
#include "adf_platform_acceldev_common.h"
#include "adf_dev_ring_ctl.h"
#include "adf_io_ring.h"
#include "icp_platform.h"

static inline void update_ring(Cpa32U *csr_base_addr,
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
