/*****************************************************************************
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
 *****************************************************************************/

/*****************************************************************************
 * @file adf_platform_acceldev_4xxx.h
 *
 * @description
 *      This file contains the platform specific macros for 4XXX that are
 *      common for PF and VF
 *
 *****************************************************************************/
#ifndef ADF_PLATFORM_ACCELDEV_4XXX_H
#define ADF_PLATFORM_ACCELDEV_4XXX_H

#include "icp_accel_devices.h"
/*****************************************************************************
 * Define Constants and Macros
 *****************************************************************************/

/* Ring Csrs offsets */
#define ICP_RING_CSR_RING_CONFIG_4XXX 0x1000
#define ICP_RING_CSR_RING_LBASE_4XXX 0x1040
#define ICP_RING_CSR_RING_UBASE_4XXX 0x1080
#define ICP_RING_CSR_RING_STAT_4XXX 0x0140

#define CSR_RING_STAT_RL_EXCEPTION_MASK (0x1UL << 10)
#define CSR_RING_STAT_RL_HALT_MASK (0x1UL << 9)

/* Ring Base Addresse */
#define BUILD_RING_BASE_ADDR_4XXX(addr, size)                                  \
    (((addr >> 6) & (0xFFFFFFFFFFFFFFFFULL << size)) << 6)

/* CSR read/write macros */
#define READ_CSR_RING_CONFIG_4XXX(csr_base_addr, bank_offset, ring)            \
    ICP_ADF_CSR_RD(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_CONFIG_4XXX + (ring << 2))

#define WRITE_CSR_RING_CONFIG_4XXX(csr_base_addr, bank_offset, ring, value)    \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_CONFIG_4XXX + (ring << 2),  \
                   value)

#define WRITE_CSR_RING_BASE_4XXX(csr_base_addr, bank_offset, ring, value)      \
    do                                                                         \
    {                                                                          \
        Cpa32U l_base = 0, u_base = 0;                                         \
        l_base = (Cpa32U)(value & 0xFFFFFFFF);                                 \
        u_base = (Cpa32U)((value & 0xFFFFFFFF00000000ULL) >> 32);              \
        ICP_ADF_CSR_WR(csr_base_addr,                                          \
                       bank_offset + ICP_RING_CSR_RING_LBASE_4XXX +            \
                           (ring << 2),                                        \
                       l_base);                                                \
        ICP_ADF_CSR_WR(csr_base_addr,                                          \
                       bank_offset + ICP_RING_CSR_RING_UBASE_4XXX +            \
                           (ring << 2),                                        \
                       u_base);                                                \
    } while (0)

#define READ_CSR_RING_STATUS_4XXX(csr_base_addr, bank_offset)                  \
    ICP_ADF_CSR_RD(csr_base_addr, (bank_offset) + ICP_RING_CSR_RING_STAT_4XXX)

static inline Cpa64U read_base_4xxx(Cpa32U *csr_base_addr,
                                    Cpa32U bank_offset,
                                    Cpa32U ring)
{
    Cpa32U l_base = ICP_ADF_CSR_RD(csr_base_addr,
                                   bank_offset + ICP_RING_CSR_RING_LBASE_4XXX +
                                       (ring << 2));
    Cpa32U u_base = ICP_ADF_CSR_RD(csr_base_addr,
                                   bank_offset + ICP_RING_CSR_RING_UBASE_4XXX +
                                       (ring << 2));
    Cpa64U addr = (l_base & 0xFFFFFFFF);
    addr |= ((((Cpa64U)u_base) << 32) & 0xFFFFFFFF00000000ULL);
    return addr;
}

#endif /* ADF_PLATFORM_ACCELDEV_4XXX_H */
