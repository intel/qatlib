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
 * @file adf_platform_acceldev_gen4.h
 *
 * @description
 *      This file contains the platform specific macros for GEN4 that are
 *      common for PF and VF
 *
 *****************************************************************************/
#ifndef ADF_PLATFORM_ACCELDEV_GEN4_H
#define ADF_PLATFORM_ACCELDEV_GEN4_H

#include "icp_accel_devices.h"
/*****************************************************************************
 * Define Constants and Macros
 *****************************************************************************/

/* Ring Csrs offsets */
#define ICP_RING_CSR_RING_CONFIG_GEN4 0x1000
#define ICP_RING_CSR_RING_LBASE_GEN4 0x1040
#define ICP_RING_CSR_RING_UBASE_GEN4 0x1080
#define ICP_RING_CSR_RING_STAT_GEN4 0x0140

#define CSR_RING_STAT_RL_EXCEPTION_MASK (0x1UL << 10)
#define CSR_RING_STAT_RL_HALT_MASK (0x1UL << 9)

/* Ring Base Address */
#define BUILD_RING_BASE_ADDR_GEN4(addr, size)                                  \
    (((addr >> 6) & (0xFFFFFFFFFFFFFFFFULL << size)) << 6)

/* CSR read/write macros */
#define READ_CSR_RING_CONFIG_GEN4(csr_base_addr, bank_offset, ring)            \
    ICP_ADF_CSR_RD(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_CONFIG_GEN4 + (ring << 2))

#define WRITE_CSR_RING_CONFIG_GEN4(csr_base_addr, bank_offset, ring, value)    \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_CONFIG_GEN4 + (ring << 2),  \
                   value)

#define WRITE_CSR_RING_BASE_GEN4(csr_base_addr, bank_offset, ring, value)      \
    do                                                                         \
    {                                                                          \
        Cpa32U l_base = 0, u_base = 0;                                         \
        l_base = (Cpa32U)(value & 0xFFFFFFFF);                                 \
        u_base = (Cpa32U)((value & 0xFFFFFFFF00000000ULL) >> 32);              \
        ICP_ADF_CSR_WR(csr_base_addr,                                          \
                       bank_offset + ICP_RING_CSR_RING_LBASE_GEN4 +            \
                           (ring << 2),                                        \
                       l_base);                                                \
        ICP_ADF_CSR_WR(csr_base_addr,                                          \
                       bank_offset + ICP_RING_CSR_RING_UBASE_GEN4 +            \
                           (ring << 2),                                        \
                       u_base);                                                \
    } while (0)

#define READ_CSR_RING_STATUS_GEN4(csr_base_addr, bank_offset)                  \
    ICP_ADF_CSR_RD(csr_base_addr, (bank_offset) + ICP_RING_CSR_RING_STAT_GEN4)

static inline Cpa64U read_base_gen4(Cpa32U *csr_base_addr,
                                    Cpa32U bank_offset,
                                    Cpa32U ring)
{
    Cpa32U l_base = ICP_ADF_CSR_RD(csr_base_addr,
                                   bank_offset + ICP_RING_CSR_RING_LBASE_GEN4 +
                                       (ring << 2));
    Cpa32U u_base = ICP_ADF_CSR_RD(csr_base_addr,
                                   bank_offset + ICP_RING_CSR_RING_UBASE_GEN4 +
                                       (ring << 2));
    Cpa64U addr = (l_base & 0xFFFFFFFF);
    addr |= ((((Cpa64U)u_base) << 32) & 0xFFFFFFFF00000000ULL);
    return addr;
}

#endif /* ADF_PLATFORM_ACCELDEV_GEN4_H */
