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
 * @file adf_platform_acceldev_common.h
 *
 * @description
 *      This file contains the platform specific macros for DH89xxCC that are
 *      common for PF and VF
 *
 *****************************************************************************/
#ifndef ADF_PLATFORM_ACCELDEV_COMMON_H
#define ADF_PLATFORM_ACCELDEV_COMMON_H

/*****************************************************************************
 * Define Constants and Macros
 *****************************************************************************/

/* Coalesced Interrupt Enable */
#define ETR_CSR_INTR_COL_CTL_ENABLE 0x80000000

/*
 * Interrupt coalescing timer hardware constants.
 *
 * CSR_INT_COL_CTL CSR
 * | Bit 31 | Bits 30..16 | Bits 15..0 |
 * | enable | reserved    | delcnt     |
 *
 * CSR_INT_COL_CTL DELCNT is decremented every ICP_INT_COL_CTL_CYCLES_PER_DECR
 * clock cycles of the CPP clock. With a 1 GHz clock and 256 cycles per
 * decrement the granularity is 256 ns and the maximum delay is 0xFFFF * 256 ns.
 */
#define ICP_INT_COL_CTL_CPP_FREQ_HZ (1000000000ULL) /* 1 GHz */
#define ICP_INT_COL_CTL_CYCLES_PER_DECR (256U)
#define ICP_INT_COL_CTL_DELCNT_MIN (0x1U)
#define ICP_INT_COL_CTL_DELCNT_MAX (0xFFFFU)
/* Mask for the DELCNT field in the CSR_INT_COL_CTL register (bits [15:0]). */
#define ICP_INT_COL_CTL_DELCNT_MASK (0xFFFFU)
#define ICP_NS_PER_SECOND (1000000000ULL)
#define ICP_INT_COL_DEFAULT_TIMER_NS 10000

/* Hardware maximum expressed in ns (~16.78 ms). */
#define ICP_INT_COL_MAX_CSR_TIMER_NS                                           \
    ((Cpa32U)(ICP_DELCNT_TO_NS(ICP_INT_COL_CTL_DELCNT_MAX)))

/* Software cap (512 us) to avoid excessive interrupt latency. */
#define ICP_INT_COL_MAX_CFG_TIMER_NS 512000U

/* Effective maximum is the lower of the hardware limit and the software cap. */
#define ICP_INT_COL_MAX_TIMER_NS                                               \
    (ICP_INT_COL_MAX_CFG_TIMER_NS < ICP_INT_COL_MAX_CSR_TIMER_NS               \
         ? ICP_INT_COL_MAX_CFG_TIMER_NS                                        \
         : ICP_INT_COL_MAX_CSR_TIMER_NS)

/* Convert a DELCNT hardware counter value to nanoseconds. */
#define ICP_DELCNT_TO_NS(cnt)                                                  \
    ((cnt)*ICP_INT_COL_CTL_CYCLES_PER_DECR * ICP_NS_PER_SECOND /               \
     ICP_INT_COL_CTL_CPP_FREQ_HZ)

/* Ring Csrs offsets */
#define ICP_RING_CSR_RING_CONFIG 0x000
#define ICP_RING_CSR_RING_LBASE 0x040
#define ICP_RING_CSR_RING_UBASE 0x080
#define ICP_RING_CSR_RING_HEAD_OFFSET 0x0C0
#define ICP_RING_CSR_RING_TAIL_OFFSET 0x100
#define ICP_RING_CSR_RING_STAT 0x140
#define ICP_RING_CSR_UO_STAT 0x148
#define ICP_RING_CSR_E_STAT 0x14C
#define ICP_RING_CSR_NE_STAT 0x150
#define ICP_RING_CSR_NF_STAT 0x154
#define ICP_RING_CSR_F_STAT 0x158
#define ICP_RING_CSR_C_STAT 0x15C
#define ICP_RING_CSR_INT_EN 0x16C
#define ICP_RING_CSR_INT_COL_EN 0x17C
#define ICP_RING_CSR_INT_COL_CTL 0x180
#define ICP_RING_CSR_FLAG_AND_COL_EN 0x184
#define ICP_RING_CSR_RING_SRV_ARB_EN 0x19C

/* RingConfig CSR Parameter Watermark Offsets */
#define RING_CONFIG_NEAR_FULL_WM 0x0A
#define RING_CONFIG_NEAR_EMPTY_WM 0x05

/* Default RingConfig is Nearly Full = Full and Nearly Empty = Empty */
#define BUILD_RING_CONFIG(size)                                                \
    ((ICP_RING_NEAR_WATERMARK_0 << RING_CONFIG_NEAR_FULL_WM) |                 \
     (ICP_RING_NEAR_WATERMARK_0 << RING_CONFIG_NEAR_EMPTY_WM) | size)

/* Response Ring Configuration */
#define BUILD_RESP_RING_CONFIG(size, watermark_nf, watermark_ne)               \
    ((watermark_nf << RING_CONFIG_NEAR_FULL_WM) |                              \
     (watermark_ne << RING_CONFIG_NEAR_EMPTY_WM) | size)

/* All Ring Base Addresses are 64 byte aligned, thus
 * bits[43:0] of the RingBase register correspond to
 * bits[49:6] of the Rings Memory Address. */

#define BUILD_RING_BASE_ADDR(addr, size)                                       \
    ((addr >> 6) & (0xFFFFFFFFFFFFFFFFULL << size))

/* CSR read/write macros */
#define READ_CSR_RING_CONFIG(bank_offset, ring)                                \
    ICP_ADF_CSR_RD(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_CONFIG + (ring << 2))

#define READ_CSR_RING_HEAD(bank_offset, ring)                                  \
    ICP_ADF_CSR_RD(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_HEAD_OFFSET + (ring << 2))

#define READ_CSR_RING_TAIL(bank_offset, ring)                                  \
    ICP_ADF_CSR_RD(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_TAIL_OFFSET + (ring << 2))

#define READ_CSR_E_STAT(bank_offset)                                           \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_E_STAT)

#define READ_CSR_E_STAT_EXT(csr_base_addr, bank_offset)                        \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_E_STAT)

#define READ_CSR_NE_STAT(bank_offset)                                          \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_NE_STAT)

#define READ_CSR_NF_STAT(bank_offset)                                          \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_NF_STAT)

#define READ_CSR_F_STAT(bank_offset)                                           \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_F_STAT)

#define READ_CSR_INT_EN(bank_offset)                                           \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_INT_EN)

#define READ_CSR_INT_COL_CTL(bank_offset)                                      \
    ICP_ADF_CSR_RD(csr_base_addr, bank_offset + ICP_RING_CSR_INT_COL_CTL)

#define WRITE_CSR_RING_CONFIG(bank_offset, ring, value)                        \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_CONFIG + (ring << 2),       \
                   value)

#define WRITE_CSR_RING_BASE(bank_offset, ring, value)                          \
    do                                                                         \
    {                                                                          \
        Cpa32U l_base = 0, u_base = 0;                                         \
        l_base = (Cpa32U)(value & 0xFFFFFFFF);                                 \
        u_base = (Cpa32U)((value & 0xFFFFFFFF00000000ULL) >> 32);              \
        ICP_ADF_CSR_WR(csr_base_addr,                                          \
                       bank_offset + ICP_RING_CSR_RING_LBASE + (ring << 2),    \
                       l_base);                                                \
        ICP_ADF_CSR_WR(csr_base_addr,                                          \
                       bank_offset + ICP_RING_CSR_RING_UBASE + (ring << 2),    \
                       u_base);                                                \
    } while (0)

static inline Cpa64U read_base(Cpa32U *csr_base_addr,
                               Cpa32U bank_offset,
                               Cpa32U ring)
{
    Cpa32U l_base = ICP_ADF_CSR_RD(
        csr_base_addr, bank_offset + ICP_RING_CSR_RING_LBASE + (ring << 2));
    Cpa32U u_base = ICP_ADF_CSR_RD(
        csr_base_addr, bank_offset + ICP_RING_CSR_RING_UBASE + (ring << 2));
    Cpa64U addr = (l_base & 0xFFFFFFFF);
    addr |= ((((Cpa64U)u_base) << 32) & 0xFFFFFFFF00000000ULL);
    return addr;
}

#define WRITE_CSR_RING_HEAD(csr_base_addr, bank_offset, ring, value)           \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_HEAD_OFFSET + (ring << 2),  \
                   value)

#define WRITE_CSR_RING_TAIL(csr_base_addr, bank_offset, ring, value)           \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_RING_TAIL_OFFSET + (ring << 2),  \
                   value)

#define WRITE_CSR_INT_COL_EN(bank_offset, value)                               \
    ICP_ADF_CSR_WR(csr_base_addr, bank_offset + ICP_RING_CSR_INT_COL_EN, value)

#define WRITE_CSR_INT_COL_EN_EXT(csr_base_addr, bank_offset, value)            \
    ICP_ADF_CSR_WR(csr_base_addr, bank_offset + ICP_RING_CSR_INT_COL_EN, value)

#define WRITE_CSR_INT_COL_CTL(bank_offset, value)                              \
    ICP_ADF_CSR_WR(csr_base_addr,                                              \
                   bank_offset + ICP_RING_CSR_INT_COL_CTL,                     \
                   ETR_CSR_INTR_COL_CTL_ENABLE | value)

/* Disable interrupt coalescing: clears the ENABLE bit entirely so the
 * hardware fires an interrupt immediately on each response. */
#define WRITE_CSR_INT_COL_CTL_DISABLE(bank_offset)                             \
    ICP_ADF_CSR_WR(csr_base_addr, bank_offset + ICP_RING_CSR_INT_COL_CTL, 0)

#define WRITE_CSR_INT_FLAG_AND_COL(bank_offset, value)                         \
    ICP_ADF_CSR_WR(                                                            \
        csr_base_addr, bank_offset + ICP_RING_CSR_FLAG_AND_COL_EN, value)

#endif /* ADF_PLATFORM_ACCELDEV_COMMON_H */
