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

#define WRITE_CSR_INT_FLAG_AND_COL(bank_offset, value)                         \
    ICP_ADF_CSR_WR(                                                            \
        csr_base_addr, bank_offset + ICP_RING_CSR_FLAG_AND_COL_EN, value)

#endif /* ADF_PLATFORM_ACCELDEV_COMMON_H */
