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
 * @file adf_platform_common.h
 *
 * @description
 *      This file contains the macros common to supported platform(s).
 *
 *****************************************************************************/
#ifndef ADF_PLATFORM_COMMON_H
#define ADF_PLATFORM_COMMON_H

/* Number of Rings Per Bank */
#define ICP_ETR_MAX_RINGS_PER_BANK 16

#define ICP_ADF_BYTES_PER_WORD 4

/* Ring size values. Name reflects num bytes, value is for RingBufferSize field
 * in RingConfig CSR */
#define ICP_RINGSIZE_64 0x00
#define ICP_RINGSIZE_128 0x01
#define ICP_RINGSIZE_256 0x02
#define ICP_RINGSIZE_512 0x03
#define ICP_RINGSIZE_KILO_1 0x04
#define ICP_RINGSIZE_KILO_2 0x05
#define ICP_RINGSIZE_KILO_4 0x06
#define ICP_RINGSIZE_KILO_8 0x07
#define ICP_RINGSIZE_KILO_16 0x08
#define ICP_RINGSIZE_KILO_32 0x09
#define ICP_RINGSIZE_KILO_64 0x0A
#define ICP_RINGSIZE_KILO_128 0x0B
#define ICP_RINGSIZE_KILO_256 0x0C
#define ICP_RINGSIZE_KILO_512 0x0D
#define ICP_RINGSIZE_MEG_1 0x0E
#define ICP_RINGSIZE_MEG_2 0x0F
#define ICP_RINGSIZE_MEG_4 0x10

/* Ring Near Full/Empty watermarks values */
#define ICP_RING_NEAR_WATERMARK_0 0x00
#define ICP_RING_NEAR_WATERMARK_4 0x01
#define ICP_RING_NEAR_WATERMARK_8 0x02
#define ICP_RING_NEAR_WATERMARK_16 0x03
#define ICP_RING_NEAR_WATERMARK_32 0x04
#define ICP_RING_NEAR_WATERMARK_64 0x05
#define ICP_RING_NEAR_WATERMARK_128 0x06
#define ICP_RING_NEAR_WATERMARK_256 0x07
#define ICP_RING_NEAR_WATERMARK_512 0x08
#define ICP_RING_NEAR_WATERMARK_KILO_1 0x09
#define ICP_RING_NEAR_WATERMARK_KILO_2 0x0A
#define ICP_RING_NEAR_WATERMARK_KILO_4 0x0B
#define ICP_RING_NEAR_WATERMARK_KILO_8 0x0C
#define ICP_RING_NEAR_WATERMARK_KILO_16 0x0D
#define ICP_RING_NEAR_WATERMARK_KILO_32 0x0E
#define ICP_RING_NEAR_WATERMARK_KILO_64 0x0F
#define ICP_RING_NEAR_WATERMARK_KILO_128 0x10
#define ICP_RING_NEAR_WATERMARK_KILO_256 0x11

/* Bundle size */
#define ICP_BUNDLE_SIZE 0x1000

/* For coalescing based on number of messages define the required ring message
 * count, and the limits on the allowed thresholds.
 */
#define ICP_NUM_COAL_MSG_CNT 256
#define ICP_NUM_COAL_MSG_MIN_USED 2
#define ICP_NUM_COAL_MSG_MIN_FREE 8

/* Interrupt source values */
#define INT_SRC_N_FULL_TRUE 2
#define INT_SRC_EMPTY_FALSE 4
#define INT_SRC_N_EMPTY_FALSE 5

/* Defines for the IAIntSrcSel register setup */
#define IAINTSRCSEL_REG_MAX_RING_IN_REG 7
#define IAINTSRCSEL_REG_RINGS_PER_REG 8
#define IAINTSRCSEL_REG_BITSPERRING 4
#define IAINTSRCSEL_REG_IRQ_MODE_BIT 3
#define IAINTSRCSEL_REG_RING_VAL_MASK 0xF

/* Modulo shifts for different ring sizes */
#define MODULO_SHIFT_FOR_64 6
#define MODULO_SHIFT_FOR_128 7
#define MODULO_SHIFT_FOR_256 8
#define MODULO_SHIFT_FOR_512 9
#define MODULO_SHIFT_FOR_1K 10
#define MODULO_SHIFT_FOR_2K 11
#define MODULO_SHIFT_FOR_4K 12
#define MODULO_SHIFT_FOR_8K 13
#define MODULO_SHIFT_FOR_16K 14
#define MODULO_SHIFT_FOR_32K 15
#define MODULO_SHIFT_FOR_64K 16
#define MODULO_SHIFT_FOR_128K 17
#define MODULO_SHIFT_FOR_256K 18
#define MODULO_SHIFT_FOR_512K 19
#define MODULO_SHIFT_FOR_1M 20
#define MODULO_SHIFT_FOR_2M 21
#define MODULO_SHIFT_FOR_4M 22

/* Ring size conversion - only for use with ICP_RINGSIZE_xxx cfg values above */
#define ICP_ET_SIZE_TO_BYTES(size) (64 << (size))

/* Ring watermark conversion */
#define ICP_ET_WATERMARK_TO_BYTES(wm) ((wm == 0) ? 0 : (4 << (wm - 1)))

/* Default ring size */
#define ICP_ET_DEFAULT_RING_SIZE ICP_RINGSIZE_KILO_16

/* Default modulo shift - must correspond to the default ring size */
#define ICP_ET_DEFAULT_MODULO_SHIFT MODULO_SHIFT_FOR_16K

#define ADF_MSG_SIZE_64_BYTES 64
#define ADF_MSG_SIZE_128_BYTES 128

/* Default message size in bytes */
#define ICP_ET_DEFAULT_MSG_SIZE ADF_MSG_SIZE_64_BYTES

/* Minimum ring free space is the size of one msg on the ring plus this value */
#define ICP_ET_RING_MIN_FREE_SPACE_ADDON 1

/* Set the response quota to a high number. */
#define ICP_NO_RESPONSE_QUOTA 10000

/* Translates from a ringNum (integer) to a ringmaskId (bit mask) */
#define RING_NUMBER_TO_ID(ring_num) (1 << ring_num)

/*
 * Internal parameter to describe user polling method in kernel space.
 * This must be set to a value higher than the max icp_resp_deliv_method.
 * and less than the width of the Cpa32U type.
 */
#define ADF_RESP_TYPE_USER_POLL 31

/* Number of responses we need to get before we update the head
 * in a Rx ring. NOTE: this needs to be smaller than
 * min ring size - 8 msg for NF threashold. */
#define MIN_RESPONSES_PER_HEAD_WRITE 32

/*
 * Fast message copy functions for userspace
 *
 * There are several versions of fast memcpy, i.e. adf_memcpyxx_yy
 *     xx refers to arch, i.e.64bit or 32bit
 *     yy refers to number of bytes copied from src to dst, i.e. 64 or 128 bytes
 */
#ifdef __x86_64__
#define adf_memcpy64_64(dst, src)                                              \
    do                                                                         \
    {                                                                          \
        __asm__ __volatile__("mov %0, %%rsi \n"                                \
                             "mov %1, %%rdi \n"                                \
                             "movdqu (%%rsi), %%xmm0 \n"                       \
                             "movdqu 16(%%rsi), %%xmm1 \n"                     \
                             "movdqu 32(%%rsi), %%xmm2 \n"                     \
                             "movdqu 48(%%rsi), %%xmm3 \n"                     \
                             "movdqu %%xmm0, (%%rdi) \n"                       \
                             "movdqu %%xmm1, 16(%%rdi) \n"                     \
                             "movdqu %%xmm2, 32(%%rdi) \n"                     \
                             "movdqu %%xmm3, 48(%%rdi) \n"                     \
                             : /* no output */                                 \
                             : "r"(src), "r"(dst)                              \
                             : "%esi", "%edi");                                \
    } while (0);
#define adf_memcpy64_128(dst, src)                                             \
    do                                                                         \
    {                                                                          \
        __asm__ __volatile__("mov %0, %%rsi \n"                                \
                             "mov %1, %%rdi \n"                                \
                             "movdqu (%%rsi), %%xmm0 \n"                       \
                             "movdqu 16(%%rsi), %%xmm1 \n"                     \
                             "movdqu 32(%%rsi), %%xmm2 \n"                     \
                             "movdqu 48(%%rsi), %%xmm3 \n"                     \
                             "movdqu 64(%%rsi), %%xmm4 \n"                     \
                             "movdqu 80(%%rsi), %%xmm5 \n"                     \
                             "movdqu 96(%%rsi), %%xmm6 \n"                     \
                             "movdqu 112(%%rsi), %%xmm7 \n"                    \
                             "movdqu %%xmm0, (%%rdi) \n"                       \
                             "movdqu %%xmm1, 16(%%rdi) \n"                     \
                             "movdqu %%xmm2, 32(%%rdi) \n"                     \
                             "movdqu %%xmm3, 48(%%rdi) \n"                     \
                             "movdqu %%xmm4, 64(%%rdi) \n"                     \
                             "movdqu %%xmm5, 80(%%rdi) \n"                     \
                             "movdqu %%xmm6, 96(%%rdi) \n"                     \
                             "movdqu %%xmm7, 112(%%rdi) \n"                    \
                             : /* no output */                                 \
                             : "r"(src), "r"(dst)                              \
                             : "%esi", "%edi");                                \
    } while (0);
#define adf_memcpy64 adf_memcpy64_64
#define adf_memcpy128 adf_memcpy64_128
#else
/*
 * 32bit versions of fast memcpy
 */
#define adf_memcpy32_64(dst, src)                                              \
    do                                                                         \
    {                                                                          \
        __asm__ __volatile__("mov %0, %%esi \n"                                \
                             "mov %1, %%edi \n"                                \
                             "movdqu (%%esi), %%xmm0 \n"                       \
                             "movdqu 16(%%esi), %%xmm1 \n"                     \
                             "movdqu 32(%%esi), %%xmm2 \n"                     \
                             "movdqu 48(%%esi), %%xmm3 \n"                     \
                             "movdqu %%xmm0, (%%edi) \n"                       \
                             "movdqu %%xmm1, 16(%%edi) \n"                     \
                             "movdqu %%xmm2, 32(%%edi) \n"                     \
                             "movdqu %%xmm3, 48(%%edi) \n"                     \
                             : /* no output */                                 \
                             : "r"(src), "r"(dst)                              \
                             : "%esi", "%edi");                                \
    } while (0);
#define adf_memcpy32_128(dst, src)                                             \
    do                                                                         \
    {                                                                          \
        __asm__ __volatile__("mov %0, %%esi \n"                                \
                             "mov %1, %%edi \n"                                \
                             "movdqu (%%esi), %%xmm0 \n"                       \
                             "movdqu 16(%%esi), %%xmm1 \n"                     \
                             "movdqu 32(%%esi), %%xmm2 \n"                     \
                             "movdqu 48(%%esi), %%xmm3 \n"                     \
                             "movdqu 64(%%esi), %%xmm4 \n"                     \
                             "movdqu 80(%%esi), %%xmm5 \n"                     \
                             "movdqu 96(%%esi), %%xmm6 \n"                     \
                             "movdqu 112(%%esi), %%xmm7 \n"                    \
                             "movdqu %%xmm0, (%%edi) \n"                       \
                             "movdqu %%xmm1, 16(%%edi) \n"                     \
                             "movdqu %%xmm2, 32(%%edi) \n"                     \
                             "movdqu %%xmm3, 48(%%edi) \n"                     \
                             "movdqu %%xmm4, 64(%%edi) \n"                     \
                             "movdqu %%xmm5, 80(%%edi) \n"                     \
                             "movdqu %%xmm6, 96(%%edi) \n"                     \
                             "movdqu %%xmm7, 112(%%edi) \n"                    \
                             : /* no output */                                 \
                             : "r"(src), "r"(dst)                              \
                             : "%esi", "%edi");                                \
    } while (0);
#define adf_memcpy64 adf_memcpy32_64
#define adf_memcpy128 adf_memcpy32_128
#endif

/* modulo function that doesnt use slow divide operation */
static inline unsigned int modulo(unsigned int data, unsigned int shift)
{
    unsigned int div = data >> shift;
    unsigned int mult = div << shift;
    return data - mult;
}

/* Ring controler CSR Accessor Macros */
/* CSR write macro */
#define ICP_ADF_CSR_WR(csrAddr, csrOffset, val)                                \
    (void)((*((volatile Cpa32U *)(((Cpa8U *)csrAddr) + csrOffset)) = (val)))

/* CSR read macro */
#define ICP_ADF_CSR_RD(csrAddr, csrOffset)                                     \
    (*((volatile Cpa32U *)(((Cpa8U *)csrAddr) + csrOffset)))

#endif /* ADF_PLATFORM_COMMON_H */
