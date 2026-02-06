/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file dc_xxhash.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the xxhash32 operation.
 *
 *****************************************************************************/
#include "dc_xxhash32.h"

/* *******************************************************************
 *  32-bit hash functions
 *********************************************************************/
static const Cpa32U XXHASH_PRIME32_A = 0x9E3779B1U;
static const Cpa32U XXHASH_PRIME32_B = 0x85EBCA77U;
static const Cpa32U XXHASH_PRIME32_C = 0xC2B2AE3DU;
static const Cpa32U XXHASH_PRIME32_D = 0x27D4EB2FU;
static const Cpa32U XXHASH_PRIME32_E = 0x165667B1U;

#define XXH32_STRIP_SIZE 16
#define ROTATE_LEFT_32(n, d) ((n << d) | (n >> (-d & 31)))

/* Static function definitions */
static Cpa32U xxh32Avalanche(Cpa32U xxHash32);
static CpaStatus calculateXxh32(const Cpa8U *xxH32input,
                                Cpa32U dataLength,
                                Cpa32U seed,
                                Cpa32U *result);
static Cpa32U xxh32ConsumeRemaining(Cpa32U xxHash32Accumulator,
                                    const Cpa8U *ptr,
                                    Cpa32U remainingBytes);

CpaStatus dcXxhash32Lz4HdrChecksum(const void *xxH32input,
                                   const Cpa32U dataLength,
                                   Cpa8U *checksum)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U result = 0;
    Cpa32U seed = 0;

    LAC_CHECK_PARAM_RANGE(dataLength, 2, 16);

    status = calculateXxh32(xxH32input, dataLength, seed, &result);

    if (CPA_STATUS_SUCCESS != status)
        return CPA_STATUS_FAIL;

    *checksum = (Cpa8U)(result >> 8) & 0xFF;

    return CPA_STATUS_SUCCESS;
}

/*Calculate the XXH32 on a block of data */
static CpaStatus calculateXxh32(const Cpa8U *xxH32input,
                                Cpa32U dataLength,
                                Cpa32U seed,
                                Cpa32U *result)
{
    Cpa32U xxHash32Accumulator = 0;
#ifdef ICP_PARAM_CHECK
    /* Check for null parameters */
    LAC_CHECK_NULL_PARAM(xxH32input);
    LAC_CHECK_NULL_PARAM(result);
#endif

    if (dataLength < XXH32_STRIP_SIZE)
        xxHash32Accumulator = seed + XXHASH_PRIME32_E;
    else
        return CPA_STATUS_FAIL;

    /* Add data length to accumulator */
    xxHash32Accumulator += (Cpa32U)dataLength;

    /* Consume the remaining bytes of input (< 16) */
    *result =
        xxh32ConsumeRemaining(xxHash32Accumulator, xxH32input, dataLength);

    return CPA_STATUS_SUCCESS;
}

static Cpa32U xxh32ConsumeRemaining(Cpa32U xxHash32Accumulator,
                                    const Cpa8U *ptr,
                                    Cpa32U remainingBytes)
{
    /* Input buffer less that 16 bytes. Each round is a block of 4 bytes(strip).
     * The bytes are processed in blocks of 4 and we keep processing until
     * we have less than 4 bytes left in the buffer */
    while (remainingBytes >= 4)
    {
        xxHash32Accumulator += *(Cpa32U *)ptr * XXHASH_PRIME32_C;
        xxHash32Accumulator =
            ROTATE_LEFT_32(xxHash32Accumulator, 17) * XXHASH_PRIME32_D;
        ptr += 4;
        remainingBytes -= 4;
    }
    /* Remaining bytes left after above calculation use following */
    while (remainingBytes > 0)
    {
        xxHash32Accumulator += (*ptr++) * XXHASH_PRIME32_E;
        xxHash32Accumulator =
            ROTATE_LEFT_32(xxHash32Accumulator, 11) * XXHASH_PRIME32_A;
        remainingBytes -= 1;
    }

    return xxh32Avalanche(xxHash32Accumulator);
}

static Cpa32U xxh32Avalanche(Cpa32U xxHash32)
{
    xxHash32 ^= xxHash32 >> 15;
    xxHash32 *= XXHASH_PRIME32_B;
    xxHash32 ^= xxHash32 >> 13;
    xxHash32 *= XXHASH_PRIME32_C;
    xxHash32 ^= xxHash32 >> 16;
    return (xxHash32);
}
