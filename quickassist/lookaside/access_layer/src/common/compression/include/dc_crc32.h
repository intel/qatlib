/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef DC_CRC32_H_
#define DC_CRC32_H_

#include <cpa_types.h>
#include <cpa_dc.h>
#include "lac_common.h"
#include "dc_session.h"

/**
 * @description
 *     Calculates CRC-32 checksum for given buffer, adhering to RFC 1952 CRC
 *
 * @param[in]  initial_crc    Initial CRC-32 value (used for multi-segment calc)
 * @param[in]  buffer         Pointer to data byte array to calculate CRC on
 * @param[in]  buffer_length  Length of data array
 *
 * @retval uint32_t           32bit long CRC checksum for given buffer
 */
#ifdef USE_CCODE_CRC
uint32_t crc32_gzip_refl_base(uint32_t initial_crc,
                              uint8_t *buffer,
                              uint64_t buffer_length);
#else
extern uint32_t crc32_gzip_refl_by8(uint32_t initial_crc,
                                    uint8_t *buffer,
                                    uint64_t buffer_length);
#endif

/**
 * @description
 *     Helper function to calculate CRC32 checksum on a buffer list.
 *
 *     For a given SGL, the CRC32 checksum is calculated based on the
 *     size of the buffer list.
 *
 * @param[out] checksum       New CRC32 checksum value
 * @param[in]  pBufferList    virtual address of src SGL to calculate CRC on.
 * @param[in]  consumedBytes  total number of bytes inside of pUserSrcBuff
 *                            to calculate CRC checksum for.
 * @param[in]  seedChecksum   Input checksum from where the calculation
 *                            will start from.
 * @note
 *     currently only CRC-32 (0x4C11DB7) algorithm is supported for calculating
 *     CRCs on input and output buffers and CRC value is expected to be
 *     32bit long.
 */
Cpa32U dcCalculateCrc32(CpaBufferList *pBufferList,
                        Cpa32U consumedBytes,
                        const Cpa32U seedChecksum);

#endif /* end of DC_CRC32_H_ */
