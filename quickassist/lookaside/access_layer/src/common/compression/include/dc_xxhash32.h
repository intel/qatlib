/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef DC_XXHASH_H_
#define DC_XXHASH_H_

#include "cpa.h"
#include "cpa_dc.h"
#include "lac_common.h"

/**
 * @description
 *     Calculate LZ4 checksum on an input buffer
 *
 * @param[return] checksum      New LZ4 checksum value.
 * @param[in] xxH32input        Virtual addr of src input to calculate hash on.
 * @param[in] dataLength        Length in bytes the input data is.
 */
CpaStatus dcXxhash32Lz4HdrChecksum(const void *xxH32input,
                                   const Cpa32U dataLength,
                                   Cpa8U *checksum);

#endif /* end of DC_XXHASH32_H_ */
