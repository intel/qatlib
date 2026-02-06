/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef QAT_COMPRESSION_ZLIB_H_
#define QAT_COMPRESSION_ZLIB_H_

#ifdef USER_SPACE
#include "zlib.h"
#else
#include <linux/zlib.h>
#endif

/**
 *****************************************************************************
 * @file qat_compression_zlib.h
 *
 * @defgroup sample_code
 *
 * @ingroup sample_code
 *
 * @description Initialize a zlib stream
 *
 * @param[in]   stream          zlib stream context
 *
 * @param[in]   sessState       initialize a stateful or stateless zlib stream
 *
 * @pre                         stream structure is already allocated
 *
 * @post                        stream is ready to be used for decompression
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      The stream could not be initialized
 ****************************************************************************/
CpaStatus inflate_init(z_stream *stream, CpaDcSessionState sessState);

/**
 *****************************************************************************
 * @file qat_compression_zlib.h
 *
 * @ingroup sample_code
 *
 * @description decompress data with a zlib stream
 *
 * @param[in]   stream          zlib stream context
 * @param[in]   src             pointer to the data to be decompressed
 * @param[in]   slen            len of data in bytes to be decompressed
 * @param[out]  dst             pointer to the decompressed output
 * @param[in]   dlen            amount of memory available for decompressed
 *                              output
 * @param[in]   sessState       initialise a stateful or stateless zlib stream
 *
 * @pre                         stream structure is already initialized
 *
 * @post                        dst contains compressed data
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      The data could not be compressed
 ****************************************************************************/
CpaStatus inflate_decompress(z_stream *stream,
                             const Cpa8U *src,
                             Cpa32U slen,
                             Cpa8U *dst,
                             Cpa32U dlen,
                             CpaDcSessionState sessState);

/**
 *****************************************************************************
 * @file qat_compression_zlib.h
 *
 * @ingroup sample_code
 *
 * @description destroy a zlib stream
 *
 * @param[in]   stream          zlib stream context
 *
 * @pre                         stream structure is already allocated
 *
 * @post                        stream can no longer be used
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      The stream could not be uninitialized
 ****************************************************************************/
void inflate_destroy(struct z_stream_s *stream);

/**
 *****************************************************************************
 * @file qat_compression_zlib.h
 *
 * @defgroup sample_code
 *
 * @ingroup sample_code
 *
 * @description Initialize a zlib stream
 *
 * @param[in]   stream          zlib stream context
 *
 * @param[in]   sessState       initialize a stateful or stateless zlib stream
 *
 * @pre                         stream structure is already allocated
 *
 * @post                        stream is ready to be used for compress
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      The stream could not be initialized
 ****************************************************************************/
CpaStatus deflate_init(z_stream *stream);

/**
 *****************************************************************************
 * @file qat_compression_zlib.h
 *
 * @ingroup sample_code
 *
 * @description compress data with a zlib stream
 *
 * @param[in]   stream          zlib stream context
 * @param[in]   src             pointer to the data to be compressed
 * @param[in]   slen            len of data in bytes to be compressed
 * @param[out]  dst             pointer to the compressed output
 * @param[in]   dlen            amount of memory available for compressed
 *                              output
 * @param[in]   zfflag          zlib flush flag. Please consult with zlib.h
 *                              for the allowed values
 *
 * @pre                         stream structure is already initialized
 *
 * @post                        dst contains compressed data
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      The data could not be compressed
 ****************************************************************************/
CpaStatus deflate_compress(z_stream *stream,
                           const Cpa8U *src,
                           Cpa32U slen,
                           Cpa8U *dst,
                           Cpa32U dlen,
                           int zfflag);

/**
 *****************************************************************************
 * @file qat_compression_zlib.h
 *
 * @ingroup sample_code
 *
 * @description destroy a zlib stream
 *
 * @param[in]   stream          zlib stream context
 *
 * @pre                         stream structure is already allocated
 *
 * @post                        stream can no longer be used
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      The stream could not be uninitialized
 ****************************************************************************/
void deflate_destroy(struct z_stream_s *stream);

#endif /* QAT_COMPRESSION_ZLIB_H_ */
