/****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
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
