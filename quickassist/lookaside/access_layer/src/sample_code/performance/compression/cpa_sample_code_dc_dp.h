/***************************************************************************
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

/**
 *****************************************************************************
 * @file cpa_sample_code_dc_dp.h
 *
 * @defgroup compressionThreads
 *
 * @ingroup compressionThreads
 *
 * @description
 * Contains function prototypes and #defines used throughout code
 * and macros
 *
 ***************************************************************************/
#ifndef CPA_SAMPLE_CODE_DC_DP_H_
#define CPA_SAMPLE_CODE_DC_DP_H_

#include "cpa.h"
#include "cpa_dc.h"
#include "cpa_dc_dp.h"
#include "cpa_sample_code_dc_perf.h"

/* step back for the dynamic algorithm */
#define DP_BACKOFF_STEP_BACK 20
/* step forward for the dynamic algorithm */
#define DP_BACKOFF_STEP_FORWARD 10 * DP_BACKOFF_STEP_BACK
/* maximum value of the dynamic backoff delay  */
#define DP_BACKOFF_TIMER_MAX 10000

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  setupDpDcTest
 *
 *  @description
 *      this API is the main API called by the framework, this is configures
 *      data structure before starting the performance threads
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *  @param[in]  algorithm       Algorithm used for compression/decompression
 *  @param[in]  direction       session direction
 *  @param[in]  compLevel       compression Level
 *  @param[in]  HuffmanType     HuffMantype Dynamic/static
 *  @param[in]  testBuffersize  size of the flat Buffer to use
 *  @parma[in]  corpusType      type of corpus Calgary/Canterbury corpus
 *  @param[in]  syncFlag        synchronous/Asynchronous operation
 *  @param[in]  dpTestType      If set to DC_DP_BATCHING, then the number of
 *                              requests to batch is set by the numRequests
 *                              parameter.
 *                              If set to DC_DP_ENQUEUEING, then a single
 *                              request is Enqueued.
 *  @param[in]  numRequests     How many requests to submit in a single call for
 *                              Batch Mode, currently > 1 requests is not
 *                              supported in Enqueue Mode.
 *  @param[in]  numloops        Number of loops to compress or decompress
 ******************************************************************************/
CpaStatus setupDcDpTest(CpaDcCompType algorithm,
                        CpaDcSessionDir direction,
                        CpaDcCompLvl compLevel,
                        CpaDcHuffType huffmanType,
                        Cpa32U windowSize,
                        Cpa32U testBufferSize,
                        corpus_type_t corpusType,
                        sync_mode_t syncFlag,
                        dp_request_type_t dpTestType,
                        Cpa32U numRequests,
                        Cpa32U numLoops);

#endif /* CPA_SAMPLE_CODE_DC_DP_H_ */
