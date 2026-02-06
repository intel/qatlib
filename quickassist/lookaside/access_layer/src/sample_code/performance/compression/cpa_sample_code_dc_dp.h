/***************************************************************************
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
 *  @param[in]  corpusType      type of corpus Calgary/Canterbury corpus
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
