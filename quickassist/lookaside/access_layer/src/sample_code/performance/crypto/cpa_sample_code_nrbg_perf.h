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
 ***************************************************************************
 * @file cpa_sample_code_nrbg_perf.h
 *
 * @defgroup sampleNrbgFunctional
 *
 * @ingroup sampleCode
 *
 * @description
 *     Non-Deterministic Random Bit Generation Performance Sample Code
 *functions.
 *
 ***************************************************************************/
#ifndef CPA_SAMPLE_CODE_NRBG_PERF_H
#define CPA_SAMPLE_CODE_NRBG_PERF_H
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_cy_nrbg.h"
#include "icp_sal_nrbg_ht.h"
#include "cpa.h"

/*************************************************************************
 * @ingroup sampleNrbgFunctional
 *
 * @description
 *    This function starts the crypto instance and registers NRBG
 *    functions.
 *
 * @param[in] syncMode					Sync Mode of the test: async and sync
 * @param[in] nLenInBytes				Data length of Non-Deterministic Random
 Bit
 *                                      Generation, unit is byte, must be more
 than 0.
 * @param[in] numBuffers				The number of buffers List,a minimum
 * @param[in] numLoops					The number of Loops
 * @context
 *      This functions is called from the user process context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes

 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *************************************************************************/
CpaStatus setupNrbgTest(Cpa32U nLenInBytes,
                        sync_mode_t syncMode,
                        Cpa32U numBuffers,
                        Cpa32U numLoops);

#endif
