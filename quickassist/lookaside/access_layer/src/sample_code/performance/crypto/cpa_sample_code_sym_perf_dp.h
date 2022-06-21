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
 * @file cpa_sample_code_sym_perf_dp.h
 *
 * @defgroup sampleSymmetricDpPerf  Symmetric Data Plane Performance code
 *
 * @ingroup sampleSymmetricDpPerf
 *
 * @description
 *      This file contains function prototype and macro definition
 *      for symmetric Data Plane performance sample code.
 *
 *****************************************************************************/
#ifndef CPA_SAMPLE_CODE_SYM_PERF_DP_H_
#define CPA_SAMPLE_CODE_SYM_PERF_DP_H_

#include "cpa_sample_code_crypto_utils.h"
#include "cpa_cy_sym_dp.h"
/** Macro definition **/

/* Symmetric DP operation Type
 * SYM_DP_ENQUEUEING: Enqueue operation will submit one operation
 * into the queue list at one time
 */
#define SYM_DP_ENQUEUEING (0)
/* Symmetric DP operation perform flag
 * if setup->numRequests is equal to SYM_DP_PERFORM_NOW_FLAG,
 * the operation should be performed immediately (performOpNow is CPA_TRUE),
 * otherwise enqueued to be performed later (performOpNow = CPA_FALSE).
 */
#define SYM_DP_PERFORM_NOW_FLAG (1)

/* init value for AdditionalAuthData when Snow3g */
#define SYM_AUTH_INIT_VALUE (0XAA)

/* Symmetric DP min num loop */
#define SYM_DP_MIN_NUM_LOOP (1)

/* lv field offset for CPA_CY_SYM_CIPHER_AES_CCM */
#define SYM_DP_LV_OFFSET_CCM (1)

#define SYM_DP_SINGLE_SESSION (1)

#define SYM_DP_NUM_BUFFERS (5000)

/* step back for the dynamic algorithm */
#define SYM_BACKOFF_STEP_BACK 20
/* step forward for the dynamic algorithm */
#define SYM_BACKOFF_STEP_FORWARD 10 * SYM_BACKOFF_STEP_BACK
/* maximum value of the dynamic backoff delay  */
#define SYM_BACKOFF_TIMER_MAX 10000

/** Function Declaration**/

/**
*****************************************************************************
* @ingroup sampleSymmetricDpPerf
*   setup a symmetric test
*
* @description
* This function needs to be called from main to setup a symmetric test.
* then the framework createThreads function is used to propagate this setup
* across cores using different crypto logical instances.
*
* @param[in] opType                    operation type
* @param[in] cipherAlg                 Indicates cipher algorithms and modes
* @param[in] cipherKeyLengthInBytes    The length of cipher key in bytes
* @param[in] priority                  The level of priority
* @param[in] hashAlg                   Indicates hash algorithm
* @param[in] hashMode                  Mode of Hash algorithm
* @param[in] authKeyLengthInBytes      The length of Authentication key in
*                                      bytes.
* @param[in] chainOrder                If this opType is an chaining algorithm
*                                      then this parameter determines the order
*                                      in which the operations are chained.
*                                      If this opType isn't chaining algorithm
*                                      then this parameter will be ignored.
* @param[in] syncMode                  Sync Mode of the test: async and sync
* @param[in] nestedModeSetupDataPtr    The pointer of Hash Mode Nested Setup
*                                      Data
* @param[in] packetSize                Data packet size of array
* @param[in] numDpOpBatch              How many Op at one time. if
*                                      numOpDpBatch >0, enqueue multiple
*                                      requests with one operation.
*                                      Otherwise, perform a single symmetric
*                                      request
* @param[in] numRequests               How many requests will be submitted
*                                      at one time:
*                                      numRequests = 1: enqueue a single
*                                      request and perform symmetric operation
*                                      immediately.
*                                      otherwise : enqueue numRequests before
*                                      calling API to perform the operations.
* @param[in] numSessions               The number Of session per test thread.
* @param[in] bufferSizeInBytes         The Length Of flat buffer per buffer
*                                      list. If bufferSizeInBytes is 0,
*                                      it will only provide physical address
*                                      to srcbuffer/destbuffer in OpData.
* @param[in] numBuffLists              The number of buffers List,a minimum
*                                      of 1024 buffers should be used in the
*                                      sample code to ensure that both RX/TX
*                                      rings are full during performance
*                                      operations. This also ensures that
*                                      in-flight requests are not being
*                                      resubmitted before being returned by the
*                                      driver.
* @param[in] numLoops                  The number of Loops
*
* @retval CPA_STATUS_SUCCESS           Function executed successfully.
* @retval CPA_STATUS_FAIL              Function failed.
* @retval CPA_STATUS_INVALID_PARAM     Invalid parameter passed in.
*
*****************************************************************************/
CpaStatus setupSymmetricDpTest(
    CpaCySymOp opType,
    CpaCySymCipherAlgorithm cipherAlg,
    Cpa32U cipherKeyLengthInBytes,
    Cpa32U cipherOffset,
    CpaCyPriority priority,
    CpaCySymHashAlgorithm hashAlg,
    CpaCySymHashMode hashMode,
    Cpa32U authKeyLengthInBytes,
    CpaCySymAlgChainOrder chainOrder,
    sync_mode_t syncMode,
    CpaCySymHashNestedModeSetupData *nestedModeSetupDataPtr,
    Cpa32U packetSize,
    Cpa32U numDpBatchOp,
    Cpa32U numRequests,
    Cpa32U numSessions,
    Cpa32U numBuffers,
    Cpa32U numBuffLists,
    Cpa32U numLoops,
    Cpa32U digestAppend,
    CpaBoolean isTLS);

/**
*****************************************************************************
* @ingroup sampleSymmetricDpPerf
*   setup a cipher test
*
* @description
* This function needs to be called from main to setup a cipher test.
* then the framework createThreads function is used to propagate this setup
* across cores using different crypto logical instances.
*
* @param[in] cipherAlg                 Indicates cipher algorithms and modes
* @param[in] cipherKeyLengthInBytes    The length of cipher key in bytes
* @param[in] priority                  The level of priority
* @param[in] syncMode                  Sync Mode of the test: async and sync
* @param[in] packetSize                Data packet size of array
* @param[in] numDpOpBatch              How many Op at one time. if
*                                      numOpDpBatch >0, enqueue multiple
*                                      requests with one operation.
*                                      Otherwise, perform a single symmetric
*                                      request
* @param[in] numRequests               How many requests will be submitted
*                                      at one time:
*                                      numRequests = 1: enqueue a single
*                                      request and perform symmetric operation
*                                      immediately.
*                                      otherwise : enqueue numRequests before
*                                      calling API to perform the operations.
* @param[in] numSessions               The number Of session per test thread.
* @param[in] numBuffLists              The number of buffers List,a minimum
*                                      of 1024 buffers should be used in the
*                                      sample code to ensure that both RX/TX
*                                      rings are full during performance
*                                      operations. This also ensures that
*                                      in-flight requests are not being
*                                      resubmitted before being returned by the
*                                      driver.
* @param[in] numLoops                  The number of Loops
*
* @retval CPA_STATUS_SUCCESS           Function executed successfully.
* @retval CPA_STATUS_FAIL              Function failed.
* @retval CPA_STATUS_INVALID_PARAM     Invalid parameter passed in.
*****************************************************************************/
CpaStatus setupCipherDpTest(CpaCySymCipherAlgorithm cipherAlg,
                            Cpa32U cipherKeyLengthInBytes,
                            CpaCyPriority priority,
                            sync_mode_t syncMode,
                            Cpa32U packetSize,
                            Cpa32U numDpBatchOp,
                            Cpa32U flatBufferSize,
                            Cpa32U numRequests,
                            Cpa32U numSessions,
                            Cpa32U numBuffLists,
                            Cpa32U numLoops);

/**
*****************************************************************************
* @ingroup sampleSymmetricDpPerf
*   setup a hash test
*
* @description
* This function needs to be called from main to setup a hash test.
* then the framework createThreads function is used to propagate this setup
* across cores using different crypto logical instances.
*
* @param[in] hashAlg                   Indicates hash algorithm
* @param[in] hashMode                  Mode of Hash algorithm
* @param[in] authKeyLengthInBytes      The length of Authentication key in
*                                      bytes.
* @param[in] priority                  The level of priority
* @param[in] syncMode                  Sync Mode of the test: async and sync
* @param[in] packetSize                Data packet size of array
* @param[in] numDpOpBatch              How many Op at one time. if
*                                      numOpDpBatch >0, enqueue multiple
*                                      requests with one operation.
*                                      Otherwise, perform a single symmetric
*                                      request
* @param[in] numRequests               How many requests will be submitted
*                                      at one time:
*                                      numRequests = 1: enqueue a single
*                                      request and perform symmetric operation
*                                      immediately.
*                                      otherwise : enqueue numRequests before
*                                      calling API to perform the operations.
* @param[in] numSessions               The number Of session per test thread.
* @param[in] numBuffLists              The number of buffers List,a minimum
*                                      of 1024 buffers should be used in the
*                                      sample code to ensure that both RX/TX
*                                      rings are full during performance
*                                      operations. This also ensures that
*                                      in-flight requests are not being
*                                      resubmitted before being returned by the
*                                      driver.
* @param[in] numLoops                  The number of Loops
*
* @retval CPA_STATUS_SUCCESS           Function executed successfully.
* @retval CPA_STATUS_FAIL              Function failed.
* @retval CPA_STATUS_INVALID_PARAM     Invalid parameter passed in.
*****************************************************************************/
CpaStatus setupHashDpTest(CpaCySymHashAlgorithm hashAlg,
                          CpaCySymHashMode hashMode,
                          Cpa32U authKeyLengthInBytes,
                          CpaCyPriority priority,
                          sync_mode_t syncMode,
                          Cpa32U packetSize,
                          Cpa32U numDpBatchOp,
                          Cpa32U numRequests,
                          Cpa32U numSessions,
                          Cpa32U numBuffLists,
                          Cpa32U numLoops);

/**
*****************************************************************************
* @ingroup sampleSymmetricDpPerf
*    setup a alg chain test (default High Priority)
*
* @description
* This function needs to be called from main to setup an alg chain test.
* then the framework createThreads function is used to propagate this setup
* across IA cores using different crypto logical instances
*
* @param[in] cipherAlg                 Indicates cipher algorithms and modes
* @param[in] cipherKeyLengthInBytes    The length of cipher key in bytes
* @param[in] hashAlg                   Indicates hash algorithm
* @param[in] hashMode                  Mode of Hash algorithm
* @param[in] authKeyLengthInBytes      the length of Authentication key in
*                                      bytes
* @param[in] chainOrder                If this opType is an chaining algorithm
*                                      then this parameter determines the order
*                                      in which the operations are chained.
*                                      If this opType isn't chaining algorithm
*                                      then this parameter will be ignored.
* @param[in] syncMode                  Sync Mode of the test: async and sync
* @param[in] packetSize                Data packet size of array
* @param[in] numDpOpBatch              How many Op at one time. if
*                                      numOpDpBatch >0, enqueue multiple
*                                      requests with one operation.
*                                      Otherwise, perform a single symmetric
*                                      request
* @param[in] numRequests               How many requests will be submitted
*                                      at one time:
*                                      numRequests = 1: enqueue a single
*                                      request and perform symmetric operation
*                                      immediately.
*                                      otherwise : enqueue numRequests before
*                                      calling API to perform the operations.
* @param[in] numSessions               The number Of session per test thread.
* @param[in] numBuffLists              The number of buffers List,a minimum
*                                      of 1024 buffers should be used in the
*                                      sample code to ensure that both RX/TX
*                                      rings are full during performance
*                                      operations. This also ensures that
*                                      in-flight requests are not being
*                                      resubmitted before being returned by the
*                                      driver.
* @param[in] numLoops                  The number of Loops
*
* @retval CPA_STATUS_SUCCESS           Function executed successfully.
* @retval CPA_STATUS_FAIL              Function failed.
* @retval CPA_STATUS_INVALID_PARAM     Invalid parameter passed in.
*****************************************************************************/
CpaStatus setupAlgChainDpTest(CpaCySymCipherAlgorithm cipherAlg,
                              Cpa32U cipherKeyLengthInBytes,
                              CpaCySymHashAlgorithm hashAlg,
                              CpaCySymHashMode hashMode,
                              Cpa32U authKeyLengthInBytes,
                              CpaCySymAlgChainOrder chainOrder,
                              CpaCyPriority priority,
                              sync_mode_t syncMode,
                              Cpa32U packetSize,
                              Cpa32U numDpBatchOp,
                              Cpa32U flatBufferSize,
                              Cpa32U numRequests,
                              Cpa32U numSessions,
                              Cpa32U numBuffLists,
                              Cpa32U numLoops);

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup an IPsec scenario where payload = IP packet, the IP header is not
 * encrypted thus requires an offset into the buffer to test.
 *
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupIpSecDpTest(CpaCySymCipherAlgorithm cipherAlg,
                           Cpa32U cipherKeyLengthInBytes,
                           Cpa32U cipherOffset,
                           CpaCySymHashAlgorithm hashAlg,
                           CpaCySymHashMode hashMode,
                           Cpa32U authKeyLengthInBytes,
                           CpaCySymAlgChainOrder chainOrder,
                           Cpa32U packetSize,
                           Cpa32U numDpBatchOp,
                           Cpa32U numRequests,
                           Cpa32U numSessions,
                           Cpa32U numBuffLists,
                           Cpa32U numLoops);

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a TLS scenario where packet size passed in represents the size of
 * the payload data. Seq num, header, MAC and padding will get added to packet
 * so it will be bigger.
 *
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupTLSDpTest(CpaCySymCipherAlgorithm cipherAlg,
                         Cpa32U cipherKeyLengthInBytes,
                         Cpa32U cipherOffset,
                         CpaCySymHashAlgorithm hashAlg,
                         CpaCySymHashMode hashMode,
                         Cpa32U authKeyLengthInBytes,
                         CpaCySymAlgChainOrder chainOrder,
                         Cpa32U packetSize,
                         Cpa32U numDpBatchOp,
                         Cpa32U numRequests,
                         Cpa32U numSessions,
                         Cpa32U numBuffLists,
                         Cpa32U numLoops);

/**
*****************************************************************************
* @ingroup sampleSymmetricDpPerf
*  setup a alg chain nested mode test for data plane API.
*
* @description
*      This function needs to be called from main to setup an alg chain test.
*      then the framework createThreads function is used to propagate this
*      setup across IA cores using different crypto logical instances.
*
* @param[in] cipherAlg                 Indicates cipher algorithms and modes
* @param[in] cipherKeyLengthInBytes    The length of cipher key in bytes
* @param[in] hashAlg                   Indicates hash algorithms
* @param[in] authKeyLengthInBytes      the length of Authentication key in
*                                      bytes
* @param[in] chainOrder                If this opType is an chaining algorithm
*                                      then this parameter determines the order
*                                      in which the operations are chained.
*                                      If this opType isn't chaining algorithm
*                                      then this parameter will be ignored.
* @param[in] priority                  The level of priority
* @param[in] syncMode                  Sync Mode of the test: async and sync
* @param[in] nestedModeSetupData       Hash Mode Nested Setup Data
* @param[in] packetSize                Data packet size of array
* @param[in] numDpOpBatch              How many Op at one time. if
*                                      numOpDpBatch >0, enqueue multiple
*                                      requests with one operation.
*                                      Otherwise, perform a single symmetric
*                                      request
* @param[in] numRequests               How many requests will be submitted
*                                      at one time:
*                                      numRequests = 1: enqueue a single
*                                      request and perform symmetric operation
*                                      immediately.
*                                      otherwise : enqueue numRequests before
*                                      calling API to perform the operations.
* @param[in] numSessions               The number Of session per test thread.
* @param[in] numBuffLists              The number of buffers List,a minimum
*                                      of 1024 buffers should be used in the
*                                      sample code to ensure that both RX/TX
*                                      rings are full during performance
*                                      operations. This also ensures that
*                                      in-flight requests are not being
*                                      resubmitted before being returned by the
*                                      driver.
* @param[in] numLoops                  The number of Loops
*
* @retval CPA_STATUS_SUCCESS        Function executed successfully.
* @retval CPA_STATUS_FAIL           Function failed.
* @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
*****************************************************************************/
CpaStatus setupAlgChainTestDpNestedMode(
    CpaCySymCipherAlgorithm cipherAlg,
    Cpa32U cipherKeyLengthInBytes,
    CpaCySymHashAlgorithm hashAlg,
    Cpa32U authKeyLengthInBytes,
    CpaCySymAlgChainOrder chainOrder,
    CpaCyPriority priority,
    sync_mode_t syncMode,
    CpaCySymHashNestedModeSetupData *nestedModeSetupData,
    Cpa32U packetSize,
    Cpa32U numDpOpBatch,
    Cpa32U numRequests,
    Cpa32U numSessions,
    Cpa32U numBuffLists,
    Cpa32U numLoops);

#endif /* CPA_SAMPLE_CODE_SYM_PERF_DP_H_ */
