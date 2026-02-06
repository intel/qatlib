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
 * @file qat_compression_e2e.h
 * *
 * @ingroup sampleCode
 *
 * @description                 This module defines functions that show how to
 *                              use the end2end feature
 * *
 *****************************************************************************/

#ifndef QAT_COMPRESSION_E2E_H_
#define QAT_COMPRESSION_E2E_H_

/**
 *****************************************************************************
 * @file qat_compression_e2e.h
 *
 * @ingroup sample_code
 *
 * @description                 initialize the e2e members in the compression
 *                              setup structure
 *
 * @param[in]   setup           pointer to the compress test parameters
 * *
 * @pre                         setup points to an allocated memory location
 *
 * @post                        e2e members in the setup structure are
 *                              Initialized
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 * @retval CPA_STATUS_FAIL      could to initialize the setup structure
 ****************************************************************************/
CpaStatus qatCompressionE2EInit(compression_test_params_t *setup);

/**
 *****************************************************************************
 * @file qat_compression_e2e.h
 *
 * @ingroup sample_code
 *
 * @description                 this function verifies the end2end status of
 *                              a compression request
 *
 * @param[in]   setup           pointer to the compress test parameters
 * @param[in]   srcBufferList   pointer to the source buffer that was compressed
 * @param[in]   dstBufferList   pointer to the compressed output
 * @param[in]   results         pointer to the results structure used for each
 *                              compression request on scrBufferList
 * *
 * @pre                         source data has already been compressed into dst
 *                              buffer
 *
 * @post                        internal crcs are checked
 *
 * @retval CPA_STATUS_SUCCESS   dstBufferData shows no internal error occurred
 *on the data compressed
 *
 *
 * @retval CPA_STATUS_FAIL      the dst data has been compromised
 ****************************************************************************/
CpaStatus qatCompressionE2EVerify(compression_test_params_t *setup,
                                  CpaBufferList *srcBufferList,
                                  CpaBufferList *dstBufferList,
                                  CpaDcRqResults *results);

#ifdef SC_CHAINING_ENABLED
/**
 *****************************************************************************
 * @file qat_compression_e2e.h
 *
 * @ingroup sample_code
 *
 * @description                 this function verifies the end2end status of
 *                              a compression request
 *
 * @param[in]   setup           pointer to the compress test parameters
 * @param[in]   srcBufferList   pointer to the source buffer that was compressed
 * @param[in]   dstBufferList   pointer to the compressed output
 * @param[in]   results         pointer to the results structure used for each
 *                              compression request on scrBufferList
 * *
 * @pre                         source data has already been compressed into dst
 *                              buffer
 *
 * @post                        internal crcs are checked
 *
 * @retval CPA_STATUS_SUCCESS   dstBufferData shows no internal error occurred
 *on the data compressed
 *
 *
 * @retval CPA_STATUS_FAIL      the dst data has been compromised
 ****************************************************************************/
CpaStatus qatDcChainE2EVerify(compression_test_params_t *setup,
                              CpaBufferList *srcBufferList,
                              CpaBufferList *dstBufferList,
                              CpaDcChainRqResults *results);

#endif
#endif /* QAT_COMPRESSION_E2E_H_ */
