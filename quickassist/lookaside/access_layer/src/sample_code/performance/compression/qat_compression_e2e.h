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
