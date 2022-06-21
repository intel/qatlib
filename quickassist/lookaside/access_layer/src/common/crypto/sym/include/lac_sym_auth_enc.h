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
 * @file lac_sym_auth_enc.h
 *
 * @defgroup LacAuthEnc Authenticated Encryption
 *
 * @ingroup LacSym
 *
 * @description
 *  Authenticated encryption specific functionality.
 *  For CCM related code NIST SP 800-38C is followed.
 *  For GCM related code NIST SP 800-38D is followed.
 *
 ***************************************************************************/
#ifndef LAC_SYM_AUTH_ENC_H_
#define LAC_SYM_AUTH_ENC_H_

/* This define for CCM describes constant sum of n and q */
#define LAC_ALG_CHAIN_CCM_NQ_CONST 15

/* These defines for CCM describe maximum and minimum
 * length of nonce in bytes */
#define LAC_ALG_CHAIN_CCM_N_LEN_IN_BYTES_MAX 13
#define LAC_ALG_CHAIN_CCM_N_LEN_IN_BYTES_MIN 7

/**
 * @ingroup LacAuthEnc
 * This function applies any necessary padding to additional authentication data
 * pointed by pAdditionalAuthData field of pOpData as described in
 * NIST SP 800-38D
 *
 * @param[in] pSessionDesc              Pointer to the session descriptor
 * @param[in,out] pAdditionalAuthData   Pointer to AAD
 *
 * @retval CPA_STATUS_SUCCESS          Operation finished successfully
 *
 * @pre pAdditionalAuthData has been param checked
 *
 */
void LacSymAlgChain_PrepareGCMData(lac_session_desc_t *pSessionDesc,
                                   Cpa8U *pAdditionalAuthData);

#ifdef ICP_PARAM_CHECK
/**
 * @ingroup LacAuthEnc
 * This function prepares param checks iv and aad for CCM
 *
 * @param[in,out] pAdditionalAuthData   Pointer to AAD
 * @param[in,out] pIv                   Pointer to IV
 * @param[in] messageLenToCipherInBytes Size of the message to cipher
 * @param[in] ivLenInBytes              Size of the IV
 *
 * @retval CPA_STATUS_SUCCESS          Operation finished successfully
 * @retval CPA_STATUS_INVALID_PARAM    Invalid parameter passed
 *
 */
CpaStatus LacSymAlgChain_CheckCCMData(Cpa8U *pAdditionalAuthData,
                                      Cpa8U *pIv,
                                      Cpa32U messageLenToCipherInBytes,
                                      Cpa32U ivLenInBytes);
#endif

/**
 * @ingroup LacAuthEnc
 * This function prepares Ctr0 and B0-Bn blocks for CCM algorithm as described
 * in NIST SP 800-38C. Ctr0 block is placed in pIv field of pOpData and B0-BN
 * blocks are placed in pAdditionalAuthData.
 *
 * @param[in] pSessionDesc              Pointer to the session descriptor
 * @param[in,out] pAdditionalAuthData   Pointer to AAD
 * @param[in,out] pIv                   Pointer to IV
 * @param[in] messageLenToCipherInBytes Size of the message to cipher
 * @param[in] ivLenInBytes              Size of the IV
 *
 * @retval none
 *
 * @pre parameters have been checked using LacSymAlgChain_CheckCCMData()
 */
void LacSymAlgChain_PrepareCCMData(lac_session_desc_t *pSessionDesc,
                                   Cpa8U *pAdditionalAuthData,
                                   Cpa8U *pIv,
                                   Cpa32U messageLenToCipherInBytes,
                                   Cpa32U ivLenInBytes);

#endif /* LAC_SYM_AUTH_ENC_H_ */
