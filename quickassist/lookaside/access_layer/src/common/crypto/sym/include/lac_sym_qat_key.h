/******************************************************************************
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
 *****************************************************************************/

/**
 *****************************************************************************
 * @file lac_sym_qat_key.h
 *
 * @defgroup LacSymQatKey  Key QAT
 *
 * @ingroup LacSymQat
 *
 * interfaces for populating qat structures for a key operation
 *
 *****************************************************************************/

#ifndef LAC_SYM_QAT_KEY_H
#define LAC_SYM_QAT_KEY_H

#include "cpa.h"
#include "lac_sym.h"
#include "icp_qat_fw_la.h"
#include "cpa_cy_key.h"

/**
******************************************************************************
* @ingroup LacSymQatKey
*      Number of bytes generated per iteration
* @description
*      This define is the number of bytes generated per iteration
*****************************************************************************/
#define LAC_SYM_QAT_KEY_SSL_BYTES_PER_ITERATION (16)

/**
******************************************************************************
* @ingroup LacSymQatKey
*      Shift to calculate the number of iterations
* @description
*      This define is the shift to calculate the number of iterations
*****************************************************************************/
#define LAC_SYM_QAT_KEY_SSL_ITERATIONS_SHIFT LAC_16BYTE_ALIGNMENT_SHIFT

/**
*******************************************************************************
* @ingroup LacSymKey
*      Populate the SSL request
*
* @description
*      Populate the SSL request
*
* @param[out] pKeyGenReqHdr            Pointer to Key Generation request Header
* @param[out] pKeyGenReqMid            Pointer to LW's 14/15 of Key Gen request
* @param[in] generatedKeyLenInBytes    Length of Key generated
* @param[in] labelLenInBytes           Length of Label
* @param[in] secretLenInBytes          Length of Secret
* @param[in] iterations                Number of iterations. This is related
*                                      to the label length.
*
* @return None
*
*****************************************************************************/
void LacSymQat_KeySslRequestPopulate(
    icp_qat_la_bulk_req_hdr_t *pKeyGenReqHdr,
    icp_qat_fw_la_key_gen_common_t *pKeyGenReqMid,
    Cpa32U generatedKeyLenInBytes,
    Cpa32U labelLenInBytes,
    Cpa32U secretLenInBytes,
    Cpa32U iterations);

/**
*******************************************************************************
* @ingroup LacSymKey
*      Populate the TLS request
*
* @description
*      Populate the TLS request
*
* @param[out] pKeyGenReq               Pointer to Key Generation request
* @param[in] generatedKeyLenInBytes    Length of Key generated
* @param[in] labelLenInBytes           Length of Label
* @param[in] secretLenInBytes          Length of Secret
* @param[in] seedLenInBytes            Length of Seed
* @param[in] cmdId                     Command Id to differentiate TLS versions
*
* @return None
*
*****************************************************************************/
void LacSymQat_KeyTlsRequestPopulate(
    icp_qat_fw_la_key_gen_common_t *pKeyGenReqParams,
    Cpa32U generatedKeyLenInBytes,
    Cpa32U labelLenInBytes,
    Cpa32U secretLenInBytes,
    Cpa8U seedLenInBytes,
    icp_qat_fw_la_cmd_id_t cmdId);

/**
*******************************************************************************
* @ingroup LacSymKey
*      Populate MGF request
*
* @description
*      Populate MGF request
*
* @param[out] pKeyGenReqHdr      Pointer to Key Generation request Header
* @param[out] pKeyGenReqMid      Pointer to LW's 14/15 of Key Gen request
* @param[in] seedLenInBytes      Length of Seed
* @param[in] maskLenInBytes      Length of Mask
* @param[in] hashLenInBytes      Length of hash
*
* @return None
*
*****************************************************************************/
void LacSymQat_KeyMgfRequestPopulate(
    icp_qat_la_bulk_req_hdr_t *pKeyGenReqHdr,
    icp_qat_fw_la_key_gen_common_t *pKeyGenReqMid,
    Cpa8U seedLenInBytes,
    Cpa16U maskLenInBytes,
    Cpa8U hashLenInBytes);

/**
*******************************************************************************
* @ingroup LacSymKey
*      Populate the SSL key material input
*
* @description
*      Populate the SSL key material input
*
* @param[in] pService                  Pointer to service
* @param[out] pSslKeyMaterialInput     Pointer to SSL key material input
* @param[in] pSeed                     Pointer to Seed
* @param[in] labelPhysAddr             Physical address of the label
* @param[in] pSecret                   Pointer to Secret
*
* @return None
*
*****************************************************************************/
void LacSymQat_KeySslKeyMaterialInputPopulate(
    sal_service_t *pService,
    icp_qat_fw_la_ssl_key_material_input_t *pSslKeyMaterialInput,
    void *pSeed,
    Cpa64U labelPhysAddr,
    void *pSecret);

/**
*******************************************************************************
* @ingroup LacSymKey
*      Populate the TLS key material input
*
* @description
*      Populate the TLS key material input
*
* @param[in] pService                  Pointer to service
* @param[out] pTlsKeyMaterialInput   Pointer to TLS key material input
* @param[in] pSeed                   Pointer to Seed
* @param[in] labelPhysAddr             Physical address of the label
*
* @return None
*
*****************************************************************************/
void LacSymQat_KeyTlsKeyMaterialInputPopulate(
    sal_service_t *pService,
    icp_qat_fw_la_tls_key_material_input_t *pTlsKeyMaterialInput,
    void *pSeed,
    Cpa64U labelPhysAddr);

/**
*******************************************************************************
* @ingroup LacSymKey
*      Populate the TLS HKDF key material input
*
* @description
*      Populate the TLS HKDF key material input
*
* @param[in] pService                  Pointer to service
* @param[out] pTlsHKDFKeyMaterialInput Pointer to HKDF TLS key material input
* @param[in] pKeyGenTlsHKDFOpData      Pointer to HKDF key data
* @param[in] sublabelPhysAddr          Physical address of the sub label
* @param[in] cmdId                     Command ID
*
* @return None
*
*****************************************************************************/
void LacSymQat_KeyTlsHKDFKeyMaterialInputPopulate(
    sal_service_t *pService,
    icp_qat_fw_la_hkdf_key_material_input_t *pTlsHKDFKeyMaterialInput,
    CpaCyKeyGenHKDFOpData *pKeyGenTlsHKDFOpData,
    Cpa64U subLabelPhysAddr,
    icp_qat_fw_la_cmd_id_t cmdId);

#endif /* LAC_SYM_QAT_KEY_H */
