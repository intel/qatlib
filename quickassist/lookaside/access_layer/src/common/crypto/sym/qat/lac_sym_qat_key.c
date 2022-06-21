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
 * @file lac_sym_qat_key.c Interfaces for populating the symmetric qat key
 *  structures
 *
 * @ingroup LacSymQatKey
 *
 *****************************************************************************/

#include "cpa.h"
#include "lac_mem.h"
#include "icp_qat_fw_la.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"
#include "lac_list.h"
#include "lac_sal_types.h"
#include "lac_sym_qat_key.h"
#include "lac_sym_hash_defs.h"

void LacSymQat_KeySslRequestPopulate(
    icp_qat_la_bulk_req_hdr_t *pKeyGenReqHdr,
    icp_qat_fw_la_key_gen_common_t *pKeyGenReqMid,
    Cpa32U generatedKeyLenInBytes,
    Cpa32U labelLenInBytes,
    Cpa32U secretLenInBytes,
    Cpa32U iterations)
{
    /* Rounded to nearest 8 byte boundary */
    Cpa8U outLenRounded = 0;
    LAC_ENSURE_NOT_NULL(pKeyGenReqHdr);
    LAC_ENSURE_NOT_NULL(pKeyGenReqMid);
    outLenRounded =
        LAC_ALIGN_POW2_ROUNDUP(generatedKeyLenInBytes, LAC_QUAD_WORD_IN_BYTES);

    pKeyGenReqMid->u.secret_lgth_ssl = (Cpa16U)secretLenInBytes;
    pKeyGenReqMid->u1.s1.output_lgth_ssl = outLenRounded;
    pKeyGenReqMid->u1.s1.label_lgth_ssl = (Cpa8U)labelLenInBytes;
    pKeyGenReqMid->u2.iter_count = (Cpa8U)iterations;
    pKeyGenReqMid->u3.resrvd2 = 0;
    pKeyGenReqMid->resrvd3 = 0;

    /* Set up the common LA flags */
    pKeyGenReqHdr->comn_hdr.service_cmd_id = ICP_QAT_FW_LA_CMD_SSL3_KEY_DERIVE;
    pKeyGenReqHdr->comn_hdr.resrvd1 = 0;
}

void LacSymQat_KeyTlsRequestPopulate(
    icp_qat_fw_la_key_gen_common_t *pKeyGenReqParams,
    Cpa32U generatedKeyLenInBytes,
    Cpa32U labelInfo,
    Cpa32U secretLenInBytes,
    Cpa8U seedLenInBytes,
    icp_qat_fw_la_cmd_id_t cmdId)
{
    LAC_ENSURE_NOT_NULL(pKeyGenReqParams);

    pKeyGenReqParams->u1.s3.output_lgth_tls =
        LAC_ALIGN_POW2_ROUNDUP(generatedKeyLenInBytes, LAC_QUAD_WORD_IN_BYTES);

    /* For TLS u param of auth_req_params is set to secretLen */
    pKeyGenReqParams->u.secret_lgth_tls = (Cpa16U)secretLenInBytes;

    switch (cmdId)
    {
        case ICP_QAT_FW_LA_CMD_HKDF_EXTRACT:
            pKeyGenReqParams->u2.hkdf_ikm_length = (Cpa8U)secretLenInBytes;
            pKeyGenReqParams->u3.resrvd2 = 0;
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXPAND:
            pKeyGenReqParams->u1.hkdf.info_length = (Cpa8U)labelInfo;
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND:
            pKeyGenReqParams->u2.hkdf_ikm_length = (Cpa8U)secretLenInBytes;
            pKeyGenReqParams->u1.hkdf.info_length = (Cpa8U)labelInfo;
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXPAND_LABEL:
            /* Num of Labels */
            pKeyGenReqParams->u1.hkdf_label.num_labels = (Cpa8U)labelInfo;
            pKeyGenReqParams->u3.hkdf_num_sublabels =
                CPA_CY_HKDF_KEY_MAX_LABEL_COUNT;
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND_LABEL:
            pKeyGenReqParams->u2.hkdf_ikm_length = (Cpa8U)secretLenInBytes;
            /* Num of Labels */
            pKeyGenReqParams->u1.hkdf_label.num_labels = (Cpa8U)labelInfo;
            pKeyGenReqParams->u3.hkdf_num_sublabels =
                CPA_CY_HKDF_KEY_MAX_LABEL_COUNT;
            break;
        default:
            pKeyGenReqParams->u1.s3.label_lgth_tls = (Cpa8U)labelInfo;
            pKeyGenReqParams->u2.tls_seed_length = seedLenInBytes;
            pKeyGenReqParams->u3.resrvd2 = 0;
            break;
    }
    pKeyGenReqParams->resrvd3 = 0;
}

void LacSymQat_KeyMgfRequestPopulate(
    icp_qat_la_bulk_req_hdr_t *pKeyGenReqHdr,
    icp_qat_fw_la_key_gen_common_t *pKeyGenReqMid,
    Cpa8U seedLenInBytes,
    Cpa16U maskLenInBytes,
    Cpa8U hashLenInBytes)
{
    LAC_ENSURE_NOT_NULL(pKeyGenReqHdr);
    LAC_ENSURE_NOT_NULL(pKeyGenReqMid);

    pKeyGenReqHdr->comn_hdr.service_cmd_id = ICP_QAT_FW_LA_CMD_MGF1;
    pKeyGenReqMid->u.mask_length =
        LAC_ALIGN_POW2_ROUNDUP(maskLenInBytes, LAC_QUAD_WORD_IN_BYTES);

    pKeyGenReqMid->u1.s2.hash_length = hashLenInBytes;
    pKeyGenReqMid->u1.s2.seed_length = seedLenInBytes;
}

void LacSymQat_KeySslKeyMaterialInputPopulate(
    sal_service_t *pService,
    icp_qat_fw_la_ssl_key_material_input_t *pSslKeyMaterialInput,
    void *pSeed,
    Cpa64U labelPhysAddr,
    void *pSecret)
{
    LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
        (*pService), pSslKeyMaterialInput->seed_addr, pSeed);

    pSslKeyMaterialInput->label_addr = labelPhysAddr;

    LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
        (*pService), pSslKeyMaterialInput->secret_addr, pSecret);
}

void LacSymQat_KeyTlsKeyMaterialInputPopulate(
    sal_service_t *pService,
    icp_qat_fw_la_tls_key_material_input_t *pTlsKeyMaterialInput,
    void *pSeed,
    Cpa64U labelPhysAddr)
{
    LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
        (*pService), pTlsKeyMaterialInput->seed_addr, pSeed);

    pTlsKeyMaterialInput->label_addr = labelPhysAddr;
}

void LacSymQat_KeyTlsHKDFKeyMaterialInputPopulate(
    sal_service_t *pService,
    icp_qat_fw_la_hkdf_key_material_input_t *pTlsHKDFKeyMaterialInput,
    CpaCyKeyGenHKDFOpData *pKeyGenTlsHKDFOpData,
    Cpa64U subLabelPhysAddr,
    icp_qat_fw_la_cmd_id_t cmdId)
{
    switch (cmdId)
    {
        case ICP_QAT_FW_LA_CMD_HKDF_EXTRACT:
            LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
                (*pService),
                pTlsHKDFKeyMaterialInput->ikm_addr,
                pKeyGenTlsHKDFOpData->secret);
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXPAND:
            LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
                (*pService),
                pTlsHKDFKeyMaterialInput->labels_addr,
                pKeyGenTlsHKDFOpData->info);
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND:
            LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
                (*pService),
                pTlsHKDFKeyMaterialInput->ikm_addr,
                pKeyGenTlsHKDFOpData->secret);
            pTlsHKDFKeyMaterialInput->labels_addr =
                pTlsHKDFKeyMaterialInput->ikm_addr +
                ((LAC_ARCH_UINT)&pKeyGenTlsHKDFOpData->info -
                 (LAC_ARCH_UINT)&pKeyGenTlsHKDFOpData->secret);
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXPAND_LABEL:
            pTlsHKDFKeyMaterialInput->sublabels_addr = subLabelPhysAddr;
            LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
                (*pService),
                pTlsHKDFKeyMaterialInput->labels_addr,
                pKeyGenTlsHKDFOpData->label);
            break;
        case ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND_LABEL:
            pTlsHKDFKeyMaterialInput->sublabels_addr = subLabelPhysAddr;
            LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
                (*pService),
                pTlsHKDFKeyMaterialInput->ikm_addr,
                pKeyGenTlsHKDFOpData->secret);
            pTlsHKDFKeyMaterialInput->labels_addr =
                pTlsHKDFKeyMaterialInput->ikm_addr +
                ((LAC_ARCH_UINT)&pKeyGenTlsHKDFOpData->label -
                 (LAC_ARCH_UINT)&pKeyGenTlsHKDFOpData->secret);
            break;
        default:
            break;
    }
}
