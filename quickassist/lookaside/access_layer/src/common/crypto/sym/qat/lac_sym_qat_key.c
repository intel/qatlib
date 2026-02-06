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
