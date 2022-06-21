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
 * @file dc_session.c
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the Data Compression session operations.
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include public/global header files
 *******************************************************************************
 */
#include "cpa.h"
#include "cpa_dc.h"

#include "icp_qat_fw.h"
#include "icp_qat_fw_comp.h"
#include "icp_qat_hw.h"
#include "icp_qat_hw_20_comp.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "dc_session.h"
#include "dc_datapath.h"
#include "lac_mem_pools.h"
#include "sal_types_compression.h"
#include "lac_buffer_desc.h"
#include "sal_service_state.h"
#include "sal_qat_cmn_msg.h"

#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check that pSessionData is valid
 *
 * @description
 *      Check that all the parameters defined in the pSessionData are valid
 *
 * @param[in]       pSessionData     Pointer to a user instantiated structure
 *                                   containing session data
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported algorithm/feature
 *
 *****************************************************************************/
STATIC CpaStatus dcCheckSessionData(const CpaDcSessionSetupData *pSessionData,
                                    CpaInstanceHandle dcInstance)
{
    CpaDcInstanceCapabilities instanceCapabilities = {0};

    cpaDcQueryCapabilities(dcInstance, &instanceCapabilities);

    if ((pSessionData->compLevel < CPA_DC_L1) ||
        (pSessionData->compLevel > CPA_DC_L12))
    {
        LAC_INVALID_PARAM_LOG("Invalid compLevel value");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((pSessionData->autoSelectBestHuffmanTree < CPA_DC_ASB_DISABLED) ||
        (pSessionData->autoSelectBestHuffmanTree > CPA_DC_ASB_ENABLED))
    {
        LAC_INVALID_PARAM_LOG("Invalid autoSelectBestHuffmanTree value");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((pSessionData->compType < CPA_DC_DEFLATE) ||
        (pSessionData->compType > CPA_DC_LZ4S))
    {
        LAC_INVALID_PARAM_LOG("Invalid compType value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pSessionData->huffType < CPA_DC_HT_STATIC) ||
        (pSessionData->huffType > CPA_DC_HT_FULL_DYNAMIC) ||
        (CPA_DC_HT_PRECOMP == pSessionData->huffType))
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pSessionData->sessDirection < CPA_DC_DIR_COMPRESS) ||
        (pSessionData->sessDirection > CPA_DC_DIR_COMBINED))
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pSessionData->sessState < CPA_DC_STATEFUL) ||
        (pSessionData->sessState > CPA_DC_STATELESS))
    {
        LAC_INVALID_PARAM_LOG("Invalid sessState value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pSessionData->checksum < CPA_DC_NONE) ||
        (pSessionData->checksum > CPA_DC_XXHASH32))
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_XXHASH32 == pSessionData->checksum &&
        CPA_DC_DEFLATE == pSessionData->compType)
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum type for DEFLATE compression");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((CPA_DC_LZ4 == pSessionData->compType) &&
        (CPA_DC_XXHASH32 != pSessionData->checksum) &&
        (CPA_DC_NONE != pSessionData->checksum))
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum type for LZ4 compression");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((CPA_DC_LZ4S == pSessionData->compType) &&
        (CPA_DC_NONE != pSessionData->checksum) &&
        (CPA_DC_XXHASH32 != pSessionData->checksum))
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum type for LZ4S compression");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_LZ4 == pSessionData->compType)
    {
        if ((pSessionData->lz4BlockMaxSize < CPA_DC_LZ4_MAX_BLOCK_SIZE_64K) ||
            (pSessionData->lz4BlockMaxSize > CPA_DC_LZ4_MAX_BLOCK_SIZE_4M))
        {
            LAC_INVALID_PARAM_LOG("Invalid LZ4 Block Max Size value.");
            return CPA_STATUS_INVALID_PARAM;
        }
        if (CPA_FALSE != pSessionData->lz4BlockChecksum &&
            CPA_TRUE != pSessionData->lz4BlockChecksum)
        {
            LAC_INVALID_PARAM_LOG("Invalid LZ4 Block checksum setting.");
            return CPA_STATUS_INVALID_PARAM;
        }
        if (CPA_FALSE != pSessionData->lz4BlockIndependence &&
            CPA_TRUE != pSessionData->lz4BlockIndependence)
        {
            LAC_INVALID_PARAM_LOG("Invalid LZ4 Block independence setting.");
            return CPA_STATUS_INVALID_PARAM;
        }
        if (CPA_FALSE != pSessionData->accumulateXXHash &&
            CPA_TRUE != pSessionData->accumulateXXHash)
        {
            LAC_INVALID_PARAM_LOG("Invalid LZ4 accumulateXXHash setting.");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_DC_LZ4S == pSessionData->compType)
    {
        if ((pSessionData->minMatch < CPA_DC_MIN_3_BYTE_MATCH) ||
            (pSessionData->minMatch > CPA_DC_MIN_4_BYTE_MATCH))
        {
            LAC_INVALID_PARAM_LOG("Invalid LZ4S Min match value.");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    return CPA_STATUS_SUCCESS;
}
#endif

static void setBlockIndep(icp_qat_hw_comp_20_config_csr_upper_t *conf)
{
    conf->scb_mode_reset =
        ICP_QAT_HW_COMP_20_SCB_MODE_RESET_MASK_RESET_COUNTERS_AND_HISTORY;
}

static void setBlockDep(icp_qat_hw_comp_20_config_csr_upper_t *conf)
{
    conf->scb_mode_reset =
        ICP_QAT_HW_COMP_20_SCB_MODE_RESET_MASK_RESET_COUNTERS;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression hardware block
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      the size in bytes of the block
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 *
 *****************************************************************************/
STATIC void dcCompHwBlockPopulate(sal_compression_service_t *pService,
                                  dc_session_desc_t *pSessionDesc,
                                  icp_qat_hw_compression_config_t *pCompConfig,
                                  dc_request_dir_t compDecomp)
{
    icp_qat_hw_compression_direction_t dir =
        ICP_QAT_HW_COMPRESSION_DIR_COMPRESS;
    icp_qat_hw_compression_algo_t algo = ICP_QAT_HW_COMPRESSION_ALGO_DEFLATE;
    icp_qat_hw_compression_depth_t depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
    icp_qat_hw_compression_file_type_t filetype =
        ICP_QAT_HW_COMPRESSION_FILE_TYPE_0;
    icp_qat_hw_compression_delayed_match_t dmm;

    /* Set the direction */
    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
        dir = ICP_QAT_HW_COMPRESSION_DIR_COMPRESS;
    }
    else
    {
        dir = ICP_QAT_HW_COMPRESSION_DIR_DECOMPRESS;
    }

    if (CPA_DC_DEFLATE == pSessionDesc->compType)
    {
        algo = ICP_QAT_HW_COMPRESSION_ALGO_DEFLATE;
    }
    else
    {
        LAC_ENSURE(CPA_FALSE, "Algorithm not supported for Compression\n");
    }

    /* Set delay match mode */
    if (CPA_TRUE == pService->comp_device_data.enableDmm)
    {
        dmm = ICP_QAT_HW_COMPRESSION_DELAYED_MATCH_ENABLED;
    }
    else
    {
        dmm = ICP_QAT_HW_COMPRESSION_DELAYED_MATCH_DISABLED;
    }

    /* Set the depth */
    if (DC_DECOMPRESSION_REQUEST == compDecomp)
    {
        depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
    }
    else
    {
        switch (pSessionDesc->compLevel)
        {
            case CPA_DC_L1:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
                break;
            case CPA_DC_L2:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_4;
                break;
            case CPA_DC_L3:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_8;
                break;
            default:
                depth = ICP_QAT_HW_COMPRESSION_DEPTH_16;
        }
    }

    /* The file type is set to ICP_QAT_HW_COMPRESSION_FILE_TYPE_0. The other
     * modes will be used in the future for precompiled huffman trees */
    filetype = ICP_QAT_HW_COMPRESSION_FILE_TYPE_0;

    pCompConfig->lower_val =
        ICP_QAT_HW_COMPRESSION_CONFIG_BUILD(dir, dmm, algo, depth, filetype);

    /* Upper 32-bits of the configuration word do not need to be
     * configured with legacy devices.
     */
    pCompConfig->upper_val = 0;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression hardware block for CPM 2.0
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      for CPM 2.0 the size in bytes of the block
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 *
 *****************************************************************************/
STATIC void dcCompHwBlockPopulateGen4(
    sal_compression_service_t *pService,
    dc_session_desc_t *pSessionDesc,
    icp_qat_hw_compression_config_t *pCompConfig,
    dc_request_dir_t compDecomp)
{
    /* Direction: Compression */
    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
        icp_qat_hw_comp_20_config_csr_upper_t hw_comp_upper_csr;
        icp_qat_hw_comp_20_config_csr_lower_t hw_comp_lower_csr;

        osalMemSet(&hw_comp_upper_csr, 0, sizeof hw_comp_upper_csr);
        osalMemSet(&hw_comp_lower_csr, 0, sizeof hw_comp_lower_csr);

        /* Disable Literal + Length Limit Block Drop by default */
        hw_comp_lower_csr.lllbd = ICP_QAT_HW_COMP_20_LLLBD_CTRL_LLLBD_DISABLED;

        switch (pSessionDesc->compType)
        {
            case CPA_DC_DEFLATE:
                /* DEFLATE algorithm settings */
                hw_comp_lower_csr.skip_ctrl =
                    ICP_QAT_HW_COMP_20_BYTE_SKIP_3BYTE_LITERAL;

                if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
                {
                    hw_comp_lower_csr.algo =
                        ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_ILZ77;
                }
                else /* Static DEFLATE */
                {
                    hw_comp_lower_csr.algo =
                        ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_DEFLATE;
                    hw_comp_upper_csr.scb_ctrl =
                        ICP_QAT_HW_COMP_20_SCB_CONTROL_DISABLE;
                }

                if (CPA_DC_STATEFUL == pSessionDesc->sessState)
                {
                    hw_comp_upper_csr.som_ctrl =
                        ICP_QAT_HW_COMP_20_SOM_CONTROL_REPLAY_MODE;
                }
                break;
            case CPA_DC_LZ4:
                /* LZ4 algorithm settings */
                hw_comp_lower_csr.algo = ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_LZ4;
                hw_comp_upper_csr.lbms = pSessionDesc->lz4BlockMaxSize;
                hw_comp_lower_csr.mmctrl =
                    ICP_QAT_HW_COMP_20_MIN_MATCH_CONTROL_MATCH_4B;

                if (CPA_TRUE == pSessionDesc->lz4BlockIndependence)
                {
                    setBlockIndep(&hw_comp_upper_csr);
                }
                else
                {
                    setBlockDep(&hw_comp_upper_csr);
                }
                break;
            case CPA_DC_LZ4S:
                /* LZ4S algorithm settings */
                hw_comp_lower_csr.algo = ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_LZ4S;
                hw_comp_lower_csr.mmctrl = pSessionDesc->minMatch;
                hw_comp_upper_csr.scb_ctrl =
                    ICP_QAT_HW_COMP_20_SCB_CONTROL_DISABLE;
                break;
            default:
                LAC_ENSURE(CPA_FALSE, "Compression algorithm not supported\n");
                break;
        }

        /* Set the search depth */
        switch (pSessionDesc->compLevel)
        {
            case CPA_DC_L1:
            case CPA_DC_L2:
            case CPA_DC_L3:
            case CPA_DC_L4:
            case CPA_DC_L5:
                hw_comp_lower_csr.sd = ICP_QAT_HW_COMP_20_SEARCH_DEPTH_LEVEL_1;
                hw_comp_lower_csr.hash_col =
                    ICP_QAT_HW_COMP_20_SKIP_HASH_COLLISION_DONT_ALLOW;
                break;
            case CPA_DC_L6:
            case CPA_DC_L7:
            case CPA_DC_L8:
                hw_comp_lower_csr.sd = ICP_QAT_HW_COMP_20_SEARCH_DEPTH_LEVEL_6;
                break;
            case CPA_DC_L9:
                hw_comp_lower_csr.sd = ICP_QAT_HW_COMP_20_SEARCH_DEPTH_LEVEL_9;
                break;
            default:
                hw_comp_lower_csr.sd =
                    pService->comp_device_data.highestHwCompressionDepth;
                if ((CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType) &&
                    (CPA_DC_DEFLATE == pSessionDesc->compType))
                {
                    /* Enable Literal + Length Limit Block Drop
                     * with dynamic deflate compression when
                     * highest compression levels are selected.
                     */
                    hw_comp_lower_csr.lllbd =
                        ICP_QAT_HW_COMP_20_LLLBD_CTRL_LLLBD_ENABLED;
                }
                break;
        }

        /* Same for all algorithms */
        hw_comp_lower_csr.abd = ICP_QAT_HW_COMP_20_ABD_ABD_DISABLED;
        hw_comp_lower_csr.hash_update =
            ICP_QAT_HW_COMP_20_SKIP_HASH_UPDATE_DONT_ALLOW;
        hw_comp_lower_csr.edmm =
            (CPA_TRUE == pService->comp_device_data.enableDmm)
                ? ICP_QAT_HW_COMP_20_EXTENDED_DELAY_MATCH_MODE_EDMM_ENABLED
                : ICP_QAT_HW_COMP_20_EXTENDED_DELAY_MATCH_MODE_EDMM_DISABLED;

        /* Hard-coded HW-specific values */
        hw_comp_upper_csr.nice =
            ICP_QAT_HW_COMP_20_CONFIG_CSR_NICE_PARAM_DEFAULT_VAL;
        hw_comp_upper_csr.lazy =
            ICP_QAT_HW_COMP_20_CONFIG_CSR_LAZY_PARAM_DEFAULT_VAL;

        pCompConfig->upper_val =
            ICP_QAT_FW_COMP_20_BUILD_CONFIG_UPPER(hw_comp_upper_csr);

        pCompConfig->lower_val =
            ICP_QAT_FW_COMP_20_BUILD_CONFIG_LOWER(hw_comp_lower_csr);
    }
    else /* Direction: Decompression */
    {
        icp_qat_hw_decomp_20_config_csr_lower_t hw_decomp_lower_csr;

        osalMemSet(&hw_decomp_lower_csr, 0, sizeof hw_decomp_lower_csr);

        /* Set the algorithm */
        if (CPA_DC_DEFLATE == pSessionDesc->compType)
        {
            hw_decomp_lower_csr.algo =
                ICP_QAT_HW_DECOMP_20_HW_DECOMP_FORMAT_DEFLATE;
        }
        else if (CPA_DC_LZ4 == pSessionDesc->compType)
        {
            hw_decomp_lower_csr.algo = ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_LZ4;
            hw_decomp_lower_csr.lbms = pSessionDesc->lz4BlockMaxSize;
            if (CPA_TRUE == pSessionDesc->lz4BlockChecksum)
            {
                hw_decomp_lower_csr.lbc =
                    ICP_QAT_HW_DECOMP_20_LZ4_BLOCK_CHKSUM_PRESENT;
            }
            else
            {
                hw_decomp_lower_csr.lbc =
                    ICP_QAT_HW_DECOMP_20_LZ4_BLOCK_CHKSUM_ABSENT;
            }
        }
        else if (CPA_DC_LZ4S == pSessionDesc->compType)
        {
            hw_decomp_lower_csr.algo = ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_LZ4S;
            hw_decomp_lower_csr.mmctrl = pSessionDesc->minMatch;
        }
        else
        {
            LAC_ENSURE(CPA_FALSE,
                       "Algorithm not supported for Decompression\n");
        }

        pCompConfig->upper_val = 0;
        pCompConfig->lower_val =
            ICP_QAT_FW_DECOMP_20_BUILD_CONFIG_LOWER(hw_decomp_lower_csr);
    }
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression content descriptor
 *
 * @description
 *      This function will populate the compression content descriptor
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   contextBufferAddrPhys   Physical address of the context buffer
 * @param[out]  pMsg                    Pointer to the compression message
 * @param[in]   nextSlice               Next slice
 * @param[in]   compDecomp              Direction of the operation
 *
 *****************************************************************************/
STATIC void dcCompContentDescPopulate(sal_compression_service_t *pService,
                                      dc_session_desc_t *pSessionDesc,
                                      CpaPhysicalAddr contextBufferAddrPhys,
                                      icp_qat_fw_comp_req_t *pMsg,
                                      icp_qat_fw_slice_t nextSlice,
                                      dc_request_dir_t compDecomp)
{

    icp_qat_fw_comp_cd_hdr_t *pCompControlBlock = NULL;
    icp_qat_hw_compression_config_t *pCompConfig = NULL;
    CpaBoolean bankEnabled = CPA_FALSE;

    LAC_ENSURE_NOT_NULL(pService);
    LAC_ENSURE_NOT_NULL(pSessionDesc);
    LAC_ENSURE_NOT_NULL(pMsg);

    pCompControlBlock = (icp_qat_fw_comp_cd_hdr_t *)&(pMsg->comp_cd_ctrl);
    pCompConfig = (icp_qat_hw_compression_config_t *)(pMsg->cd_pars.sl
                                                          .comp_slice_cfg_word);

    ICP_QAT_FW_COMN_NEXT_ID_SET(pCompControlBlock, nextSlice);
    ICP_QAT_FW_COMN_CURR_ID_SET(pCompControlBlock, ICP_QAT_FW_SLICE_COMP);

    pCompControlBlock->comp_cfg_offset = 0;

    if ((CPA_DC_STATEFUL == pSessionDesc->sessState) &&
        (CPA_DC_DEFLATE == pSessionDesc->compType) &&
        (DC_DECOMPRESSION_REQUEST == compDecomp))
    {
        /* Enable A, B, C, D, and E (CAMs).  */
        pCompControlBlock->ram_bank_flags = ICP_QAT_FW_COMP_RAM_FLAGS_BUILD(
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank I */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank H */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank G */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank F */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank E */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank D */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank C */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank B */
            ICP_QAT_FW_COMP_BANK_ENABLED); /* Bank A */
        bankEnabled = CPA_TRUE;
    }
    else if ((CPA_DC_STATEFUL == pSessionDesc->sessState) &&
             (CPA_DC_LZ4 == pSessionDesc->compType) &&
             (DC_DECOMPRESSION_REQUEST == compDecomp))
    {
        /* Enable A, B, C, and D (no CAMs for LZ4). */
        pCompControlBlock->ram_bank_flags = ICP_QAT_FW_COMP_RAM_FLAGS_BUILD(
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank I */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank H */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank G */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank F */
            ICP_QAT_FW_COMP_BANK_DISABLED, /* Bank E */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank D */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank C */
            ICP_QAT_FW_COMP_BANK_ENABLED,  /* Bank B */
            ICP_QAT_FW_COMP_BANK_ENABLED); /* Bank A */
        bankEnabled = CPA_TRUE;
    }
    else
    {
        /* Disable all banks */
        pCompControlBlock->ram_bank_flags = ICP_QAT_FW_COMP_RAM_FLAGS_BUILD(
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank I */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank H */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank G */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank F */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank E */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank D */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank C */
            ICP_QAT_FW_COMP_BANK_DISABLED,  /* Bank B */
            ICP_QAT_FW_COMP_BANK_DISABLED); /* Bank A */
    }

    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
        LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
            pService->generic_service_info,
            pCompControlBlock->comp_state_addr,
            pSessionDesc->stateRegistersComp);
    }
    else
    {
        LAC_MEM_SHARED_WRITE_VIRT_TO_PHYS_PTR_EXTERNAL(
            pService->generic_service_info,
            pCompControlBlock->comp_state_addr,
            pSessionDesc->stateRegistersDecomp);
    }

    if (CPA_TRUE == bankEnabled)
    {
        pCompControlBlock->ram_banks_addr = contextBufferAddrPhys;
    }
    else
    {
        pCompControlBlock->ram_banks_addr = 0;
    }

    pCompControlBlock->resrvd = 0;

    /* Populate Compression Hardware Setup Block */
    if (pService->generic_service_info.isGen4)
    {
        dcCompHwBlockPopulateGen4(
            pService, pSessionDesc, pCompConfig, compDecomp);
    }
    else
    {
        dcCompHwBlockPopulate(pService, pSessionDesc, pCompConfig, compDecomp);
    }
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the translator content descriptor
 *
 * @description
 *      This function will populate the translator content descriptor
 *
 * @param[out]  pMsg                     Pointer to the compression message
 * @param[in]   nextSlice                Next slice
 *
 *****************************************************************************/
STATIC void dcTransContentDescPopulate(icp_qat_fw_comp_req_t *pMsg,
                                       icp_qat_fw_slice_t nextSlice)
{

    icp_qat_fw_xlt_cd_hdr_t *pTransControlBlock = NULL;
    LAC_ENSURE_NOT_NULL(pMsg);
    pTransControlBlock = (icp_qat_fw_xlt_cd_hdr_t *)&(pMsg->u2.xlt_cd_ctrl);
    LAC_ENSURE_NOT_NULL(pTransControlBlock);

    ICP_QAT_FW_COMN_NEXT_ID_SET(pTransControlBlock, nextSlice);
    ICP_QAT_FW_COMN_CURR_ID_SET(pTransControlBlock, ICP_QAT_FW_SLICE_XLAT);

    pTransControlBlock->resrvd1 = 0;
    pTransControlBlock->resrvd2 = 0;
    pTransControlBlock->resrvd3 = 0;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Get the context size and the history size
 *
 * @description
 *      This function will get the size of the context buffer and the history
 *      buffer. The history buffer is a subset of the context buffer and its
 *      size is needed for stateful compression.

 * @param[in]   dcInstance         DC Instance Handle
 *
 * @param[in]   pSessionData       Pointer to a user instantiated
 *                                 structure containing session data
 * @param[out]  pContextSize       Pointer to the context size
 *
 * @retval CPA_STATUS_SUCCESS      Function executed successfully
 *
 *
 *****************************************************************************/
STATIC CpaStatus dcGetContextSize(CpaInstanceHandle dcInstance,
                                  CpaDcSessionSetupData *pSessionData,
                                  Cpa32U *pContextSize)
{
    sal_compression_service_t *pCompService = NULL;

    pCompService = (sal_compression_service_t *)dcInstance;

    *pContextSize = 0;
    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_DIR_COMPRESS != pSessionData->sessDirection))
    {
        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pContextSize =
                    pCompService->comp_device_data.inflateContextSize;
                break;
            case CPA_DC_LZ4:
                *pContextSize =
                    pCompService->comp_device_data.lz4DecompContextSize;
                break;
            default:
                LAC_LOG_ERROR("Invalid compression algorithm.");
                return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Get the compression command id for the given session setup data.
 *
 * @description
 *      This function will get the compression command id based on parameters
 *passed in the given session stup data.
 * @param[in]   pService           Pointer to the service
 *
 * @param[in]   pSessionData       Pointer to a user instantiated
 *                                 structure containing session data
 * @param[out]  pDcCmdId           Pointer to the command id
 *
 * @retval CPA_STATUS_SUCCESS      Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED  Unsupported algorithm/feature
 *
 *****************************************************************************/
STATIC CpaStatus dcGetCompressCommandId(sal_compression_service_t *pService,
                                        CpaDcSessionSetupData *pSessionData,
                                        Cpa8U *pDcCmdId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pService);
    LAC_CHECK_NULL_PARAM(pSessionData);
    LAC_CHECK_NULL_PARAM(pDcCmdId);
#endif
    *pDcCmdId = -1;

    if (pService->generic_service_info.isGen4)
    {
        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pDcCmdId = (CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType)
                                ? ICP_QAT_FW_COMP_CMD_DYNAMIC
                                : ICP_QAT_FW_COMP_CMD_STATIC;
                break;
            case CPA_DC_LZ4:
                *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4_COMPRESS;
                break;
            case CPA_DC_LZ4S:
                *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4S_COMPRESS;
                break;
            default:
                LAC_ENSURE(CPA_FALSE,
                           "Algorithm not supported for compression\n");
                status = CPA_STATUS_UNSUPPORTED;
                break;
        }
    }
    else /* !isGen4 path*/
    {
        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pDcCmdId = (CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType)
                                ? ICP_QAT_FW_COMP_CMD_DYNAMIC
                                : ICP_QAT_FW_COMP_CMD_STATIC;
                break;
            default:
                LAC_ENSURE(CPA_FALSE,
                           "Algorithm not supported for compression\n");
                status = CPA_STATUS_UNSUPPORTED;
                break;
        }
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Get the decompression command id for the given session setup data.
 *
 * @description
 *      This function will get the decompression command id based on parameters
 passed in the given session stup data.

 * @param[in]   pService           Pointer to the service
 *
 * @param[in]   pSessionData       Pointer to a user instantiated
 *                                 structure containing session data
 * @param[out]  pDcCmdId           Pointer to the command id
 *
 * @retval CPA_STATUS_SUCCESS      Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED  Unsupported algorithm/feature
 *
 *****************************************************************************/
STATIC CpaStatus dcGetDecompressCommandId(sal_compression_service_t *pService,
                                          CpaDcSessionSetupData *pSessionData,
                                          Cpa8U *pDcCmdId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pService);
    LAC_CHECK_NULL_PARAM(pSessionData);
    LAC_CHECK_NULL_PARAM(pDcCmdId);
#endif
    *pDcCmdId = -1;

    if (pService->generic_service_info.isGen4)
    {
        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pDcCmdId = ICP_QAT_FW_COMP_CMD_DECOMPRESS;
                break;
            case CPA_DC_LZ4:
                *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4_DECOMPRESS;
                break;
            case CPA_DC_LZ4S:
                *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4S_DECOMPRESS;
                break;
            default:
                LAC_ENSURE(CPA_FALSE,
                           "Algorithm not supported for decompression\n");
                status = CPA_STATUS_UNSUPPORTED;
                break;
        }
    }
    else
    {
        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pDcCmdId = ICP_QAT_FW_COMP_CMD_DECOMPRESS;
                break;
            default:
                LAC_ENSURE(CPA_FALSE,
                           "Algorithm not supported for decompression\n");
                status = CPA_STATUS_UNSUPPORTED;
                break;
        }
    }

    return status;
}

CpaStatus dcXxhash32SetState(dc_session_desc_t *pSessionDesc, Cpa32U seed)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    xxhash_acc_state_buff_t *xxhashStateBuffer;

    LAC_CHECK_NULL_PARAM(pSessionDesc);

    xxhashStateBuffer = (xxhash_acc_state_buff_t *)pSessionDesc;

    /* Zero the compression state register */
    LAC_OS_BZERO(xxhashStateBuffer, sizeof(xxhash_acc_state_buff_t));

    xxhashStateBuffer->xxhash_state[0] =
        seed + XXHASH_PRIME32_A + XXHASH_PRIME32_B;
    xxhashStateBuffer->xxhash_state[1] = seed + XXHASH_PRIME32_B;
    xxhashStateBuffer->xxhash_state[2] = seed + 0;
    xxhashStateBuffer->xxhash_state[3] = seed - XXHASH_PRIME32_A;

    return status;
}

CpaStatus dcInitSession(CpaInstanceHandle dcInstance,
                        CpaDcSessionHandle pSessionHandle,
                        CpaDcSessionSetupData *pSessionData,
                        CpaBufferList *pContextBuffer,
                        CpaDcCallbackFn callbackFn)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_compression_service_t *pService = NULL;
    icp_qat_fw_comp_req_t *pReqCache = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaPhysicalAddr contextAddrPhys = 0;
    CpaPhysicalAddr physAddress = 0;
    CpaPhysicalAddr physAddressAligned = 0;
    Cpa32U minContextSize = 0, historySize = 0;
    Cpa32U rpCmdFlags = 0;
    icp_qat_fw_serv_specif_flags cmdFlags = 0;
    Cpa8U secureRam = ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
    Cpa8U sessType = ICP_QAT_FW_COMP_STATELESS_SESSION;
    Cpa8U autoSelectBest = ICP_QAT_FW_COMP_NOT_AUTO_SELECT_BEST;
    Cpa8U enhancedAutoSelectBest = ICP_QAT_FW_COMP_NOT_ENH_AUTO_SELECT_BEST;
    Cpa8U disableType0EnhancedAutoSelectBest =
        ICP_QAT_FW_COMP_NOT_DISABLE_TYPE0_ENH_AUTO_SELECT_BEST;
    Cpa8U dcCmdId = ICP_QAT_FW_COMP_CMD_STATIC;
    icp_qat_fw_comn_flags cmnRequestFlags = 0;
    icp_qat_fw_ext_serv_specif_flags extServiceCmdFlags = 0;

    cmnRequestFlags = ICP_QAT_FW_COMN_FLAGS_BUILD(
        DC_DEFAULT_QAT_PTR_TYPE, QAT_COMN_CD_FLD_TYPE_16BYTE_DATA);

    pService = (sal_compression_service_t *)dcInstance;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pSessionData);

    /* Check that the parameters defined in the pSessionData are valid for the
     * device */
    if (CPA_STATUS_SUCCESS != dcCheckSessionData(pSessionData, dcInstance))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection))
    {
        LAC_UNSUPPORTED_PARAM_LOG("Stateful sessions are not supported");
        return CPA_STATUS_UNSUPPORTED;
    }
    /* Check for Gen4 and stateful, return error if both exist */
    if (pService->generic_service_info.isGen4 &&
        CPA_DC_STATEFUL == pSessionData->sessState)
    {
        LAC_INVALID_PARAM_LOG("Stateful sessions are not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    secureRam = pService->comp_device_data.useDevRam;

    if ((!pService->generic_service_info.isGen4) &&
        (CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType))
    {
        /* Test if DRAM is available for the intermediate buffers */
        if ((NULL == pService->pInterBuffPtrsArray) &&
            (0 == pService->pInterBuffPtrsArrayPhyAddr))
        {
            if (CPA_DC_ASB_STATIC_DYNAMIC ==
                pSessionData->autoSelectBestHuffmanTree)
            {
                /* Define the Huffman tree as static */
                pSessionData->huffType = CPA_DC_HT_STATIC;
            }
            else
            {
                LAC_LOG_ERROR("No buffer defined for this instance - see "
                              "cpaDcStartInstance");
                return CPA_STATUS_RESOURCE;
            }
        }
    }

    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_DEFLATE == pSessionData->compType ||
         CPA_DC_LZ4 == pSessionData->compType))
    {
        /* Get the size of the context buffer */
        status = dcGetContextSize(dcInstance, pSessionData, &minContextSize);

        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Unable to get the context size of the session\n");
            return CPA_STATUS_FAIL;
        }

#ifdef ICP_PARAM_CHECK
        /* If the minContextSize is zero it means we will not save or restore
         * any history */
        if (0 != minContextSize)
        {
            Cpa64U contextBuffSize = 0;

            LAC_CHECK_NULL_PARAM(pContextBuffer);

            if (LacBuffDesc_BufferListVerify(
                    pContextBuffer, &contextBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
                CPA_STATUS_SUCCESS)
            {
                return CPA_STATUS_INVALID_PARAM;
            }

            /* Ensure that the context buffer size is greater or equal
             * to minContextSize */
            if (contextBuffSize < minContextSize)
            {
                LAC_INVALID_PARAM_LOG1("Context buffer size should be "
                                       "greater or equal to %d",
                                       minContextSize);
                return CPA_STATUS_INVALID_PARAM;
            }
        }
#endif
    }

    /* Re-align the session structure to 64 byte alignment */
    physAddress =
        LAC_OS_VIRT_TO_PHYS_EXTERNAL(pService->generic_service_info,
                                     (Cpa8U *)pSessionHandle + sizeof(void *));

    if (physAddress == 0)
    {
        LAC_LOG_ERROR("Unable to get the physical address of the session\n");
        return CPA_STATUS_FAIL;
    }

    physAddressAligned = (CpaPhysicalAddr)LAC_ALIGN_POW2_ROUNDUP(
        physAddress, LAC_64BYTE_ALIGNMENT);

    pSessionDesc = (dc_session_desc_t *)
        /* Move the session pointer by the physical offset
        between aligned and unaligned memory */
        ((Cpa8U *)pSessionHandle + sizeof(void *) +
         (physAddressAligned - physAddress));

    /* Save the aligned pointer in the first bytes (size of LAC_ARCH_UINT)
     * of the session memory */
    *((LAC_ARCH_UINT *)pSessionHandle) = (LAC_ARCH_UINT)pSessionDesc;

    /* Zero the compression session */
    LAC_OS_BZERO(pSessionDesc, sizeof(dc_session_desc_t));

    /* Write the buffer descriptor for context/history */
    if (0 != minContextSize)
    {
        status =
            LacBuffDesc_BufferListDescWrite(pContextBuffer,
                                            &contextAddrPhys,
                                            CPA_FALSE,
                                            &(pService->generic_service_info));

        if (status != CPA_STATUS_SUCCESS)
        {
            return status;
        }

        pSessionDesc->pContextBuffer = pContextBuffer;
        pSessionDesc->historyBuffSize = historySize;
    }

    pSessionDesc->cumulativeConsumedBytes = 0;

    /* Initialise pSessionDesc */
    pSessionDesc->requestType = DC_REQUEST_FIRST;
    pSessionDesc->huffType = pSessionData->huffType;
    pSessionDesc->compType = pSessionData->compType;
    pSessionDesc->checksumType = pSessionData->checksum;
    pSessionDesc->autoSelectBestHuffmanTree =
        pSessionData->autoSelectBestHuffmanTree;
    pSessionDesc->sessDirection = pSessionData->sessDirection;
    pSessionDesc->sessState = pSessionData->sessState;
    pSessionDesc->compLevel = pSessionData->compLevel;
    pSessionDesc->lz4BlockMaxSize = pSessionData->lz4BlockMaxSize;
    pSessionDesc->lz4BlockChecksum = pSessionData->lz4BlockChecksum;
    pSessionDesc->lz4BlockIndependence = pSessionData->lz4BlockIndependence;
    pSessionDesc->accumulateXXHash = pSessionData->accumulateXXHash;
    pSessionDesc->minMatch = pSessionData->minMatch;
    pSessionDesc->isDcDp = CPA_FALSE;
    pSessionDesc->minContextSize = minContextSize;
    pSessionDesc->isSopForCompressionProcessed = CPA_FALSE;
    pSessionDesc->isSopForDecompressionProcessed = CPA_FALSE;

    /* Alter auto select best setting depending on the hardware version */
    if (!pService->generic_service_info.isGen4)
    {
        /* Gen 2 hardware devices */
        if (CPA_DC_ASB_ENABLED == pSessionDesc->autoSelectBestHuffmanTree)
        {
            /* Select best compression ratio optimization setting */
            pSessionDesc->autoSelectBestHuffmanTree =
                CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS;
        }
    }
    else
    {
        /* Gen 4 hardware devices */
        switch (pSessionDesc->autoSelectBestHuffmanTree)
        {
            case CPA_DC_ASB_STATIC_DYNAMIC: /* Fall through */
            case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS:
            case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_NO_HDRS:
            case CPA_DC_ASB_ENABLED:
                /* Enable compression ratio optimization */
                pSessionDesc->autoSelectBestHuffmanTree = CPA_DC_ASB_ENABLED;
                break;
            case CPA_DC_ASB_DISABLED:
            default:
                /* Keep setting from session setup data */
                break;
        }
    }

    if (CPA_DC_LZ4 == pSessionDesc->compType &&
        CPA_TRUE == pSessionDesc->accumulateXXHash &&
        CPA_DC_ASB_ENABLED == pSessionDesc->autoSelectBestHuffmanTree)
    {
        LAC_LOG_ERROR("Unsupported combination of accumulateXXHash"
                              " and autoSelectBestHuffmanTree.");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_DC_STATELESS == pSessionDesc->sessState &&
        CPA_DC_LZ4 == pSessionDesc->compType &&
        CPA_TRUE == pSessionDesc->accumulateXXHash)
    {
        if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection ||
            CPA_DC_DIR_COMBINED == pSessionDesc->sessDirection)
        {
            LAC_LOG_ERROR("AccumulateXXHash not supported on decompression"
                                  " or combined sessions.");
            return CPA_STATUS_UNSUPPORTED;
        }
        dcXxhash32SetState(pSessionDesc, 0);
    }

    if (CPA_DC_STATEFUL == pSessionData->sessState)
    {
        /* Init the spinlock used to lock the access to the number of stateful
         * in-flight requests */
        status = LAC_SPINLOCK_INIT(&(pSessionDesc->sessionLock));
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Spinlock init failed for sessionLock");
            return CPA_STATUS_RESOURCE;
        }
    }

    if (CPA_DC_STATELESS == pSessionDesc->sessState)
    {
        /* Init the spinlock used to lock access to the cached session data */
        status = LAC_SPINLOCK_INIT(&(pSessionDesc->updateLock));
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Spinlock init failed for updateLock");
            return CPA_STATUS_RESOURCE;
        }
    }

    /* For asynchronous - use the user supplied callback
     * for synchronous - use the internal synchronous callback */
    pSessionDesc->pCompressionCb = ((void *)NULL != (void *)callbackFn)
                                       ? callbackFn
                                       : LacSync_GenWakeupSyncCaller;

    /* Reset the pending callback counters */
    osalAtomicSet(0, &pSessionDesc->pendingStatelessCbCount);
    osalAtomicSet(0, &pSessionDesc->pendingStatefulCbCount);
    pSessionDesc->pendingDpStatelessCbCount = 0;

    if (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection)
    {
        if ((!pService->generic_service_info.isGen4) &&
            CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType)
        {
            /* Populate the compression section of the content descriptor */
            dcCompContentDescPopulate(pService,
                                      pSessionDesc,
                                      contextAddrPhys,
                                      &(pSessionDesc->reqCacheComp),
                                      ICP_QAT_FW_SLICE_XLAT,
                                      DC_COMPRESSION_REQUEST);

            /* Populate the translator section of the content descriptor */
            dcTransContentDescPopulate(&(pSessionDesc->reqCacheComp),
                                       ICP_QAT_FW_SLICE_DRAM_WR);

            if (0 != pService->pInterBuffPtrsArrayPhyAddr)
            {
                pReqCache = &(pSessionDesc->reqCacheComp);

                pReqCache->u1.xlt_pars.inter_buff_ptr =
                    pService->pInterBuffPtrsArrayPhyAddr;
            }
        }
        else
        {
            dcCompContentDescPopulate(pService,
                                      pSessionDesc,
                                      contextAddrPhys,
                                      &(pSessionDesc->reqCacheComp),
                                      ICP_QAT_FW_SLICE_DRAM_WR,
                                      DC_COMPRESSION_REQUEST);
        }
    }

    /* Populate the compression section of the content descriptor for
     * the decompression case or combined */
    if (CPA_DC_DIR_COMPRESS != pSessionData->sessDirection)
    {
        dcCompContentDescPopulate(pService,
                                  pSessionDesc,
                                  contextAddrPhys,
                                  &(pSessionDesc->reqCacheDecomp),
                                  ICP_QAT_FW_SLICE_DRAM_WR,
                                  DC_DECOMPRESSION_REQUEST);
    }

    if (CPA_DC_STATEFUL == pSessionData->sessState)
    {
        sessType = ICP_QAT_FW_COMP_STATEFUL_SESSION;

        LAC_OS_BZERO(&pSessionDesc->stateRegistersComp,
                     sizeof(pSessionDesc->stateRegistersComp));

        LAC_OS_BZERO(&pSessionDesc->stateRegistersDecomp,
                     sizeof(pSessionDesc->stateRegistersDecomp));
    }

    /* Populate the cmdFlags */
    switch (pSessionDesc->autoSelectBestHuffmanTree)
    {
        case CPA_DC_ASB_DISABLED:
            break;
        case CPA_DC_ASB_STATIC_DYNAMIC:
            autoSelectBest = ICP_QAT_FW_COMP_AUTO_SELECT_BEST;
            break;
        case CPA_DC_ASB_ENABLED: /* Fall through */
        case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS:
            /* CPA_DC_ASB_ENABLED provides the same settings as
             * CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS.
             */
            autoSelectBest = ICP_QAT_FW_COMP_AUTO_SELECT_BEST;
            enhancedAutoSelectBest = ICP_QAT_FW_COMP_ENH_AUTO_SELECT_BEST;
            break;
        case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_NO_HDRS:
            autoSelectBest = ICP_QAT_FW_COMP_AUTO_SELECT_BEST;
            enhancedAutoSelectBest = ICP_QAT_FW_COMP_ENH_AUTO_SELECT_BEST;
            disableType0EnhancedAutoSelectBest =
                ICP_QAT_FW_COMP_DISABLE_TYPE0_ENH_AUTO_SELECT_BEST;
            break;
        default:
            break;
    }

    rpCmdFlags =
        ICP_QAT_FW_COMP_REQ_PARAM_FLAGS_BUILD(ICP_QAT_FW_COMP_SOP,
                                              ICP_QAT_FW_COMP_EOP,
                                              ICP_QAT_FW_COMP_BFINAL,
                                              ICP_QAT_FW_COMP_NO_CNV,
                                              ICP_QAT_FW_COMP_NO_CNV_RECOVERY,
                                              ICP_QAT_FW_COMP_NO_CNV_DFX,
                                              ICP_QAT_FW_COMP_CRC_MODE_LEGACY);

    cmdFlags = ICP_QAT_FW_COMP_FLAGS_BUILD(sessType,
                                           autoSelectBest,
                                           enhancedAutoSelectBest,
                                           disableType0EnhancedAutoSelectBest,
                                           secureRam);

    if (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection)
    {
        status = dcGetCompressCommandId(pService, pSessionData, &dcCmdId);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR(
                "Couldn't get compress command ID for current session data.");

            return status;
        }
        pReqCache = &(pSessionDesc->reqCacheComp);
        pReqCache->comp_pars.req_par_flags = rpCmdFlags;
        pReqCache->comp_pars.crc.legacy.initial_adler = 1;
        pReqCache->comp_pars.crc.legacy.initial_crc32 = 0;

        /* Populate header of the common request message */
        SalQatMsg_CmnHdrWrite((icp_qat_fw_comn_req_t *)pReqCache,
                              ICP_QAT_FW_COMN_REQ_CPM_FW_COMP,
                              dcCmdId,
                              cmnRequestFlags,
                              cmdFlags,
                              extServiceCmdFlags);
    }

    if (CPA_DC_DIR_COMPRESS != pSessionData->sessDirection)
    {
        status = dcGetDecompressCommandId(pService, pSessionData, &dcCmdId);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR(
                "Couldn't get decompress command ID for current session data.");

            return status;
        }
        pReqCache = &(pSessionDesc->reqCacheDecomp);
        pReqCache->comp_pars.req_par_flags = rpCmdFlags;
        pReqCache->comp_pars.crc.legacy.initial_adler = 1;
        pReqCache->comp_pars.crc.legacy.initial_crc32 = 0;

        /* Populate header of the common request message */
        SalQatMsg_CmnHdrWrite((icp_qat_fw_comn_req_t *)pReqCache,
                              ICP_QAT_FW_COMN_REQ_CPM_FW_COMP,
                              dcCmdId,
                              cmnRequestFlags,
                              cmdFlags,
                              extServiceCmdFlags);
    }

    return status;
}

STATIC CpaStatus
dcCheckUpdateSession(const CpaInstanceHandle insHandle,
                     dc_session_desc_t *pSessionDesc,
                     CpaDcSessionUpdateData *pUpdateSessionData)
{
    sal_compression_service_t *pService =
        (sal_compression_service_t *)insHandle;

    /* Check if DRAM is available for the intermediate buffers
     * for dynamic compression */
    if ((!pService->generic_service_info.isGen4) &&
        (CPA_DC_HT_FULL_DYNAMIC == pUpdateSessionData->huffType) &&
        (NULL == pService->pInterBuffPtrsArray) &&
        (0 == pService->pInterBuffPtrsArrayPhyAddr))
    {
        LAC_LOG_ERROR("No intermediate buffer defined for this instance - see "
                      "cpaDcStartInstance");
        return CPA_STATUS_RESOURCE;
    }

    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        LAC_LOG_ERROR("Stateful sessions are not supported\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        LAC_LOG_ERROR("Decompression sessions are not supported\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus dcUpdateSession(const CpaInstanceHandle insHandle,
                                 dc_session_desc_t *pSessionDesc,
                                 CpaDcSessionUpdateData *pUpdateSessionData)
{
    sal_compression_service_t *pService =
        (sal_compression_service_t *)insHandle;

    icp_qat_fw_comp_req_t *pReqCacheComp = &(pSessionDesc->reqCacheComp);
    icp_qat_fw_comn_req_hdr_t *pHeader = &(pReqCacheComp->comn_hdr);
    icp_qat_hw_compression_config_t *pCompConfig =
        (icp_qat_hw_compression_config_t *)(pReqCacheComp->cd_pars.sl
                                                .comp_slice_cfg_word);
    icp_qat_fw_comp_cd_hdr_t *pCompControlBlock =
        (icp_qat_fw_comp_cd_hdr_t *)&(pReqCacheComp->comp_cd_ctrl);

    /* Acquire a lock prior to updating the session parameters
     * for traditional only */
    if (CPA_FALSE == pSessionDesc->isDcDp)
    {
        LAC_SPINLOCK(&(pSessionDesc->updateLock));
    }

    pService->comp_device_data.enableDmm =
        pUpdateSessionData->enableDmm ? 1 : 0;
    pSessionDesc->compLevel = pUpdateSessionData->compLevel;
    pSessionDesc->huffType = pUpdateSessionData->huffType;

    if (CPA_DC_HT_FULL_DYNAMIC == pUpdateSessionData->huffType)
    {
        ICP_QAT_FW_COMN_NEXT_ID_SET(pCompControlBlock, ICP_QAT_FW_SLICE_XLAT);
        ICP_QAT_FW_COMN_CURR_ID_SET(pCompControlBlock, ICP_QAT_FW_SLICE_COMP);

        /* Populate the translator section of the content descriptor */
        dcTransContentDescPopulate(pReqCacheComp, ICP_QAT_FW_SLICE_DRAM_WR);
        pReqCacheComp->u1.xlt_pars.inter_buff_ptr =
            pService->pInterBuffPtrsArrayPhyAddr;
        pHeader->service_cmd_id = ICP_QAT_FW_COMP_CMD_DYNAMIC;
    }
    else
    {
        ICP_QAT_FW_COMN_NEXT_ID_SET(pCompControlBlock,
                                    ICP_QAT_FW_SLICE_DRAM_WR);
        ICP_QAT_FW_COMN_CURR_ID_SET(pCompControlBlock, ICP_QAT_FW_SLICE_COMP);
        pHeader->service_cmd_id = ICP_QAT_FW_COMP_CMD_STATIC;
    }

    /* Populate Compression Hardware Setup Block */
    if (pService->generic_service_info.isGen4)
    {
        dcCompHwBlockPopulateGen4(
            pService, pSessionDesc, pCompConfig, DC_COMPRESSION_REQUEST);
    }
    else
    {
        dcCompHwBlockPopulate(
            pService, pSessionDesc, pCompConfig, DC_COMPRESSION_REQUEST);
    }

    /* Release the lock after updating session parameters */
    if (CPA_FALSE == pSessionDesc->isDcDp)
    {
        LAC_SPINUNLOCK(&(pSessionDesc->updateLock));
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcInitSession(CpaInstanceHandle dcInstance,
                           CpaDcSessionHandle pSessionHandle,
                           CpaDcSessionSetupData *pSessionData,
                           CpaBufferList *pContextBuffer,
                           CpaDcCallbackFn callbackFn)
{
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSessionData,
             (LAC_ARCH_UINT)pContextBuffer,
             (LAC_ARCH_UINT)callbackFn);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(insHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pService = (sal_compression_service_t *)insHandle;

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(pService);

    return dcInitSession(
        insHandle, pSessionHandle, pSessionData, pContextBuffer, callbackFn);
}

CpaStatus cpaDcUpdateSession(const CpaInstanceHandle dcInstance,
                             CpaDcSessionHandle pSessionHandle,
                             CpaDcSessionUpdateData *pUpdateSessionData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pUpdateSessionData);
#endif
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pUpdateSessionData);
#endif
    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        insHandle = dcInstance;
    }
    else
    {
        if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
        {
            insHandle = dcGetFirstHandle();
        }
        else
        {
            insHandle = dcInstance;
        }
    }
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif
    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    status = dcCheckUpdateSession(insHandle, pSessionDesc, pUpdateSessionData);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcUpdateSession(insHandle, pSessionDesc, pUpdateSessionData);
    }

    return status;
}

CpaStatus cpaDcResetXXHashState(const CpaInstanceHandle dcInstance,
                                CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle insHandle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    if (CPA_DC_STATELESS == pSessionDesc->sessState &&
        CPA_DC_LZ4 == pSessionDesc->compType &&
        CPA_TRUE == pSessionDesc->accumulateXXHash)
    {
        /* Check if there are stateless pending requests */
        if (0 != osalAtomicGet(&(pSessionDesc->pendingStatelessCbCount)))
        {
            LAC_LOG_ERROR("There are stateless requests pending");
            return CPA_STATUS_RETRY;
        }

        dcXxhash32SetState(pSessionDesc, 0);
    }
    else
    {
        LAC_LOG_ERROR("Only Stateless LZ4 session with accumulateXXHash can "
                      "reset state.");
        return CPA_STATUS_UNSUPPORTED;
    }

    return status;
}

CpaStatus cpaDcResetSession(const CpaInstanceHandle dcInstance,
                            CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle insHandle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    Cpa64U numPendingStateless = 0;
    Cpa64U numPendingStateful = 0;
    icp_comms_trans_handle trans_handle = NULL;
#ifdef ICP_DEBUG
    Cpa32U i = 0;
    CpaBufferList *pContextBuffer = NULL;
#endif

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
#endif
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle);
#endif
    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        insHandle = dcInstance;
    }
    else
    {
        if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
        {
            insHandle = dcGetFirstHandle();
        }
        else
        {
            insHandle = dcInstance;
        }
    }
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif
    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);
    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        trans_handle = ((sal_compression_service_t *)insHandle)
                           ->trans_handle_compression_tx;
        if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
        {
            /* Process the remaining messages on the ring */
            icp_adf_updateQueueTail(trans_handle);
            LAC_LOG_ERROR("There are remaining messages on the ring");
            return CPA_STATUS_RETRY;
        }

        /* Check if there are stateless pending requests */
        if (0 != pSessionDesc->pendingDpStatelessCbCount)
        {
            LAC_LOG_ERROR1("There are %d stateless DP requests pending",
                           pSessionDesc->pendingDpStatelessCbCount);
            return CPA_STATUS_RETRY;
        }
    }
    else
    {
        numPendingStateless =
            osalAtomicGet(&(pSessionDesc->pendingStatelessCbCount));
        numPendingStateful =
            osalAtomicGet(&(pSessionDesc->pendingStatefulCbCount));
        /* Check if there are stateless pending requests */
        if (0 != numPendingStateless)
        {
            LAC_LOG_ERROR1("There are %d stateless requests pending",
                           numPendingStateless);
            return CPA_STATUS_RETRY;
        }
        /* Check if there are stateful pending requests */
        if (0 != numPendingStateful)
        {
            LAC_LOG_ERROR1("There are %d stateful requests pending",
                           numPendingStateful);
            return CPA_STATUS_RETRY;
        }
#ifdef ICP_DEBUG
        pContextBuffer = pSessionDesc->pContextBuffer;
        if (pContextBuffer)
        {
            /* Fill context buffer with 0xFF in debug mode */
            for (i = 0; i < pContextBuffer->numBuffers; i++)
            {
                osalMemSet(pContextBuffer->pBuffers[i].pData,
                           0xFF,
                           pContextBuffer->pBuffers[i].dataLenInBytes);
            }
        }
#endif

        /* Reset pSessionDesc */
        pSessionDesc->requestType = DC_REQUEST_FIRST;
        pSessionDesc->cumulativeConsumedBytes = 0;
        pSessionDesc->cnvErrorInjection = ICP_QAT_FW_COMP_NO_CNV_DFX;
    }

    /* Reset the pending callback counters */
    osalAtomicSet(0, &pSessionDesc->pendingStatelessCbCount);
    osalAtomicSet(0, &pSessionDesc->pendingStatefulCbCount);
    pSessionDesc->pendingDpStatelessCbCount = 0;
    if (CPA_DC_STATEFUL == pSessionDesc->sessState)
    {
        LAC_OS_BZERO(&pSessionDesc->stateRegistersComp,
                     sizeof(pSessionDesc->stateRegistersComp));
        LAC_OS_BZERO(&pSessionDesc->stateRegistersDecomp,
                     sizeof(pSessionDesc->stateRegistersDecomp));
    }
    return status;
}

CpaStatus cpaDcRemoveSession(const CpaInstanceHandle dcInstance,
                             CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle insHandle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    Cpa64U numPendingStateless = 0;
    Cpa64U numPendingStateful = 0;
    icp_comms_trans_handle trans_handle = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
#endif
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle);
#endif

    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        insHandle = dcInstance;
    }
    else
    {
        if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
        {
            insHandle = dcGetFirstHandle();
        }
        else
        {
            insHandle = dcInstance;
        }
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        trans_handle = ((sal_compression_service_t *)insHandle)
                           ->trans_handle_compression_tx;

        if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
        {
            /* Process the remaining messages on the ring */
            icp_adf_updateQueueTail(trans_handle);
            LAC_LOG_ERROR("There are remaining messages on the ring");
            return CPA_STATUS_RETRY;
        }

        /* Check if there are stateless pending requests */
        if (0 != pSessionDesc->pendingDpStatelessCbCount)
        {
            LAC_LOG_ERROR1("There are %d stateless DP requests pending",
                           pSessionDesc->pendingDpStatelessCbCount);
            return CPA_STATUS_RETRY;
        }
    }
    else
    {
        numPendingStateless =
            osalAtomicGet(&(pSessionDesc->pendingStatelessCbCount));
        numPendingStateful =
            osalAtomicGet(&(pSessionDesc->pendingStatefulCbCount));

        /* Check if there are stateless pending requests */
        if (0 != numPendingStateless)
        {
            LAC_LOG_ERROR1("There are %d stateless requests pending",
                           numPendingStateless);
            status = CPA_STATUS_RETRY;
        }

        /* Check if there are stateful pending requests */
        if (0 != numPendingStateful)
        {
            LAC_LOG_ERROR1("There are %d stateful requests pending",
                           numPendingStateful);
            status = CPA_STATUS_RETRY;
        }
        if ((CPA_DC_STATEFUL == pSessionDesc->sessState) &&
            (CPA_STATUS_SUCCESS == status))
        {
            LAC_SPINLOCK_DESTROY(&(pSessionDesc->sessionLock));
        }
    }

    if (CPA_DC_STATELESS == pSessionDesc->sessState)
    {
        LAC_SPINLOCK_DESTROY(&(pSessionDesc->updateLock));
    }

    return status;
}

CpaStatus dcGetSessionSize(CpaInstanceHandle dcInstance,
                           CpaDcSessionSetupData *pSessionData,
                           Cpa32U *pSessionSize,
                           Cpa32U *pContextSize)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle insHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    /* Check parameters */
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pSessionData);
    LAC_CHECK_NULL_PARAM(pSessionSize);

    if (dcCheckSessionData(pSessionData, insHandle) != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    /* Get session size for session data */
    *pSessionSize = sizeof(dc_session_desc_t) + LAC_64BYTE_ALIGNMENT +
                    sizeof(LAC_ARCH_UINT);

    if (NULL != pContextSize)
    {
        status = dcGetContextSize(insHandle, pSessionData, pContextSize);

        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Unable to get the context size of the session\n");
            return CPA_STATUS_FAIL;
        }
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcGetSessionSize(CpaInstanceHandle dcInstance,
                              CpaDcSessionSetupData *pSessionData,
                              Cpa32U *pSessionSize,
                              Cpa32U *pContextSize)
{
/* Check parameter */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pContextSize);
#endif

    return dcGetSessionSize(
        dcInstance, pSessionData, pSessionSize, pContextSize);

#ifdef ICP_TRACE
    LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx[%d], 0x%lx[%d])\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionData,
             (LAC_ARCH_UINT)pSessionSize,
             *pSessionSize,
             (LAC_ARCH_UINT)pContextSize,
             *pContextSize);
#endif
}

#ifdef ICP_DC_ERROR_SIMULATION
CpaStatus dcSetCnvError(CpaInstanceHandle dcInstance,
                        CpaDcSessionHandle pSessionHandle)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(dcInstance);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
#endif

    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

    if (!pService->generic_service_info.isGen4)
    {
        LAC_ENSURE(CPA_FALSE, "Unsupported compression feature.\n");
        return CPA_STATUS_UNSUPPORTED;
    }

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

    pSessionDesc->cnvErrorInjection = ICP_QAT_FW_COMP_CNV_DFX;

    return CPA_STATUS_SUCCESS;
}
#endif /* ICP_DC_ERROR_SIMULATION */
