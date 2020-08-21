/****************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
        (pSessionData->compLevel > CPA_DC_L9))
    {
        LAC_INVALID_PARAM_LOG("Invalid compLevel value");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((pSessionData->autoSelectBestHuffmanTree < CPA_DC_ASB_DISABLED) ||
        (pSessionData->autoSelectBestHuffmanTree >
         CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_NO_HDRS))
    {
        LAC_INVALID_PARAM_LOG("Invalid autoSelectBestHuffmanTree value");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((pSessionData->compType < CPA_DC_LZS) ||
        (pSessionData->compType > CPA_DC_DEFLATE) ||
        (CPA_DC_ELZS == pSessionData->compType) ||
        (CPA_DC_LZSS == pSessionData->compType))
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
        (pSessionData->checksum > CPA_DC_ADLER32))
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum value");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* LZS only supports stateless */
    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_LZS == pSessionData->compType))
    {
        LAC_INVALID_PARAM_LOG("LZS only supports stateless");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* LZS only supports static trees */
    if ((CPA_DC_HT_STATIC != pSessionData->huffType) &&
        (CPA_DC_LZS == pSessionData->compType))
    {
        LAC_INVALID_PARAM_LOG("LZS only supports static trees");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression hardware block
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      the size in bytes of the block
 *
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 * @param[in]   enableDmm               Delayed Match Mode
 *
 *****************************************************************************/
STATIC void dcCompHwBlockPopulate(
    dc_session_desc_t *pSessionDesc,
    icp_qat_hw_compression_config_t *pCompConfig,
    dc_request_dir_t compDecomp,
    icp_qat_hw_compression_delayed_match_t enableDmm)
{
    icp_qat_hw_compression_direction_t dir =
        ICP_QAT_HW_COMPRESSION_DIR_COMPRESS;
    icp_qat_hw_compression_algo_t algo = ICP_QAT_HW_COMPRESSION_ALGO_DEFLATE;
    icp_qat_hw_compression_depth_t depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
    icp_qat_hw_compression_file_type_t filetype =
        ICP_QAT_HW_COMPRESSION_FILE_TYPE_0;

    /* Set the direction */
    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
        dir = ICP_QAT_HW_COMPRESSION_DIR_COMPRESS;
    }
    else
    {
        dir = ICP_QAT_HW_COMPRESSION_DIR_DECOMPRESS;
    }

    /* Set the algorithm */
    if (CPA_DC_LZS == pSessionDesc->compType)
    {
        algo = ICP_QAT_HW_COMPRESSION_ALGO_LZS;
    }
    else if (CPA_DC_DEFLATE == pSessionDesc->compType)
    {
        algo = ICP_QAT_HW_COMPRESSION_ALGO_DEFLATE;
    }
    else
    {
        LAC_ENSURE(CPA_FALSE, "Algorithm not supported for Compression\n");
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

    pCompConfig->val = ICP_QAT_HW_COMPRESSION_CONFIG_BUILD(
        dir, enableDmm, algo, depth, filetype);

    pCompConfig->reserved = 0;
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
    dcCompHwBlockPopulate(pSessionDesc,
                          pCompConfig,
                          compDecomp,
                          pService->comp_device_data.enableDmm);
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
        (CPA_DC_DEFLATE == pSessionData->compType) &&
        (CPA_DC_DIR_COMPRESS != pSessionData->sessDirection))
    {
        *pContextSize = pCompService->comp_device_data.inflateContextSize;
    }
    return CPA_STATUS_SUCCESS;
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
    icp_qat_fw_la_cmd_id_t dcCmdId =
        (icp_qat_fw_la_cmd_id_t)ICP_QAT_FW_COMP_CMD_STATIC;
    icp_qat_fw_comn_flags cmnRequestFlags = 0;

    cmnRequestFlags =
        ICP_QAT_FW_COMN_FLAGS_BUILD_BNP(DC_DEFAULT_QAT_PTR_TYPE,
                                        QAT_COMN_CD_FLD_TYPE_16BYTE_DATA,
                                        QAT_COMN_BNP_ENABLED);

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

#ifdef CNV_STRICT_MODE
    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection))
    {
        LAC_INVALID_PARAM_LOG("Stateful sessions are not supported");
        return CPA_STATUS_UNSUPPORTED;
    }
#endif

    status = checkLzsSupport(dcInstance,
                             pSessionData->compType,
                             CPA_FALSE,
                             pSessionData->sessDirection);
    if (status != CPA_STATUS_SUCCESS)
    {
        return status;
    }

    secureRam = pService->comp_device_data.useDevRam;

    if (CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType)
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
        (CPA_DC_DEFLATE == pSessionData->compType))
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
    pSessionDesc->isDcDp = CPA_FALSE;
    pSessionDesc->minContextSize = minContextSize;
    pSessionDesc->isSopForCompressionProcessed = CPA_FALSE;
    pSessionDesc->isSopForDecompressionProcessed = CPA_FALSE;

    if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
    {
        pSessionDesc->previousChecksum = 1;
    }
    else
    {
        pSessionDesc->previousChecksum = 0;
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
        if (CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType)
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
        case CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS:
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
                                              ICP_QAT_FW_COMP_NO_CNV_RECOVERY);

    cmdFlags = ICP_QAT_FW_COMP_FLAGS_BUILD(sessType,
                                           autoSelectBest,
                                           enhancedAutoSelectBest,
                                           disableType0EnhancedAutoSelectBest,
                                           secureRam);

    if (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection)
    {
        if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
        {
            dcCmdId = (icp_qat_fw_la_cmd_id_t)(ICP_QAT_FW_COMP_CMD_DYNAMIC);
        }

        pReqCache = &(pSessionDesc->reqCacheComp);
        pReqCache->comp_pars.req_par_flags = rpCmdFlags;
        pReqCache->comp_pars.initial_adler = 1;
        pReqCache->comp_pars.initial_crc32 = 0;

        /* Populate header of the common request message */
        SalQatMsg_CmnHdrWrite((icp_qat_fw_comn_req_t *)pReqCache,
                              ICP_QAT_FW_COMN_REQ_CPM_FW_COMP,
                              (uint8_t)dcCmdId,
                              cmnRequestFlags,
                              cmdFlags,
                              0,
                              pService->generic_service_info.isGen4);
    }

    if (CPA_DC_DIR_COMPRESS != pSessionData->sessDirection)
    {
        dcCmdId = (icp_qat_fw_la_cmd_id_t)(ICP_QAT_FW_COMP_CMD_DECOMPRESS);
        pReqCache = &(pSessionDesc->reqCacheDecomp);
        pReqCache->comp_pars.req_par_flags = rpCmdFlags;
        pReqCache->comp_pars.initial_adler = 1;
        pReqCache->comp_pars.initial_crc32 = 0;

        /* Populate header of the common request message */
        SalQatMsg_CmnHdrWrite((icp_qat_fw_comn_req_t *)pReqCache,
                              ICP_QAT_FW_COMN_REQ_CPM_FW_COMP,
                              (uint8_t)dcCmdId,
                              cmnRequestFlags,
                              cmdFlags,
                              0,
                              pService->generic_service_info.isGen4);
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
    if ((CPA_DC_HT_FULL_DYNAMIC == pUpdateSessionData->huffType) &&
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
    dcCompHwBlockPopulate(pSessionDesc,
                          pCompConfig,
                          DC_COMPRESSION_REQUEST,
                          pService->comp_device_data.enableDmm);

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
        trans_handle = ((sal_compression_service_t *)dcInstance)
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
        if (CPA_DC_ADLER32 == pSessionDesc->checksumType)
        {
            pSessionDesc->previousChecksum = 1;
        }
        else
        {
            pSessionDesc->previousChecksum = 0;
        }
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
