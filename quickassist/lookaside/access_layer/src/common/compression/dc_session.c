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
#include "dc_capabilities.h"
#include "lac_mem_pools.h"
#include "sal_types_compression.h"
#include "lac_buffer_desc.h"
#include "sal_service_state.h"
#include "sal_qat_cmn_msg.h"
#include "dc_crc64.h"

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check supported session data
 *
 * @description
 *      Check that all the parameters defined in the pSessionData are
 *      supported
 *
 * @param[in]       pSessionData     Pointer to a user instantiated structure
 *                                   containing session data
 * @param[in]       dcInstance       DC Instance Handle
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported feature
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter
 *
 *****************************************************************************/
STATIC CpaStatus
dcCheckUnsupportedParams(const CpaDcSessionSetupData *pSessionData,
                         CpaInstanceHandle dcInstance)
{
    sal_compression_service_t *pCompService =
        (sal_compression_service_t *)dcInstance;
    dc_capabilities_t *pDcCapabilities = &pCompService->dc_capabilities;
    CpaBoolean deflateSupported = CPA_FALSE;
    CpaBoolean zstdSupported = pDcCapabilities->zstd.supported;
    CpaBoolean lz4Supported = CPA_FALSE;
    CpaBoolean lz4sSupported = CPA_FALSE;
    CpaBoolean staticSupported = CPA_FALSE;
    CpaBoolean dynamicSupported = CPA_FALSE;
    Cpa8U huffmanTypeSupport = 0;
    CpaBoolean asbEnablePref = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;

    switch (pCompService->generic_service_info.type)
    {
        case SAL_SERVICE_TYPE_COMPRESSION:
            if (CPA_FALSE ==
                pDcCapabilities->deviceData.compressionServiceSupported)
            {
                LAC_UNSUPPORTED_PARAM_LOG("Dc capability not supported");
                return CPA_STATUS_UNSUPPORTED;
            }
            break;
        case SAL_SERVICE_TYPE_DECOMPRESSION:
            if (CPA_FALSE ==
                pDcCapabilities->deviceData.decompressionServiceSupported)
            {
                LAC_UNSUPPORTED_PARAM_LOG("Decomp capability not supported");
                return CPA_STATUS_UNSUPPORTED;
            }
            break;
        default:
            LAC_INVALID_PARAM_LOG("Invalid service type for compression");
            return CPA_STATUS_FAIL;
    }

    deflateSupported = pDcCapabilities->deflate.supported;
    lz4Supported = pDcCapabilities->lz4.supported;
    lz4sSupported = pDcCapabilities->lz4s.supported;

    switch (pSessionData->compType)
    {
        case CPA_DC_DEFLATE:
            if (CPA_FALSE == deflateSupported)
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "Deflate algorithm not supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            /* Retrieve internal capabilities */
            huffmanTypeSupport = pDcCapabilities->deflate.typeSupport;
            staticSupported = DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(
                huffmanTypeSupport,
                DC_CAPS_DEFLATE_TYPE_STATIC,
                DC_CAPS_DEFLATE_TYPE_SUPPORTED);

            dynamicSupported = DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(
                huffmanTypeSupport,
                DC_CAPS_DEFLATE_TYPE_DYNAMIC,
                DC_CAPS_DEFLATE_TYPE_SUPPORTED);

            if ((CPA_DC_HT_STATIC == pSessionData->huffType) &&
                (CPA_FALSE == staticSupported))
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "Static huffman encoding not supported "
                    "on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if ((CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType) &&
                (CPA_FALSE == dynamicSupported))
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "Dynamic huffman encoding not supported "
                    "on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->deflate.dirMask & DC_CAPS_COMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("Deflate compression direction not "
                                          "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_DECOMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->deflate.dirMask & DC_CAPS_DECOMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("Deflate decompression direction not "
                                          "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMBINED == pSessionData->sessDirection &&
                (!(pDcCapabilities->deflate.dirMask & DC_CAPS_COMPRESSION) ||
                 !(pDcCapabilities->deflate.dirMask & DC_CAPS_DECOMPRESSION)))
            {
                LAC_UNSUPPORTED_PARAM_LOG("Deflate not supported for combined "
                                          "sessions on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            break;
        case CPA_DC_LZ4:
            if (CPA_FALSE == lz4Supported)
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "LZ4 algorithm not supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_FALSE == pDcCapabilities->lz4.accumulateXXHash &&
                CPA_TRUE == pSessionData->accumulateXXHash)
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "XXHash32 Accumulate not supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->lz4.dirMask & DC_CAPS_COMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "LZ4 compression direction not supported "
                    "on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_DECOMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->lz4.dirMask & DC_CAPS_DECOMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("LZ4 decompression direction not "
                                          "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMBINED == pSessionData->sessDirection &&
                (!(pDcCapabilities->lz4.dirMask & DC_CAPS_COMPRESSION) ||
                 !(pDcCapabilities->lz4.dirMask & DC_CAPS_DECOMPRESSION)))
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "LZ4 not supported for combined sessions "
                    "on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection &&
                (!((1 << (pSessionData->lz4BlockMaxSize)) &
                   pDcCapabilities->lz4.maxBlockSize)))
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "UnSupported LZ4 Block Max Size value");
                return CPA_STATUS_UNSUPPORTED;
            }
            break;
        case CPA_DC_LZ4S:
            if (CPA_FALSE == lz4sSupported)
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "LZ4s algorithm not supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->lz4s.dirMask & DC_CAPS_COMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("LZ4s compression direction not "
                                          "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_DECOMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->lz4s.dirMask & DC_CAPS_DECOMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("LZ4s decompression direction not "
                                          "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMBINED == pSessionData->sessDirection &&
                (!(pDcCapabilities->lz4s.dirMask & DC_CAPS_COMPRESSION) ||
                 !(pDcCapabilities->lz4s.dirMask & DC_CAPS_DECOMPRESSION)))
            {
                LAC_UNSUPPORTED_PARAM_LOG("LZ4s not supported for combined "
                                          "sessions on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            break;
        case CPA_DC_ZSTD:
            if (CPA_FALSE == zstdSupported)
            {
                LAC_UNSUPPORTED_PARAM_LOG(
                    "Zstd algorithm not supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->zstd.dirMask & DC_CAPS_COMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("Zstd compression direction not "
                                      "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_DECOMPRESS == pSessionData->sessDirection &&
                !(pDcCapabilities->zstd.dirMask & DC_CAPS_DECOMPRESSION))
            {
                LAC_UNSUPPORTED_PARAM_LOG("Zstd decompression direction not "
                                      "supported on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            if (CPA_DC_DIR_COMBINED == pSessionData->sessDirection &&
                (!(pDcCapabilities->zstd.dirMask & DC_CAPS_COMPRESSION) ||
                 !(pDcCapabilities->zstd.dirMask & DC_CAPS_DECOMPRESSION)))
            {
                LAC_UNSUPPORTED_PARAM_LOG("Zstd not supported for combined "
                                      "sessions on current instance");
                return CPA_STATUS_UNSUPPORTED;
            }
            break;
        default:
            LAC_INVALID_PARAM_LOG("Invalid compType value");
            return CPA_STATUS_INVALID_PARAM;
    }

    /* Retrieve capability */
    if (CPA_DC_DIR_COMPRESS == pSessionData->sessDirection)
    {
        status = dcGetAsbEnablePrefCapabilityStatus(
            pDcCapabilities, pSessionData->compType, &asbEnablePref);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
        if ((pSessionData->autoSelectBestHuffmanTree == CPA_DC_ASB_DISABLED) &&
            (CPA_TRUE == asbEnablePref))
        {
            LAC_UNSUPPORTED_PARAM_LOG(
                "CPA_DC_ASB_DISABLED is not supported.\n");
            return CPA_STATUS_UNSUPPORTED;
        }
    }

    return CPA_STATUS_SUCCESS;
}

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
 * @param[in]       dcInstance       DC Instance Handle
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 * @note:
 * This function is only testing for invalid uses of the API. This code
 * may be compiled out for performance in production software. It is
 * intended for application developers to prevent invalid parameters from
 * being used. It should not be used to check for UNSUPPORTED capabilities.
 * The dcCheckUnsupportedParams() function should be used for this purpose
 * instead.
 *****************************************************************************/
CpaStatus dcCheckSessionData(const CpaDcSessionSetupData *pSessionData,
                             CpaInstanceHandle dcInstance)
{
    sal_compression_service_t *pService =
        (sal_compression_service_t *)dcInstance;

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

    if ((pService->generic_service_info.type ==
         SAL_SERVICE_TYPE_DECOMPRESSION) &&
        ((pSessionData->sessDirection == CPA_DC_DIR_COMPRESS) ||
         (pSessionData->sessDirection == CPA_DC_DIR_COMBINED)))
    {
        LAC_INVALID_PARAM_LOG("Invalid Service Type and SessDirection");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pService->generic_service_info.type ==
         SAL_SERVICE_TYPE_DECOMPRESSION) &&
        (pSessionData->sessState == CPA_DC_STATEFUL))
    {
        LAC_INVALID_PARAM_LOG("Invalid Service Type and sessState");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pSessionData->sessState < CPA_DC_STATEFUL) ||
        (pSessionData->sessState > CPA_DC_STATELESS))
    {
        LAC_INVALID_PARAM_LOG("Invalid sessState value");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((pSessionData->checksum < CPA_DC_NONE) ||
        (pSessionData->checksum > CPA_DC_XXHASH64))
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

    if ((CPA_DC_ZSTD == pSessionData->compType) &&
        (CPA_DC_XXHASH64 != pSessionData->checksum))
    {
        LAC_INVALID_PARAM_LOG("Invalid checksum type for zstd compression");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check that pCrcControlData is valid
 *
 * @description
 *      Check that all the parameters defined in the pCrcControlData are valid
 *
 * @param[in]       pCrcControlData   Pointer to a user instantiated structure
 *                                    containing session CRC control data.
 *
 * @retval CPA_STATUS_SUCCESS         Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcCheckSessionCrcControlData(const CpaCrcControlData *pCrcControlData)
{
    /* CRC polynomial must not be zero */
    if (pCrcControlData->polynomial == 0)
    {
        LAC_INVALID_PARAM_LOG("Invalid CRC polynomial value = 0");
        return CPA_STATUS_INVALID_PARAM;
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
void dcCompHwBlockPopulate(void *pServiceType,
                           void *pSessionDescp,
                           CpaDcNsSetupData *pSetupData,
                           icp_qat_hw_compression_config_t *pCompConfig,
                           void *compDecompDir,
                           CpaBoolean bNsOp)
{
    icp_qat_hw_compression_direction_t dir =
        ICP_QAT_HW_COMPRESSION_DIR_COMPRESS;
    icp_qat_hw_compression_algo_t algo = ICP_QAT_HW_COMPRESSION_ALGO_DEFLATE;
    icp_qat_hw_compression_depth_t depth = ICP_QAT_HW_COMPRESSION_DEPTH_1;
    icp_qat_hw_compression_file_type_t filetype =
        ICP_QAT_HW_COMPRESSION_FILE_TYPE_0;
    icp_qat_hw_compression_delayed_match_t dmm;
    sal_compression_service_t *pService = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    dc_request_dir_t compDecomp;

    pService = (sal_compression_service_t *)pServiceType;
    pSessionDesc = (dc_session_desc_t *)pSessionDescp;

    pDcCapabilities = &pService->dc_capabilities;
    compDecomp = *(dc_request_dir_t *)compDecompDir;

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
        LAC_LOG_ERROR("Algorithm not supported for Compression\n");
    }

    /* Set delay match mode */
    if (CPA_TRUE == pDcCapabilities->deviceData.enableDmm)
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
 *      Populate the compression hardware block for QAT Gen4
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      for QAT Gen4 the size in bytes of the block
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pSetupData              Pointer to setup data
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 * @param[in]   bNsOp                   Boolean to indicate no session operation
 *
 *****************************************************************************/
void dcCompHwBlockPopulateGen4(void *pServiceType,
                               void *pSessionDescp,
                               CpaDcNsSetupData *pSetupData,
                               icp_qat_hw_compression_config_t *pCompConfig,
                               void *compDecompDir,
                               CpaBoolean bNsOp)
{
    CpaDcCompType compType = 0;
    CpaDcCompLvl compLevel = 0;
    CpaDcHuffType huffType;
    CpaDcCompMinMatch minMatch;
    CpaDcCompLZ4BlockMaxSize lz4BlockMaxSize;
    CpaBoolean lz4BlockChecksum, lz4BlockIndependence;
    sal_compression_service_t *pService = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    dc_request_dir_t compDecomp;

    pService = (sal_compression_service_t *)pServiceType;
    pSessionDesc = (dc_session_desc_t *)pSessionDescp;
    pDcCapabilities = &pService->dc_capabilities;
    compDecomp = *(dc_request_dir_t *)compDecompDir;

    if (bNsOp)
    {
        compType = pSetupData->compType;
        compLevel = pSetupData->compLevel;
        huffType = pSetupData->huffType;
        minMatch = pSetupData->minMatch;
        lz4BlockMaxSize = pSetupData->lz4BlockMaxSize;
        lz4BlockChecksum = pSetupData->lz4BlockChecksum;
        lz4BlockIndependence = pSetupData->lz4BlockIndependence;
    }
    else
    {
        compType = pSessionDesc->compType;
        compLevel = pSessionDesc->compLevel;
        huffType = pSessionDesc->huffType;
        minMatch = pSessionDesc->minMatch;
        lz4BlockMaxSize = pSessionDesc->lz4BlockMaxSize;
        lz4BlockChecksum = pSessionDesc->lz4BlockChecksum;
        lz4BlockIndependence = pSessionDesc->lz4BlockIndependence;
    }

    /* Direction: Compression */
    if (DC_COMPRESSION_REQUEST == compDecomp)
    {
        icp_qat_hw_comp_20_config_csr_upper_t hw_comp_upper_csr;
        icp_qat_hw_comp_20_config_csr_lower_t hw_comp_lower_csr;

        osalMemSet(&hw_comp_upper_csr, 0, sizeof hw_comp_upper_csr);
        osalMemSet(&hw_comp_lower_csr, 0, sizeof hw_comp_lower_csr);

        /* Disable Literal + Length Limit Block Drop by default */
        hw_comp_lower_csr.lllbd = ICP_QAT_HW_COMP_20_LLLBD_CTRL_LLLBD_DISABLED;

        switch (compType)
        {
            case CPA_DC_DEFLATE:
                /* DEFLATE algorithm settings */
                hw_comp_lower_csr.skip_ctrl =
                    ICP_QAT_HW_COMP_20_BYTE_SKIP_3BYTE_LITERAL;

                if (CPA_DC_HT_FULL_DYNAMIC == huffType)
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

                break;
            case CPA_DC_LZ4:
                /* LZ4 algorithm settings */
                hw_comp_lower_csr.algo = ICP_QAT_HW_COMP_20_HW_COMP_FORMAT_LZ4;
                hw_comp_upper_csr.lbms =
                    (icp_qat_hw_comp_20_lbms_t)lz4BlockMaxSize;
                hw_comp_lower_csr.mmctrl =
                    ICP_QAT_HW_COMP_20_MIN_MATCH_CONTROL_MATCH_4B;

                if (CPA_TRUE == lz4BlockIndependence)
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
                hw_comp_lower_csr.mmctrl =
                    (icp_qat_hw_comp_20_min_match_control_t)minMatch;
                hw_comp_upper_csr.scb_ctrl =
                    ICP_QAT_HW_COMP_20_SCB_CONTROL_DISABLE;
                break;
            default:
                LAC_LOG_ERROR("Compression algorithm not supported\n");
                break;
        }

        /* Set the search depth */
        switch (compLevel)
        {
            case CPA_DC_L1:
            case CPA_DC_L2:
            case CPA_DC_L3:
            case CPA_DC_L4:
            case CPA_DC_L5:
                hw_comp_lower_csr.sd = ICP_QAT_HW_COMP_20_SEARCH_DEPTH_LEVEL_1;
                hw_comp_lower_csr.hash_col =
                    ICP_QAT_HW_COMP_20_HASH_COLLISION_SKIP;
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
                    pDcCapabilities->deviceData.highestHwCompressionDepth;
                if ((CPA_DC_HT_FULL_DYNAMIC == huffType) &&
                    (CPA_DC_DEFLATE == compType))
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
        hw_comp_lower_csr.hash_update = ICP_QAT_HW_COMP_20_HASH_UPDATE_SKIP;
        hw_comp_lower_csr.edmm =
            (CPA_TRUE == pDcCapabilities->deviceData.enableDmm)
                ? ICP_QAT_HW_COMP_20_EXTENDED_DELAY_MATCH_MODE_EDMM_ENABLED
                : ICP_QAT_HW_COMP_20_EXTENDED_DELAY_MATCH_MODE_EDMM_DISABLED;

        /* Enable Adaptive Block Drop with dynamic deflate
         * compression when levels 10-12 are selected.
         * This field is ignored by firmware for devices that
         * do not support adaptive block drop */
        if ((CPA_DC_HT_FULL_DYNAMIC == huffType) &&
            (CPA_DC_DEFLATE == compType) &&
            (CPA_DC_L10 == compLevel || CPA_DC_L11 == compLevel ||
             CPA_DC_L12 == compLevel))
        {
            hw_comp_lower_csr.abd = ICP_QAT_HW_COMP_20_ABD_ABD_ENABLED;
        }
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
        if (CPA_DC_DEFLATE == compType)
        {
            hw_decomp_lower_csr.algo =
                ICP_QAT_HW_DECOMP_20_HW_DECOMP_FORMAT_DEFLATE;
        }
        else if (CPA_DC_LZ4 == compType)
        {
            hw_decomp_lower_csr.algo =
                ICP_QAT_HW_DECOMP_20_HW_DECOMP_FORMAT_LZ4;
            hw_decomp_lower_csr.lbms =
                (icp_qat_hw_decomp_20_lbms_t)lz4BlockMaxSize;
            if (CPA_TRUE == lz4BlockChecksum)
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
        else if (CPA_DC_LZ4S == compType)
        {
            hw_decomp_lower_csr.algo =
                ICP_QAT_HW_DECOMP_20_HW_DECOMP_FORMAT_LZ4S;
            hw_decomp_lower_csr.mmctrl =
                (icp_qat_hw_decomp_20_min_match_control_t)minMatch;
        }
        else
        {
            LAC_LOG_ERROR("Algorithm not supported for Decompression\n");
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

    /* Retrieve internal capabilities */
    dc_capabilities_t *pDcCapabilities = &pService->dc_capabilities;

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
    (pDcCapabilities->dcCompHwBlockPopulate)((void *)pService,
                                             (void *)pSessionDesc,
                                             NULL,
                                             pCompConfig,
                                             (void *)&compDecomp,
                                             CPA_FALSE);
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
void dcTransContentDescPopulate(icp_qat_fw_comp_req_t *pMsg,
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
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_compression_service_t *pCompService = NULL;

    pCompService = (sal_compression_service_t *)dcInstance;

    dc_capabilities_t *pDcCapabilities = &pCompService->dc_capabilities;

    *pContextSize = 0;
    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_DIR_COMPRESS != pSessionData->sessDirection))
    {
        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pContextSize = pDcCapabilities->deflate.inflateContextSize;
                break;
            case CPA_DC_LZ4:
                *pContextSize = pDcCapabilities->lz4.decompContextSize;
                break;
            default:
                LAC_LOG_ERROR("Invalid compression algorithm.");
                status = CPA_STATUS_UNSUPPORTED;
                break;
        }
    }

    return status;
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
CpaStatus dcGetCompressCommandId(sal_compression_service_t *pService,
                                 CpaDcSessionSetupData *pSessionData,
                                 Cpa8U *pDcCmdId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pService);
    LAC_CHECK_NULL_PARAM(pSessionData);
    LAC_CHECK_NULL_PARAM(pDcCmdId);
#endif

    *pDcCmdId = ICP_QAT_FW_COMP_CMD_DELIMITER;

    switch (pSessionData->compType)
    {
        case CPA_DC_DEFLATE:
            if (CPA_DC_HT_FULL_DYNAMIC == pSessionData->huffType)
            {
                *pDcCmdId = ICP_QAT_FW_COMP_CMD_DYNAMIC;
            }
            else if (CPA_DC_HT_STATIC == pSessionData->huffType)
            {
                *pDcCmdId = ICP_QAT_FW_COMP_CMD_STATIC;
            }
            break;
        case CPA_DC_LZ4:
            *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4_COMPRESS;
            break;
        case CPA_DC_LZ4S:
            *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4S_COMPRESS;
            break;
        default:
            LAC_LOG_ERROR("Algorithm not supported for compression\n");
            status = CPA_STATUS_UNSUPPORTED;
            break;
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
CpaStatus dcGetDecompressCommandId(sal_compression_service_t *pService,
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

        switch (pSessionData->compType)
        {
            case CPA_DC_DEFLATE:
                *pDcCmdId = ICP_QAT_FW_COMP_CMD_DECOMPRESS;
                break;
            case CPA_DC_LZ4:
                *pDcCmdId = ICP_QAT_FW_COMP_20_CMD_LZ4_DECOMPRESS;
                break;
            default:
                LAC_ENSURE(CPA_FALSE, "Algo not supported for decompression\n");
                status = CPA_STATUS_UNSUPPORTED;
                break;
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

CpaStatus dcInitSessionCrcControl(CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle,
                                  CpaCrcControlData *pCrcControlData)
{
    dc_session_desc_t *pSessionDesc = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    sal_compression_service_t *pService = NULL;
    CpaBoolean bPcrc64Supported = CPA_FALSE;
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pCrcControlData);

    /* Check that the parameters defined in the pCrcControlData are valid */
    if (CPA_STATUS_SUCCESS != dcCheckSessionCrcControlData(pCrcControlData))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif
    pService = (sal_compression_service_t *)dcInstance;
    pDcCapabilities = &pService->dc_capabilities;
    dcGetPcrc64CapabilityStatus(
        pDcCapabilities, pSessionDesc->compType, &bPcrc64Supported);
    if (!bPcrc64Supported)
    {
        LAC_LOG_ERROR("Programmable CRC64 is unsupported");
        return CPA_STATUS_UNSUPPORTED;
    }
    /* Generate the CRC64 lookup table for the provided polynomial */
    status = dcGenerateLookupTable(pCrcControlData->polynomial,
                                   &pSessionDesc->crcConfig.pCrcLookupTable);
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set CRC parameters provided */
        pSessionDesc->crcConfig.crcParam.crc64Poly =
            pCrcControlData->polynomial;
        pSessionDesc->crcConfig.crcParam.iCrc64Cpr =
            pCrcControlData->initialValue;
        pSessionDesc->crcConfig.crcParam.oCrc64Cpr =
            pCrcControlData->initialValue;
        pSessionDesc->crcConfig.crcParam.reflectIn =
            (Cpa32U)pCrcControlData->reflectIn;
        pSessionDesc->crcConfig.crcParam.reflectOut =
            (Cpa32U)pCrcControlData->reflectOut;
        pSessionDesc->crcConfig.crcParam.oCrc64Xlt =
            pCrcControlData->initialValue;
        pSessionDesc->crcConfig.crcParam.xor64Out = pCrcControlData->xorOut;

        pSessionDesc->crcConfig.useProgCrcSetup = CPA_TRUE;
    }

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
    dc_capabilities_t *pDcCapabilities;
    CpaBoolean capabilityDcStateful = CPA_FALSE;
    Cpa16U numInterBuffs = 0;

    cmnRequestFlags = ICP_QAT_FW_COMN_FLAGS_BUILD(
        QAT_COMN_CD_FLD_TYPE_16BYTE_DATA, DC_DEFAULT_QAT_PTR_TYPE);

    pService = (sal_compression_service_t *)dcInstance;

    /* Retrieve internal capabilities */
    pDcCapabilities = &pService->dc_capabilities;
    capabilityDcStateful =
        DC_CAPS_BITFIELD_GET(pDcCapabilities->sessState, CPA_DC_STATEFUL);
    numInterBuffs = pDcCapabilities->numInterBuffs;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pSessionData);

    /* Check that the parameters defined in the pSessionData are valid and
     * supported by the device
     */
    status = dcCheckSessionData(pSessionData, dcInstance);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
#endif

    status = dcCheckUnsupportedParams(pSessionData, dcInstance);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_UNSUPPORTED_PARAM_LOG("Trying to set unsupported features");
        return status;
    }

    if ((CPA_DC_STATEFUL == pSessionData->sessState) &&
        (CPA_DC_DIR_DECOMPRESS != pSessionData->sessDirection))
    {
        LAC_UNSUPPORTED_PARAM_LOG("Stateful sessions are not supported");
        return CPA_STATUS_UNSUPPORTED;
    }
    /* Check for Gen4 and stateful, return error if both exist */
    if ((CPA_FALSE == capabilityDcStateful) &&
        CPA_DC_STATEFUL == pSessionData->sessState)
    {
        LAC_INVALID_PARAM_LOG("Stateful sessions are not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    secureRam = pDcCapabilities->deviceData.useDevRam;

    if ((numInterBuffs > 0) &&
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
            return status;
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
    pSessionDesc->crcConfig.useProgCrcSetup = CPA_FALSE;
    pSessionDesc->crcConfig.pCrcLookupTable = NULL;
    pSessionDesc->lz4OutputFormat = CPA_DC_LZ4_OUTPUT_WITH_HEADER;

    /* Alter auto select best setting depending on the hardware version */
    /* Configure CRC parameters based on the hardware version */
    if (DC_CAPS_GEN4_HW != pDcCapabilities->deviceData.hw_gen)
    {
        /* Gen 2 hardware devices */
        if (CPA_DC_ASB_ENABLED == pSessionDesc->autoSelectBestHuffmanTree)
        {
            /* Select best compression ratio optimization setting */
            pSessionDesc->autoSelectBestHuffmanTree =
                CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS;
        }

        /* Gen2 hardcoded CRC parameters */
        pSessionDesc->crcConfig.crcParam.crcPoly = DC_CRC_POLY_DEFAULT;
        pSessionDesc->crcConfig.crcParam.iCrc32Cpr = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.oCrc32Cpr = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.iCrc32Xlt = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.oCrc32Xlt = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.xorFlags = DC_XOR_FLAGS_DEFAULT;
        pSessionDesc->crcConfig.crcParam.xorOut = DC_XOR_OUT_DEFAULT;
        pSessionDesc->crcConfig.crcParam.deflateBlockType = DC_STATIC_TYPE;
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
            /* Gen4 hardcoded CRC parameters */
        pSessionDesc->crcConfig.crcParam.crc64Poly = DC_CRC64_POLY_DEFAULT;
        pSessionDesc->crcConfig.crcParam.iCrc64Cpr = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.oCrc64Cpr = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.reflectIn = DC_REFLECT_IN_DEFAULT;
        pSessionDesc->crcConfig.crcParam.reflectOut = DC_REFLECT_OUT_DEFAULT;
        pSessionDesc->crcConfig.crcParam.oCrc64Xlt = DC_DEFAULT_CRC;
        pSessionDesc->crcConfig.crcParam.xor64Out = DC_XOR64_OUT_DEFAULT;
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
        if ((DC_CAPS_GEN4_HW != pDcCapabilities->deviceData.hw_gen) &&
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

    /* Retrieve internal capabilities */
    dc_capabilities_t *pDcCapabilities = &pService->dc_capabilities;

    /* Check if DRAM is available for the intermediate buffers
     * for dynamic compression */
    if ((pDcCapabilities->numInterBuffs > 0) &&
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
    dc_request_dir_t compDecomp;

    /* Retrieve internal capabilities */
    dc_capabilities_t *pDcCapabilities = &pService->dc_capabilities;

    compDecomp = DC_COMPRESSION_REQUEST;

    /* Acquire a lock prior to updating the session parameters
     * for traditional only */
    if (CPA_FALSE == pSessionDesc->isDcDp)
    {
        LAC_SPINLOCK(&(pSessionDesc->updateLock));
    }

    pDcCapabilities->deviceData.enableDmm =
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
    (pDcCapabilities->dcCompHwBlockPopulate)((void *)pService,
                                             (void *)pSessionDesc,
                                             NULL,
                                             pCompConfig,
                                             (void *)&compDecomp,
                                             CPA_FALSE);

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
    /* Ensure this is a compression or a decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
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

CpaStatus cpaDcSetLZ4OutputFormat(CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle,
                                  CpaDcLZ4OutputFormat outLZ4Format)
{
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);

    if (CPA_DC_LZ4_OUTPUT_WITH_HEADER > outLZ4Format ||
        CPA_DC_LZ4_OUTPUT_WITHOUT_HEADER < outLZ4Format)
    {
        LAC_INVALID_PARAM_LOG("Invalid outLZ4Format");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)outLZ4Format);
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

    if (CPA_DC_LZ4 != pSessionDesc->compType)
    {
        LAC_INVALID_PARAM_LOG("Invalid compression type");
        return CPA_STATUS_INVALID_PARAM;
    }

    pService = (sal_compression_service_t *)insHandle;

    if (!(pService->generic_service_info.dcExtendedFeatures &
          DC_LZ4_E2E_COMP_CRC_OVER_BLOCK_EXTENDED_CAPABILITY) &&
        (CPA_DC_LZ4_OUTPUT_WITHOUT_HEADER == outLZ4Format))
    {
        LAC_UNSUPPORTED_PARAM_LOG("CRC over LZ4 data block (without header) "
                                  "feature not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    pSessionDesc->lz4OutputFormat = outLZ4Format;

    return CPA_STATUS_SUCCESS;
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
    sal_compression_service_t *pService = NULL;
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
    /* Ensure this is a compression or a decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
#endif
    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pService = (sal_compression_service_t *)(insHandle);

    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        if (pService->generic_service_info.type == SAL_SERVICE_TYPE_COMPRESSION)
        {
            trans_handle = ((sal_compression_service_t *)insHandle)
                               ->trans_handle_compression_tx;
        }
        else
        {
            trans_handle = ((sal_compression_service_t *)insHandle)
                               ->trans_handle_decompression_tx;
        }

        if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
        {
            LAC_LOG_ERROR("There are remaining messages on the ring");

            /* Process the remaining messages on the ring */
            status = icp_adf_updateQueueTail(trans_handle);
            if (CPA_STATUS_SUCCESS != status)
            {
                return status;
            }

            return CPA_STATUS_RETRY;
        }

        /* Check if there are stateless pending requests */
        if (0 != pSessionDesc->pendingDpStatelessCbCount)
        {
            LAC_LOG_ERROR1("There are %llu stateless DP requests pending",
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
            LAC_LOG_ERROR1("There are %llu stateless requests pending",
                           numPendingStateless);
            return CPA_STATUS_RETRY;
        }
        /* Check if there are stateful pending requests */
        if (0 != numPendingStateful)
        {
            LAC_LOG_ERROR1("There are %llu stateful requests pending",
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
    sal_compression_service_t *pService = NULL;

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
    /* Ensure this is a compression or a decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
#endif

    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pService = (sal_compression_service_t *)(insHandle);

    if (CPA_TRUE == pSessionDesc->isDcDp)
    {
        if (pService->generic_service_info.type == SAL_SERVICE_TYPE_COMPRESSION)
        {
            trans_handle = ((sal_compression_service_t *)insHandle)
                               ->trans_handle_compression_tx;
        }
        else
        {
            trans_handle = ((sal_compression_service_t *)insHandle)
                               ->trans_handle_decompression_tx;
        }

        if (CPA_TRUE == icp_adf_queueDataToSend(trans_handle))
        {
            LAC_LOG_ERROR("There are remaining messages on the ring");

            /* Process the remaining messages on the ring */
            status = icp_adf_updateQueueTail(trans_handle);
            if (CPA_STATUS_SUCCESS != status)
            {
                return status;
            }

            return CPA_STATUS_RETRY;
        }

        /* Check if there are stateless pending requests */
        if (0 != pSessionDesc->pendingDpStatelessCbCount)
        {
            LAC_LOG_ERROR1("There are %llu stateless DP requests pending",
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
            LAC_LOG_ERROR1("There are %llu stateless requests pending",
                           numPendingStateless);
            status = CPA_STATUS_RETRY;
        }

        /* Check if there are stateful pending requests */
        if (0 != numPendingStateful)
        {
            LAC_LOG_ERROR1("There are %llu stateful requests pending",
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
    /* Free the CRC lookup table if one was allocated */
    if (NULL != pSessionDesc->crcConfig.pCrcLookupTable)
    {
        LAC_OS_FREE(pSessionDesc->crcConfig.pCrcLookupTable);
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
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
    LAC_CHECK_NULL_PARAM(pSessionData);
    status = dcCheckSessionData(pSessionData, insHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
#endif

    status = dcCheckUnsupportedParams(pSessionData, insHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_UNSUPPORTED_PARAM_LOG("Trying to set unsupported features");
        return status;
    }

    /* Get session size for session data */
    *pSessionSize = sizeof(dc_session_desc_t) + LAC_64BYTE_ALIGNMENT +
                    sizeof(LAC_ARCH_UINT);

    if (NULL != pContextSize)
    {
        status = dcGetContextSize(insHandle, pSessionData, pContextSize);

        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Unable to get the context size of the session\n");
            return status;
        }
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcGetSessionSize(CpaInstanceHandle dcInstance,
                              CpaDcSessionSetupData *pSessionData,
                              Cpa32U *pSessionSize,
                              Cpa32U *pContextSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
/* Check parameter */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionSize);
    LAC_CHECK_NULL_PARAM(pContextSize);
#endif
    status =
        dcGetSessionSize(dcInstance, pSessionData, pSessionSize, pContextSize);
#ifdef ICP_TRACE
    LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx[%d], 0x%lx[%d])\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionData,
             (LAC_ARCH_UINT)pSessionSize,
             *pSessionSize,
             (LAC_ARCH_UINT)pContextSize,
             *pContextSize);
#endif
    return status;
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

    /* Retrieve internal capabilities */
    dc_capabilities_t *pDcCapabilities = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

    pDcCapabilities = &pService->dc_capabilities;

    if (CPA_TRUE != pDcCapabilities->cnv.errorInjection)
    {
        LAC_LOG_ERROR("Unsupported compression feature.\n");
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

CpaStatus cpaDcSetAsbThreshold(const CpaInstanceHandle dcInstance,
                               CpaDcSessionHandle pSessionHandle,
                               CpaDcAsbThreshold asbThreshold)
{
    CpaInstanceHandle insHandle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    sal_compression_service_t *pCompService = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;

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
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_PARAM_RANGE(
        asbThreshold, CPA_DC_ASB_THRESHOLD_256, CPA_DC_ASB_THRESHOLD_65536 + 1);
#endif

    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

    pCompService = (sal_compression_service_t *)insHandle;
    pDcCapabilities = &pCompService->dc_capabilities;

    if (!((pDcCapabilities->asb.supported) &&
          (pDcCapabilities->asb.asbTshSupported)))
    {
        LAC_UNSUPPORTED_PARAM_LOG("ASB threshold mode not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid session direction");
        return CPA_STATUS_INVALID_PARAM;
    }

    pSessionDesc->asb_mode = DC_ASB_THRESHOLD_MODE;
    pSessionDesc->asb_value = asbThreshold;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcSetAsbRatio(const CpaInstanceHandle dcInstance,
                           CpaDcSessionHandle pSessionHandle,
                           CpaDcAsbRatio asbRatio)
{
    CpaInstanceHandle insHandle = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    sal_compression_service_t *pCompService = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;

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
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_PARAM_LT_MAX(asbRatio, CPA_DC_ASB_RATIO_16_SIXTEENTH + 1);
#endif

    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionDesc);
#endif

    pCompService = (sal_compression_service_t *)insHandle;
    pDcCapabilities = &pCompService->dc_capabilities;

    if (!((pDcCapabilities->asb.supported) &&
          (pDcCapabilities->asb.asbRatioSupported)))
    {
        LAC_UNSUPPORTED_PARAM_LOG("ASB ratio mode not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_DC_DIR_DECOMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid session direction");
        return CPA_STATUS_INVALID_PARAM;
    }

    pSessionDesc->asb_mode = DC_ASB_RATIO_MODE;
    pSessionDesc->asb_value = asbRatio;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcSetCrcControlData(CpaInstanceHandle dcInstance,
                                 CpaDcSessionHandle pSessionHandle,
                                 CpaCrcControlData *pCrcControlData)
{
#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pCrcControlData);
#endif
    return dcInitSessionCrcControl(dcInstance, pSessionHandle, pCrcControlData);
}
