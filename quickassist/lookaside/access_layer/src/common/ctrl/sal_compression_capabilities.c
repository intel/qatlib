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
 * @file sal_compression_capabilities.c
 *
 * @defgroup SalCtrl_SetDCCaps for different devices
 *
 * @ingroup SalCtrl_SetDCCaps
 *
 * @description
 *      Set capabilities based on device type for all devices
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa_dc_chain.h"

#include "icp_qat_fw_comp.h"
#include "icp_qat_hw_20_comp_defs.h"
#include "icp_qat_hw_51_comp_defs.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "sal_types_compression.h"
#include "dc_session.h"

/* DEBUG  */
#ifdef ICP_DEBUG
#undef STATIC
/* When DEBUG is set STATIC evaluates to nothing. */
#define STATIC
#else
/* otherwise it evaluates to the static keyword */
#define STATIC static
#endif

STATIC void SalCtrl_Set4xxxDcExtendedCapabilities(
    dc_capabilities_t *pDcCapabilities,
    fw_caps_t *fw_caps)
{
    pDcCapabilities->checksum =
        ((fw_caps->cksum_algos & DC_CAPS_CRC32) |
         (fw_caps->cksum_algos & DC_CAPS_ADLER32) |
         ((fw_caps->cksum_algos & DC_CAPS_ADLER32) << DC_CAPS_XXHASH32_OFFSET));
    pDcCapabilities->deflate.supported =
        (fw_caps->comp_algos & DC_CAPS_DEFLATE_SUPPORTED);
    pDcCapabilities->deflate.dynamicHuffmanBufferReq =
        LAC_SHIFT_RIGHT((fw_caps->deflate_caps & DC_CAPS_DYNAMIC_HUFF_BUFF_REQ),
                        DC_CAPS_DYNAMIC_HUFF_OFFSET);
    pDcCapabilities->deflate.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
    pDcCapabilities->lz4.supported = LAC_SHIFT_RIGHT(
        (fw_caps->comp_algos & DC_CAPS_LZ4_SUPPORTED), DC_CAPS_LZ4_OFFSET);
    pDcCapabilities->lz4.checksumXXHash32 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_ADLER32), DC_CAPS_ADLER32_OFFSET);
    pDcCapabilities->lz4.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
    pDcCapabilities->lz4s.supported = LAC_SHIFT_RIGHT(
        (fw_caps->comp_algos & DC_CAPS_LZ4S_SUPPORTED), DC_CAPS_LZ4S_OFFSET);
    pDcCapabilities->lz4s.checksumXXHash32 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_ADLER32), DC_CAPS_ADLER32_OFFSET);
    pDcCapabilities->lz4s.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
}

STATIC void SalCtrl_Set4xxxDcCapabilities(dc_capabilities_t *pDcCapabilities,
                                          Cpa32U dcExtendedFeatures,
                                          fw_caps_t *fw_caps,
                                          device_type_t device_type)
{
    dc_extd_ftrs_t *pExtendedFtrs = (dc_extd_ftrs_t *)&(dcExtendedFeatures);
    memset(pDcCapabilities, 0, sizeof(dc_capabilities_t));

    /* Set compression HW capabilitities */
    pDcCapabilities->deviceData.translatorOverflow = CPA_TRUE;
    pDcCapabilities->deviceData.oddByteDecompNobFinal = CPA_TRUE;
    pDcCapabilities->deviceData.enableDmm = CPA_TRUE;
    pDcCapabilities->deviceData.minOutputBuffSize =
        DC_DEST_BUFFER_STA_MIN_SIZE_GEN4;
    pDcCapabilities->deviceData.minOutputBuffSizeDynamic =
        DC_DEST_BUFFER_DYN_MIN_SIZE_GEN4;
    pDcCapabilities->deviceData.useDevRam =
        ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
    pDcCapabilities->deviceData.highestHwCompressionDepth =
        ICP_QAT_HW_COMP_20_SEARCH_DEPTH_LEVEL_9;
    pDcCapabilities->deviceData.uncompressedDataSupported = CPA_TRUE;
    pDcCapabilities->deviceData.hw_gen = DC_CAPS_GEN4_HW;
    pDcCapabilities->deviceData.compressionServiceSupported = CPA_TRUE;
    if (device_type == DEVICE_420XX || device_type == DEVICE_420XXVF)
    {
        pDcCapabilities->dcDeflateBound = dcDeflateBoundGen4_2;
    }
    else
    {
        pDcCapabilities->dcDeflateBound = dcDeflateBoundGen4;
    }
    pDcCapabilities->dcLZ4Bound = dcLZ4BoundGen4;
    pDcCapabilities->dcLZ4SBound = dcLZ4SBoundGen4;
    pDcCapabilities->dcCompHwBlockPopulate = dcCompHwBlockPopulateGen4;
    pDcCapabilities->dcNsCompHwBlockPopulate = dcCompHwBlockPopulateGen4;

    /* Set generic capabilities */
    pDcCapabilities->sessState = DC_CAPS_STATELESS;
    pDcCapabilities->checksum =
        (DC_CAPS_CRC32 | DC_CAPS_ADLER32 | DC_CAPS_XXHASH32);
    pDcCapabilities->numInterBuffs = 0;
    pDcCapabilities->endOfLastBlock = CPA_TRUE;
    pDcCapabilities->storedBlockGeneration = CPA_TRUE;
    pDcCapabilities->reportParityError = CPA_TRUE;
    pDcCapabilities->asb.supported = CPA_TRUE;

    /* Set data integrity capabilities */
    pDcCapabilities->crcIntegrity.supported = CPA_TRUE;
    pDcCapabilities->crcIntegrity.checkCRC64 = CPA_TRUE;

    /* Set CNV capabilities */
    pDcCapabilities->cnv.supported =
        (dcExtendedFeatures & DC_CNV_EXTENDED_CAPABILITY);
    pDcCapabilities->cnv.recovery =
        LAC_SHIFT_RIGHT((dcExtendedFeatures & DC_CNVNR_EXTENDED_CAPABILITY),
                        DC_CAPS_CNVNR_EXTENDED_OFFSET);
    pDcCapabilities->cnv.errorInjection = CPA_TRUE;
    pDcCapabilities->cnv.strict = CPA_TRUE;

    /* Set deflate capabilities */
    DC_CAPS_DEFLATE_TYPE_SUPPORT_SET(pDcCapabilities->deflate.typeSupport,
                                     DC_CAPS_DEFLATE_TYPE_STATIC,
                                     DC_CAPS_DEFLATE_TYPE_SUPPORTED);
    DC_CAPS_DEFLATE_TYPE_SUPPORT_SET(pDcCapabilities->deflate.typeSupport,
                                     DC_CAPS_DEFLATE_TYPE_DYNAMIC,
                                     DC_CAPS_DEFLATE_TYPE_SUPPORTED);

    pDcCapabilities->deflate.supported = CPA_TRUE;
    pDcCapabilities->deflate.dirMask =
        (DC_CAPS_COMPRESSION | DC_CAPS_DECOMPRESSION);
    pDcCapabilities->deflate.inflateContextSize = DC_INFLATE_CONTEXT_SIZE;
    pDcCapabilities->deflate.dynamicHuffmanBufferReq = CPA_TRUE;
    pDcCapabilities->deflate.internalHuffmanMem = CPA_TRUE;
    pDcCapabilities->deflate.bypassIncompleteFileErr = CPA_TRUE;
    pDcCapabilities->deflate.historyBufferSize = CPA_DC_WINSIZE_32K;
    pDcCapabilities->deflate.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->deflate.validWindowSizeMaskCompression =
        DC_32K_WINDOW_MASK;
    pDcCapabilities->deflate.validWindowSizeMaskDecompression =
        DC_4K_WINDOW_MASK | DC_8K_WINDOW_MASK | DC_16K_WINDOW_MASK |
        DC_32K_WINDOW_MASK;
    pDcCapabilities->deflate.programmableCrc64 = CPA_TRUE;
    pDcCapabilities->deflate.hashThenCompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_hash_then_compress;

    /* Set lz4 capabilities */
    pDcCapabilities->lz4.supported = CPA_TRUE;
    pDcCapabilities->lz4.dirMask =
        (DC_CAPS_COMPRESSION | DC_CAPS_DECOMPRESSION);
    pDcCapabilities->lz4.decompContextSize = DC_LZ4_DECOMP_CONTEXT_SIZE;
    pDcCapabilities->lz4.checksumXXHash32 = CPA_TRUE;
    pDcCapabilities->lz4.blockIndependence = CPA_TRUE;
    pDcCapabilities->lz4.accumulateXXHash = CPA_TRUE;
    pDcCapabilities->lz4.maxBlockSize =
        (DC_CAPS_LZ4_64K | DC_CAPS_LZ4_256K | DC_CAPS_LZ4_1M | DC_CAPS_LZ4_4M);
    pDcCapabilities->lz4.historyBufferSize = CPA_DC_WINSIZE_32K;
    pDcCapabilities->lz4.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->lz4.validWindowSizeMaskCompression = DC_32K_WINDOW_MASK;
    pDcCapabilities->lz4.validWindowSizeMaskDecompression =
        DC_4K_WINDOW_MASK | DC_8K_WINDOW_MASK | DC_16K_WINDOW_MASK |
        DC_32K_WINDOW_MASK;
    pDcCapabilities->lz4.programmableCrc64 = CPA_TRUE;

    /* Set lz4s capabilities */
    pDcCapabilities->lz4s.supported = CPA_TRUE;
    pDcCapabilities->lz4s.dirMask = DC_CAPS_COMPRESSION;
    pDcCapabilities->lz4s.checksumXXHash32 = CPA_TRUE;
    pDcCapabilities->lz4s.minMatch = (DC_CAPS_LZ4S_3B | DC_CAPS_LZ4S_4B);
    pDcCapabilities->lz4s.historyBufferSize = CPA_DC_WINSIZE_32K;
    pDcCapabilities->lz4s.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->lz4s.validWindowSizeMaskCompression = DC_32K_WINDOW_MASK;
    pDcCapabilities->lz4s.programmableCrc64 = CPA_TRUE;

    /* Overwrite default capabilities with capabilities returned
     * from firmware if available. */
    if (fw_caps->is_fw_caps)
    {
        SalCtrl_Set4xxxDcExtendedCapabilities(pDcCapabilities, fw_caps);
    }
}

STATIC void SalCtrl_Set6xxxDcExtendedCapabilities(
    dc_capabilities_t *pDcCapabilities,
    fw_caps_t *fw_caps)
{
    pDcCapabilities->checksum =
        ((fw_caps->cksum_algos & DC_CAPS_CRC32) |
         (fw_caps->cksum_algos & DC_CAPS_ADLER32) |
         ((fw_caps->cksum_algos & DC_CAPS_ADLER32) << DC_CAPS_XXHASH32_OFFSET) |
         ((fw_caps->cksum_algos & DC_CAPS_ADLER32) << DC_CAPS_XXHASH64_OFFSET));
    pDcCapabilities->deflate.supported =
        (fw_caps->comp_algos & DC_CAPS_DEFLATE_SUPPORTED);
    pDcCapabilities->deflate.dynamicHuffmanBufferReq =
        LAC_SHIFT_RIGHT((fw_caps->deflate_caps & DC_CAPS_DYNAMIC_HUFF_BUFF_REQ),
                        DC_CAPS_DYNAMIC_HUFF_OFFSET);
    pDcCapabilities->deflate.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
    pDcCapabilities->lz4.supported = LAC_SHIFT_RIGHT(
        (fw_caps->comp_algos & DC_CAPS_LZ4_SUPPORTED), DC_CAPS_LZ4_OFFSET);
    pDcCapabilities->lz4.checksumXXHash32 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_ADLER32), DC_CAPS_ADLER32_OFFSET);
    pDcCapabilities->lz4.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
    pDcCapabilities->lz4s.supported = LAC_SHIFT_RIGHT(
        (fw_caps->comp_algos & DC_CAPS_LZ4S_SUPPORTED), DC_CAPS_LZ4S_OFFSET);
    pDcCapabilities->lz4s.checksumXXHash32 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_ADLER32), DC_CAPS_ADLER32_OFFSET);
    pDcCapabilities->lz4s.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
    pDcCapabilities->zstd.supported = LAC_SHIFT_RIGHT(
        (fw_caps->comp_algos & DC_CAPS_ZSTD_SUPPORTED), DC_CAPS_ZSTD_OFFSET);
    pDcCapabilities->zstd.checksumXXHash64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_ADLER32), DC_CAPS_ADLER32_OFFSET);
    pDcCapabilities->zstd.programmableCrc64 = LAC_SHIFT_RIGHT(
        (fw_caps->cksum_algos & DC_CAPS_PCRC), DC_CAPS_PCRC_OFFSET);
    pDcCapabilities->zstd.dictId = LAC_SHIFT_RIGHT(
	(fw_caps->zstd_caps & DC_CAPS_DICT_ID), DC_CAPS_DICT_ID_OFFSET);
}

STATIC void SalCtrl_Set6xxxDcCapabilities(dc_capabilities_t *pDcCapabilities,
                                          Cpa32U dcExtendedFeatures,
                                          fw_caps_t *fw_caps)
{
    LAC_OS_BZERO(pDcCapabilities, sizeof(dc_capabilities_t));

    dc_extd_ftrs_t *pExtendedFtrs = (dc_extd_ftrs_t *)&(dcExtendedFeatures);

    /* Set compression HW capabilitities */
    pDcCapabilities->deviceData.oddByteDecompNobFinal = CPA_TRUE;
    pDcCapabilities->deviceData.oddByteDecompInterim = CPA_TRUE;
    pDcCapabilities->deviceData.enableDmm = CPA_TRUE;
    pDcCapabilities->deviceData.minOutputBuffSize =
        DC_DEST_BUFFER_MIN_SIZE_GEN6;
    pDcCapabilities->deviceData.minOutputBuffSizeDynamic =
        DC_DEST_BUFFER_DYN_MIN_SIZE_GEN6;
    pDcCapabilities->deviceData.useDevRam =
        ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
    pDcCapabilities->deviceData.highestHwCompressionDepth =
        ICP_QAT_HW_COMP_51_SEARCH_DEPTH_LEVEL_9;
    pDcCapabilities->deviceData.uncompressedDataSupported = CPA_TRUE;
    pDcCapabilities->deviceData.hw_gen = DC_CAPS_GEN6_HW;
    pDcCapabilities->deviceData.decompressionServiceSupported = CPA_TRUE;
    pDcCapabilities->deviceData.compressionServiceSupported = CPA_TRUE;
    pDcCapabilities->dcDeflateBound = dcDeflateBoundGen6;
    pDcCapabilities->dcLZ4Bound = dcLZ4BoundGen6;
    pDcCapabilities->dcLZ4SBound = dcLZ4SBoundGen6;
    pDcCapabilities->dcZstdBound = dcZstdBoundGen6;
    pDcCapabilities->dcCompHwBlockPopulate = dcCompHwBlockPopulateGen6;
    pDcCapabilities->dcNsCompHwBlockPopulate = dcCompHwBlockPopulateGen6;
    pDcCapabilities->dcGetMetaSizeForSrcBuffWithDict =
        dcGetMetaSizeForSrcBuffWithDictGen6;

    /* Set generic capabilities */
    pDcCapabilities->sessState = DC_CAPS_STATELESS;
    pDcCapabilities->checksum =
        (DC_CAPS_CRC32 | DC_CAPS_ADLER32 | DC_CAPS_XXHASH32 | DC_CAPS_XXHASH64);
    pDcCapabilities->numInterBuffs = 0;
    pDcCapabilities->endOfLastBlock = CPA_TRUE;
    pDcCapabilities->storedBlockGeneration = CPA_TRUE;
    pDcCapabilities->determinism = CPA_TRUE;
    pDcCapabilities->reportParityError = CPA_TRUE;
    pDcCapabilities->overflowResubmitUnsupported = CPA_TRUE;
    pDcCapabilities->statefulLiteUnsupported = CPA_TRUE;

    /* Set asb capabilities */
    pDcCapabilities->asb.supported = CPA_TRUE;
    pDcCapabilities->asb.asbTshSupported = CPA_TRUE;
    pDcCapabilities->asb.asbRatioSupported = CPA_TRUE;

    /* Set data integrity capabilities */
    pDcCapabilities->crcIntegrity.supported = CPA_TRUE;
    pDcCapabilities->crcIntegrity.checkCRC64 = CPA_TRUE;

    /* Set CNV capabilities */
    pDcCapabilities->cnv.supported =
        (dcExtendedFeatures & DC_CNV_EXTENDED_CAPABILITY);
    pDcCapabilities->cnv.recovery =
        LAC_SHIFT_RIGHT((dcExtendedFeatures & DC_CNVNR_EXTENDED_CAPABILITY),
                        DC_CAPS_CNVNR_EXTENDED_OFFSET);

    pDcCapabilities->cnv.errorInjection = CPA_TRUE;
    pDcCapabilities->cnv.strict = CPA_TRUE;

    /* Set deflate capabilities */
    DC_CAPS_DEFLATE_TYPE_SUPPORT_SET(pDcCapabilities->deflate.typeSupport,
                                     DC_CAPS_DEFLATE_TYPE_DYNAMIC,
                                     DC_CAPS_DEFLATE_TYPE_SUPPORTED);

    pDcCapabilities->deflate.supported = CPA_TRUE;
    pDcCapabilities->deflate.dirMask =
        (DC_CAPS_COMPRESSION | DC_CAPS_DECOMPRESSION);
    pDcCapabilities->deflate.dynamicHuffmanBufferReq = CPA_FALSE;
    pDcCapabilities->deflate.precompiledHuffman = CPA_FALSE;
    pDcCapabilities->deflate.internalHuffmanMem = CPA_TRUE;
    pDcCapabilities->deflate.bypassIncompleteFileErr = CPA_TRUE;
    pDcCapabilities->deflate.historyBufferSize = CPA_DC_WINSIZE_32K;
    pDcCapabilities->deflate.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->deflate.validWindowSizeMaskCompression =
        DC_32K_WINDOW_MASK;
    pDcCapabilities->deflate.validWindowSizeMaskDecompression =
        DC_4K_WINDOW_MASK | DC_8K_WINDOW_MASK | DC_16K_WINDOW_MASK |
        DC_32K_WINDOW_MASK;
    pDcCapabilities->deflate.asbSupported = CPA_TRUE;
    pDcCapabilities->deflate.dictCompSupported = CPA_TRUE;
    pDcCapabilities->deflate.dictCap = DC_CAPS_UNCOMPRESSED_DICT;
    pDcCapabilities->deflate.programmableCrc64 = CPA_TRUE;
    pDcCapabilities->deflate.hashThenCompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_hash_then_compress;
    pDcCapabilities->deflate.compressThenAeadSupported =
        (Cpa8U)pExtendedFtrs->is_chain_compress_then_aead;
    pDcCapabilities->deflate.aeadThenDecompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_aead_then_decompress;

    /* Set lz4 capabilities */
    pDcCapabilities->lz4.supported = CPA_TRUE;
    pDcCapabilities->lz4.dirMask =
        (DC_CAPS_COMPRESSION | DC_CAPS_DECOMPRESSION);
    pDcCapabilities->lz4.checksumXXHash32 = CPA_TRUE;
    pDcCapabilities->lz4.accumulateXXHash = CPA_FALSE;
    pDcCapabilities->lz4.blockIndependence = CPA_TRUE;
    pDcCapabilities->lz4.maxBlockSize = DC_CAPS_LZ4_64K;
    pDcCapabilities->lz4.historyBufferSize = CPA_DC_WINSIZE_64K;
    pDcCapabilities->lz4.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->lz4.validWindowSizeMaskCompression = DC_64K_WINDOW_MASK;
    pDcCapabilities->lz4.validWindowSizeMaskDecompression =
        DC_4K_WINDOW_MASK | DC_8K_WINDOW_MASK | DC_16K_WINDOW_MASK |
        DC_32K_WINDOW_MASK | DC_64K_WINDOW_MASK;
    pDcCapabilities->lz4.asbSupported = CPA_TRUE;
    pDcCapabilities->lz4.programmableCrc64 = CPA_TRUE;
    pDcCapabilities->lz4.hashThenCompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_hash_then_compress;
    pDcCapabilities->lz4.compressThenAeadSupported =
        (Cpa8U)pExtendedFtrs->is_chain_compress_then_aead;
    pDcCapabilities->lz4.aeadThenDecompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_aead_then_decompress;
    pDcCapabilities->lz4.asbEnablePref = CPA_TRUE;

    /* Set lz4s capabilities */
    pDcCapabilities->lz4s.supported = CPA_TRUE;
    pDcCapabilities->lz4s.dirMask = DC_CAPS_COMPRESSION;
    pDcCapabilities->lz4s.checksumXXHash32 = CPA_TRUE;
    pDcCapabilities->lz4s.minMatch = (DC_CAPS_LZ4S_3B | DC_CAPS_LZ4S_4B);
    pDcCapabilities->lz4s.historyBufferSize = CPA_DC_WINSIZE_64K;
    pDcCapabilities->lz4s.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->lz4s.validWindowSizeMaskCompression = DC_64K_WINDOW_MASK;
    pDcCapabilities->lz4s.asbSupported = CPA_FALSE;
    pDcCapabilities->lz4s.dictCompSupported = CPA_TRUE;
    pDcCapabilities->lz4s.dictCap = DC_CAPS_UNCOMPRESSED_DICT;
    pDcCapabilities->lz4s.programmableCrc64 = CPA_TRUE;

    /* Set zstd capabilities */
    pDcCapabilities->zstd.supported = CPA_TRUE;
    pDcCapabilities->zstd.dirMask =
        (DC_CAPS_COMPRESSION | DC_CAPS_DECOMPRESSION);
    pDcCapabilities->zstd.checksumXXHash64 = CPA_TRUE;
    pDcCapabilities->zstd.historyBufferSize = CPA_DC_WINSIZE_64K;
    pDcCapabilities->zstd.zerolengthRequests = CPA_TRUE;
    pDcCapabilities->zstd.validWindowSizeMaskCompression = DC_64K_WINDOW_MASK;
    pDcCapabilities->zstd.validWindowSizeMaskDecompression =
        DC_4K_WINDOW_MASK | DC_8K_WINDOW_MASK | DC_16K_WINDOW_MASK |
        DC_32K_WINDOW_MASK | DC_64K_WINDOW_MASK;

    pDcCapabilities->zstd.asbSupported = CPA_TRUE;
    pDcCapabilities->zstd.asbEnablePref = CPA_TRUE;
    pDcCapabilities->zstd.dictCompSupported = CPA_TRUE;
    pDcCapabilities->zstd.dictCap = DC_CAPS_UNCOMPRESSED_DICT;
    pDcCapabilities->zstd.dictId = CPA_TRUE;
    pDcCapabilities->zstd.programmableCrc64 = CPA_TRUE;
    pDcCapabilities->zstd.hashThenCompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_hash_then_compress;
    pDcCapabilities->zstd.compressThenAeadSupported =
        (Cpa8U)pExtendedFtrs->is_chain_compress_then_aead;
    pDcCapabilities->zstd.aeadThenDecompressSupported =
        (Cpa8U)pExtendedFtrs->is_chain_aead_then_decompress;

    /* Overwrite default capabilities with capabilities returned
     * from firmware if available. */
    if (fw_caps->is_fw_caps)
    {
        SalCtrl_Set6xxxDcExtendedCapabilities(pDcCapabilities, fw_caps);
    }
}

/* Sets device specific information needed by compression service */
CpaStatus SalCtrl_SetDCCaps(dc_capabilities_t *pDcCapabilities,
                            int device_type,
                            Cpa32U dcExtendedFeatures,
                            fw_caps_t *fw_caps)
{
    CpaStatus ret = CPA_STATUS_SUCCESS;

    switch (device_type)
    {
            /* 401XX and 402XX hardware share the same device type. All 3
             * devices 401XX, 402XX and 420XX share the same device capabilities
             * as 4XXX. */
        case DEVICE_4XXX:
        case DEVICE_4XXXVF:
        case DEVICE_420XX:
        case DEVICE_420XXVF:
            SalCtrl_Set4xxxDcCapabilities(
                pDcCapabilities, dcExtendedFeatures, fw_caps, device_type);
            break;
        case DEVICE_6XXX:
        case DEVICE_6XXXVF:
            SalCtrl_Set6xxxDcCapabilities(
                pDcCapabilities, dcExtendedFeatures, fw_caps);
            break;
        default:
            LAC_LOG_ERROR1("Unknown device type! - %u\n", device_type);
            ret = CPA_STATUS_FAIL;
            break;
    }

    return ret;
}
