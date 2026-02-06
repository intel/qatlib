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
 * @file dc_capabilities.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Gets capabilities on the current instance
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "sal_types_compression.h"

/* DEBUG  */
#ifdef ICP_DEBUG
#undef STATIC
/* When DEBUG is set, STATIC and INLINE evaluates to nothing. */
#define STATIC
#define INLINE
#else
/* otherwise they evaluate to the static and inline keywords,
 * respectively. */
#define STATIC static
#define INLINE inline
#endif

CpaStatus dcGetAsbEnablePrefCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                             Cpa32U algo,
                                             CpaBoolean *pCapStatus)
{
    *pCapStatus = CPA_FALSE;
    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.asbEnablePref)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.asbEnablePref)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4S:
            if (pDcCapabilities->lz4s.asbEnablePref)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.asbEnablePref)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcGetAlgoWindowSizeForCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                       Cpa32U capId,
                                       Cpa32U dir,
                                       Cpa32U algo,
                                       CpaBoolean *pCapStatus)
{
    Cpa16U validBitMask = 0;
    Cpa16U windowSizeMask = 0;
    *pCapStatus = CPA_FALSE;

    switch (dir)
    {
        case CPA_DC_DIR_COMPRESS:
        case CPA_DC_DIR_DECOMPRESS:
            break;
        case CPA_DC_DIR_COMBINED:
            LAC_LOG_ERROR("Combined direction is not supported\n");
            return CPA_STATUS_INVALID_PARAM;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm direction is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    switch (capId)
    {
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_4K:
            validBitMask = DC_4K_WINDOW_MASK;
            break;
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_8K:
            validBitMask = DC_8K_WINDOW_MASK;
            break;
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_16K:
            validBitMask = DC_16K_WINDOW_MASK;
            break;
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_32K:
            validBitMask = DC_32K_WINDOW_MASK;
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Window size is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (dir == CPA_DC_DIR_COMPRESS)
            {
                windowSizeMask =
                    pDcCapabilities->deflate.validWindowSizeMaskCompression;
            }
            else
            {
                windowSizeMask =
                    pDcCapabilities->deflate.validWindowSizeMaskDecompression;
            }
            break;
        case CPA_DC_LZ4:
            if (dir == CPA_DC_DIR_COMPRESS)
            {
                windowSizeMask =
                    pDcCapabilities->lz4.validWindowSizeMaskCompression;
            }
            else
            {
                windowSizeMask =
                    pDcCapabilities->lz4.validWindowSizeMaskDecompression;
            }
            break;
        case CPA_DC_LZ4S:
            if (dir == CPA_DC_DIR_COMPRESS)
            {
                windowSizeMask =
                    pDcCapabilities->lz4s.validWindowSizeMaskCompression;
            }
            break;
        case CPA_DC_ZSTD:
            if (dir == CPA_DC_DIR_COMPRESS)
            {
                windowSizeMask =
                    pDcCapabilities->zstd.validWindowSizeMaskCompression;
            }
            else
            {
                windowSizeMask =
                    pDcCapabilities->zstd.validWindowSizeMaskDecompression;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    if (windowSizeMask & validBitMask)
    {
        *pCapStatus = CPA_TRUE;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcGetAlgoWindowSizeCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                    Cpa32U dir,
                                    Cpa32U algo,
                                    Cpa32U *pU32Status)
{
    *pU32Status = 0;

    switch (dir)
    {
        case CPA_DC_DIR_COMPRESS:
        case CPA_DC_DIR_DECOMPRESS:
            break;
        case CPA_DC_DIR_COMBINED:
            LAC_LOG_ERROR("Combined direction is not supported\n");
            return CPA_STATUS_INVALID_PARAM;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm direction is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            *pU32Status = pDcCapabilities->deflate.historyBufferSize;
            break;
        case CPA_DC_LZ4:
            *pU32Status = pDcCapabilities->lz4.historyBufferSize;
            break;
        case CPA_DC_LZ4S:
            *pU32Status = pDcCapabilities->lz4s.historyBufferSize;
            break;
        case CPA_DC_ZSTD:
            *pU32Status = pDcCapabilities->zstd.historyBufferSize;
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcGetMaxBlockSizeForBitmaskCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                            Cpa8U lz4BlockSize,
                                            Cpa32U algo,
                                            CpaBoolean *pCapStatus)
{
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.maxBlockSize & lz4BlockSize)
            {
                *pCapStatus = CPA_TRUE;
            }
            else
            {
                *pCapStatus = CPA_FALSE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcGetCompDictSupportCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                     Cpa32U algo,
                                     Cpa32U dirMask,
                                     CpaBoolean *pCapStatus)
{
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if ((pDcCapabilities->deflate.supported) &&
                (pDcCapabilities->deflate.dictCompSupported) &&
                ((pDcCapabilities->deflate.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->deflate.dictCap & DC_CAPS_COMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if ((pDcCapabilities->lz4.supported) &&
                (pDcCapabilities->lz4.dictCompSupported) &&
                ((pDcCapabilities->lz4.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->lz4.dictCap & DC_CAPS_COMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4S:
            if ((pDcCapabilities->lz4s.supported) &&
                (pDcCapabilities->lz4s.dictCompSupported) &&
                ((pDcCapabilities->lz4s.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->lz4s.dictCap & DC_CAPS_COMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if ((pDcCapabilities->zstd.supported) &&
                (pDcCapabilities->zstd.dictCompSupported) &&
                ((pDcCapabilities->zstd.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->zstd.dictCap & DC_CAPS_COMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcChainGetPcrc64CapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                 Cpa32U algo,
                                 CpaBoolean *pCapStatus)
{
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus dcGetDirMaskFromApiDir(Cpa32U dir, Cpa32U *pDirMask)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDirMask);
#endif

    switch (dir)
    {
        case CPA_DC_DIR_COMPRESS:
            *pDirMask = DC_CAPS_COMPRESSION;
            break;
        case CPA_DC_DIR_DECOMPRESS:
            *pDirMask = DC_CAPS_DECOMPRESSION;
            break;
        case CPA_DC_DIR_COMBINED:
            *pDirMask = (DC_CAPS_COMPRESSION | DC_CAPS_DECOMPRESSION);
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm direction is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcGetDirCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                         Cpa32U capabilitiesMask,
                         Cpa32U algo,
                         Cpa32U dirMask,
                         CpaBoolean *pCapStatus)
{
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if ((pDcCapabilities->deflate.supported) &&
                ((pDcCapabilities->deflate.dirMask & dirMask) == dirMask))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if ((pDcCapabilities->lz4.supported) &&
                (capabilitiesMask & ICP_ACCEL_CAPABILITIES_LZ4_COMPRESSION) &&
                ((pDcCapabilities->lz4.dirMask & dirMask) == dirMask))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4S:
            if ((pDcCapabilities->lz4s.supported) &&
                (capabilitiesMask & ICP_ACCEL_CAPABILITIES_LZ4S_COMPRESSION) &&
                ((pDcCapabilities->lz4s.dirMask & dirMask) == dirMask))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if ((pDcCapabilities->zstd.supported) &&
                ((pDcCapabilities->zstd.dirMask & dirMask) == dirMask))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC INLINE CpaStatus
dcGetCrcOverBlockCapabilityStatus(dc_extd_ftrs_t *pExtendedFtrs,
                                  Cpa32U algo,
                                  CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif

    * pCapStatus = CPA_FALSE;
    switch (algo)
    {
        case CPA_DC_LZ4:
            if (pExtendedFtrs->is_e2e_comp_crc_over_block)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_LOG_ERROR("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcQueryCapabilityByType(CpaInstanceHandle dcInstance,
                                     CpaDcCapabilityReq capabilityReq,
                                     CpaDcCapabilityResp *pCapabilityResp)
{
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;
    Cpa32U capabilitiesMask = 0, dirMask = 0;
    dc_capabilities_t *pDcCapabilities = NULL;
    dc_extd_ftrs_t *pExtendedFtrs = NULL;
    CpaStatus result = CPA_STATUS_SUCCESS;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    /* Ensure this is a compression or a decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
    LAC_CHECK_NULL_PARAM(pCapabilityResp);
#endif

    pService = (sal_compression_service_t *)insHandle;
    capabilitiesMask = pService->generic_service_info.capabilitiesMask;
    pDcCapabilities = &pService->dc_capabilities;
    pExtendedFtrs =
        (dc_extd_ftrs_t *)&(((sal_service_t *)insHandle)->dcExtendedFeatures);
    osalMemSet(pCapabilityResp, 0, sizeof(CpaDcCapabilityResp));

    switch (capabilityReq.algo)
    {
        case CPA_DC_DEFLATE:
        case CPA_DC_LZ4:
        case CPA_DC_LZ4S:
        case CPA_DC_ZSTD:
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    switch (capabilityReq.dir)
    {
        case CPA_DC_DIR_COMPRESS:
            dirMask = DC_CAPS_COMPRESSION;
            break;
        case CPA_DC_DIR_DECOMPRESS:
            dirMask = DC_CAPS_DECOMPRESSION;
            break;
        case CPA_DC_DIR_COMBINED:
            LAC_LOG_ERROR("Invalid Algorithm Direction not supported\n");
            return CPA_STATUS_INVALID_PARAM;
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm direction is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }

    switch (capabilityReq.capId)
    {
        case CPA_DC_CAP_BOOL_STATEFUL:
        case CPA_DC_CAP_BOOL_STATELESS:
            if ((CPA_DC_CAP_BOOL_STATEFUL == capabilityReq.capId) &&
                !(pDcCapabilities->sessState & DC_CAPS_STATEFUL))
            {
                pCapabilityResp->boolStatus = CPA_FALSE;
                break;
            }
            if ((CPA_DC_CAP_BOOL_STATELESS == capabilityReq.capId) &&
                !(pDcCapabilities->sessState & DC_CAPS_STATELESS))
            {
                pCapabilityResp->boolStatus = CPA_FALSE;
                break;
            }
            result = dcGetDirCapabilityStatus(pDcCapabilities,
                                              capabilitiesMask,
                                              capabilityReq.algo,
                                              dirMask,
                                              &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_4K:
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_8K:
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_16K:
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_32K:
        case CPA_DC_CAP_BOOL_WINDOW_SIZE_64K:
            result = dcGetAlgoWindowSizeForCapabilityStatus(
                pDcCapabilities,
                capabilityReq.capId,
                capabilityReq.dir,
                capabilityReq.algo,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_U32_DEFAULT_WINDOW_SIZE:
            result = dcGetAlgoWindowSizeCapabilityStatus(
                pDcCapabilities,
                capabilityReq.dir,
                capabilityReq.algo,
                &pCapabilityResp->u32Status);
            break;
        case CPA_DC_CAP_BOOL_DYNAMIC_HUFFMAN:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus = DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(
                    pDcCapabilities->deflate.typeSupport,
                    DC_CAPS_DEFLATE_TYPE_DYNAMIC,
                    DC_CAPS_DEFLATE_TYPE_SUPPORTED);
            }
            break;
        case CPA_DC_CAP_BOOL_STATIC_HUFFMAN:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus = DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(
                    pDcCapabilities->deflate.typeSupport,
                    DC_CAPS_DEFLATE_TYPE_STATIC,
                    DC_CAPS_DEFLATE_TYPE_SUPPORTED);
            }
            break;
        case CPA_DC_CAP_BOOL_BLOCK_CHECKSUM:
            if (capabilityReq.algo == CPA_DC_LZ4 &&
                capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus =
                    pDcCapabilities->lz4.blockChecksum;
            }
            break;
        case CPA_DC_CAP_BOOL_ACCUMULATE_XXHASH:
            if (capabilityReq.algo == CPA_DC_LZ4 &&
                capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus =
                    pDcCapabilities->lz4.accumulateXXHash;
            }
            break;
        case CPA_DC_CAP_BOOL_BLOCK_SIZE_64K:
            result = dcGetMaxBlockSizeForBitmaskCapabilityStatus(
                pDcCapabilities,
                DC_CAPS_LZ4_64K,
                capabilityReq.algo,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_BLOCK_SIZE_256K:
            result = dcGetMaxBlockSizeForBitmaskCapabilityStatus(
                pDcCapabilities,
                DC_CAPS_LZ4_256K,
                capabilityReq.algo,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_BLOCK_SIZE_1M:
            result = dcGetMaxBlockSizeForBitmaskCapabilityStatus(
                pDcCapabilities,
                DC_CAPS_LZ4_1M,
                capabilityReq.algo,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_BLOCK_SIZE_4M:
            result = dcGetMaxBlockSizeForBitmaskCapabilityStatus(
                pDcCapabilities,
                DC_CAPS_LZ4_4M,
                capabilityReq.algo,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_U32_BLOCK_SIZE_BITMASK:
            if (capabilityReq.algo == CPA_DC_LZ4)
            {
                pCapabilityResp->u32Status = pDcCapabilities->lz4.maxBlockSize;
            }
            break;
        case CPA_DC_CAP_BOOL_CHECKSUM_CRC32:
            if (pDcCapabilities->checksum & DC_CAPS_CRC32)
            {
                pCapabilityResp->boolStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_CAP_BOOL_CHECKSUM_ADLER32:
            if (pDcCapabilities->checksum & DC_CAPS_ADLER32)
            {
                pCapabilityResp->boolStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_CAP_BOOL_CHECKSUM_XXHASH32:
            if (pDcCapabilities->checksum & DC_CAPS_XXHASH32)
            {
                pCapabilityResp->boolStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_CAP_BOOL_CHECKSUM_XXHASH64:
            if (pDcCapabilities->checksum & DC_CAPS_XXHASH64)
            {
                pCapabilityResp->boolStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_CAP_BOOL_ASB:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS &&
                capabilityReq.algo != CPA_DC_LZ4S)
            {
                pCapabilityResp->boolStatus = pDcCapabilities->asb.supported;
            }
            break;
        case CPA_DC_CAP_BOOL_ASB_THRESHOLD:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS &&
                capabilityReq.algo != CPA_DC_LZ4S)
            {
                pCapabilityResp->boolStatus =
                    pDcCapabilities->asb.asbTshSupported;
            }
            break;
        case CPA_DC_CAP_BOOL_ASB_RATIO:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS &&
                capabilityReq.algo != CPA_DC_LZ4S)
            {
                pCapabilityResp->boolStatus =
                    pDcCapabilities->asb.asbRatioSupported;
            }
            break;
        case CPA_DC_CAP_BOOL_DETERMINISM:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus = pDcCapabilities->determinism;
            }
            break;
        case CPA_DC_CAP_BOOL_OVERFLOW_RESUBMIT:
            pCapabilityResp->boolStatus =
                !pDcCapabilities->overflowResubmitUnsupported;
            break;
        case CPA_DC_CAP_BOOL_COMPRESS_N_VERIFY:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus = (CpaBoolean)pExtendedFtrs->is_cnv;
            }
            break;
        case CPA_DC_CAP_BOOL_COMPRESS_N_VERIFY_N_RECOVER:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                pCapabilityResp->boolStatus =
                    (CpaBoolean)pExtendedFtrs->is_cnvnr;
            }
            break;
        case CPA_DC_CAP_BOOL_INTEGRITY_CRC32:
            if (capabilitiesMask & ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY)
            {
                pCapabilityResp->boolStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_CAP_BOOL_INTEGRITY_CRC64:
            if (capabilitiesMask & ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY64)
            {
                pCapabilityResp->boolStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_CAP_BOOL_CHAIN_HASH_THEN_COMPRESS:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS &&
                capabilityReq.algo != CPA_DC_LZ4S)
            {
                result = dcGetHashChainingCapabilityStatus(
                    pDcCapabilities,
                    capabilityReq.algo,
                    &pCapabilityResp->boolStatus);
            }
            break;
        case CPA_DC_CAP_BOOL_CHAIN_COMPRESS_THEN_AEAD:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS &&
                capabilityReq.algo != CPA_DC_LZ4S)
            {
                result = dcGetCompAeadChainingCapabilityStatus(
                    pDcCapabilities,
                    capabilityReq.algo,
                    &pCapabilityResp->boolStatus);
            }
            break;
        case CPA_DC_CAP_BOOL_CHAIN_AEAD_THEN_DECOMPRESS:
            if (capabilityReq.dir == CPA_DC_DIR_DECOMPRESS &&
                capabilityReq.algo != CPA_DC_LZ4S)
            {
                result = dcGetAeadDecompChainingCapabilityStatus(
                    pDcCapabilities,
                    capabilityReq.algo,
                    &pCapabilityResp->boolStatus);
            }
            break;
        case CPA_DC_CAP_BOOL_STATEFUL_LITE:
            if (capabilityReq.algo == CPA_DC_DEFLATE)
            {
                pCapabilityResp->boolStatus =
                    !pDcCapabilities->statefulLiteUnsupported;
            }
            break;
        case CPA_DC_CAP_BOOL_UNCOMPRESSED_DICT:
            result = dcGetUncompDictSupportCapabilityStatus(
                pDcCapabilities,
                capabilityReq.algo,
                dirMask,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_COMPRESSED_DICT:
            result = dcGetCompDictSupportCapabilityStatus(
                pDcCapabilities,
                capabilityReq.algo,
                dirMask,
                &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_ZERO_LENGTH_REQ:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                result = dcGetZeroLengthReqCapabilityStatus(
                    pDcCapabilities,
                    capabilityReq.algo,
                    &pCapabilityResp->boolStatus);
            }
            break;
        case CPA_DC_CAP_BOOL_PROGRAMMABLE_CRC64:
            result = dcGetPcrc64CapabilityStatus(pDcCapabilities,
                                                 capabilityReq.algo,
                                                 &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_ASB_ENABLE_PREFERRED:
            if (capabilityReq.dir == CPA_DC_DIR_COMPRESS)
            {
                result = dcGetAsbEnablePrefCapabilityStatus(
                    pDcCapabilities,
                    capabilityReq.algo,
                    &pCapabilityResp->boolStatus);
            }
            break;
        case CPA_DC_CAP_BOOL_CHAIN_PROGRAMMABLE_CRC64:
            result =
                dcChainGetPcrc64CapabilityStatus(pDcCapabilities,
                                                 capabilityReq.algo,
                                                 &pCapabilityResp->boolStatus);
            break;
        case CPA_DC_CAP_BOOL_E2E_CRC_OVER_COMP_BLOCK:
            result =
                dcGetCrcOverBlockCapabilityStatus(pExtendedFtrs,
                                                  capabilityReq.algo,
                                                  &pCapabilityResp->boolStatus);
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Capability is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return result;
}

inline CpaStatus dcGetUncompDictSupportCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    Cpa32U dirMask,
    CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcCapabilities);
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif

    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if ((pDcCapabilities->deflate.supported) &&
                (pDcCapabilities->deflate.dictCompSupported) &&
                ((pDcCapabilities->deflate.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->deflate.dictCap & DC_CAPS_UNCOMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if ((pDcCapabilities->lz4.supported) &&
                (pDcCapabilities->lz4.dictCompSupported) &&
                ((pDcCapabilities->lz4.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->lz4.dictCap & DC_CAPS_UNCOMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4S:
            if ((pDcCapabilities->lz4s.supported) &&
                (pDcCapabilities->lz4s.dictCompSupported) &&
                ((pDcCapabilities->lz4s.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->lz4s.dictCap & DC_CAPS_UNCOMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if ((pDcCapabilities->zstd.supported) &&
                (pDcCapabilities->zstd.dictCompSupported) &&
                ((pDcCapabilities->zstd.dirMask & dirMask) == dirMask) &&
                (pDcCapabilities->zstd.dictCap & DC_CAPS_UNCOMPRESSED_DICT))
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

inline CpaStatus dcGetZeroLengthReqCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcCapabilities);
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif

    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.zerolengthRequests)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.zerolengthRequests)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4S:
            if (pDcCapabilities->lz4s.zerolengthRequests)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.zerolengthRequests)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

inline CpaStatus dcGetPcrc64CapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                             Cpa32U algo,
                                             CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcCapabilities);
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif

    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4S:
            if (pDcCapabilities->lz4s.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.programmableCrc64)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

inline CpaStatus dcGetHashChainingCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcCapabilities);
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.hashThenCompressSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.hashThenCompressSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.hashThenCompressSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

inline CpaStatus dcGetCompAeadChainingCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcCapabilities);
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.compressThenAeadSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.compressThenAeadSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.compressThenAeadSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

inline CpaStatus dcGetAeadDecompChainingCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus)
{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcCapabilities);
    LAC_CHECK_NULL_PARAM(pCapStatus);
#endif
    *pCapStatus = CPA_FALSE;

    switch (algo)
    {
        case CPA_DC_DEFLATE:
            if (pDcCapabilities->deflate.aeadThenDecompressSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_LZ4:
            if (pDcCapabilities->lz4.aeadThenDecompressSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        case CPA_DC_ZSTD:
            if (pDcCapabilities->zstd.aeadThenDecompressSupported)
            {
                *pCapStatus = CPA_TRUE;
            }
            break;
        default:
            LAC_UNSUPPORTED_PARAM_LOG("Algorithm is not supported\n");
            return CPA_STATUS_UNSUPPORTED;
    }
    return CPA_STATUS_SUCCESS;
}

