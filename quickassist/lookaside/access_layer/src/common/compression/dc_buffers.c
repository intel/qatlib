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
 * @file dc_buffers.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the buffer management operations for
 *      Data Compression service.
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "cpa.h"
#include "cpa_dc.h"

#include "sal_types_compression.h"
#include "icp_qat_fw_comp.h"

#define CPA_DC_CEIL_DIV(x, y) (((x) + (y)-1) / (y))
#define DC_DEST_BUFF_EXTRA_DEFLATE_GEN2 (55)
#define DC_DEST_BUFF_EXTRA_DEFLATE_GEN4_STATIC (1029)
#define DC_DEST_BUFF_EXTRA_DEFLATE_GEN4_DYN (512)
#define DC_DEST_BUFF_EXTRA_LZ4_GEN4 (1024)
#define DC_DEST_BUFF_EXTRA_LZ4S_GEN4 (1024)
#define DC_DEST_BUFF_MIN_EXTRA_BYTES(x) ((x < 8) ? (8 - x) : 0)
#define DC_BUF_MAX_SIZE (0xFFFFFFFF)
/* To determine an overflow on a 32 unsigned value */
#define UINT_OVERFLOW (0xFFFFFFFF00000000UL)
#define DC_NUM_EXTRA_BUFFERS (1)
#define DC_NUM_DICT_BUFFERS (1)

CpaStatus cpaDcBufferListGetMetaSize(const CpaInstanceHandle instanceHandle,
                                     Cpa32U numBuffers,
                                     Cpa32U *pSizeInBytes)
{
    CpaInstanceHandle insHandle = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = instanceHandle;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(insHandle);
    LAC_CHECK_NULL_PARAM(pSizeInBytes);

    /* Ensure this is a compression or a decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));

    if (0 == numBuffers)
    {
        LAC_INVALID_PARAM_LOG("Number of Buffers");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    *pSizeInBytes = (sizeof(icp_buffer_list_desc_t) +
                     (sizeof(icp_flat_buffer_desc_t) *
                      (numBuffers + DC_NUM_EXTRA_BUFFERS)) +
                     ICP_DESCRIPTOR_ALIGNMENT_BYTES);

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, %d, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             numBuffers,
             (LAC_ARCH_UINT)pSizeInBytes,
             *pSizeInBytes);
#endif

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup cpaDc
 *      Function to return the size of the memory which must be allocated for
 *      the pPrivateMetaData member of the CpaBufferList used with dictionary
 *      compression.
 *
 * @description
 *      This function is used to obtain the size (in bytes) required to
 *      allocate a buffer descriptor for the pPrivateMetaData member in the
 *      CpaBufferList structure of the source buffer list used in the API's
 *      cpaDcCompressDataWithDict() and cpaDcDecompressDataWithDict().
 *      In contrast the size in bytes to allocate the descriptor of the
 *      destination buffer list must not use this API, and needs to be
 *      determined using the API cpaDcBufferListGetMetaSize().
 *
 * @param[in]  instanceHandle      Handle to an instance of this API.
 * @param[in]  numDictBuffers      The number of CpaFlatBuffers contained in
 *                                 the dictionary buffer CpaBufferList.
 *                                 This number must not be exceeded during use.
 * @param[in]  numSourceBuffers    The number of CpaFlatBuffers contained in
 *                                 the source buffer CpaBufferList.
 *                                 This number must not be exceeded during use.
 * @param[out] pSizeInBytes        Pointer to the size in bytes of memory to be
 *                                 allocated as metadata to be assigned within
 *                                 the source buffer CpaBufferList.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 *****************************************************************************/
CpaStatus cpaDcGetMetaSizeForSrcBuffWithDict(
    const CpaInstanceHandle instanceHandle,
    Cpa32U numDictBuffers,
    Cpa32U numSourceBuffers,
    Cpa32U *pSizeInBytes)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus dcDeflateBoundGen2(void *pService,
                             CpaDcHuffType huffType,
                             Cpa32U inputSize,
                             Cpa32U *outputSize)
{
    Cpa64U inBufferSize = inputSize;
    Cpa64U outBufferSize = 0;

    /* Formula for GEN2 deflate:
     * ceil(9 * Total input bytes / 8) + 55 bytes.
     * 55 bytes is the skid pad value for GEN2 devices.
     * Adding extra bytes = `DC_DEST_BUFF_MIN_EXTRA_BYTES(inputSize)`
     * when calculated value from `CPA_DC_CEIL_DIV(9 * inputSize, 8) +
     * DC_DEST_BUFF_EXTRA_DEFLATE_GEN2` is less than 64 bytes to
     * achieve a safer output buffer size of 64 bytes.
     */
    outBufferSize = CPA_DC_CEIL_DIV(9 * inBufferSize, 8) +
                    DC_DEST_BUFF_EXTRA_DEFLATE_GEN2 +
                    DC_DEST_BUFF_MIN_EXTRA_BYTES(inputSize);

    if (outBufferSize > DC_BUF_MAX_SIZE)
        *outputSize = DC_BUF_MAX_SIZE;
    else
        *outputSize = (Cpa32U)outBufferSize;

    return CPA_STATUS_SUCCESS;
}

CpaStatus dcDeflateBoundGen4(void *pServiceType,
                             CpaDcHuffType huffType,
                             Cpa32U inputSize,
                             Cpa32U *outputSize)
{
    Cpa64U outputSizeLong;
    Cpa64U inputSizeLong = (Cpa64U)inputSize;
    sal_compression_service_t *pService = NULL;

    pService = (sal_compression_service_t *)pServiceType;

    switch (huffType)
    {
        case CPA_DC_HT_STATIC:
            /* Formula for GEN4 static deflate:
             * ceil((9*sourceLen)/8) + 5 + 1024. */
            outputSizeLong = CPA_DC_CEIL_DIV(9 * inputSizeLong, 8) +
                             DC_DEST_BUFF_EXTRA_DEFLATE_GEN4_STATIC;
            break;
        case CPA_DC_HT_FULL_DYNAMIC:
            outputSizeLong = DC_DEST_BUFF_EXTRA_DEFLATE_GEN4_DYN;
            outputSizeLong += CPA_DC_CEIL_DIV(9 * inputSizeLong, 8);
            if (pService->generic_service_info.isGen4_2)
            {
                /* Formula for GEN4_2 dynamic deflate:
                 * Ceil ((9*sourceLen)/8) +
                 * ((((8/7) * sourceLen)/ 4KB) * (150+5)) + 512
                 */
                outputSizeLong += ((8 * inputSizeLong * 155) / 7) / (4 * 1024);
            }
            else
            {
                /* Formula for GEN4 dynamic deflate:
                 * Ceil ((9*sourceLen)/8) +
                 * ((((8/7) * sourceLen)/ 16KB) * (150+5)) + 512
                 */
                outputSizeLong += ((8 * inputSizeLong * 155) / 7) / (16 * 1024);
            }
            break;
        default:
            return CPA_STATUS_INVALID_PARAM;
    }

    /* Avoid output size overflow */
    if (outputSizeLong & UINT_OVERFLOW)
        return CPA_STATUS_INVALID_PARAM;

    *outputSize = (Cpa32U)outputSizeLong;
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcDeflateCompressBound(const CpaInstanceHandle dcInstance,
                                    CpaDcHuffType huffType,
                                    Cpa32U inputSize,
                                    Cpa32U *outputSize)
{
    sal_compression_service_t *pService;
    CpaInstanceHandle insHandle = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
#ifdef ICP_PARAM_CHECK
    CpaBoolean dynHuffmanSupported = CPA_FALSE;
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
    LAC_CHECK_NULL_PARAM(outputSize);
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pService = (sal_compression_service_t *)insHandle;
    /* Retrieve capabilities */
    pDcCapabilities = &pService->dc_capabilities;

#ifdef ICP_PARAM_CHECK
    dynHuffmanSupported =
        DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(pDcCapabilities->deflate.typeSupport,
                                         DC_CAPS_DEFLATE_TYPE_DYNAMIC,
                                         DC_CAPS_DEFLATE_TYPE_SUPPORTED);
    if (!inputSize)
    {
        LAC_INVALID_PARAM_LOG("The input size needs to be greater than zero");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((CPA_DC_HT_STATIC != huffType) && (CPA_DC_HT_FULL_DYNAMIC != huffType))
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value");
        return CPA_STATUS_INVALID_PARAM;
    }
    if ((CPA_FALSE == dynHuffmanSupported) &&
        (CPA_DC_HT_FULL_DYNAMIC == huffType))
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    return (pDcCapabilities->dcDeflateBound)(
        (void *)pService, huffType, inputSize, outputSize);
}

CpaStatus dcLZ4BoundGen4(Cpa32U inputSize, Cpa32U *outputSize)
{
    Cpa64U outputSizeLong;
    Cpa64U inputSizeLong = (Cpa64U)inputSize;

    /* Formula for GEN4 LZ4:
     * sourceLen + Ceil(sourceLen/1520) * 13 + 1024 */
    outputSizeLong = inputSizeLong + DC_DEST_BUFF_EXTRA_LZ4_GEN4;
    outputSizeLong += CPA_DC_CEIL_DIV(inputSizeLong, 1520) * 13;

    /* Avoid output size overflow */
    if (outputSizeLong & UINT_OVERFLOW)
        return CPA_STATUS_INVALID_PARAM;

    *outputSize = (Cpa32U)outputSizeLong;
    return CPA_STATUS_SUCCESS;
}

CpaStatus dcLZ4SBoundGen4(Cpa32U inputSize, Cpa32U *outputSize)
{
    Cpa64U outputSizeLong;
    Cpa64U inputSizeLong = (Cpa64U)inputSize;

    /* Formula for GEN4 LZ4S:
     * sourceLen + Ceil(sourceLen/2000) * 11 + 1024 */
    outputSizeLong = inputSizeLong + DC_DEST_BUFF_EXTRA_LZ4S_GEN4;
    outputSizeLong += CPA_DC_CEIL_DIV(inputSizeLong, 2000) * 11;

    /* Avoid output size overflow */
    if (outputSizeLong & UINT_OVERFLOW)
        return CPA_STATUS_INVALID_PARAM;

    *outputSize = (Cpa32U)outputSizeLong;
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcLZ4CompressBound(const CpaInstanceHandle dcInstance,
                                Cpa32U inputSize,
                                Cpa32U *outputSize)
{
    sal_compression_service_t *pService = NULL;
    CpaInstanceHandle insHandle = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean lz4Supported = CPA_FALSE;

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
    LAC_CHECK_NULL_PARAM(outputSize);
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    if (!inputSize)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pService = (sal_compression_service_t *)insHandle;

    /* Retrieve capabilities */
    pDcCapabilities = &pService->dc_capabilities;
    lz4Supported = pDcCapabilities->lz4.supported;

    if (CPA_FALSE == lz4Supported)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    if (pDcCapabilities->dcLZ4Bound)
    {
        return (pDcCapabilities->dcLZ4Bound)(inputSize, outputSize);
    }
    else
    {
        return CPA_STATUS_UNSUPPORTED;
    }
}

CpaStatus cpaDcLZ4SCompressBound(const CpaInstanceHandle dcInstance,
                                 Cpa32U inputSize,
                                 Cpa32U *outputSize)
{
    sal_compression_service_t *pService = NULL;
    CpaInstanceHandle insHandle = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean lz4sSupported = CPA_FALSE;

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
    LAC_CHECK_NULL_PARAM(outputSize);
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    if (!inputSize)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pService = (sal_compression_service_t *)insHandle;
    /* Retrieve capabilities */
    pDcCapabilities = &pService->dc_capabilities;
    lz4sSupported = pDcCapabilities->lz4s.supported;

    if (CPA_FALSE == lz4sSupported)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    if (pDcCapabilities->dcLZ4SBound)
    {
        return (pDcCapabilities->dcLZ4SBound)(inputSize, outputSize);
    }
    else
    {
        return CPA_STATUS_UNSUPPORTED;
    }
}

CpaStatus cpaDcZstdCompressBound(const CpaInstanceHandle dcInstance,
                                 Cpa32U inputSize,
                                 Cpa32U *outputSize)
{
    sal_compression_service_t *pService = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean zstdSupported = CPA_FALSE;
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
    LAC_CHECK_INSTANCE_HANDLE(insHandle);
    LAC_CHECK_NULL_PARAM(outputSize);
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    if (!inputSize)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    pService = (sal_compression_service_t *)insHandle;
    /* Retrieve capabilities */
    pDcCapabilities = &pService->dc_capabilities;
    zstdSupported = pDcCapabilities->zstd.supported;

    if (CPA_FALSE == zstdSupported)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    if (pDcCapabilities->dcZstdBound)
    {
        return (pDcCapabilities->dcZstdBound)(inputSize, outputSize);
    }
    else
    {
        return CPA_STATUS_UNSUPPORTED;
    }
}
