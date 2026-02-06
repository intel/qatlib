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
 * @file dc_dictionary.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of dictionary to compress a data buffer
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "dc_datapath.h"
#include "sal_service_state.h"
#include "lac_buffer_desc.h"

CpaStatus cpaDcCompressDataWithDict(CpaInstanceHandle dcInstance,
                                    CpaDcSessionHandle pSessionHandle,
                                    CpaBufferList *pSrcBuff,
                                    CpaBufferList *pDestBuff,
                                    CpaDcDictionaryData *pDictionaryData,
                                    CpaDcOpData *pOpData,
                                    CpaDcRqResults *pResults,
                                    void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
    dc_cnv_mode_t cnvMode = DC_NO_CNV;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG8("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pDictionaryData,
             (LAC_ARCH_UINT)pOpData,
             (LAC_ARCH_UINT)pResults,
             (LAC_ARCH_UINT)callbackTag);
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
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    if (CPA_FALSE == pOpData->compressAndVerify)
    {
        LAC_UNSUPPORTED_PARAM_LOG(
            "Data compression without verification are not allowed");
        return CPA_STATUS_UNSUPPORTED;
    }

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

#ifdef ICP_PARAM_CHECK
    /* Ensure this is a compression instance */
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif

    pService = (sal_compression_service_t *)insHandle;
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

    /* This check is outside the parameter checking as it is needed to manage
     * zero length requests. For dictionary compression there is an
     * expectation that a buffer list that includes metadata is supplied. */
    if (LacBuffDesc_BufferListVerifyNull(
            pSrcBuff, &srcBuffSize, LAC_NO_ALIGNMENT_SHIFT) !=
        CPA_STATUS_SUCCESS)
    {
        LAC_INVALID_PARAM_LOG("Invalid source buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

#ifdef ICP_PARAM_CHECK
    if (CPA_STATUS_SUCCESS != dcParamCheck(insHandle,
                                           pSessionHandle,
                                           pService,
                                           pSrcBuff,
                                           pDestBuff,
                                           pResults,
                                           pSessionDesc,
                                           pOpData->flushFlag,
                                           srcBuffSize))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    LAC_CHECK_NULL_PARAM(pOpData);
    if (CPA_STATUS_SUCCESS !=
        dcCheckOpData(pService, pOpData, pSessionDesc->sessDirection))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    retStatus = dcCheckDictData(pDictionaryData, pService, pSessionDesc);
    if (CPA_STATUS_SUCCESS != retStatus)
    {
        return retStatus;
    }

    if (!(pService->dc_capabilities.cnv.supported) &&
        (CPA_TRUE == pOpData->compressAndVerify))
    {
        LAC_UNSUPPORTED_PARAM_LOG("CompressAndVerify feature is not supported");
        return CPA_STATUS_UNSUPPORTED;
    }

    if ((CPA_TRUE == pOpData->compressAndVerifyAndRecover) &&
        (CPA_FALSE == pService->dc_capabilities.cnv.recovery))
    {
        LAC_UNSUPPORTED_PARAM_LOG("CompressAndVerifyAndRecover feature is not"
                                  " supported for dictionary requests");
        return CPA_STATUS_UNSUPPORTED;
    }

#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions are"
                              "not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (CPA_TRUE == pOpData->compressAndVerify)
    {
        cnvMode = DC_CNV;
    }

    return dcCompDecompData(pService,
                            pSessionDesc,
                            insHandle,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            pResults,
                            pOpData->flushFlag,
                            pOpData,
                            callbackTag,
                            DC_COMPRESSION_REQUEST,
                            CPA_TRUE,
                            cnvMode,
                            pDictionaryData);
}

CpaStatus cpaDcDecompressDataWithDict(CpaInstanceHandle dcInstance,
                                      CpaDcSessionHandle pSessionHandle,
                                      CpaBufferList *pSrcBuff,
                                      CpaBufferList *pDestBuff,
                                      CpaDcDictionaryData *pDictionaryData,
                                      CpaDcOpData *pOpData,
                                      CpaDcRqResults *pResults,
                                      void *callbackTag)
{
    sal_compression_service_t *pService = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa64U srcBuffSize = 0;
    CpaStatus retStatus = CPA_STATUS_SUCCESS;

#ifdef ICP_TRACE
    LAC_LOG8("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, "
             "0x%lx, 0x%x, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pSrcBuff,
             (LAC_ARCH_UINT)pDestBuff,
             (LAC_ARCH_UINT)pDictionaryData,
             (LAC_ARCH_UINT)pResults,
             pOpData->flushFlag,
             (LAC_ARCH_UINT)callbackTag);
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
    /* Ensure this is a compression or decompression instance */
    SAL_CHECK_INSTANCE_TYPE(
        insHandle,
        (SAL_SERVICE_TYPE_COMPRESSION | SAL_SERVICE_TYPE_DECOMPRESSION));
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pOpData);
#endif

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pService = (sal_compression_service_t *)insHandle;
    pSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

    retStatus = dcCheckDictData(pDictionaryData, pService, pSessionDesc);
    if (CPA_STATUS_SUCCESS != retStatus)
    {
        return retStatus;
    }

    /* This check is outside the parameter checking as it is needed to manage
     * zero length requests */
    if (CPA_STATUS_SUCCESS !=
        LacBuffDesc_BufferListVerifyNull(
            pSrcBuff, &srcBuffSize, LAC_NO_ALIGNMENT_SHIFT))
    {
        LAC_INVALID_PARAM_LOG("Invalid source buffer list parameter");
        return CPA_STATUS_INVALID_PARAM;
    }

#ifdef ICP_PARAM_CHECK
    if (CPA_STATUS_SUCCESS != dcCheckSourceData(pService,
                                                pSessionHandle,
                                                pSrcBuff,
                                                pDestBuff,
                                                pResults,
                                                CPA_DC_FLUSH_NONE,
                                                srcBuffSize,
                                                NULL))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (CPA_STATUS_SUCCESS !=
        dcCheckDestinationData(
            pService, pSessionHandle, pDestBuff, DC_DECOMPRESSION_REQUEST))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_STATUS_SUCCESS !=
        dcCheckOpData(pService, pOpData, pSessionDesc->sessDirection))
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    if (CPA_DC_DIR_COMPRESS == pSessionDesc->sessDirection)
    {
        LAC_INVALID_PARAM_LOG("Invalid sessDirection value");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

#ifdef ICP_DC_DYN_NOT_SUPPORTED
    if (CPA_DC_HT_FULL_DYNAMIC == pSessionDesc->huffType)
    {
        LAC_INVALID_PARAM_LOG("Invalid huffType value, dynamic sessions "
                              "are not supported");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    return dcCompDecompData(pService,
                            pSessionDesc,
                            insHandle,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            pResults,
                            pOpData->flushFlag,
                            pOpData,
                            callbackTag,
                            DC_DECOMPRESSION_REQUEST,
                            CPA_TRUE,
                            DC_NO_CNV,
                            pDictionaryData);
}
