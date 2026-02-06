/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#include "qat_compression_main.h"
#include "cpa_sample_code_dc_perf.h"
#include "qat_perf_utils.h"
#include "qat_compression_e2e.h"

#include <zlib.h>

CpaStatus qatCompressionE2EInit(compression_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    if (CPA_TRUE == setup->useE2E)
    {
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
        if ((CPA_STATUS_SUCCESS == status) && (NULL == setup->e2e))
        {
            setup->e2e = qaeMemAlloc(sizeof(qat_dc_e2e_t));
            QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup->e2e, status);
            if (CPA_STATUS_SUCCESS == status)
            {
                memset(setup->e2e, 0, sizeof(qat_dc_e2e_t));
                setup->e2e->compCrcData.adler32 = 1;
                setup->e2e->compCrcData.crc32 = 0;
                setup->requestOps.integrityCrcCheck = setup->useE2E;
                setup->requestOps.inputSkipData.skipMode = CPA_DC_SKIP_DISABLED;
                setup->requestOps.outputSkipData.skipMode =
                    CPA_DC_SKIP_DISABLED;
                setup->requestOps.verifyHwIntegrityCrcs = setup->useE2EVerify;
                setup->requestOps.pCrcData = &setup->e2e->compCrcData;
            }
        }
    }
    return status;
}

static Cpa32U crc32_checksum(Cpa32U inputChecksum, Cpa8U *pData, Cpa32U length)
{
    Cpa32U resultChecksum = 0;
    resultChecksum = crc32(inputChecksum, pData, length);
    return resultChecksum;
}

static CpaStatus computeSglChecksum(CpaBufferList *inputBuff,
                                    const Cpa32U computationSize,
                                    const CpaDcChecksum checksumType,
                                    Cpa32U *swChecksum)
{
    Cpa32U numBuffs = 0;
    Cpa32U lenLeft = 0;
    Cpa32U totalLen = 0;
    Cpa32U status = CPA_STATUS_SUCCESS;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(inputBuff, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(swChecksum, status);
    if (CPA_STATUS_SUCCESS == status)
    {
        for (numBuffs = 0; numBuffs < inputBuff->numBuffers; numBuffs++)
        {
            totalLen += inputBuff->pBuffers[numBuffs].dataLenInBytes;
            if (totalLen > computationSize)
            {
                totalLen -= inputBuff->pBuffers[numBuffs].dataLenInBytes;
                lenLeft = computationSize - totalLen;
                if (CPA_DC_CRC32 == checksumType)
                {
                    *swChecksum =
                        crc32_checksum(*swChecksum,
                                       inputBuff->pBuffers[numBuffs].pData,
                                       lenLeft);
                }
                break;
            }
            else
            {
                lenLeft = inputBuff->pBuffers[numBuffs].dataLenInBytes;
            }

            if (CPA_DC_CRC32 == checksumType)
            {
                *swChecksum = crc32_checksum(
                    *swChecksum, inputBuff->pBuffers[numBuffs].pData, lenLeft);
            }
        }
    }
    return status;
}

#ifdef SC_CHAINING_ENABLED
CpaStatus qatDcChainE2EVerify(compression_test_params_t *setup,
                              CpaBufferList *srcBufferList,
                              CpaBufferList *dstBufferList,
                              CpaDcChainRqResults *results)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(srcBufferList, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(dstBufferList, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(results, status);
    if ((CPA_STATUS_SUCCESS == status) && (CPA_TRUE == setup->useE2E))
    {
        /* Verify integrity CRCs (iCrc + oCrc) */
        /* Calculate CRC on the input buffer list.*/
        status = computeSglChecksum(srcBufferList,
                                    results->consumed,
                                    CPA_DC_CRC32,
                                    &(setup->e2e->swInputChecksum));
        if (CPA_STATUS_SUCCESS == status)
        {
            if (setup->requestOps.pCrcData->integrityCrc.iCrc !=
                setup->e2e->swInputChecksum)
            {
                PRINT("Checksum error! SW input checksum: 0x%08x"
                      " - HW checksum: 0x%08x\n",
                      setup->e2e->swInputChecksum,
                      setup->requestOps.pCrcData->integrityCrc.iCrc);
                PRINT("COMPRESSION consumed: %d, produced: %d,"
                      "checksum: 0x%08x, status: %d\n",
                      results->consumed,
                      results->produced,
                      results->crc32,
                      results->dcStatus);
                status = CPA_STATUS_FAIL;
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                /* Calculate CRC on the output buffer list.*/
                status = computeSglChecksum(dstBufferList,
                                            results->produced,
                                            CPA_DC_CRC32,
                                            &(setup->e2e->swOutputChecksum));
                if ((CPA_STATUS_SUCCESS == status) &&
                    (setup->requestOps.pCrcData->integrityCrc.oCrc !=
                     setup->e2e->swOutputChecksum))
                {
                    PRINT("Checksum error! SW output checksum: 0x%08x"
                          " - HW checksum: 0x%08x\n",
                          setup->e2e->swOutputChecksum,
                          setup->requestOps.pCrcData->integrityCrc.oCrc);
                    PRINT("COMPRESSION consumed: %d, produced: %d,"
                          "checksum: 0x%08x, status: %d\n",
                          results->consumed,
                          results->produced,
                          results->crc32,
                          results->dcStatus);
                    status = CPA_STATUS_FAIL;
                }
            }
        }
    }
    return status;
}
#endif

CpaStatus qatCompressionE2EVerify(compression_test_params_t *setup,
                                  CpaBufferList *srcBufferList,
                                  CpaBufferList *dstBufferList,
                                  CpaDcRqResults *results)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcInstanceCapabilities capabilities = { 0 };
    CpaBufferList *tempSrcBufferList = NULL;
    CpaBufferList *tempDstBufferList = NULL;
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(setup, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(srcBufferList, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(dstBufferList, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(results, status);
    if ((CPA_STATUS_SUCCESS == status) && (CPA_TRUE == setup->useE2E))
    {
        if (setup->dcSessDir == CPA_DC_DIR_COMPRESS)
        {
            tempSrcBufferList = srcBufferList;
            tempDstBufferList = dstBufferList;
        }
        else
        {
            tempSrcBufferList = dstBufferList;
            tempDstBufferList = srcBufferList;
        }

        status = cpaDcQueryCapabilities(setup->dcInstanceHandle, &capabilities);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT("%s::%d cpaDcQueryCapabilities failed", __func__, __LINE__);
            status = CPA_STATUS_FAIL;
        }
        if ((CPA_TRUE == capabilities.integrityCrcs) &&
            (CPA_STATUS_SUCCESS == status))
        {
#if DC_API_VERSION_AT_LEAST(3, 2)
            /* For Stateless case do not seed previous E2E checksum*/
            if (setup->setupData.sessState == CPA_DC_STATELESS)
            {
                setup->e2e->swInputChecksum = 0;
                setup->e2e->swOutputChecksum = 0;
            }
#endif
            /* Verify integrity CRCs (iCrc + oCrc) */
            /* Calculate CRC on the input buffer list.*/
            status = computeSglChecksum(tempSrcBufferList,
                                        results->consumed,
                                        CPA_DC_CRC32,
                                        &(setup->e2e->swInputChecksum));
            if (CPA_STATUS_SUCCESS == status)
            {
                if (setup->requestOps.pCrcData->integrityCrc.iCrc !=
                    setup->e2e->swInputChecksum)
                {
                    PRINT("Checksum error! SW input checksum: 0x%08x"
                          " - HW checksum: 0x%08x\n",
                          setup->e2e->swInputChecksum,
                          setup->requestOps.pCrcData->integrityCrc.iCrc);
                    PRINT("COMPRESSION consumed: %d, produced: %d,"
                          "checksum: 0x%08x, status: %d\n",
                          results->consumed,
                          results->produced,
                          results->checksum,
                          results->status);
                    status = CPA_STATUS_FAIL;
                }
                if (CPA_STATUS_SUCCESS == status)
                {
                    /* Calculate CRC on the output buffer list.*/
                    status =
                        computeSglChecksum(tempDstBufferList,
                                           results->produced,
                                           CPA_DC_CRC32,
                                           &(setup->e2e->swOutputChecksum));
                    if ((CPA_STATUS_SUCCESS == status) &&
                        (setup->requestOps.pCrcData->integrityCrc.oCrc !=
                         setup->e2e->swOutputChecksum))
                    {
                        PRINT("Checksum error! SW output checksum: 0x%08x"
                              " - HW checksum: 0x%08x\n",
                              setup->e2e->swOutputChecksum,
                              setup->requestOps.pCrcData->integrityCrc.oCrc);
                        PRINT("COMPRESSION consumed: %d, produced: %d,"
                              "checksum: 0x%08x, status: %d\n",
                              results->consumed,
                              results->produced,
                              results->checksum,
                              results->status);
                        status = CPA_STATUS_FAIL;
                    }
                }
            }
        }
    }
    return status;
}
