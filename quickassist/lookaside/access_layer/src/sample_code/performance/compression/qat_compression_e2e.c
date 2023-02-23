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

#include "qat_compression_main.h"
#include "cpa_sample_code_dc_perf.h"
#include "qat_perf_utils.h"

#ifdef KERNEL_SPACE
#include <linux/zlib.h>
#include <linux/crc32.h>
#define CRC32_XOR_VALUE (0xffffffff)
#else
#include <zlib.h>
#endif

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
#ifdef KERNEL_SPACE
    resultChecksum =
        crc32(inputChecksum ^ CRC32_XOR_VALUE, pData, length) ^ CRC32_XOR_VALUE;
#else
    resultChecksum = crc32(inputChecksum, pData, length);
#endif
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
    CpaDcInstanceCapabilities capabilities = {0};
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
