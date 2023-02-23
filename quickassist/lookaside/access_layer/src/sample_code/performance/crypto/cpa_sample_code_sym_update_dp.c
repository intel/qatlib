/***************************************************************************
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
 * @file cpa_sample_code_sym_update_sp.c
 *
 * @defgroup sampleSymmetricDpPerf  Symmetric Data Plane Performance code
 *
 * @ingroup sampleSymmetricDpPerf
 *
 * @description
 *      This file contains the main symmetric Data Plane session update
 *      performance sample code. It is capable of performing all ciphers,
 *      all hashes, authenticated hashes and algorithm chaining with session
 *      update operation.
 *
 *****************************************************************************/
#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_sym_dp.h"
#include "icp_sal_poll.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_cy_common.h"
#include "cpa_sample_code_sym_update_common.h"
#include "qat_perf_buffer_utils.h"

#define SYM_DP_OPS_DEFAULT_POLLING_INTERVAL (16)
Cpa32U symDpPollingInterval_g = SYM_DP_OPS_DEFAULT_POLLING_INTERVAL;

#if CY_API_VERSION_AT_LEAST(2, 2)

void symDpPerformUpdateCallback(CpaCySymDpOpData *pOpData,
                                CpaStatus status,
                                CpaBoolean verifyResult)
{
    /* pCallbacktag in the pOpData structure is used to store
     * index of to the perf_data_t associated the thread */
    perf_data_t *pPerfData = pOpData->pCallbackTag;
    pPerfData->responses++;
    /*if we have received the pre-set numOperations, then get the clock cycle
     * as a timestamp and post the Semaphore to release parent thread */
    if (pPerfData->numOperations == pPerfData->responses)
    {
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
    }
}


// Perform verify
static CpaStatus performOpAndVerifyDp(CpaInstanceHandle cyInstHandle,
                                      CpaCySymSessionCtx sessionCtx,
                                      symmetric_test_params_t *setup,
                                      CpaCySymSessionUpdateData *pSessionUpdate,
                                      Cpa32U node,
                                      perf_data_t *pSymData,
                                      Cpa8U **pSrcBuffer,
                                      Cpa8U **pDstBuffer,
                                      CpaCySymDpOpData **pOpData,
                                      Cpa8U *pCipherKey,
                                      Cpa8U *pUpdateCipherKey,
                                      Cpa8U *pAuthKey,
                                      Cpa8U *pUpdateAuthKey,
                                      Cpa8U *pAdditionalAuthData,
                                      Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U failCount = 0;
    Cpa32U innerLoop = 0;
    CpaBoolean sessionInUse = CPA_FALSE;
    CpaBoolean performNow = CPA_FALSE;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = symDpPollingInterval_g;

// Perform

    setup->performanceStats->numOperations += setup->numBuffers;

    for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
    {
        if (innerLoop == setup->numBuffers - 1)
        {
            performNow = CPA_TRUE;
        }
        else
        {
            performNow = CPA_FALSE;
        }

        do
        {
            status = cpaCySymDpEnqueueOp(pOpData[innerLoop], performNow);
            if (CPA_STATUS_RETRY == status)
            {
                pSymData->retries++;
                pSymData->pollCount++;
                icp_sal_CyPollDpInstance(setup->cyInstanceHandle, 0);
                nextPoll = numOps + symDpPollingInterval_g;
                AVOID_SOFTLOCKUP;
            }
        } while (status == CPA_STATUS_RETRY);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymDpPerformOp failed\n");
            failCount++;
        }

        ++numOps;
        if (numOps == nextPoll)
        {
            icp_sal_CyPollDpInstance(setup->cyInstanceHandle, 0);
            nextPoll = numOps + symDpPollingInterval_g;
        }
    }

// Wait for completion

    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            cyDpPollRemainingOperations(setup->performanceStats, cyInstHandle);
    }

    do
    {
        status = cpaCySymSessionInUse(sessionCtx, &sessionInUse);
        if (status == CPA_STATUS_FAIL)
        {
            PRINT_ERR("cpaCySymSessionInUse: failed\n");
            break;
        }
        AVOID_SOFTLOCKUP;
    } while (sessionInUse == CPA_TRUE);

    if (failCount > 0)
    {
        status = CPA_STATUS_FAIL;
    }


    return status;
}

// Perform for cipher session
static CpaStatus updatePerformCipherDp(
    symmetric_test_params_t *setup,
    CpaCySymSessionCtx sessionCtx,
    CpaCySymSessionUpdateData *pSessionUpdate,
    CpaInstanceHandle cyInstHandle,
    Cpa32U node,
    perf_data_t *pSymData,
    CpaCySymDpOpData **pOpData,
    Cpa8U **pSrcBuffer,
    Cpa8U **pDstBuffer,
    Cpa8U *pCipherKey,
    Cpa8U *pUpdateCipherKey,
    Cpa8U *pAuthKey,
    Cpa8U *pUpdateAuthKey,
    Cpa8U *pAdditionalAuthData,
    Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus updateStatus = CPA_STATUS_SUCCESS;

    status = performOpAndVerifyDp(cyInstHandle,
                                  sessionCtx,
                                  setup,
                                  pSessionUpdate,
                                  node,
                                  pSymData,
                                  pSrcBuffer,
                                  pDstBuffer,
                                  pOpData,
                                  pCipherKey,
                                  pUpdateCipherKey,
                                  pAuthKey,
                                  pUpdateAuthKey,
                                  pAdditionalAuthData,
                                  pIvBuffer);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("performOpAndVerify failed\n");
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, &pUpdateCipherKey, NULL, CPA_FALSE);

        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS == updateStatus)
        {
            status = performOpAndVerifyDp(cyInstHandle,
                                          sessionCtx,
                                          setup,
                                          pSessionUpdate,
                                          node,
                                          pSymData,
                                          pSrcBuffer,
                                          pDstBuffer,
                                          pOpData,
                                          pCipherKey,
                                          pUpdateCipherKey,
                                          pAuthKey,
                                          pUpdateAuthKey,
                                          pAdditionalAuthData,
                                          pIvBuffer);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("performOpAndVerify failed\n");
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(sessionCtx, pSessionUpdate, NULL, NULL, CPA_TRUE);

        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS == updateStatus)
        {
            status = performOpAndVerifyDp(cyInstHandle,
                                          sessionCtx,
                                          setup,
                                          pSessionUpdate,
                                          node,
                                          pSymData,
                                          pSrcBuffer,
                                          pDstBuffer,
                                          pOpData,
                                          pCipherKey,
                                          pUpdateCipherKey,
                                          pAuthKey,
                                          pUpdateAuthKey,
                                          pAdditionalAuthData,
                                          pIvBuffer);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("performOpAndVerify failed\n");
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, &pCipherKey, NULL, CPA_TRUE);

        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS != updateStatus)
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    return status;
}

// Perfom for hash session
static CpaStatus updatePerformHashDp(symmetric_test_params_t *setup,
                                     CpaCySymSessionCtx sessionCtx,
                                     CpaCySymSessionUpdateData *pSessionUpdate,
                                     CpaInstanceHandle cyInstHandle,
                                     Cpa32U node,
                                     perf_data_t *pSymData,
                                     CpaCySymDpOpData **pOpData,
                                     Cpa8U **pSrcBuffer,
                                     Cpa8U **pDstBuffer,
                                     Cpa8U *pCipherKey,
                                     Cpa8U *pUpdateCipherKey,
                                     Cpa8U *pAuthKey,
                                     Cpa8U *pUpdateAuthKey,
                                     Cpa8U *pAdditionalAuthData,
                                     Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus updateStatus = CPA_STATUS_SUCCESS;

    status = performOpAndVerifyDp(cyInstHandle,
                                  sessionCtx,
                                  setup,
                                  pSessionUpdate,
                                  node,
                                  pSymData,
                                  pSrcBuffer,
                                  pDstBuffer,
                                  pOpData,
                                  pCipherKey,
                                  pUpdateCipherKey,
                                  pAuthKey,
                                  pUpdateAuthKey,
                                  pAdditionalAuthData,
                                  pIvBuffer);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("performOpAndVerify failed\n");
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, NULL, &pUpdateAuthKey, CPA_FALSE);

        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS == updateStatus)
        {
            status = performOpAndVerifyDp(cyInstHandle,
                                          sessionCtx,
                                          setup,
                                          pSessionUpdate,
                                          node,
                                          pSymData,
                                          pSrcBuffer,
                                          pDstBuffer,
                                          pOpData,
                                          pCipherKey,
                                          pUpdateCipherKey,
                                          pAuthKey,
                                          pUpdateAuthKey,
                                          pAdditionalAuthData,
                                          pIvBuffer);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("performOpAndVerify failed\n");
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS != status)
    {
        setupUpdateData(sessionCtx, pSessionUpdate, NULL, &pAuthKey, CPA_FALSE);

        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS != updateStatus)
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    return status;
}

// Perform for alg chain session
static CpaStatus updatePerformAlgChainDp(
    symmetric_test_params_t *setup,
    CpaCySymSessionCtx sessionCtx,
    CpaCySymSessionUpdateData *pSessionUpdate,
    CpaInstanceHandle cyInstHandle,
    Cpa32U node,
    perf_data_t *pSymData,
    CpaCySymDpOpData **pOpData,
    Cpa8U **pSrcBuffer,
    Cpa8U **pDstBuffer,
    Cpa8U *pCipherKey,
    Cpa8U *pUpdateCipherKey,
    Cpa8U *pAuthKey,
    Cpa8U *pUpdateAuthKey,
    Cpa8U *pAdditionalAuthData,
    Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus updateStatus = CPA_STATUS_SUCCESS;

    status = performOpAndVerifyDp(cyInstHandle,
                                  sessionCtx,
                                  setup,
                                  pSessionUpdate,
                                  node,
                                  pSymData,
                                  pSrcBuffer,
                                  pDstBuffer,
                                  pOpData,
                                  pCipherKey,
                                  pUpdateCipherKey,
                                  pAuthKey,
                                  pUpdateAuthKey,
                                  pAdditionalAuthData,
                                  pIvBuffer);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("performOpAndVerify failed\n");
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, &pUpdateCipherKey, NULL, CPA_FALSE);

        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS == updateStatus)
        {
            status = performOpAndVerifyDp(cyInstHandle,
                                          sessionCtx,
                                          setup,
                                          pSessionUpdate,
                                          node,
                                          pSymData,
                                          pSrcBuffer,
                                          pDstBuffer,
                                          pOpData,
                                          pCipherKey,
                                          pUpdateCipherKey,
                                          pAuthKey,
                                          pUpdateAuthKey,
                                          pAdditionalAuthData,
                                          pIvBuffer);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("performOpAndVerify failed\n");
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, NULL, &pUpdateAuthKey, CPA_FALSE);

        /* Skip invalid case with auth key update on AES_CCM AES_GCM algchain
         * algorithm */
        if ((setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_CCM ||
             setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_GCM) &&
            (pSessionUpdate->flags & CPA_CY_SYM_SESUPD_AUTH_KEY))
        {
            updateStatus = CPA_STATUS_UNSUPPORTED;
        }
        else
        {
            // Update session
            updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        }
        if (CPA_STATUS_UNSUPPORTED == updateStatus ||
            CPA_STATUS_SUCCESS == updateStatus)
        {
            if (CPA_STATUS_UNSUPPORTED == updateStatus)
            {
                setupUpdateData(
                    sessionCtx, pSessionUpdate, NULL, &pAuthKey, CPA_FALSE);
            }
            else
            {
                status = performOpAndVerifyDp(cyInstHandle,
                                              sessionCtx,
                                              setup,
                                              pSessionUpdate,
                                              node,
                                              pSymData,
                                              pSrcBuffer,
                                              pDstBuffer,
                                              pOpData,
                                              pCipherKey,
                                              pUpdateCipherKey,
                                              pAuthKey,
                                              pUpdateAuthKey,
                                              pAdditionalAuthData,
                                              pIvBuffer);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("performOpAndVerify failed\n");
                }
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(sessionCtx, pSessionUpdate, NULL, NULL, CPA_TRUE);
        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS == updateStatus)
        {
            status = performOpAndVerifyDp(cyInstHandle,
                                          sessionCtx,
                                          setup,
                                          pSessionUpdate,
                                          node,
                                          pSymData,
                                          pSrcBuffer,
                                          pDstBuffer,
                                          pOpData,
                                          pCipherKey,
                                          pUpdateCipherKey,
                                          pAuthKey,
                                          pUpdateAuthKey,
                                          pAdditionalAuthData,
                                          pIvBuffer);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("performOpAndVerify failed\n");
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, &pCipherKey, &pAuthKey, CPA_FALSE);
        /* Skip invalid case with auth key update on AES_CCM AES_GCM algchain
         * algorithm */
        if ((setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_CCM ||
             setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_GCM) &&
            (pSessionUpdate->flags & CPA_CY_SYM_SESUPD_AUTH_KEY))
        {
            updateStatus = CPA_STATUS_UNSUPPORTED;
        }
        else
        {
            updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        }
        if (CPA_STATUS_UNSUPPORTED == updateStatus ||
            CPA_STATUS_SUCCESS == updateStatus)
        {
            if (CPA_STATUS_UNSUPPORTED == updateStatus)
            {
                setupUpdateData(sessionCtx,
                                pSessionUpdate,
                                &pUpdateCipherKey,
                                &pUpdateAuthKey,
                                CPA_FALSE);
            }
            else
            {
                status = performOpAndVerifyDp(cyInstHandle,
                                              sessionCtx,
                                              setup,
                                              pSessionUpdate,
                                              node,
                                              pSymData,
                                              pSrcBuffer,
                                              pDstBuffer,
                                              pOpData,
                                              pCipherKey,
                                              pUpdateCipherKey,
                                              pAuthKey,
                                              pUpdateAuthKey,
                                              pAdditionalAuthData,
                                              pIvBuffer);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("performOpAndVerify failed\n");
                }
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, NULL, &pUpdateAuthKey, CPA_TRUE);
        /* Skip invalid case with auth key update on AES_CCM AES_GCM algchain
         * algorithm */
        if ((setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_CCM ||
             setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_GCM) &&
            (pSessionUpdate->flags & CPA_CY_SYM_SESUPD_AUTH_KEY))
        {
            updateStatus = CPA_STATUS_UNSUPPORTED;
        }
        else
        {
            updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        }
        if (CPA_STATUS_UNSUPPORTED == updateStatus ||
            CPA_STATUS_SUCCESS == updateStatus)
        {
            if (CPA_STATUS_UNSUPPORTED == updateStatus)
            {
                setupUpdateData(
                    sessionCtx, pSessionUpdate, NULL, &pAuthKey, CPA_TRUE);
            }
            else
            {
                status = performOpAndVerifyDp(cyInstHandle,
                                              sessionCtx,
                                              setup,
                                              pSessionUpdate,
                                              node,
                                              pSymData,
                                              pSrcBuffer,
                                              pDstBuffer,
                                              pOpData,
                                              pCipherKey,
                                              pUpdateCipherKey,
                                              pAuthKey,
                                              pUpdateAuthKey,
                                              pAdditionalAuthData,
                                              pIvBuffer);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("performOpAndVerify failed\n");
                }
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, &pUpdateCipherKey, NULL, CPA_TRUE);
        // Update session
        updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        if (CPA_STATUS_SUCCESS == updateStatus)
        {
            status = performOpAndVerifyDp(cyInstHandle,
                                          sessionCtx,
                                          setup,
                                          pSessionUpdate,
                                          node,
                                          pSymData,
                                          pSrcBuffer,
                                          pDstBuffer,
                                          pOpData,
                                          pCipherKey,
                                          pUpdateCipherKey,
                                          pAuthKey,
                                          pUpdateAuthKey,
                                          pAdditionalAuthData,
                                          pIvBuffer);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("performOpAndVerify failed\n");
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    // Setup update data
    if (CPA_STATUS_SUCCESS == status)
    {
        setupUpdateData(
            sessionCtx, pSessionUpdate, &pCipherKey, &pAuthKey, CPA_TRUE);

        /* Skip invalid case with auth key update on AES_CCM AES_GCM algchain
         * algorithm */
        if ((setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_CCM ||
             setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_GCM) &&
            (pSessionUpdate->flags & CPA_CY_SYM_SESUPD_AUTH_KEY))
        {
            updateStatus = CPA_STATUS_UNSUPPORTED;
        }
        else
        {
            updateStatus = cpaCySymUpdateSession(sessionCtx, pSessionUpdate);
        }
        if (CPA_STATUS_UNSUPPORTED == updateStatus ||
            CPA_STATUS_SUCCESS == updateStatus)
        {
            if (CPA_STATUS_UNSUPPORTED == updateStatus)
            {
                setupUpdateData(sessionCtx,
                                pSessionUpdate,
                                &pUpdateCipherKey,
                                NULL,
                                CPA_TRUE);
            }
        }
        else
        {
            PRINT_ERR("Update session failed\n");
            status = CPA_STATUS_FAIL;
        }
    }

    return status;
}

static CpaStatus updatePerformDp(symmetric_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus sessionStatus = CPA_STATUS_SUCCESS;
    Cpa32U node = 0;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    CpaInstanceHandle cyInstHandle = setup->cyInstanceHandle;
    Cpa8U *pIvBuffer = NULL;
    Cpa32U ivBufferLen = setup->ivLength;
    Cpa8U **pSrcBuffer = NULL;
    Cpa8U **pDstBuffer = NULL;
    Cpa32U srcBufferLen = setup->flatBufferSizeInBytes;
    Cpa32U dstBufferLen = setup->flatBufferSizeInBytes;
    CpaCySymDpOpData **pOpData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx sessionCtx = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    perf_data_t *pSymData = NULL;
    Cpa8U *pCipherKey = NULL;
    Cpa8U *pUpdateCipherKey = NULL;
    Cpa8U *pAuthKey = NULL;
    Cpa8U *pUpdateAuthKey = NULL;
    Cpa8U *pAdditionalAuthData = NULL;
    Cpa32U innerLoop = 0;
    Cpa32U outerLoop = 0;
    Cpa32U failCount = 0;
    CpaCySymSessionUpdateData sessionUpdate = {0};
    CpaCySymCapabilitiesInfo capInfo;

    sampleCodeBarrier();

    cpaCySymQueryCapabilities(cyInstHandle, &capInfo);

    if (setup->setupData.symOperation == CPA_CY_SYM_OP_CIPHER ||
        setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
    {
        /* For cipher, check if cipher algorithm is correct */
        if (!CPA_BITMAP_BIT_TEST(
                capInfo.ciphers,
                setup->setupData.cipherSetupData.cipherAlgorithm))
        {
            PRINT("Cipher ");
            printCipherAlg(setup->setupData.cipherSetupData);
            PRINT(" is not supported on device. Marking as SUCCESS\n");
            return CPA_STATUS_SUCCESS;
        }
    }

    if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH ||
        setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
    {
        /* For cipher, check if hash algorithm is correct */
        if (!CPA_BITMAP_BIT_TEST(capInfo.hashes,
                                 setup->setupData.hashSetupData.hashAlgorithm))
        {
            PRINT("Hash ");
            printHashAlg(setup->setupData.hashSetupData);
            PRINT(" is not supported on device. Marking as SUCCESS\n");
            return CPA_STATUS_SUCCESS;
        }
    }

    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    // Get instance info
    status = cpaCyInstanceGetInfo2(cyInstHandle, instanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        qaeMemFree((void **)&instanceInfo2);
        return status;
    }
    qaeMemFree((void **)&instanceInfo2);

    // Get node
    status = sampleCodeCyGetNode(cyInstHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return status;
    }


    // Alloc src
    if (CPA_STATUS_SUCCESS == status)
    {
        pSrcBuffer = qaeMemAllocNUMA(
            (sizeof(Cpa8U *) * setup->numBuffers), node, BYTE_ALIGNMENT_64);
        if (NULL == pSrcBuffer)
        {
            PRINT_ERR("Alloc Src buffer failed\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
            {
                // Alloc src buffer
                pSrcBuffer[innerLoop] = qaeMemAllocNUMA(
                    srcBufferLen +
                        setup->setupData.hashSetupData.digestResultLenInBytes,
                    node,
                    BYTE_ALIGNMENT_64);

                if (pSrcBuffer[innerLoop] == NULL)
                {
                    PRINT_ERR("Alloc Src buffer failed\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
                else
                {
                    generateRandomData(pSrcBuffer[innerLoop], srcBufferLen);
                }
            }
        }
    }

    // Alloc dst buffer list
    if (CPA_STATUS_SUCCESS == status)
    {
        pDstBuffer = qaeMemAllocNUMA(
            sizeof(Cpa8U *) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == pDstBuffer)
        {
            PRINT_ERR("Alloc Dst buffer failed\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
            {
                // Alloc dst buffer
                pDstBuffer[innerLoop] = qaeMemAllocNUMA(
                    dstBufferLen +
                        setup->setupData.hashSetupData.digestResultLenInBytes,
                    node,
                    BYTE_ALIGNMENT_64);

                if (NULL == pDstBuffer[innerLoop])
                {
                    PRINT_ERR("Alloc Dst buffer failed\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        // Alloc cipherkey & update cipherkey
        if (setup->setupData.cipherSetupData.cipherKeyLenInBytes > 0)
        {
            status = allocAndFillRandom(
                &pCipherKey,
                setup->setupData.cipherSetupData.cipherKeyLenInBytes,
                node);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Alloc and fill random failed for cipherKey\n");
            }
            else
            {
                status = allocAndFillRandom(
                    &pUpdateCipherKey,
                    setup->setupData.cipherSetupData.cipherKeyLenInBytes,
                    node);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR(
                        "Alloc and fill random failed for update cipherKey\n");
                }
            }
        }
    }

    // Alloc IV
    if (CPA_STATUS_SUCCESS == status)
    {
        if (ivBufferLen > 0)
        {
            if (setup->setupData.cipherSetupData.cipherAlgorithm ==
                CPA_CY_SYM_CIPHER_AES_CCM)
            {
                pIvBuffer =
                    qaeMemAllocNUMA(ivBufferLen, node, BYTE_ALIGNMENT_64);
                if (NULL == pIvBuffer)
                {
                    PRINT_ERR("Alloc iv failed\n");
                    status = CPA_STATUS_FAIL;
                }

                if (CPA_STATUS_SUCCESS == status)
                {
                    memset(pIvBuffer, 0, ivBufferLen);
                    /*Although the IV data length for CCM must be 16 bytes,
                      The nonce length must be between 7 and 13 inclusive*/
                    ivBufferLen = AES_CCM_DEFAULT_NONCE_LENGTH;
                    setup->ivLength = AES_CCM_DEFAULT_NONCE_LENGTH;
                    /*generate a random IV*/
                    generateRandomData(&pIvBuffer[1], ivBufferLen);
                }
            }
            else
            {
                status = allocAndFillRandom(&pIvBuffer, ivBufferLen, node);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Alloc iv failed with status %u\n", status);
                }
            }
        }
    }

    // Alloc authkey & update authkey
    if (CPA_STATUS_SUCCESS == status)
    {
        if (setup->setupData.hashSetupData.authModeSetupData.authKeyLenInBytes >
            0)
        {
            status =
                allocAndFillRandom(&pAuthKey,
                                   setup->setupData.hashSetupData
                                       .authModeSetupData.authKeyLenInBytes,
                                   node);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Alloc and fill random failed for authKey\n");
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                status =
                    allocAndFillRandom(&pUpdateAuthKey,
                                       setup->setupData.hashSetupData
                                           .authModeSetupData.authKeyLenInBytes,
                                       node);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR(
                        "Alloc and fill random failed for update authKey\n");
                }
            }
        }
    }

    // Alloc additional auth data
    if (CPA_STATUS_SUCCESS == status)
    {
        if (setup->setupData.hashSetupData.authModeSetupData.aadLenInBytes > 0)
        {
            if ((setup->setupData.cipherSetupData.cipherAlgorithm ==
                 CPA_CY_SYM_CIPHER_AES_CCM) &&
                (setup->setupData.hashSetupData.hashAlgorithm !=
                 CPA_CY_SYM_HASH_AES_GMAC))
            {
                pAdditionalAuthData =
                    qaeMemAllocNUMA(setup->setupData.hashSetupData
                                        .authModeSetupData.aadLenInBytes,
                                    node,
                                    BYTE_ALIGNMENT_64);
                if (NULL == pAdditionalAuthData)
                {
                    PRINT_ERR("Alloc and fill random failed for additional "
                              "auth data\n");
                    status = CPA_STATUS_FAIL;
                }

                if (CPA_STATUS_SUCCESS == status)
                {
                    memset(pAdditionalAuthData,
                           0,
                           setup->setupData.hashSetupData.authModeSetupData
                               .aadLenInBytes);
                    memcpy(&pAdditionalAuthData[1], &pIvBuffer[1], ivBufferLen);
                }
            }
            else
            {
                status =
                    allocAndFillRandom(&pAdditionalAuthData,
                                       setup->setupData.hashSetupData
                                           .authModeSetupData.aadLenInBytes,
                                       node);
                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("Alloc and fill random failed for additional"
                              "auth data\n");
                }
            }
        }
    }

    // Session setup
    if (CPA_STATUS_SUCCESS == status)
    {
        sessionSetupData.symOperation = setup->setupData.symOperation;
        sessionSetupData.sessionPriority = setup->setupData.sessionPriority;
        sessionSetupData.partialsNotRequired =
            setup->setupData.partialsNotRequired;

        if (setup->setupData.symOperation == CPA_CY_SYM_OP_CIPHER ||
            setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
        {
            sessionSetupData.cipherSetupData.cipherAlgorithm =
                setup->setupData.cipherSetupData.cipherAlgorithm;
            sessionSetupData.cipherSetupData.pCipherKey = pCipherKey;
            sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
                setup->setupData.cipherSetupData.cipherKeyLenInBytes;
            sessionSetupData.cipherSetupData.cipherDirection =
                setup->setupData.cipherSetupData.cipherDirection;
        }

        if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH ||
            setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
        {
            sessionSetupData.hashSetupData.hashAlgorithm =
                setup->setupData.hashSetupData.hashAlgorithm;
            sessionSetupData.hashSetupData.hashMode =
                setup->setupData.hashSetupData.hashMode;
            sessionSetupData.hashSetupData.digestResultLenInBytes =
                setup->setupData.hashSetupData.digestResultLenInBytes;
            sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
                setup->setupData.hashSetupData.authModeSetupData
                    .authKeyLenInBytes;
            sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes =
                setup->setupData.hashSetupData.authModeSetupData.aadLenInBytes;
            sessionSetupData.digestIsAppended = CPA_FALSE;
            sessionSetupData.verifyDigest = CPA_FALSE;
            sessionSetupData.hashSetupData.authModeSetupData.authKey = pAuthKey;
        }

        if (setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
        {
            sessionSetupData.algChainOrder = setup->setupData.algChainOrder;
        }

        if ((setup->setupData.symOperation ==
             CPA_CY_SYM_OP_ALGORITHM_CHAINING) &&
            (setup->setupData.cipherSetupData.cipherAlgorithm ==
             CPA_CY_SYM_CIPHER_AES_CCM))
        {
            sessionSetupData.digestIsAppended = CPA_TRUE;
        }
    }

    // Get sessionCtx size
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCySymDpSessionCtxGetSize(
            cyInstHandle, &sessionSetupData, &sessionCtxSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymDpSessionCtxGetSize failed with status: %d\n",
                      status);
        }
    }

    // Alloc session ctx
    if (CPA_STATUS_SUCCESS == status)
    {
        sessionCtx = qaeMemAllocNUMA(sessionCtxSize, node, BYTE_ALIGNMENT_64);
        if (NULL == sessionCtx)
        {
            PRINT_ERR("Could not allocate pLocalSession memory\n");
            status = CPA_STATUS_FAIL;
        }
        else
        {
            memset(sessionCtx, 0, sessionCtxSize);
        }
    }

    // Init session
    if (CPA_STATUS_SUCCESS == status)
    {

        status =
            cpaCySymDpInitSession(cyInstHandle, &sessionSetupData, sessionCtx);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymDpInitSession failed with status: %d\n", status);
        }
    }

    // Alloc pOpData
    if (CPA_STATUS_SUCCESS == status)
    {
        pOpData =
            qaeMemAllocNUMA((sizeof(CpaCySymDpOpData *) * setup->numBuffers),
                            node,
                            BYTE_ALIGNMENT_64);
        if (NULL == pOpData)
        {
            PRINT_ERR("Alloc pOpData buffer failed\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
            {
                pOpData[innerLoop] = qaeMemAllocNUMA(
                    sizeof(CpaCySymDpOpData), node, BYTE_ALIGNMENT_64);
                if (NULL == pOpData[innerLoop])
                {
                    PRINT_ERR("Alloc pOpData buffer failed\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
                /* Zero initialize Op data structure*/
                memset(pOpData[innerLoop], 0, sizeof(CpaCySymDpOpData));
            }
        }
    }

    // Setup opData
    if (CPA_STATUS_SUCCESS == status)
    {
        for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
        {
            pOpData[innerLoop]->thisPhys = (CpaPhysicalAddr)virtAddrToDevAddr(
                pOpData[innerLoop], cyInstHandle, CPA_ACC_SVC_TYPE_CRYPTO);
            pOpData[innerLoop]->instanceHandle = cyInstHandle;
            pOpData[innerLoop]->sessionCtx = sessionCtx;
            pOpData[innerLoop]->pCallbackTag = setup->performanceStats;
            pOpData[innerLoop]->cryptoStartSrcOffsetInBytes = 0;
            pOpData[innerLoop]->hashStartSrcOffsetInBytes = 0;
            pOpData[innerLoop]->messageLenToHashInBytes = srcBufferLen;
            pOpData[innerLoop]->messageLenToCipherInBytes = srcBufferLen;
            pOpData[innerLoop]->srcBuffer = (CpaPhysicalAddr)virtAddrToDevAddr(
                pSrcBuffer[innerLoop], cyInstHandle, CPA_ACC_SVC_TYPE_CRYPTO);
            pOpData[innerLoop]->srcBufferLen = srcBufferLen;
            pOpData[innerLoop]->dstBuffer = (CpaPhysicalAddr)virtAddrToDevAddr(
                pDstBuffer[innerLoop], cyInstHandle, CPA_ACC_SVC_TYPE_CRYPTO);
            pOpData[innerLoop]->dstBufferLen = dstBufferLen;
            if (setup->setupData.symOperation == CPA_CY_SYM_OP_CIPHER ||
                setup->setupData.symOperation ==
                    CPA_CY_SYM_OP_ALGORITHM_CHAINING)
            {
                pOpData[innerLoop]->iv = (CpaPhysicalAddr)virtAddrToDevAddr(
                    pIvBuffer, cyInstHandle, CPA_ACC_SVC_TYPE_CRYPTO);
                pOpData[innerLoop]->pIv = pIvBuffer;
                pOpData[innerLoop]->ivLenInBytes = ivBufferLen;
            }
            if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH ||
                setup->setupData.symOperation ==
                    CPA_CY_SYM_OP_ALGORITHM_CHAINING)
            {
                if (NULL != pAdditionalAuthData)
                {
                    pOpData[innerLoop]->additionalAuthData =
                        (CpaPhysicalAddr)virtAddrToDevAddr(
                            pAdditionalAuthData,
                            cyInstHandle,
                            CPA_ACC_SVC_TYPE_CRYPTO);
                    pOpData[innerLoop]->pAdditionalAuthData =
                        pAdditionalAuthData;
                }
                else
                {
                    pOpData[innerLoop]->additionalAuthData =
                        (CpaPhysicalAddr)(uintptr_t)NULL;
                    pOpData[innerLoop]->pAdditionalAuthData = NULL;
                }
                pOpData[innerLoop]->digestResult =
                    (CpaPhysicalAddr)virtAddrToDevAddr(
                        pDstBuffer[innerLoop],
                        cyInstHandle,
                        CPA_ACC_SVC_TYPE_CRYPTO) +
                    dstBufferLen;
                pOpData[innerLoop]->srcBufferLen =
                    srcBufferLen +
                    setup->setupData.hashSetupData.digestResultLenInBytes;
                pOpData[innerLoop]->dstBufferLen =
                    dstBufferLen +
                    setup->setupData.hashSetupData.digestResultLenInBytes;
            }
            if (setup->setupData.cipherSetupData.cipherAlgorithm ==
                CPA_CY_SYM_CIPHER_AES_CCM)
            {
                pOpData[innerLoop]->digestResult = (CpaPhysicalAddr)CPA_TRUE;
            }
        }
    }

    // Register Callback
    if (CPA_STATUS_SUCCESS == status)
    {
        if (setup->syncMode == ASYNC)
        {
            status = cpaCySymDpRegCbFunc(
                cyInstHandle, (CpaCySymDpCbFunc)symDpPerformUpdateCallback);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaCySymDpRegCbFunc failed with status %u\n",
                          status);
            }
        }
    }

    // Perform op
    if (CPA_STATUS_SUCCESS == status)
    {
        pSymData = setup->performanceStats;

        memset(pSymData, 0, sizeof(perf_data_t));
        /* Get the time, collect this only for the first
         * request, the callback collects it for the last */
        pSymData->startCyclesTimestamp = sampleCodeTimestamp();

        for (outerLoop = 0; outerLoop < setup->numLoops; outerLoop++)
        {
            if (setup->setupData.symOperation == CPA_CY_SYM_OP_CIPHER)
            {
                status = updatePerformCipherDp(setup,
                                               sessionCtx,
                                               &sessionUpdate,
                                               cyInstHandle,
                                               node,
                                               pSymData,
                                               pOpData,
                                               pSrcBuffer,
                                               pDstBuffer,
                                               pCipherKey,
                                               pUpdateCipherKey,
                                               pAuthKey,
                                               pUpdateAuthKey,
                                               pAdditionalAuthData,
                                               pIvBuffer);

                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("updatePerformCipherDp failed\n");
                    failCount++;
                }
            }
            else if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH)
            {
                status = updatePerformHashDp(setup,
                                             sessionCtx,
                                             &sessionUpdate,
                                             cyInstHandle,
                                             node,
                                             pSymData,
                                             pOpData,
                                             pSrcBuffer,
                                             pDstBuffer,
                                             pCipherKey,
                                             pUpdateCipherKey,
                                             pAuthKey,
                                             pUpdateAuthKey,
                                             pAdditionalAuthData,
                                             pIvBuffer);

                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("updatePerformHashDp failed\n");
                    failCount++;
                }
            }
            else if (setup->setupData.symOperation ==
                     CPA_CY_SYM_OP_ALGORITHM_CHAINING)
            {
                status = updatePerformAlgChainDp(setup,
                                                 sessionCtx,
                                                 &sessionUpdate,
                                                 cyInstHandle,
                                                 node,
                                                 pSymData,
                                                 pOpData,
                                                 pSrcBuffer,
                                                 pDstBuffer,
                                                 pCipherKey,
                                                 pUpdateCipherKey,
                                                 pAuthKey,
                                                 pUpdateAuthKey,
                                                 pAdditionalAuthData,
                                                 pIvBuffer);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("updatePerformAlgChainDp failed\n");
                    failCount++;
                }
            }
        }
    }

    if (failCount > 0)
    {
        status = CPA_STATUS_FAIL;
    }

// Remove session
    sessionStatus = removeSymSession(cyInstHandle, sessionCtx);
    if (sessionStatus != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("removeSymSession failed with status: %d\n", sessionStatus);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = sessionStatus;
    }

    for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
    {
        freeUpdateMem((void **)&pSrcBuffer[innerLoop]);
        freeUpdateMem((void **)&pDstBuffer[innerLoop]);
        freeUpdateMem((void **)&pOpData[innerLoop]);
    }
    freeUpdateMem((void **)&pSrcBuffer);
    freeUpdateMem((void **)&pDstBuffer);
    freeUpdateMem((void **)&pOpData);
    freeUpdateMem((void **)&pIvBuffer);
    freeUpdateMem((void **)&pCipherKey);
    freeUpdateMem((void **)&pUpdateCipherKey);
    freeUpdateMem((void **)&pAuthKey);
    freeUpdateMem((void **)&pUpdateAuthKey);
    freeUpdateMem((void **)&pAdditionalAuthData);
    freeUpdateMem((void **)&sessionCtx);

    return status;
}

void sampleSymmetricDpUpdatePerformance(single_thread_test_data_t *testSetup)
{
    symmetric_test_params_t updateTestSetup;
    symmetric_test_params_t *pSetup =
        ((symmetric_test_params_t *)testSetup->setupPtr);
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;

    memset(&updateTestSetup, 0, sizeof(symmetric_test_params_t));
    updateTestSetup.setupData = pSetup->setupData;
    updateTestSetup.performanceStats = testSetup->performanceStats;

    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        updateTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        updateTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        updateTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        updateTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    updateTestSetup.cyInstanceHandle =
        cyInstances[testSetup->logicalQaInstance];
    updateTestSetup.ivLength = pSetup->ivLength;
    updateTestSetup.syncMode = pSetup->syncMode;
    updateTestSetup.flatBufferSizeInBytes = pSetup->flatBufferSizeInBytes;
    updateTestSetup.numBuffers = pSetup->numBuffers;
    updateTestSetup.numLoops = pSetup->numLoops;

    PRINT("Thread %u, LI %u, ",
          testSetup->threadID,
          testSetup->logicalQaInstance);
    if (updateTestSetup.setupData.symOperation == CPA_CY_SYM_OP_CIPHER)
    {
        PRINT("CipherDP ");
        printCipherAlg(updateTestSetup.setupData.cipherSetupData);
    }
    else if (updateTestSetup.setupData.symOperation == CPA_CY_SYM_OP_HASH)
    {
        PRINT("HashDP ");
        printHashAlg(updateTestSetup.setupData.hashSetupData);
    }
    else if (updateTestSetup.setupData.symOperation ==
             CPA_CY_SYM_OP_ALGORITHM_CHAINING)
    {
        PRINT("AlgChainDP ");
        printCipherAlg(updateTestSetup.setupData.cipherSetupData);
        PRINT(" ");
        printHashAlg(updateTestSetup.setupData.hashSetupData);
    }
    PRINT("\n");

    startBarrier();

    status = updatePerformDp(&updateTestSetup);

    if (CPA_STATUS_SUCCESS != status)
    {
        updateTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
    }

    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */

CpaStatus setupSessionUpdateCipherDp(CpaCySymCipherAlgorithm cipherAlgorithm,
                                     Cpa32U cipherKeyLen,
                                     CpaCyPriority priority,
                                     sync_mode_t syncMode,
                                     Cpa32U packetSize,
                                     Cpa32U numOfPacketsInBuffer,
                                     Cpa32U numBuffers,
                                     Cpa32U numLoops)
{
#if CY_API_VERSION_AT_LEAST(2, 2)
    return symSetupSessionUpdateTest(CPA_CY_SYM_OP_CIPHER,
                                     cipherAlgorithm,
                                     cipherKeyLen,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     priority,
                                     syncMode,
                                     packetSize,
                                     numOfPacketsInBuffer,
                                     numBuffers,
                                     numLoops,
                                     CPA_TRUE,
                                     sampleSymmetricDpUpdatePerformance);
#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}

CpaStatus setupSessionUpdateHashDp(CpaCySymHashAlgorithm hashAlgorithm,
                                   Cpa32U authKeyLen,
                                   CpaCySymHashMode hashMode,
                                   Cpa32U digestResultLenInBytes,
                                   CpaCyPriority priority,
                                   sync_mode_t syncMode,
                                   Cpa32U packetSize,
                                   Cpa32U numOfPacketsInBuffer,
                                   Cpa32U numBuffers,
                                   Cpa32U numLoops)
{
#if CY_API_VERSION_AT_LEAST(2, 2)
    return symSetupSessionUpdateTest(CPA_CY_SYM_OP_HASH,
                                     0,
                                     0,
                                     hashAlgorithm,
                                     authKeyLen,
                                     hashMode,
                                     digestResultLenInBytes,
                                     0,
                                     priority,
                                     syncMode,
                                     packetSize,
                                     numOfPacketsInBuffer,
                                     numBuffers,
                                     numLoops,
                                     CPA_TRUE,
                                     sampleSymmetricDpUpdatePerformance);
#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}

CpaStatus setupSessionUpdateAlgChainDp(CpaCySymCipherAlgorithm cipherAlgorithm,
                                       Cpa32U cipherKeyLen,
                                       CpaCySymHashAlgorithm hashAlgorithm,
                                       Cpa32U authKeyLen,
                                       CpaCySymHashMode hashMode,
                                       Cpa32U digestResultLenInBytes,
                                       CpaCySymAlgChainOrder chainOrder,
                                       CpaCyPriority priority,
                                       sync_mode_t syncMode,
                                       Cpa32U packetSize,
                                       Cpa32U numOfPacketsInBuffer,
                                       Cpa32U numBuffers,
                                       Cpa32U numLoops)
{
#if CY_API_VERSION_AT_LEAST(2, 2)
    return symSetupSessionUpdateTest(CPA_CY_SYM_OP_ALGORITHM_CHAINING,
                                     cipherAlgorithm,
                                     cipherKeyLen,
                                     hashAlgorithm,
                                     authKeyLen,
                                     hashMode,
                                     digestResultLenInBytes,
                                     chainOrder,
                                     priority,
                                     syncMode,
                                     packetSize,
                                     numOfPacketsInBuffer,
                                     numBuffers,
                                     numLoops,
                                     CPA_TRUE,
                                     sampleSymmetricDpUpdatePerformance);
#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}

CpaStatus sessionUpdateTestDp(Cpa32U numLoops, Cpa32U numBuffers)
{
#if CY_API_VERSION_AT_LEAST(2, 2)
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U failCount = 0;
    Cpa32U cipher = 0;
    Cpa32U hash = 0;
    Cpa32U *coreMask = NULL;
    extern const Cpa32U algChainAlgs[][ALGCHAIN_HASH_NUM];
    extern const testSetupCipher_t cipherSetup[ALGCHAIN_CIPHER_NUM];
    extern const testSetupHash_t hashSetup[ALGCHAIN_HASH_NUM];
    extern const Cpa32U cipherAlgs[CIPHER_ALG_NUM];
    extern const Cpa32U hashAlgs[HASH_ALG_NUM];

    // Run cipher tests
    for (cipher = 0; cipher < CIPHER_ALG_NUM; cipher++)
    {

        status = setupSessionUpdateCipherDp(
            cipherSetup[cipherAlgs[cipher]].cipherAlgorithm,
            cipherSetup[cipherAlgs[cipher]].cipherKeyLen,
            CPA_CY_PRIORITY_NORMAL,
            ASYNC,
            SIZE_BIT_IN_BYTES(768),
            10,
            numBuffers,
            numLoops);

        if (CPA_STATUS_SUCCESS == status)
        {

            if (CPA_STATUS_SUCCESS != getCryptoInstanceMapping())
            {
                PRINT_ERR("Could not get Crypto Instance mapping\n");
                return CPA_STATUS_FAIL;
            }

            coreMask = cyInstMap_g;
            status = createPerfomanceThreads(numInst_g, coreMask, numInst_g, 0);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Could not create threads\n");
                return status;
            }

            status = startThreads();
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("Error starting threads\n");
                return status;
            }

            status = waitForThreadCompletion();
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("Performance thread(s) failed\n");
                failCount++;
                continue;
            }
        }
        else
        {

            PRINT("Error setup session");
            failCount++;
        }
    }

    // Run hash tests
    for (hash = 0; hash < HASH_ALG_NUM; hash++)
    {
        status = setupSessionUpdateHashDp(
            hashSetup[hashAlgs[hash]].hashAlgorithm,
            hashSetup[hashAlgs[hash]].authKeyLen,
            CPA_CY_SYM_HASH_MODE_AUTH,
            hashSetup[hashAlgs[hash]].digestResultLenInBytes,
            CPA_CY_PRIORITY_NORMAL,
            ASYNC,
            SIZE_BIT_IN_BYTES(768),
            10,
            numBuffers,
            numLoops);

        if (CPA_STATUS_SUCCESS == status)
        {

            if (CPA_STATUS_SUCCESS != getCryptoInstanceMapping())
            {
                PRINT_ERR("Could not get Crypto Instance mapping\n");
                return CPA_STATUS_FAIL;
            }

            coreMask = cyInstMap_g;
            status = createPerfomanceThreads(numInst_g, coreMask, numInst_g, 0);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Could not create threads\n");
                return status;
            }

            status = startThreads();

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("Error starting threads\n");
                return status;
            }
            status = waitForThreadCompletion();

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("Performance thread(s) failed\n");
                failCount++;
                continue;
            }
        }
        else
        {

            PRINT("Error setup session");
            failCount++;
        }
    }

    // Run algchain tests
    for (cipher = 0; cipher < ALGCHAIN_CIPHER_NUM; cipher++)
    {

        for (hash = 0; hash < ALGCHAIN_HASH_NUM; hash++)
        {

            if (algChainAlgs[cipher][hash])
            {

                status = setupSessionUpdateAlgChainDp(
                    cipherSetup[cipher].cipherAlgorithm,
                    cipherSetup[cipher].cipherKeyLen,
                    hashSetup[hash].hashAlgorithm,
                    hashSetup[hash].authKeyLen,
                    CPA_CY_SYM_HASH_MODE_AUTH,
                    hashSetup[hash].digestResultLenInBytes,
                    CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
                    CPA_CY_PRIORITY_NORMAL,
                    ASYNC,
                    SIZE_BIT_IN_BYTES(768),
                    10,
                    numBuffers,
                    numLoops);

                if (CPA_STATUS_SUCCESS == status)
                {

                    if (CPA_STATUS_SUCCESS != getCryptoInstanceMapping())
                    {
                        PRINT_ERR("Could not get Crypto Instance mapping\n");
                        return CPA_STATUS_FAIL;
                    }

                    coreMask = cyInstMap_g;
                    status = createPerfomanceThreads(
                        numInst_g, coreMask, numInst_g, 0);
                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT_ERR("Could not create threads\n");
                        return status;
                    }

                    status = startThreads();

                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT("Error starting threads\n");
                        return status;
                    }
                    status = waitForThreadCompletion();

                    if (CPA_STATUS_SUCCESS != status)
                    {
                        PRINT("Performance thread(s) failed\n");
                        failCount++;
                        continue;
                    }
                }
                else
                {
                    PRINT("Error setup session");
                    failCount++;
                }
            }
        }
    }

    if (failCount > 0)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;

#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}
EXPORT_SYMBOL(sessionUpdateTestDp);
