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
 * @file cpa_sample_code_sym_update.c
 *
 * @defgroup sampleSymmetricPerf  Symmetric Performance code
 *
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *      This file contains the main symmetric session update performance
 *      sample code. It is capable of performing all ciphers, all hashes,
 *      authenticated hashes and algorithm chaining with session update
 *      operation.
 *
 *****************************************************************************/
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "icp_sal_poll.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa.h"
#include "cpa_cy_common.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_code_sym_update_common.h"

#if CY_API_VERSION_AT_LEAST(2, 2)

// Perform
static CpaStatus performOpAndVerify(CpaInstanceHandle cyInstHandle,
                                    CpaCySymSessionCtx sessionCtx,
                                    symmetric_test_params_t *setup,
                                    CpaCySymSessionUpdateData *pSessionUpdate,
                                    Cpa32U node,
                                    perf_data_t *pSymData,
                                    CpaBufferList **pSrcBufferList,
                                    CpaBufferList **pDstBufferList,
                                    CpaCySymOpData **pOpData,
                                    Cpa8U *pCipherKey,
                                    Cpa8U *pUpdateCipherKey,
                                    Cpa8U *pAuthKey,
                                    Cpa8U *pUpdateAuthKey,
                                    Cpa8U *pAdditionalAuthData,
                                    Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U innerLoop = 0;
    Cpa32U failCount = 0;
    CpaBoolean sessionInUse = CPA_TRUE;
    CpaBoolean verifyResult = CPA_TRUE;

    setup->performanceStats->numOperations += setup->numBuffers;

    // Perform
    for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
    {
        do
        {
            status = cpaCySymPerformOp(cyInstHandle,
                                       pSymData,
                                       pOpData[innerLoop],
                                       pSrcBufferList[innerLoop],
                                       pDstBufferList[innerLoop],
                                       &verifyResult);
            if (CPA_STATUS_RETRY == status)
            {
                pSymData->retries++;
                AVOID_SOFTLOCKUP;
            }
        } while (status == CPA_STATUS_RETRY);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp failed - status %d\n", status);
            failCount++;
        }
    }

// Wait for completion
    do
    {
        status = cpaCySymSessionInUse(sessionCtx, &sessionInUse);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("cpaCySymSessionInUse: failed - status: %d\n", status);
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
static CpaStatus updatePerformCipher(symmetric_test_params_t *setup,
                                     CpaCySymSessionCtx sessionCtx,
                                     CpaCySymSessionUpdateData *pSessionUpdate,
                                     CpaInstanceHandle cyInstHandle,
                                     Cpa32U node,
                                     perf_data_t *pSymData,
                                     CpaCySymOpData **pOpData,
                                     CpaBufferList **pSrcBufferList,
                                     CpaBufferList **pDstBufferList,
                                     CpaBoolean *verifyResult,
                                     Cpa8U *pCipherKey,
                                     Cpa8U *pUpdateCipherKey,
                                     Cpa8U *pAuthKey,
                                     Cpa8U *pUpdateAuthKey,
                                     Cpa8U *pAdditionalAuthData,
                                     Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus updateStatus = CPA_STATUS_SUCCESS;

    status = performOpAndVerify(cyInstHandle,
                                sessionCtx,
                                setup,
                                pSessionUpdate,
                                node,
                                pSymData,
                                pSrcBufferList,
                                pDstBufferList,
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
            status = performOpAndVerify(cyInstHandle,
                                        sessionCtx,
                                        setup,
                                        pSessionUpdate,
                                        node,
                                        pSymData,
                                        pSrcBufferList,
                                        pDstBufferList,
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
            status = performOpAndVerify(cyInstHandle,
                                        sessionCtx,
                                        setup,
                                        pSessionUpdate,
                                        node,
                                        pSymData,
                                        pSrcBufferList,
                                        pDstBufferList,
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
static CpaStatus updatePerformHash(symmetric_test_params_t *setup,
                                   CpaCySymSessionCtx sessionCtx,
                                   CpaCySymSessionUpdateData *pSessionUpdate,
                                   CpaInstanceHandle cyInstHandle,
                                   Cpa32U node,
                                   perf_data_t *pSymData,
                                   CpaCySymOpData **pOpData,
                                   CpaBufferList **pSrcBufferList,
                                   CpaBufferList **pDstBufferList,
                                   CpaBoolean *verifyResult,
                                   Cpa8U *pCipherKey,
                                   Cpa8U *pUpdateCipherKey,
                                   Cpa8U *pAuthKey,
                                   Cpa8U *pUpdateAuthKey,
                                   Cpa8U *pAdditionalAuthData,
                                   Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus updateStatus = CPA_STATUS_SUCCESS;

    status = performOpAndVerify(cyInstHandle,
                                sessionCtx,
                                setup,
                                pSessionUpdate,
                                node,
                                pSymData,
                                pSrcBufferList,
                                pDstBufferList,
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
            status = performOpAndVerify(cyInstHandle,
                                        sessionCtx,
                                        setup,
                                        pSessionUpdate,
                                        node,
                                        pSymData,
                                        pSrcBufferList,
                                        pDstBufferList,
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
            PRINT_ERR("Update sesssion failed\n");
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
static CpaStatus updatePerformAlgChain(
    symmetric_test_params_t *setup,
    CpaCySymSessionCtx sessionCtx,
    CpaCySymSessionUpdateData *pSessionUpdate,
    CpaInstanceHandle cyInstHandle,
    Cpa32U node,
    perf_data_t *pSymData,
    CpaCySymOpData **pOpData,
    CpaBufferList **pSrcBufferList,
    CpaBufferList **pDstBufferList,
    CpaBoolean *verifyResult,
    Cpa8U *pCipherKey,
    Cpa8U *pUpdateCipherKey,
    Cpa8U *pAuthKey,
    Cpa8U *pUpdateAuthKey,
    Cpa8U *pAdditionalAuthData,
    Cpa8U *pIvBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus updateStatus = CPA_STATUS_SUCCESS;

    status = performOpAndVerify(cyInstHandle,
                                sessionCtx,
                                setup,
                                pSessionUpdate,
                                node,
                                pSymData,
                                pSrcBufferList,
                                pDstBufferList,
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
            status = performOpAndVerify(cyInstHandle,
                                        sessionCtx,
                                        setup,
                                        pSessionUpdate,
                                        node,
                                        pSymData,
                                        pSrcBufferList,
                                        pDstBufferList,
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
                status = performOpAndVerify(cyInstHandle,
                                            sessionCtx,
                                            setup,
                                            pSessionUpdate,
                                            node,
                                            pSymData,
                                            pSrcBufferList,
                                            pDstBufferList,
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
            status = performOpAndVerify(cyInstHandle,
                                        sessionCtx,
                                        setup,
                                        pSessionUpdate,
                                        node,
                                        pSymData,
                                        pSrcBufferList,
                                        pDstBufferList,
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
            // Update session
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
                status = performOpAndVerify(cyInstHandle,
                                            sessionCtx,
                                            setup,
                                            pSessionUpdate,
                                            node,
                                            pSymData,
                                            pSrcBufferList,
                                            pDstBufferList,
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
            // Update session
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
                status = performOpAndVerify(cyInstHandle,
                                            sessionCtx,
                                            setup,
                                            pSessionUpdate,
                                            node,
                                            pSymData,
                                            pSrcBufferList,
                                            pDstBufferList,
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
            status = performOpAndVerify(cyInstHandle,
                                        sessionCtx,
                                        setup,
                                        pSessionUpdate,
                                        node,
                                        pSymData,
                                        pSrcBufferList,
                                        pDstBufferList,
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
            // Update session
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

static CpaStatus updatePerform(symmetric_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus sessionStatus = CPA_STATUS_SUCCESS;
    Cpa32U node = 0;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    CpaInstanceHandle cyInstHandle = setup->cyInstanceHandle;
    Cpa8U *pIvBuffer = NULL;
    Cpa32U ivBufferLen = setup->ivLength;
    Cpa8U **pSrcBuffer = NULL;
    CpaBufferList **pSrcBufferList = NULL;
    Cpa8U **pDstBuffer = NULL;
    CpaBufferList **pDstBufferList = NULL;
    Cpa32U srcBufferLen = setup->flatBufferSizeInBytes;
    Cpa32U dstBufferLen = setup->flatBufferSizeInBytes;
    CpaCySymOpData **pOpData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx sessionCtx = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    CpaBoolean verifyResult = CPA_TRUE;
    perf_data_t *pSymData = NULL;
    CpaCySymCbFunc pSymCb = NULL;
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
            pSrcBufferList = qaeMemAllocNUMA(
                (sizeof(Cpa8U *) * setup->numBuffers), node, BYTE_ALIGNMENT_64);
            if (NULL == pSrcBufferList)
            {
                PRINT_ERR("Alloc Src buffer list failed\n");
                status = CPA_STATUS_FAIL;
            }
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

                if (NULL == pSrcBuffer[innerLoop])
                {
                    PRINT_ERR("Alloc Src buffer failed\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
                else
                {
                    generateRandomData(pSrcBuffer[innerLoop], srcBufferLen);
                }

                // Alloc src buffer list
                status = setupBufferList(
                    &pSrcBuffer[innerLoop],
                    1,
                    srcBufferLen +
                        setup->setupData.hashSetupData.digestResultLenInBytes,
                    &pSrcBufferList[innerLoop],
                    node);
                if (pSrcBufferList[innerLoop] == NULL)
                {
                    PRINT_ERR("Alloc Src buffer list failed\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
    }

    // Alloc dst buffer list
    if (CPA_STATUS_SUCCESS == status)
    {

        pDstBuffer = qaeMemAllocNUMA(
            (sizeof(Cpa8U *) * setup->numBuffers), node, BYTE_ALIGNMENT_64);
        if (NULL == pDstBuffer)
        {
            PRINT_ERR("Alloc Dst buffer failed\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            pDstBufferList = qaeMemAllocNUMA(
                (sizeof(Cpa8U *) * setup->numBuffers), node, BYTE_ALIGNMENT_64);
            if (NULL == pDstBufferList)
            {
                PRINT_ERR("Alloc Dst buffer failed\n");
                status = CPA_STATUS_FAIL;
            }
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

                // Alloc dst buffer list
                status = setupBufferList(
                    &pDstBuffer[innerLoop],
                    1,
                    dstBufferLen +
                        setup->setupData.hashSetupData.digestResultLenInBytes,
                    &pDstBufferList[innerLoop],
                    node);
                if (pDstBufferList[innerLoop] == NULL)
                {
                    PRINT_ERR("Alloc Dst buffer list failed\n");
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
            sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
            sessionSetupData.hashSetupData.digestResultLenInBytes =
                setup->setupData.hashSetupData.digestResultLenInBytes;
            sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes =
                setup->setupData.hashSetupData.authModeSetupData
                    .authKeyLenInBytes;
            sessionSetupData.hashSetupData.authModeSetupData.aadLenInBytes =
                setup->setupData.hashSetupData.authModeSetupData.aadLenInBytes;
            sessionSetupData.digestIsAppended = CPA_TRUE;
            sessionSetupData.verifyDigest = CPA_FALSE;
            sessionSetupData.hashSetupData.authModeSetupData.authKey = pAuthKey;
        }

        if (setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
        {
            sessionSetupData.algChainOrder = setup->setupData.algChainOrder;
        }
    }

    // Get sessionCtx size
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCySymSessionCtxGetSize(
            cyInstHandle, &sessionSetupData, &sessionCtxSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymSessionCtxGetSize failed with status: %d\n",
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

    // Set sync mode
    if (CPA_STATUS_SUCCESS == status)
    {
        if (ASYNC == setup->syncMode)
        {
            pSymCb = symPerformCallback;
        }
    }

    // Init session
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCySymInitSession(
            cyInstHandle, pSymCb, &sessionSetupData, sessionCtx);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymInitSession failed with status: %d\n", status);
        }
    }

    // Alloc pOpData
    if (CPA_STATUS_SUCCESS == status)
    {
        pOpData =
            qaeMemAllocNUMA((sizeof(CpaCySymOpData *) * setup->numBuffers),
                            node,
                            BYTE_ALIGNMENT_64);
        if (pOpData == NULL)
        {
            PRINT_ERR("Alloc pOpData buffer failed\n");
            status = CPA_STATUS_FAIL;
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
            {
                pOpData[innerLoop] = qaeMemAllocNUMA(
                    sizeof(CpaCySymOpData), node, BYTE_ALIGNMENT_64);
                if (NULL == pOpData[innerLoop])
                {
                    PRINT_ERR("Alloc pOpData buffer failed\n");
                    status = CPA_STATUS_FAIL;
                    break;
                }
            }
        }
    }

    // Setup opData
    if (CPA_STATUS_SUCCESS == status)
    {
        for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
        {
            pOpData[innerLoop]->sessionCtx = sessionCtx;
            pOpData[innerLoop]->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
            pOpData[innerLoop]->pIv = pIvBuffer;
            pOpData[innerLoop]->ivLenInBytes = ivBufferLen;
            pOpData[innerLoop]->cryptoStartSrcOffsetInBytes = 0;
            pOpData[innerLoop]->hashStartSrcOffsetInBytes = 0;
            pOpData[innerLoop]->messageLenToHashInBytes = srcBufferLen;
            pOpData[innerLoop]->messageLenToCipherInBytes = srcBufferLen;
            if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH ||
                setup->setupData.symOperation ==
                    CPA_CY_SYM_OP_ALGORITHM_CHAINING)
            {
                pOpData[innerLoop]->pAdditionalAuthData = pAdditionalAuthData;
            }
        }
    }

    pSymData = setup->performanceStats;
    memset(pSymData, 0, sizeof(perf_data_t));

    /* Init the semaphore used in the callback */
    sampleCodeSemaphoreInit(&pSymData->comp, 0);

    // Perform op
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Get the time, collect this only for the first
         * request, the callback collects it for the last */
        pSymData->startCyclesTimestamp = sampleCodeTimestamp();

        for (outerLoop = 0; outerLoop < setup->numLoops; outerLoop++)
        {
            if (setup->setupData.symOperation == CPA_CY_SYM_OP_CIPHER)
            {
                status = updatePerformCipher(setup,
                                             sessionCtx,
                                             &sessionUpdate,
                                             cyInstHandle,
                                             node,
                                             pSymData,
                                             pOpData,
                                             pSrcBufferList,
                                             pDstBufferList,
                                             &verifyResult,
                                             pCipherKey,
                                             pUpdateCipherKey,
                                             pAuthKey,
                                             pUpdateAuthKey,
                                             pAdditionalAuthData,
                                             pIvBuffer);

                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("updatePerformCipher failed\n");
                    failCount++;
                }
            }
            else if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH)
            {
                status = updatePerformHash(setup,
                                           sessionCtx,
                                           &sessionUpdate,
                                           cyInstHandle,
                                           node,
                                           pSymData,
                                           pOpData,
                                           pSrcBufferList,
                                           pDstBufferList,
                                           &verifyResult,
                                           pCipherKey,
                                           pUpdateCipherKey,
                                           pAuthKey,
                                           pUpdateAuthKey,
                                           pAdditionalAuthData,
                                           pIvBuffer);

                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("updatePerformHash failed\n");
                    failCount++;
                }
            }
            else if (setup->setupData.symOperation ==
                     CPA_CY_SYM_OP_ALGORITHM_CHAINING)
            {
                status = updatePerformAlgChain(setup,
                                               sessionCtx,
                                               &sessionUpdate,
                                               cyInstHandle,
                                               node,
                                               pSymData,
                                               pOpData,
                                               pSrcBufferList,
                                               pDstBufferList,
                                               &verifyResult,
                                               pCipherKey,
                                               pUpdateCipherKey,
                                               pAuthKey,
                                               pUpdateAuthKey,
                                               pAdditionalAuthData,
                                               pIvBuffer);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("updatePerformAlgChain failed\n");
                    failCount++;
                }
            }
        }
    }

    /*clean up the callback semaphore*/
    sampleCodeSemaphoreDestroy(&pSymData->comp);

    if (failCount > 0)
    {
        status = CPA_STATUS_FAIL;
    }

// Remove session
    sessionStatus = removeSymSession(cyInstHandle, sessionCtx);
    if (sessionStatus != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCySymRemoveSession failed with status: %d\n",
                  sessionStatus);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = sessionStatus;
    }

// Free memory
    for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
    {
        freeUpdateMem((void **)&pSrcBuffer[innerLoop]);
        freeUpdateMem((void **)&pSrcBufferList[innerLoop]);
        freeUpdateMem((void **)&pDstBuffer[innerLoop]);
        freeUpdateMem((void **)&pDstBufferList[innerLoop]);
        freeUpdateMem((void **)&pOpData[innerLoop]);
    }
    freeUpdateMem((void **)&pSrcBuffer);
    freeUpdateMem((void **)&pSrcBufferList);
    freeUpdateMem((void **)&pDstBuffer);
    freeUpdateMem((void **)&pDstBufferList);
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

void sampleSymmetricUpdatePerformance(single_thread_test_data_t *testSetup)
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
    updateTestSetup.syncMode = pSetup->syncMode;
    updateTestSetup.flatBufferSizeInBytes = pSetup->flatBufferSizeInBytes;
    updateTestSetup.numBuffers = pSetup->numBuffers;
    updateTestSetup.numLoops = pSetup->numLoops;
    updateTestSetup.ivLength = pSetup->ivLength;

    PRINT("Thread %u, LI %u, ",
          testSetup->threadID,
          testSetup->logicalQaInstance);
    if (updateTestSetup.setupData.symOperation == CPA_CY_SYM_OP_CIPHER)
    {
        PRINT("Cipher ");
        printCipherAlg(updateTestSetup.setupData.cipherSetupData);
    }
    else if (updateTestSetup.setupData.symOperation == CPA_CY_SYM_OP_HASH)
    {
        PRINT("Hash ");
        printHashAlg(updateTestSetup.setupData.hashSetupData);
    }
    else if (updateTestSetup.setupData.symOperation ==
             CPA_CY_SYM_OP_ALGORITHM_CHAINING)
    {
        PRINT("AlgChain ");
        printCipherAlg(updateTestSetup.setupData.cipherSetupData);
        PRINT(" ");
        printHashAlg(updateTestSetup.setupData.hashSetupData);
    }
    PRINT("\n");

    startBarrier();

    status = updatePerform(&updateTestSetup);

    if (CPA_STATUS_SUCCESS != status)
    {
        updateTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        testSetup->statsPrintFunc =
            (stats_print_func_t)printSymmetricPerfDataAndStopCyService;
    }

    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */

CpaStatus setupSessionUpdateCipher(CpaCySymCipherAlgorithm cipherAlgorithm,
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
                                     CPA_FALSE,
                                     sampleSymmetricUpdatePerformance);
#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}
EXPORT_SYMBOL(setupSessionUpdateCipher);

CpaStatus setupSessionUpdateHash(CpaCySymHashAlgorithm hashAlgorithm,
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
                                     CPA_FALSE,
                                     sampleSymmetricUpdatePerformance);
#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}
EXPORT_SYMBOL(setupSessionUpdateHash);

CpaStatus setupSessionUpdateAlgChain(CpaCySymCipherAlgorithm cipherAlgorithm,
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
                                     CPA_FALSE,
                                     sampleSymmetricUpdatePerformance);
#else
    PRINT_ERR("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}
EXPORT_SYMBOL(setupSessionUpdateAlgChain);

CpaStatus sessionUpdateTest(Cpa32U numLoops, Cpa32U numBuffers)
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
        status = setupSessionUpdateCipher(
            cipherSetup[cipherAlgs[cipher]].cipherAlgorithm,
            cipherSetup[cipherAlgs[cipher]].cipherKeyLen,
            CPA_CY_PRIORITY_NORMAL,
            ASYNC,
            SIZE_BIT_IN_BYTES(768),
            100,
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
        status = setupSessionUpdateHash(
            hashSetup[hashAlgs[hash]].hashAlgorithm,
            hashSetup[hashAlgs[hash]].authKeyLen,
            CPA_CY_SYM_HASH_MODE_AUTH,
            hashSetup[hashAlgs[hash]].digestResultLenInBytes,
            CPA_CY_PRIORITY_NORMAL,
            ASYNC,
            SIZE_BIT_IN_BYTES(768),
            100,
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
                status = setupSessionUpdateAlgChain(
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
                    100,
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
EXPORT_SYMBOL(sessionUpdateTest);
