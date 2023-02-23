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
 * @file cpa_sample_code_drbg_perf.c
 *
 * @ingroup drbgPerformance
 *
 * @description
 *      This file contains the DRBG performance functions
 *
 *****************************************************************************/

#include "cpa_sample_code_drbg_perf.h"
#include "icp_sal_drbg_impl.h"

/* internal data structure to be filled in personalizationString for
 * DRBG session setup
 */
typedef struct personalize_s
{
    struct timeval tv;
    int tmid;
} personalize_t;

typedef struct nrbg_sample_data_s
{
    CpaCyNrbgOpData opData;
    /* NRBG client information */
    IcpSalDrbgGetEntropyInputCbFunc pClientCbFunc;
    void *pClientCallbackTag;
    void *pClientOpData;
} nrbg_sample_data_t;

static CpaStatus drbgRemoveSession(drbg_test_params_t *setup,
                                   CpaCyDrbgSessionSetupData *pSessionSetupData,
                                   CpaCyDrbgSessionHandle *pSessionHdl,
                                   Cpa32U numSessions);
static CpaStatus drbgSetupSession(drbg_test_params_t *setup,
                                  CpaCyDrbgSessionSetupData *pSessionSetupData,
                                  CpaCyDrbgSessionHandle *pSessionHdl,
                                  Cpa32U node);
static CpaStatus drbgPerformOp(drbg_test_params_t *setup,
                               CpaCyDrbgSessionHandle *pSessionHdl,
                               Cpa32U node);

/* Previously set GetEntropy function pointer */
static IcpSalDrbgGetEntropyInputFunc pPrevGetEntropyInputFunc = NULL;

/* Previously set GetNonce function pointer */
static IcpSalDrbgGetNonceFunc pPrevGetNonceFunc = NULL;

/* Previously set IsDFReq function pointer */
static IcpSalDrbgIsDFReqFunc pPrevDrbgIsDFReqFunc = NULL;

/* A counter for ImplFucntion is registered or not */
/* Only when this number equal 0, then real impl function can be called*/
static int drbgImplFunctionsRegistered = 0;

/* A semaphore to make the impl function register/unregister only once */
static sample_code_semaphore_t semaphoreImplFunction;

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *      NRBG Internal Callback Function
 *
 * @description
 *      This is an internal callback function that will be used to signal
 *      the caller that the asynchronous operation is completed. The signal
 *      is performed by calling the client-supplied callback function.
 *
 *****************************************************************************/
void drbgPerformCallback(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaFlatBuffer *pOut)
{
    perf_data_t *pDrbgPerf = (perf_data_t *)pCallbackTag;

    if (NULL == pDrbgPerf)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    pDrbgPerf->responses++;

    /* post the semaphore until all session are Okay */
    if (pDrbgPerf->responses == pDrbgPerf->numOperations)
    {
        pDrbgPerf->endCyclesTimestamp = sampleCodeTimestamp();
        sampleCodeSemaphorePost(&pDrbgPerf->comp);
    }
    return;
}

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *      NRBG Internal Callback Function
 *
 * @description
 *      This is an internal callback function that will be used to signal
 *      the caller that the asynchronous operation is completed. The signal
 *      is performed by calling the client-supplied callback function.
 *
 *****************************************************************************/
static void nrbgCallback(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpdata,
                         CpaFlatBuffer *pOut)
{
    nrbg_sample_data_t *pNrbgData = NULL;
    IcpSalDrbgGetEntropyInputCbFunc pClientCb = NULL;
    void *pClientCallbackTag = NULL;
    void *pClientOpData = NULL;
    Cpa32U lengthReturned = 0;

    if (NULL == pCallbackTag)
    {
        PRINT_ERR("pCallbackTag is null");
        return;
    }

    pNrbgData = (nrbg_sample_data_t *)pCallbackTag;

    if (CPA_STATUS_SUCCESS == status)
    {
        lengthReturned = pNrbgData->opData.lengthInBytes;
    }

    pClientCb = pNrbgData->pClientCbFunc;
    pClientCallbackTag = pNrbgData->pClientCallbackTag;
    pClientOpData = pNrbgData->pClientOpData;

    qaeMemFree((void **)&pNrbgData);

    pClientCb(pClientCallbackTag, status, pClientOpData, lengthReturned, pOut);
}

/***************************************************************************
 * @ingroup drbgPerformance
 *
 * @description
 *      Print the performance stats of the elliptic curve dsa operations
 ***************************************************************************/
CpaStatus drbgPrintStats(thread_creation_data_t *data)
{
    PRINT("DRBG Size %23u\n", data->packetSize);
    printSymmetricPerfDataAndStopCyService(data);
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *
 * @description
 *       This function implements the DRBG implementation-specific
 *      'Get Entropy Input' function by calling cpaCyNrbgGetEntropy API.
 *
 *****************************************************************************/
static CpaStatus nrbgGetEntropy(IcpSalDrbgGetEntropyInputCbFunc pCb,
                                void *pCallbackTag,
                                icp_sal_drbg_get_entropy_op_data_t *pOpData,
                                CpaFlatBuffer *pBuffer,
                                Cpa32U *pLengthReturned)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyGenFlatBufCbFunc pNrbgCbFunc = NULL;
    nrbg_sample_data_t *pNrbgData = NULL;
    CpaCyCapabilitiesInfo cyCap;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    /* For now use the first crypto instance - assumed to be
        started already */
    status = cpaCyGetInstances(1, &instanceHandle);
    if (instanceHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }
    /* Verify that the instance has NRBG capabilities */
    status = cpaCyQueryCapabilities(instanceHandle, &cyCap);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
    /* Check if the instance support NRBG*/
    if (cyCap.nrbgSupported != CPA_TRUE)
    {
        PRINT_ERR("Instance does not support NRBG\n");
        return CPA_STATUS_RESOURCE;
    }

    if (NULL == pOpData)
    {
        PRINT_ERR("Invalid parameter -- pOpData\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    if ((NULL == pLengthReturned) && (NULL == pCb))
    {
        PRINT_ERR("Invalid parameter -- pLengthReturned\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    pNrbgData = qaeMemAlloc(sizeof(nrbg_sample_data_t));
    if (NULL == pNrbgData)
    {
        PRINT_ERR("Failed to allocate pNrbgData\n");
        return CPA_STATUS_FAIL;
    }

    /* number of bytes to be generated */
    pNrbgData->opData.lengthInBytes = pOpData->maxLength;

    /* store client information */
    pNrbgData->pClientCbFunc = pCb;
    pNrbgData->pClientCallbackTag = pCallbackTag;
    pNrbgData->pClientOpData = (void *)pOpData;

    /* use local callback function on asynchronous operation */
    if (NULL != pCb)
    {
        pNrbgCbFunc = nrbgCallback;
    }

    do
    {
        /* call nrbg function to get entropy */
        status = cpaCyNrbgGetEntropy(instanceHandle,
                                     pNrbgCbFunc,
                                     pNrbgData,
                                     &(pNrbgData->opData),
                                     pBuffer);
    } while (CPA_STATUS_RETRY == status);

    if (CPA_STATUS_SUCCESS != status)
    {
        status =
            (CPA_STATUS_INVALID_PARAM == status) ? status : CPA_STATUS_FAIL;
        PRINT_ERR("cpaCyNrbgGetEntropy failed. (status = %d)\n", status);
        qaeMemFree((void **)&pNrbgData);
        return status;
    }

    if (NULL == pCb)
    {
        *pLengthReturned = pNrbgData->opData.lengthInBytes;
        qaeMemFree((void **)&pNrbgData);
    }

    return CPA_STATUS_SUCCESS;
}

static CpaStatus nrbgGetNonce(icp_sal_drbg_get_entropy_op_data_t *pOpData,
                              CpaFlatBuffer *pBuffer,
                              Cpa32U *pLengthReturned)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = nrbgGetEntropy(NULL, NULL, pOpData, pBuffer, pLengthReturned);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("nrbgGetEntropy failed. (status = %d)\n", status);
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *      NRBG Is Derivation Function(DF) Required Function
 *
 * @description
 *      This function implements the DRBG implementation-specific
 *      'Is Derivation Function Required' function.
 *
 *****************************************************************************/
static CpaBoolean nrbgIsDFRequired(void)
{
    return CPA_TRUE;
}

static CpaBoolean nrbgNotDFRequired(void)
{
    return CPA_FALSE;
}

static void nrbgRegisterDrbgImplFunctions(CpaBoolean dFReq)
{
    CpaStatus status;

    status = sampleCodeSemaphoreWait(&semaphoreImplFunction,
                                     SAMPLE_CODE_WAIT_FOREVER);
    if (CPA_STATUS_SUCCESS == status)
    {
        if (0 == drbgImplFunctionsRegistered)
        {
            pPrevGetEntropyInputFunc =
                icp_sal_drbgGetEntropyInputFuncRegister(nrbgGetEntropy);

            pPrevGetNonceFunc = icp_sal_drbgGetNonceFuncRegister(nrbgGetNonce);

            if (CPA_TRUE == dFReq)
            {
                pPrevDrbgIsDFReqFunc =
                    icp_sal_drbgIsDFReqFuncRegister(nrbgIsDFRequired);
            }
            else
            {
                pPrevDrbgIsDFReqFunc =
                    icp_sal_drbgIsDFReqFuncRegister(nrbgNotDFRequired);
            }
            /* add the register number per thread */
        }
        drbgImplFunctionsRegistered++;
        sampleCodeSemaphorePost(&semaphoreImplFunction);
    }

    return;
}

void nrbgUnregisterDrbgImplFunctions(void)
{
    CpaStatus status;

    status = sampleCodeSemaphoreWait(&semaphoreImplFunction,
                                     SAMPLE_CODE_WAIT_FOREVER);
    if (CPA_STATUS_SUCCESS == status)
    {
        drbgImplFunctionsRegistered--;
        if (0 == drbgImplFunctionsRegistered)
        {
            icp_sal_drbgGetEntropyInputFuncRegister(pPrevGetEntropyInputFunc);
            icp_sal_drbgGetNonceFuncRegister(pPrevGetNonceFunc);
            icp_sal_drbgIsDFReqFuncRegister(pPrevDrbgIsDFReqFunc);
            sampleCodeSemaphoreDestroy(&semaphoreImplFunction);
        }
        else
        {
            sampleCodeSemaphorePost(&semaphoreImplFunction);
        }
    }
}

/*
 * This function performs a drbg generate operation.
 */

static CpaStatus drbgPerformOp(drbg_test_params_t *setup,
                               CpaCyDrbgSessionHandle *pSessionHdl,
                               Cpa32U node)

{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U drbgDataSize = setup->lengthInBytes;
    perf_data_t *pDrbgPerf = NULL;
    CpaCyDrbgGenOpData *pCurOpData = NULL;
    CpaCyDrbgGenOpData **pOpData;
    Cpa8U *pDrbgData = NULL;
    CpaFlatBuffer *pDrbgOut;
    Cpa32U numLoops, numSessions;
    Cpa32U anyFail = 0, ses;

    pDrbgPerf = setup->performanceStats;
    numSessions = setup->numSessions;

    pOpData = qaeMemAlloc(sizeof(CpaCyDrbgGenOpData *) * numSessions);
    if (NULL == pOpData)
    {
        PRINT_ERR("Failed to alloc memory\n");
        return (CPA_STATUS_FAIL);
    }

    pDrbgOut = qaeMemAlloc(sizeof(CpaFlatBuffer) * numSessions);
    if (NULL == pDrbgOut)
    {
        PRINT_ERR("Failed to alloc memory\n");
        qaeMemFree((void **)&pOpData);
        return (CPA_STATUS_FAIL);
    }

    /* Init the pointer array to be 0 */
    for (ses = 0; ses < numSessions; ses++)
    {
        pOpData[ses] = NULL;
        pDrbgOut[ses].pData = NULL;
    }

    /* allocate all memory needed */
    for (ses = 0; ses < numSessions; ses++)
    {

        pDrbgData =
            (Cpa8U *)qaeMemAllocNUMA(drbgDataSize, node, BYTE_ALIGNMENT_64);
        if (NULL == pDrbgData)
        {
            anyFail++;
            break;
        }
        pDrbgOut[ses].pData = pDrbgData;
        pDrbgOut[ses].dataLenInBytes = drbgDataSize;

        pCurOpData =
            (CpaCyDrbgGenOpData *)qaeMemAlloc(sizeof(CpaCyDrbgGenOpData));
        if (NULL == pCurOpData)
        {
            anyFail++;
            break;
        }
        memset(pCurOpData, 0, sizeof(CpaCyDrbgGenOpData));
        pCurOpData->sessionHandle = pSessionHdl[ses];
        pCurOpData->lengthInBytes = drbgDataSize;
        pCurOpData->secStrength = setup->secStrength;
        pCurOpData->predictionResistanceRequired =
            setup->predictionResistanceRequired;
        pCurOpData->additionalInput.dataLenInBytes = 0;
        pCurOpData->additionalInput.pData = NULL;
        pOpData[ses] = pCurOpData;
    }

    /*this barrier will wait until all threads get to this point */
    sampleCodeBarrier();
    if (0 == anyFail)
    {
        sampleCodeSemaphoreInit(&pDrbgPerf->comp, 0);

        pDrbgPerf->startCyclesTimestamp = sampleCodeTimestamp();
        for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
        {
            /* prepare this data structure for callback */
            pDrbgPerf->responses = 0;
            pDrbgPerf->numOperations = numSessions;
            for (ses = 0; ses < numSessions; ses++)
            {
                do
                {
                    status = cpaCyDrbgGen(
                        setup->cyInstanceHandle,
                        (void *)pDrbgPerf,
                        /* data sent as is to the callback function*/
                        pOpData[ses],    /* operational data struct */
                        &pDrbgOut[ses]); /* dst buffer list */
                    if (CPA_STATUS_RETRY == status)
                    {
                        setup->performanceStats->retries++;
                        /*if the acceleration engine is busy pause for a
                         * moment by making a context switch*/
                        if (RETRY_LIMIT == (setup->performanceStats->retries %
                                            (RETRY_LIMIT + 1)))
                        {
                            AVOID_SOFTLOCKUP;
                        }
                    }
                } while (CPA_STATUS_RETRY == status);

                if (CPA_STATUS_SUCCESS != status)
                {
                    PRINT_ERR("cpaCyDrbgGen failed. (status = %d)\n", status);
                    break;
                }
                else
                {
                }
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                if (sampleCodeSemaphoreWait(&pDrbgPerf->comp,
                                            SAMPLE_CODE_WAIT_DEFAULT) !=
                    CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("timeout or interruption in cpaCyDrbgGen\n");
                    status = CPA_STATUS_FAIL;
                }
            }

        } // end of for numLoop
        sampleCodeSemaphoreDestroy(&pDrbgPerf->comp);
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    for (ses = 0; ses < numSessions; ses++)
    {
        if (pOpData[ses])
        {
            qaeMemFree((void **)&pOpData[ses]);
        }
        if (pDrbgOut[ses].pData)
        {
            qaeMemFreeNUMA((void **)&pDrbgOut[ses].pData);
        }
    }
    qaeMemFree((void **)&pOpData);
    qaeMemFree((void **)&pDrbgOut);

    return status;
}

static CpaStatus drbgSetupSession(drbg_test_params_t *setup,
                                  CpaCyDrbgSessionSetupData *pSessionSetupData,
                                  CpaCyDrbgSessionHandle *pSessionHdl,
                                  Cpa32U node)
{
    CpaCyDrbgSessionHandle sessionHdl;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionSize = 0;
    void *personalization;
    Cpa32U ses, seedLen = 0;
    Cpa32U numSessions;

    numSessions = setup->numSessions;
    /* Clear the pointer to be NULL */
    for (ses = 0; ses < numSessions; ses++)
    {
        personalization = NULL;
        pSessionSetupData[ses].personalizationString.pData = NULL;
        pSessionSetupData[ses].personalizationString.dataLenInBytes = 0;
        pSessionHdl[ses] = NULL;
    }

    for (ses = 0; ses < numSessions; ses++)
    {
        pSessionSetupData[ses].predictionResistanceRequired =
            setup->predictionResistanceRequired;
        pSessionSetupData[ses].secStrength = setup->secStrength;
        if (setup->predictionResistanceRequired == CPA_TRUE)
        {
            personalization =
                qaeMemAllocNUMA(sizeof(personalize_t), node, BYTE_ALIGNMENT_64);
            if (NULL == personalization)
            {
                PRINT("Failed to alloc memory\n");
                status = CPA_STATUS_FAIL;
                break;
            }

            memset(personalization, 0, sizeof(personalize_t));
            pSessionSetupData[ses].personalizationString.dataLenInBytes =
                sizeof(personalize_t);
            pSessionSetupData[ses].personalizationString.pData =
                personalization;
        }
        status = cpaCyDrbgSessionGetSize(
            setup->cyInstanceHandle, &pSessionSetupData[ses], &sessionSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            sessionHdl = qaeMemAllocNUMA(sessionSize, node, BYTE_ALIGNMENT_64);
            if (NULL == sessionHdl)
            {
                PRINT("Failed to create a session\n");
                qaeMemFreeNUMA((void **)&personalization);
                status = CPA_STATUS_FAIL;
                break;
            }

            pSessionHdl[ses] = sessionHdl;
            status = cpaCyDrbgInitSession(
                setup->cyInstanceHandle,
                /* callback function for generate */
                drbgPerformCallback,
                NULL,                    /* callback function for reseed */
                &pSessionSetupData[ses], /* session setup data */
                sessionHdl,
                &seedLen);
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            qaeMemFreeNUMA((void **)&personalization);
            qaeMemFreeNUMA((void **)&sessionHdl);
            break;
        }
    }
    /* Need to remove established sessions */
    if (CPA_STATUS_SUCCESS != status)
    {
        drbgRemoveSession(setup, pSessionSetupData, pSessionHdl, ses);
    }
    return (status);
}

/* Free the memory session in setup */
static CpaStatus drbgRemoveSession(drbg_test_params_t *setup,
                                   CpaCyDrbgSessionSetupData *pSessionSetupData,
                                   CpaCyDrbgSessionHandle *pSessionHdl,
                                   Cpa32U numSessions)
{
    void *personalization;
    CpaStatus status = CPA_STATUS_SUCCESS, sessionStatus;
    Cpa32U ses;

    for (ses = 0; ses < numSessions; ses++)
    {
        do
        {
            sessionStatus = cpaCyDrbgRemoveSession(setup->cyInstanceHandle,
                                                   pSessionHdl[ses]);
        } while (CPA_STATUS_RETRY == sessionStatus);

        if (pSessionHdl[ses])
        {
            qaeMemFreeNUMA((void **)&pSessionHdl[ses]);
        }
        personalization = pSessionSetupData[ses].personalizationString.pData;
        if (personalization)
        {
            qaeMemFreeNUMA((void **)&personalization);
        }
        if (CPA_STATUS_SUCCESS != sessionStatus)
        {
            status = sessionStatus;
        }
    }
    return (status);
}

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *      drbgPerform
 *
 * @description
 *     This function implements the DRBG implementation-specific
 *      'Get Entropy Input' function by calling cpaCyNrbgGetEntropy API.
 *
 *****************************************************************************/
CpaStatus drbgPerform(drbg_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS, sessionStatus;
    perf_data_t *pDrbgPerf = NULL;
    Cpa32U node = 0;
    CpaCyDrbgStats64 drbgStats = {0};
    CpaCyDrbgSessionHandle *pSessionHdl;
    CpaCyDrbgSessionSetupData *pSessionSetupData;
    Cpa32U numSessions;


    if (NULL == setup)
    {
        PRINT_ERR("Setup Pointer is NULL\n");
        return CPA_STATUS_FAIL;
    }

    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not determine node for memory allocation\n");
        return status;
    }
    if (0 == setup->lengthInBytes)
    {
        PRINT_ERR("Invalid parameter -- lengthInBytes\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (0 == setup->numLoops)
    {
        PRINT_ERR("Invalid parameter -- numLoops\n");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (0 == setup->numSessions)
    {
        PRINT_ERR("Invalid parameter -- numSessions\n");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (setup->numSessions > DRBG_MAX_SESSION_PERTHREAD)
    {
        PRINT_ERR("Invalid parameter -- numSessions must less or equal %d\n",
                  DRBG_MAX_SESSION_PERTHREAD);
        return CPA_STATUS_INVALID_PARAM;
    }
    numSessions = setup->numSessions;

    nrbgRegisterDrbgImplFunctions(setup->dFReq);

    pSessionSetupData =
        qaeMemAlloc(sizeof(CpaCyDrbgSessionSetupData) * numSessions);
    if (NULL == pSessionSetupData)
    {
        PRINT_ERR("Failed to alloc memory\n");
        return CPA_STATUS_FAIL;
    }
    memset(
        pSessionSetupData, 0, sizeof(CpaCyDrbgSessionSetupData) * numSessions);
    pSessionHdl = qaeMemAlloc(sizeof(CpaCyDrbgSessionHandle) * numSessions);
    if (NULL == pSessionHdl)
    {
        PRINT_ERR("Failed to alloc memory\n");
        qaeMemFree((void **)&pSessionSetupData);
        return CPA_STATUS_FAIL;
    }

    pDrbgPerf = setup->performanceStats;
    /*get memory location to write performance stats to*/
    memset(pDrbgPerf, 0, sizeof(perf_data_t));

    status = drbgSetupSession(setup, pSessionSetupData, pSessionHdl, node);
    if (CPA_STATUS_SUCCESS == status)
    {
        status = drbgPerformOp(setup, pSessionHdl, node);
        sessionStatus = drbgRemoveSession(
            setup, pSessionSetupData, pSessionHdl, numSessions);
        if (CPA_STATUS_SUCCESS != sessionStatus)
        {
            PRINT_ERR("DRBG remove Session Failed, status = %d\n", status);
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }
    else
    {
        sampleCodeBarrier();
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDrbgQueryStats64(setup->cyInstanceHandle, &drbgStats);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyDrbgQueryStats64 failed, status = %d\n", status);
        }
        else
        {
        }
    }
    qaeMemFree((void **)&pSessionSetupData);
    qaeMemFree((void **)&pSessionHdl);
    nrbgUnregisterDrbgImplFunctions();
    /* Need to re-write the actual operations and responses */
    pDrbgPerf->numOperations = setup->numLoops * numSessions;
    pDrbgPerf->responses = setup->numLoops * numSessions;
    pDrbgPerf->threadReturnStatus = status;
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *      drbgPerformance
 *
 * @description
 *     This function is called by the framework to execute the drbgPerform
 *     thread
 *
 *****************************************************************************/
void drbgPerformance(single_thread_test_data_t *testSetup)
{
    drbg_test_params_t drbgSetup;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    drbg_test_params_t *params = (drbg_test_params_t *)testSetup->setupPtr;

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway */
    startBarrier();
    /*give our thread a unique memory location to store performance stats */
    drbgSetup.performanceStats = testSetup->performanceStats;

    /*get the instance handles so that we can start our thread on the selected
     * instance */
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("Could not get any instances\n");
        PRINT_ERR("DRBG Thread FAILED\n");
        drbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        drbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        drbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    drbgSetup.cyInstanceHandle =
        cyInstances[(testSetup->logicalQaInstance) % numInstances];
    drbgSetup.dFReq = params->dFReq;
    drbgSetup.secStrength = params->secStrength;
    drbgSetup.predictionResistanceRequired =
        params->predictionResistanceRequired;
    drbgSetup.lengthInBytes = params->lengthInBytes;
    drbgSetup.numLoops = params->numLoops;
    drbgSetup.numSessions = params->numSessions;

    /*launch function that does all the work */
    status = drbgPerform(&drbgSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("DRBG Thread FAILED\n");
        drbgSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test */
        testSetup->statsPrintFunc = (stats_print_func_t)drbgPrintStats;
    }
    qaeMemFree((void **)&cyInstances);
    // PRINT("Thread exit...\n");
    sampleCodeThreadComplete(testSetup->threadID);
}

/**
 *****************************************************************************
 * @ingroup drbgPerformance
 *      setupDrbgTest
 *
 * @description
 *     This function setups up DRBG thread. Once called the user then calls the
 *      createThreads function which replicates this setup in threads across
 *      several cores, each using a separate acceleration engine instances
 *
 *****************************************************************************/
CpaStatus setupDrbgTest(CpaBoolean dFReq,
                        Cpa32U secStrength,
                        CpaBoolean predictionResistanceRequired,
                        Cpa32U lengthInBytes,
                        Cpa32U numSessions,
                        Cpa32U numLoops)
{
    /*setup is a multi-dimensional array that stores the setup for all thread
     * variations in an array of characters. We store our test setup at the
     * start of the second array ie index 0, [][0].
     * There may be multi thread types(setups) running as counted by
     * testTypeCount_g */

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure */
    drbg_test_params_t *drbgSetup = NULL;
    Cpa8S name[] = {'D', 'R', 'B', '\0'};

    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    /*start crypto service if not already started */
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Error starting Crypto Services\n");
        return CPA_STATUS_FAIL;
    }
    /* start polling threads if polling is enabled in the configuration file */
    if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
    {
        PRINT_ERR("Error creating polling threads\n");
        return CPA_STATUS_FAIL;
    }
    memcpy(&thread_name_g[testTypeCount_g][0], name, THREAD_NAME_LEN);

    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)drbgPerformance;
    testSetupData_g[testTypeCount_g].packetSize = lengthInBytes;

    drbgSetup = (drbg_test_params_t *)&thread_setup_g[testTypeCount_g][0];

    drbgSetup->dFReq = dFReq;
    drbgSetup->secStrength = secStrength;
    drbgSetup->predictionResistanceRequired = predictionResistanceRequired;
    drbgSetup->lengthInBytes = lengthInBytes;
    drbgSetup->numSessions = numSessions;
    drbgSetup->numLoops = numLoops;
    /* a semaphore used to control impl function register */
    sampleCodeSemaphoreInit(&semaphoreImplFunction, 1);

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupDrbgTest);
