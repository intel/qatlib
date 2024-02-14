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
 * @file cpa_sample_code_sm2_perf.c
 *
 * @ingroup cryptoThreads
 *
 * @description
 *      This file contains the sm2 performance code.
 *      This file setup Sign, Verify, Encryption, Decryption, Key Exchange P1/P2
 *      More details about the algorithm is in
 *      http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *****************************************************************************/

#include "cpa_sample_code_sm2_perf.h"

extern int
    latency_single_buffer_mode; /* set to 1 for single buffer processing */

extern Cpa32U packageIdCount_g;

/**
 ******************************************************************************
 * SM2 performance test data setup function
 *     This function will be called in sm2Performance() function, before the
 * performance testing thread started. It setup the random data for the testing
 * according to the setup->step.
 * e.g. If run sm2 decryption performance test, this function will generate a
 * random private key and calculate the public key, then generate random
 * messages and call sm2Enc() to encrypt the random message to get the data
 * that decryption needs.
 *
 ******************************************************************************/
static CpaStatus sm2PerfDataSetup(sm2_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U node = 0;
    Cpa32U i = 0;
    CpaCyEcsm2GeneratorMultiplyOpData privateKey = {{0}};
    CpaCyEcsm2SignOpData signOp = {{0}};
    CpaCyEcsm2KeyExPhase1OpData keyexOp = {{0}};
    CpaCyEcsm2KeyExOutputData keyexOutput = {{0}};
    CpaBoolean sm2Status = CPA_FALSE;
    CpaFlatBuffer signOutput_r = {0};
    CpaFlatBuffer signOutput_s = {0};
    CpaFlatBuffer pubKey_x = {0};
    CpaFlatBuffer pubKey_y = {0};

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }
    /* Allocate memory for common data,
     * private key(d, d2, d2 is set for key exchange) and public key(xP,yP)*/
    setup->d = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    setup->d2 = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    setup->xP = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    setup->yP = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);

    if (NULL == setup->d || NULL == setup->d2 || NULL == setup->xP ||
        NULL == setup->yP)
    {
        PRINT_ERR("key memory allocation error\n");
        goto cleanup;
    }

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         setup->d,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_FLAT_MEM_FREE());
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         setup->d2,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_FLAT_MEM_FREE());
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         setup->xP,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_FLAT_MEM_FREE());
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         setup->yP,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_FLAT_MEM_FREE());

    /* alloc memory for random message for encryption */
    setup->message = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    if (NULL == setup->message)
    {
        PRINT_ERR("key memory allocation error\n");
        goto cleanup;
    }

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         setup->message,
                         MESSAGE_LEN,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_FLAT_MEM_FREE());

    generateRandomData(setup->d->pData, setup->d->dataLenInBytes);
    /* For parameters being passed to Large Number API, the MSB must be 1 */
    setup->d->pData[0] = 0x01;

    generateRandomData(setup->d2->pData, setup->d2->dataLenInBytes);
    /* For parameters being passed to Large Number API, the MSB must be 1 */
    setup->d2->pData[0] = 0x01;

    generateRandomData(setup->message->pData, setup->message->dataLenInBytes);

    /* calculate public key via d */
    privateKey.k.dataLenInBytes = setup->d->dataLenInBytes;
    privateKey.k.pData = setup->d->pData;
    privateKey.fieldType = setup->fieldType;

    pubKey_x.dataLenInBytes = setup->xP->dataLenInBytes;
    pubKey_x.pData = setup->xP->pData;
    pubKey_y.dataLenInBytes = setup->yP->dataLenInBytes;
    pubKey_y.pData = setup->yP->pData;

    /* call the driver API in synchronous mode */
    status = cpaCyEcsm2GeneratorMultiply(
        setup->cyInstanceHandle,
        NULL, /* Sync mode*/
        NULL,
        &privateKey, /* Generator multiplication request data */
        &sm2Status,  /* Multiply status */
        &pubKey_x,   /* Generator multiplication response data */
        &pubKey_y);  /* Generator multiplication response data */

    if (CPA_STATUS_SUCCESS != status)
    {
        /* Not a success; could be a retry, a fail, an invalid param or
         * a resource issue */
        PRINT_ERR("Generate public key failed (status = %d)\n", status);
        goto cleanup;
    }
    /* Allocate memory for random digests for signature */
    setup->digest = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
    if (NULL == setup->digest)
    {
        PRINT_ERR("digest mem allocation error\n");
        goto cleanup;
    }
    for (i = 0; i < setup->numBuffers; i++)
    {
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &setup->digest[i],
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        generateRandomData(setup->digest[i].pData,
                           setup->digest[i].dataLenInBytes);

        /* For parameters being passed to Large Number API, the MSB must be 1 */
        setup->digest[i].pData[0] = 0x01;
    }
    /* Allocate memory for random numbers */
    setup->random = (CpaFlatBuffer *)qaeMemAllocNUMA(
        sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
    if (NULL == setup->random)
    {
        PRINT_ERR("random number mem allocation error\n");
        goto cleanup;
    }

    for (i = 0; i < setup->numBuffers; i++)
    {
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &setup->random[i],
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        generateRandomData(setup->random[i].pData,
                           setup->random[i].dataLenInBytes);

        /* For parameters being passed to Large Number API, the MSB must be 1 */
        setup->random[i].pData[0] = 0x01;
    }
    /* If running SM2 signature verify , we need to generate correct signature
     * data, using cyEcsm2Sign API to sign random digest, store the result in
     * the setup->verifOp */
    if (setup->step == SM2_STEP_VERIFY)
    {
        /* Allocate memory for setup->verifOp */
        status = allocArrayOfPointers(setup->cyInstanceHandle,
                                      (void **)&setup->verifyOp,
                                      setup->numBuffers);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("setup->verifyOp mem allocation error\n");
            goto cleanup;
        }

        for (i = 0; i < setup->numBuffers; i++)
        {
            setup->verifyOp[i] = qaeMemAlloc(sizeof(CpaCyEcsm2VerifyOpData));
            if (NULL == setup->verifyOp[i])
            {
                PRINT_ERR("setup->verifyOp[%u] memory allocation error\n", i);
                goto cleanup;
            }
            memset(setup->verifyOp[i], 0, sizeof(CpaCyEcsm2VerifyOpData));

            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->verifyOp[i]->e,
                                 setup->nLenInBytes,
                                 setup->digest[i].pData,
                                 setup->digest[i].dataLenInBytes,
                                 SM2_PERFORM_SETUP_VERIFY_MEM_FREE());
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->verifyOp[i]->xP,
                                 setup->nLenInBytes,
                                 setup->xP->pData,
                                 setup->xP->dataLenInBytes,
                                 SM2_PERFORM_SETUP_VERIFY_MEM_FREE());
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->verifyOp[i]->yP,
                                 setup->nLenInBytes,
                                 setup->yP->pData,
                                 setup->yP->dataLenInBytes,
                                 SM2_PERFORM_SETUP_VERIFY_MEM_FREE());
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->verifyOp[i]->r,
                                 setup->nLenInBytes,
                                 NULL,
                                 0,
                                 SM2_PERFORM_SETUP_VERIFY_MEM_FREE());
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->verifyOp[i]->s,
                                 setup->nLenInBytes,
                                 NULL,
                                 0,
                                 SM2_PERFORM_SETUP_VERIFY_MEM_FREE());

            /* fill input and output structure */
            signOp.k.dataLenInBytes = setup->random[i].dataLenInBytes;
            signOp.k.pData = setup->random[i].pData;
            signOp.e.dataLenInBytes = setup->digest[i].dataLenInBytes;
            signOp.e.pData = setup->digest[i].pData;
            signOp.d.dataLenInBytes = setup->d->dataLenInBytes;
            signOp.d.pData = setup->d->pData;
            signOp.fieldType = setup->fieldType;

            signOutput_r.dataLenInBytes = setup->verifyOp[i]->r.dataLenInBytes;
            signOutput_r.pData = setup->verifyOp[i]->r.pData;
            signOutput_s.dataLenInBytes = setup->verifyOp[i]->s.dataLenInBytes;
            signOutput_s.pData = setup->verifyOp[i]->s.pData;
            /* call the driver API to sign the random digest */
            do
            {
                status = cpaCyEcsm2Sign(
                    setup->cyInstanceHandle,
                    NULL, /* Sync mode*/
                    NULL,
                    &signOp,    /* Structure containing k, d and e */
                    &sm2Status, /* signStatus indicates if the result is valid
                                 */
                    &signOutput_r,  /* Signature r, s (function output) */
                    &signOutput_s); /* Signature r, s (function output) */
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                /* Not a success; could be a retry, a fail, an invalid param or
                 * a resourse issue */
                PRINT_ERR("cpaCyEcsm2Sign() not a success. (status = %d)\n",
                          status);
                goto cleanup;
            }
        }
    }
    /* if running SM2 decryption performance test, we need to generate correct
     * ciphers using cyEcsm2Enc API to encryption the random message ,
     * store the results in setup->cipher */
    if (setup->step == SM2_STEP_DEC)
    {

        setup->cipher = (CpaFlatBuffer *)qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
        if (NULL == setup->cipher)
        {
            PRINT_ERR("cipher memory allocation error\n");
            goto cleanup;
        }
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             setup->cipher,
                             CIPHER_LEN,
                             NULL,
                             0,
                             SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        /* sm2 encryption operation, encrypt the random messages to get the
         * ciphers that decryption needs */
        status = sm2Enc(setup);
    }

    /* if running SM2 key exchange phase2 , we need prepare the correct data
     * that generated by key exchange phase 1 */
    if (setup->step == SM2_STEP_KEYEX_P2)
    {

        setup->x1 = (CpaFlatBuffer *)qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == setup->x1)
        {
            PRINT_ERR("random number mem allocation error\n");
            goto cleanup;
        }

        for (i = 0; i < setup->numBuffers; i++)
        {
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->x1[i],
                                 setup->nLenInBytes,
                                 NULL,
                                 0,
                                 SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        }

        setup->y1 = (CpaFlatBuffer *)qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == setup->y1)
        {
            PRINT_ERR("random number mem allocation error\n");
            goto cleanup;
        }
        for (i = 0; i < setup->numBuffers; i++)
        {
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->y1[i],
                                 setup->nLenInBytes,
                                 NULL,
                                 0,
                                 SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        }

        setup->x2 = (CpaFlatBuffer *)qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == setup->x2)
        {
            PRINT_ERR("random number mem allocation error\n");
            goto cleanup;
        }

        for (i = 0; i < setup->numBuffers; i++)
        {
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->x2[i],
                                 setup->nLenInBytes,
                                 NULL,
                                 0,
                                 SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        }

        setup->y2 = (CpaFlatBuffer *)qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * setup->numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == setup->y2)
        {
            PRINT_ERR("random number mem allocation error\n");
            goto cleanup;
        }

        for (i = 0; i < setup->numBuffers; i++)
        {
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &setup->y2[i],
                                 setup->nLenInBytes,
                                 NULL,
                                 0,
                                 SM2_PERFORM_SETUP_FLAT_MEM_FREE());
        }
        /* key exchange need two sides , both sides generate a SM2 EC point
         * and exchange it with each other then any side will generate the
         * secret key using the two points(both generated by key exchange
         * phase1, one is his own and one is from the other side.) so here we
         * need to calculate 2 key exchange phase 1,
         * using different random parameters */
        for (i = 0; i < setup->numBuffers; i++)
        {
            /* fill the input and output structure for key exchange phase 1*/
            keyexOp.r.dataLenInBytes = setup->random[i].dataLenInBytes;
            keyexOp.r.pData = setup->random[i].pData;
            keyexOp.fieldType = setup->fieldType;
            keyexOutput.x.dataLenInBytes = setup->x1[i].dataLenInBytes;
            keyexOutput.x.pData = setup->x1[i].pData;
            keyexOutput.y.dataLenInBytes = setup->y1[i].dataLenInBytes;
            keyexOutput.y.pData = setup->y1[i].pData;
            status = cpaCyEcsm2KeyExPhase1(
                setup->cyInstanceHandle,
                NULL, /* Sync mode */
                NULL,
                &keyexOp, /* Key exchange p1 request data */
                &keyexOutput /* Key exchange p1 response data */);

            /* fill the input and output structure for key exchange phase 1
             * using the random value in inverse order */
            keyexOp.r.dataLenInBytes =
                setup->random[setup->numBuffers - i - 1].dataLenInBytes;

            keyexOp.r.pData = setup->random[setup->numBuffers - i - 1].pData;
            keyexOp.fieldType = setup->fieldType;
            keyexOutput.x.dataLenInBytes = setup->x2[i].dataLenInBytes;
            keyexOutput.x.pData = setup->x2[i].pData;
            keyexOutput.y.dataLenInBytes = setup->y2[i].dataLenInBytes;
            keyexOutput.y.pData = setup->y2[i].pData;
            do
            {
                status = cpaCyEcsm2KeyExPhase1(
                    setup->cyInstanceHandle,
                    NULL, /* Sync mode*/
                    NULL,
                    &keyexOp, /* Key exchange p1 request data */
                    &keyexOutput /* Key exchange p1 response data */);
            } while (CPA_STATUS_RETRY == status);
        }
    }
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (setup->verifyOp != NULL)
        SM2_PERFORM_SETUP_VERIFY_MEM_FREE();
    return CPA_STATUS_FAIL;
}

#ifndef NEWDISPLAY
/**
 ***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Print the performance stats of the SM2 operations according to the step
 ***************************************************************************/
static CpaStatus sm2PrintStats(thread_creation_data_t *data)
{
    sm2_test_params_t *params = (sm2_test_params_t *)data->setupPtr;
    switch (params->step)
    {
        case (SM2_STEP_SIGN):
            PRINT("SM2 SIGN \n");
            break;
        case (SM2_STEP_VERIFY):
            PRINT("SM2 VERIFY\n");
            break;
        case (SM2_STEP_ENC):
            PRINT("SM2 ENCRYPT\n");
            break;
        case (SM2_STEP_DEC):
            PRINT("SM2 DECRYPT\n");
            break;
        case (SM2_STEP_KEYEX_P1):
            PRINT("SM2 KEY EXCHANGE P1\n");
            break;
        case (SM2_STEP_KEYEX_P2):
            PRINT("SM2 KEY EXCHANGE P2\n");
            break;
    }
    PRINT("SM2 Size %23u\n", data->packetSize);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      setup a SM2 performance thread
 **************************************************************************/
void sm2Performance(single_thread_test_data_t *testSetup)
{
    sm2_test_params_t sm2Setup = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    sm2_test_params_t *params = (sm2_test_params_t *)testSetup->setupPtr;
    CpaInstanceInfo2 instanceInfo = {0};
    CpaDeviceInfo deviceInfo = {0};
    CpaCyCapabilitiesInfo capInfo = {0};
    testSetup->passCriteria = getPassCriteria();


    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call
     * startThreads anyway*/
    startBarrier();
    /*set the print function that can be used to print stats at the end of
     * the test*/
    testSetup->statsPrintFunc = (stats_print_func_t)sm2PrintStats;
    /*give our thread a unique memory location to store performance stats*/
    sm2Setup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (cyInstances == NULL)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }

    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances*/
    sm2Setup.cyInstanceHandle =
        cyInstances[(testSetup->logicalQaInstance) % numInstances];
    status = cpaCyInstanceGetInfo2(sm2Setup.cyInstanceHandle, &instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 failed\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    /* check whether asym service enabled or not for the instance */
    status = cpaGetDeviceInfo(instanceInfo.physInstId.packageId, &deviceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaGetDeviceInfo failed\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (CPA_FALSE == deviceInfo.cyAsymEnabled)
    {
        PRINT_ERR("Error! cyAsymEnabled service not enabled for the "
                  "configured instance\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    /* check if SM2 is supported for the instance */
    if (CPA_STATUS_SUCCESS !=
        cpaCyQueryCapabilities(sm2Setup.cyInstanceHandle, &capInfo))
    {
        PRINT_ERR("cpaCyQueryCapabilities failed\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (!capInfo.ecSm2Supported)
    {
        PRINT_ERR("SM2 is Unsupported on Device\n");
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (instanceInfo.physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo.physInstId.packageId;
    }

    sm2Setup.nLenInBytes = params->nLenInBytes;
    sm2Setup.fieldType = params->fieldType;
    sm2Setup.numBuffers = params->numBuffers;
    sm2Setup.numLoops = params->numLoops;
    sm2Setup.syncMode = params->syncMode;
    sm2Setup.step = params->step;
    /* according to the sm2Setup->step, this function will generate the correct
     * random data for the performance test */
    sm2PerfDataSetup(&sm2Setup);
    /* Launch function that does all the work */
    switch (params->step)
    {
        case SM2_STEP_SIGN:
            status = sm2SignPerform(&sm2Setup);
            break;
        case SM2_STEP_VERIFY:
            status = sm2VerifyPerform(&sm2Setup);
            break;
        case SM2_STEP_ENC:
            status = sm2EncPerform(&sm2Setup);
            break;
        case SM2_STEP_DEC:
            status = sm2DecPerform(&sm2Setup);
            break;
        case SM2_STEP_KEYEX_P1:
            status = sm2KeyexP1Perform(&sm2Setup);
            break;
        case SM2_STEP_KEYEX_P2:
            status = sm2KeyexP2Perform(&sm2Setup);
            break;
        default:
            PRINT_ERR("Function not supported for step %d\n", params->step);
            status = CPA_STATUS_FAIL;
            break;
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("SM2 Thread %u FAILED\n", testSetup->logicalQaInstance);
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        sm2Setup.performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
    }
exit:
    if (cyInstances != NULL)
    {
        qaeMemFree((void **)&cyInstances);
    }
    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(sm2Performance);

/**
 ***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      This function is used to set the parameters to be used in the SM2
 *       performance thread. It is called before the createThreads
 *      function of the framework. The framework replicates it across many
 *      cores
 ***************************************************************************/
CpaStatus setupSm2Test(Cpa32U nLenInBits,
                       CpaCyEcFieldType fieldType,
                       sync_mode_t syncMode,
                       sm2_step_t step,
                       Cpa32U numBuffers,
                       Cpa32U numLoops)
{
    /* testSetupData_g is a multi-dimensional array that stores the setup for
     * all thread variations in an array of characters. we store our test setup
     * at the start of the second array ie index 0. There maybe multi-thread
     * types (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure*/
    sm2_test_params_t *sm2Setup = NULL;
    Cpa8S name[] = {'S', 'M', '2', '\0'};
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }
    /*start crypto service if not already started*/
    if (CPA_STATUS_SUCCESS != startCyServices())
    {
        PRINT_ERR("Error starting Crypto Services\n");
        return CPA_STATUS_FAIL;
    }
    if (iaCycleCount_g)
    {
#ifdef POLL_INLINE
        enablePollInline();
#endif
        timeStampTime_g = getTimeStampTime();
        PRINT("timeStampTime_g %llu\n", timeStampTime_g);
    }
    if (!poll_inline_g)
    {
        /* start polling threads if polling is enabled in the configuration
         * file */
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }
    memcpy(&thread_name_g[testTypeCount_g][0], name, THREAD_NAME_LEN);
    sm2Setup = (sm2_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)sm2Performance;
    /* If nLenInBits is not an even number of bytes then round up
     * sm2Setup->nLenInBytes*/
    sm2Setup->nLenInBytes =
        (nLenInBits + NUM_BITS_IN_BYTE - 1) / NUM_BITS_IN_BYTE;
    testSetupData_g[testTypeCount_g].packetSize = sm2Setup->nLenInBytes;
    sm2Setup->fieldType = fieldType;
    sm2Setup->syncMode = syncMode;
    sm2Setup->numBuffers = numBuffers;
    sm2Setup->numLoops = numLoops;
    sm2Setup->step = step;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupSm2Test);

