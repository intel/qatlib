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
 * @file cpa_sample_code_ike_rsa_perf.c
 *
 * @ingroup cryptoThreads
 *
 * @description
 *      This file contains code which chains QA API functions together to
 *      simulate IKE, over all flow of data is as follows:
 *
 * 1. Alice & Bob generate public & private RSA keys
 *    we generated a third RSA key set to act as a trusted third party
 * 2. Alice & Bob agree on a p & g and generate secret random x
 * 3. Alice & Bob Perform DH Phase1 to produce Public Value - PV = g^x mod p
 * 4. Bob Perform DH Phase2 to produce Secret Key SK = alicePV^x mod p
 * 5. Sign Bobs Public Value using peers public key -> RSA decrypt bobsPV
 * 6. Setup Alices Decrypt and Diffie Hellman Data for performance Loop
 * 7. IKE main mode Asymmetric steps
 *      7a Perform DH phase1 for Alice alicePV = g^x mod p
 *      7b Perform RSA verify of third party: bobsPV = RSA encrypt bobsSig
 *      7c Perform RSA verify of Bobs signed public values (same as 7b)
 *      7d Sign all of Alices public value buffers RSA decrypt alicesPV
 *      7e Perform the DH phase2 operation for Alice
 *          SK = bobsPV(from 7b)^x mod p
 *
 *****************************************************************************/
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_utils_common.h"

/*This is the number of RSA and Diffie Hellman QA APIs chained together in
 * which performance is measured against*/
#define NUMBER_OF_CHAINED_OPS (5)
#define ONE_LOOP (1)
#define ONE_BUFFER (1)
#define NUMBER_OF_RSA_VERIFIES (2)

/* this structure is used to store data required by each client in the ike-rsa
 * transaction */
typedef struct ike_rsa_client_data_s
{
    CpaFlatBuffer **ppPublicValues;
    CpaFlatBuffer **ppSecretKeys;
    CpaCyDhPhase2SecretKeyGenOpData **ppPhase2;
    CpaCyDhPhase1KeyGenOpData **ppPhase1;
    CpaCyRsaEncryptOpData **ppEncryptOpData;
    CpaFlatBuffer **ppPVverifier;
    CpaCyRsaEncryptOpData **ppEncryptOpData2;
    CpaFlatBuffer **ppPVverifier2;
    CpaCyRsaDecryptOpData **ppDecryptOpData;
    CpaFlatBuffer **ppSignatures;
} ike_rsa_client_data_t;
/*****************************************************************************
 * @ingroup IKE_RSA Threads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * operation has been processed
 *****************************************************************************/
void ikeRsaCallback(void *pCallbackTag,
                    CpaStatus status,
                    void *pOpData,
                    CpaFlatBuffer *pOut)
{
    processCallback(pCallbackTag);
}
/*****************************************************************************
 * @ingroup IKE_RSA
 *
 * @description
 * This function is free an array of operation data structures for
 * ikersa operations, any memory allocation is freed in
 * ikeRsaPerform
 ******************************************************************************/
static void ikeRsaMemFreeRsaData(ike_rsa_client_data_t *client)
{
    if (NULL != client)
    {
        if (NULL != client->ppSignatures)
        {
            qaeMemFreeNUMA((void **)&client->ppSignatures);
        }
        if (NULL != client->ppDecryptOpData)
        {
            qaeMemFreeNUMA((void **)&client->ppDecryptOpData);
        }
        if (NULL != client->ppEncryptOpData)
        {
            qaeMemFreeNUMA((void **)&client->ppEncryptOpData);
        }
        if (NULL != client->ppPVverifier)
        {
            qaeMemFreeNUMA((void **)&client->ppPVverifier);
        }
        if (NULL != client->ppEncryptOpData2)
        {
            qaeMemFreeNUMA((void **)&client->ppEncryptOpData2);
        }
        if (NULL != client->ppPVverifier2)
        {
            qaeMemFreeNUMA((void **)&client->ppPVverifier2);
        }
    }
}
/*****************************************************************************
 * @ingroup IKE_RSA
 *
 * @description
 *      This function frees all the dynamically allocated memory used in the
 * ikeRsaPerform
 * Each pointer is checked to see if its null and if not it is free'd,
 * The underlying free function ensures that when freeing the pointer is reset
 * to NULL
 ******************************************************************************/
static void ikeRsaMemFree(asym_test_params_t *setup,
                          ike_rsa_client_data_t *alice,
                          ike_rsa_client_data_t *bob,
                          CpaCyRsaPrivateKey *pPrivateKey[],
                          CpaCyRsaPublicKey *pPublicKey[])
{
    rsaFreeDataMemory(setup,
                      alice->ppDecryptOpData,
                      alice->ppSignatures,
                      alice->ppEncryptOpData,
                      alice->ppPVverifier);
    rsaFreeKeyMemory(setup, pPrivateKey, pPublicKey);
    rsaFreeDataMemory(setup,
                      bob->ppDecryptOpData,
                      bob->ppSignatures,
                      bob->ppEncryptOpData,
                      bob->ppPVverifier);
    rsaFreeDataMemory(
        setup, NULL, NULL, bob->ppEncryptOpData2, bob->ppPVverifier2);
    rsaFreeDataMemory(
        setup, NULL, NULL, alice->ppEncryptOpData2, alice->ppPVverifier2);
    /*free the signature pointer arrays because in RSA code this is allocated
     * as a local variable*/
    ikeRsaMemFreeRsaData(alice);
    ikeRsaMemFreeRsaData(bob);
    dhMemFreePh1(setup,
                 alice->ppPhase1,
                 alice->ppPublicValues,
                 bob->ppPhase1,
                 bob->ppPublicValues);
    qaeMemFree((void **)&alice->ppPublicValues);
    qaeMemFree((void **)&bob->ppPublicValues);
    qaeMemFree((void **)&alice->ppPhase1);
    qaeMemFree((void **)&bob->ppPhase1);
    dhMemFreePh2(setup,
                 alice->ppSecretKeys,
                 alice->ppPhase2,
                 bob->ppSecretKeys,
                 bob->ppPhase2);
    qaeMemFree((void **)&alice->ppSecretKeys);
    qaeMemFree((void **)&bob->ppSecretKeys);
    qaeMemFree((void **)&alice->ppPhase2);
    qaeMemFree((void **)&bob->ppPhase2);
    if (NULL != pPrivateKey)
    {
        qaeMemFreeNUMA((void **)&pPrivateKey);
    }
    if (NULL != pPublicKey)
    {
        qaeMemFreeNUMA((void **)&pPublicKey);
    }
}

/*****************************************************************************
 * @ingroup IKE_RSA
 *
 * @description
 *      This function allocates the client memory for an IKE-RSA
 *      transaction used in ikeRsaPerform
 ******************************************************************************/
CpaStatus allocClientMem(asym_test_params_t *setup,
                         ike_rsa_client_data_t *client)
{
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppDecryptOpData,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate DecryptOpData\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppEncryptOpData,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate EncryptOpData\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppPVverifier,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppPVverifier\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppEncryptOpData2,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate EncryptOpData\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppPVverifier2,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppPVverifier\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppPhase1, setup->numBuffers))
    {
        PRINT_ERR("Could not allocate DecryptOpData\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppPhase2, setup->numBuffers))
    {
        PRINT_ERR("Could not allocate DecryptOpData\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppPublicValues,
                                 setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppPublicValues\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfVirtPointers((void **)&client->ppSecretKeys,
                                 setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppSecretKeys\n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        allocArrayOfPointers(setup->cyInstanceHandle,
                             (void **)&client->ppSignatures,
                             setup->numBuffers))
    {
        PRINT_ERR("Could not allocate ppSignatures\n");
        return CPA_STATUS_FAIL;
    }
    /*all allocation was successful if we get to here*/
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(allocClientMem);

/*****************************************************************************
 * @ingroup IKE_RSA
 *
 * @description
 *      This function sets up the QA API asymmetric functions of an IKE
 *      transaction using RSA to sign/verify DH generated keys
 ******************************************************************************/
static CpaStatus ikeRsaPerform(asym_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U innerLoop = 0;
    ike_rsa_client_data_t alice = {0};
    ike_rsa_client_data_t bob = {0};
    CpaCyRsaPrivateKey **pPrivateKey = NULL;
    CpaCyRsaPublicKey **pPublicKey = NULL;
    Cpa32U node = 0;
    Cpa32U packageId = 0;
    /*functions called in this code over writes the performanceStats->response,
     * so we use a local counter to count responses */
    Cpa32U responses = 0;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        qaeMemFree((void **)&instanceInfo2);
        return CPA_STATUS_FAIL;
    }
    packageId = instanceInfo2->physInstId.packageId;
    qaeMemFree((void **)&instanceInfo2);

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return status;
    }
    /************************************************************************/
    /* Allocate all the memory for DH and RSA operations                    */
    /************************************************************************/
    /*these macros internally free memory return fail if they fail*/
    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&pPrivateKey, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&pPublicKey, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        qaeMemFreeNUMA((void **)&pPrivateKey);
        return CPA_STATUS_FAIL;
    }

    /*Allocate for Alice*/
    if (CPA_STATUS_SUCCESS != allocClientMem(setup, &alice))
    {
        PRINT_ERR("allocClientMem error\n");
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return CPA_STATUS_FAIL;
    }
    /*Allocate for Bob*/
    if (CPA_STATUS_SUCCESS != allocClientMem(setup, &bob))
    {
        PRINT_ERR("allocClientMem error\n");
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return CPA_STATUS_FAIL;
    }
    /* *************************************************************************
     * STEP 1. Alice & Bob generate public & private RSA keys
     * ************************************************************************/
    status = genKeyArray(setup, pPrivateKey, pPublicKey);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed genKeyArray, status: %d\n", status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /**************************************************************************
     * STEP 2. Alice & Bob agree on a p & g and generate secret random x
     **************************************************************************/
    status = dhPhase1Setup(setup,
                           alice.ppPhase1,
                           bob.ppPhase1,
                           alice.ppPublicValues,
                           bob.ppPublicValues,
                           pPublicKey);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed dhPhase1Setup, status: %d\n", status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /**************************************************************************
     * STEP 3. Alice & Bob Perform DH Phase1 to produce Public Value -
     * PV = g^x mod p
     **************************************************************************/
    status = dhPhase1(alice.ppPhase1,
                      alice.ppPublicValues,
                      setup,
                      setup->numBuffers,
                      ONE_LOOP);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error, failed to complete dhPhase1 for Alice, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /**************************************************************************/
    /*Perform DH phase1 for Bob                                               */
    /**************************************************************************/
    status = dhPhase1(
        bob.ppPhase1, bob.ppPublicValues, setup, setup->numBuffers, ONE_LOOP);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to complete dhPhase1 for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }

    /**************************************************************************/
    /*Perform Phase2 setup for Bob                                            */
    /**************************************************************************/
    status = dhPhase2Setup(bob.ppSecretKeys,
                           bob.ppPhase1,
                           bob.ppPhase2,
                           alice.ppPublicValues,
                           setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to setup phase2 for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /**************************************************************************/
    /*Calculate Bobs secret keys                                            */
    /**************************************************************************/
    status = dhPhase2Perform(
        bob.ppSecretKeys, bob.ppPhase2, setup, setup->numBuffers, ONE_LOOP);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to perform phase2 for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }

    /***************************************************************************
     * STEP 5. Sign Bobs Public Value using peers public key ->
     * Bobs Signature = RSA decrypt bobsPV
     * ************************************************************************/
    /**************************************************************************/
    /*Setup the RSA decrypt structure                                         */
    /**************************************************************************/
    status = rsaDecryptDataSetup(
        bob.ppPublicValues, bob.ppDecryptOpData, bob.ppSignatures, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaDecryptDataSetup for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /**************************************************************************
     * setup encryption, we need an encryptOpData structure, because the
     * rsaSetOpDataKeys generates a public key and needs to copy it into
     * an encryptOpData structure
     **************************************************************************/
    status = rsaEncryptDataSetup(
        bob.ppSignatures, bob.ppEncryptOpData, bob.ppPVverifier, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaEncryptDataSetup for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    status = rsaEncryptDataSetup(
        bob.ppSignatures, bob.ppEncryptOpData2, bob.ppPVverifier2, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaEncryptDataSetup for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /**************************************************************************/
    /* Setup decryption opData structure with RSA key                         */
    /**************************************************************************/
    rsaSetOpDataKeys(setup,
                     bob.ppDecryptOpData,
                     bob.ppEncryptOpData,
                     pPrivateKey,
                     pPublicKey);
    rsaSetOpDataKeys(setup,
                     bob.ppDecryptOpData,
                     bob.ppEncryptOpData2,
                     pPrivateKey,
                     pPublicKey);
    /**************************************************************************/
    /* Sign all of Bobs public value buffers, but loop only once              */
    /**************************************************************************/
    status = sampleRsaDecrypt(setup,
                              bob.ppDecryptOpData,
                              bob.ppSignatures,
                              pPrivateKey,
                              pPublicKey,
                              setup->numBuffers,
                              ONE_LOOP);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed sampleRsaDecrypt for Bob, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /* Copy the RSADecrypt output into the Encrypt Op structure
     * in the performance loop we verify bobs signature. Bobs signature is
     * the input the the encrypt operation*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*check that the signature is the expected length*/
        if (bob.ppEncryptOpData[i]->inputData.dataLenInBytes !=
            bob.ppSignatures[i]->dataLenInBytes)
        {
            PRINT_ERR("encrypt data len does not match the signature len\n");
            ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
            return status;
        }
        memcpy(bob.ppEncryptOpData[i]->inputData.pData,
               bob.ppSignatures[i]->pData,
               bob.ppEncryptOpData[i]->inputData.dataLenInBytes);
        /*check that the signature is the expected length*/
        if (bob.ppEncryptOpData2[i]->inputData.dataLenInBytes !=
            bob.ppSignatures[i]->dataLenInBytes)
        {
            PRINT_ERR("encrypt data len does not match the signature len\n");
            ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
            return status;
        }
        memcpy(bob.ppEncryptOpData2[i]->inputData.pData,
               bob.ppSignatures[i]->pData,
               bob.ppEncryptOpData2[i]->inputData.dataLenInBytes);
    }
    /***************************************************************************
     * STEP 6. Setup Alices Decrypt and Diffie Hellman Data for performance Loop
     * ************************************************************************/
    /**************************************************************************/
    /* Setup the RSA decrypt structure*/
    /**************************************************************************/
    status = rsaDecryptDataSetup(
        alice.ppPublicValues, alice.ppDecryptOpData, alice.ppSignatures, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaDecryptDataSetup for Alice, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return CPA_STATUS_FAIL;
    }
    /**************************************************************************
     * Setup encryption: we need an encryptOpData structure, because the
     * rsaSetOpDataKeys generates a public key and needs to copy it into
     * an encryptOpData structure
     **************************************************************************/
    status = rsaEncryptDataSetup(
        alice.ppSignatures, alice.ppEncryptOpData, alice.ppPVverifier, setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed rsaEncryptDataSetup for Alice, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return CPA_STATUS_FAIL;
    }
    /**************************************************************************/
    /*setup decryption opData structure with RSA key                          */
    /**************************************************************************/
    rsaSetOpDataKeys(setup,
                     alice.ppDecryptOpData,
                     alice.ppEncryptOpData,
                     pPrivateKey,
                     pPublicKey);

    /**************************************************************************/
    /* Perform Phase2 setup for Alice                                         */
    /**************************************************************************/
    status = dhPhase2Setup(alice.ppSecretKeys,
                           alice.ppPhase1,
                           alice.ppPhase2,
                           bob.ppPVverifier,
                           setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to setup phase2 for Alice, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }

    /***************************************************************************
     * STEP 7 IKE main mode Asymmetric steps
     **************************************************************************/

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error, failed to allcate ppPVverifier2, status: %d\n",
                  status);
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }
    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();
    memset(setup->performanceStats, 0, sizeof(perf_data_t));
    setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();
    setup->performanceStats->packageId = packageId;
    /*pre-set the number of ops we plan to submit*/
    /*number of responses equals the number of QA APIs we have chained together
     * multiplied by the number of buffers and how many times we have looped
     * over the buffers */
    setup->performanceStats->numOperations =
        (Cpa64U)NUMBER_OF_CHAINED_OPS * setup->numBuffers * setup->numLoops;
    setup->performanceStats->averagePacketSizeInBytes =
        setup->modulusSizeInBytes;
    setup->performanceStats->responses = 0;
    /* Completion used in callback */
    sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);

    for (i = 0; i < setup->numLoops; i++)
    {
        for (innerLoop = 0; innerLoop < setup->numBuffers; innerLoop++)
        {
            /******************************************************************/
            /* Step 7a Perform DH phase1 for Alice
             * This step, performs setup->NumBuffers DH Phase1 Operations to
             * Calculate setup->numBuffers Public Values for Alice*/
            /******************************************************************/
            do
            {
                /*****************************************************************/
                /* ikeRsaCallback  : used in asynchronous mode
                 * performanceStats: Opaque user data
                 * ppPhase1        : Structure containing p, g and x
                 * ppPublicValues  : Public value (output) */
                /******************************************************************/

                status = cpaCyDhKeyGenPhase1(setup->cyInstanceHandle,
                                             NULL /*ikeRsaCallback*/,
                                             setup->performanceStats,
                                             alice.ppPhase1[innerLoop],
                                             alice.ppPublicValues[innerLoop]);

                /*this is a back off mechanism to stop the code
                 * continually submitting requests. Without this the CPU
                 * can report a soft lockup if it continually loops
                 * on busy*/
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to complete dhPhase1 for Alice, status: %d\n",
                          status);
                break;
            }
            /******************************************************************/
            /* Step 7b Perform RSA verify of third party...normally this is done
             *  on at third party to verify that bob is who he says he is, but
             *  here we are performing a second RSA encrypt on Bobs signature to
             *  test the sequence of calls                                    */
            /******************************************************************/
            do
            {
                status = cpaCyRsaEncrypt(setup->cyInstanceHandle,
                                         NULL /*ikeRsaCallback*/,
                                         setup->performanceStats,
                                         bob.ppEncryptOpData[innerLoop],
                                         bob.ppPVverifier[innerLoop]);
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed on RsaVerify for Bob using buffer=%d \n",
                          innerLoop);
                break;
            }

            /***************************************************************
             * Step 7c Perform RSA verify of Bobs signed public values.
             * Bobs Public values and Bobs RSA Signature have been
             * pre-calculated Bobs signature is in the EncryptOpData
             * structure, the verifier value should match bobsPublic value,
             * but in this code we don't check if they match
             **************************************************************/
            do
            {
                status = cpaCyRsaEncrypt(setup->cyInstanceHandle,
                                         NULL /*ikeRsaCallback*/,
                                         setup->performanceStats,
                                         bob.ppEncryptOpData2[innerLoop],
                                         bob.ppPVverifier2[innerLoop]);
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed on RsaVerify for Bob using buffer=%d \n ",
                          innerLoop);
                break;
            }

            /******************************************************************
             * Step 7d Sign all of Alices public value buffers,
             * Alices Public Value is in the Decrypt opData setup, the signature
             *  is placed in alices signature
             ******************************************************************/
            do
            {
                status = cpaCyRsaDecrypt(setup->cyInstanceHandle,
                                         NULL /*ikeRsaCallback*/,
                                         setup->performanceStats,
                                         alice.ppDecryptOpData[innerLoop],
                                         alice.ppSignatures[innerLoop]);
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to complete RsaSign for Alice, status: %d\n",
                          innerLoop);
                break;
            }
            /******************************************************************/
            /* Step 7e Perform the DH phase2 operation for Alice,
             * using Bobs verified Public values                              */

            do
            {
                status =
                    cpaCyDhKeyGenPhase2Secret(setup->cyInstanceHandle,
                                              NULL /*ikeRsaCallback*/,
                                              setup->performanceStats,
                                              alice.ppPhase2[innerLoop],
                                              alice.ppSecretKeys[innerLoop]);

                /*this is a back off mechanism to stop the code
                 * continually calling the Decrypt operation when the
                 * acceleration units are busy. Without this the CPU
                 * can report a soft lockup if it continually loops
                 * on busy*/
                if (status == CPA_STATUS_RETRY)
                {
                    setup->performanceStats->retries++;
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);

            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Diffie Hellman Phase2 for Alice, status: %d\n",
                          status);
                break;
            }
            /*At this point Bob and Alice should have created the same shared
             * secret key*/
            responses++;
        } /*end innerLoop*/
        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }

    } /*end numLoops*/
    setup->performanceStats->endCyclesTimestamp = sampleCodeTimestamp();
    /*if (CPA_STATUS_SUCCESS == status)
    {
        if(sampleCodeSemaphoreWait(&setup->performanceStats->comp,
                SAMPLE_CODE_WAIT_FOREVER) != CPA_STATUS_SUCCESS)
        {
           PRINT_ERR("interruption in ike rsa Loop\n");
           status = CPA_STATUS_FAIL;
        }
    }*/

    sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);

    if (CPA_STATUS_SUCCESS != status)
    {
        ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
        return status;
    }

    ikeRsaMemFree(setup, &alice, &bob, pPrivateKey, pPublicKey);
    /*set the total number of responses and requests. */
    setup->performanceStats->numOperations =
        (Cpa64U)responses * NUMBER_OF_CHAINED_OPS;
    setup->performanceStats->responses = responses * NUMBER_OF_CHAINED_OPS;
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/*****************************************************************************
 * @ingroup IKE_RSA
 *
 * @description
 *      This function prints the IKE-RSA performance stats
 ******************************************************************************/
CpaStatus ikeRsaPrintStats(thread_creation_data_t *data)
{
    PRINT("IKE_RSA SIMULATION\n");
    PRINT("Modulus Size %17u\n", data->packetSize);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 *@ingroup cryptoThreads
 *
 * @description
 *      This function sets up an IKE-RSA thread
 ******************************************************************************/
void ikeRsaPerformance(single_thread_test_data_t *testSetup)
{
    asym_test_params_t ikeRsaSetup;
    asym_test_params_t *setup = (asym_test_params_t *)testSetup->setupPtr;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    /* This barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*give our thread a unique memory location to store performance stats*/
    ikeRsaSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        ikeRsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        ikeRsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        ikeRsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    if (testSetup->logicalQaInstance > numInstances)
    {
        PRINT_ERR("%u is Invalid Logical QA Instance, max is: %u\n",
                  testSetup->logicalQaInstance,
                  numInstances);
        ikeRsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }
    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances*/
    ikeRsaSetup.cyInstanceHandle = cyInstances[testSetup->logicalQaInstance];
    ikeRsaSetup.modulusSizeInBytes = setup->modulusSizeInBytes;
    ikeRsaSetup.exponentSizeInBytes = setup->exponentSizeInBytes;
    ikeRsaSetup.numBuffers = setup->numBuffers;
    ikeRsaSetup.numLoops = setup->numLoops;
    ikeRsaSetup.rsaKeyRepType = setup->rsaKeyRepType;
    ikeRsaSetup.syncMode = ASYNC;
    /*launch function that does all the work*/
    status = ikeRsaPerform(&ikeRsaSetup);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("ikeRsa Thread FAILED with status: %d\n", status);
        ikeRsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    else
    {
        /*set the print function that can be used to print stats at the end of
         * the test*/
        testSetup->statsPrintFunc = (stats_print_func_t)ikeRsaPrintStats;
    }
    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}

/*****************************************************************************
 *@ingroup cryptoThreads
 *
 * @description
 *      This function needs to be called first to setup an IKE test.
 * Then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupIkeRsaTest(Cpa32U modSizeInBits,
                          Cpa32U expSizeInBits,
                          Cpa32U numBuffs,
                          Cpa32U numLoops)
{
    /*thread_setup_g is a multi-dimensional array that stores the setup for all
     * thread variations in an array of characters. we store our test setup at
     * the start of the second array ie index 0. There maybe multi thread types
     * (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * asymmetric structure*/
    asym_test_params_t *ikeRsaSetup = NULL;

    if (MAX_THREAD_VARIATION <= testTypeCount_g)
    {
        PRINT_ERR("Maximum Supported Thread Variation has been exceeded\n");
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
    /* start polling threads if polling is enabled in the configuration file */
    if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
    {
        PRINT_ERR("Error creating polling threads\n");
        return CPA_STATUS_FAIL;
    }
    if (MAX_SETUP_STRUCT_SIZE_IN_BYTES <= sizeof(asym_test_params_t))
    {
        PRINT_ERR("Test structure is to big for framework\n");
        PRINT_ERR("Size needed: %u, limit %u\n",
                  (Cpa32U)sizeof(asym_test_params_t),
                  (Cpa32U)MAX_SETUP_STRUCT_SIZE_IN_BYTES);
        return CPA_STATUS_FAIL;
    }
    /*get the pre-allocated memory allocation to store the setup for IKE test*/
    ikeRsaSetup = (asym_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)ikeRsaPerformance;
    testSetupData_g[testTypeCount_g].packetSize = modSizeInBits;
    ikeRsaSetup->modulusSizeInBytes = modSizeInBits / NUM_BITS_IN_BYTE;
    ikeRsaSetup->exponentSizeInBytes = expSizeInBits / NUM_BITS_IN_BYTE;
    ikeRsaSetup->numBuffers = numBuffs;
    ikeRsaSetup->numLoops = numLoops;
    ikeRsaSetup->rsaKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setupIkeRsaTest);
