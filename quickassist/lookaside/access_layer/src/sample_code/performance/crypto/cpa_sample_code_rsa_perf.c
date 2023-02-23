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
 * @file cpa_sample_code_rsa_perf.c
 *
 * @defgroup sampleRSACode RSA 1024, 2048, 4096 bit Decrypt CRT
 *              Performance code
 *
 * @ingroup sampleRSACode
 *
 * @description
 *      This is a sample code that uses RSA APIs.
 *       Functions contained in this file:
 *        - rsaCallback
 *        - ALLOC_FLAT_BUFF_DATA
 *        - FREE_GENERATE_RSA_KEY_MEM
 *        - generateRSAKey
 *        - FREE_GEN_KEY_ARRAY_MEM
 *        - genKeyArray
 *        - rsaSetOpDataKeys
 *        - FREE_RSA_ENCRYPT_DATA_SETUP_MEM
 *        - rsaEncryptDataSetup
 *        - FREE_RSA_DECRYPT_DATA_SETUP_MEM
 *        - rsaDecryptDataSetup
 *        - rsaFreeDataMemory
 *        - rsaFreeKeyMemory
 *        - sampleRsaEncrypt
 *        - sampleRsaDcrypt
 *        - sampleRsaPerform
 *        - sampleRsaThreadSetup
 *        - printRsaPerfData
 *        - setupRsaTest
 *
 *      This code preallocates a number of buffers as defined by
 *      setup->numBuffers. The preallocated buffers are then
 *      continuously looped until setup->numLoops is met.
 *      Time stamping is started prior to the first performed RSA Decrypt
 *      Operation and is stopped when all callbacks have returned.
 *      The code is called for each packet size as defined in cpaPerformance
 *
 *****************************************************************************/
#include "cpa.h"
#include "cpa_cy_common.h"
#include "cpa_cy_rsa.h"
#include "cpa_sample_code_crypto_utils.h"
#include "icp_sal_poll.h"
#include "qat_perf_sleeptime.h"
#ifdef SC_DEV_INFO_ENABLED
#include "cpa_dev.h"
#endif
#include "qat_perf_cycles.h"
#include "cpa_sample_code_framework.h"
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
#include "cpa_sample_code_rsa_kpt2_perf.h"
#endif
#endif
#endif
/*
******************************************************************************
* macros
******************************************************************************
*/
#define NUM_KEY_PAIRS (2)
#define NUM_RSA_KEYGEN_RETRIES (1000)

#ifdef POLL_INLINE
Cpa32U asymPollingInterval_g = 0;
EXPORT_SYMBOL(asymPollingInterval_g);
#endif

#ifdef LATENCY_CODE
extern int
    latency_single_buffer_mode; /* set to 1 for single buffer processing */
#endif

/*we use public exponent e = 65537. The NIST Special Publication on Computer
 * Security (SP 800-78 Rev 1 of August 2007) does not allow public exponents e
 * smaller than 65537.
 *
 * This value can be regarded as a compromise between avoiding potential small
 * exponent attacks and still allowing efficient encryptions
 * (or signature verification).*/
Cpa8U rsaPublicExponent_g[] = {0x01, 0x00, 0x01};
// Cpa8U rsaPublicExponent_g[] = {0x03};
// Cpa8U rsaPublicExponent_g[] = {0x11};
extern Cpa32U packageIdCount_g;


/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Callback for RSA KeyGen operations, we declare function signature as per the
 *  API but we only use the pCallbackTag parameter
 * ****************************************************************************/
void rsaKeyGenCallback(void *pCallbackTag,
                       CpaStatus status,
                       void *pKeyGenOpData,
                       CpaCyRsaPrivateKey *pPrivateKey,
                       CpaCyRsaPublicKey *pPublicKey)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;

    /*check perf_data pointer is valid*/
    if (pPerfData == NULL)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    /* response has been received */
    pPerfData->responses++;
    /*if we have received the pre-set numOperations, then get the clock cycle
     * as a timestamp and post the Semaphore to release parent thread*/

    if (pPerfData->numOperations == pPerfData->responses)
    {
        /*let calling thread know that we are done*/
        sampleCodeSemaphorePost(&pPerfData->comp);
    }
}

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Callback for RSA operations, we declare function signature as per the API
 * but we only use the pCallbackTag parameter
 * ****************************************************************************/
void rsaCallback(void *pCallbackTag,
                 CpaStatus status,
                 void *pOpdata,
                 CpaFlatBuffer *pOut)
{
    processCallback(pCallbackTag);
}

#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Callback for KPT2 RSA operations
 * ****************************************************************************/
void kpt2RsaCallback(void *pCallbackTag,
                     CpaStatus status,
                     void *pOpdata,
                     CpaFlatBuffer *pOut)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    if (CPA_STATUS_SUCCESS != status)
    {
        pPerfData->threadReturnStatus = status;
        PRINT_ERR("kpt2RsaCallback failed with status %d\n", status);
    }
    if (CPA_STATUS_FAIL == status)
    {
        PRINT_ERR("KPT RSA Decrypt failed!\n");
    }

    processCallback(pCallbackTag);
}
EXPORT_SYMBOL(kpt2RsaCallback);
#endif
#endif

#ifdef POLL_INLINE
CpaStatus setAsymPollingInterval(Cpa64U pollingInterval)
{
    asymPollingInterval_g = pollingInterval;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setAsymPollingInterval);
#endif

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Frees any memory allocated by the generateRSAKey function
 * qaeMemFreeNUMA first checks to see if any memory is allocated before
 * attempting to free
 ******************************************************************************/
#define FREE_GENERATE_RSA_KEY_MEM()                                            \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&pPublicKey->modulusN.pData);                  \
        qaeMemFreeNUMA((void **)&pPublicKey->publicExponentE.pData);           \
        qaeMemFreeNUMA((void **)&pPrivateKey->privateKeyRep1.modulusN.pData);  \
        qaeMemFreeNUMA(                                                        \
            (void **)&pPrivateKey->privateKeyRep1.privateExponentD.pData);     \
        qaeMemFreeNUMA((void **)&pPrivateKey->privateKeyRep2.prime1P.pData);   \
        qaeMemFreeNUMA((void **)&pPrivateKey->privateKeyRep2.prime2Q.pData);   \
        qaeMemFreeNUMA(                                                        \
            (void **)&pPrivateKey->privateKeyRep2.exponent2Dq.pData);          \
        qaeMemFreeNUMA(                                                        \
            (void **)&pPrivateKey->privateKeyRep2.exponent1Dp.pData);          \
        qaeMemFreeNUMA(                                                        \
            (void **)&pPrivateKey->privateKeyRep2.coefficientQInv.pData);      \
    } while (0)

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * This function generates RSA keys from a given modulus length
 ******************************************************************************/
CpaStatus generateRSAKey(CpaInstanceHandle instanceHandle,
                         Cpa32U modulusLenInBytes,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey,
                         asym_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyRsaKeyGenOpData keyGenOpData;
    Cpa32U kSize = 0;
    Cpa32U retry = 0;
    perf_data_t *pPerfData = setup->performanceStats;
    CpaCyRsaKeyGenCbFunc rsaKeyGenCb = NULL;
#ifdef POLL_INLINE
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));
#endif


    if (SYNC == setup->syncMode)
    {
        rsaKeyGenCb = NULL;
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
        rsaKeyGenCb = rsaKeyGenCallback;
    }
#endif

    /*allocate the public key modulus*/
    ALLOC_FLAT_BUFF_DATA(instanceHandle,
                         &(pPublicKey->modulusN),
                         modulusLenInBytes,
                         NULL,
                         0,
                         FREE_GENERATE_RSA_KEY_MEM());
    /*allocate and set the public exponent (e)*/
    ALLOC_FLAT_BUFF_DATA(instanceHandle,
                         &(pPublicKey->publicExponentE),
                         sizeof(rsaPublicExponent_g),
                         rsaPublicExponent_g,
                         sizeof(rsaPublicExponent_g),
                         FREE_GENERATE_RSA_KEY_MEM());
    /*setup private key data*/
    /*if key type is CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 then kSize is the size of
     * the modulus, otherwise its half the modulus size */
    if (pPrivateKey->privateKeyRepType == CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1)
    {
        kSize = modulusLenInBytes;
        /*allocate space for the key data modulusN*/
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep1.modulusN),
                             modulusLenInBytes,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());
        /*allocate space for the key data privateExponentD*/
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep1.privateExponentD),
                             modulusLenInBytes,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());
    }
    else
    {
        /*allocate space for the key data modulusN*/
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep1.modulusN),
                             modulusLenInBytes,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());
        /*allocate space for the key data privateExponentD*/
        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep1.privateExponentD),
                             modulusLenInBytes,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());
        kSize = modulusLenInBytes / NUM_KEY_PAIRS;
        /*allocate space for all the type2 key parameters
         * all allocated memory is freed in sampleRSAperform*/

        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep2.exponent2Dq),
                             kSize,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());

        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep2.exponent1Dp),
                             kSize,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());

        ALLOC_FLAT_BUFF_DATA(instanceHandle,
                             &(pPrivateKey->privateKeyRep2.coefficientQInv),
                             kSize,
                             NULL,
                             0,
                             FREE_GENERATE_RSA_KEY_MEM());
    }
    ALLOC_FLAT_BUFF_DATA(instanceHandle,
                         &(pPrivateKey->privateKeyRep2.prime1P),
                         modulusLenInBytes / NUM_KEY_PAIRS,
                         NULL,
                         0,
                         FREE_GENERATE_RSA_KEY_MEM());

    if (useStaticPrime == 1)
    {
        status = generateHardCodedPrime1P(
            &(pPrivateKey->privateKeyRep2.prime1P), setup);
    }
    else
    {
        status = generatePrime(
            &(pPrivateKey->privateKeyRep2.prime1P), instanceHandle, setup);
    }

    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT("Error could not generate privateKeyRep2.prime1P");
        FREE_GENERATE_RSA_KEY_MEM();
        status = CPA_STATUS_FAIL;
        goto exit;
    }

    ALLOC_FLAT_BUFF_DATA(instanceHandle,
                         &(pPrivateKey->privateKeyRep2.prime2Q),
                         modulusLenInBytes / NUM_KEY_PAIRS,
                         NULL,
                         0,
                         FREE_GENERATE_RSA_KEY_MEM());
    if (useStaticPrime == 1)
    {
        status = generateHardCodedPrime2Q(
            &(pPrivateKey->privateKeyRep2.prime2Q), setup);
    }
    else
    {
        status = generatePrime(
            &(pPrivateKey->privateKeyRep2.prime2Q), instanceHandle, setup);
    }
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT("Error could not generate privateKeyRep2.prime2Q");
        FREE_GENERATE_RSA_KEY_MEM();
        status = CPA_STATUS_FAIL;
        goto exit;
    }

    /*set the keyGen operation data*/
    keyGenOpData.privateKeyRepType = pPrivateKey->privateKeyRepType;
    keyGenOpData.version = pPrivateKey->version;
    keyGenOpData.modulusLenInBytes = modulusLenInBytes;
    keyGenOpData.prime1P = pPrivateKey->privateKeyRep2.prime1P;
    keyGenOpData.prime2Q = pPrivateKey->privateKeyRep2.prime2Q;
    keyGenOpData.publicExponentE = pPublicKey->publicExponentE;
    /*generate the public and private RSA keys*/
    pPerfData->responses = 0;
    pPerfData->numOperations = SINGLE_OPERATION;

    sampleCodeSemaphoreInit(&pPerfData->comp, 0);
        for (retry = 0; retry < NUM_RSA_KEYGEN_RETRIES; retry++)
        {
            status = cpaCyRsaGenKey(instanceHandle,
                                    rsaKeyGenCb,
                                    pPerfData,
                                    &keyGenOpData,
                                    pPrivateKey,
                                    pPublicKey);
            if ((status == CPA_STATUS_SUCCESS) &&
                (0 !=
                 memcmp(pPrivateKey->privateKeyRep2.prime1P.pData,
                        pPrivateKey->privateKeyRep2.prime2Q.pData,
                        pPrivateKey->privateKeyRep2.prime1P.dataLenInBytes)))
            {
                break;
            }
            if (!useStaticPrime)
            {
                /*could fail due to invalid e,p,q combination, so re-generate
                 * p,q and try again*/
                if (generatePrime(&(pPrivateKey->privateKeyRep2.prime1P),
                                  instanceHandle,
                                  setup) != CPA_STATUS_SUCCESS)
                {
                    PRINT("Error could not generate privateKeyRep2.prime1P");
                    FREE_GENERATE_RSA_KEY_MEM();
                    sampleCodeSemaphoreDestroy(&pPerfData->comp);
                    status = CPA_STATUS_FAIL;
                    goto exit;
                }
                if (generatePrime(&(pPrivateKey->privateKeyRep2.prime2Q),
                                  instanceHandle,
                                  setup) != CPA_STATUS_SUCCESS)
                {
                    PRINT("Error could not generate privateKeyRep2.prime2Q");
                    FREE_GENERATE_RSA_KEY_MEM();
                    sampleCodeSemaphoreDestroy(&pPerfData->comp);
                    status = CPA_STATUS_FAIL;
                    goto exit;
                }
                keyGenOpData.prime1P = pPrivateKey->privateKeyRep2.prime1P;
                keyGenOpData.prime2Q = pPrivateKey->privateKeyRep2.prime2Q;
            }
        }
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to generate RSA key, status: %d\n", status);
        FREE_GENERATE_RSA_KEY_MEM();
        sampleCodeSemaphoreDestroy(&pPerfData->comp);
        status = CPA_STATUS_FAIL;
        goto exit;
    }
    if (SYNC == setup->syncMode || rsaKeyGenCb == NULL)
    {
        rsaKeyGenCallback(
            pPerfData, status, &keyGenOpData, pPrivateKey, pPublicKey);
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (instanceInfo2->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, setup->cyInstanceHandle, pPerfData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        if (sampleCodeSemaphoreWait(&pPerfData->comp,
                                    SAMPLE_CODE_WAIT_DEFAULT) !=
            CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("timeout or interruption in cpaCyPrimeTest\n");
            status = CPA_STATUS_FAIL;
        }
    }
    sampleCodeSemaphoreDestroy(&pPerfData->comp);

exit:
#ifdef POLL_INLINE
    qaeMemFree((void **)&instanceInfo2);
#endif
    return status;
}
EXPORT_SYMBOL(generateRSAKey);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Frees any memory allocated by the genKeyArray function
 * qaeMemFree first checks to see if any memory is allocated before
 * attempting to free
 ******************************************************************************/
#define FREE_GEN_KEY_ARRAY_MEM(publicCount, privateCount)                      \
    do                                                                         \
    {                                                                          \
        Cpa32U j = 0;                                                          \
        for (j = 0; j < privateCount; j++)                                     \
        {                                                                      \
            qaeMemFree((void **)&pPrivateKey[j]);                              \
        }                                                                      \
        for (j = 0; j < publicCount; j++)                                      \
        {                                                                      \
            qaeMemFree((void **)&pPublicKey[j]);                               \
        }                                                                      \
    } while (0)

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * this function allocates space and generates arrays of RSA keys, based on the
 * parameters within the setup
 * ****************************************************************************/
CpaStatus genKeyArray(asym_test_params_t *setup,
                      CpaCyRsaPrivateKey *pPrivateKey[],
                      CpaCyRsaPublicKey *pPublicKey[])
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U bufferCount = 0;
    Cpa32U node = 0;


    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not get node\n");
        return status;
    }

    /*for each bufferList create the operation data*/
    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        /*set key pointers to null so that if any memory allocation fails and
         * we attempt to free it, the free will check if its NULL 1st*/
        pPrivateKey[bufferCount] = NULL;
        pPublicKey[bufferCount] = NULL;
    }
    /*for each bufferList create the operation data*/
    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        /*********************/
        /* Setup Public Key */
        /*********************/
        pPublicKey[bufferCount] =
            (CpaCyRsaPublicKey *)qaeMemAlloc(sizeof(CpaCyRsaPublicKey));
        if (NULL == pPublicKey[bufferCount])
        {
            PRINT_ERR("No memory for pTmpPublicKey\n");
            FREE_GEN_KEY_ARRAY_MEM(bufferCount, bufferCount);
            return CPA_STATUS_FAIL;
        }
        memset(pPublicKey[bufferCount], 0, sizeof(CpaCyRsaPublicKey));

        /* Setup Private Key */
        pPrivateKey[bufferCount] =
            (CpaCyRsaPrivateKey *)qaeMemAlloc(sizeof(CpaCyRsaPrivateKey));

        if (NULL == pPrivateKey[bufferCount])
        {
            PRINT_ERR("No memory for pTmpPrivateKey\n");
            FREE_GEN_KEY_ARRAY_MEM(bufferCount + 1, bufferCount);
            return CPA_STATUS_FAIL;
        }
        memset(pPrivateKey[bufferCount], 0, sizeof(CpaCyRsaPrivateKey));

        /* Setup version and key type */
        pPrivateKey[bufferCount]->version = CPA_CY_RSA_VERSION_TWO_PRIME;
        if (setup->rsaKeyRepType == CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2)
        {
            pPrivateKey[bufferCount]->privateKeyRepType =
                CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
        }
        else
        {
            pPrivateKey[bufferCount]->privateKeyRepType =
                CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;
        }

        /*generate the keys*/
        status = generateRSAKey(setup->cyInstanceHandle,
                                setup->modulusSizeInBytes,
                                pPrivateKey[bufferCount],
                                pPublicKey[bufferCount],
                                setup);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("RSAKey gen error %d on %d\n", status, bufferCount);
            FREE_GEN_KEY_ARRAY_MEM(bufferCount + 1, bufferCount + 1);
            return status;
        }
    }

    return status;
}
EXPORT_SYMBOL(genKeyArray);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * this function gets RSA keys and copies them into the RSA decryptOpData or
 * encryptOpStructures structure, in this function any memory allocation
 * is freed in sampleRSAPerform function
 * ****************************************************************************/
void rsaSetOpDataKeys(asym_test_params_t *setup,
                      CpaCyRsaDecryptOpData *pDecryptOpData[],
                      CpaCyRsaEncryptOpData *pEncryptOpData[],
                      CpaCyRsaPrivateKey *pPrivateKey[],
                      CpaCyRsaPublicKey *pPublicKey[])
{
    Cpa32U bufferCount = 0;

    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        /*copy keys into Encrypt or Decrypt operation data structures*/
        if (pDecryptOpData != NULL)
        {
            if (pDecryptOpData[bufferCount] != NULL &&
                pPrivateKey[bufferCount] != NULL)
            {
                pDecryptOpData[bufferCount]->pRecipientPrivateKey =
                    pPrivateKey[bufferCount];
            }
            else
            {
                PRINT_ERR("Could not assign RecipientPrivateKey\n");
            }
        }
        if (pEncryptOpData != NULL)
        {
            if (pEncryptOpData[bufferCount] != NULL &&
                pPublicKey[bufferCount] != NULL)
            {
                pEncryptOpData[bufferCount]->pPublicKey =
                    pPublicKey[bufferCount];
            }
            else
            {
                PRINT_ERR("Could not assign RecipientPrivateKey\n");
            }
        }
    }
}
EXPORT_SYMBOL(rsaSetOpDataKeys);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Frees any memory allocated by the rsaEncryptDataSetup function
 * qaeMemFreeNUMA first checks to see if any memory is allocated before
 * attempting to free
 ******************************************************************************/
#define FREE_RSA_ENCRYPT_DATA_SETUP_MEM()                                      \
    do                                                                         \
    {                                                                          \
        Cpa32U j = 0;                                                          \
        for (j = 0; j < setup->numBuffers; j++)                                \
        {                                                                      \
            qaeMemFreeNUMA((void **)&pOpdata[j]->inputData.pData);             \
            qaeMemFree((void **)&pOpdata[j]);                                  \
            qaeMemFreeNUMA((void **)&pOutputData[j]->pData);                   \
            qaeMemFree((void **)&pOutputData[j]);                              \
        }                                                                      \
    } while (0)

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * This function setups up an array of operation data structures for
 * Encryption operations, any memory allocation is freed in
 * sampleRSAPerform
 ******************************************************************************/
CpaStatus rsaEncryptDataSetup(CpaFlatBuffer *pEncryptData[],
                              CpaCyRsaEncryptOpData *pOpdata[],
                              CpaFlatBuffer *pOutputData[],
                              asym_test_params_t *setup)
{
    /*status is used inside macros within this function*/
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U bufferCount = 0;
    Cpa32U bufferSize = setup->modulusSizeInBytes;
    Cpa32U node = 0;


    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not get node\n");
        return status;
    }
    /*for each bufferList create the operation data*/
    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        /*allocate a flat buffer for the output*/
        pOutputData[bufferCount] = qaeMemAlloc(sizeof(CpaFlatBuffer));
        if (NULL == pOutputData[bufferCount])
        {
            PRINT_ERR("Failed to allocate mem for encrypt output data\n");
            FREE_RSA_ENCRYPT_DATA_SETUP_MEM();
            return CPA_STATUS_FAIL;
        }
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pOutputData[bufferCount],
                             bufferSize,
                             NULL,
                             0,
                             FREE_RSA_ENCRYPT_DATA_SETUP_MEM());

        pOpdata[bufferCount] = qaeMemAlloc(sizeof(CpaCyRsaEncryptOpData));
        /*allocate the input data and populate with random data*/
        if (NULL == pOpdata[bufferCount])
        {
            PRINT_ERR("Failed to allocate mem for encrypt input data\n");
            FREE_RSA_ENCRYPT_DATA_SETUP_MEM();
            return CPA_STATUS_FAIL;
        }
        memset(pOpdata[bufferCount], 0, sizeof(CpaCyRsaEncryptOpData));

        /*if there is no encrypt data provided,
         * generate random data to encrypt*/
        if (pEncryptData == NULL)
        {
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &pOpdata[bufferCount]->inputData,
                                 bufferSize,
                                 NULL,
                                 0,
                                 FREE_RSA_ENCRYPT_DATA_SETUP_MEM());
            generateRandomData(pOpdata[bufferCount]->inputData.pData,
                               bufferSize);
        }
        /*else copy the input data into the buffer*/
        else
        {
            ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                                 &pOpdata[bufferCount]->inputData,
                                 pEncryptData[bufferCount]->dataLenInBytes,
                                 pEncryptData[bufferCount]->pData,
                                 0,
                                 FREE_RSA_ENCRYPT_DATA_SETUP_MEM());
        }
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(rsaEncryptDataSetup);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * Frees any memory allocated by the rsaDecryptDataSetup function
 * qaeMemFreeNUMA first checks to see if any memory is allocated before
 * attempting to free
 ******************************************************************************/
#define FREE_RSA_DECRYPT_DATA_SETUP_MEM()                                      \
    do                                                                         \
    {                                                                          \
        Cpa32U j = 0;                                                          \
        for (j = 0; j < setup->numBuffers; j++)                                \
        {                                                                      \
            qaeMemFreeNUMA((void **)&pOpdata[j]->inputData.pData);             \
            qaeMemFree((void **)&pOpdata[j]);                                  \
            qaeMemFreeNUMA((void **)&pOutputData[j]->pData);                   \
            qaeMemFree((void **)&pOutputData[j]);                              \
        }                                                                      \
    } while (0)

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * this function sets up the data to be decrypted and allocates space to
 * store the output
 * ****************************************************************************/
CpaStatus rsaDecryptDataSetup(CpaFlatBuffer *pDecryptData[],
                              CpaCyRsaDecryptOpData *pOpdata[],
                              CpaFlatBuffer *pOutputData[],
                              asym_test_params_t *setup)
{
    /*status is used inside macros within this function*/
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U bufferCount = 0;
    Cpa32U bufferSize = setup->modulusSizeInBytes;
    Cpa32U node = 0;


    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not get node\n");
        return status;
    }

    /*for each bufferList create the operation data*/
    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        pOpdata[bufferCount] = NULL;
        pOutputData[bufferCount] = NULL;
        /*allocate a flat buffer for the output*/
        pOutputData[bufferCount] = qaeMemAlloc(sizeof(CpaFlatBuffer));
        if (NULL == pOutputData[bufferCount])
        {
            PRINT_ERR("Failed to allocate memory for Decrypt output buffer\n");
            FREE_RSA_DECRYPT_DATA_SETUP_MEM();
            return CPA_STATUS_FAIL;
        }
        memset(pOutputData[bufferCount], 0, sizeof(CpaFlatBuffer));
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             pOutputData[bufferCount],
                             bufferSize,
                             NULL,
                             0,
                             FREE_RSA_DECRYPT_DATA_SETUP_MEM());
        /*allocate memory for operation data*/
        pOpdata[bufferCount] = qaeMemAlloc(sizeof(CpaCyRsaDecryptOpData));
        if (NULL == pOpdata[bufferCount])
        {
            PRINT_ERR("Failed to allocate memory for Decrypt opData\n");
            FREE_RSA_DECRYPT_DATA_SETUP_MEM();
            return CPA_STATUS_FAIL;
        }
        memset(pOpdata[bufferCount], 0, sizeof(CpaCyRsaDecryptOpData));
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &(pOpdata[bufferCount]->inputData),
                             bufferSize,
                             NULL,
                             0,
                             FREE_RSA_DECRYPT_DATA_SETUP_MEM());

        /*generate random data to decrypt if there is no input data*/
        if (pDecryptData == NULL)
        {
            generateRandomData(pOpdata[bufferCount]->inputData.pData,
                               bufferSize);
            /*make sure it's less than the modulus (MSB = modulusN.pData[0])*/
            pOpdata[bufferCount]->inputData.pData[0] = 0;
        }
        /*else copy the input data into the buffer*/
        else
        {
            if (pDecryptData[bufferCount] != NULL)
            {
                if (pDecryptData[bufferCount]->pData != NULL)
                {
                    memcpy(pOpdata[bufferCount]->inputData.pData,
                           pDecryptData[bufferCount]->pData,
                           pDecryptData[bufferCount]->dataLenInBytes);
                }
                else
                {
                    PRINT_ERR("Could not copy decrypt data into buffers\n");
                    return CPA_STATUS_FAIL;
                }
            }
            else
            {
                PRINT_ERR("decrypt flat buffer points to NULL\n");
                return CPA_STATUS_FAIL;
            }
        }
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(rsaDecryptDataSetup);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * This function frees all Operation Data memory setup in this file.
 * The code checks for any unallocated memory before it attempts to free it.
 ******************************************************************************/
void rsaFreeDataMemory(asym_test_params_t *setup,
                       CpaCyRsaDecryptOpData *pOpdata[],
                       CpaFlatBuffer *pOutputData[],
                       CpaCyRsaEncryptOpData *pEncryptOpdata[],
                       CpaFlatBuffer *pInputData[])
{
    Cpa32U bufferCount = 0;
    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        if (NULL != pOpdata)
        {
            if (NULL != pOpdata[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pOpdata[bufferCount]->inputData.pData);
                qaeMemFree((void **)&pOpdata[bufferCount]);
            }
        }
        if (NULL != pOutputData)
        {
            if (NULL != pOutputData[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pOutputData[bufferCount]->pData);
                qaeMemFree((void **)&pOutputData[bufferCount]);
            }
        }
        if (NULL != pEncryptOpdata)
        {
            if (NULL != pEncryptOpdata[bufferCount])
            {
                qaeMemFreeNUMA(
                    (void **)&pEncryptOpdata[bufferCount]->inputData.pData);
                qaeMemFree((void **)&pEncryptOpdata[bufferCount]);
            }
        }
        if (NULL != pInputData)
        {
            if (NULL != pInputData[bufferCount])
            {
                qaeMemFreeNUMA((void **)&pInputData[bufferCount]->pData);
                qaeMemFree((void **)&pInputData[bufferCount]);
            }
        }
    }
    return;
}
EXPORT_SYMBOL(rsaFreeDataMemory);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * This function frees all memory related to RSA key data. This function must be
 * called before rsaFreeDataMemory otherwise the pointers to the key data will
 * be lost and we wont be able to free the memory
 * ****************************************************************************/
void rsaFreeKeyMemory(asym_test_params_t *setup,
                      CpaCyRsaPrivateKey *pPrivateKey[],
                      CpaCyRsaPublicKey *pPublicKey[])
{
    Cpa32U bufferCount = 0;

    if (NULL == pPrivateKey || NULL == pPrivateKey)
    {
        PRINT_ERR("Could not free rsaKeys\n");
        return;
    }
    for (bufferCount = 0; bufferCount < setup->numBuffers; bufferCount++)
    {
        /* free public key*/
        if (NULL == pPublicKey[bufferCount])
        {
            PRINT_ERR("Could not free pPublicKey[%d]\n", bufferCount);
        }
        else
        {
            qaeMemFreeNUMA((void **)&pPublicKey[bufferCount]->modulusN.pData);
            qaeMemFreeNUMA(
                (void **)&pPublicKey[bufferCount]->publicExponentE.pData);
            qaeMemFree((void **)&pPublicKey[bufferCount]);
        }
        /* free private key*/
        if (NULL == pPrivateKey[bufferCount])
        {
            PRINT_ERR("Could not free pPrivateKey[%d]\n", bufferCount);
        }
        else
        {
            if (pPrivateKey[bufferCount]->privateKeyRepType ==
                CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2)
            {
                CpaCyRsaPrivateKeyRep1 *resp1 =
                    &pPrivateKey[bufferCount]->privateKeyRep1;
                qaeMemFreeNUMA((void **)&resp1->modulusN.pData);
                qaeMemFreeNUMA((void **)&resp1->privateExponentD.pData);

                qaeMemFreeNUMA((void **)&pPrivateKey[bufferCount]
                                   ->privateKeyRep2.coefficientQInv.pData);
                qaeMemFreeNUMA((void **)&pPrivateKey[bufferCount]
                                   ->privateKeyRep2.exponent2Dq.pData);
                qaeMemFreeNUMA((void **)&pPrivateKey[bufferCount]
                                   ->privateKeyRep2.exponent1Dp.pData);
                qaeMemFreeNUMA((void **)&pPrivateKey[bufferCount]
                                   ->privateKeyRep2.prime2Q.pData);
                qaeMemFreeNUMA((void **)&pPrivateKey[bufferCount]
                                   ->privateKeyRep2.prime1P.pData);
                qaeMemFree((void **)&pPrivateKey[bufferCount]);
            }
        }
    }
    return;
}
EXPORT_SYMBOL(rsaFreeKeyMemory);

/******************************************************************************
 *
 * @ingroup sampleRSACode
 *
 * @description
 * this function measures the performance of RSA Encrypt operations
 * It is assume all the encrypt data and keys have been been set using functions
 * defined in this file
 * ****************************************************************************/
CpaStatus sampleRsaEncrypt(asym_test_params_t *setup,
                           CpaCyRsaEncryptOpData **ppEncryptOpData,
                           CpaFlatBuffer **ppOutputData,
                           Cpa32U numBuffers,
                           Cpa32U numLoops)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U insideLoopCount = 0;
    Cpa32U outsideLoopCount = 0;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;
    perf_data_t *pPerfData = setup->performanceStats;
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_SUCCESS;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
#endif

    DECLARE_IA_CYCLE_COUNT_VARIABLES();
#ifdef POLL_INLINE
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR(
            "Failed to allocate memory for instanceInfo2");
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
#endif
    setup->performanceStats->averagePacketSizeInBytes =
        setup->modulusSizeInBytes;
    setup->performanceStats->numOperations = (Cpa64U)numLoops * numBuffers;
    setup->performanceStats->responses = 0;
    coo_init(pPerfData, pPerfData->numOperations);
    /* Semaphore used in callback */
    sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = rsaCallback;
    }
    if (setup->performEncrypt)
    {
        sampleCodeBarrier();
        /* Get the clock cycle timestamp and store in Global, collect this only
         * for the first request, the callback collects it for the last */
        setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();
    }
    /*loop around number of preallocated buffer lists*/
    for (outsideLoopCount = 0; outsideLoopCount < numLoops; outsideLoopCount++)
    {

        /*perform on preallocated buffer lists*/
        for (insideLoopCount = 0; insideLoopCount < numBuffers;
             insideLoopCount++)
        {
            do
            {
                coo_req_start(pPerfData);
                status = cpaCyRsaEncrypt(setup->cyInstanceHandle,
                                         cbFunc,
                                         pPerfData,
                                         ppEncryptOpData[insideLoopCount],
                                         ppOutputData[insideLoopCount]);
                coo_req_stop(pPerfData, status);
                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo2->isPolled)
                        {
                            coo_poll_trad_cy(pPerfData,
                                             setup->cyInstanceHandle,
                                             &pollStatus);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    if (RETRY_LIMIT ==
                        (setup->performanceStats->retries % (RETRY_LIMIT + 1)))
                    {
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status);
            if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                BUSY_LOOP();
            }
            if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo2->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(
                            pPerfData, setup->cyInstanceHandle, &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif
        } /* end of inner loop */

        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }
    } /* end of outer loop */

    if (CPA_STATUS_SUCCESS == status)
    {
        if (SYNC == setup->syncMode)
        {
            pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
            sampleCodeSemaphorePost(&setup->performanceStats->comp);
            pPerfData->responses = (Cpa64U)setup->numBuffers * setup->numLoops;
        }
        /*wait for all submitted encrypt operations to complete*/
        if (sampleCodeSemaphoreWait(&setup->performanceStats->comp,
                                    SAMPLE_CODE_WAIT_DEFAULT) !=
            CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("interruption in cpaCyRsaEncrypt\n");
        }
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        IA_CYCLE_COUNT_CALCULATION();
    }
    coo_average(pPerfData);
    coo_deinit(pPerfData);
    sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);
#ifdef POLL_INLINE
    qaeMemFree((void **)&instanceInfo2);
#endif
    return status;
}

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 * this function measures the performance of RSA Encrypt operations
 * It is assumed all the encrypt data and keys have been been set using
 * functions defined in this file
 * ****************************************************************************/
CpaStatus sampleRsaDecrypt(asym_test_params_t *setup,
                           CpaCyRsaDecryptOpData **ppDecryptOpData,
                           CpaFlatBuffer **ppOutputData,
                           CpaCyRsaPrivateKey **pPrivateKey,
                           CpaCyRsaPublicKey **pPublicKey,
                           Cpa32U numBuffers,
                           Cpa32U numLoops)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U insideLoopCount = 0;
    Cpa32U outsideLoopCount = 0;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;
    perf_data_t *pPerfData = setup->performanceStats;
    CpaInstanceInfo2 *instanceInfo = NULL;
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_FAIL;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
    CpaBoolean isPolled = CPA_FALSE;
#endif
#ifdef LATENCY_CODE
    Cpa64U latency_submissions = 0;
    Cpa32U i = 0;
    perf_cycles_t *request_submit_start = NULL;
    perf_cycles_t *request_respnse_time = NULL;
    const Cpa32U request_mem_sz = sizeof(perf_cycles_t) * MAX_LATENCY_COUNT;

#endif

#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    /* KPT related */
    CpaCyKptKeyManagementStatus kpt2Status = CPA_CY_KPT_SUCCESS;
    CpaCyKptUnwrapContext **pKptUnwrapCtx = NULL;
    Cpa32U node = 0;
    Cpa32U keyProvisionRetryTimes = 0;
    CpaCyKptRsaDecryptOpData **ppKPTDecryptOpData = NULL;
    CpaCyCapabilitiesInfo pCapInfo = {0};
    CpaStatus delKeyStatus = CPA_STATUS_SUCCESS;
    Cpa8U rsaAdditionalAuthData[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01};
    /*SWK*/
    Cpa8U sampleSWK[SWK_LEN_IN_BYTES] = {0};

    Cpa8U iv[IV_LEN_IN_BYTES] = {0};

    if (CPA_TRUE == setup->enableKPT)
    {
        status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("sampleCodeCyGetNode failed!\n");
            return status;
        }
        ppKPTDecryptOpData = qaeMemAllocNUMA(
            sizeof(CpaCyKptRsaDecryptOpData *) * setup->numBuffers,
            node,
            BYTE_ALIGNMENT_64);
        if (NULL == ppKPTDecryptOpData)
        {
            PRINT_ERR("qaeMemAlloc ppKPTDecryptOpData error\n");
            return CPA_STATUS_FAIL;
        }
        pKptUnwrapCtx =
            qaeMemAllocNUMA(sizeof(CpaCyKptUnwrapContext) * setup->numBuffers,
                            node,
                            BYTE_ALIGNMENT_64);
        if (NULL == pKptUnwrapCtx)
        {
            PRINT_ERR("qaeMemAlloc pKptUnwrapCtx error\n");
            qaeMemFreeNUMA((void **)&ppKPTDecryptOpData);
            return CPA_STATUS_FAIL;
        }
    }
/* KPT related */
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */

/* KPT Stolen Key Test */
#endif

    DECLARE_IA_CYCLE_COUNT_VARIABLES();

#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (setup->performanceStats->numOperations > LATENCY_SUBMISSION_LIMIT)
        {
            PRINT_ERR("Error max submissions for latency  must be <= %d\n",
                      LATENCY_SUBMISSION_LIMIT);
            return CPA_STATUS_FAIL;
        }

        request_submit_start = qaeMemAlloc(request_mem_sz);
        request_respnse_time = qaeMemAlloc(request_mem_sz);
        if (request_submit_start == NULL || request_respnse_time == NULL)
        {
            PRINT_ERR("Failed to allocate memory for submission and"
                      " response times\n");
            return CPA_STATUS_FAIL;
        }
        memset(request_submit_start, 0, request_mem_sz);
        memset(request_respnse_time, 0, request_mem_sz);
        setup->performanceStats->nextCount =
            (setup->numBuffers * setup->numLoops) / 100;
        setup->performanceStats->countIncrement =
            (setup->numBuffers * setup->numLoops) / 100;

        setup->performanceStats->response_times = request_respnse_time;
        /* for debug purposes*/
        setup->performanceStats->start_times = request_submit_start;
    }
#endif
    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        qaeMemFree((void **)&instanceInfo);
        return CPA_STATUS_FAIL;
    }
    setup->performanceStats->packageId = instanceInfo->physInstId.packageId;
    setup->performanceStats->averagePacketSizeInBytes =
        setup->modulusSizeInBytes;
    setup->performanceStats->numOperations = (Cpa64U)numLoops * numBuffers;
    setup->performanceStats->responses = 0;
    coo_init(pPerfData, pPerfData->numOperations);
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        setup->performanceStats->busyLoopValue = busyLoopCounter_g;
        setup->performanceStats->busyLoopCount = 0;
    }

    /* Semaphore used in callback */
    sampleCodeSemaphoreInit(&setup->performanceStats->comp, 0);
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == setup->enableKPT)
        {
            cbFunc = kpt2RsaCallback;
        }
        else
        {
#endif
#endif
            cbFunc = rsaCallback;
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        }
#endif
#endif
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&instanceInfo);
            return CPA_STATUS_FAIL;
        }
        isPolled = instanceInfo->isPolled;
    }
#endif
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    if (CPA_TRUE == setup->enableKPT)
    {
        status = cpaCyQueryCapabilities(setup->cyInstanceHandle, &pCapInfo);
        if ((CPA_STATUS_SUCCESS == status) && !pCapInfo.kptSupported)
        {
            PRINT_ERR(
                "Inst (BDF:%02x:%02d.%d) does not support KPT2!\n",
                (Cpa8U)(instanceInfo->physInstId.busAddress >> 8),
                (Cpa8U)((instanceInfo->physInstId.busAddress & 0xFF) >> 3),
                (Cpa8U)(instanceInfo->physInstId.busAddress & 7));
            sampleCodeBarrier();
            qaeMemFree((void **)&instanceInfo);
            return CPA_STATUS_SUCCESS;
        }
        qaeMemFree((void **)&instanceInfo);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyQueryCapabilities failed!\n");
            return status;
        }
        generateRandomData(sampleSWK, SWK_LEN_IN_BYTES);
        generateRandomData(iv, IV_LEN_IN_BYTES);
        status = encryptAndLoadSWK(
            setup->cyInstanceHandle, &setup->kptKeyHandle, sampleSWK);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("encryptAndLoadSWKs failed!\n");
            kpt2RsaFreeDataMemory(setup, pKptUnwrapCtx, ppKPTDecryptOpData);
            qaeMemFreeNUMA((void **)&ppKPTDecryptOpData);
            qaeMemFreeNUMA((void **)&pKptUnwrapCtx);
            return status;
        }
        for (insideLoopCount = 0; insideLoopCount < numBuffers;
             insideLoopCount++)
        {
            pKptUnwrapCtx[insideLoopCount] = qaeMemAllocNUMA(
                sizeof(CpaCyKptUnwrapContext), node, BYTE_ALIGNMENT_64);

            status =
                setKpt2RsaDecryptOpData(setup->cyInstanceHandle,
                                        &ppKPTDecryptOpData[insideLoopCount],
                                        ppDecryptOpData[insideLoopCount],
                                        pPublicKey[insideLoopCount],
                                        node,
                                        sampleSWK,
                                        iv,
                                        rsaAdditionalAuthData,
                                        sizeof(rsaAdditionalAuthData));
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("setKptRsaDecryptOpData failed!\n");
                cpaCyKptDeleteKey(
                    setup->cyInstanceHandle, setup->kptKeyHandle, &kpt2Status);
                kpt2RsaFreeDataMemory(setup, pKptUnwrapCtx, ppKPTDecryptOpData);
                qaeMemFreeNUMA((void **)&ppKPTDecryptOpData);
                qaeMemFreeNUMA((void **)&pKptUnwrapCtx);
                return status;
            }

            pKptUnwrapCtx[insideLoopCount]->kptHandle = setup->kptKeyHandle;
            memcpy(pKptUnwrapCtx[insideLoopCount]->iv, iv, IV_LEN_IN_BYTES);
            memcpy(pKptUnwrapCtx[insideLoopCount]->additionalAuthData,
                   rsaAdditionalAuthData,
                   sizeof(rsaAdditionalAuthData));
            pKptUnwrapCtx[insideLoopCount]->aadLenInBytes =
                sizeof(rsaAdditionalAuthData);
        }
    }
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */

#endif

    qaeMemFree((void **)&instanceInfo);

    /*this barrier will wait until all threads get to this point*/
    sampleCodeBarrier();
    /* Get the clock cycle timestamp and store in Global, collect this only
     * for the first request, the callback collects it for the last */
    setup->performanceStats->startCyclesTimestamp = sampleCodeTimestamp();

    /*loop around number of pre-allocated buffer lists*/
    for (outsideLoopCount = 0; outsideLoopCount < numLoops; outsideLoopCount++)
    {
        /*perform on pre-allocated buffer lists*/
        for (insideLoopCount = 0; insideLoopCount < numBuffers;
             insideLoopCount++)
        {
            do
            {
#ifdef LATENCY_CODE
                if (latency_enable)
                {
                    if (latency_submissions + 1 ==
                        setup->performanceStats->nextCount)
                    {
                        request_submit_start[setup->performanceStats
                                                 ->latencyCount] =
                            sampleCodeTimestamp();
                    }
                }
#endif
                coo_req_start(pPerfData);
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
                if (CPA_TRUE == setup->enableKPT)
                {
                    status =
                        cpaCyKptRsaDecrypt(setup->cyInstanceHandle,
                                           cbFunc,
                                           setup->performanceStats,
                                           ppKPTDecryptOpData[insideLoopCount],
                                           ppOutputData[insideLoopCount],
                                           pKptUnwrapCtx[insideLoopCount]);
                    if (CPA_STATUS_FAIL == status)
                    {
                        PRINT_ERR("KPT RSA Decrypt failed!\n");
                    }
                }
                else
                {
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
#endif
                    status = cpaCyRsaDecrypt(setup->cyInstanceHandle,
                                             cbFunc,
                                             setup->performanceStats,
                                             ppDecryptOpData[insideLoopCount],
                                             ppOutputData[insideLoopCount]);
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
                }
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
#endif
                coo_req_stop(pPerfData, status);
                if (CPA_STATUS_RETRY == status)
                {
                    setup->performanceStats->retries++;
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (isPolled)
                        {
                            coo_poll_trad_cy(pPerfData,
                                             setup->cyInstanceHandle,
                                             &pollStatus);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    AVOID_SOFTLOCKUP;
                }
            } while (CPA_STATUS_RETRY == status);
            if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
            {
                BUSY_LOOP();
            }

            if (CPA_STATUS_INVALID_PARAM == status)
            {
                /* Reduce number of operations to poll because of invalid
                 * parameters. Keys are invalid because the generation of
                 * them was based on invalid prime.
                 */
                pPerfData->numOperations =
                    (outsideLoopCount + 1) * numBuffers - 1;
                /* Do not continue with outside loop in case of invalid param */
                outsideLoopCount = numLoops;
            }
            else if (CPA_STATUS_SUCCESS != status)
            {
                break;
            }

#ifdef LATENCY_CODE
            if (latency_enable)
            {
                /* Another buffer has been submitted to the accelerator */
                latency_submissions++;

                /* Have we been requested to process one buffer at a time. This
                 * will result in no retries and so the best latency times.
                 */
                if (latency_single_buffer_mode != 0)
                {
                    /* Must now wait until this buffer is processed by the CPM
                     */
                    while (pPerfData->responses != latency_submissions)
                    {
                        /* Keep polling until encryption of the buffer
                         * completes
                         * and rsaPerformCallback() increments
                         * pPerfData->responses */
                        sampleCodeAsymPollInstance(setup->cyInstanceHandle, 0);
                    }
                }
            }
#endif

#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(
                            pPerfData, setup->cyInstanceHandle, &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif

        } /* end of inner loop */

        if (CPA_STATUS_SUCCESS != status)
        {
            break;
        }

    } /* end of outer loop */
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, setup->cyInstanceHandle, pPerfData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pPerfData, setup->syncMode, setup->numBuffers, setup->numLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Thread %u timeout. ", setup->threadID);
        }
    }
#ifdef LATENCY_CODE
    if (latency_enable)
    {
        if (latency_debug)
        {
            PRINT("%s: Calculating min, max and ave latencies...\n",
                  __FUNCTION__);
            sampleCodeSleep(1); /* Let all our debug be printed out */
        }
        /* Will be less than this */
        setup->performanceStats->minLatency = MAX_LATENCY_LIMIT;
        /* Will be more than this */
        setup->performanceStats->maxLatency = 0;

        /* Let's accumulate in 'aveLatency' all the individual 'latency'
         * times. Typically, there should be MAX_LATENCY_COUNT of these.
         * We also calculate min/max so we can get a sense of the variance.
         */

        for (i = 0; i < setup->performanceStats->latencyCount; i++)
        {
            perf_cycles_t latency = setup->performanceStats->response_times[i] -
                                    request_submit_start[i];
            setup->performanceStats->aveLatency += latency;

            if (latency < setup->performanceStats->minLatency)
                setup->performanceStats->minLatency = latency;
            if (latency > setup->performanceStats->maxLatency)
                setup->performanceStats->maxLatency = latency;

            if (latency_debug)
                PRINT("%d, end[i]:%llu, start[i]:%llu, min:%llu, ave:%llu, "
                      "max:%llu\n",
                      i,
                      setup->performanceStats->response_times[i],
                      request_submit_start[i],
                      setup->performanceStats->minLatency,
                      setup->performanceStats->aveLatency,
                      setup->performanceStats->maxLatency);
        }
        if (setup->performanceStats->latencyCount > 0)
        {
            /* Then scale down this accumulated value to get the average.
             * This will be reported by dcPrintStats() at the end of the test */
            do_div(setup->performanceStats->aveLatency,
                   setup->performanceStats->latencyCount);
        }

        /*we are finished with the response time so set to null before exit*/
        setup->performanceStats->response_times = NULL;
        qaeMemFree((void **)&request_respnse_time);
        qaeMemFree((void **)&request_submit_start);
    }
#endif
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        IA_CYCLE_COUNT_CALCULATION();
    }
    coo_average(pPerfData);
    coo_deinit(pPerfData);
    sampleCodeSemaphoreDestroy(&setup->performanceStats->comp);
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    if (CPA_TRUE == setup->enableKPT)
    {
        do
        {
            delKeyStatus = cpaCyKptDeleteKey(
                setup->cyInstanceHandle, setup->kptKeyHandle, &kpt2Status);
            usleep(KEY_PROVISION_RETRY_DELAY_MS * 1000);
            keyProvisionRetryTimes++;
        } while ((CPA_STATUS_RETRY == delKeyStatus) &&
                 (keyProvisionRetryTimes <= KEY_PROVISION_RETRY_TIMES_LIMIT));
        if (1 < keyProvisionRetryTimes)
        {
            PRINT("KPT RSA Delete SWK Retry Times : %d\n",
                  keyProvisionRetryTimes - 1);
        }
        if ((CPA_STATUS_SUCCESS != delKeyStatus) ||
            (CPA_CY_KPT_SUCCESS != kpt2Status))
        {
            PRINT_ERR("Delete SWK failed with status: %d,kpt2Status: %d.\n",
                      delKeyStatus,
                      kpt2Status);
            status = CPA_STATUS_FAIL;
        }
        kpt2RsaFreeDataMemory(setup, pKptUnwrapCtx, ppKPTDecryptOpData);
        qaeMemFreeNUMA((void **)&ppKPTDecryptOpData);
        qaeMemFreeNUMA((void **)&pKptUnwrapCtx);
    }
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
#endif
    return status;
}
EXPORT_SYMBOL(sampleRsaDecrypt);

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 *  Main executing function
 *
 *****************************************************************************/

CpaStatus sampleRsaPerform(asym_test_params_t *setup)
{
    /* start of local variable declarations */
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* RSA key and opData parameters */
    CpaCyRsaPrivateKey **ppPrivateKey = NULL;
    CpaCyRsaPublicKey **ppPublicKey = NULL;
    CpaCyRsaDecryptOpData **ppDecryptOpData = NULL;
    CpaFlatBuffer **ppDecryptOutputData = NULL;
    /* end of local variable declarations */

    ppPrivateKey =
        qaeMemAlloc(sizeof(CpaCyRsaPrivateKey *) * setup->numBuffers);
    if (NULL == ppPrivateKey)
    {
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    ppPublicKey = qaeMemAlloc(sizeof(CpaCyRsaPublicKey *) * setup->numBuffers);
    if (NULL == ppPublicKey)
    {
        qaeMemFree((void **)&ppPrivateKey);
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    ppDecryptOpData =
        qaeMemAlloc(sizeof(CpaCyRsaDecryptOpData *) * setup->numBuffers);
    if (NULL == ppDecryptOpData)
    {
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    ppDecryptOutputData =
        qaeMemAlloc(sizeof(CpaFlatBuffer *) * setup->numBuffers);
    if (NULL == ppDecryptOutputData)
    {
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        qaeMemFree((void **)&ppDecryptOpData);
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    status = genKeyArray(setup, ppPrivateKey, ppPublicKey);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("genKeyArray error %d\n", status);
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        qaeMemFree((void **)&ppDecryptOpData);
        qaeMemFree((void **)&ppDecryptOutputData);
        return CPA_STATUS_FAIL;
    }

    /*setup decrypt operation to decrypt random data*/
    status =
        rsaDecryptDataSetup(NULL, ppDecryptOpData, ppDecryptOutputData, setup);
    if (status != CPA_STATUS_SUCCESS)
    {
        rsaFreeDataMemory(
            setup, ppDecryptOpData, ppDecryptOutputData, NULL, NULL);
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        qaeMemFree((void **)&ppDecryptOpData);
        qaeMemFree((void **)&ppDecryptOutputData);
        return CPA_STATUS_FAIL;
    }
    /*setup decryption opData structure with RSA key*/
    rsaSetOpDataKeys(setup, ppDecryptOpData, NULL, ppPrivateKey, ppPublicKey);

    status = sampleRsaDecrypt(setup,
                              ppDecryptOpData,
                              ppDecryptOutputData,
                              ppPrivateKey,
                              ppPublicKey,
                              setup->numBuffers,
                              setup->numLoops);
    /*free all the key and operation data memory*/
    rsaFreeKeyMemory(setup, ppPrivateKey, ppPublicKey);
    rsaFreeDataMemory(setup, ppDecryptOpData, ppDecryptOutputData, NULL, NULL);
    qaeMemFree((void **)&ppPrivateKey);
    qaeMemFree((void **)&ppPublicKey);
    qaeMemFree((void **)&ppDecryptOpData);
    qaeMemFree((void **)&ppDecryptOutputData);
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}

CpaStatus sampleRsaEncryptPerform(asym_test_params_t *setup)
{
    /* start of local variable declarations */
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U count = 0;

    /* RSA key and opData parameters */
    CpaCyRsaPrivateKey **ppPrivateKey = NULL;
    CpaCyRsaPublicKey **ppPublicKey = NULL;
    CpaCyRsaEncryptOpData **ppEncryptOpData = NULL;
    CpaFlatBuffer **ppEncryptOutputData = NULL;
    /* end of local variable declarations */

    ppPrivateKey =
        qaeMemAlloc(sizeof(CpaCyRsaPrivateKey *) * setup->numBuffers);
    if (NULL == ppPrivateKey)
    {
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    ppPublicKey = qaeMemAlloc(sizeof(CpaCyRsaPublicKey *) * setup->numBuffers);
    if (NULL == ppPublicKey)
    {
        qaeMemFree((void **)&ppPrivateKey);
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    ppEncryptOpData =
        qaeMemAlloc(sizeof(CpaCyRsaEncryptOpData *) * setup->numBuffers);
    if (NULL == ppEncryptOpData)
    {
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    ppEncryptOutputData =
        qaeMemAlloc(sizeof(CpaFlatBuffer *) * setup->numBuffers);
    if (NULL == ppEncryptOutputData)
    {
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        qaeMemFree((void **)&ppEncryptOpData);
        PRINT_ERR("qaeMemAlloc error\n");
        return CPA_STATUS_FAIL;
    }

    status = genKeyArray(setup, ppPrivateKey, ppPublicKey);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("genKeyArray error %d\n", status);
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        qaeMemFree((void **)&ppEncryptOpData);
        qaeMemFree((void **)&ppEncryptOutputData);
        return CPA_STATUS_FAIL;
    }

    /*setup decrypt operation to decrypt random data*/
    status =
        rsaEncryptDataSetup(NULL, ppEncryptOpData, ppEncryptOutputData, setup);
    if (status != CPA_STATUS_SUCCESS)
    {
        rsaFreeDataMemory(
            setup, NULL, NULL, ppEncryptOpData, ppEncryptOutputData);
        qaeMemFree((void **)&ppPrivateKey);
        qaeMemFree((void **)&ppPublicKey);
        qaeMemFree((void **)&ppEncryptOpData);
        qaeMemFree((void **)&ppEncryptOutputData);
        return CPA_STATUS_FAIL;
    }
    for (count = 0; count < setup->numBuffers; count++)
    {
        makeParam1SmallerThanParam2(ppEncryptOpData[count]->inputData.pData,
                                    ppPublicKey[count]->modulusN.pData,
                                    ppPublicKey[count]->modulusN.dataLenInBytes,
                                    CPA_FALSE);
    }
    /*setup decryption opData structure with RSA key*/
    rsaSetOpDataKeys(setup, NULL, ppEncryptOpData, ppPrivateKey, ppPublicKey);

    status = sampleRsaEncrypt(setup,
                              ppEncryptOpData,
                              ppEncryptOutputData,
                              setup->numBuffers,
                              setup->numLoops);
    /*free all the key and operation data memory*/
    rsaFreeKeyMemory(setup, ppPrivateKey, ppPublicKey);
    rsaFreeDataMemory(setup, NULL, NULL, ppEncryptOpData, ppEncryptOutputData);
    qaeMemFree((void **)&ppPrivateKey);
    qaeMemFree((void **)&ppPublicKey);
    qaeMemFree((void **)&ppEncryptOpData);
    qaeMemFree((void **)&ppEncryptOutputData);

    return status;
}

/******************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 *      Function for executing relevant algorithm and packet size
 *
 *****************************************************************************/
void sampleRsaThreadSetup(single_thread_test_data_t *testSetup)
{

    asym_test_params_t rsaTestSetup = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    asym_test_params_t *params = (asym_test_params_t *)testSetup->setupPtr;
    CpaInstanceInfo2 *instanceInfo = NULL;
#ifdef SC_DEV_INFO_ENABLED
    CpaDeviceInfo deviceInfo = {0};
#endif
    testSetup->passCriteria = getPassCriteria();

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call startThreads
     * anyway*/
    startBarrier();
    /*
     * In case of error scenario, the thread will exit early.
     * register the print function here itself to properly exit with statistics.
     */
    if (params->rsaKeyRepType == CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2)
    {
        testSetup->statsPrintFunc = (stats_print_func_t)printRsaCrtPerfData;
    }
    else
    {
        testSetup->statsPrintFunc = (stats_print_func_t)printRsaPerfData;
    }
    /*give our thread a unique memory location to store performance stats*/
    rsaTestSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        return;
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        return;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    /* give our thread a logical crypto instance to use.
     * Use % to wrap around the max number of instances*/
    rsaTestSetup.cyInstanceHandle =
        cyInstances[(testSetup->logicalQaInstance) % numInstances];
    status = cpaCyInstanceGetInfo2(rsaTestSetup.cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }

#ifdef SC_DEV_INFO_ENABLED
    /* check whether asym service enabled or not for the instance */
    status = cpaGetDeviceInfo(instanceInfo->physInstId.packageId, &deviceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaGetDeviceInfo failed", __func__, __LINE__);
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
    if (CPA_FALSE == deviceInfo.cyAsymEnabled)
    {
        PRINT_ERR("%s::%d Error! cyAsymEnabled service not enabled for the "
                  "configured instance\n",
                  __func__,
                  __LINE__);
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        goto exit;
    }
#endif
    if (instanceInfo->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo->physInstId.packageId;
    }

    rsaTestSetup.modulusSizeInBytes = testSetup->packetSize;
    rsaTestSetup.rsaKeyRepType = params->rsaKeyRepType;
    rsaTestSetup.numBuffers = params->numBuffers;
    rsaTestSetup.numLoops = params->numLoops;
    rsaTestSetup.syncMode = params->syncMode;
    rsaTestSetup.performEncrypt = params->performEncrypt;
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    rsaTestSetup.enableKPT = params->enableKPT;
#endif
#endif


    /*launch function that does all the work*/
    if (params->performEncrypt)
    {
        status = sampleRsaEncryptPerform(&rsaTestSetup);
    }
    else
    {
        status = sampleRsaPerform(&rsaTestSetup);
    }
    //    status = CPA_STATUS_FAIL;
    if (CPA_STATUS_SUCCESS != status)
    {
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == params->enableKPT)
        {
            PRINT("KPT2 Rsa Thread %u Failed\n", testSetup->threadID);
        }
        else
        {
#endif
#endif
            PRINT("Rsa Thread %u Failed\n", testSetup->threadID);
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        }
#endif
#endif
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeBarrier();
    }
    else
    {
        rsaTestSetup.performanceStats->threadReturnStatus = CPA_STATUS_SUCCESS;
    }
exit:
    qaeMemFree((void **)&instanceInfo);
    qaeMemFree((void **)&cyInstances);
    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(sampleRsaThreadSetup);

/**
 *****************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 *     function to print out RSA CRT performance data
 *
 *****************************************************************************/
CpaStatus printRsaCrtPerfData(thread_creation_data_t *data)
{
    asym_test_params_t *params = (asym_test_params_t *)data->setupPtr;
    if (params->performEncrypt)
    {
        PRINT("RSA CRT ENCRYPT\n");
    }
    else
    {
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == params->enableKPT)
        {
            PRINT("KPT RSA CRT DECRYPT\n");
        }
        else
        {
            PRINT("RSA CRT DECRYPT\n");
        }
#else
        PRINT("RSA CRT DECRYPT\n");
#endif
#else
        PRINT("RSA CRT DECRYPT\n");
#endif
    }
    PRINT("Modulus Size %19u\n", data->packetSize * NUM_BITS_IN_BYTE);
    return (printAsymStatsAndStopServices(data));
}

/**
 *****************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 *     function to print out RSA CRT performance data
 *
 *****************************************************************************/
CpaStatus printRsaPerfData(thread_creation_data_t *data)
{
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    asym_test_params_t *params = (asym_test_params_t *)data->setupPtr;
    if (CPA_TRUE == params->enableKPT)
    {
        PRINT("KPT RSA DECRYPT\n");
    }
    else
    {
        PRINT("RSA DECRYPT\n");
    }
#else
    PRINT("RSA DECRYPT\n");
#endif
#else
    PRINT("RSA DECRYPT\n");
#endif
    PRINT("Modulus Size %19u\n", data->packetSize * NUM_BITS_IN_BYTE);
    return (printAsymStatsAndStopServices(data));
}

/**
 *****************************************************************************
 * @ingroup sampleRSACode
 *
 * @description
 *      Function for setup RSA test before calling framework createThreads
 *      functions
 *
 *****************************************************************************/
CpaStatus setupRsaTest(Cpa32U modulusSize,
                       CpaCyRsaPrivateKeyRepType rsaKeyRepType,
                       sync_mode_t syncMode,
                       Cpa32U numBuffs,
                       Cpa32U numLoops)
{
    /*setup is a multi-dimensional array that stores the setup for all thread
     * variations in an array of characters. we store our test setup at the
     * start of the second array ie index 0. There maybe multi thread types
     * (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure*/
    asym_test_params_t *rsaSetup = NULL;
    Cpa8S name[] = {'R', 'S', 'A', '\0'};
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
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
    rsaSetup = (asym_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)sampleRsaThreadSetup;
    testSetupData_g[testTypeCount_g].packetSize =
        modulusSize / NUM_BITS_IN_BYTE;
    rsaSetup->rsaKeyRepType = rsaKeyRepType;
    rsaSetup->syncMode = syncMode;
    rsaSetup->numBuffers = numBuffs;
    rsaSetup->numLoops = numLoops;
    return CPA_STATUS_SUCCESS;
}
