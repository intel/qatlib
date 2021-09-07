/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 ******************************************************************************
 * @file cpa_fips_sample_aes_gcm.c
 *
 * @ingroup fipsSampleGcm
 *
 * This is sample code that uses Quick Assist APIs to implement the AES-GCM
 * algorithm according to FIPS 800-38D in the case where the Initialization
 * Vector is not 12 bytes in length.
 *
 *****************************************************************************/

#include "cpa_fips_sample.h"
#include "cpa_fips_sample_utils.h"
#include "cpa_fips_sample_aes_gcm.h"
#include "icp_sal_poll.h"

#include <pthread.h>
#include <sched.h>
typedef pthread_t sampleThread;
static sampleThread gPollingThread;
volatile static int gPollingCy = 0;
volatile static int gPollingThreadStopped = 0;
/**
 ******************************************************************************
 * @ingroup fipsSampleGcm
 *      EXPORT_SYMBOLs
 *
 * Functions which are exported for the kernel module interface
 *****************************************************************************/


/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      gMultiply
 *
 * @description
 *      Perform Galois Multiply (specified in FIPS 800-36D section 6.3
 *
 * @param[in]  pX         Left operand in the Galois multiply function
 * @param[in]  pY         Right operand in the Galois multiply function
 *
 * @param[out] pX         Result is written to the pX input buffer
 *
 * @retval This function returns void
 *
 * @pre
 *      Memory has been allocated for the X and Y inputs
 * @post
 *      none
 *
 *****************************************************************************/
static void gMultiply(Cpa8U *pX, const Cpa8U *restrict pY)
{

    Cpa8U Z[FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE] =
        {
            0,
        },
          V[FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE] = {
              0,
          };

    Cpa32U i = 0;

    /*1. Sequence of bits is stored in X */
    /*2. V0 = Y, Z = {0}*/
    (void)memcpy(V, pY, FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE);

    /*3. for i = 0 to 127, calculate Z and V as follows*/
    for (i = 0; i < (FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE * BYTE_SIZE); i++)
    {
        Cpa32U loop_byte_position = i / BYTE_SIZE;
        Cpa32U loop_bit = i % BYTE_SIZE;
        /*get Xi bit*/
        Cpa32U Xi = 1 & (pX[loop_byte_position] >> (BYTE_SIZE - loop_bit - 1));
        /*must store the LSB of V before doing the right shift*/
        bool lsbV = V[FIPS_SAMPLE_GHASH_INPUT_BUFFER_LAST_BYTE_INDEX] & 1;

        /*if Xi = 1*/
        /*Z = Z XOR V*/
        /*if Xi = 0, do nothing*/
        if (1 == Xi)
        {
            fipsSampleBufXOR(Z, V, FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE);
        }
        /*if LSB(V) = 0*/
        /*V = rightshift(V)*/
        /*else*/
        /*V = rightshift(V) XOR R*/
        rightShift(V, FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE);
        if (lsbV)
        {
            /*only top byte of R is none zero*/
            V[0] ^= FIPS_SAMPLE_GALOIS_MULTIPLY_CONSTANT_TOP_BYTE;
            /*V[0] ^= 0xE1;*/
        }
    }
    /*return Z*/
    (void)memcpy(pX, Z, FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      gHash
 *
 * @description
 *      Perform ghash algorithm (specified in FIPS 800-36D section 6.4)
 *      This function performs ghash algorithm.
 *
 * @param[in]  pH               the hash subkey
 * @param[in]  pX               the ghash input data
 *
 * @param[out] pY               The result of the gHash operation
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      All inputs have been allocated with at least 16 bytes of memory
 * @post
 *      none
 *
 *
 *****************************************************************************/
static CpaStatus gHash(const Cpa8U *restrict pH,
                       const CpaFlatBuffer *restrict pX,
                       Cpa8U *pY)
{
    Cpa32U i = 0, loop_count = 0;

    /*Validate that X = (128 * m), where m is some positive integer*/
    if (0 != pX->dataLenInBytes % FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE)
    {
        PRINT_ERR("input data length is not a multiple of the block size");
        return CPA_STATUS_FAIL;
    }
    /*1. Sequence of bits is stored in X */
    /*2. initialize set Y0 to zero*/
    (void)memset(pY, 0, FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE);

    /*3. get value of 'm'*/
    loop_count = (pX->dataLenInBytes) / FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE;

    /*3. loop 1 to 'm' times, calculating Yi*/
    for (i = 0; i < loop_count; i++)
    {
        fipsSampleBufXOR(pY,
                         &(pX->pData[i * FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE]),
                         FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE);
        gMultiply(pY, pH);
    }
    /*4. Return Yi*/
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      aes128ECBCipher
 *
 * @description
 *      This function performs aes128ECB encryption algorithm. For Quick
 *      Assist API structures, only some values are required to be filled
 *      in here.
 *
 * @param[in] pHashSubKey            A pointer to memory of the hash subkey
 * @param[in] pCipherKey             A pointer to memory of cipher key
 * @param[in] cipherKeyLength        The length of the cipher key
 * @param[in] instanceHandle         QA instance handle.
 *
 * @param[out] pHashSubkey           Value to become the GHASH subkey
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      none
 *
 * @see
 *
 *****************************************************************************/
static CpaStatus aes128ECBCipher(Cpa8U *pHashSubkey,
                                 Cpa8U *pCipherKey,
                                 Cpa32U cipherKeyLength,
                                 const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    CpaCySymSessionCtx *pSessionCtx = NULL;
    CpaBoolean verifyResult = CPA_TRUE;

    CpaCySymSessionSetupData sessionData = {
        .sessionPriority = CPA_CY_PRIORITY_NORMAL,
        .symOperation = CPA_CY_SYM_OP_CIPHER,
        .cipherSetupData = {.cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_ECB,
                            .cipherKeyLenInBytes = cipherKeyLength,
                            .pCipherKey = pCipherKey,
                            .cipherDirection =
                                CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT},
        .hashSetupData =
            {
                0,
            },              /*not used*/
        .algChainOrder = 0, /*ignored*/
        .digestIsAppended = CPA_FALSE,
        .verifyDigest = CPA_FALSE};
    CpaBufferList bufferList = {.pPrivateMetaData = NULL,
                                .numBuffers = 0,
                                .pBuffers = NULL,
                                .pUserData = NULL};
    CpaCySymOpData opData = {.sessionCtx = NULL,
                             .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
                             .pIv = NULL, /*IV not used for ECB mode AES*/
                             .ivLenInBytes = 0,
                             .cryptoStartSrcOffsetInBytes = 0,
                             .messageLenToCipherInBytes =
                                 FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE,
                             .hashStartSrcOffsetInBytes = 0,
                             .messageLenToHashInBytes = 0,
                             .pDigestResult = NULL};
    CpaFlatBuffer hFlatBuffer = {.dataLenInBytes =
                                     FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE,
                                 .pData = pHashSubkey};

    status = symSessionInit(&(sessionData), &(pSessionCtx), instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("session init error\n");
        goto finish;
    }
    status = symSetupBufferLists(1, /*one buffer in the list*/
                                 &bufferList,
                                 NULL,
                                 instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Buffer lists init error\n");
        goto finish;
    }

    bufferList.pBuffers = &hFlatBuffer;

    /*load params*/
    opData.sessionCtx = pSessionCtx;

    do
    {
        status = cpaCySymPerformOp(instanceHandle,
                                   NULL, /*callback function not required*/
                                   &opData,
                                   &(bufferList),
                                   &(bufferList),
                                   &verifyResult);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Perform Op Fail\n");
    }

finish:
    /*close session*/
    if (CPA_STATUS_SUCCESS != symSessionRemove(instanceHandle, pSessionCtx))
    {
        PRINT_ERR("Sym Remove Session error\n");
    }

    osFree((Cpa8U **)&bufferList.pPrivateMetaData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      gcmSessionInit
 *
 * @description
 *      This function initializes data structure to usr_gcm_data_t and
 *      initializes the session with instance handle and AES-GCM
 *      operation data.
 *
 *
 * @param[in] pGcmData       Structure containing all the data needed to
 *                           perform the AES-GCM encryption operation. The
 *                           test code allocates the memory for this
 *                           structure.
 * @param[out] pSessionCtx   Session Context to be used for GCM operations
 * @param[in] instanceHandle Instance handle for Quick Assist API functions
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *
 *****************************************************************************/
static CpaStatus gcmSessionInit(usr_gcm_data_t *pGcmData,
                                CpaCySymSessionCtx **ppSessionCtx,
                                const CpaInstanceHandle instanceHandle)
{

    CpaCySymSessionSetupData sessionData;

    sessionData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    sessionData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;

    sessionData.cipherSetupData.cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_GCM;
    sessionData.cipherSetupData.cipherKeyLenInBytes = pGcmData->cipherKeyLength;
    sessionData.cipherSetupData.pCipherKey = pGcmData->cipherKey;
    sessionData.cipherSetupData.cipherDirection = pGcmData->cipherDirection;

    sessionData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    sessionData.hashSetupData.digestResultLenInBytes =
        pGcmData->digestResultLenInBytes;
    if (GMAC_MODE == pGcmData->gcmMode)
    {
        sessionData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_GMAC;

        sessionData.hashSetupData.authModeSetupData.authKey = NULL;
        sessionData.hashSetupData.authModeSetupData.authKeyLenInBytes = 0;
        sessionData.hashSetupData.authModeSetupData.aadLenInBytes = 0;
    }
    else
    {
        sessionData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_GCM;
        sessionData.hashSetupData.authModeSetupData.authKey =
            pGcmData->cipherKey;
        sessionData.hashSetupData.authModeSetupData.authKeyLenInBytes =
            pGcmData->cipherKeyLength;
        sessionData.hashSetupData.authModeSetupData.aadLenInBytes =
            pGcmData->additionalAuthData.dataLenInBytes;
    }

    sessionData.digestIsAppended = CPA_FALSE;
    sessionData.verifyDigest = CPA_FALSE;
    return symSessionInit(&(sessionData), ppSessionCtx, instanceHandle);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      gcmPerformOp
 *
 * @description
 *      This function performs the AES-GCM operation according to FIPS 800-38D
 *      section 7.1 (if Encrypt) and section 7.2 (if Decrypt)
 *
 *
 * @param[in] pGcmData         Structure containing all the data needed to
 *                             perform the AES-GCM encryption operation. The
 *                             test code allocates the memory for this
 *                             structure.
 * @param[out] pSessionCtx     Session Context to be used for GCM operations
 * @param[out] pBufferListMesg Input message list
 * @param[out] pSessionCtx     Output message list
 * @param[in] instanceHandle   Instance handle.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *
 *****************************************************************************/
static CpaStatus gcmPerformOp(usr_gcm_data_t *pGcmData,
                              CpaCySymSessionCtx *pSessionCtx,
                              CpaBufferList *pBufferListMesg,
                              CpaBufferList *pBufferListMesgResult,
                              const CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /*The Quick Assist API does not support zero length input/output buffers.
      However, it does support zero data length processing.*/
    CpaBoolean inputOutputBuffersWereNULL = CPA_FALSE;
    Cpa32U maxCyRetries = 0;
    CpaCySymOpData opData = {
        .sessionCtx = pSessionCtx,
        .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
        .pIv = NULL, /*set this later as the J0 block*/
        .ivLenInBytes = 0,
        .cryptoStartSrcOffsetInBytes = 0,
        .messageLenToCipherInBytes = 0,
        .hashStartSrcOffsetInBytes = 0,
        .messageLenToHashInBytes = 0,
        .pDigestResult = 0,
        .pAdditionalAuthData = NULL,
    };
    Cpa8U *J0 = NULL, *H = NULL;
    Cpa32U gcmIvLen = pGcmData->iV.dataLenInBytes, buflen = 0;
    CpaFlatBuffer gHashInputData = {.dataLenInBytes = 0, .pData = NULL};

    /*If the IV length is 12 bytes, all GCM algorithm parts are done through a
      single call to the Quick Assist API.
      If the IV length is not 12 bytes, step 2 is calculated before the 16
      byte result is passed to the Quick Assist API.*/
    J0 = osZalloc(FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE, instanceHandle);
    if (NULL == J0)
    {
        PRINT_ERR("Could not allocate J0 block\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    /*An extra byte is allocated here for the case where the input buffer
      has zero data.*/
    H = osZalloc(FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE + 1, instanceHandle);
    if (NULL == H)
    {
        PRINT_ERR("Could not allocate H block\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    /*load params*/
    if (GMAC_MODE == pGcmData->gcmMode)
    {
        opData.messageLenToHashInBytes =
            pGcmData->additionalAuthData.dataLenInBytes;
        opData.pDigestResult = pGcmData->digestResult.pData;
        opData.pAdditionalAuthData = NULL;
        PRINT_ERR("GMAC opdata\n");
    }
    else
    {
        opData.messageLenToCipherInBytes = pGcmData->mesg.dataLenInBytes;
        opData.pDigestResult = pGcmData->digestResult.pData;
        opData.pAdditionalAuthData = pGcmData->additionalAuthData.pData;
    }
    if (0 == pGcmData->mesg.dataLenInBytes)
    {
        inputOutputBuffersWereNULL = CPA_TRUE;
        pGcmData->mesg.dataLenInBytes = 1;
        pGcmData->mesgResult.dataLenInBytes = 1;
        /*message value is still zero*/
        pGcmData->mesg.pData = H + FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE;
        /*We don't care if the result byte is overwritten*/
        pGcmData->mesgResult.pData = H + FIPS_SAMPLE_GHASH_INPUT_BUFFER_SIZE;
    }

    /*2. Encode J0 block*/
    if (FIPS_SAMPLE_GCM_12_BYTE_IV_LENGTH == gcmIvLen)
    {
        /*2.a. IV = 12 bytes*/
        PRINT_DBG("GCM with 12 byte IV\n");
        opData.ivLenInBytes = FIPS_SAMPLE_GCM_12_BYTE_IV_LENGTH;
        memcpy(J0, pGcmData->iV.pData, FIPS_SAMPLE_GCM_12_BYTE_IV_LENGTH);
    }
    else
    {
        /*2.b. IV != 12 bytes*/
        PRINT_DBG("GCM with %d byte IV\n", gcmIvLen);

        /*1. Let H = CIPH(128 zeros)
             This is required for the GHASH operation (it is also performed
             in the Quick Assist Driver)*/
        status = aes128ECBCipher(
            H, pGcmData->cipherKey, pGcmData->cipherKeyLength, instanceHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("GHASH H calculation Fail\n");
            goto finish;
        }

        /*must pad the IV to 128 bits using zeros, then add another
          128 bits of zeros. The IV length in bits is then added to the
          resulting number*/
        buflen = gcmIvLen % FIPS_SAMPLE_GCM_16_BYTE_IV_LENGTH;
        if (0 == buflen)
        {
            buflen = gcmIvLen + FIPS_SAMPLE_GCM_16_BYTE_IV_LENGTH;
        }
        else
        {
            buflen = FIPS_SAMPLE_GCM_16_BYTE_IV_LENGTH - buflen;
            buflen = gcmIvLen + buflen + FIPS_SAMPLE_J0_PADDING_LEN_IN_BYTES;
        }
        gHashInputData.pData = osZalloc(buflen, instanceHandle);
        if (NULL == gHashInputData.pData)
        {
            PRINT_ERR("Could not allocate gHashInputData block\n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        gHashInputData.dataLenInBytes = buflen;

        (void)memcpy(gHashInputData.pData, pGcmData->iV.pData, gcmIvLen);

        gcmIvLen *= BYTE_SIZE; /*hashed number is in bits*/

        /*Copy the number into the GHash input data*/
        COPY_32_BIT_UNSIGNED_VAL_TO_4_BYTE_ARRAY(
            ((gHashInputData.pData) +
             (buflen - (FOUR_BYTE_ARRAY_MAX_INDEX + 1))),
            gcmIvLen);

        /*Result is stored in J0 block*/
        status = gHash(H, &gHashInputData, J0);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("GHASH Op Fail\n");
            goto finish;
        }
        opData.ivLenInBytes = FIPS_SAMPLE_GCM_16_BYTE_IV_LENGTH;
    }
    opData.pIv = J0;
/*Perform*/
    do
    {
        status = cpaCySymPerformOp(instanceHandle,
                                   NULL, /*callback function not required*/
                                   &opData,
                                   pBufferListMesg,
                                   pBufferListMesgResult,
                                   &pGcmData->resultVerified);
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);


    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Perform Op Fail with maxCyRetries = %d \n", maxCyRetries);
        goto finish;
    }
    /*check whether the TAG was found to be correct*/
    if (CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT == pGcmData->cipherDirection)
    {
        if (CPA_FALSE == pGcmData->resultVerified)
        {
            PRINT_DBG("result not verified\n");
        }
    }
finish:
    osFree(&J0);
    osFree(&H);
    if (CPA_TRUE == inputOutputBuffersWereNULL)
    {
        pGcmData->mesg.dataLenInBytes = 0;
        pGcmData->mesgResult.dataLenInBytes = 0;
        pGcmData->mesg.pData = NULL;
        pGcmData->mesgResult.pData = NULL;
    }
    osFree(&gHashInputData.pData);
    return status;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      checkGcmData
 *
 * @description
 *      Check the Gcm operation data
 *
 *
 * @param[in] pGcmData        Structure containing all the data needed to
 *                           perform the AES-GCM encryption operation.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static CpaStatus checkGcmData(const usr_gcm_data_t *restrict pGcmData)
{

    if (NULL == pGcmData)
    {
        PRINT_ERR("Gcm Data input is NULL\n");
        return CPA_STATUS_FAIL;
    }
    switch (pGcmData->cipherKeyLength)
    {

        case FIPS_SAMPLE_KEYLEN_16_BYTES:
        case FIPS_SAMPLE_KEYLEN_24_BYTES:
        case FIPS_SAMPLE_KEYLEN_32_BYTES:
            break;
        default:
            PRINT_ERR("Key Length not supported\n");
            return CPA_STATUS_FAIL;
    }

    /*cipherDirection is caught by the QA API*/
    switch (pGcmData->digestResultLenInBytes)
    {
        case FIPS_SAMPLE_GCM_SUPPORTED_TAG_LEN_8_BYTES:
        case FIPS_SAMPLE_GCM_SUPPORTED_TAG_LEN_12_BYTES:
        case FIPS_SAMPLE_GCM_SUPPORTED_TAG_LEN_16_BYTES:
            break;
        default:
            PRINT_ERR("Key Length not supported\n");
            return CPA_STATUS_FAIL;
    }

    switch (pGcmData->gcmMode)
    {
        case GMAC_MODE:
            PRINT_DBG("GCM algorithm running in GMAC mode\n");
            break;
        case GCM_MODE:
            PRINT_DBG("GCM algorithm running in GCM mode\n");
            break;
        default:
            PRINT_ERR("GCM mode not supported\n");
            return CPA_STATUS_FAIL;
    }

    RETURN_IF_CPA_STATUS_FAIL(
        checkFlatBuffer("digestResult = ", &pGcmData->digestResult));
    RETURN_IF_CPA_STATUS_FAIL(
        checkFlatBuffer("digestResult = ", &pGcmData->iV));

    return CPA_STATUS_SUCCESS;
}

static CpaStatus sampleThreadCreate(sampleThread *thread,
                                    void *funct,
                                    void *args)
{
    if (pthread_create(thread, NULL, funct, args) != 0)
    {
        PRINT_ERR("Failed create thread\n");
        return CPA_STATUS_FAIL;
    }
    else
    {
        return CPA_STATUS_SUCCESS;
    }
}

static void sampleThreadExit(void)
{
    pthread_exit(NULL);
}

static void sal_polling(CpaInstanceHandle cyInstHandle)
{
    gPollingCy = 1;
    gPollingThreadStopped = 0;
    while (gPollingCy)
    {
        if (CPA_STATUS_RETRY == icp_sal_CyPollInstance(cyInstHandle, 0))
        {
            sched_yield();
        }
    }
    sampleThreadExit();
    gPollingThreadStopped = 1;
}

CpaStatus sampleCyStartPolling(CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 info2 = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaCyInstanceGetInfo2(cyInstHandle, &info2);
    if ((status == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE))
    {
        /* Start thread to poll instance */
        sampleThreadCreate(&gPollingThread, sal_polling, cyInstHandle);
    }
    return CPA_STATUS_SUCCESS;
}

void sampleCyStopPolling(void)
{
    gPollingCy = 0;
    while (gPollingThreadStopped)
    {
    }
}
/**
 *****************************************************************************
 * @ingroup fipsSampleGcm
 *      fipsSample_aesGcm
 *
 * @description
 *      This function implemented GCM and GMAC modes of operation based on
 *      FIPS 800-38D standard. In GCM mode, full authentication/verification
 *      and encrypt/decrypt is performed. GMAC mode gives only
 *      authentication/verification based on Plain Text inputs.
 *
 * @param[in,out] pGcmData   Structure containing all the data needed to
 *                           perform the AES-GCM operations. The caller
 *                           must allocate all memory associated with this
 *                           structure.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
CpaStatus fipsSample_aesGcm(usr_gcm_data_t *pGcmData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    CpaCySymSessionCtx *pSessionCtx = NULL;
    CpaBufferList bufferListMesg = {.pPrivateMetaData = NULL,
                                    .numBuffers = 0,
                                    .pBuffers = NULL,
                                    .pUserData = NULL};
    CpaBufferList bufferListMesgResult = {.pPrivateMetaData = NULL,
                                          .numBuffers = 0,
                                          .pBuffers = NULL,
                                          .pUserData = NULL};

    if (CPA_STATUS_SUCCESS != checkGcmData(pGcmData))
    {
        PRINT_ERR("GCM Data is not setup correctly\n");
        return CPA_STATUS_FAIL;
    }

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }
    pGcmData->resultVerified = 0;
    /*init session*/
    status = gcmSessionInit(pGcmData, &pSessionCtx, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("GCM session init error\n");
        goto finish;
    }
    status = symSetupBufferLists(1, /*one buffer in the list*/
                                 &bufferListMesg,
                                 &bufferListMesgResult,
                                 instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Buffer lists init error\n");
        goto finish;
    }

    if (GMAC_MODE == pGcmData->gcmMode)
    {
        bufferListMesg.pBuffers = &(pGcmData->additionalAuthData);
        bufferListMesgResult.pBuffers = &(pGcmData->additionalAuthData);
    }
    else
    {
        bufferListMesg.pBuffers = &(pGcmData->mesg);
        bufferListMesgResult.pBuffers = &(pGcmData->mesgResult);
    }

    status = sampleCyStartPolling(instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start polling Failed \n");
        goto finish;
    }
    /*encode/execute*/
    status = gcmPerformOp(pGcmData,
                          pSessionCtx,
                          &bufferListMesg,
                          &bufferListMesgResult,
                          instanceHandle);
    sampleCyStopPolling();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Sym Perform error\n");
        goto finish;
    }

finish:
    /*close session*/
    if (CPA_STATUS_SUCCESS != symSessionRemove(instanceHandle, pSessionCtx))
    {
        PRINT_ERR("Sym Remove Session error\n");
    }
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("Stop QA instance Fail \n");
    }

    osFree((Cpa8U **)&bufferListMesg.pPrivateMetaData);
    osFree((Cpa8U **)&bufferListMesgResult.pPrivateMetaData);

    return status;
}
