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
 *      Including  Encryption, Decryption
 *      More details about the algorithm is in
 *      http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *****************************************************************************/

#include "cpa_sample_code_sm2_perf.h"
#include "cpa_sample_code_crypto_utils.h"

/**
 *******************************************************************************
 *
 * Free any memory allocated in the SM2 cipher data setup
 *
 *******************************************************************************/
void sm2SetupEncMemFree(CpaCyEcsm2EncryptOpData *opData,
                        CpaCyEcsm2EncryptOutputData *outData)
{
    if (NULL != opData)
    {
        qaeMemFreeNUMA((void **)&opData->k.pData);
        qaeMemFreeNUMA((void **)&opData->xP.pData);
        qaeMemFreeNUMA((void **)&opData->yP.pData);
        qaeMemFreeNUMA((void **)&opData);
    }
    if (NULL != outData)
    {
        qaeMemFreeNUMA((void **)&outData->x1.pData);
        qaeMemFreeNUMA((void **)&outData->y1.pData);
        qaeMemFreeNUMA((void **)&outData->x2.pData);
        qaeMemFreeNUMA((void **)&outData->y2.pData);
        qaeMemFreeNUMA((void **)&outData);
    }
}

/**
 ******************************************************************************
 * SM2 encryption function for data setup
 *     This function will be called in sm2PerfDataSetup(), encrypt the
 *     random message, and store the cipher for the decryption perform.
 *
 ******************************************************************************/
CpaStatus sm2Enc(sm2_test_params_t *setup)
{
    Cpa32U j = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2EncryptOpData *opData = NULL;
    CpaCyEcsm2EncryptOutputData *outData = NULL;
    CpaFlatBuffer *pC1Buffer = NULL;
    CpaFlatBuffer *pC2Buffer = NULL;
    CpaFlatBuffer *pC3Buffer = NULL;
    CpaFlatBuffer *pIntermediateBuffer = NULL;
    CpaFlatBuffer *pEncOutputData = NULL;
    /*variable to store what cpu thread is running on*/
    Cpa32U node = 0;

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }
    /* Allocate memory for the operation data */
    opData = qaeMemAllocNUMA(
        sizeof(CpaCyEcsm2EncryptOpData), node, BYTE_ALIGNMENT_64);
    if (NULL == opData)
    {
        PRINT_ERR("opData memory allocation error\n");
        goto cleanup;
    }
    memset(opData, 0, sizeof(CpaCyEcsm2EncryptOpData));

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &opData->k,
                         setup->nLenInBytes,
                         setup->random[0].pData,
                         GFP_SM2_SIZE_IN_BYTE,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &opData->xP,
                         setup->nLenInBytes,
                         setup->xP->pData,
                         GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &opData->yP,
                         setup->nLenInBytes,
                         setup->yP->pData,
                         GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());
    /* Alloc memory for the output data */
    outData = qaeMemAllocNUMA(
        sizeof(CpaCyEcsm2EncryptOutputData), 0, BYTE_ALIGNMENT_64);
    if (NULL == outData)
    {
        PRINT_ERR("SM2 outData memory allocation error\n");
        goto cleanup;
    }
    memset(outData, 0, sizeof(CpaCyEcsm2EncryptOutputData));

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &outData->x1,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &outData->y1,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &outData->x2,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &outData->y2,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         SM2_PERFORM_SETUP_ENC_MEM_FREE());
    /* Alloc memory for the intermediate buffers */
    pC1Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC1Buffer,
                         GFP_SM2_POINT_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_ENC_SETUP_MSG_MEM_FREE());

    pC2Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC2Buffer,
                         MESSAGE_LEN,
                         NULL,
                         0,
                         SM2_ENC_SETUP_MSG_MEM_FREE());

    pC3Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC3Buffer,
                         SM3_HASH_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_ENC_SETUP_MSG_MEM_FREE());

    pIntermediateBuffer =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pIntermediateBuffer,
                         2 * GFP_SM2_SIZE_IN_BYTE + KDF_COUNTER_PADDING,
                         NULL,
                         0,
                         SM2_ENC_SETUP_MSG_MEM_FREE());

    pEncOutputData =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pEncOutputData,
                         GFP_SM2_POINT_SIZE_IN_BYTE + MESSAGE_LEN +
                             SM3_HASH_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_ENC_SETUP_MSG_MEM_FREE());

    /* Call the driver API to calculate point multiplication, in
     * synchronous mode */
    do
    {
        opData->fieldType = setup->fieldType;

        status = cpaCyEcsm2Encrypt(
            setup->cyInstanceHandle, NULL, NULL, opData, outData);
    } while (CPA_STATUS_RETRY == status);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("SM2 Enc function failed with status:%d\n", status);
        goto cleanup;
    }
    /* convert point (x1,y1) to byte string, uncompressed */
    convertPointToBytes(
        pC1Buffer->pData, outData->x1.pData, outData->y1.pData, FALSE);
    /* copy point multiply results, x2 , y2 to x2||y2 */
    memcpy(pIntermediateBuffer->pData,
           outData->x2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(pIntermediateBuffer->pData + GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           outData->y2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* kdf function, input buffer 68bytes x2||y2 + 4byte ct,
     * output buffer 32bytes */
    kdf(pIntermediateBuffer, pC2Buffer);
    /*  msg xor t (output of KDF) */
    for (j = 0; j < MESSAGE_LEN; j++)
    {
        *(pC2Buffer->pData + j) ^= *(setup->message->pData + j);
    }
    /* x2||M||y2 */
    memcpy(pEncOutputData->pData,
           outData->x2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(pEncOutputData->pData + GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           setup->message->pData,
           MESSAGE_LEN);
    memcpy(pEncOutputData->pData + GFP_SM2_COORDINATE_SIZE_IN_BYTE +
               MESSAGE_LEN,
           outData->y2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* hash(x2||M||y2) */
    sm3(pEncOutputData->pData,
        2 * GFP_SM2_COORDINATE_SIZE_IN_BYTE + MESSAGE_LEN,
        pC3Buffer->pData);

    /* C1||C2||C3 */
    memcpy(setup->cipher->pData, pC1Buffer->pData, GFP_SM2_POINT_SIZE_IN_BYTE);
    memcpy(setup->cipher->pData + GFP_SM2_POINT_SIZE_IN_BYTE,
           pC2Buffer->pData,
           MESSAGE_LEN);
    memcpy(setup->cipher->pData + GFP_SM2_POINT_SIZE_IN_BYTE + MESSAGE_LEN,
           pC3Buffer->pData,
           GFP_SM2_SIZE_IN_BYTE);
    /*Free all memory*/
    SM2_ENC_SETUP_MSG_MEM_FREE();
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (pC1Buffer != NULL)
        SM2_ENC_SETUP_MSG_MEM_FREE();
    else
        SM2_PERFORM_SETUP_ENC_MEM_FREE();
    return status;
}

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 encryption operation
 *
 ******************************************************************************/
static void sm2EncMemFree(sm2_test_params_t *setup,
                          CpaCyEcsm2EncryptOpData **opData,
                          CpaCyEcsm2EncryptOutputData **outData,
                          post_proc_data_t **post_proc_data)
{
    Cpa32U k = 0;
    if (NULL != opData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != opData[k])
            {
                qaeMemFreeNUMA((void **)&opData[k]->k.pData);
                qaeMemFreeNUMA((void **)&opData[k]->xP.pData);
                qaeMemFreeNUMA((void **)&opData[k]->yP.pData);
                qaeMemFreeNUMA((void **)&opData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&opData);
    }
    if (NULL != outData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != outData[k])
            {
                qaeMemFreeNUMA((void **)&outData[k]->x1.pData);
                qaeMemFreeNUMA((void **)&outData[k]->y1.pData);
                qaeMemFreeNUMA((void **)&outData[k]->x2.pData);
                qaeMemFreeNUMA((void **)&outData[k]->y2.pData);
                qaeMemFreeNUMA((void **)&outData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&outData);
    }
    if (NULL != post_proc_data)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != post_proc_data[k])
            {
                qaeMemFreeNUMA((void **)&post_proc_data[k]);
            }
        }
        qaeMemFreeNUMA((void **)&post_proc_data);
    }
}

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 decryption operation
 *
 ******************************************************************************/
static void sm2DecMemFree(sm2_test_params_t *setup,
                          CpaCyEcsm2DecryptOpData **opData,
                          CpaCyEcsm2DecryptOutputData **outData,
                          post_proc_data_t **post_proc_data)
{
    Cpa32U k = 0;
    if (NULL != opData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != opData[k])
            {
                qaeMemFreeNUMA((void **)&opData[k]->d.pData);
                qaeMemFreeNUMA((void **)&opData[k]->x1.pData);
                qaeMemFreeNUMA((void **)&opData[k]->y1.pData);
                qaeMemFreeNUMA((void **)&opData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&opData);
    }
    if (NULL != outData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != outData[k])
            {
                qaeMemFreeNUMA((void **)&outData[k]->x2.pData);
                qaeMemFreeNUMA((void **)&outData[k]->y2.pData);
                qaeMemFreeNUMA((void **)&outData[k]);
            }
        }
        qaeMemFreeNUMA((void **)&outData);
    }
    if (NULL != post_proc_data)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != post_proc_data[k])
            {
                qaeMemFreeNUMA((void **)&post_proc_data[k]);
            }
        }
        qaeMemFreeNUMA((void **)&post_proc_data);
    }
}

/**
 ******************************************************************************
 * SM2 encryption post processing
 * SM2 APIs return the results of the point multiplication
 * In this function, continue to calculate the cipher text with KDF && SM3 hash
 * param input  : pC1Buffer,pC2Buffer,pC3Buffer,pIntermediateBuffer,pEncPKEOut
 * param output : pEncOutputData
 ******************************************************************************/
static CpaStatus sm2EncPostProc(sm2_perf_test_t *perf_test, void *ptr)
{
    int j = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyEcsm2EncryptOutputData *pEncPKEOut = NULL;
    pEncPKEOut = (CpaCyEcsm2EncryptOutputData *)ptr;
    /* convert point (x1,y1) to byte string, uncompressed */
    convertPointToBytes(perf_test->perf_buffer->pC1Buffer->pData,
                        pEncPKEOut->x1.pData,
                        pEncPKEOut->y1.pData,
                        FALSE);
    /* copy point multiply results, x2 , y2 to x2||y2 */
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData,
           pEncPKEOut->x2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           pEncPKEOut->y2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* kdf function, input buffer 68bytes x2||y2 + 4byte ct,
     * output buffer 32bytes
     */
    kdf(perf_test->perf_buffer->pIntermediateBuffer,
        perf_test->perf_buffer->pC2Buffer);

    /*  msg xor t (output of KDF) */
    for (j = 0; j < MESSAGE_LEN; j++)
    {
        *(perf_test->perf_buffer->pC2Buffer->pData + j) ^=
            *(perf_test->setup->message->pData + j);
    }

    /* x2||M||y2 */
    memcpy(perf_test->perf_buffer->pEncOutputData->pData,
           pEncPKEOut->x2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);
    memcpy(perf_test->perf_buffer->pEncOutputData->pData +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           perf_test->setup->message->pData,
           MESSAGE_LEN);
    memcpy(perf_test->perf_buffer->pEncOutputData->pData +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE + MESSAGE_LEN,
           pEncPKEOut->y2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* hash(x2||M||y2) */
    sm3(perf_test->perf_buffer->pEncOutputData->pData,
        GFP_SM2_COORDINATE_SIZE_IN_BYTE + MESSAGE_LEN +
            GFP_SM2_COORDINATE_SIZE_IN_BYTE,
        perf_test->perf_buffer->pC3Buffer->pData);
    memset(perf_test->perf_buffer->pEncOutputData->pData,
           0,
           GFP_SM2_POINT_SIZE_IN_BYTE + MESSAGE_LEN +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* C1||C2||C3 */
    memcpy(perf_test->perf_buffer->pEncOutputData->pData,
           perf_test->perf_buffer->pC1Buffer->pData,
           GFP_SM2_POINT_SIZE_IN_BYTE);
    memcpy(perf_test->perf_buffer->pEncOutputData->pData +
               GFP_SM2_POINT_SIZE_IN_BYTE,
           perf_test->perf_buffer->pC2Buffer->pData,
           MESSAGE_LEN);
    memcpy(perf_test->perf_buffer->pEncOutputData->pData +
               GFP_SM2_POINT_SIZE_IN_BYTE + MESSAGE_LEN,
           perf_test->perf_buffer->pC3Buffer->pData,
           GFP_SM2_SIZE_IN_BYTE);
    return status;
}

/*
 ******************************************************************************
 * SM2 decryption post processing
 * SM2 APIs return the results of the point multiplication
 * In this function, continue to calculate the plain text with KDF && SM3 hash
 * param input  : pC1Buffer,pC2Buffer,pC3Buffer,pHashBuffer,pIntermediateBuffer,
 *                pDecPKEOut
 * param output : pDecOutputData
 ******************************************************************************/
static CpaStatus sm2DecPostProc(sm2_perf_test_t *perf_test, void *ptr)
{
    int j = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2DecryptOutputData *pDecPKEOut = NULL;
    pDecPKEOut = (CpaCyEcsm2DecryptOutputData *)ptr;
    /* x2||y2 */
    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData,
           pDecPKEOut->x2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    memcpy(perf_test->perf_buffer->pIntermediateBuffer->pData +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           pDecPKEOut->y2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* KDF(X2||y2,klen) */
    kdf(perf_test->perf_buffer->pIntermediateBuffer,
        perf_test->perf_buffer->pC1Buffer);

    /* msg = C2 xor t */
    for (j = 0; j < MESSAGE_LEN; j++)
    {
        *(perf_test->perf_buffer->pC1Buffer->pData + j) ^=
            *(perf_test->perf_buffer->pC2Buffer->pData + j);
    }

    /* x2||M'||y2 */
    memcpy(perf_test->perf_buffer->pDecOutputData->pData,
           pDecPKEOut->x2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    memcpy(perf_test->perf_buffer->pDecOutputData->pData +
               GFP_SM2_COORDINATE_SIZE_IN_BYTE,
           perf_test->perf_buffer->pC1Buffer->pData,
           MESSAGE_LEN);

    memcpy(perf_test->perf_buffer->pDecOutputData->pData + CIPHER_LEN -
               GFP_SM2_POINT_SIZE_IN_BYTE,
           pDecPKEOut->y2.pData,
           GFP_SM2_COORDINATE_SIZE_IN_BYTE);

    /* hash(x2||M'||y2) */
    sm3(perf_test->perf_buffer->pDecOutputData->pData,
        GFP_SM2_COORDINATE_SIZE_IN_BYTE + CIPHER_LEN -
            GFP_SM2_POINT_SIZE_IN_BYTE,
        perf_test->perf_buffer->pHashBuffer->pData);

    /* check if hash value is equal to the C3 */
    hashCheck(perf_test->perf_buffer->pC3Buffer->pData,
              perf_test->perf_buffer->pHashBuffer->pData,
              &status);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("DEC Error \n");
    }
    return status;
}

/**
 ******************************************************************************
 * Callback function
 * Sm2 Encryption Callback function
 *    Post processing with KDF && SM3 Hash
 *    Performance statistic
 *
 ******************************************************************************/
static void sm2EncCallback(void *pCallbackTag,
                           CpaStatus status,
                           void *pOpData,
                           CpaFlatBuffer *pOut)
{
    post_proc_data_t *postProcData = NULL;
    sm2_perf_test_t *pPerfTestData = NULL;
    perf_data_t *pPerfData = NULL;
    void *ptr = NULL;

    postProcData = (post_proc_data_t *)pCallbackTag;
    pPerfTestData = postProcData->sm2_perf_test;
    ptr = postProcData->ptr;
    pPerfData = pPerfTestData->setup->performanceStats;
    sm2EncPostProc(pPerfTestData, ptr);
    processCallback(pPerfData);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("sm2EncCallback error status %d\n", status);
    }
}

/**
 ******************************************************************************
 * Callback function
 * Sm2 Decryption Callback function
 *     Post processing with KDF && SM3 Hash
 *     Performance statistic
 *
 ******************************************************************************/
static void sm2DecCallback(void *pCallbackTag,
                           CpaStatus status,
                           void *pOpData,
                           CpaFlatBuffer *pOut)
{
    post_proc_data_t *postProcData = NULL;
    sm2_perf_test_t *pPerfTestData = NULL;
    perf_data_t *pPerfData = NULL;
    void *ptr = NULL;

    postProcData = (post_proc_data_t *)pCallbackTag;
    pPerfTestData = postProcData->sm2_perf_test;
    ptr = postProcData->ptr;
    pPerfData = pPerfTestData->setup->performanceStats;

    sm2DecPostProc(pPerfTestData, ptr);
    processCallback(pPerfData);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("sm2DecCallback error status %d\n", status);
    }
}

/**
 ******************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Encryption operation
 *       This function is called for performance test.
 *
 ******************************************************************************/
CpaStatus sm2EncPerform(sm2_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    Cpa32U loops = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2EncryptOpData **opData = NULL;
    CpaCyEcsm2EncryptOutputData **outData = NULL;
    /* allocated for every loop */
    post_proc_data_t **post_proc_data = NULL;
    CpaFlatBuffer *pC1Buffer = NULL;
    CpaFlatBuffer *pC2Buffer = NULL;
    CpaFlatBuffer *pC3Buffer = NULL;
    CpaFlatBuffer *pIntermediateBuffer = NULL;
    CpaFlatBuffer *pEncOutputData = NULL;
    /* Variable to store what CPU Node/socket is running on*/
    Cpa32U node = 0;
    /* Pointer to location to store performance data*/
    perf_data_t *pSm2Data = NULL;
    sm2_perf_test_t *sm2PerfTest = NULL;
    sm2_perf_buf_t *sm2PerfBuffer = NULL;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;

    /* Get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }

    sm2PerfTest =
        qaeMemAllocNUMA(sizeof(sm2_perf_test_t), node, BYTE_ALIGNMENT_64);
    if (NULL == sm2PerfTest)
    {
        PRINT_ERR("Memory allocation failure for sm2PerfTest\n");
        return CPA_STATUS_FAIL;
    }

    sm2PerfBuffer =
        qaeMemAllocNUMA(sizeof(sm2_perf_buf_t), node, BYTE_ALIGNMENT_64);
    if (NULL == sm2PerfBuffer)
    {
        PRINT_ERR("Memory allocation failure for sm2PerfBuffer\n");
        goto cleanup;
    }

    initSemaphoreAndVariables(pSm2Data, setup);

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&opData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("opData mem allocation error\n");
        goto cleanup;
    }
    /* allocate memory according to the setup->numBuffers */
    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&post_proc_data, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("post_proc_data mem allocation error\n");
        goto cleanup;
    }

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&outData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("outData mem allocation error\n");
        goto cleanup;
    }

    for (i = 0; i < setup->numBuffers; i++)
    {
        opData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2EncryptOpData), node, BYTE_ALIGNMENT_64);
        if (NULL == opData[i])
        {
            PRINT_ERR("opData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(opData[i], 0, sizeof(CpaCyEcsm2EncryptOpData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->k,
                             setup->nLenInBytes,
                             setup->random[i].pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_ENC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->xP,
                             setup->nLenInBytes,
                             setup->xP->pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_ENC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->yP,
                             setup->nLenInBytes,
                             setup->yP->pData,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_ENC_MEM_FREE());
        opData[i]->fieldType = setup->fieldType;

        outData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2EncryptOutputData), node, BYTE_ALIGNMENT_64);
        if (NULL == outData[i])
        {
            PRINT_ERR("outData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(outData[i], 0, sizeof(CpaCyEcsm2EncryptOutputData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->x1,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_ENC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->y1,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_ENC_MEM_FREE());
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->x2,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_ENC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->y2,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_ENC_MEM_FREE());
        post_proc_data[i] =
            qaeMemAllocNUMA(sizeof(post_proc_data_t), node, BYTE_ALIGNMENT_64);
        if (NULL == post_proc_data[i])
        {
            PRINT_ERR("Memory allocation failure for post_proc_data\n");
            goto cleanup;
        }
        memset(post_proc_data[i], 0, sizeof(post_proc_data_t));
    }
    /* Set the callback function if asynchronous mode is set */
    if (ASYNC == setup->syncMode)
    {
        cbFunc = (CpaCyGenFlatBufCbFunc)sm2EncCallback;
    }
    numLoops = setup->numLoops;

    pC1Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC1Buffer,
                         GFP_SM2_POINT_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_ENC_MSG_MEM_FREE());

    pC2Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC2Buffer,
                         MESSAGE_LEN,
                         NULL,
                         0,
                         SM2_ENC_MSG_MEM_FREE());

    pC3Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC3Buffer,
                         GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_ENC_MSG_MEM_FREE());

    pIntermediateBuffer =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pIntermediateBuffer,
                         2 * GFP_SM2_SIZE_IN_BYTE + KDF_COUNTER_PADDING,
                         NULL,
                         0,
                         SM2_ENC_MSG_MEM_FREE());

    pEncOutputData =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pEncOutputData,
                         GFP_SM2_POINT_SIZE_IN_BYTE + MESSAGE_LEN +
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_ENC_MSG_MEM_FREE());

    /* Temporary buffers for sm2EncPostProc */
    sm2PerfBuffer->pC1Buffer = pC1Buffer;
    sm2PerfBuffer->pC2Buffer = pC2Buffer;
    sm2PerfBuffer->pC3Buffer = pC3Buffer;
    sm2PerfBuffer->pIntermediateBuffer = pIntermediateBuffer;
    sm2PerfBuffer->pEncOutputData = pEncOutputData;
    /* record the base address of the output data of API */
    sm2PerfBuffer->pDecPKEOut = (CpaCyEcsm2DecryptOutputData *)outData[0];

    /* This barrier will wait until all threads get to this point */
    sampleCodeBarrier();

    /* Record the start time, the callback measures the end time when the last
     * response is received*/
    pSm2Data->startCyclesTimestamp = sampleCodeTimestamp();

    for (loops = 0; loops < numLoops; loops++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            do
            {
                opData[i]->fieldType = setup->fieldType;

                sm2PerfTest->setup = setup;
                sm2PerfTest->perf_buffer = sm2PerfBuffer;
                post_proc_data[i]->sm2_perf_test = sm2PerfTest;
                post_proc_data[i]->ptr = (void *)outData[i];

                status = cpaCyEcsm2Encrypt(setup->cyInstanceHandle,
                                           (CpaCyGenFlatBufCbFunc)cbFunc,
                                           (void *)post_proc_data[i],
                                           opData[i],
                                           outData[i]);
                waitForAEonRetry(status, pSm2Data);
            } while (CPA_STATUS_RETRY == status);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("SM2 Enc function failed with status:%d\n", status);
                goto cleanup;
            }

        } /*end buffers loop */
    }     /* end of numLoops loop*/

    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pSm2Data, setup->syncMode, setup->numBuffers, setup->numLoops);
    }

    sampleCodeSemaphoreDestroy(&pSm2Data->comp);
    /*Free all memory*/
    SM2_ENC_MSG_MEM_FREE();
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (pC1Buffer != NULL)
        SM2_ENC_MSG_MEM_FREE();
    if (sm2PerfTest != NULL)
        SM2_PERFORM_ENC_MEM_FREE();
    return CPA_STATUS_FAIL;
}

/*
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Decryption operation
 *       This function is called for performance test.
 *
 ******************************************************************************/
CpaStatus sm2DecPerform(sm2_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    Cpa32U loops = 0;
    CpaCyEcsm2Stats64 sm2Stats = {0};
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyEcsm2DecryptOpData **opData = NULL;
    CpaCyEcsm2DecryptOutputData **outData = NULL;
    /* allocated for every loop */
    post_proc_data_t **post_proc_data = NULL;
    CpaFlatBuffer *pDecOutputData = NULL;
    CpaFlatBuffer *pM1Buffer = NULL;
    CpaFlatBuffer *pC2Buffer = NULL;
    CpaFlatBuffer *pC3Buffer = NULL;
    CpaFlatBuffer *pHashBuffer = NULL;
    CpaFlatBuffer *pIntermediateBuffer = NULL;
    /*variable to store what cpu thread is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pSm2Data = NULL;
    sm2_perf_test_t *sm2PerfTest = NULL;
    sm2_perf_buf_t *sm2PerfBuffer = NULL;
    CpaCyGenFlatBufCbFunc cbFunc = NULL;

    status = cpaCyEcsm2QueryStats64(setup->cyInstanceHandle, &sm2Stats);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Could not retrieve stats, error status %d\n", status);
        return status;
    }
    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        return status;
    }

    sm2PerfTest =
        qaeMemAllocNUMA(sizeof(sm2_perf_test_t), node, BYTE_ALIGNMENT_64);
    if (NULL == sm2PerfTest)
    {
        PRINT_ERR("Memory allocation failure for sm2PerfTest\n");
        return CPA_STATUS_FAIL;
    }

    sm2PerfBuffer =
        qaeMemAllocNUMA(sizeof(sm2_perf_buf_t), node, BYTE_ALIGNMENT_64);
    if (NULL == sm2PerfBuffer)
    {
        PRINT_ERR("Memory allocation failure for sm2PerfBuffer\n");
        goto cleanup;
    }

    initSemaphoreAndVariables(pSm2Data, setup);

    numLoops = setup->numLoops;

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&opData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("opData mem allocation error\n");
        goto cleanup;
    }
    /* allocate memory according to the setup->numBuffers */
    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&post_proc_data, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("post_proc_data mem allocation error\n");
        goto cleanup;
    }

    status = allocArrayOfPointers(
        setup->cyInstanceHandle, (void **)&outData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("outData mem allocation error\n");
        goto cleanup;
    }

    /* Allocate and populate all the operation data buffers */
    for (i = 0; i < setup->numBuffers; i++)
    {
        opData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2DecryptOpData), node, BYTE_ALIGNMENT_64);
        if (NULL == opData[i])
        {
            PRINT_ERR("opData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(opData[i], 0, sizeof(CpaCyEcsm2DecryptOpData));
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->d,
                             setup->nLenInBytes,
                             setup->d->pData,
                             GFP_SM2_SIZE_IN_BYTE,
                             SM2_PERFORM_DEC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->x1,
                             setup->nLenInBytes,
                             setup->cipher->pData + 1,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_DEC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &opData[i]->y1,
                             setup->nLenInBytes,
                             setup->cipher->pData + 1 +
                                 GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             GFP_SM2_COORDINATE_SIZE_IN_BYTE,
                             SM2_PERFORM_DEC_MEM_FREE());

        outData[i] = qaeMemAllocNUMA(
            sizeof(CpaCyEcsm2DecryptOutputData), node, BYTE_ALIGNMENT_64);
        if (NULL == outData[i])
        {
            PRINT_ERR("outData[%u] memory allocation error\n", i);
            goto cleanup;
        }
        memset(outData[i], 0, sizeof(CpaCyEcsm2DecryptOutputData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->x2,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_DEC_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &outData[i]->y2,
                             setup->nLenInBytes,
                             NULL,
                             0,
                             SM2_PERFORM_DEC_MEM_FREE());

        post_proc_data[i] =
            qaeMemAllocNUMA(sizeof(post_proc_data_t), node, BYTE_ALIGNMENT_64);
        if (NULL == post_proc_data[i])
        {
            PRINT_ERR("Memory allocation failure for post_proc_data\n");
            goto cleanup;
        }
        memset(post_proc_data[i], 0, sizeof(post_proc_data_t));
    }

    pC2Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC2Buffer,
                         MESSAGE_LEN,
                         setup->cipher->pData + GFP_SM2_POINT_SIZE_IN_BYTE,
                         MESSAGE_LEN,
                         SM2_DEC_MSG_MEM_FREE());

    pC3Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pC3Buffer,
                         SM3_HASH_SIZE_IN_BYTE,
                         setup->cipher->pData + GFP_SM2_POINT_SIZE_IN_BYTE +
                             MESSAGE_LEN,
                         SM3_HASH_SIZE_IN_BYTE,
                         SM2_DEC_MSG_MEM_FREE());

    pM1Buffer = qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pM1Buffer,
                         MESSAGE_LEN,
                         NULL,
                         0,
                         SM2_DEC_MSG_MEM_FREE());

    pHashBuffer =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pHashBuffer,
                         SM3_HASH_SIZE_IN_BYTE,
                         NULL,
                         0,
                         SM2_DEC_MSG_MEM_FREE());

    pIntermediateBuffer =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pIntermediateBuffer,
                         2 * GFP_SM2_SIZE_IN_BYTE + KDF_COUNTER_PADDING,
                         NULL,
                         0,
                         SM2_DEC_MSG_MEM_FREE());

    pDecOutputData =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer), node, BYTE_ALIGNMENT_64);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pDecOutputData,
                         CIPHER_LEN,
                         NULL,
                         0,
                         SM2_DEC_MSG_MEM_FREE());

    /* Set the callback function if asynchronous mode is set */
    if (ASYNC == setup->syncMode)
    {
        cbFunc = (CpaCyGenFlatBufCbFunc)sm2DecCallback;
    }

    /* Temporary buffers for sm2DecPostProc*/
    sm2PerfBuffer->pC1Buffer = pM1Buffer;
    sm2PerfBuffer->pC2Buffer = pC2Buffer;
    sm2PerfBuffer->pC3Buffer = pC3Buffer;
    sm2PerfBuffer->pHashBuffer = pHashBuffer;

    /* 64 bytes + 4 bytes */
    sm2PerfBuffer->pIntermediateBuffer = pIntermediateBuffer;

    /* 1 byte(header,04=uncompression) + 64 bytes(x,y coordinate) + msg_len +
     * 32 bytes */
    sm2PerfBuffer->pDecOutputData = pDecOutputData;
    /* record the base address of the output data of API */
    sm2PerfBuffer->pDecPKEOut = outData[0];
    /* This barrier will wait until all threads get to this point */
    sampleCodeBarrier();

    /* Record the start time, the callback measures the end time when the last
     * response is received*/
    pSm2Data->startCyclesTimestamp = sampleCodeTimestamp();

    for (loops = 0; loops < numLoops; loops++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {
            do
            {
                opData[i]->fieldType = setup->fieldType;

                sm2PerfTest->setup = setup;
                sm2PerfTest->perf_buffer = sm2PerfBuffer;
                post_proc_data[i]->sm2_perf_test = sm2PerfTest;
                post_proc_data[i]->ptr = (void *)outData[i];

                status = cpaCyEcsm2Decrypt(setup->cyInstanceHandle,
                                           (CpaCyGenFlatBufCbFunc)cbFunc,
                                           (void *)post_proc_data[i],
                                           opData[i],
                                           outData[i]);
                waitForAEonRetry(status, pSm2Data);
            } while (CPA_STATUS_RETRY == status);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("SM2 Decryption function failed with status:%d\n",
                          status);
                goto cleanup;
            }

        } /*end buffers loop */
    }     /* end of numLoops loop*/
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pSm2Data, setup->syncMode, setup->numBuffers, setup->numLoops);
    }

    sampleCodeSemaphoreDestroy(&pSm2Data->comp);
    /* Free all memory */
    SM2_DEC_MSG_MEM_FREE();
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;

cleanup:
    SM2_PERFORM_SETUP_FLAT_MEM_FREE();
    if (pC2Buffer != NULL)
        SM2_DEC_MSG_MEM_FREE();
    if (opData != NULL)
        SM2_PERFORM_DEC_MEM_FREE();
    return CPA_STATUS_FAIL;
}

