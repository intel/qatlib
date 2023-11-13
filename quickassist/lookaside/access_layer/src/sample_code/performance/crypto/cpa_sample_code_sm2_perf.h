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
 *      Including Macros and function decleration
 *      More details about the algorithm is in
 *      http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *****************************************************************************/

#ifndef CPA_SAMPLE_CODE_SM2_PERF_H

#define CPA_SAMPLE_CODE_SM2_PERF_H

#include "cpa_cy_ec.h"
#include "cpa_cy_ecsm2.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_dev.h"
#ifdef NEWDISPLAY
#include "cpa_sample_code_NEWDISPLAY_crypto_utils.h"
#endif

/**
 ******************************************************************************
 * SM2 encryption function for data setup
 *     This function will be called in sm2PerfDataSetup(), encrypt the
 *     random message, and store the cipher for the decryption perform.
 *
 ******************************************************************************/
CpaStatus sm2Enc(sm2_test_params_t *setup);

/**
 ******************************************************************************
 * SM3 Hash function
 * param input  : input digest, input digest length
 * param output : digest output buffer
 ******************************************************************************/
extern void sm3(Cpa8U *input, Cpa64U ilen, Cpa8U *output);

/**
 ******************************************************************************
 *  Key Derivation Function
 *  param inbuf    flatbuffer holding the  data
 *  param outbuf   kdf output buffer
 ******************************************************************************/
extern CpaStatus kdf(CpaFlatBuffer *inbuf, CpaFlatBuffer *outbuf);

#define TIMEOUT_MS 5000 /* 5 seconds*/
#define MESSAGE_LEN 19
#define CIPHER_LEN                                                             \
    (SM3_HASH_SIZE_IN_BYTE + GFP_SM2_POINT_SIZE_IN_BYTE + MESSAGE_LEN)

/* ID of A for key exchange ,arbitrary data*/
const static Cpa8U ZA[] = {0xE4, 0xD1, 0xD0, 0xC3, 0xCA, 0x4C, 0x7F, 0x11,
                           0xBC, 0x8F, 0xF8, 0xCB, 0x3F, 0x4C, 0x02, 0xA7,
                           0x8F, 0x10, 0x8F, 0xA0, 0x98, 0xE5, 0x1A, 0x66,
                           0x84, 0x87, 0x24, 0x0F, 0x75, 0xE2, 0x0F, 0x31};
/* ID of B for key exchange, arbitrary data*/
const static Cpa8U ZB[] = {0x6B, 0x4B, 0x6D, 0x0E, 0x27, 0x66, 0x91, 0xBD,
                           0x4A, 0x11, 0xBF, 0x72, 0xF4, 0xFB, 0x50, 0x1A,
                           0xE3, 0x09, 0xFD, 0xAC, 0xB7, 0x2F, 0xA6, 0xCC,
                           0x33, 0x6E, 0x66, 0x56, 0x11, 0x9A, 0xBD, 0x67};
/* This struct is used in the performance test loop, such as encryption,
 * decryption.
 * Every loop has its own post processing data struct, using it to pass the
 * result of API to the callback function for the next hash operations.
 * It has two members:
 *      sm2_perf_test is a point to the regular performance testing data struct,
 *      including some base pointer.
 *      ptr is general pointer, point to the current API outData struct
 * */
typedef struct post_proc_data_s
{
    sm2_perf_test_t *sm2_perf_test;
    void *ptr;
} post_proc_data_t;
typedef struct Ecsm2SignOutputData
{
    CpaFlatBuffer r;
    /**< signature output r */
    CpaFlatBuffer s;
    /**< signature output s */
} Ecsm2SignOutputData;

/**
 ******************************************************************************
 * wait for AE execution slot on Retry
 * param input  : status
 * param output : pSm2Data
 ******************************************************************************/
#define waitForAEonRetry(status, pSm2Data)                                     \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_RETRY == status)                                        \
        {                                                                      \
            pSm2Data->retries++;                                               \
            /* If the acceleration engine is busy pause for a moment by        \
             * making a context switch */                                      \
            if (RETRY_LIMIT == (pSm2Data->retries % (RETRY_LIMIT + 1)))        \
            {                                                                  \
                AVOID_SOFTLOCKUP;                                              \
            }                                                                  \
        }                                                                      \
    } while (0)

/**
 ******************************************************************************
 * Initialise the semaphore, perfomance stat, number of operations
 * param input  : setup
 * param output : pSm2Data
 ******************************************************************************/
#define initSemaphoreAndVariables(pSm2Data, setup)                             \
    do                                                                         \
    {                                                                          \
        /* Get memory location to write performance stats to */                \
        pSm2Data = setup->performanceStats;                                    \
        memset(pSm2Data, 0, sizeof(perf_data_t));                              \
                                                                               \
        /*get the number of operations to be done in this test*/               \
        pSm2Data->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops; \
        pSm2Data->responses = 0;                                               \
                                                                               \
        /* Initialise semaphore used in callback */                            \
        sampleCodeSemaphoreInit(&pSm2Data->comp, 0);                           \
                                                                               \
    } while (0)

/**
 ******************************************************************************
 * convert point coordinates to byte string
 * param input  : byteString, converted byte string, uncompressed format, PC=04
 * param output : x , y , coordinate
 ******************************************************************************/
#define convertPointToBytes(byteString, x, y, isCompressed)                    \
    do                                                                         \
    {                                                                          \
        *(byteString) = HEADER_UNCOMPRESSION_POINT;                            \
        memcpy((byteString) + 1, (x), GFP_SM2_COORDINATE_SIZE_IN_BYTE);        \
        memcpy((byteString) + 1 + GFP_SM2_COORDINATE_SIZE_IN_BYTE,             \
               (y),                                                            \
               GFP_SM2_COORDINATE_SIZE_IN_BYTE);                               \
    } while (0)

/*
 ******************************************************************************
 * Split cipher to C1 C2 C3, according to the spec
 * param input  : Cipher C, length ilen
 * param output : C1,C2,C3
 ******************************************************************************/
#define splitCipherData(C, ilen, C1, C2, C3, isCompressed)                     \
    do                                                                         \
    {                                                                          \
        memcpy((C1), (C), GFP_SM2_POINT_SIZE_IN_BYTE);                         \
        memcpy((C2),                                                           \
               (C) + GFP_SM2_POINT_SIZE_IN_BYTE,                               \
               (ilen)-GFP_SM2_POINT_SIZE_IN_BYTE - SM3_HASH_SIZE_IN_BYTE);     \
        memcpy((C3),                                                           \
               (C) + (ilen)-GFP_SM2_COORDINATE_SIZE_IN_BYTE,                   \
               SM3_HASH_SIZE_IN_BYTE);                                         \
    } while (0)

/*
 ******************************************************************************
 * Split C1 to point, according to the spec
 * param input  : C1
 * param output : x coordinate X1, y coordinate Y1
 ******************************************************************************/
#define splitC1toPoint(C1, X1, Y1, isCompressed)                               \
    do                                                                         \
    {                                                                          \
        memcpy((X1), (C1) + 1, GFP_SM2_COORDINATE_SIZE_IN_BYTE);               \
        memcpy((Y1),                                                           \
               (C1) + 1 + GFP_SM2_COORDINATE_SIZE_IN_BYTE,                     \
               GFP_SM2_COORDINATE_SIZE_IN_BYTE);                               \
    } while (0)

/*
 ******************************************************************************
 * Check hash value
 * param input  : C3,hashValue
 * param outpu  : status
 ******************************************************************************/
#define hashCheck(C3, hashValue, status)                                       \
    do                                                                         \
    {                                                                          \
        int i;                                                                 \
        *(status) = CPA_STATUS_SUCCESS;                                        \
        for (i = 0; i < SM3_HASH_SIZE_IN_BYTE; i++)                            \
        {                                                                      \
            if (*((C3) + i) != *((hashValue) + i))                             \
            {                                                                  \
                *(status) = CPA_STATUS_FAIL;                                   \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0)

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 data setup process
 *
 ******************************************************************************/
static void sm2SetupFlatMemFree(sm2_test_params_t *setup)
{
    Cpa32U k = 0;

    if (setup->d != NULL)
    {
        if (NULL != setup->d->pData)
            qaeMemFreeNUMA((void **)&setup->d->pData);
        qaeMemFreeNUMA((void **)&setup->d);
    }

    if (setup->d2 != NULL)
    {
        if (NULL != setup->d2->pData)
            qaeMemFreeNUMA((void **)&setup->d2->pData);
        qaeMemFreeNUMA((void **)&setup->d2);
    }

    if (setup->xP != NULL)
    {
        if (NULL != setup->xP->pData)
            qaeMemFreeNUMA((void **)&setup->xP->pData);
        qaeMemFreeNUMA((void **)&setup->xP);
    }

    if (setup->yP != NULL)
    {
        if (NULL != setup->yP->pData)
            qaeMemFreeNUMA((void **)&setup->yP->pData);
        qaeMemFreeNUMA((void **)&setup->yP);
    }

    if (setup->message != NULL)
    {
        if (NULL != setup->message->pData)
            qaeMemFreeNUMA((void **)&setup->message->pData);
        qaeMemFreeNUMA((void **)&setup->message);
    }

    if (setup->cipher != NULL)
    {
        if (NULL != setup->cipher->pData)
            qaeMemFreeNUMA((void **)&setup->cipher->pData);
        qaeMemFreeNUMA((void **)&setup->cipher);
    }

    if (NULL != setup->digest)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != setup->digest[k].pData)
                qaeMemFreeNUMA((void **)&setup->digest[k].pData);
        }
        qaeMemFreeNUMA((void **)&setup->digest);
    }

    if (NULL != setup->random)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != setup->random[k].pData)
                qaeMemFreeNUMA((void **)&setup->random[k].pData);
        }
        qaeMemFreeNUMA((void **)&setup->random);
    }

    if (NULL != setup->x1)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != setup->x1[k].pData)
                qaeMemFreeNUMA((void **)&setup->x1[k].pData);
        }
        qaeMemFreeNUMA((void **)&setup->x1);
    }

    if (NULL != setup->y1)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != setup->y1[k].pData)
                qaeMemFreeNUMA((void **)&setup->y1[k].pData);
        }
        qaeMemFreeNUMA((void **)&setup->y1);
    }

    if (NULL != setup->x2)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != setup->x2[k].pData)
                qaeMemFreeNUMA((void **)&setup->x2[k].pData);
        }
        qaeMemFreeNUMA((void **)&setup->x2);
    }

    if (NULL != setup->y2)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != setup->y2[k].pData)
                qaeMemFreeNUMA((void **)&setup->y2[k].pData);
        }
        qaeMemFreeNUMA((void **)&setup->y2);
    }
}

/**
 ******************************************************************************
 *
 * Free any memory allocated in the sm2Perform function
 *
 ******************************************************************************/
#define SM2_ENC_SETUP_MSG_MEM_FREE()                                           \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&pC1Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC1Buffer);                                   \
        qaeMemFreeNUMA((void **)&pC2Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC2Buffer);                                   \
        qaeMemFreeNUMA((void **)&pC3Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC3Buffer);                                   \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer->pData);                  \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer);                         \
        qaeMemFreeNUMA((void **)&pEncOutputData->pData);                       \
        qaeMemFreeNUMA((void **)&pEncOutputData);                              \
        sm2SetupEncMemFree(opData, outData);                                   \
    } while (0)

#define SM2_ENC_MSG_MEM_FREE()                                                 \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&pC1Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC1Buffer);                                   \
        qaeMemFreeNUMA((void **)&pC2Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC2Buffer);                                   \
        qaeMemFreeNUMA((void **)&pC3Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC3Buffer);                                   \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer->pData);                  \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer);                         \
        qaeMemFreeNUMA((void **)&pEncOutputData->pData);                       \
        qaeMemFreeNUMA((void **)&pEncOutputData);                              \
        sm2EncMemFree(setup, opData, outData, post_proc_data);                 \
        if (NULL != sm2PerfBuffer)                                             \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfBuffer);                           \
        }                                                                      \
        if (NULL != sm2PerfTest)                                               \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfTest);                             \
        }                                                                      \
    } while (0)

#define SM2_DEC_MSG_MEM_FREE()                                                 \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&pM1Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pM1Buffer);                                   \
        qaeMemFreeNUMA((void **)&pC2Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC2Buffer);                                   \
        qaeMemFreeNUMA((void **)&pC3Buffer->pData);                            \
        qaeMemFreeNUMA((void **)&pC3Buffer);                                   \
        qaeMemFreeNUMA((void **)&pHashBuffer->pData);                          \
        qaeMemFreeNUMA((void **)&pHashBuffer);                                 \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer->pData);                  \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer);                         \
        qaeMemFreeNUMA((void **)&pDecOutputData->pData);                       \
        qaeMemFreeNUMA((void **)&pDecOutputData);                              \
        sm2DecMemFree(setup, opData, outData, post_proc_data);                 \
        if (NULL != sm2PerfBuffer)                                             \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfBuffer);                           \
        }                                                                      \
        if (NULL != sm2PerfTest)                                               \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfTest);                             \
        }                                                                      \
    } while (0)

#define SM2_KEYEX_MSG_MEM_FREE()                                               \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&pSecretKey->pData);                           \
        qaeMemFreeNUMA((void **)&pSecretKey);                                  \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer->pData);                  \
        qaeMemFreeNUMA((void **)&pIntermediateBuffer);                         \
        sm2KeyexP2MemFree(setup, opData, outData, post_proc_data);             \
        if (NULL != sm2PerfBuffer)                                             \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfBuffer);                           \
        }                                                                      \
        if (NULL != sm2PerfTest)                                               \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfTest);                             \
        }                                                                      \
    } while (0)

#define SM2_PERFORM_ENC_MEM_FREE()                                             \
    do                                                                         \
    {                                                                          \
        sm2EncMemFree(setup, opData, outData, post_proc_data);                 \
        if (NULL != sm2PerfBuffer)                                             \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfBuffer);                           \
        }                                                                      \
        if (NULL != sm2PerfTest)                                               \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfTest);                             \
        }                                                                      \
    } while (0)

#define SM2_PERFORM_DEC_MEM_FREE()                                             \
    do                                                                         \
    {                                                                          \
        sm2DecMemFree(setup, opData, outData, post_proc_data);                 \
        if (NULL != sm2PerfBuffer)                                             \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfBuffer);                           \
        }                                                                      \
        if (NULL != sm2PerfTest)                                               \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfTest);                             \
        }                                                                      \
    } while (0)

#define SM2_PERFORM_KEYEX_P1_MEM_FREE()                                        \
    do                                                                         \
    {                                                                          \
        sm2KeyexP1MemFree(setup, opData, outData);                             \
    } while (0)

#define SM2_PERFORM_KEYEX_P2_MEM_FREE()                                        \
    do                                                                         \
    {                                                                          \
        sm2KeyexP2MemFree(setup, opData, outData, post_proc_data);             \
        if (NULL != sm2PerfBuffer)                                             \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfBuffer);                           \
        }                                                                      \
        if (NULL != sm2PerfTest)                                               \
        {                                                                      \
            qaeMemFreeNUMA((void **)&sm2PerfTest);                             \
        }                                                                      \
    } while (0)

#define SM2_PERFORM_SIGN_MEM_FREE()                                            \
    do                                                                         \
    {                                                                          \
        sm2SignMemFree(setup, opData, outData);                                \
    } while (0)

#define SM2_PERFORM_VERIFY_MEM_FREE()                                          \
    do                                                                         \
    {                                                                          \
        sm2VerifyMemFree(setup, vOpData);                                      \
    } while (0)
#define SM2_PERFORM_SETUP_VERIFY_MEM_FREE()                                    \
    do                                                                         \
    {                                                                          \
        sm2VerifyMemFree(setup, setup->verifyOp);                              \
    } while (0)

#define SM2_PERFORM_SETUP_FLAT_MEM_FREE()                                      \
    do                                                                         \
    {                                                                          \
        sm2SetupFlatMemFree(setup);                                            \
    } while (0)

#define SM2_PERFORM_SETUP_ENC_MEM_FREE()                                       \
    do                                                                         \
    {                                                                          \
        sm2SetupEncMemFree(opData, outData);                                   \
    } while (0)

/**
 *******************************************************************************
 *
 * Free any memory allocated in the SM2 cipher data setup
 *
 *******************************************************************************/
void sm2SetupEncMemFree(CpaCyEcsm2EncryptOpData *opData,
                        CpaCyEcsm2EncryptOutputData *outData);

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 signature verification operation
 *
 ******************************************************************************/
void sm2VerifyMemFree(sm2_test_params_t *setup,
                      CpaCyEcsm2VerifyOpData **vOpData);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Signature operation
 *       This function is called for signature performance test.
 *
 ******************************************************************************/
CpaStatus sm2SignPerform(sm2_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Signature verify operation
 *       This function is called for signatrue verify performance test.
 *
 ******************************************************************************/
CpaStatus sm2VerifyPerform(sm2_test_params_t *setup);

/**
 ******************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Encryption operation
 *       This function is called for performance test.
 *
 ******************************************************************************/
CpaStatus sm2EncPerform(sm2_test_params_t *setup);

/*
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 Decryption operation
 *       This function is called for performance test.
 *
 ******************************************************************************/
CpaStatus sm2DecPerform(sm2_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 key exchange phase 1 operation
 *       This function is called for key exchange phase 1 performance test.
 *
 ******************************************************************************/
CpaStatus sm2KeyexP1Perform(sm2_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *       Perform Ecsm2 key exchange phase 2 operation
 *       This function is called for key exchange phase 2 performance test.
 *
 ******************************************************************************/
CpaStatus sm2KeyexP2Perform(sm2_test_params_t *setup);

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 key exchange phase 2 operation
 *
 ******************************************************************************/
void sm2KeyexP2MemFree(sm2_test_params_t *setup,
                       CpaCyEcsm2KeyExPhase2OpData **opData,
                       CpaCyEcsm2KeyExOutputData **outData,
                       post_proc_data_t **post_proc_data);

/**
 ******************************************************************************
 *
 * Free any memory allocated in the SM2 key exchange phase 1 operation
 *
 ******************************************************************************/
void sm2KeyexP1MemFree(sm2_test_params_t *setup,
                       CpaCyEcsm2KeyExPhase1OpData **opData,
                       CpaCyEcsm2KeyExOutputData **outData);
#endif
