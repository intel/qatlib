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

/*
 *        This is a sample code that uses Diffie-Hellman APIs.
 *        In order to use this algorithm, 3 elements have to be set:
 *          - a prime number p (the modulus)
 *          - a base g
 *          - a random value x
 *
 *       This sample code defines arbitrary values for p, g and x.
 *       Phase 1. In this phase, the public value A=g^x mod p is calculated
 *       Then, in a real implementation, this value has to be sent to another
 *       party (B) that will send back its public value
 *       Phase 2. Based on the public value returned by B, the prime number p
 *       and x, the private key is calculated
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_dh.h"

#include "cpa_sample_utils.h"

#define TIMEOUT_MS 5000 /* 5 seconds*/

extern int gDebugParam;

/*
 * Sample prime number for DH algorithm.  This number may be 768, 1024, 1536,
 * 2048, 3072 or 4096 bits in length.
 */
static Cpa8U primeP_768[] = {
    0xC7, 0x3B, 0x18, 0xB5, 0x71, 0xE1, 0xE0, 0x7C, 0x70, 0x66, 0x5F, 0xD8,
    0x8B, 0xD9, 0xC2, 0x55, 0x3E, 0xD7, 0x09, 0x68, 0x80, 0xF2, 0x17, 0x1A,
    0x7A, 0x6D, 0xC9, 0x24, 0xF2, 0x5C, 0x84, 0x7D, 0xB4, 0xC5, 0xA5, 0x40,
    0x9A, 0x3F, 0xB7, 0xBD, 0xD4, 0xD0, 0xE6, 0xA0, 0x01, 0xC5, 0x1E, 0xA7,
    0x60, 0x42, 0x2D, 0xF5, 0x16, 0xAF, 0x01, 0x6C, 0xF7, 0xA5, 0x73, 0xCF,
    0x36, 0xB3, 0x6E, 0x5C, 0xE7, 0x2C, 0x18, 0x19, 0x5C, 0x21, 0x40, 0x1B,
    0xF4, 0xD5, 0xD9, 0xF4, 0x46, 0x08, 0xDA, 0x84, 0x0B, 0x34, 0x8F, 0x80,
    0xB9, 0x7C, 0x7B, 0xAF, 0x23, 0xEA, 0x6E, 0xF2, 0x45, 0x8C, 0xC0, 0x0B};

/*
 * Base of DH algorithm chosen by A.
 */
static Cpa8U baseG1[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/*
 * Random value for DH algorithm chosen by A. It must match the
 * following condition:
 *
 *     0 < PrivateValueX < (PrimeP - 1)
 *
 * where PrimeP is the prime number (primeP_768, above).
 */
static Cpa8U privateValueX[] = {
    0x00, 0x14, 0x34, 0x12, 0x93, 0xCE, 0xBF, 0x04, 0x7C, 0x87, 0x16, 0x37,
    0xEB, 0xB8, 0x75, 0xF0, 0x69, 0x6D, 0xEA, 0x92, 0x5C, 0x3A, 0xDF, 0x87,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

CpaStatus dhSample(void);

/*
 * Callback function
 *
 * This function is "called back" (invoked by the implementation of
 * the API) when the asynchronous operation has completed.  The
 * context in which it is invoked depends on the implementation, but
 * as described in the API it should not sleep (since it may be called
 * in a context which does not permit sleeping, e.g. a Linux bottom
 * half).
 *
 * This function can perform whatever processing is appropriate to the
 * application.  For example, it may free memory, continue processing,
 * etc.  In this example, the function only sets the complete variable
 * to indicate it has been called.
 */
static void asymCallback(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaFlatBuffer *pOut)
{
    PRINT_DBG("CallBack function\n");

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("operation not a success, status = %d\n", status);
    }

    PRINT_DBG("asymCallback: status = %d\n", status);

    /** indicate the callback function has been executed, meaning that
     * cpaCyDhKeyGenPhase2Secret is completed*/
    if (NULL != pCallbackTag)
    {
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

/*****************************************************************************
 * Perform Diffie-Hellman phase 1 and 2 operations
 *****************************************************************************/
static CpaStatus sampleDhPerformOp(CpaInstanceHandle cyInstHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /** callback data for function 1*/
    void *pCallbackTagPh1 = (void *)1;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;
    void *pCallbackTagPh2 = (void *)&complete;

    /** Pointer that will contain the public value (returned by
     * cpaCyDhKeyGenPhase1) */
    CpaFlatBuffer *pLocalOctetStringPV = NULL;
    /** Pointer that will contain the private key (returned by
     * cpaCyDhKeyGenPhase2) */
    CpaFlatBuffer *pOctetStringSecretKey = NULL;

    CpaCyDhPhase2SecretKeyGenOpData *pCpaDhOpDataP2 = NULL;

    CpaCyDhPhase1KeyGenOpData *pCpaDhOpDataP1 = NULL;

    //<snippet name="memAlloc">
    status = OS_MALLOC(&pCpaDhOpDataP1, sizeof(CpaCyDhPhase1KeyGenOpData));

    /*
     * Allocate input buffers for phase 1 and copy data. Input to DH
     * phase 1 includes the prime (primeP), the base g (baseG) and
     * a random private value (privateValueX).
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        memset(pCpaDhOpDataP1, 0, sizeof(CpaCyDhPhase1KeyGenOpData));

        pCpaDhOpDataP1->primeP.dataLenInBytes = sizeof(primeP_768);
        status = PHYS_CONTIG_ALLOC(&pCpaDhOpDataP1->primeP.pData,
                                   sizeof(primeP_768));

        if (NULL != pCpaDhOpDataP1->primeP.pData)
        {
            memcpy(
                pCpaDhOpDataP1->primeP.pData, primeP_768, sizeof(primeP_768));
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        pCpaDhOpDataP1->baseG.dataLenInBytes = sizeof(baseG1);
        status =
            PHYS_CONTIG_ALLOC(&pCpaDhOpDataP1->baseG.pData, sizeof(baseG1));

        if (NULL != pCpaDhOpDataP1->baseG.pData)
        {
            memcpy(pCpaDhOpDataP1->baseG.pData, baseG1, sizeof(baseG1));
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        pCpaDhOpDataP1->privateValueX.dataLenInBytes = sizeof(privateValueX);
        status = PHYS_CONTIG_ALLOC(&pCpaDhOpDataP1->privateValueX.pData,
                                   sizeof(privateValueX));

        if (NULL != pCpaDhOpDataP1->privateValueX.pData)
        {
            memcpy(pCpaDhOpDataP1->privateValueX.pData,
                   privateValueX,
                   sizeof(privateValueX));
        }
    }

    /*
     * Allocate output buffer for phase 1 (pLocalOctetStringPV).
     * This the the public value PV as described in PKCS#3.
     */

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pLocalOctetStringPV, sizeof(CpaFlatBuffer));

        if (CPA_STATUS_SUCCESS == status)
        {
            pLocalOctetStringPV->dataLenInBytes =
                pCpaDhOpDataP1->primeP.dataLenInBytes;
            status = PHYS_CONTIG_ALLOC(&pLocalOctetStringPV->pData,
                                       pLocalOctetStringPV->dataLenInBytes);
        }
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Perform Diffie-Hellman Phase 1 operation */
        PRINT_DBG("calling cpaCyDhKeyGenPhase1\n");
        PRINT_DBG("Phase 1: generate the public value from the p, g and x\n");

        //<snippet name="ph1OpPerform">
        status = cpaCyDhKeyGenPhase1(
            cyInstHandle,
            NULL,                 /* synchronous mode */
            pCallbackTagPh1,      /* Opaque user data; */
            pCpaDhOpDataP1,       /* Structure containing p, g and x*/
            pLocalOctetStringPV); /* Public value (function output) */
                                  //</snippet>

        if (CPA_STATUS_SUCCESS != status)
        {
            /* Not a success; could be a retry, a fail, an invalid param or
             * a resource issue */
            PRINT_ERR("cpaCyDhKeyGenPhase1() not a success. (status = %d)\n",
                      status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Allocate memory for the pOctetStringSecretKey */
        status = OS_MALLOC(&pOctetStringSecretKey, sizeof(CpaFlatBuffer));

        if (CPA_STATUS_SUCCESS == status)
        {
            /** Set the data length */
            pOctetStringSecretKey->dataLenInBytes =
                pCpaDhOpDataP1->primeP.dataLenInBytes;
            /** Allocate memory for the pOctetStringSecretKey pData*/
            status = PHYS_CONTIG_ALLOC(&pOctetStringSecretKey->pData,
                                       pOctetStringSecretKey->dataLenInBytes);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("In a typical application, the public value would be sent to "
                  "B\n");
        PRINT_DBG("and the remoteOctetvalue would be returned\n");
        /** In a typical application, at this stage, the public information
         * (prime number, base and the public value that has just been
         * calculated by cpaCyDhKeyGenPhase1) would be sent to the other user.
         * As cpaCyDhKeyGenPhase1 runs in synchronous mode, it is sure that the
         * public value has been calculated.
         * The user would then send back a remoteOctet value.
         */
        status =
            OS_MALLOC(&pCpaDhOpDataP2, sizeof(CpaCyDhPhase2SecretKeyGenOpData));

        if (CPA_STATUS_SUCCESS == status)
        {
            memset(pCpaDhOpDataP2, 0, sizeof(CpaCyDhPhase2SecretKeyGenOpData));

            pCpaDhOpDataP2->primeP.pData = pCpaDhOpDataP1->primeP.pData;
            pCpaDhOpDataP2->primeP.dataLenInBytes =
                pCpaDhOpDataP1->primeP.dataLenInBytes;
            pCpaDhOpDataP2->remoteOctetStringPV.pData =
                pLocalOctetStringPV->pData;
            pCpaDhOpDataP2->remoteOctetStringPV.dataLenInBytes =
                pLocalOctetStringPV->dataLenInBytes;
            pCpaDhOpDataP2->privateValueX.pData =
                pCpaDhOpDataP1->privateValueX.pData;
            pCpaDhOpDataP2->privateValueX.dataLenInBytes =
                pCpaDhOpDataP1->privateValueX.dataLenInBytes;

            /** Perform Diffie-Hellman Phase 2 operation */
            PRINT_DBG("cpaCyDhKeyGenPhase2Secret\n");
            PRINT_DBG("Phase 2: generate the private key\n");

            COMPLETION_INIT(&complete);

            //<snippet name="ph2OpPerform">
            status = cpaCyDhKeyGenPhase2Secret(
                cyInstHandle,
                (const CpaCyGenFlatBufCbFunc)asymCallback, /* CB function*/
                pCallbackTagPh2, /* pointer to the complete variable*/
                pCpaDhOpDataP2,  /* structure containing p, the public value &
                                    x*/
                pOctetStringSecretKey); /* private key (output of the
                                           function)*/
            //</snippet>

            if (CPA_STATUS_SUCCESS != status)
            {
                /* Not a success; could be a retry, a fail, an invalid param or
                 * a resource issue */
                PRINT_ERR("cpaCyDhKeyGenPhase2Secret() not a success. "
                          "(status = %d)\n",
                          status);
            }
        }
    }

    /** wait until the completion of the operation*/
    if (CPA_STATUS_SUCCESS == status)
    {
        if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
        {
            PRINT_ERR("timeout or interruption in cpaCyDhKeyGenPhase2Secret\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /* Free Flat Buffers */
    if (NULL != pLocalOctetStringPV)
    {
        PHYS_CONTIG_FREE(pLocalOctetStringPV->pData);
    }
    if (NULL != pOctetStringSecretKey)
    {
        PHYS_CONTIG_FREE(pOctetStringSecretKey->pData);
    }
    OS_FREE(pLocalOctetStringPV);
    OS_FREE(pOctetStringSecretKey);

    /* Free buffers */
    if (NULL != pCpaDhOpDataP1)
    {
        PHYS_CONTIG_FREE(pCpaDhOpDataP1->primeP.pData);
        PHYS_CONTIG_FREE(pCpaDhOpDataP1->baseG.pData);
        PHYS_CONTIG_FREE(pCpaDhOpDataP1->privateValueX.pData);
    }
    OS_FREE(pCpaDhOpDataP1);
    OS_FREE(pCpaDhOpDataP2);

    COMPLETION_DESTROY(&complete);

    return status;
}

CpaStatus dhSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle cyInstHandle = NULL;
    /** Buffer for the stats*/
    CpaCyDhStats64 dhStats = {0};

    PRINT_DBG("start of Diffie-Hellman sample code\n");
    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    sampleCyGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    /* Start Cryptographic component */
    PRINT_DBG("cpaCyStartInstance\n");
    status = cpaCyStartInstance(cyInstHandle);

    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }

    /*
     * Set the address translation function for the instance
     */
    status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
    if (CPA_STATUS_SUCCESS != status)
    {
        cpaCyStopInstance(cyInstHandle);
        return CPA_STATUS_FAIL;
    }

    /*
     * If the instance is polled start the polling thread. Note that
     * how the polling is done is implementation-dependent.
     */
    sampleCyStartPolling(cyInstHandle);

    /** Perform DH operations */
    PRINT_DBG("calling sampleDhPerformOp\n");
    status = sampleDhPerformOp(cyInstHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        /* Not a success; could be a retry, a fail, an invalid param or
         * a resource issue */
        PRINT_ERR("sampleDhPerformOp not a success, status = %d\n", status);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Query Diffie-Hellman statistics */
        PRINT_DBG("cpaCyDhQueryStats\n");
        status = cpaCyDhQueryStats64(cyInstHandle, &dhStats);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyDhQueryStats() failed. (status = %d)\n", status);
            status = CPA_STATUS_FAIL;
        }
        /** Print some stats*/
        PRINT_DBG("Number of successful DH phase 1 key gen request: %llu\n",
                  (unsigned long long)dhStats.numDhPhase1KeyGenRequests);
        /** Print some stats*/
        PRINT_DBG("Number of successful DH phase 2 key gen request: %llu\n",
                  (unsigned long long)dhStats.numDhPhase2KeyGenRequests);
    }

    /* Stop the polling thread */
    sampleCyStopPolling();

    /** Stop Cryptographic instance */
    PRINT_DBG("cpaCyStopInstance\n");
    cpaCyStopInstance(cyInstHandle);

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Sample code ran successfully\n");
    }
    else
    {
        PRINT_DBG("Sample code failed with status of %d\n", status);
    }

    return status;
}
