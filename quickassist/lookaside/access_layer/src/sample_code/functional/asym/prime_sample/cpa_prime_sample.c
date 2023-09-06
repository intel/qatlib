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
 * This is sample code that uses the primality testing APIs. A hard-coded
 * prime number is tested with four different algorithms:
 *
 * - GCD primality test
 * - Fermat primality test
 * - Miller-Rabin primality test. This test requires random numbers that are
 *   also hardcoded here (see unsigned char MR[])
 * - Lucas primality test
 */

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_prime.h"

#include "cpa_sample_utils.h"

#define NB_MR_ROUNDS 2
#define TIMEOUT_MS 5000 /* 5 seconds*/

extern int gDebugParam;

/* Sample prime number: we want to test the primality of this number */
static Cpa8U samplePrimeP_768[] = {
    0xDF, 0x3A, 0xD3, 0x1F, 0x2B, 0x41, 0xC5, 0xE8, 0x36, 0x61, 0xAD, 0x36,
    0x23, 0xDD, 0xD0, 0x47, 0x8A, 0xB5, 0x06, 0xAA, 0x96, 0x43, 0xC9, 0xD6,
    0xC4, 0x5B, 0x43, 0x4C, 0xE7, 0x74, 0x47, 0xF6, 0x5A, 0xA9, 0x9A, 0xA1,
    0x3D, 0x38, 0xAD, 0xC1, 0x7E, 0x7A, 0x6E, 0x31, 0x95, 0xB4, 0xD2, 0xF2,
    0xD4, 0x6C, 0x6D, 0x87, 0x32, 0x52, 0xF8, 0xE9, 0xC8, 0xDF, 0x1D, 0xDA,
    0x16, 0x1C, 0xCB, 0x2B, 0x2C, 0x1D, 0x32, 0x4D, 0x7C, 0x82, 0x8E, 0x29,
    0xA6, 0x3F, 0xD9, 0x0C, 0xD4, 0xCE, 0x9E, 0x2D, 0x40, 0xC9, 0x2C, 0x9C,
    0x0F, 0xBE, 0x5D, 0x6E, 0x68, 0x5A, 0xEB, 0x0F, 0x5D, 0xDF, 0xBF, 0x7D};

/* Concatenation of two 768 bit length random numbers. Each of these numbers
 * will be used for Miller-Rabin primality test and has to be greater than
 * 1 and smaller than the number to test - 1 */
static Cpa8U MR[] = {
    0x00, 0x00, 0x18, 0xB5, 0x71, 0xE1, 0xE0, 0x7C, 0x70, 0x66, 0x5F, 0xD8,
    0x8B, 0xD9, 0xC2, 0x55, 0x3E, 0xD7, 0x09, 0x68, 0x80, 0xF2, 0x17, 0x1A,
    0x7A, 0x6D, 0xC9, 0x24, 0xF2, 0x5C, 0x84, 0x7D, 0xB4, 0xC5, 0xA5, 0x40,
    0x9A, 0x3F, 0xB7, 0xBD, 0xD4, 0x66, 0x5F, 0xD8, 0x01, 0xC5, 0x1E, 0xA7,
    0x60, 0x42, 0x2D, 0xF5, 0x16, 0xAF, 0x08, 0x6C, 0xF7, 0xA5, 0x73, 0xAB,
    0x36, 0xB3, 0x6E, 0x5C, 0xE7, 0x8B, 0xD9, 0xC2, 0x3E, 0xD7, 0x09, 0x1B,
    0xF4, 0xD5, 0xD9, 0xF4, 0x46, 0x08, 0xDA, 0x84, 0x0B, 0x34, 0x77, 0x80,
    0xB9, 0x7C, 0x7B, 0xAF, 0x23, 0xEA, 0x6E, 0xF2, 0x45, 0x8C, 0xC0, 0x0B,
    0x00, 0x00, 0x08, 0xB5, 0x71, 0xE1, 0xE0, 0x7C, 0x70, 0x66, 0x5F, 0xD8,
    0x8B, 0xD9, 0xC2, 0x55, 0x3E, 0xD7, 0x09, 0x68, 0x80, 0xF2, 0x17, 0x1A,
    0x7A, 0x6D, 0xC9, 0x24, 0xF2, 0x5C, 0x84, 0x7D, 0xB4, 0x7B, 0xAF, 0xCC,
    0x9A, 0x3F, 0xB7, 0xBD, 0xD4, 0x66, 0x5F, 0xD8, 0x01, 0xC5, 0x1E, 0xA7,
    0x60, 0x42, 0x2D, 0xF5, 0x16, 0xAF, 0x08, 0x6C, 0xF7, 0xA5, 0x73, 0xAB,
    0x36, 0xB3, 0x6E, 0x5C, 0x3E, 0xD7, 0x09, 0x68, 0x80, 0xF2, 0x17, 0x1A,
    0xF4, 0xD5, 0xD8, 0xF4, 0x46, 0x08, 0xDA, 0x84, 0x0B, 0x34, 0x77, 0x80,
    0xB9, 0x7C, 0x7B, 0xAF, 0x23, 0xEA, 0x6E, 0xF2, 0x45, 0x8C, 0xC0, 0x00};

/* Forward declaration */
CpaStatus primeSample(void);

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
 * etc.  In this example, the function prints out the status of the
 * primality test, and sets the complete variable to indicate it has
 * been called.
 */
static void primeCallback(void *pCallbackTag,
                          CpaStatus status,
                          void *pOpData,
                          CpaBoolean testPassed)
{
    PRINT_DBG("primeCallback, status = %d.\n", status);
    if (NULL == pOpData)
    {
        PRINT_ERR("pOpData is null, status = %d\n", status);
        return;
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("callback failed, status = %d\n", status);
    }

    PRINT_DBG("Result of the test: ");
    if (CPA_TRUE == testPassed)
    {
        /* these algorithms can not guarantee that the number is prime: we
         * can only say it is prime with a high probability */
        PRINT_DBG("the number is probably a prime\n");
    }
    else
    {
        PRINT_DBG("the number is not a prime: testPassed = %d\n", testPassed);
    }

    COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
}

/*
 * Perform a primality test operation on an hardcoded prime number
 */
static CpaStatus primePerformOp(CpaInstanceHandle cyInstHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /** Default is false (meaning the number is not a prime), except if the
     *  test explicitly says it is probably a prime */
    CpaBoolean testPassed = CPA_FALSE;
    /* Prime buffer */
    Cpa8U *pPrime = NULL;
    Cpa8U *pMR = NULL;
    struct COMPLETION_STRUCT complete;

    /** Structure containing the operational data */
    CpaCyPrimeTestOpData *pPrimeTestOpData = NULL;

    PRINT_DBG("primePerformOp\n");

    COMPLETION_INIT(&complete);

    status = PHYS_CONTIG_ALLOC(&pPrime, sizeof(samplePrimeP_768));

    if (NULL != pPrime)
    {
        memcpy(pPrime, samplePrimeP_768, sizeof(samplePrimeP_768));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pMR, sizeof(MR));

        if (NULL != pMR)
        {
            memcpy(pMR, MR, sizeof(MR));
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pPrimeTestOpData, sizeof(CpaCyPrimeTestOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Populate the structure containing the data about the number to test:
         * - the number of which we want to test the primality
         * - its length
         * - perform a GCD Primality Test
         * - perform a Fermat Primality Test
         * - number of Miller-Rabin rounds to perform (from 0 to 50)
         * - Miller-Rabin random numbers (one for each test)
         * - perform a Lucas Primality Test */
        //<snippet name="opDataAndPerform">
        pPrimeTestOpData->primeCandidate.pData = pPrime;
        pPrimeTestOpData->primeCandidate.dataLenInBytes =
            sizeof(samplePrimeP_768);
        pPrimeTestOpData->performGcdTest = CPA_TRUE;
        pPrimeTestOpData->performFermatTest = CPA_TRUE;
        pPrimeTestOpData->numMillerRabinRounds = NB_MR_ROUNDS;
        pPrimeTestOpData->millerRabinRandomInput.pData = pMR;
        pPrimeTestOpData->millerRabinRandomInput.dataLenInBytes = sizeof(MR);
        pPrimeTestOpData->performLucasTest = CPA_TRUE;

        status = cpaCyPrimeTest(
            cyInstHandle,
            (const CpaCyPrimeTestCbFunc)primeCallback, /* CB function */
            (void *)&complete,                         /* callback tag */
            pPrimeTestOpData,                          /* operation data */
            &testPassed); /* return value: true if the number is probably
                             a prime, false if it is not a prime */
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Wait until the callback function has been called*/
        if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
        {
            PRINT_ERR("timeout or interruption in cpaCySymPerformOp\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /** Free all allocated structures before exit*/
    PHYS_CONTIG_FREE(pPrime);
    PHYS_CONTIG_FREE(pMR);
    OS_FREE(pPrimeTestOpData);

    COMPLETION_DESTROY(&complete);

    return status;
}

CpaStatus primeSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCyPrimeStats64 primeStats = {0};

    PRINT_DBG("start of Prime sample code\n");

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
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCyStartInstance() failed. (status = %d)\n", status);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("cpaCySetAddressTranslation() failed. (status = %d)\n",
                      status);
            cpaCyStopInstance(cyInstHandle);
            return status;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependent.
         */
        sampleCyStartPolling(cyInstHandle);

        /** Perform Primality test operations */
        status = primePerformOp(cyInstHandle);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("primePerformOp() failed. (status = %d)\n", status);
            sampleCyStopPolling();
            cpaCyStopInstance(cyInstHandle);
            return status;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCyPrimeQueryStats\n");
        status = cpaCyPrimeQueryStats64(cyInstHandle, &primeStats);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("cpaCyPrimeQueryStats() failed. (status = %d)\n", status);
            sampleCyStopPolling();
            cpaCyStopInstance(cyInstHandle);
            return status;
        }
        PRINT_DBG("Number of prime test requests: %llu\n",
                  (unsigned long long)primeStats.numPrimeTestRequests);
    }

    /* Stop the polling thread */
    sampleCyStopPolling();

    /** Stop Cryptographic component */
    PRINT_DBG("cpaCyStopInstance\n");
    status = cpaCyStopInstance(cyInstHandle);

    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("cpaCyStopInstance() failed. (status = %d)\n", status);
        return status;
    }
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
