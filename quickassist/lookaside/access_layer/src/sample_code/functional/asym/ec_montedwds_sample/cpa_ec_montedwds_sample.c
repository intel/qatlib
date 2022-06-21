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
 * This is sample code that demonstrates usage of the asymmetric API, and
 * specifically using this API to perform a cpaCyEcMontEdwdsPointMultiply
 * operations.
 * It uses Twisted Edwards or Montgomery algorithm and curve 448 or 25519 to
 * perform generator multiplication or point multiplication operations.
 */

#include <stdlib.h>
#include <string.h>
#include "cpa.h"
#include "lac/cpa_cy_key.h"
#include "cpa_cy_ec.h"
#include "cpa_sample_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
#define TIMEOUT_MS 5000 /* 5 seconds */

extern int gDebugParam;

/***************************************************************************
 * Input and Output vectors for Public Key Encryption
 * Elliptic Curve (EC) operations.
 ***************************************************************************/
static Cpa8U edwards_448_kp_x[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x2f, 0x7d,
    0x05, 0x80, 0xfd, 0x8e, 0x88, 0xf3, 0xfc, 0x8e, 0xcd, 0x47, 0xf4,
    0x34, 0x99, 0xb0, 0x00, 0x0f, 0xaf, 0x1e, 0x84, 0xd0, 0xc2, 0x28,
    0x37, 0x36, 0xc9, 0x91, 0xc4, 0xa6, 0x44, 0x47, 0xce, 0x4e, 0x8d,
    0x8a, 0x6c, 0x74, 0x01, 0x0b, 0xaf, 0x72, 0x6e, 0xf2, 0x00, 0x06,
    0xbc, 0xf1, 0xfa, 0x99, 0x0e, 0x7a, 0x82, 0x22, 0x87};

static Cpa8U edwards_448_kp_y[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x25, 0xe8,
    0xaf, 0xbe, 0x1a, 0xfa, 0xd1, 0x6c, 0x0f, 0xe5, 0xf1, 0x3d, 0x78,
    0xd6, 0x1b, 0x06, 0xc7, 0x46, 0x9b, 0x76, 0x24, 0xf1, 0xed, 0x78,
    0x67, 0xe9, 0x80, 0x5d, 0xa7, 0x0e, 0x8a, 0x1f, 0x0e, 0xa7, 0x85,
    0x24, 0x34, 0xa1, 0x1d, 0x6a, 0xd4, 0x6a, 0x61, 0xec, 0x87, 0xe7,
    0x2c, 0xfd, 0x61, 0xb4, 0x59, 0x9b, 0x44, 0xd7, 0x5f};

static Cpa8U edwards_448_kp_k[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x03, 0x79,
    0xde, 0x16, 0x3f, 0xfe, 0x49, 0x98, 0x66, 0x1c, 0x2d, 0x46, 0xd9,
    0xdf, 0x0f, 0xff, 0xa8, 0x6e, 0x5f, 0xe7, 0x18, 0xef, 0xc5, 0xa6,
    0xca, 0x51, 0xe7, 0xe9, 0x58, 0xba, 0x02, 0x87, 0x18, 0x61, 0x23,
    0xf9, 0xf0, 0xd3, 0x95, 0x7a, 0x43, 0x5c, 0x13, 0xb3, 0x65, 0xa5,
    0xa1, 0x1f, 0x4c, 0x76, 0x3a, 0xc0, 0x71, 0x26, 0xae};

static Cpa8U edwards_448_kp_u[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdb, 0xb1, 0xfe,
    0xe3, 0x1d, 0x2a, 0x0e, 0x7c, 0x50, 0x08, 0x48, 0xbf, 0x8f, 0x55,
    0x03, 0xc0, 0xe7, 0x5d, 0x62, 0x85, 0xdd, 0x25, 0x83, 0xf2, 0xde,
    0x69, 0xba, 0xa5, 0x34, 0x4a, 0x79, 0x38, 0x77, 0x42, 0xab, 0x20,
    0x80, 0xf5, 0xe0, 0x48, 0xac, 0xd4, 0x59, 0x95, 0xa0, 0x54, 0x53,
    0x61, 0x7f, 0xf4, 0x33, 0x9b, 0xa4, 0xbb, 0x4f, 0x33};

static Cpa8U edwards_448_kp_v[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0xc5, 0x7b,
    0x02, 0x90, 0x55, 0x48, 0x1a, 0x04, 0xf5, 0x37, 0x78, 0x22, 0x54,
    0xc5, 0xe9, 0x38, 0x10, 0x80, 0xca, 0x28, 0x56, 0xfe, 0x51, 0xfa,
    0x91, 0x41, 0x44, 0x26, 0xec, 0x8e, 0xa3, 0xe3, 0xc7, 0x91, 0xf7,
    0x75, 0x28, 0x7e, 0xa3, 0xd4, 0x63, 0xa7, 0x7c, 0x54, 0xd9, 0xbe,
    0xff, 0x74, 0xb1, 0xf3, 0x96, 0xe6, 0x2e, 0x2d, 0x8b};

static Cpa8U montgomery_448_kg_k[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x90, 0x92,
    0x36, 0xd3, 0xaf, 0x35, 0x96, 0x00, 0xd5, 0x41, 0xe6, 0x05, 0xd8,
    0xb7, 0x98, 0x03, 0x35, 0xd1, 0x1a, 0xb4, 0xdc, 0xeb, 0xce, 0x27,
    0x30, 0x5d, 0xef, 0x75, 0x01, 0xda, 0x8c, 0xed, 0x72, 0xca, 0xfc,
    0xa3, 0x20, 0x59, 0x98, 0x41, 0xde, 0x0c, 0x70, 0x73, 0x9f, 0xd8,
    0xad, 0x72, 0xa3, 0xe7, 0x4a, 0x48, 0xb8, 0x09, 0xf2};

static Cpa8U montgomery_448_kg_u[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x61, 0xb9,
    0x75, 0x6f, 0xa4, 0x84, 0x07, 0x52, 0x25, 0x6f, 0xee, 0xa1, 0xcd,
    0xdc, 0x40, 0xc0, 0x09, 0xe5, 0xfc, 0x3f, 0xad, 0x0d, 0x45, 0xfe,
    0x44, 0xdd, 0x26, 0x4e, 0xd0, 0x8d, 0xe7, 0xdb, 0x4a, 0xdb, 0x66,
    0xef, 0x65, 0x78, 0x82, 0xa6, 0xd3, 0xcd, 0x74, 0xb7, 0x29, 0xc0,
    0x4c, 0x66, 0x9d, 0xdf, 0x77, 0x57, 0x0b, 0xec, 0x6e};

static Cpa8U montgomery_25519_kp_x[32] = {
    0x62, 0x9d, 0x47, 0x54, 0x8a, 0x31, 0x49, 0xad, 0xa9, 0x6f, 0x66,
    0x8e, 0x67, 0x49, 0x3a, 0x2a, 0x9c, 0x1e, 0xe4, 0xf5, 0x90, 0xb1,
    0x18, 0xf9, 0xdf, 0x98, 0x01, 0x38, 0x4b, 0x47, 0xe4, 0x05};

static Cpa8U montgomery_25519_kp_k[32] = {
    0x36, 0xd3, 0xe1, 0xe0, 0xde, 0x0c, 0x2e, 0x89, 0xaf, 0x97, 0x57,
    0x05, 0x78, 0xaf, 0x81, 0xdb, 0x9e, 0xa9, 0x9b, 0xc4, 0xb1, 0xb1,
    0x86, 0xfe, 0xa5, 0x7e, 0x16, 0x85, 0x86, 0xe4, 0x45, 0x88};

static Cpa8U montgomery_25519_kp_u[32] = {
    0x1a, 0x0f, 0x77, 0x9c, 0xf1, 0xc8, 0x4a, 0x4b, 0x46, 0x23, 0x01,
    0x28, 0x04, 0x5f, 0x5e, 0x41, 0x84, 0x29, 0xa7, 0x76, 0xba, 0xd8,
    0xfb, 0x84, 0x37, 0x36, 0x4e, 0xc5, 0x18, 0x5d, 0x60, 0xe8};

static void ecMontEdwdsPointMultiplyPerformCallback(void *pCallbackTag,
                                                    CpaStatus status,
                                                    void *pOpData,
                                                    CpaBoolean multiplyStatus,
                                                    CpaFlatBuffer *pXk,
                                                    CpaFlatBuffer *pYk)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
}

static void printBuffer(const char *name, Cpa8U *buffer, Cpa32U bufferSize)
{
    int i = 0;

    PRINT("%s\n", name);
    for (i = 0; i < bufferSize; i++)
        PRINT("%02x ", buffer[i]);
    PRINT("\n");

    return;
}

static CpaStatus checkResult(const char *name,
                             Cpa8U *buffer,
                             Cpa8U *expected,
                             Cpa32U bufferSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (memcmp(buffer, expected, bufferSize) != 0)
    {
        PRINT_ERR("ERROR: %s doesn't match\n", name);
        printBuffer("ACTUAL:", buffer, bufferSize);
        printBuffer("EXPECTED:", expected, bufferSize);

        status = CPA_STATUS_FAIL;
    }
    else
    {
        PRINT("%s correct\n", name);
    }

    return status;
}

static CpaStatus ed448PointSamplePerform(CpaInstanceHandle cyInstHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaCyEcMontEdwdsPointMultiplyOpData *opData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
    Cpa8U *pointX;
    Cpa8U *pointY;
    Cpa8U *pointK;
    Cpa8U dataLenInBytes = 0;

    struct COMPLETION_STRUCT complete;
    COMPLETION_INIT(&complete);

    /* Set test vectors and buffer size */
    PRINT_DBG("Edwards448pPerformOp\n");
    pointX = edwards_448_kp_x;
    pointY = edwards_448_kp_y;
    pointK = edwards_448_kp_k;
    dataLenInBytes = sizeof(edwards_448_kp_k);

    /* Allocate memory for input and output buffers */
    status = OS_MALLOC(&pXk, sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pYk, sizeof(CpaFlatBuffer));
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pXk->dataLenInBytes = dataLenInBytes;
        pYk->dataLenInBytes = dataLenInBytes;
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pXk->pData, dataLenInBytes, BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pYk->pData, dataLenInBytes, BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            OS_MALLOC(&opData, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));
    }
    /* Prepare operation data */
    if (CPA_STATUS_SUCCESS == status)
    {
        opData->generator = CPA_FALSE;
        opData->curveType = CPA_CY_EC_MONTEDWDS_ED448_TYPE;

        PHYS_CONTIG_ALLOC_ALIGNED(
            &opData->x.pData, dataLenInBytes, BYTE_ALIGNMENT_64);
        opData->x.dataLenInBytes = dataLenInBytes;

        PHYS_CONTIG_ALLOC_ALIGNED(
            &opData->y.pData, dataLenInBytes, BYTE_ALIGNMENT_64);
        opData->y.dataLenInBytes = dataLenInBytes;

        PHYS_CONTIG_ALLOC_ALIGNED(
            &opData->k.pData, dataLenInBytes, BYTE_ALIGNMENT_64);
        opData->k.dataLenInBytes = dataLenInBytes;

        /* Verify allocated memory */
        if (!(opData->y.pData) || !(opData->x.pData) || !(opData->k.pData))
        {
            status = CPA_STATUS_FAIL;
        }
        else
        {
            memcpy(opData->y.pData, pointY, dataLenInBytes);
            memcpy(opData->x.pData, pointX, dataLenInBytes);
            memcpy(opData->k.pData, pointK, dataLenInBytes);

            /* Perform operation */
            PRINT_DBG("cpaCyEcMontEdwdsPointMultiply\n");
            status = cpaCyEcMontEdwdsPointMultiply(
                cyInstHandle,
                ecMontEdwdsPointMultiplyPerformCallback,
                (void *)&complete,
                opData,
                &multiplyStatus,
                pXk,
                pYk);
        }
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyEcMontEdwdsPointMultiply failed. (status = %d)\n",
                  status);
    }

    /*
     * We now wait until the polling thread to complete
     * the operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
        {
            PRINT_ERR("timeout or interruption in cpaCyKeyGenTls\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /*
     * Data sanity
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = checkResult("edwards_448_kp_u",
                             pXk->pData,
                             edwards_448_kp_u,
                             sizeof(edwards_448_kp_u));
        if (CPA_STATUS_SUCCESS == status)
        {
            status = checkResult("edwards_448_kp_v",
                                 pYk->pData,
                                 edwards_448_kp_v,
                                 sizeof(edwards_448_kp_v));
        }
    }

    COMPLETION_DESTROY(&complete);
    if (NULL != pXk)
    {
        PHYS_CONTIG_FREE(pXk->pData);
        OS_FREE(pXk);
    }
    if (NULL != pYk)
    {
        PHYS_CONTIG_FREE(pYk->pData);
        OS_FREE(pYk);
    }
    if (NULL != opData)
    {
        PHYS_CONTIG_FREE(opData->k.pData);
        PHYS_CONTIG_FREE(opData->y.pData);
        PHYS_CONTIG_FREE(opData->x.pData);
        OS_FREE(opData);
    }
    return status;
}

static CpaStatus curve448GeneratorSamplePerform(CpaInstanceHandle cyInstHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaCyEcMontEdwdsPointMultiplyOpData *opData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
    Cpa8U *pointK;
    Cpa8U dataLenInBytes = 0;

    struct COMPLETION_STRUCT complete;
    COMPLETION_INIT(&complete);

    /* Set test vectors and buffer size */
    PRINT_DBG("Montgomery448gPerformOp\n");
    pointK = montgomery_448_kg_k;
    dataLenInBytes = sizeof(montgomery_448_kg_k);

    /* Allocate memory for input and output buffers */
    status = OS_MALLOC(&pXk, sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pYk, sizeof(CpaFlatBuffer));
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pXk->dataLenInBytes = dataLenInBytes;
        pYk->dataLenInBytes = dataLenInBytes;
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pXk->pData, dataLenInBytes, BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pYk->pData, dataLenInBytes, BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            OS_MALLOC(&opData, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));
    }

    /* Prepare operation data */
    if (CPA_STATUS_SUCCESS == status)
    {
        opData->generator = CPA_TRUE;
        opData->curveType = CPA_CY_EC_MONTEDWDS_CURVE448_TYPE;

        PHYS_CONTIG_ALLOC_ALIGNED(
            &opData->k.pData, dataLenInBytes, BYTE_ALIGNMENT_64);
        opData->k.dataLenInBytes = dataLenInBytes;

        /* Verify allocated memory */
        if (!(opData->k.pData))
        {
            status = CPA_STATUS_FAIL;
        }
        else
        {
            memcpy(opData->k.pData, pointK, dataLenInBytes);

            /* Perform operation */
            PRINT_DBG("cpaCyEcMontEdwdsPointMultiply\n");
            status = cpaCyEcMontEdwdsPointMultiply(
                cyInstHandle,
                ecMontEdwdsPointMultiplyPerformCallback,
                (void *)&complete,
                opData,
                &multiplyStatus,
                pXk,
                pYk);
        }
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyEcMontEdwdsPointMultiply failed. (status = %d)\n",
                  status);
    }

    /*
     * We now wait until the polling thread to complete
     * the operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
        {
            PRINT_ERR("timeout or interruption in cpaCyKeyGenTls\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /*
     * Data sanity
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = checkResult("montgomery_448_kg_u",
                             pXk->pData,
                             montgomery_448_kg_u,
                             sizeof(montgomery_448_kg_u));
    }

    COMPLETION_DESTROY(&complete);

    if (NULL != pXk)
    {
        PHYS_CONTIG_FREE(pXk->pData);
        OS_FREE(pXk);
    }
    if (NULL != pYk)
    {
        PHYS_CONTIG_FREE(pYk->pData);
        OS_FREE(pYk);
    }
    if (NULL != opData)
    {
        PHYS_CONTIG_FREE(opData->k.pData);
        OS_FREE(opData);
    }

    return status;
}

static CpaStatus curve25519PointSamplePerform(CpaInstanceHandle cyInstHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaCyEcMontEdwdsPointMultiplyOpData *opData = NULL;
    CpaFlatBuffer *pXk = NULL;
    CpaFlatBuffer *pYk = NULL;
    Cpa8U *pointX;
    Cpa8U *pointK;
    Cpa8U dataLenInBytes = 0;

    struct COMPLETION_STRUCT complete;
    COMPLETION_INIT(&complete);

    /* Set test vectors and buffer size */
    PRINT_DBG("Montgomery25519pPerformOp\n");
    pointX = montgomery_25519_kp_x;
    pointK = montgomery_25519_kp_k;
    dataLenInBytes = sizeof(montgomery_25519_kp_k);

    /* Allocate memory for input and output buffers */
    status = OS_MALLOC(&pXk, sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pYk, sizeof(CpaFlatBuffer));
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pXk->dataLenInBytes = dataLenInBytes;
        pYk->dataLenInBytes = dataLenInBytes;
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pXk->pData, dataLenInBytes, BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pYk->pData, dataLenInBytes, BYTE_ALIGNMENT_64);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            OS_MALLOC(&opData, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));
    }

    /* Prepare operation data */
    if (CPA_STATUS_SUCCESS == status)
    {
        opData->generator = CPA_FALSE;
        opData->curveType = CPA_CY_EC_MONTEDWDS_CURVE25519_TYPE;

        PHYS_CONTIG_ALLOC_ALIGNED(
            &opData->x.pData, dataLenInBytes, BYTE_ALIGNMENT_64);
        opData->x.dataLenInBytes = dataLenInBytes;

        PHYS_CONTIG_ALLOC_ALIGNED(
            &opData->k.pData, dataLenInBytes, BYTE_ALIGNMENT_64);
        opData->k.dataLenInBytes = dataLenInBytes;

        /* Verify allocated memory */
        if (!(opData->x.pData) || !(opData->k.pData))
        {
            status = CPA_STATUS_FAIL;
        }
        else
        {
            memcpy(opData->x.pData, pointX, dataLenInBytes);
            memcpy(opData->k.pData, pointK, dataLenInBytes);

            /* Perform operation */
            PRINT_DBG("cpaCyEcMontEdwdsPointMultiply\n");
            status = cpaCyEcMontEdwdsPointMultiply(
                cyInstHandle,
                ecMontEdwdsPointMultiplyPerformCallback,
                (void *)&complete,
                opData,
                &multiplyStatus,
                pXk,
                pYk);
        }
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyEcMontEdwdsPointMultiply failed. (status = %d)\n",
                  status);
    }

    /*
     * We now wait until the polling thread to complete
     * the operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
        {
            PRINT_ERR("timeout or interruption in cpaCyKeyGenTls\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /*
     * Data sanity
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = checkResult("montgomery_25519_kp_u",
                             pXk->pData,
                             montgomery_25519_kp_u,
                             sizeof(montgomery_25519_kp_u));
        PHYS_CONTIG_FREE(opData->x.pData);
    }

    COMPLETION_DESTROY(&complete);
    if (NULL != pXk)
    {
        PHYS_CONTIG_FREE(pXk->pData);
        OS_FREE(pXk);
    }
    if (NULL != pYk)
    {
        PHYS_CONTIG_FREE(pYk->pData);
        OS_FREE(pYk);
    }
    if (NULL != opData)
    {
        PHYS_CONTIG_FREE(opData->k.pData);
        PHYS_CONTIG_FREE(opData->x.pData);
        OS_FREE(opData);
    }
    return status;
}

CpaStatus ecMontEdwdsSample(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle cyInstHandle = NULL;
    CpaInstanceInfo2 info = {0};

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    sampleCyGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    status = cpaCyInstanceGetInfo2(cyInstHandle, &info);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Cannot get instance info\n");
        return status;
    }

    /* Start Cryptographic component */
    PRINT_DBG("cpaCyStartInstance\n");
    status = cpaCyStartInstance(cyInstHandle);

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    /*
     * If the instance is polled start the polling thread. Note that
     * how the polling is done is implementation-dependent.
     */
    sampleCyStartPolling(cyInstHandle);

    status = ed448PointSamplePerform(cyInstHandle);
    status |= curve448GeneratorSamplePerform(cyInstHandle);
    status |= curve25519PointSamplePerform(cyInstHandle);

    /* Stop the polling thread */
    sampleCyStopPolling();

    /* Stop Cryptographic component */
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
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
