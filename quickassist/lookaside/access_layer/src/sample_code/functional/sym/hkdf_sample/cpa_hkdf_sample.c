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
 * This is sample code that demonstrates usage of the symmetric API, and
 * specifically using this API to perform a HKDF based operations.
 * It performs HKDF Extract and Expand, and Extract and Expand Label operation
 * without and with sublabels (KEY and IV).
 */
#include "cpa.h"
#include "lac/cpa_cy_key.h"
#include "cpa_sample_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
#define TIMEOUT_MS 5000 /* 5 seconds */

/*
 * Test vectors from RFC 5869
 *   https://tools.ietf.org/html/rfc5869
 */

/* Input Keying Material */
static Cpa8U sampleIkm[] = {0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B};

/* Output Keying Material, NOTE: truncated to 32 bytes */
static Cpa8U sampleOkm[] = {0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A,
                            0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F, 0x2A,
                            0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
                            0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF};

/* Pseudorandom Key */
static Cpa8U samplePrk[] = {0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF,
                            0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA, 0x63,
                            0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31,
                            0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5};

/* Salt */
static Cpa8U sampleSlt[] = {0x00,
                            0x01,
                            0x02,
                            0x03,
                            0x04,
                            0x05,
                            0x06,
                            0x07,
                            0x08,
                            0x09,
                            0x0A,
                            0x0B,
                            0x0C};

/* Info */
static Cpa8U sampleInf[] =
    {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9};

/* Expand and extarct label random input data */

static Cpa8U sampleSeedLabel[] = {
    0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54,
    0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48,
    0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba};

static Cpa8U sampleSecretLabel[] = {
    0x35, 0x75, 0x4d, 0x42, 0xc9, 0x9c, 0xd5, 0x10, 0x80, 0x6f, 0x5a,
    0xfa, 0x87, 0x0c, 0x44, 0xad, 0x98, 0x03, 0x96, 0x81, 0xa6, 0x18,
    0xb2, 0xd4, 0xd0, 0x59, 0x1b, 0xd9, 0xd2, 0x77, 0x4d, 0x21};

static Cpa8U samplePrkExpected[] = {
    0x9e, 0x9b, 0xc0, 0x58, 0x69, 0x09, 0x24, 0xb5, 0x6d, 0xe4, 0x34,
    0x67, 0x75, 0x38, 0xec, 0x25, 0x9f, 0x61, 0x38, 0xd4, 0x55, 0x4d,
    0x93, 0xa3, 0xe7, 0x09, 0xfc, 0xcc, 0xe8, 0x65, 0x93, 0x57};

static Cpa8U sampleLabel[] = {
    0x00, 0x20, 0x12, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73, 0x20,
    0x68, 0x73, 0x20, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x20,
    0xc7, 0x45, 0x3c, 0x9b, 0xf5, 0x6c, 0xff, 0x11, 0x28, 0x71, 0x66,
    0x54, 0xfc, 0x74, 0xc4, 0x88, 0xaf, 0x38, 0x60, 0xae, 0xf7, 0xac,
    0x98, 0x5a, 0x83, 0x5b, 0xde, 0x97, 0x82, 0xa4, 0xa6, 0x66};

static Cpa8U sampleExpandExpected[] = {
    0xbf, 0x29, 0x72, 0xc5, 0x27, 0x66, 0x00, 0xcc, 0xbc, 0x58, 0x2d,
    0x22, 0x6d, 0x5d, 0x63, 0x83, 0x4d, 0xb8, 0x3e, 0x49, 0x5d, 0x16,
    0x35, 0x58, 0xf4, 0x00, 0xbf, 0x1a, 0x88, 0x17, 0x56, 0xe5};

static Cpa8U sampleKeyExpected[] = {0x10,
                                    0x68,
                                    0x5e,
                                    0xe5,
                                    0x2a,
                                    0x2d,
                                    0xcb,
                                    0x25,
                                    0x1c,
                                    0x76,
                                    0xe5,
                                    0xa8,
                                    0x51,
                                    0x4e,
                                    0x3e,
                                    0x9d};

static Cpa8U sampleIvExpected[] =
    {0xec, 0x63, 0xaa, 0x6d, 0x39, 0xc2, 0xb9, 0x94, 0x80, 0x3d, 0x24, 0xd9};

extern int gDebugParam;

static void hkdfSampleCallback(void *pCallbackTag,
                               CpaStatus status,
                               void *pOpData,
                               CpaFlatBuffer *pOut)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    if (NULL != pCallbackTag)
    {
        /* indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

static void print_buffer(const char *name, Cpa8U *buffer, Cpa32U bufferSize)
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

    if (memcmp(buffer, expected, sizeof(bufferSize)) != 0)
    {
        PRINT_ERR("ERROR: %s doesn't match\n", name);
        print_buffer("ACTUAL:", buffer, bufferSize);
        print_buffer("EXPECTED:", expected, bufferSize);

        status = CPA_STATUS_FAIL;
    }
    else
    {
        PRINT("%s correct\n", name);
    }

    return status;
}

static CpaStatus hkdfSampleExtractExpandLabelPerform(
    CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 instanceInfo2;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKeyGenHKDFOpData *pOpData = NULL;
    Cpa8U *pHkdfData = NULL;
    Cpa32U hkdfDataSize =
        sizeof(samplePrkExpected) + sizeof(sampleExpandExpected);
    Cpa32U offset = 0;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;
    CpaFlatBuffer hkdfOut;

    status = PHYS_CONTIG_ALLOC(&pHkdfData, hkdfDataSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        hkdfOut.pData = pHkdfData;
        hkdfOut.dataLenInBytes = hkdfDataSize;

        status = cpaCyInstanceGetInfo2(cyInstHandle, &instanceInfo2);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PHYS_CONTIG_ALLOC_ALIGNED(
            &pOpData, sizeof(CpaCyKeyGenHKDFOpData), BYTE_ALIGNMENT_64);

        if (!pOpData)
        {
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        pOpData->hkdfKeyOp = CPA_CY_HKDF_KEY_EXTRACT_EXPAND_LABEL;

        pOpData->seedLen = sizeof(sampleSeedLabel);
        memcpy(pOpData->seed, sampleSeedLabel, sizeof(sampleSeedLabel));

        pOpData->secretLen = sizeof(sampleSecretLabel);
        memcpy(pOpData->secret, sampleSecretLabel, sizeof(sampleSecretLabel));

        pOpData->numLabels = 1;

        memcpy(pOpData->label[0].label, sampleLabel, sizeof(sampleLabel));
        pOpData->label[0].labelLen = sizeof(sampleLabel);
        pOpData->label[0].sublabelFlag = 0x00;
    }

    /*
     * Now, we initialize the completion variable which is used by the callback
     * function
     * to indicate that the operation is complete.  We then perform the
     * operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCyKeyGenTls3\n");

        COMPLETION_INIT(&complete);

        status = cpaCyKeyGenTls3(cyInstHandle,
                                 hkdfSampleCallback,
                                 (void *)&complete,
                                 pOpData,
                                 CPA_CY_HKDF_TLS_AES_128_GCM_SHA256,
                                 &hkdfOut);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyKeyGenTls failed. (status = %d)\n", status);
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
            status = checkResult("PRK",
                                 hkdfOut.pData,
                                 samplePrkExpected,
                                 sizeof(samplePrkExpected));
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            offset += sizeof(samplePrkExpected);

            status = checkResult("LABEL",
                                 hkdfOut.pData + offset,
                                 sampleExpandExpected,
                                 sizeof(sampleExpandExpected));
        }
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    PHYS_CONTIG_FREE(pHkdfData);
    PHYS_CONTIG_FREE(pOpData);

    COMPLETION_DESTROY(&complete);

    return status;
}

static CpaStatus hkdfSampleExtractExpandLabelSublabelsPerform(
    CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 instanceInfo2;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKeyGenHKDFOpData *pOpData = NULL;
    Cpa8U *pHkdfData = NULL;
    Cpa32U offset = 0;
    Cpa32U hkdfDataSize = sizeof(samplePrkExpected) +
                          sizeof(sampleExpandExpected) +
                          sizeof(sampleKeyExpected) + sizeof(sampleIvExpected);

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;
    CpaFlatBuffer hkdfOut;

    status = PHYS_CONTIG_ALLOC(&pHkdfData, hkdfDataSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        hkdfOut.pData = pHkdfData;
        hkdfOut.dataLenInBytes = hkdfDataSize;

        status = cpaCyInstanceGetInfo2(cyInstHandle, &instanceInfo2);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PHYS_CONTIG_ALLOC_ALIGNED(
            &pOpData, sizeof(CpaCyKeyGenHKDFOpData), BYTE_ALIGNMENT_64);

        if (!pOpData)
        {
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        pOpData->hkdfKeyOp = CPA_CY_HKDF_KEY_EXTRACT_EXPAND_LABEL;

        pOpData->seedLen = sizeof(sampleSeedLabel);
        memcpy(pOpData->seed, sampleSeedLabel, sizeof(sampleSeedLabel));

        pOpData->secretLen = sizeof(sampleSecretLabel);
        memcpy(pOpData->secret, sampleSecretLabel, sizeof(sampleSecretLabel));

        pOpData->numLabels = 1;

        memcpy(pOpData->label[0].label, sampleLabel, sizeof(sampleLabel));
        pOpData->label[0].labelLen = sizeof(sampleLabel);
        pOpData->label[0].sublabelFlag = CPA_CY_HKDF_SUBLABEL_KEY;
        pOpData->label[0].sublabelFlag |= CPA_CY_HKDF_SUBLABEL_IV;
    }

    /*
     * Now, we initialize the completion variable which is used by the callback
     * function
     * to indicate that the operation is complete.  We then perform the
     * operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCyKeyGenTls3\n");

        COMPLETION_INIT(&complete);

        status = cpaCyKeyGenTls3(cyInstHandle,
                                 hkdfSampleCallback,
                                 (void *)&complete,
                                 pOpData,
                                 CPA_CY_HKDF_TLS_AES_128_GCM_SHA256,
                                 &hkdfOut);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyKeyGenTls failed. (status = %d)\n", status);
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
            status = checkResult("PRK",
                                 hkdfOut.pData,
                                 samplePrkExpected,
                                 sizeof(samplePrkExpected));
            offset += sizeof(samplePrkExpected);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = checkResult("LABEL",
                                 hkdfOut.pData + offset,
                                 sampleExpandExpected,
                                 sizeof(sampleExpandExpected));
            offset += sizeof(sampleExpandExpected);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = checkResult("KEY",
                                 hkdfOut.pData + offset,
                                 sampleKeyExpected,
                                 sizeof(sampleKeyExpected));
            offset += sizeof(sampleKeyExpected);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = checkResult("IV",
                                 hkdfOut.pData + offset,
                                 sampleIvExpected,
                                 sizeof(sampleIvExpected));
        }
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    PHYS_CONTIG_FREE(pHkdfData);
    PHYS_CONTIG_FREE(pOpData);

    COMPLETION_DESTROY(&complete);

    return status;
}

static CpaStatus hkdfSampleExtractExpandPerform(CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 instanceInfo2;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKeyGenHKDFOpData *pOpData = NULL;
    Cpa8U *pHkdfData = NULL;
    Cpa32U hkdfDataSize = 64;
    Cpa32U offset = 0;

    /* The following variables are allocated on the stack because we block
     * until the callback comes back. If a non-blocking approach was to be
     * used then these variables should be dynamically allocated */
    struct COMPLETION_STRUCT complete;
    CpaFlatBuffer hkdfOut;

    status = PHYS_CONTIG_ALLOC(&pHkdfData, hkdfDataSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        hkdfOut.pData = pHkdfData;
        hkdfOut.dataLenInBytes = hkdfDataSize;

        status = cpaCyInstanceGetInfo2(cyInstHandle, &instanceInfo2);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PHYS_CONTIG_ALLOC_ALIGNED(
            &pOpData, sizeof(CpaCyKeyGenHKDFOpData), BYTE_ALIGNMENT_64);

        if (!pOpData)
        {
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        pOpData->hkdfKeyOp = CPA_CY_HKDF_KEY_EXTRACT_EXPAND;
        pOpData->numLabels = 0;
        pOpData->secretLen = sizeof(sampleIkm);
        memcpy(pOpData->secret, sampleIkm, pOpData->secretLen);
        pOpData->seedLen = sizeof(sampleSlt);
        memcpy(pOpData->seed, sampleSlt, pOpData->seedLen);

        pOpData->infoLen = sizeof(sampleInf);
        memcpy(pOpData->info, sampleInf, pOpData->infoLen);
    }

    /*
     * Now, we initialize the completion variable which is used by the callback
     * function
     * to indicate that the operation is complete.  We then perform the
     * operation.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCyKeyGenTls3\n");

        COMPLETION_INIT(&complete);

        status = cpaCyKeyGenTls3(cyInstHandle,
                                 hkdfSampleCallback,
                                 (void *)&complete,
                                 pOpData,
                                 CPA_CY_HKDF_TLS_AES_128_GCM_SHA256,
                                 &hkdfOut);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyKeyGenTls failed. (status = %d)\n", status);
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
            status =
                checkResult("PRK", hkdfOut.pData, samplePrk, sizeof(samplePrk));
            offset += sizeof(samplePrk);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            status = checkResult(
                "OKM", hkdfOut.pData + offset, sampleOkm, sizeof(sampleOkm));
        }
    }

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    PHYS_CONTIG_FREE(pHkdfData);
    PHYS_CONTIG_FREE(pOpData);

    COMPLETION_DESTROY(&complete);

    return status;
}

CpaStatus hkdfSample(void)
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
        PRINT_ERR("Can not get instance info\n");
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

    status = hkdfSampleExtractExpandPerform(cyInstHandle);
    status |= hkdfSampleExtractExpandLabelPerform(cyInstHandle);
    status |= hkdfSampleExtractExpandLabelSublabelsPerform(cyInstHandle);

    /* Stop the polling thread */
    sampleCyStopPolling();

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
