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
 * @file cpa_sample_code_ecdsa_perf.c
 *
 * @ingroup cryptoThreads
 *
 * @description
 *      This file contains the main ecdsa performance code. This code generates
 *      a random private key, then uses Elliptic curves to get a public key.
 *      A User defined number of  random messages are generated and signed
 *      using the private key. A User defined number of messages are then
 *      verified repeatedly using the public key to  measure performance
 *
 *****************************************************************************/

#include "cpa_cy_ec.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_ec_curves.h"
#include "cpa_cy_im.h"
#ifdef SC_DEV_INFO_ENABLED
#include "cpa_dev.h"
#endif
#ifdef POLL_INLINE
#include "icp_sal_poll.h"
#endif
#include "qat_perf_cycles.h"
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
#include "cpa_sample_code_ecdsa_kpt2_perf.h"
#endif
#endif
#endif

extern Cpa32U packageIdCount_g;
CpaBoolean msgFlagSym2 = CPA_FALSE;

///*
// * ***********************************************************************
// * elliptic curve definitions as defined in:
// *      http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
// * ************************************************************************/

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Callback function for ECDSA verify operations
 ***************************************************************************/
void ecdsaPerformCallback(void *pCallbackTag,
                          CpaStatus status,
                          void *pOpData,
                          CpaBoolean verifyStatus)
{
    processCallback(pCallbackTag);
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Callback function for ECDSA Point Multiply operations
 ***************************************************************************/
void ecdsaPointMultiplyPerformCallback(void *pCallbackTag,
                                       CpaStatus status,
                                       void *pOpData,
                                       CpaBoolean multiplyStatus,
                                       CpaFlatBuffer *pR,
                                       CpaFlatBuffer *pS)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("ECDSA Point Multiply callback failed: status = %d\n",
                  status);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    if (CPA_FALSE == multiplyStatus)
    {
        PRINT_ERR("ECDSA Point Multiply output failed\n");
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    processCallback(pCallbackTag);
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Callback function for ECDSA verify operations
 ***************************************************************************/
void ecdsaSignOnlyPerformCallback(void *pCallbackTag,
                                  CpaStatus status,
                                  void *pOpData,
                                  CpaBoolean multiplyStatus,
                                  CpaFlatBuffer *pR,
                                  CpaFlatBuffer *pS)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("ECDSA Sign RS callback failed: status = %d\n", status);
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    if (CPA_FALSE == multiplyStatus)
    {
        PRINT_ERR("ECDSA Sign RS multiply output failed\n");
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    processCallback(pCallbackTag);
}

#ifdef POLL_INLINE
static void processEcdsaCallback(void *pCallbackTag, CpaStatus status)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    /*check perf_data pointer is valid*/
    if (pPerfData == NULL)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
    }
    /* response has been received */
    pPerfData->responses++;
}

static void calcEcPointCb(void *pCallbackTag,
                          CpaStatus status,
                          void *pOpData,
                          CpaBoolean multiplyStatus,
                          CpaFlatBuffer *pXk,
                          CpaFlatBuffer *pYk)
{
    processEcdsaCallback(pCallbackTag, status);
}

static void ecdsaSignRSCb(void *pCallbackTag,
                          CpaStatus status,
                          void *pOpData,
                          CpaBoolean multiplyStatus,
                          CpaFlatBuffer *pR,
                          CpaFlatBuffer *pS)
{
    processEcdsaCallback(pCallbackTag, status);
}
#endif
/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      get the relevant curve data for the test parameters passed in
 ***************************************************************************/
CpaStatus getCurveData(ecdsa_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numCurves = sizeof(curves_g) / sizeof(ec_curves_t);
    /*loop through the pre-defined curves and match on the nLenInBytes and the
     * fieldType than pass a pointer to the matched curve into the setup
     * structure*/
    for (i = 0; i < numCurves; i++)
    {
        if (curves_g[i].nLenInBytes == setup->nLenInBytes &&
            curves_g[i].fieldType == setup->fieldType)
        {
            break;
        }
    }
    if (i == numCurves)
    {
        PRINT_ERR("Could not find curve data for the user input supplied\n");
        return CPA_STATUS_FAIL;
    }
    /*set the setup to the matched curve*/
    setup->pCurve = &curves_g[i];
    return CPA_STATUS_SUCCESS;
}

#define CALC_EC_POINT_MEM_FREE                                                 \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&opData.a.pData);                              \
        qaeMemFreeNUMA((void **)&opData.b.pData);                              \
        qaeMemFreeNUMA((void **)&opData.q.pData);                              \
        qaeMemFreeNUMA((void **)&opData.xg.pData);                             \
        qaeMemFreeNUMA((void **)&opData.yg.pData);                             \
    } while (0)
/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Calculate a point on an Elliptic curve, using the curve in the setup
 *      parameter and a given k, and place the calculated point in pXk and
 *      pYk
 ***************************************************************************/
CpaStatus calcEcPoint(ecdsa_test_params_t *setup,
                      CpaFlatBuffer *k,
                      CpaFlatBuffer *pXk,
                      CpaFlatBuffer *pYk)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaCyEcPointMultiplyOpData opData = {{0}};
    Cpa32U retries = 0;
    perf_data_t *pPerfData = NULL;
    CpaCyEcPointMultiplyCbFunc cbFunc = NULL;
#ifdef POLL_INLINE
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    if (poll_inline_g)
    {
        cbFunc = calcEcPointCb;
        pPerfData = setup->performanceStats;
        pPerfData->numOperations = SINGLE_OPERATION;
        pPerfData->responses = 0;
    }
#endif

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
    }
#endif

    /*allocate the operation data structure and copy in the elliptic curve
     *  data*/
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pXk,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         CALC_EC_POINT_MEM_FREE);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pYk,
                         setup->nLenInBytes,
                         NULL,
                         0,
                         CALC_EC_POINT_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(opData.a),
                         setup->nLenInBytes,
                         setup->pCurve->a,
                         setup->pCurve->sizeOfa,
                         CALC_EC_POINT_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(opData.b),
                         setup->pCurve->sizeOfb,
                         setup->pCurve->b,
                         setup->pCurve->sizeOfb,
                         CALC_EC_POINT_MEM_FREE);

    //    displayHexArray("opData.b", opData.b.pData,
    //            opData.b.dataLenInBytes);
    //
    //    PRINT("opData.b.dataLenInBytes length =
    //    %u\n",opData.b.dataLenInBytes);

    /* We copy p into q,  the QA API uses q and NIST calls the same thing p*/
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(opData.q),
                         setup->nLenInBytes,
                         setup->pCurve->p,
                         setup->pCurve->sizeOfp,
                         CALC_EC_POINT_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(opData.xg),
                         setup->nLenInBytes,
                         setup->pCurve->xg,
                         setup->pCurve->sizeOfxg,
                         CALC_EC_POINT_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(opData.yg),
                         setup->nLenInBytes,
                         setup->pCurve->yg,
                         setup->pCurve->sizeOfyg,
                         CALC_EC_POINT_MEM_FREE);

    /*make sure the private key is less than the modulus*/
    makeParam1SmallerThanParam2(
        k->pData, opData.q.pData, k->dataLenInBytes, CPA_FALSE);

    opData.k.pData = k->pData;
    opData.k.dataLenInBytes = k->dataLenInBytes;
    /*set h param*/
    opData.h.pData = NULL;
    opData.h.dataLenInBytes = 0;
    /*set fieldType*/
    opData.fieldType = setup->fieldType;

    /*Calculate the point on the curve*/
    do
    {
        status = cpaCyEcPointMultiply(setup->cyInstanceHandle,
                                      cbFunc,
                                      pPerfData,
                                      &opData,
                                      &multiplyStatus,
                                      pXk,
                                      pYk);

        if (CPA_STATUS_RETRY == status)
        {
            retries++;
            /*once we get to many retries, perform a context switch
             * to give the acceleration engine a small break */
            if (RETRY_LIMIT == (retries % (RETRY_LIMIT + 1)))
            {
                AVOID_SOFTLOCKUP;
            }
        }
    } while (CPA_STATUS_RETRY == status);
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

    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to perform cpaCyEcPointMultiply: status: %d\n",
                  status);
        status = CPA_STATUS_FAIL;
        goto exit;
    }
    else
    {
        if (multiplyStatus == CPA_FALSE)
        {
            PRINT_ERR("cpaCyEcPointMultiply status is CPA_FALSE\n");
            status = CPA_STATUS_FAIL;
            goto exit;
        }
    }

exit:
    /*free the memory in the operation data structure*/
    CALC_EC_POINT_MEM_FREE;
#ifdef POLL_INLINE
    qaeMemFree((void **)&instanceInfo2);
#endif
    return status;
}
EXPORT_SYMBOL(calcEcPoint);

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Free any memory allocated in the ecdsaSignRS function
 ***************************************************************************/
#define ECDSA_SIGN_RS_OPDATA_MEM_FREE                                          \
    do                                                                         \
    {                                                                          \
        if (NULL != pSignRSOpData->a.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->a.pData);                  \
        if (NULL != pSignRSOpData->b.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->b.pData);                  \
        if (NULL != pSignRSOpData->k.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->k.pData);                  \
        if (NULL != pSignRSOpData->n.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->n.pData);                  \
        if (NULL != pSignRSOpData->q.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->q.pData);                  \
        if (NULL != pSignRSOpData->xg.pData)                                   \
            qaeMemFreeNUMA((void **)&pSignRSOpData->xg.pData);                 \
        if (NULL != pSignRSOpData->yg.pData)                                   \
            qaeMemFreeNUMA((void **)&pSignRSOpData->yg.pData);                 \
        if (NULL != pSignRSOpData->d.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->d.pData);                  \
        if (NULL != pSignRSOpData->m.pData)                                    \
            qaeMemFreeNUMA((void **)&pSignRSOpData->m.pData);                  \
        if (NULL != pDigest->pData)                                            \
            qaeMemFreeNUMA((void **)&pDigest->pData);                          \
    } while (0)

CpaStatus ecdsaSignRSOpDataSetup(ecdsa_test_params_t *setup,
                                 CpaFlatBuffer *d,
                                 CpaFlatBuffer *r,
                                 CpaFlatBuffer *s,
                                 CpaFlatBuffer *message,
                                 CpaFlatBuffer *z,
                                 CpaFlatBuffer *pDigest,
                                 perf_data_t *pEcdsaData,
                                 CpaCyEcdsaSignRSOpData *pSignRSOpData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyCapabilitiesInfo cap = {0};
    /*allocate memory for a SHA512 digest*/
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         pDigest,
                         SHA512_DIGEST_LENGTH_IN_BYTES,
                         NULL,
                         0,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);
    /*allocate sign parameters*/
    generateRandomData(message->pData, message->dataLenInBytes);
/*Calculate the digest of the message*/

    status = getCySpecificInstanceCapabilities(setup->cyInstanceHandle, &cap);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("getCyInstanceCapabilities failed with status: %d\n", status);
        return status;
    }

    if (cap.symSupported == CPA_FALSE)
    {
        if (msgFlagSym2 == CPA_FALSE)
        {
            PRINT(
                "ECDSA Warning! SYMMETRIC operation is not supported on Instance.\
                   Using calcSWDigest instead.\n");
            msgFlagSym2 = CPA_TRUE;
        }
        status = calcSWDigest(message, pDigest, CPA_CY_SYM_HASH_SHA512);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("ECDSA Calc Digest Error hashAlg %u\n",
                      CPA_CY_SYM_HASH_SHA512);
        }
    }
    else
    {
        status = calcDigest(
            setup->cyInstanceHandle, message, pDigest, CPA_CY_SYM_HASH_SHA512);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("ECDSA Calc Digest Error hashAlg %u\n",
                      CPA_CY_SYM_HASH_SHA512);
            return status;
        }
    }

    /*copy left most Bytes of digest into z parameter, the length should
     * be equal or less than SHA512_DIGEST_LENGTH_IN_BYTES*/
    memcpy(z->pData, pDigest->pData, z->dataLenInBytes);

    /*set the opData parameters for signing the message*/
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->a),
                         setup->nLenInBytes,
                         setup->pCurve->a,
                         setup->pCurve->sizeOfa,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->b),
                         setup->nLenInBytes,
                         setup->pCurve->b,
                         setup->pCurve->sizeOfb,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->k),
                         setup->nLenInBytes,
                         NULL,
                         0,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);
    generateRandomData(pSignRSOpData->k.pData, pSignRSOpData->k.dataLenInBytes);
    /*k is a value >0 and < the order of the base point*/
    makeParam1SmallerThanParam2(pSignRSOpData->k.pData,
                                setup->pCurve->r,
                                pSignRSOpData->k.dataLenInBytes,
                                CPA_FALSE);

    /* we copy r into n, the QA API uses the parameter n as the order of the
     * base point, the NIST definition of the same is r*/
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->n),
                         setup->nLenInBytes,
                         setup->pCurve->r,
                         setup->pCurve->sizeOfr,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);

    /* We copy p into q,  the QA API uses q and NIST calls the same thing p*/
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->q),
                         setup->nLenInBytes,
                         setup->pCurve->p,
                         setup->pCurve->sizeOfp,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->xg),
                         setup->nLenInBytes,
                         setup->pCurve->xg,
                         setup->pCurve->sizeOfxg,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->yg),
                         setup->nLenInBytes,
                         setup->pCurve->yg,
                         setup->pCurve->sizeOfyg,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);
    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->d),
                         d->dataLenInBytes,
                         d->pData,
                         d->dataLenInBytes,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);

    ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                         &(pSignRSOpData->m),
                         z->dataLenInBytes,
                         z->pData,
                         z->dataLenInBytes,
                         ECDSA_SIGN_RS_OPDATA_MEM_FREE);

    pSignRSOpData->fieldType = setup->fieldType;

    return status;
}
EXPORT_SYMBOL(ecdsaSignRSOpDataSetup);

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Sign the digest of a random message using elliptic curve data in setup
 *      parameter
 ***************************************************************************/
CpaStatus ecdsaSignRS(ecdsa_test_params_t *setup,
                      CpaFlatBuffer *d,
                      CpaFlatBuffer *r,
                      CpaFlatBuffer *s,
                      CpaFlatBuffer *message,
                      CpaFlatBuffer *z,
                      CpaCyEcdsaSignRSCbFunc cbFunc,
                      perf_data_t *pEcdsaData)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean signStatus = CPA_FALSE;
    Cpa32U node = 0;
    CpaCyEcdsaSignRSOpData *pSignRSOpData = NULL;
    CpaFlatBuffer *pDigest = NULL;
    Cpa32U retries = 0;
    perf_data_t *pPerfData = NULL;
    CpaCyEcdsaSignRSCbFunc signRSCbFunc = NULL;
    CpaInstanceInfo2 *instanceInfo2 = NULL;
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    CpaCyKptEcdsaSignRSOpData *pKPTSignRSOpData = NULL;
    CpaCyKptUnwrapContext *pKptUnwrapCtx = NULL;
    Cpa32U keyProvisionRetryTimes = 0;
    /*SWK*/
    Cpa8U sampleSWK[SWK_LEN_IN_BYTES] = {0};

    Cpa8U iv[IV_LEN_IN_BYTES] = {0};
    CpaStatus delKeyStatus = CPA_STATUS_SUCCESS;
    CpaCyKptKeyManagementStatus kpt2Status = CPA_CY_KPT_SUCCESS;
    Cpa8U kpt2Ecdsa_AAD_P256[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
    Cpa8U kpt2Ecdsa_AAD_P384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
    Cpa8U kpt2Ecdsa_AAD_P521[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
#endif
#endif
#endif

#ifdef POLL_INLINE
    CpaBoolean isPolled = CPA_FALSE;
    if (poll_inline_g)
    {
        pPerfData = setup->performanceStats;
        signRSCbFunc = ecdsaSignRSCb;
        pPerfData->numOperations = SINGLE_OPERATION;
        pPerfData->responses = 0;
    }
#endif

    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return status;
    }

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
    if (instanceInfo2->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo2->physInstId.packageId;
    }
#ifdef POLL_INLINE
    isPolled = instanceInfo2->isPolled;
#endif
    qaeMemFree((void **)&instanceInfo2);

    pSignRSOpData = qaeMemAlloc(sizeof(CpaCyEcdsaSignRSOpData));
    if (NULL == pSignRSOpData)
    {
        PRINT_ERR("Cannot allocate memory for CpaCyEcdsaSignRSOpData\n");
        return CPA_STATUS_FAIL;
    }

    pDigest = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pDigest)
    {
        PRINT_ERR("Cannot allocate memory for CpaCyEcdsaSignRSOpData\n");
        qaeMemFree((void **)&pSignRSOpData);
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS !=
        ecdsaSignRSOpDataSetup(
            setup, d, r, s, message, z, pDigest, pEcdsaData, pSignRSOpData))
    {
        PRINT_ERR("ecdsaSignRSOpDataSetup error, status: %d\n", status);
        qaeMemFree((void **)&(pSignRSOpData));
        qaeMemFree((void **)&(pDigest));
        return CPA_STATUS_FAIL;
    }
    /*perform the sign operation*/
    do
    {
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == setup->enableKPT)
        {
            generateRandomData(sampleSWK, SWK_LEN_IN_BYTES);
            generateRandomData(iv, IV_LEN_IN_BYTES);

            pKPTSignRSOpData = qaeMemAllocNUMA(
                sizeof(CpaCyKptEcdsaSignRSOpData *), node, BYTE_ALIGNMENT_64);
            if (NULL == pKPTSignRSOpData)
            {
                PRINT_ERR("pKPTSignRSOpData qaeMemAlloc error\n");
                return CPA_STATUS_FAIL;
            }

            pKptUnwrapCtx = qaeMemAllocNUMA(
                sizeof(CpaCyKptUnwrapContext), node, BYTE_ALIGNMENT_64);
            if (NULL == pKptUnwrapCtx)
            {
                PRINT_ERR("pKptUnwrapCtx qaeMemAlloc error\n");
                kpt2EcdsaFreeDataMemory(pKPTSignRSOpData, pKptUnwrapCtx);
                return CPA_STATUS_FAIL;
            }
            status = encryptAndLoadSWK(
                setup->cyInstanceHandle, &setup->kptKeyHandle, sampleSWK);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("encryptAndLoadSWKs failed!\n");
                kpt2EcdsaFreeDataMemory(pKPTSignRSOpData, pKptUnwrapCtx);
                return status;
            }

            pKptUnwrapCtx->kptHandle = setup->kptKeyHandle;
            memcpy(pKptUnwrapCtx->iv, iv, IV_LEN_IN_BYTES);
            switch (setup->nLenInBytes)
            {
                case GFP_P256_SIZE_IN_BYTES:
                    memcpy(pKptUnwrapCtx->additionalAuthData,
                           kpt2Ecdsa_AAD_P256,
                           sizeof(kpt2Ecdsa_AAD_P256));
                    pKptUnwrapCtx->aadLenInBytes = sizeof(kpt2Ecdsa_AAD_P256);
                    break;
                case GFP_P384_SIZE_IN_BYTES:
                    memcpy(pKptUnwrapCtx->additionalAuthData,
                           kpt2Ecdsa_AAD_P384,
                           sizeof(kpt2Ecdsa_AAD_P384));
                    pKptUnwrapCtx->aadLenInBytes = sizeof(kpt2Ecdsa_AAD_P384);
                    break;
                case GFP_P521_SIZE_IN_BYTES:
                    memcpy(pKptUnwrapCtx->additionalAuthData,
                           kpt2Ecdsa_AAD_P521,
                           sizeof(kpt2Ecdsa_AAD_P521));
                    pKptUnwrapCtx->aadLenInBytes = sizeof(kpt2Ecdsa_AAD_P521);
                    break;
                default:
                    PRINT_ERR("Curve size(%d) not supported by kpt!\n",
                              setup->nLenInBytes);
                    kpt2EcdsaFreeDataMemory(pKPTSignRSOpData, pKptUnwrapCtx);
                    return CPA_STATUS_FAIL;
            }
            status = setKPT2EcdsaSignRSOpData(setup->cyInstanceHandle,
                                              pKPTSignRSOpData,
                                              pSignRSOpData,
                                              sampleSWK,
                                              iv,
                                              pKptUnwrapCtx->additionalAuthData,
                                              pKptUnwrapCtx->aadLenInBytes);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("setKPTEcdsaSignRSOpData failed!\n");
                kpt2EcdsaFreeDataMemory(pKPTSignRSOpData, pKptUnwrapCtx);
                return status;
            }

            status = cpaCyKptEcdsaSignRS(setup->cyInstanceHandle,
                                         signRSCbFunc,
                                         pPerfData,
                                         pKPTSignRSOpData,
                                         &signStatus,
                                         r,
                                         s,
                                         pKptUnwrapCtx);
        }
        else
        {
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
#endif
            status = cpaCyEcdsaSignRS(setup->cyInstanceHandle,
                                      signRSCbFunc,
                                      pPerfData,
                                      pSignRSOpData,
                                      &signStatus,
                                      r,
                                      s);
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        }
#endif
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
#endif
        if (CPA_STATUS_RETRY == status)
        {
            retries++;
            /*once we get to many retries, perform a context switch
             * to give the acceleration engine a small break */
            if (RETRY_LIMIT == (retries % (RETRY_LIMIT + 1)))
            {
                AVOID_SOFTLOCKUP;
            }
        }
    } while (CPA_STATUS_RETRY == status);
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

    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to sign message, status: %d\n", status);
        ECDSA_SIGN_RS_OPDATA_MEM_FREE;
        qaeMemFree((void **)&pSignRSOpData);
        qaeMemFree((void **)&(pDigest));
#ifdef USER_SPACE
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        cpaCyKptDeleteKey(
            setup->cyInstanceHandle, setup->kptKeyHandle, &kpt2Status);
        kpt2EcdsaFreeDataMemory(pKPTSignRSOpData, pKptUnwrapCtx);
#endif
#endif
#endif
        return status;
    }
    else
    {
        /*if(signStatus != CPA_TRUE)
        {
            PRINT_ERR("Unable to sign message\n");
            ECDSA_SIGN_RS_OPDATA_MEM_FREE;
            return CPA_STATUS_FAIL;
        }*/
    }
    /*free the memory for the operation data and the digest...we save the
     * message for the verification part*/
    ECDSA_SIGN_RS_OPDATA_MEM_FREE;
    qaeMemFree((void **)&pSignRSOpData);
    qaeMemFree((void **)&(pDigest));

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
            PRINT("KPT ECSDA Delete SWK Retry Times : %d\n",
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
        kpt2EcdsaFreeDataMemory(pKPTSignRSOpData, pKptUnwrapCtx);
    }
#endif
#endif
#endif

    return status;
}

#define ECDSA_PERFORM_MEM_FREE()                                               \
    do                                                                         \
    {                                                                          \
        ecdsaMemFree(setup, pX, pY, pR, pS, msg, pZ, ppOpData, privateKey);    \
    } while (0)

void ecdsaMemFree(ecdsa_test_params_t *setup,
                  CpaFlatBuffer *pX,
                  CpaFlatBuffer *pY,
                  CpaFlatBuffer *pR,
                  CpaFlatBuffer *pS,
                  CpaFlatBuffer *msg,
                  CpaFlatBuffer *pZ,
                  CpaCyEcdsaVerifyOpData **ppOpData,
                  CpaFlatBuffer privateKey)
{
    Cpa32U k = 0;

    /*free verify opData*/
    if (NULL != ppOpData)
    {
        for (k = 0; k < setup->numBuffers; k++)
        {
            if (NULL != ppOpData[k])
            {
                qaeMemFreeNUMA((void **)&ppOpData[k]->yp.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->xp.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->yg.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->xg.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->s.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->r.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->q.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->n.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->m.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->a.pData);
                qaeMemFreeNUMA((void **)&ppOpData[k]->b.pData);
                qaeMemFree((void **)&ppOpData[k]);
            }
            qaeMemFreeNUMA((void **)&pR[k].pData);
            qaeMemFreeNUMA((void **)&pS[k].pData);
            qaeMemFreeNUMA((void **)&msg[k].pData);
            qaeMemFreeNUMA((void **)&pZ[k].pData);
        }
    }
    /* free all memory */
    qaeMemFreeNUMA((void **)&pX->pData);
    qaeMemFreeNUMA((void **)&pY->pData);
    qaeMemFree((void **)&pX);
    qaeMemFree((void **)&pY);
    qaeMemFree((void **)&pR);
    qaeMemFree((void **)&pS);
    qaeMemFree((void **)&msg);
    qaeMemFree((void **)&pZ);
    if (NULL != ppOpData)
    {
        qaeMemFree((void **)&ppOpData);
    }
    qaeMemFreeNUMA((void **)&privateKey.pData);
}

#define ECDSA_PERFORM_RS_ONLY_MEM_FREE()                                       \
    do                                                                         \
    {                                                                          \
        ecdsaPerformRsOnlyMemFree(setup,                                       \
                                  pX,                                          \
                                  pY,                                          \
                                  pR,                                          \
                                  pS,                                          \
                                  msg,                                         \
                                  pZ,                                          \
                                  ppDigests,                                   \
                                  ppSignRSOpData,                              \
                                  NULL,                                        \
                                  privateKey);                                 \
    } while (0)

#define ECDSA_PERFORM_POINT_MULTIPLY_MEM_FREE()                                \
    do                                                                         \
    {                                                                          \
        ecdsaPerformRsOnlyMemFree(setup,                                       \
                                  pX,                                          \
                                  pY,                                          \
                                  pR,                                          \
                                  pS,                                          \
                                  msg,                                         \
                                  pZ,                                          \
                                  ppDigests,                                   \
                                  ppSignRSOpData,                              \
                                  ppPointMultiplyOpData,                       \
                                  privateKey);                                 \
    } while (0)

void ecdsaPerformRsOnlyMemFree(
    ecdsa_test_params_t *setup,
    CpaFlatBuffer *pX,
    CpaFlatBuffer *pY,
    CpaFlatBuffer *pR,
    CpaFlatBuffer *pS,
    CpaFlatBuffer *msg,
    CpaFlatBuffer *pZ,
    CpaFlatBuffer **ppDigests,
    CpaCyEcdsaSignRSOpData **ppSignRSOpData,
    CpaCyEcPointMultiplyOpData **ppPointMultiplyOpData,
    CpaFlatBuffer privateKey)
{
    Cpa32U k = 0;
    for (k = 0; k < setup->numBuffers; k++)
    {
        if (NULL != ppDigests && NULL != ppDigests[k])
        {
            if (NULL != ppDigests[k]->pData)
            {
                qaeMemFreeNUMA((void **)&ppDigests[k]->pData);
            }
            qaeMemFree((void **)&ppDigests[k]);
        }
        if (NULL != pX && NULL != pX[k].pData)
        {
            qaeMemFreeNUMA((void **)&pX[k].pData);
        }
        if (NULL != pY && NULL != pY[k].pData)
        {
            qaeMemFreeNUMA((void **)&pY[k].pData);
        }
        if (NULL != pR && NULL != pR[k].pData)
        {
            qaeMemFreeNUMA((void **)&pR[k].pData);
        }
        if (NULL != pS && NULL != pS[k].pData)
        {
            qaeMemFreeNUMA((void **)&pS[k].pData);
        }
        if (NULL != msg && NULL != msg[k].pData)
        {
            qaeMemFreeNUMA((void **)&msg[k].pData);
        }
        if (NULL != pZ && NULL != pZ[k].pData)
        {
            qaeMemFreeNUMA((void **)&pZ[k].pData);
        }
        if (NULL != ppSignRSOpData && NULL != ppSignRSOpData[k])
        {
            if (NULL != ppSignRSOpData[k]->a.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->a.pData);
            }
            if (NULL != ppSignRSOpData[k]->b.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->b.pData);
            }
            if (NULL != ppSignRSOpData[k]->k.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->k.pData);
            }
            if (NULL != ppSignRSOpData[k]->n.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->n.pData);
            }
            if (NULL != ppSignRSOpData[k]->q.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->q.pData);
            }
            if (NULL != ppSignRSOpData[k]->xg.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->xg.pData);
            }
            if (NULL != ppSignRSOpData[k]->yg.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->yg.pData);
            }
            if (NULL != ppSignRSOpData[k]->d.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->d.pData);
            }
            if (NULL != ppSignRSOpData[k]->m.pData)
            {
                qaeMemFreeNUMA((void **)&ppSignRSOpData[k]->m.pData);
            }
            qaeMemFree((void **)&ppSignRSOpData[k]);
        }
        if (NULL != ppPointMultiplyOpData && NULL != ppPointMultiplyOpData[k])
        {
            if (NULL != ppPointMultiplyOpData[k]->a.pData)
            {
                qaeMemFreeNUMA((void **)&ppPointMultiplyOpData[k]->a.pData);
            }
            if (NULL != ppPointMultiplyOpData[k]->b.pData)
            {
                qaeMemFreeNUMA((void **)&ppPointMultiplyOpData[k]->b.pData);
            }
            if (NULL != ppPointMultiplyOpData[k]->q.pData)
            {
                qaeMemFreeNUMA((void **)&ppPointMultiplyOpData[k]->q.pData);
            }
            if (NULL != ppPointMultiplyOpData[k]->xg.pData)
            {
                qaeMemFreeNUMA((void **)&ppPointMultiplyOpData[k]->xg.pData);
            }
            if (NULL != ppPointMultiplyOpData[k]->yg.pData)
            {
                qaeMemFreeNUMA((void **)&ppPointMultiplyOpData[k]->yg.pData);
            }
            qaeMemFree((void **)&ppPointMultiplyOpData[k]);
        }
    }
    if (NULL != pX)
    {
        qaeMemFree((void **)&pX);
    }
    if (NULL != pY)
    {
        qaeMemFree((void **)&pY);
    }
    if (NULL != pR)
    {
        qaeMemFree((void **)&pR);
    }
    if (NULL != pS)
    {
        qaeMemFree((void **)&pS);
    }
    if (NULL != msg)
    {
        qaeMemFree((void **)&msg);
    }
    if (NULL != pZ)
    {
        qaeMemFree((void **)&pZ);
    }
    if (NULL != ppDigests)
    {
        qaeMemFree((void **)&ppDigests);
    }
    if (NULL != ppSignRSOpData)
    {
        qaeMemFree((void(**)) & ppSignRSOpData);
    }
    if (NULL != ppPointMultiplyOpData)
    {
        qaeMemFree((void(**)) & ppPointMultiplyOpData);
    }
    if (NULL != privateKey.pData)
    {
        qaeMemFreeNUMA((void **)&privateKey.pData);
    }
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      setup a number of buffers to be signed by ECDSA then verified using
 *      EC curve data
 ***************************************************************************/
CpaStatus ecdsaPerform(ecdsa_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U numLoops = 0;
    CpaBoolean verifyStatus;
    CpaCyEcdsaStats64 ecdsaStats;
    CpaStatus status = CPA_STATUS_FAIL;
    /*pointer to Elliptic curve public key points*/
    CpaFlatBuffer *pX = NULL;
    CpaFlatBuffer *pY = NULL;
    /*array of pointers to Signature R & S of the messages below*/
    CpaFlatBuffer *pR = NULL;
    CpaFlatBuffer *pS = NULL;
    /*array of pointers to messages to be signed*/
    CpaFlatBuffer *msg = NULL;
    /*array of pointers to store digest of the above messages*/
    CpaFlatBuffer *pZ = NULL;
    /*private key used for all messages and to generate public key*/
    CpaFlatBuffer privateKey = {.dataLenInBytes = 0, .pData = NULL};
    /*array of pointers to the operation data structure for each verify
     * operation*/
    CpaCyEcdsaVerifyOpData **ppOpData = NULL;
    /*variable to store what cpu thread is running on*/
    Cpa32U node = 0;
    /*pointer to location to store performance data*/
    perf_data_t *pEcdsaData = NULL;
    CpaInstanceInfo2 *instanceInfo = NULL;
    CpaCyEcdsaVerifyCbFunc cbFunc = NULL;
#ifdef POLL_INLINE
    CpaStatus pollStatus = CPA_STATUS_FAIL;
    perf_data_t *pPerfData = setup->performanceStats;
    Cpa64U numOps = 0;
    Cpa64U nextPoll = asymPollingInterval_g;
#endif
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    CpaCyCapabilitiesInfo pCapInfo = {0};
#endif
#endif
    DECLARE_IA_CYCLE_COUNT_VARIABLES();
    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        goto barrier;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
        goto barrier;
    }
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
            status = CPA_STATUS_SUCCESS;
            goto barrier;
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyQueryCapabilities failed!\n");
            sampleCodeBarrier();
            status = CPA_STATUS_FAIL;
            goto barrier;
        }
    }
#endif
#endif

    status = cpaCyEcdsaQueryStats64(setup->cyInstanceHandle, &ecdsaStats);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Could not retrieve stats, error status %d\n", status);
    }
    /*get the node we are running on for local memory allocation*/
    status = sampleCodeCyGetNode(setup->cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode error, status: %d\n", status);
        goto barrier;
    }
    /*get the curve data based on the test setup*/
    status = getCurveData(setup);
    if (CPA_STATUS_SUCCESS != status)
    {
        /*any error is printed in the getCurveData function*/
        goto barrier;
    }

    /*get memory location to write performance stats to*/
    pEcdsaData = setup->performanceStats;

    /*get the number of operations to be done in this test*/
    pEcdsaData->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;
    pEcdsaData->responses = 0;
    coo_init(pEcdsaData, pEcdsaData->numOperations);
    /* Initialize semaphore used in callback */
    sampleCodeSemaphoreInit(&pEcdsaData->comp, 0);

    /*allocate memory to store public key points*/
    pX = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pX)
    {
        PRINT_ERR("pY mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    memset(pX, 0, sizeof(CpaFlatBuffer));

    pY = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == pY)
    {
        PRINT_ERR("pY mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    memset(pY, 0, sizeof(CpaFlatBuffer));

    privateKey.pData =
        qaeMemAllocNUMA(setup->nLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == privateKey.pData)
    {
        PRINT_ERR("privateKey pData  mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    privateKey.dataLenInBytes = setup->nLenInBytes;
    /*generate a random private key*/
    generateRandomData(privateKey.pData, privateKey.dataLenInBytes);
    makeParam1SmallerThanParam2(
        privateKey.pData, setup->pCurve->r, setup->nLenInBytes, CPA_FALSE);

    /*allocate memory for array of signatures, messages, digests and opData*/

    pR = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == pR)
    {
        PRINT_ERR("pR mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    pS = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == pS)
    {
        PRINT_ERR("pS mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    msg = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == msg)
    {
        PRINT_ERR("msg mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    pZ = qaeMemAlloc(sizeof(CpaFlatBuffer) * setup->numBuffers);
    if (NULL == pZ)
    {
        PRINT_ERR("pZ mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        status = CPA_STATUS_FAIL;
        goto barrier;
    }

    /*calculate the public key p(X,Y) points*/
    status = calcEcPoint(setup, &privateKey, pX, pY);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("calcEcPoint Failes with status %d\n", status);
        ECDSA_PERFORM_MEM_FREE();
        goto barrier;
    }
    /*for each buffer:
     *      generate a random message
     *      calculate the digest
     *      sign the digest of the message with R&S*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        /*allocate the pointers within the array of pointers*/
        /*allocate the pData for each CpaFlatBuffer*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &pR[i],
                             setup->nLenInBytes,
                             NULL,
                             0,
                             ECDSA_PERFORM_MEM_FREE());
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &pS[i],
                             setup->nLenInBytes,
                             NULL,
                             0,
                             ECDSA_PERFORM_MEM_FREE());
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &msg[i],
                             setup->nLenInBytes,
                             NULL,
                             0,
                             ECDSA_PERFORM_MEM_FREE());
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &pZ[i],
                             setup->nLenInBytes,
                             NULL,
                             0,
                             ECDSA_PERFORM_MEM_FREE());
        /*sign the message (the message is populated within the ecdsaSignRS
         * function with random data*/

        status = ecdsaSignRS(
            setup, &privateKey, &pR[i], &pS[i], &msg[i], &pZ[i], NULL, NULL);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("ecdsaSignRS error %d\n", status);
            ECDSA_PERFORM_MEM_FREE();
            goto barrier;
        }
    }

    /*verify the signatures to the messages*/

    status = allocArrayOfVirtPointers((void **)&ppOpData, setup->numBuffers);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("ppOpData mem allocation error\n");
        ECDSA_PERFORM_MEM_FREE();
        goto barrier;
    }

    /*allocate and populate all the verifyOpData buffers*/
    for (i = 0; i < setup->numBuffers; i++)
    {
        ppOpData[i] = qaeMemAlloc(sizeof(CpaCyEcdsaVerifyOpData));
        if (NULL == ppOpData[i])
        {
            PRINT_ERR("ppOpData[%u] memory allocation error\n", i);
            ECDSA_PERFORM_MEM_FREE();
            status = CPA_STATUS_FAIL;
            goto barrier;
        }
        memset(ppOpData[i], 0, sizeof(CpaCyEcdsaVerifyOpData));

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->a,
                             setup->nLenInBytes,
                             setup->pCurve->a,
                             setup->pCurve->sizeOfa,
                             ECDSA_PERFORM_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->b,
                             setup->nLenInBytes,
                             setup->pCurve->b,
                             setup->pCurve->sizeOfb,
                             ECDSA_PERFORM_MEM_FREE());

        ppOpData[i]->fieldType = setup->fieldType;

        /*m pZ contains the digest of msg*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->m,
                             setup->nLenInBytes,
                             pZ[i].pData,
                             pZ[i].dataLenInBytes,
                             ECDSA_PERFORM_MEM_FREE());

        /*http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf:
         * Any point of order r can serve as the base point
         * QA-API uses n value to describe base point*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->n,
                             setup->nLenInBytes,
                             setup->pCurve->r,
                             setup->pCurve->sizeOfr,
                             ECDSA_PERFORM_MEM_FREE());

        /*http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf:
         * use p for either prime modulus for GFP or polynomial for GF2
         * QA API uses q for the same*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->q,
                             setup->nLenInBytes,
                             setup->pCurve->p,
                             setup->pCurve->sizeOfp,
                             ECDSA_PERFORM_MEM_FREE());

        /*r is part of the RS signature*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->r,
                             setup->nLenInBytes,
                             pR[i].pData,
                             pR[i].dataLenInBytes,
                             ECDSA_PERFORM_MEM_FREE());

        /*s is part of the RS signature*/
        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->s,
                             setup->nLenInBytes,
                             pS[i].pData,
                             pS[i].dataLenInBytes,
                             ECDSA_PERFORM_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->xg,
                             setup->nLenInBytes,
                             setup->pCurve->xg,
                             setup->pCurve->sizeOfxg,
                             ECDSA_PERFORM_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->yg,
                             setup->nLenInBytes,
                             setup->pCurve->yg,
                             setup->pCurve->sizeOfyg,
                             ECDSA_PERFORM_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->xp,
                             setup->nLenInBytes,
                             pX->pData,
                             pX->dataLenInBytes,
                             ECDSA_PERFORM_MEM_FREE());

        ALLOC_FLAT_BUFF_DATA(setup->cyInstanceHandle,
                             &ppOpData[i]->yp,
                             setup->nLenInBytes,
                             pY->pData,
                             pY->dataLenInBytes,
                             ECDSA_PERFORM_MEM_FREE());
    }
    /*this barrier will wait until all threads get to this point*/
    /*set the callback function if asynchronous mode is set*/
    if (ASYNC == setup->syncMode)
    {
        cbFunc = ecdsaPerformCallback;
    }
    pEcdsaData->numOperations = (Cpa64U)setup->numBuffers * setup->numLoops;
    pEcdsaData->responses = 0;

barrier:
    sampleCodeBarrier();
    /* exiting the function if any failure occurs in previous steps*/
    if (CPA_STATUS_SUCCESS != status)
    {
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&instanceInfo);
        return status;
    }

    /*record the start time, the callback measures the end time when the last
     * response is received*/
    pEcdsaData->startCyclesTimestamp = sampleCodeTimestamp();
    for (numLoops = 0; numLoops < setup->numLoops; numLoops++)
    {
        for (i = 0; i < setup->numBuffers; i++)
        {

            do
            {
                coo_req_start(pEcdsaData);
                status = cpaCyEcdsaVerify(setup->cyInstanceHandle,
                                          cbFunc,
                                          pEcdsaData,
                                          ppOpData[i],
                                          &verifyStatus);
                coo_req_stop(pEcdsaData, status);
                if (CPA_STATUS_RETRY == status)
                {
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (instanceInfo->isPolled)
                        {
                            sampleCodeAsymPollInstance(setup->cyInstanceHandle,
                                                       0);
                            nextPoll = numOps + asymPollingInterval_g;
                        }
                    }
#endif
                    pEcdsaData->retries++;
                    /*if the acceleration engine is busy pause for a
                     * moment by making a context switch*/
                    if (RETRY_LIMIT ==
                        (pEcdsaData->retries % (RETRY_LIMIT + 1)))
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
                PRINT_ERR("ECDSA Verify function failed with status:%d\n",
                          status);
                ECDSA_PERFORM_MEM_FREE();
                qaeMemFree((void **)&instanceInfo);
                return status;
            }
#ifdef POLL_INLINE
            if (poll_inline_g)
            {
                if (instanceInfo->isPolled)
                {
                    ++numOps;
                    if (numOps == nextPoll)
                    {
                        coo_poll_trad_cy(
                            pEcdsaData, setup->cyInstanceHandle, &pollStatus);
                        nextPoll = numOps + asymPollingInterval_g;
                    }
                }
            }
#endif
            if (ASYNC != setup->syncMode)
            {
                if (CPA_TRUE != verifyStatus)
                {
                    PRINT_ERR("ECDSA Verify function verification failed "
                              "but status = %d\n",
                              status);
                    status = CPA_STATUS_FAIL;
                }
                /*else {
                    PRINT_ERR("ECDSA Verify function verification "
                                    "succeeded\n");
                }*/
            }
        } /*end buffers loop */
    }     /* end of numLoops loop*/
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((instanceInfo->isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pEcdsaData, setup->cyInstanceHandle, pEcdsaData->numOperations);
        }
    }
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = waitForResponses(
            pEcdsaData, setup->syncMode, setup->numBuffers, setup->numLoops);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Thread %u timeout. ", setup->threadID);
        }
    }
    if (CPA_CC_BUSY_LOOPS == iaCycleCount_g)
    {
        IA_CYCLE_COUNT_CALCULATION();
    }
    coo_average(pEcdsaData);
    coo_deinit(pEcdsaData);

    sampleCodeSemaphoreDestroy(&pEcdsaData->comp);
    /*Free all memory*/
    ECDSA_PERFORM_MEM_FREE();
    qaeMemFree((void **)&instanceInfo);
    if (CPA_STATUS_SUCCESS != setup->performanceStats->threadReturnStatus)
    {
        status = CPA_STATUS_FAIL;
    }
    return status;
}
EXPORT_SYMBOL(ecdsaPerform);


/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      Print the performance stats of the elliptic curve dsa operations
 ***************************************************************************/
CpaStatus ecdsaPrintStats(thread_creation_data_t *data)
{
    ecdsa_test_params_t *params = (ecdsa_test_params_t *)data->setupPtr;
    if (ECDSA_STEP_SIGNRS == params->step)
    {
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == params->enableKPT)
        {
            PRINT("KPT2 ECDSA SIGNRS\n");
        }
        else
        {
            PRINT("ECDSA SIGNRS\n");
        }
#else
        PRINT("ECDSA SIGNRS\n");
#endif
#else
        PRINT("ECDSA SIGNRS\n");
#endif
    }
    else if (ECDSA_STEP_VERIFY == params->step)
    {
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == params->enableKPT)
        {
            PRINT("KPT2 ECDSA VERIFY\n");
        }
        else
        {
            PRINT("ECDSA VERIFY\n");
        }
#else
        PRINT("ECDSA VERIFY\n");
#endif
#else
        PRINT("ECDSA VERIFY\n");
#endif
    }
    else if (ECDSA_STEP_POINT_MULTIPLY == params->step)
    {
        PRINT("ECDSA POINT MULTIPLY\n");
    }
    PRINT("EC Size %23u\n", data->packetSize);
    printAsymStatsAndStopServices(data);
    return CPA_STATUS_SUCCESS;
}

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      setup an elliptic curve performance thread
 ***************************************************************************/
void ecdsaPerformance(single_thread_test_data_t *testSetup)
{
    ecdsa_test_params_t ecdsaSetup = {0};
    Cpa16U numInstances = 0;
    CpaInstanceHandle *cyInstances = NULL;
    CpaStatus status = CPA_STATUS_FAIL;
    ecdsa_test_params_t *params = (ecdsa_test_params_t *)testSetup->setupPtr;
    CpaInstanceInfo2 *instanceInfo = NULL;
#ifdef SC_DEV_INFO_ENABLED
    CpaDeviceInfo deviceInfo = {0};
#endif

    testSetup->passCriteria = getPassCriteria();

    /*this barrier is to halt this thread when run in user space context, the
     * startThreads function releases this barrier, in kernel space it does
     * nothing, but kernel space threads do not start until we call
     * startThreads anyway*/
    startBarrier();
    /*
     * In case of error scenario, the thread will exit early.
     * register the print function here itself to properly exit with statistics.
     */
    testSetup->statsPrintFunc = (stats_print_func_t)ecdsaPrintStats;
    /*give our thread a unique memory location to store performance stats*/
    ecdsaSetup.performanceStats = testSetup->performanceStats;
    /*get the instance handles so that we can start our thread on the selected
     * instance*/
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0)
    {
        PRINT_ERR("cpaCyGetNumInstances error, status:%d, numInstanaces:%d\n",
                  status,
                  numInstances);
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Error allocating memory for instance handles\n");
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }
    if (cpaCyGetInstances(numInstances, cyInstances) != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Failed to get instances\n");
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        sampleCodeThreadExit();
    }

    /* give our thread a logical crypto instance to use
     * use % to wrap around the max number of instances*/
    ecdsaSetup.cyInstanceHandle =
        cyInstances[(testSetup->logicalQaInstance) % numInstances];

    instanceInfo = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo");
        return;
    }
    memset(instanceInfo, 0, sizeof(CpaInstanceInfo2));

    status = cpaCyInstanceGetInfo2(ecdsaSetup.cyInstanceHandle, instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        sampleCodeThreadExit();
    }

#ifdef SC_DEV_INFO_ENABLED
    /* check whether asym service enabled or not for the instance */
    status = cpaGetDeviceInfo(instanceInfo->physInstId.packageId, &deviceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaGetDeviceInfo failed", __func__, __LINE__);
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadExit();
    }
    if (CPA_FALSE == deviceInfo.cyAsymEnabled)
    {
        PRINT_ERR("%s::%d Error! cyAsymEnabled service not enabled for the "
                  "configured instance\n",
                  __func__,
                  __LINE__);
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
        qaeMemFree((void **)&cyInstances);
        qaeMemFree((void **)&instanceInfo);
        sampleCodeThreadExit();
    }
#endif
    if (instanceInfo->physInstId.packageId > packageIdCount_g)
    {
        packageIdCount_g = instanceInfo->physInstId.packageId;
    }

    memset(ecdsaSetup.performanceStats, 0, sizeof(perf_data_t));
    ecdsaSetup.performanceStats->packageId = instanceInfo->physInstId.packageId;

    ecdsaSetup.threadID = testSetup->threadID;

    ecdsaSetup.nLenInBytes = params->nLenInBytes;
    ecdsaSetup.fieldType = params->fieldType;
    ecdsaSetup.numBuffers = params->numBuffers;
    ecdsaSetup.numLoops = params->numLoops;
    ecdsaSetup.syncMode = params->syncMode;
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
    ecdsaSetup.enableKPT = params->enableKPT;
#endif
#endif
    /*launch function that does all the work*/

    switch (params->step)
    {
        case (ECDSA_STEP_VERIFY):
            status = ecdsaPerform(&ecdsaSetup);
            break;
        default:
            PRINT_ERR("Function not supported for step %d\n", params->step);
            status = CPA_STATUS_FAIL;
            break;
    }
    if (CPA_STATUS_SUCCESS != status)
    {
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        if (CPA_TRUE == params->enableKPT)
        {
            PRINT("KPT2 ECDSA Thread %u FAILED\n", testSetup->threadID);
        }
        else
        {
#endif
#endif
            PRINT("ECDSA Thread %u FAILED\n", testSetup->threadID);
#if CY_API_VERSION_AT_LEAST(3, 0)
#ifdef SC_KPT2_ENABLED
        }
#endif
#endif
        ecdsaSetup.performanceStats->threadReturnStatus = CPA_STATUS_FAIL;
    }
    qaeMemFree((void **)&cyInstances);
    qaeMemFree((void **)&instanceInfo);
    sampleCodeThreadComplete(testSetup->threadID);
}
EXPORT_SYMBOL(ecdsaPerformance);

/***************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      This function is used to set the parameters to be used in the elliptic
 *      curve performance thread. It is called before the createThreads
 *      function of the framework. The framework replicates it across many
 *      cores
 ***************************************************************************/
CpaStatus setupEcdsaTest(Cpa32U nLenInBits,
                         CpaCyEcFieldType fieldType,
                         sync_mode_t syncMode,
                         ecdsa_step_t step,
                         Cpa32U numBuffers,
                         Cpa32U numLoops)
{
    /* testSetupData_g is a multi-dimensional array that stores the setup for
     * all thread variations in an array of characters. we store our test setup
     * at the start of the second array ie index 0. There maybe multi thread
     * types (setups) running as counted by testTypeCount_g*/

    /*as setup is a multi-dimensional char array we need to cast it to the
     * symmetric structure*/
    ecdsa_test_params_t *ecdsaSetup = NULL;

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
        /* start polling threads if polling is enabled in the configuration file
         */
        if (CPA_STATUS_SUCCESS != cyCreatePollingThreadsIfPollingIsEnabled())
        {
            PRINT_ERR("Error creating polling threads\n");
            return CPA_STATUS_FAIL;
        }
    }
    ecdsaSetup = (ecdsa_test_params_t *)&thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].performance_function =
        (performance_func_t)ecdsaPerformance;
    testSetupData_g[testTypeCount_g].packetSize = nLenInBits;
    /*if nLenInBits is not an even number of bytes then round up
     * ecdsaSetup->nLenInBytes*/
    ecdsaSetup->nLenInBytes =
        (nLenInBits + NUM_BITS_IN_BYTE - 1) / NUM_BITS_IN_BYTE;
    ecdsaSetup->fieldType = fieldType;
    ecdsaSetup->syncMode = syncMode;
    ecdsaSetup->numBuffers = numBuffers;
    ecdsaSetup->numLoops = numLoops;
    ecdsaSetup->step = step;
    return CPA_STATUS_SUCCESS;
}
