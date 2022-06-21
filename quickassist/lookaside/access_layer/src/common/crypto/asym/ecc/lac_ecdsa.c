/***************************************************************************
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
 ***************************************************************************/

/**
 ***************************************************************************
 *
 * @file lac_ecdsa.c
 *
 * @ingroup Lac_Ec
 *
 * Elliptic Curve Digital Signature Algorithm functions
 *
 * @lld_start
 *
 * @lld_overview
 * This file implements the Elliptic Curve DSA apis. It implements 4
 * Ecdsa API services: signature generation (r, s, rs), and signature
 * verification. Statistics are maintained per instance for each service.
 * The parameters supplied by the client are checked, and then input/output
 * argument lists are constructed before calling the PKE Comms layer to
 * create and send a request to the QAT.
 *
 * For Ecdsa signRS and verify the number of input parameters to the function
 * is greater than the number of input parameters allowed for the PKE service
 * Therefore, for the 2 of these functions we copy and concatenate all inputs
 * to 1 internal buffer and this is sent to QAT for processing.
 *
 * In all other cases the service implementations are a straightforward
 * marshalling of client-supplied parameters for the QAT. I.e. there is
 * minimal logic handled by this component.
 *
 * For Ecdsa Verification function the output is the result of the verification
 * returned by the QAT in the form of pass/fail status. The status is
 * returned to the caller.
 *
 * @lld_dependencies
 * - \ref LacAsymCommonQatComms "PKE QAT Comms" : For creating and sending
 * messages to the QAT
 * - \ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @note
 * The ECDSA feature may be called in Asynchronous or Synchronous modes.
 * In Asynchronous mode the user supplies a Callback function to the API.
 * Control returns to the client after the message has been sent to the QAT
 * and the Callback gets invoked when the QAT completes the operation. There
 * is NO BLOCKING. This mode is preferred for maximum performance.
 * In Synchronous mode the client supplies no Callback function pointer (NULL)
 * and the point of execution is placed on a wait-queue internally, and this
 * is de-queued once the QAT completes the operation. Hence, Synchronous mode
 * is BLOCKING. So avoid using in an interrupt context. To achieve maximum
 * performance from the API Asynchronous mode is preferred.
 *
 * @performance
 *
 * @lld_initialisation
 * On initialization this component clears the stats.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 ***************************************************************************/

/*
****************************************************************************
* Include public/global header files
****************************************************************************
*/

/* API Includes */
#include "cpa.h"
#include "cpa_cy_ecdsa.h"

/* OSAL Includes */
#include "Osal.h"

/* ADF Includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* QAT includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"
#include "icp_qat_fw_pke.h"

/* Look Aside Includes */
#include "lac_log.h"
#include "lac_common.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_sync.h"
#include "lac_ec.h"
#include "lac_sym.h"
#include "lac_list.h"
#include "sal_service_state.h"
#include "lac_sal_types_crypto.h"
#include "sal_statistics.h"
#include "lac_ec_nist_curves.h"

typedef struct _OptCurveParams
{
    Cpa32U dataOperationSizeBytes;
    Cpa32U functionRS;
    const Cpa8U *p;
    const Cpa8U *r;
    const Cpa8U *a;
    const Cpa8U *b;
} OptCurveParams;

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

/**< number of 'in' arguments in the arguments size list for Sign R */
#define LAC_ECDSA_SIGNR_NUM_IN_ARGS 7
/**< number of 'out' arguments in the arguments size list for Sign R */
#define LAC_ECDSA_SIGNR_NUM_OUT_ARGS 1
/**< number of 'in' arguments in the arguments size list for Sign S */
#define LAC_ECDSA_SIGNS_NUM_IN_ARGS 5
/**< number of 'out' arguments in the arguments size list for Sign S */
#define LAC_ECDSA_SIGNS_NUM_OUT_ARGS 1
/**< number of 'in' arguments in the arguments size list for Sign RS */
#define LAC_ECDSA_SIGNRS_NUM_IN_ARGS 1
/**< number of input parameters to QA API for Sign RS */
#define LAC_ECDSA_SIGNRS_NUM_IN_QA_API 9
/**< number of 'out' arguments in the arguments size list for Sign RS */
#define LAC_ECDSA_SIGNRS_NUM_OUT_ARGS 2
/**< number of 'in' arguments in the arguments size list for Verify */
#define LAC_ECDSA_VERIFY_NUM_IN_ARGS 1
/**< number of input parameters to QA API for Verify */
#define LAC_ECDSA_VERIFY_NUM_IN_QA_API 11
/**< number of 'in' arguments in the arguments size list for Sign RS P256 P384
 */
#define LAC_ECDSA_SIGNRS_P256P384_NUM_IN_ARGS 3
/**< number of 'out' arguments in the arguments size list for Sign RS P256 P384
 */
#define LAC_ECDSA_SIGNRS_P256P384_NUM_OUT_ARGS 2

/**< number of ECDSA statistics */
#define LAC_ECDSA_NUM_STATS (sizeof(CpaCyEcdsaStats64) / sizeof(Cpa64U))

#ifndef DISABLE_STATS
#define LAC_ECDSA_STAT_INC(statistic, pCryptoService)                          \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bEccStatsEnabled)      \
        {                                                                      \
            osalAtomicInc(                                                     \
                &pCryptoService->pLacEcdsaStatsArr[offsetof(CpaCyEcdsaStats64, \
                                                            statistic) /       \
                                                   sizeof(Cpa64U)]);           \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ec
 * macro to increment a ECDSA stat (derives offset into array of atomics) */
#else
#define LAC_ECDSA_STAT_INC(statistic, pCryptoService)                          \
    (pCryptoService) = (pCryptoService)
#endif

#define LAC_ECDSA_STATS_GET(ecdsaStats, pCryptoService)                        \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_ECDSA_NUM_STATS; i++)                              \
        {                                                                      \
            ((Cpa64U *)&(ecdsaStats))[i] =                                     \
                osalAtomicGet(&pCryptoService->pLacEcdsaStatsArr[i]);          \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ec
 * macro to collect a ECDSA stat in sample period of performance counters */

/**< @ingroup Lac_Ec
 * macro to get all ECDSA stats (from internal array of atomics) */

#define LacEcdsaSignROpDataWrite(in, out, pOpData, pR)                         \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.xg, &pOpData->xg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.yg, &pOpData->yg);                    \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.n, &pOpData->n);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.q, &pOpData->q);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.a, &pOpData->a);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.b, &pOpData->b);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, &pOpData->k);                      \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.r, pR);                              \
    } while (0);
/* macro to populate Sign R parameters from CpaCyEcdsaSignROpData or
 * CpaCyEcdsaSignRSOpData structures */

#define LacEcdsaSignSOpDataWrite(in, out, pOpData, pS)                         \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.e, &pOpData->m);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.d, &pOpData->d);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.r, &pOpData->r);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, &pOpData->k);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.n, &pOpData->n);                      \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.s, pS);                              \
    } while (0);
/* macro to populate parameters from CpaCyEcdsaSignSOpData structure */

#define LacEcdsaSignRSOpDataWrite(in_struct, out, pConcateBuff, pR, pS)        \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in_struct.in, pConcateBuff);             \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.r, pR);                              \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.s, pS);                              \
    } while (0);
/* macro to populate Sign RS parameters */

#define LacEcdsaP256P384SignRSOpDataWrite(in, out, pOpData, pR, pS)            \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.k, &pOpData->k);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.e, &pOpData->m);                      \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.d, &pOpData->d);                      \
                                                                               \
        /* populate output parameters */                                       \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.r, pR);                              \
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.s, pS);                              \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to write in/out parameters for the P256 and P384
 * Ecdsa SignRS operation */

#define LacEcdsaVerifyOpDataWrite(in_struct, pConcateBuff)                     \
    do                                                                         \
    {                                                                          \
        /* populate input parameters */                                        \
        LAC_MEM_SHARED_WRITE_FROM_PTR(in_struct.in, pConcateBuff);             \
    } while (0);
/* macro to populate Verify parameters from CpaCyEcdsaSignVerifyOpData
 * structure and other */

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      return the size of the biggest number in CpaCyEcdsaSignROpData
 *
 * @description
 *      return the size of the biggest number in CpaCyEcdsaSignROpData
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcdsaSignROpData structure
 *
 * @retval max  the size in bytes of the biggest input number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEcdsa_SignROpDataSizeGetMax(const CpaCyEcdsaSignROpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of the number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->n)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->q)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->a)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->b)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);

    return max;
}

/**
 ****************************************************************************
 * @ingroup Lac_Ec
 *      return the size of the biggest number in CpaCyEcdsaSignSOpData
 *
 * @description
 *      return the size of the biggest number in CpaCyEcdsaSignSOpData
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcdsaSignSOpData structure
 *
 * @retval max  the size in bytes of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEcdsa_SignSOpDataSizeGetMax(const CpaCyEcdsaSignSOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->m)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->d)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->r)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->n)), max);

    return max;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      return the size of the biggest number in CpaCyEcdsaSignRSOpData
 *
 * @description
 *      return the size of the biggest number in CpaCyEcdsaSignRSOpData
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcdsaSignRSOpData structure
 *
 * @retval max  the size in bytes of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEcdsa_SignRSOpDataSizeGetMax(const CpaCyEcdsaSignRSOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->m)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->d)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->q)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->k)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->n)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->a)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->b)), max);

    return max;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      return the size of the biggest number in CpaCyEcdsaVerifyOpData
 *
 * @description
 *      return the size of the biggest number in CpaCyEcdsaVerifyOpData
 *
 * @param[in]  pOpData      Pointer to a CpaCyEcdsaVerifyOpData structure
 *
 * @retval max  the size in bytes of the biggest number
 *
 ***************************************************************************/
STATIC Cpa32U
LacEcdsa_VerifyOpDataSizeGetMax(const CpaCyEcdsaVerifyOpData *pOpData)
{
    Cpa32U max = 0;

    /* need to find max size in bytes of number in input buffers */
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yg)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->n)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->q)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->a)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->b)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->m)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->r)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->s)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->xp)), max);
    max = LAC_MAX(LacPke_GetMinBytes(&(pOpData->yp)), max);

    return max;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *     Copies least significant len bytes from a flat buffer (if length of
 *     flat buffer is less than len padding will be added).
 *
 * @description
 *     This function copies data in a flat buffer to memory pointed to by
 *     ptr. This function performs no checks so it is assumed that there is
 *     enough memory allocated.
 *
 * @param[in/out]  ptr      Pointer to a pointer to an array of Cpa8U
 * @param[in]  pBuff        Pointer to a CpaFlatBuffer structure
 * @param[in]  len          Number of bytes to copy.
 *                          This is the amount by which *ptr is
 *                          incremented also.
 *
 ***************************************************************************/

STATIC void LacEc_FlatBuffToConcate(Cpa8U **ptr,
                                    const CpaFlatBuffer *pBuff,
                                    Cpa32U len)
{
    Cpa8U *pMem = NULL;

    pMem = (Cpa8U *)*ptr;

    if (pBuff->dataLenInBytes < len)
    {
        /* pad */
        osalMemSet(pMem, 0, (len - pBuff->dataLenInBytes));
        pMem = pMem + (len - pBuff->dataLenInBytes);
        /* copy all flat buffer */
        memcpy(pMem, pBuff->pData, pBuff->dataLenInBytes);
        pMem = pMem + pBuff->dataLenInBytes;
    }
    else
    {
        /* no padding is required and we may need to index into
           flatbuffer - only lsbs are copied */
        memcpy(pMem, &(pBuff->pData[pBuff->dataLenInBytes - len]), len);
        pMem = pMem + len;
    }

    *ptr = pMem;
}

/**
 ***************************************************************************
 * @ingroup LacEc
 * Detect P256 or P384 and get optimised MMP function id
 ***************************************************************************/
STATIC CpaBoolean
LacEcdsa_SignRSGetOptFunctionId(CpaCyEcFieldType primeRepresentation,
                                const CpaFlatBuffer *pP,
                                const CpaFlatBuffer *pN,
                                const CpaFlatBuffer *pA,
                                const CpaFlatBuffer *pB,
                                Cpa32U *dataOperationSizeBytes,
                                Cpa32U *function)
{
    int i = 0;

    OptCurveParams curves[] = {
        /* P256 */
        {.dataOperationSizeBytes = LAC_BITS_TO_BYTES(LAC_256_BITS),
         .functionRS = PKE_ECDSA_SIGN_RS_P256,
         .p = nist_p256_p,
         .r = nist_p256_r,
         .a = nist_p256_a,
         .b = nist_p256_b},

        /* P384 */
        {.dataOperationSizeBytes = LAC_BITS_TO_BYTES(LAC_384_BITS),
         .functionRS = PKE_ECDSA_SIGN_RS_P384,
         .p = nist_p384_p,
         .r = nist_p384_r,
         .a = nist_p384_a,
         .b = nist_p384_b}};

    *function = 0;

    /* Loop through each curve returning when found and setting
     * dataOperationSizeBytes and function id */
    for (i = 0; i < ARRAY_SIZE(curves); i++)
    {
        CpaBoolean res = CPA_CY_EC_FIELD_TYPE_PRIME == primeRepresentation;

        /* if the curve has not the prime representation continue searching */
        if (!res)
            continue;

        res = LacPke_CompareFlatAndPtr(
            pN, curves[i].r, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            pP, curves[i].p, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            pA, curves[i].a, curves[i].dataOperationSizeBytes);
        if (!res)
            continue;
        res = LacPke_CompareFlatAndPtr(
            pB, curves[i].b, curves[i].dataOperationSizeBytes);

        if (res == CPA_TRUE)
        {
            *dataOperationSizeBytes = curves[i].dataOperationSizeBytes;
            *function = curves[i].functionRS;
            return CPA_TRUE;
        }
    }

    return CPA_FALSE; /* not found any optimised curve */
}

/**
 ***************************************************************************
 * @ingroup LacEc
 * Fill MMP struct for optimised Sign RS P256 and P384
 ***************************************************************************/
STATIC CpaStatus
LacEcdsa_SignRSFillMMPStructsOpt(icp_qat_fw_mmp_input_param_t *in,
                                 Cpa32U *inSizes,
                                 CpaBoolean *inAlloc,
                                 icp_qat_fw_mmp_output_param_t *out,
                                 Cpa32U *outSizes,
                                 CpaBoolean *outAlloc,
                                 Cpa32U function,
                                 Cpa32U size,
                                 const CpaCyEcdsaSignRSOpData *pOpData,
                                 CpaFlatBuffer *pR,
                                 CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Set the size for all parameters to be padded to */
    LAC_EC_SET_LIST_PARAMS(
        inSizes, LAC_ECDSA_SIGNRS_P256P384_NUM_IN_ARGS, size);

    LAC_EC_SET_LIST_PARAMS(
        outSizes, LAC_ECDSA_SIGNRS_P256P384_NUM_OUT_ARGS, size);

    /* Set all memory to externally allocated */
    LAC_EC_SET_LIST_PARAMS(
        inAlloc, LAC_ECDSA_SIGNRS_P256P384_NUM_IN_ARGS, CPA_FALSE);

    LAC_EC_SET_LIST_PARAMS(
        outAlloc, LAC_ECDSA_SIGNRS_P256P384_NUM_OUT_ARGS, CPA_FALSE);

    switch (function)
    {
        case PKE_ECDSA_SIGN_RS_P256:
            LacEcdsaP256P384SignRSOpDataWrite(in->mmp_ecdsa_sign_rs_p256,
                                              out->mmp_ecdsa_sign_rs_p256,
                                              pOpData,
                                              pR,
                                              pS);
            break;

        case PKE_ECDSA_SIGN_RS_P384:
            LacEcdsaP256P384SignRSOpDataWrite(in->mmp_ecdsa_sign_rs_p384,
                                              out->mmp_ecdsa_sign_rs_p384,
                                              pOpData,
                                              pR,
                                              pS);
            break;

        default:
            status = CPA_STATUS_INVALID_PARAM;
            break;
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign R synchronous function
 ***************************************************************************/
STATIC CpaStatus LacEcdsa_SignRSyn(const CpaInstanceHandle instanceHandle,
                                   const CpaCyEcdsaSignROpData *pOpData,
                                   CpaBoolean *pMultiplyStatus,
                                   CpaFlatBuffer *pR)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcdsaSignR(instanceHandle,
                                 LacSync_GenFlatBufVerifyCb,
                                 pSyncCallbackData,
                                 pOpData,
                                 pMultiplyStatus,
                                 pR);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_ECDSA_STAT_INC(numEcdsaSignRCompletedErrors, pCryptoService);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the Request was not sent the Callback will never
         * be called, so need to indicate that we're finished
         * with cookie so it can be destroyed. */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }

    LacSync_DestroySyncCookie(&pSyncCallbackData);
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign R internal callback
 ***************************************************************************/
STATIC
void LacEcdsa_SignRCallback(CpaStatus status,
                            CpaBoolean multiplyStatus,
                            CpaInstanceHandle instanceHandle,
                            lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcdsaGenSignCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcdsaSignROpData *pOpData = NULL;
    CpaFlatBuffer *pR = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcdsaGenSignCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcdsaSignROpData *)pCbData->pClientOpData;
    pR = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pR);
    LAC_ASSERT_NOT_NULL(pR->pData);

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRCompleted, pCryptoService);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRCompletedErrors, pCryptoService);
    }

    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRCompletedOutputInvalid, pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pR);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign R parameter check
 ***************************************************************************/
STATIC
CpaStatus LacEcdsa_SignRBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                        const CpaCyEcdsaSignROpData *pOpData,
                                        CpaBoolean *pMultiplyStatus,
                                        CpaFlatBuffer *pR)
{
    /* check for NULL pointers */
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pR);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->a.pData);
    LAC_CHECK_SIZE(&(pOpData->a), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->b.pData);
    LAC_CHECK_SIZE(&(pOpData->b), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->q.pData);
    LAC_CHECK_SIZE(&(pOpData->q), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xg.pData);
    LAC_CHECK_SIZE(&(pOpData->xg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yg.pData);
    LAC_CHECK_SIZE(&(pOpData->yg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->n.pData);
    LAC_CHECK_SIZE(&(pOpData->n), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pR->pData);
    LAC_CHECK_SIZE(pR, CHECK_NONE, 0);

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pOpData->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pOpData->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that q is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->q));

    /* Check that n is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->n));

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcdsaSignR(const CpaInstanceHandle instanceHandle_in,
                          const CpaCyEcdsaGenSignCbFunc pCb,
                          void *pCallbackTag,
                          const CpaCyEcdsaSignROpData *pOpData,
                          CpaBoolean *pMultiplyStatus,
                          CpaFlatBuffer *pR)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa32S compare = 1;
    Cpa32U bit_pos_q = 0, bit_pos_x = 0, bit_pos_y = 0;
    Cpa32U temp = 0;
    Cpa32U maxModLen = 0;
    CpaBoolean isZero = CPA_FALSE;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* instance checks - if fail, no inc stats just return */
    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* ensure LAC is initialised - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
#ifdef ICP_PARAM_CHECK
        /* Check for valid pointers */
        LAC_CHECK_NULL_PARAM(pMultiplyStatus);
#endif
        status =
            LacEcdsa_SignRSyn(instanceHandle, pOpData, pMultiplyStatus, pR);

        LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                 "0x%lx[%d], 0x%lx)\n",
                 (LAC_ARCH_UINT)instanceHandle_in,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 (LAC_ARCH_UINT)pMultiplyStatus,
                 *pMultiplyStatus,
                 (LAC_ARCH_UINT)pR);
        return status;
#else
        /* Call synchronous mode function */
        return LacEcdsa_SignRSyn(instanceHandle, pOpData, pMultiplyStatus, pR);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking */
    status = LacEcdsa_SignRBasicParamCheck(
        instanceHandle, pOpData, pMultiplyStatus, pR);

    /* Check that output buffer is big enough */
    if (CPA_STATUS_SUCCESS == status)
    {
        maxModLen = LacPke_GetMinBytes(&(pOpData->n));
        if (pR->dataLenInBytes < maxModLen)
        {
            LAC_INVALID_PARAM_LOG("Output buffer not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size */
        status = LacEc_GetRange(LacEcdsa_SignROpDataSizeGetMax(pOpData),
                                &dataOperationSizeBytes);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if ((LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            /* Check if it is a NIST curve if not use 8QW */
            LacEc_CheckCurve4QWGF2(&dataOperationSizeBytes,
                                   &(pOpData->q),
                                   &(pOpData->a),
                                   &(pOpData->b),
                                   &(pOpData->n),
                                   NULL);
        }
    }

#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) &&
        (LAC_EC_SIZE_QW9_IN_BYTES == dataOperationSizeBytes))
    {
        /* 9QW checks */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Check if is is a NIST curve (if not it is an invalid param) */
            /* Also checks that xG and yG are less than 2^521 */
            status = LacEc_CheckCurve9QWGFP(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            &(pOpData->n),
                                            NULL,
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
        else
        {
            /* Check if is is a NIST curve (if not it is an invalid param) */
            /* Also checks that deg xG and yG are less than 571 */
            status = LacEc_CheckCurve9QWGF2(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            &(pOpData->n),
                                            NULL,
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < k < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->k));
        compare = LacPke_Compare(&(pOpData->k), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("k is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure base point is not (0,0) */
        if ((0 == LacPke_CompareZero(&(pOpData->xg), 0)) &&
            (0 == LacPke_CompareZero(&(pOpData->yg), 0)))
        {
            LAC_INVALID_PARAM_LOG("Invalid base point");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* For GFP check that q>3 and xg and yg less than q
           (note for 9QW case have already ensured xg and yg <=q
           still need to eliminate xg and yg ==q case) */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Ensure q > 3 */
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            if (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GFP)
            {
                LAC_INVALID_PARAM_LOG("q is not > 3 as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure xg < q */
            compare = LacPke_Compare(&(pOpData->xg), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("xg is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure yg < q */
            compare = LacPke_Compare(&(pOpData->yg), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("yg is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
        /* For GF2 4 and 8 QW check that deg(q)>2 and that deg(xg) and deg(yg)
           are less than deg(q) (note: already checked for 9QW case) */
        if (((LAC_EC_SIZE_QW8_IN_BYTES == dataOperationSizeBytes) ||
             (LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes)) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            if (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GF2)
            {
                LAC_INVALID_PARAM_LOG("deg(q) is not > 2 as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(xg) < deg(q) for non zero xg */
            LacPke_GetBitPos(&(pOpData->xg), &bit_pos_x, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_x >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(xg) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(yg) < deg(q) for non zero yg */
            LacPke_GetBitPos(&(pOpData->yg), &bit_pos_y, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_y >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(yg) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
        lac_pke_op_cb_data_t cbData = {0};

        /* Holding the calculated size of the input/output parameters */
        Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
        Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

        CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
        CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

        Cpa32U functionID = 0;

        /* clear output buffer */
        osalMemSet(pR->pData, 0, pR->dataLenInBytes);

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pR;

        /* Set the size for all parameters to be padded to */
        LAC_EC_SET_LIST_PARAMS(
            inArgSizeList, LAC_ECDSA_SIGNR_NUM_IN_ARGS, dataOperationSizeBytes);
        LAC_EC_SET_LIST_PARAMS(outArgSizeList,
                               LAC_ECDSA_SIGNR_NUM_OUT_ARGS,
                               dataOperationSizeBytes);
        /* Set all memory to externally allocated */
        LAC_EC_SET_LIST_PARAMS(
            internalMemInList, LAC_ECDSA_SIGNR_NUM_IN_ARGS, CPA_FALSE);
        LAC_EC_SET_LIST_PARAMS(
            internalMemOutList, LAC_ECDSA_SIGNR_NUM_OUT_ARGS, CPA_FALSE);

        /* Populate input buffers and output buffer and set function ID */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcdsaSignROpDataWrite(in.mmp_ecdsa_sign_r_gfp_l256,
                                             out.mmp_ecdsa_sign_r_gfp_l256,
                                             pOpData,
                                             pR);
                    functionID = PKE_ECDSA_SIGN_R_GFP_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcdsaSignROpDataWrite(in.mmp_ecdsa_sign_r_gfp_l512,
                                             out.mmp_ecdsa_sign_r_gfp_l512,
                                             pOpData,
                                             pR);
                    functionID = PKE_ECDSA_SIGN_R_GFP_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcdsaSignROpDataWrite(in.mmp_ecdsa_sign_r_gfp_521,
                                             out.mmp_ecdsa_sign_r_gfp_521,
                                             pOpData,
                                             pR);
                    functionID = PKE_ECDSA_SIGN_R_GFP_521;
                    break;
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcdsaSignROpDataWrite(in.mmp_ecdsa_sign_r_gf2_l256,
                                             out.mmp_ecdsa_sign_r_gf2_l256,
                                             pOpData,
                                             pR);
                    functionID = PKE_ECDSA_SIGN_R_GF2_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcdsaSignROpDataWrite(in.mmp_ecdsa_sign_r_gf2_l512,
                                             out.mmp_ecdsa_sign_r_gf2_l512,
                                             pOpData,
                                             pR);
                    functionID = PKE_ECDSA_SIGN_R_GF2_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcdsaSignROpDataWrite(in.mmp_ecdsa_sign_r_gf2_571,
                                             out.mmp_ecdsa_sign_r_gf2_571,
                                             pOpData,
                                             pR);
                    functionID = PKE_ECDSA_SIGN_R_GF2_571;
                    break;
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* send a PKE request to the QAT */
            status = LacPke_SendSingleRequest(functionID,
                                              inArgSizeList,
                                              outArgSizeList,
                                              &in,
                                              &out,
                                              internalMemInList,
                                              internalMemOutList,
                                              LacEcdsa_SignRCallback,
                                              &cbData,
                                              instanceHandle);
        }
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRRequests, pCryptoService);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign S synchronous function
 ***************************************************************************/
STATIC CpaStatus LacEcdsa_SignSSyn(const CpaInstanceHandle instanceHandle,
                                   const CpaCyEcdsaSignSOpData *pOpData,
                                   CpaBoolean *pMultiplyStatus,
                                   CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcdsaSignS(instanceHandle,
                                 LacSync_GenFlatBufVerifyCb,
                                 pSyncCallbackData,
                                 pOpData,
                                 pMultiplyStatus,
                                 pS);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignSRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_ECDSA_STAT_INC(numEcdsaSignSCompletedErrors, pCryptoService);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the Request was not sent the Callback will never
         * be called, so need to indicate that we're finished
         * with cookie so it can be destroyed. */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }

    LacSync_DestroySyncCookie(&pSyncCallbackData);
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign S internal callback
 ***************************************************************************/
STATIC
void LacEcdsa_SignSCallback(CpaStatus status,
                            CpaBoolean multiplyStatus,
                            CpaInstanceHandle instanceHandle,
                            lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcdsaGenSignCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcdsaSignSOpData *pOpData = NULL;
    CpaFlatBuffer *pS = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcdsaGenSignCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcdsaSignSOpData *)pCbData->pClientOpData;
    pS = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pS);
    LAC_ASSERT_NOT_NULL(pS->pData);

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignSCompleted, pCryptoService);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignSCompletedErrors, pCryptoService);
    }

    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignSCompletedOutputInvalid, pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pS);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign S parameter check
 ***************************************************************************/
STATIC
CpaStatus LacEcdsa_SignSBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                        const CpaCyEcdsaSignSOpData *pOpData,
                                        CpaBoolean *pMultiplyStatus,
                                        CpaFlatBuffer *pS)
{
    /* check for NULL pointers */
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pS);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->m.pData);
    LAC_CHECK_SIZE(&(pOpData->m), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->d.pData);
    LAC_CHECK_SIZE(&(pOpData->d), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->r.pData);
    LAC_CHECK_SIZE(&(pOpData->r), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->n.pData);
    LAC_CHECK_SIZE(&(pOpData->n), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pS->pData);
    LAC_CHECK_SIZE(pS, CHECK_NONE, 0);

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pOpData->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pOpData->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that n is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->n));

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcdsaSignS(const CpaInstanceHandle instanceHandle_in,
                          const CpaCyEcdsaGenSignCbFunc pCb,
                          void *pCallbackTag,
                          const CpaCyEcdsaSignSOpData *pOpData,
                          CpaBoolean *pMultiplyStatus,
                          CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa32S compare = 1;
    Cpa32U maxModLen = 1;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* instance checks - if fail, no inc stats just return */
    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* ensure LAC is initialised - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
#ifdef ICP_PARAM_CHECK
        /* Check for valid pointers */
        LAC_CHECK_NULL_PARAM(pMultiplyStatus);
#endif
        status =
            LacEcdsa_SignSSyn(instanceHandle, pOpData, pMultiplyStatus, pS);

        LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                 "0x%lx[%d], 0x%lx)\n",
                 (LAC_ARCH_UINT)instanceHandle_in,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 (LAC_ARCH_UINT)pMultiplyStatus,
                 *pMultiplyStatus,
                 (LAC_ARCH_UINT)pS);
        return status;
#else
        /* Call synchronous mode function */
        return LacEcdsa_SignSSyn(instanceHandle, pOpData, pMultiplyStatus, pS);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking */
    status = LacEcdsa_SignSBasicParamCheck(
        instanceHandle, pOpData, pMultiplyStatus, pS);

    /* Check that output buffer is big enough */
    if (CPA_STATUS_SUCCESS == status)
    {
        maxModLen = LacPke_GetMinBytes(&(pOpData->n));
        if (pS->dataLenInBytes < maxModLen)
        {
            LAC_INVALID_PARAM_LOG("Output buffer not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size */
        status = LacEc_GetRange(LacEcdsa_SignSOpDataSizeGetMax(pOpData),
                                &dataOperationSizeBytes);
    }

#ifdef ICP_PARAM_CHECK
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < k < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->k));

        compare = LacPke_Compare(&(pOpData->k), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("k is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < r < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->r));

        compare = LacPke_Compare(&(pOpData->r), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("r is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < d < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->d));

        compare = LacPke_Compare(&(pOpData->d), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("d is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
        lac_pke_op_cb_data_t cbData = {0};

        /* Holding the calculated size of the input/output parameters */
        Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
        Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

        CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
        CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

        Cpa32U functionID = 0;

        /* clear output buffer - needs to be done in case
           pS->dataLenInBytes > dataOperationSizeBytes */
        osalMemSet(pS->pData, 0, pS->dataLenInBytes);

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pS;

        /* Set the size for all parameters to be padded to */
        LAC_EC_SET_LIST_PARAMS(
            inArgSizeList, LAC_ECDSA_SIGNS_NUM_IN_ARGS, dataOperationSizeBytes);
        LAC_EC_SET_LIST_PARAMS(outArgSizeList,
                               LAC_ECDSA_SIGNS_NUM_OUT_ARGS,
                               dataOperationSizeBytes);

        /* Set memory to extrenally allocated */
        LAC_EC_SET_LIST_PARAMS(
            internalMemInList, LAC_ECDSA_SIGNS_NUM_IN_ARGS, CPA_FALSE);
        LAC_EC_SET_LIST_PARAMS(
            internalMemOutList, LAC_ECDSA_SIGNS_NUM_OUT_ARGS, CPA_FALSE)

        /* Populate input buffers and output buffer and set function ID */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcdsaSignSOpDataWrite(in.mmp_ecdsa_sign_s_gfp_l256,
                                             out.mmp_ecdsa_sign_s_gfp_l256,
                                             pOpData,
                                             pS);
                    functionID = PKE_ECDSA_SIGN_S_GFP_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcdsaSignSOpDataWrite(in.mmp_ecdsa_sign_s_gfp_l512,
                                             out.mmp_ecdsa_sign_s_gfp_l512,
                                             pOpData,
                                             pS);
                    functionID = PKE_ECDSA_SIGN_S_GFP_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcdsaSignSOpDataWrite(in.mmp_ecdsa_sign_s_gfp_521,
                                             out.mmp_ecdsa_sign_s_gfp_521,
                                             pOpData,
                                             pS);
                    functionID = PKE_ECDSA_SIGN_S_GFP_521;
                    break;
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }
        else
        {
            switch (dataOperationSizeBytes)
            {
                case LAC_EC_SIZE_QW4_IN_BYTES:
                    LacEcdsaSignSOpDataWrite(in.mmp_ecdsa_sign_s_gf2_l256,
                                             out.mmp_ecdsa_sign_s_gf2_l256,
                                             pOpData,
                                             pS);
                    functionID = PKE_ECDSA_SIGN_S_GF2_L256;
                    break;
                case LAC_EC_SIZE_QW8_IN_BYTES:
                    LacEcdsaSignSOpDataWrite(in.mmp_ecdsa_sign_s_gf2_l512,
                                             out.mmp_ecdsa_sign_s_gf2_l512,
                                             pOpData,
                                             pS);
                    functionID = PKE_ECDSA_SIGN_S_GF2_L512;
                    break;
                case LAC_EC_SIZE_QW9_IN_BYTES:
                    LacEcdsaSignSOpDataWrite(in.mmp_ecdsa_sign_s_gf2_571,
                                             out.mmp_ecdsa_sign_s_gf2_571,
                                             pOpData,
                                             pS);
                    functionID = PKE_ECDSA_SIGN_S_GF2_571;
                    break;
                default:
                    status = CPA_STATUS_INVALID_PARAM;
                    break;
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* send a PKE request to the QAT */
            status = LacPke_SendSingleRequest(functionID,
                                              inArgSizeList,
                                              outArgSizeList,
                                              &in,
                                              &out,
                                              internalMemInList,
                                              internalMemOutList,
                                              LacEcdsa_SignSCallback,
                                              &cbData,
                                              instanceHandle);
        }
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignSRequests, pCryptoService);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignSRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign R & S synchronous function
 ***************************************************************************/
STATIC CpaStatus LacEcdsa_SignRSSyn(const CpaInstanceHandle instanceHandle,
                                    const CpaCyEcdsaSignRSOpData *pOpData,
                                    CpaBoolean *pMultiplyStatus,
                                    CpaFlatBuffer *pR,
                                    CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcdsaSignRS(instanceHandle,
                                  LacSync_GenDualFlatBufVerifyCb,
                                  pSyncCallbackData,
                                  pOpData,
                                  pMultiplyStatus,
                                  pR,
                                  pS);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRSRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pMultiplyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_ECDSA_STAT_INC(numEcdsaSignRSCompletedErrors, pCryptoService);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the Request was not sent the Callback will never
         * be called, so need to indicate that we're finished
         * with cookie so it can be destroyed. */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }

    LacSync_DestroySyncCookie(&pSyncCallbackData);
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign R & S internal callback
 ***************************************************************************/
STATIC
void LacEcdsa_SignRSCallback(CpaStatus status,
                             CpaBoolean multiplyStatus,
                             CpaInstanceHandle instanceHandle,
                             lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcdsaSignRSCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcdsaSignRSOpData *pOpData = NULL;
    CpaFlatBuffer *pR = NULL;
    CpaFlatBuffer *pS = NULL;
    Cpa8U *pMemPoolConcate = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcdsaSignRSCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcdsaSignRSOpData *)pCbData->pClientOpData;
    pR = pCbData->pOutputData1;
    pS = pCbData->pOutputData2;
    pMemPoolConcate = (Cpa8U *)(pCbData->pOpaqueData);

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pR);
    LAC_ASSERT_NOT_NULL(pR->pData);
    LAC_ASSERT_NOT_NULL(pS);
    LAC_ASSERT_NOT_NULL(pS->pData);

    /*  When we use opptimised path for P256/P384 we do not allocate
        pMemPoolConcate so in that case pMemPoolConcate is NULL
        and we should not free it */

    /* Free Mem Pool Entry */
    if (pMemPoolConcate)
        Lac_MemPoolEntryFree(pMemPoolConcate);

        /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRSCompleted, pCryptoService);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRSCompletedErrors, pCryptoService);
    }

    if ((CPA_FALSE == multiplyStatus) && (CPA_STATUS_SUCCESS == status))
    {
        LAC_ECDSA_STAT_INC(numEcdsaSignRSCompletedOutputInvalid,
                           pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, multiplyStatus, pR, pS);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Sign R & S parameter check
 ***************************************************************************/
STATIC
CpaStatus LacEcdsa_SignRSBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                         const CpaCyEcdsaSignRSOpData *pOpData,
                                         CpaBoolean *pMultiplyStatus,
                                         CpaFlatBuffer *pR,
                                         CpaFlatBuffer *pS)
{

    /* check for NULL pointers */
    LAC_CHECK_NULL_PARAM(pMultiplyStatus);
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_NULL_PARAM(pR);
    LAC_CHECK_NULL_PARAM(pS);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->a.pData);
    LAC_CHECK_SIZE(&(pOpData->a), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->b.pData);
    LAC_CHECK_SIZE(&(pOpData->b), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->k.pData);
    LAC_CHECK_SIZE(&(pOpData->k), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->q.pData);
    LAC_CHECK_SIZE(&(pOpData->q), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xg.pData);
    LAC_CHECK_SIZE(&(pOpData->xg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yg.pData);
    LAC_CHECK_SIZE(&(pOpData->yg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->n.pData);
    LAC_CHECK_SIZE(&(pOpData->n), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->m.pData);
    LAC_CHECK_SIZE(&(pOpData->m), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->d.pData);
    LAC_CHECK_SIZE(&(pOpData->d), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pR->pData);
    LAC_CHECK_SIZE(pR, CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pS->pData);
    LAC_CHECK_SIZE(pS, CHECK_NONE, 0);

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pOpData->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pOpData->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that q is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->q));

    /* Check that n is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->n));

    return CPA_STATUS_SUCCESS;
}
#endif

CpaStatus LacEcdsa_OptimisedSignRS(const CpaInstanceHandle instanceHandle,
                                   const CpaCyEcdsaSignRSCbFunc pCb,
                                   void *pCallbackTag,
                                   const CpaCyEcdsaSignRSOpData *pOpData,
                                   CpaFlatBuffer *pR,
                                   CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaBoolean optCurve = CPA_FALSE;
    Cpa32U functionID = 0;
    Cpa32U dataOperationSize = 0;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;


#ifdef ICP_PARAM_CHECK
    Cpa32S compare = 0;
    /* Check  0 < k < n */
    LAC_CHECK_NON_ZERO_PARAM(&(pOpData->k));

    compare = LacPke_Compare(&(pOpData->k), 0, &(pOpData->n), 0);
    if (compare >= 0)
    {
        LAC_INVALID_PARAM_LOG("k is not < n as required");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check  0 < d < n */
    LAC_CHECK_NON_ZERO_PARAM(&(pOpData->d));

    compare = LacPke_Compare(&(pOpData->d), 0, &(pOpData->n), 0);
    if (compare >= 0)
    {
        LAC_INVALID_PARAM_LOG("d is not < n as required");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
    optCurve = LacEcdsa_SignRSGetOptFunctionId(pOpData->fieldType,
                                               &(pOpData->q),
                                               &(pOpData->n),
                                               &(pOpData->a),
                                               &(pOpData->b),
                                               &dataOperationSize,
                                               &functionID);
    if (optCurve == CPA_FALSE)
        /* The optimised path is not supported for the curve */
        return CPA_STATUS_UNSUPPORTED;

    icp_qat_fw_mmp_input_param_t inRS = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t outRS = {.flat_array = {0}};
    lac_pke_op_cb_data_t cbData = {0};

    /* Holding the calculated size of the input/output parameters */
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

    CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

    /* clear output buffers */
    osalMemSet(pR->pData, 0, pR->dataLenInBytes);
    osalMemSet(pS->pData, 0, pS->dataLenInBytes);

    cbData.pClientCb = pCb;
    cbData.pCallbackTag = pCallbackTag;
    cbData.pClientOpData = pOpData;
    cbData.pOpaqueData = NULL;
    cbData.pOutputData1 = pR;
    cbData.pOutputData2 = pS;

    status = LacEcdsa_SignRSFillMMPStructsOpt(&inRS,
                                              inArgSizeList,
                                              internalMemInList,
                                              &outRS,
                                              outArgSizeList,
                                              internalMemOutList,
                                              functionID,
                                              dataOperationSize,
                                              pOpData,
                                              pR,
                                              pS);
    /* Send pke request */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* build a PKE request  */
        status = LacPke_SendSingleRequest(functionID,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &inRS,
                                          &outRS,
                                          internalMemInList,
                                          internalMemOutList,
                                          LacEcdsa_SignRSCallback,
                                          &cbData,
                                          instanceHandle);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* increment stats */
        LAC_ECDSA_STAT_INC(numEcdsaSignRSRequests, pCryptoService);
    }
    else
    {
        /* increment stats */
        LAC_ECDSA_STAT_INC(numEcdsaSignRSRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcdsaSignRS(const CpaInstanceHandle instanceHandle_in,
                           const CpaCyEcdsaSignRSCbFunc pCb,
                           void *pCallbackTag,
                           const CpaCyEcdsaSignRSOpData *pOpData,
                           CpaBoolean *pMultiplyStatus,
                           CpaFlatBuffer *pR,
                           CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    CpaInstanceHandle instanceHandle = NULL;
    sal_crypto_service_t *pCryptoService = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa32S compare = 0;
    Cpa32U bit_pos_q = 0, bit_pos_x = 0, bit_pos_y = 0;
    Cpa32U temp = 0;
    Cpa32U maxModLen = 0;
    CpaBoolean isZero = CPA_FALSE;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* instance checks - if fail, no inc stats just return */
    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* ensure LAC is initialised - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
#ifdef ICP_PARAM_CHECK
        /* Check for valid pointers */
        LAC_CHECK_NULL_PARAM(pMultiplyStatus);
#endif
        status = LacEcdsa_SignRSSyn(
            instanceHandle, pOpData, pMultiplyStatus, pR, pS);

        LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                 "%d, 0x%lx, 0x%lx)\n",
                 (LAC_ARCH_UINT)instanceHandle_in,
                 (LAC_ARCH_UINT)pCb,
                 (LAC_ARCH_UINT)pCallbackTag,
                 (LAC_ARCH_UINT)pOpData,
                 *pMultiplyStatus,
                 (LAC_ARCH_UINT)pR,
                 (LAC_ARCH_UINT)pS);
        return status;
#else
        /* Call synchronous mode function */
        return LacEcdsa_SignRSSyn(
            instanceHandle, pOpData, pMultiplyStatus, pR, pS);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking */
    status = LacEcdsa_SignRSBasicParamCheck(
        instanceHandle, pOpData, pMultiplyStatus, pR, pS);

    /* Check that output buffers are big enough */
    if (CPA_STATUS_SUCCESS == status)
    {
        maxModLen = LacPke_GetMinBytes(&(pOpData->n));
        if ((pR->dataLenInBytes < maxModLen) ||
            (pS->dataLenInBytes < maxModLen))
        {
            LAC_INVALID_PARAM_LOG("Output buffer not big enough");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus isSupported = CPA_STATUS_SUCCESS;

        isSupported = LacEcdsa_OptimisedSignRS(
            instanceHandle, pCb, pCallbackTag, pOpData, pR, pS);

        /* If LacEcdsa_OptimisedSignRS returns CPA_STATUS_UNSUPPORTED,
         * this means that the optimised path is not supported for the curve.
         * Continue with the unoptimised in that case.
         */

        if (CPA_STATUS_UNSUPPORTED != isSupported)
            return isSupported;
    }

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size */
        status = LacEc_GetRange(LacEcdsa_SignRSOpDataSizeGetMax(pOpData),
                                &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if ((LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            /* Check if it is a NIST curve if not use 8QW */
            LacEc_CheckCurve4QWGF2(&dataOperationSizeBytes,
                                   &(pOpData->q),
                                   &(pOpData->a),
                                   &(pOpData->b),
                                   &(pOpData->n),
                                   NULL);
        }
    }

#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) &&
        (LAC_EC_SIZE_QW9_IN_BYTES == dataOperationSizeBytes))
    {
        /* 9QW checks */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Check if is is a NIST curve (if not it is an invalid param) */
            /* Also checks that xG and yG are less than 2^521 */
            status = LacEc_CheckCurve9QWGFP(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            &(pOpData->n),
                                            NULL,
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
        else
        {
            /* Check if is is a NIST curve (if not it is an invalid param) */
            /* Also checks that xG and yG are less than 571 bits */
            status = LacEc_CheckCurve9QWGF2(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            &(pOpData->n),
                                            NULL,
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < k < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->k));

        compare = LacPke_Compare(&(pOpData->k), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("k is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < d < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->d));

        compare = LacPke_Compare(&(pOpData->d), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("d is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure base point is not (0,0) */
        if ((0 == LacPke_CompareZero(&(pOpData->xg), 0)) &&
            (0 == LacPke_CompareZero(&(pOpData->yg), 0)))
        {
            LAC_INVALID_PARAM_LOG("Invalid base point");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* For GFP check q>3 and xg and yg less than q */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Ensure q > 3 */
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            if (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GFP)
            {
                LAC_INVALID_PARAM_LOG("q is not > 3 as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure xg < q */
            compare = LacPke_Compare(&(pOpData->xg), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("xg is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure yg < q */
            compare = LacPke_Compare(&(pOpData->yg), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("yg is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
        /* For GF2 4 and 8 QW check deg(q)>2 and deg(xg) and deg(yg) less
           than deg(q) (note: already checked for 9QW case) */
        if (((LAC_EC_SIZE_QW8_IN_BYTES == dataOperationSizeBytes) ||
             (LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes)) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            if (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GF2)
            {
                LAC_INVALID_PARAM_LOG("deg(q) is not > 2 as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(xg) < deg(q) for non zero xg */
            LacPke_GetBitPos(&(pOpData->xg), &bit_pos_x, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_x >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(xg) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(yg) < deg(q) for non zero yg */
            LacPke_GetBitPos(&(pOpData->yg), &bit_pos_y, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_y >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(yg) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        Cpa8U *pMemPoolConcate = NULL;
        Cpa8U *pConcateTemp = NULL;
        CpaFlatBuffer *pInBuff = NULL;

        icp_qat_fw_mmp_input_param_t inRS = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t outRS = {.flat_array = {0}};
        lac_pke_op_cb_data_t cbData = {0};

        /* Holding the calculated size of the input/output parameters */
        Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
        Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};

        CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
        CpaBoolean internalMemOutList[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};

        Cpa32U functionID = 0;

        /* clear output buffers */
        osalMemSet(pR->pData, 0, pR->dataLenInBytes);
        osalMemSet(pS->pData, 0, pS->dataLenInBytes);

        /* Need to concatenate user inputs - copy to ecc mempool memory */
        do
        {
            pMemPoolConcate =
                (Cpa8U *)Lac_MemPoolEntryAlloc(pCryptoService->lac_ec_pool);
            if (NULL == pMemPoolConcate)
            {
                LAC_LOG_ERROR("Cannot get mem pool entry");
                status = CPA_STATUS_RESOURCE;
            }
            else if ((void *)CPA_STATUS_RETRY == pMemPoolConcate)
            {
                osalYield();
            }
        } while ((void *)CPA_STATUS_RETRY == pMemPoolConcate);

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Concatenate x,y, n, q, a, b, k, m, d */
            pConcateTemp = pMemPoolConcate;
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->d), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->m), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->k), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->b), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->a), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->q), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->n), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->yg), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->xg), dataOperationSizeBytes);
            pInBuff = (CpaFlatBuffer *)pConcateTemp;
            pInBuff->dataLenInBytes =
                (dataOperationSizeBytes * LAC_ECDSA_SIGNRS_NUM_IN_QA_API);
            pInBuff->pData = pMemPoolConcate;

            /* populate callback data */
            cbData.pClientCb = pCb;
            cbData.pCallbackTag = pCallbackTag;
            cbData.pClientOpData = pOpData;
            cbData.pOpaqueData = pMemPoolConcate;
            cbData.pOutputData1 = pR;
            cbData.pOutputData2 = pS;

            /* Set the size for all parameters to be padded to */
            LAC_EC_SET_LIST_PARAMS(
                inArgSizeList,
                LAC_ECDSA_SIGNRS_NUM_IN_ARGS,
                (LAC_ECDSA_SIGNRS_NUM_IN_QA_API * dataOperationSizeBytes));
            LAC_EC_SET_LIST_PARAMS(outArgSizeList,
                                   LAC_ECDSA_SIGNRS_NUM_OUT_ARGS,
                                   dataOperationSizeBytes);
            /* Input memory to QAT is internally allocated */
            LAC_EC_SET_LIST_PARAMS(
                internalMemInList, LAC_ECDSA_SIGNRS_NUM_IN_ARGS, CPA_TRUE);
            /* Output memory to QAT is externally allocated */
            LAC_EC_SET_LIST_PARAMS(
                internalMemOutList, LAC_ECDSA_SIGNRS_NUM_OUT_ARGS, CPA_FALSE);

            /* Populate input buffers and output buffers and set function IDs */
            if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
            {
                switch (dataOperationSizeBytes)
                {
                    case LAC_EC_SIZE_QW4_IN_BYTES:
                        LacEcdsaSignRSOpDataWrite(
                            inRS.mmp_ecdsa_sign_rs_gfp_l256,
                            outRS.mmp_ecdsa_sign_rs_gfp_l256,
                            pInBuff,
                            pR,
                            pS);
                        functionID = PKE_ECDSA_SIGN_RS_GFP_L256;
                        break;
                    case LAC_EC_SIZE_QW8_IN_BYTES:
                        LacEcdsaSignRSOpDataWrite(
                            inRS.mmp_ecdsa_sign_rs_gfp_l512,
                            outRS.mmp_ecdsa_sign_rs_gfp_l512,
                            pInBuff,
                            pR,
                            pS);
                        functionID = PKE_ECDSA_SIGN_RS_GFP_L512;
                        break;
                    case LAC_EC_SIZE_QW9_IN_BYTES:
                        LacEcdsaSignRSOpDataWrite(
                            inRS.mmp_ecdsa_sign_rs_gfp_521,
                            outRS.mmp_ecdsa_sign_rs_gfp_521,
                            pInBuff,
                            pR,
                            pS);
                        functionID = PKE_ECDSA_SIGN_RS_GFP_521;
                        break;
                    default:
                        status = CPA_STATUS_INVALID_PARAM;
                        break;
                }
            }
            else
            {
                switch (dataOperationSizeBytes)
                {
                    case LAC_EC_SIZE_QW4_IN_BYTES:
                        LacEcdsaSignRSOpDataWrite(
                            inRS.mmp_ecdsa_sign_rs_gf2_l256,
                            outRS.mmp_ecdsa_sign_rs_gf2_l256,
                            pInBuff,
                            pR,
                            pS);
                        functionID = PKE_ECDSA_SIGN_RS_GF2_L256;
                        break;
                    case LAC_EC_SIZE_QW8_IN_BYTES:
                        LacEcdsaSignRSOpDataWrite(
                            inRS.mmp_ecdsa_sign_rs_gf2_l512,
                            outRS.mmp_ecdsa_sign_rs_gf2_l512,
                            pInBuff,
                            pR,
                            pS);
                        functionID = PKE_ECDSA_SIGN_RS_GF2_L512;
                        break;
                    case LAC_EC_SIZE_QW9_IN_BYTES:
                        LacEcdsaSignRSOpDataWrite(
                            inRS.mmp_ecdsa_sign_rs_gf2_571,
                            outRS.mmp_ecdsa_sign_rs_gf2_571,
                            pInBuff,
                            pR,
                            pS);
                        functionID = PKE_ECDSA_SIGN_RS_GF2_571;
                        break;
                    default:
                        status = CPA_STATUS_INVALID_PARAM;
                        break;
                }
            }

            /* Send pke request */
            if (CPA_STATUS_SUCCESS == status)
            {
                /* build a PKE request  */
                status = LacPke_SendSingleRequest(functionID,
                                                  inArgSizeList,
                                                  outArgSizeList,
                                                  &inRS,
                                                  &outRS,
                                                  internalMemInList,
                                                  internalMemOutList,
                                                  LacEcdsa_SignRSCallback,
                                                  &cbData,
                                                  instanceHandle);
            }

            if (CPA_STATUS_SUCCESS != status)
            {
                /* Free Mem Pool */
                if (NULL != pMemPoolConcate)
                {
                    Lac_MemPoolEntryFree(pMemPoolConcate);
                }
            }
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* increment stats */
        LAC_ECDSA_STAT_INC(numEcdsaSignRSRequests, pCryptoService);
    }
    else
    {
        /* increment stats */
        LAC_ECDSA_STAT_INC(numEcdsaSignRSRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Verify synchronous function
 ***************************************************************************/
STATIC CpaStatus LacEcdsa_VerifySyn(const CpaInstanceHandle instanceHandle,
                                    const CpaCyEcdsaVerifyOpData *pOpData,
                                    CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the asynchronous version of the function
     * with the generic synchronous callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyEcdsaVerify(instanceHandle,
                                  LacSync_GenVerifyCb,
                                  pSyncCallbackData,
                                  pOpData,
                                  pVerifyStatus);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaVerifyRequestErrors, pCryptoService);
        return status;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pVerifyStatus);

        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            LAC_ECDSA_STAT_INC(numEcdsaVerifyCompletedErrors, pCryptoService);
            status = wCbStatus;
        }
    }
    else
    {
        /* As the Request was not sent the Callback will never
         * be called, so need to indicate that we're finished
         * with cookie so it can be destroyed. */
        LacSync_SetSyncCookieComplete(pSyncCallbackData);
    }

    LacSync_DestroySyncCookie(&pSyncCallbackData);
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Verify internal callback
 ***************************************************************************/
STATIC
void LacEcdsa_VerifyCallback(CpaStatus status,
                             CpaBoolean verifyStatus,
                             CpaInstanceHandle instanceHandle,
                             lac_pke_op_cb_data_t *pCbData)
{
    CpaCyEcdsaVerifyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyEcdsaVerifyOpData *pOpData = NULL;
    Cpa8U *pMemPoolConcate = NULL;
    sal_crypto_service_t *pCryptoService = NULL;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyEcdsaVerifyCbFunc)pCbData->pClientCb;
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyEcdsaVerifyOpData *)pCbData->pClientOpData;
    pMemPoolConcate = (Cpa8U *)(pCbData->pOpaqueData);

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pMemPoolConcate);

    /* Free Mem Pool Entry */
    Lac_MemPoolEntryFree(pMemPoolConcate);

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaVerifyCompleted, pCryptoService);

        if (CPA_FALSE == verifyStatus)
        {
            LAC_ECDSA_STAT_INC(numEcdsaVerifyCompletedOutputInvalid,
                               pCryptoService);
        }
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaVerifyCompletedErrors, pCryptoService);
    }

    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, verifyStatus);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECDSA Verify parameter check
 ***************************************************************************/
STATIC
CpaStatus LacEcdsa_VerifyBasicParamCheck(const CpaInstanceHandle instanceHandle,
                                         const CpaCyEcdsaVerifyOpData *pOpData,
                                         CpaBoolean *pVerifyStatus)
{
    /* check for NULL pointers */
    LAC_CHECK_NULL_PARAM(pVerifyStatus);
    LAC_CHECK_NULL_PARAM(pOpData);

    /* Check flat buffers in pOpData for NULL and dataLen of 0*/
    LAC_CHECK_NULL_PARAM(pOpData->a.pData);
    LAC_CHECK_SIZE(&(pOpData->a), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->b.pData);
    LAC_CHECK_SIZE(&(pOpData->b), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->q.pData);
    LAC_CHECK_SIZE(&(pOpData->q), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xg.pData);
    LAC_CHECK_SIZE(&(pOpData->xg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yg.pData);
    LAC_CHECK_SIZE(&(pOpData->yg), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->n.pData);
    LAC_CHECK_SIZE(&(pOpData->n), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->m.pData);
    LAC_CHECK_SIZE(&(pOpData->m), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->r.pData);
    LAC_CHECK_SIZE(&(pOpData->r), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->s.pData);
    LAC_CHECK_SIZE(&(pOpData->s), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->xp.pData);
    LAC_CHECK_SIZE(&(pOpData->xp), CHECK_NONE, 0);
    LAC_CHECK_NULL_PARAM(pOpData->yp.pData);
    LAC_CHECK_SIZE(&(pOpData->yp), CHECK_NONE, 0);

    if (CPA_CY_EC_FIELD_TYPE_PRIME != pOpData->fieldType &&
        CPA_CY_EC_FIELD_TYPE_BINARY != pOpData->fieldType)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check that q is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->q));

    /* Check that n is odd */
    LAC_CHECK_ODD_PARAM(&(pOpData->n));

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcdsaVerify(const CpaInstanceHandle instanceHandle_in,
                           const CpaCyEcdsaVerifyCbFunc pCb,
                           void *pCallbackTag,
                           const CpaCyEcdsaVerifyOpData *pOpData,
                           CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U dataOperationSizeBytes = 0;
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_PARAM_CHECK
    Cpa32S compare = 1;
    Cpa32U bit_pos_q = 0, bit_pos_x = 0, bit_pos_y = 0;
    Cpa32U temp = 0;
    CpaBoolean isZero = CPA_FALSE;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

#ifdef ICP_PARAM_CHECK
    /* instance checks - if fail, no inc stats just return */
    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* ensure LAC is initialised - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in synchronous mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
#ifdef ICP_PARAM_CHECK
        /* Check for valid pointers */
        LAC_CHECK_NULL_PARAM(pVerifyStatus);
#endif
        status = LacEcdsa_VerifySyn(instanceHandle, pOpData, pVerifyStatus);

        LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d]\n",
                 (LAC_ARCH_UINT)instanceHandle,
                 (LAC_ARCH_UINT)pOpData,
                 (LAC_ARCH_UINT)pVerifyStatus,
                 *pVerifyStatus);
        return status;
#else
        /* Call synchronous mode function */
        return LacEcdsa_VerifySyn(instanceHandle, pOpData, pVerifyStatus);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* Basic Param Checking  */
    status =
        LacEcdsa_VerifyBasicParamCheck(instanceHandle, pOpData, pVerifyStatus);

#endif

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Determine size */
        status = LacEc_GetRange(LacEcdsa_VerifyOpDataSizeGetMax(pOpData),
                                &dataOperationSizeBytes);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if ((LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            /* Check if it is a NIST curve if not use 8QW */
            LacEc_CheckCurve4QWGF2(&dataOperationSizeBytes,
                                   &(pOpData->q),
                                   &(pOpData->a),
                                   &(pOpData->b),
                                   &(pOpData->n),
                                   NULL);
        }
    }

#ifdef ICP_PARAM_CHECK
    if ((CPA_STATUS_SUCCESS == status) &&
        (LAC_EC_SIZE_QW9_IN_BYTES == dataOperationSizeBytes))
    {
        /* 9QW checks */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Check if it is a NIST curve (if not it is an invalid param) */
            /* Also checks that xG and yG are less than 2^521 */
            status = LacEc_CheckCurve9QWGFP(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            &(pOpData->n),
                                            NULL,
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
        else
        {
            /* Check if it is a NIST curve (if not it is an invalid param) */
            /* Also checks that xG and yG are less than 571 bits */
            status = LacEc_CheckCurve9QWGF2(&(pOpData->q),
                                            &(pOpData->a),
                                            &(pOpData->b),
                                            &(pOpData->n),
                                            NULL,
                                            &(pOpData->xg),
                                            &(pOpData->yg));
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < r < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->r));

        compare = LacPke_Compare(&(pOpData->r), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("r is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check  0 < s < n */
        LAC_CHECK_NON_ZERO_PARAM(&(pOpData->s));

        compare = LacPke_Compare(&(pOpData->s), 0, &(pOpData->n), 0);
        if (compare >= 0)
        {
            LAC_INVALID_PARAM_LOG("s is not < n as required");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure base point is not (0,0) */
        if ((0 == LacPke_CompareZero(&(pOpData->xg), 0)) &&
            (0 == LacPke_CompareZero(&(pOpData->yg), 0)))
        {
            LAC_INVALID_PARAM_LOG("Invalid base point");
            status = CPA_STATUS_INVALID_PARAM;
        }

        /* For GFP check q>3 and xg and yg less than q */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            if (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GFP)
            {
                LAC_INVALID_PARAM_LOG("q is not > 3 as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure xg < q */
            compare = LacPke_Compare(&(pOpData->xg), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("xg is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure yg < q */
            compare = LacPke_Compare(&(pOpData->yg), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("yg is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
        /* For GF2 8QW check deg(q)>2 (already done for GF2 4QW) and for
           GF2 4QW and 8QW check deg(xg) and deg(yg) less than deg(q).
           (note: already checked for 9QW case) */
        if (((LAC_EC_SIZE_QW8_IN_BYTES == dataOperationSizeBytes) ||
             (LAC_EC_SIZE_QW4_IN_BYTES == dataOperationSizeBytes)) &&
            (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType))
        {
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            if ((LAC_EC_SIZE_QW8_IN_BYTES == dataOperationSizeBytes) &&
                (bit_pos_q < LAC_EC_MIN_MOD_BIT_POS_GF2))
            {
                LAC_INVALID_PARAM_LOG("deg(q) is not > 2 as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(xg) < deg(q) for non zero xg */
            LacPke_GetBitPos(&(pOpData->xg), &bit_pos_x, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_x >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(xg) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(yg) < deg(q) for non zero yg */
            LacPke_GetBitPos(&(pOpData->yg), &bit_pos_y, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_y >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(yg) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure public key is not (0,0) */
        if ((0 == LacPke_CompareZero(&(pOpData->xp), 0)) &&
            (0 == LacPke_CompareZero(&(pOpData->yp), 0)))
        {
            LAC_INVALID_PARAM_LOG("Invalid public point");
            status = CPA_STATUS_INVALID_PARAM;
        }

        /* For GFP check xp and yp less than q */
        if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
        {
            /* Ensure xp < q */
            compare = LacPke_Compare(&(pOpData->xp), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("xp is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure yp < q */
            compare = LacPke_Compare(&(pOpData->yp), 0, &(pOpData->q), 0);
            if (compare >= 0)
            {
                LAC_INVALID_PARAM_LOG("yp is not < q as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
        /* For GF2 check deg(xp) and deg(yp) less than deg(q) */
        if (CPA_CY_EC_FIELD_TYPE_BINARY == pOpData->fieldType)
        {
            LacPke_GetBitPos(&(pOpData->q), &bit_pos_q, &temp, &isZero);
            /* Note we know deg(q)>2 and it is odd */
            /* Ensure deg(xp) < deg(q) for non zero xp */
            LacPke_GetBitPos(&(pOpData->xp), &bit_pos_x, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_x >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(xp) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
            /* Ensure deg(yp) < deg(q) for non zero yg */
            LacPke_GetBitPos(&(pOpData->yp), &bit_pos_y, &temp, &isZero);
            if ((CPA_TRUE != isZero) && (bit_pos_y >= bit_pos_q))
            {
                LAC_INVALID_PARAM_LOG("deg(yp) is not < deg(q) as required");
                status = CPA_STATUS_INVALID_PARAM;
            }
        }
    }
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        Cpa8U *pMemPoolConcate = NULL;
        Cpa8U *pConcateTemp = NULL;
        CpaFlatBuffer *pInBuff = NULL;
        Cpa32U functionID = 0;

        icp_qat_fw_mmp_input_param_t inVerify = {.flat_array = {0}};
        icp_qat_fw_mmp_output_param_t outVerify = {.flat_array = {0}};
        lac_pke_op_cb_data_t cbData = {0};

        /* Holding the calculated size of the input/output parameters */
        Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
        CpaBoolean internalMemInList[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};

        /* Need to concatenate user inputs - copy to ecc mempool memory */
        do
        {
            pMemPoolConcate =
                (Cpa8U *)Lac_MemPoolEntryAlloc(pCryptoService->lac_ec_pool);
            if (NULL == pMemPoolConcate)
            {
                LAC_LOG_ERROR("Cannot get mem pool entry");
                /* increment stats */
                LAC_ECDSA_STAT_INC(numEcdsaVerifyRequestErrors, pCryptoService);
                status = CPA_STATUS_RESOURCE;
            }
            else if ((void *)CPA_STATUS_RETRY == pMemPoolConcate)
            {
                osalYield();
            }
        } while ((void *)CPA_STATUS_RETRY == pMemPoolConcate);

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Concatenate q, b, a, yp, xp, yg, xg, n, r, s, m */
            /* Only concatenates least dataOperationSizeBytes bits
               of the buffers as this is all of interest to PKE
               rest of buffer is zero (see previous checks) */
            pConcateTemp = pMemPoolConcate;
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->q), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->b), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->a), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->yp), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->xp), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->yg), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->xg), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->n), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->r), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->s), dataOperationSizeBytes);
            LacEc_FlatBuffToConcate(
                &pConcateTemp, &(pOpData->m), dataOperationSizeBytes);
            pInBuff = (CpaFlatBuffer *)pConcateTemp;
            pInBuff->dataLenInBytes =
                (dataOperationSizeBytes * LAC_ECDSA_VERIFY_NUM_IN_QA_API);
            pInBuff->pData = pMemPoolConcate;

            /* populate callback data */
            cbData.pClientCb = pCb;
            cbData.pCallbackTag = pCallbackTag;
            cbData.pClientOpData = pOpData;
            cbData.pOpaqueData = pMemPoolConcate;

            /* Set the size for all parameters to be padded to */
            LAC_EC_SET_LIST_PARAMS(
                inArgSizeList,
                LAC_ECDSA_VERIFY_NUM_IN_ARGS,
                (LAC_ECDSA_VERIFY_NUM_IN_QA_API * dataOperationSizeBytes));

            /* Input Memory to QAT is internally allocated */
            internalMemInList[0] = CPA_TRUE;

            /* Populate input buffers and output buffers and set function IDs */
            if (CPA_CY_EC_FIELD_TYPE_PRIME == pOpData->fieldType)
            {
                switch (dataOperationSizeBytes)
                {
                    case LAC_EC_SIZE_QW4_IN_BYTES:
                        LacEcdsaVerifyOpDataWrite(
                            inVerify.mmp_ecdsa_verify_gfp_l256, pInBuff);
                        functionID = PKE_ECDSA_VERIFY_GFP_L256;
                        break;
                    case LAC_EC_SIZE_QW8_IN_BYTES:
                        LacEcdsaVerifyOpDataWrite(
                            inVerify.mmp_ecdsa_verify_gfp_l512, pInBuff);
                        functionID = PKE_ECDSA_VERIFY_GFP_L512;
                        break;
                    case LAC_EC_SIZE_QW9_IN_BYTES:
                        LacEcdsaVerifyOpDataWrite(
                            inVerify.mmp_ecdsa_verify_gfp_521, pInBuff);
                        functionID = PKE_ECDSA_VERIFY_GFP_521;
                        break;
                    default:
                        status = CPA_STATUS_INVALID_PARAM;
                        break;
                }
            }
            else
            {
                switch (dataOperationSizeBytes)
                {
                    case LAC_EC_SIZE_QW4_IN_BYTES:
                        LacEcdsaVerifyOpDataWrite(
                            inVerify.mmp_ecdsa_verify_gf2_l256, pInBuff);
                        functionID = PKE_ECDSA_VERIFY_GF2_L256;
                        break;
                    case LAC_EC_SIZE_QW8_IN_BYTES:
                        LacEcdsaVerifyOpDataWrite(
                            inVerify.mmp_ecdsa_verify_gf2_l512, pInBuff);
                        functionID = PKE_ECDSA_VERIFY_GF2_L512;
                        break;
                    case LAC_EC_SIZE_QW9_IN_BYTES:
                        LacEcdsaVerifyOpDataWrite(
                            inVerify.mmp_ecdsa_verify_gf2_571, pInBuff);
                        functionID = PKE_ECDSA_VERIFY_GF2_571;
                        break;
                    default:
                        status = CPA_STATUS_INVALID_PARAM;
                        break;
                }
            }

            /* Send pke request */
            if (CPA_STATUS_SUCCESS == status)
            {
                /* build a PKE request  */
                status = LacPke_SendSingleRequest(functionID,
                                                  inArgSizeList,
                                                  NULL,
                                                  &inVerify,
                                                  &outVerify,
                                                  internalMemInList,
                                                  NULL,
                                                  LacEcdsa_VerifyCallback,
                                                  &cbData,
                                                  instanceHandle);
            }

            if (CPA_STATUS_SUCCESS != status)
            {
                /* Free Mem Pool */
                if (NULL != pMemPoolConcate)
                {
                    Lac_MemPoolEntryFree(pMemPoolConcate);
                }
            }
        }
    }

    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_ECDSA_STAT_INC(numEcdsaVerifyRequests, pCryptoService);
    }
    else
    {
        LAC_ECDSA_STAT_INC(numEcdsaVerifyRequestErrors, pCryptoService);
    }

    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *
 ***************************************************************************/
CpaStatus cpaCyEcdsaQueryStats64(const CpaInstanceHandle instanceHandle_in,
                                 CpaCyEcdsaStats64 *pEcdsaStats)
{
    sal_crypto_service_t *pCryptoService = NULL;
    CpaInstanceHandle instanceHandle = NULL;
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle_in,
             (LAC_ARCH_UINT)pEcdsaStats);
#endif
    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
    else
    {
        instanceHandle = instanceHandle_in;
    }

    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_RUNNING_CHECK(instanceHandle);
    /* ensure this is a crypto or asym instance with pke enabled */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
    LAC_CHECK_NULL_PARAM(pEcdsaStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* get stats into user supplied stats structure */
    LAC_ECDSA_STATS_GET(*pEcdsaStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}
