/******************************************************************************
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
 *****************************************************************************/

/**
 *****************************************************************************
 * @file lac_ec.h
 *
 * @ingroup Lac_Ec
 *
 * Elliptic Curve components - EC, ECDH and ECDSA - common include file
 *
 * @lld_start
 *
 * @lld_overview
 * This is the common include location for Elliptic Curve components
 *
 * @lld_initialisation
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 *****************************************************************************/

/*****************************************************************************/

#ifndef LAC_EC_H
#define LAC_EC_H

#include "cpa_cy_ecdsa.h"

#define LAC_EC_SIZE_BYTES_MAX LAC_BITS_TO_BYTES(LAC_576_BITS)
#define LAC_EC_SIZE_BYTES_MIN LAC_BITS_TO_BYTES(LAC_256_BITS)

#define LAC_EC_SIZE_QW9_IN_BYTES LAC_EC_SIZE_BYTES_MAX
#define LAC_EC_SIZE_QW8_IN_BYTES LAC_BITS_TO_BYTES(LAC_512_BITS)
#define LAC_EC_SIZE_QW4_IN_BYTES LAC_EC_SIZE_BYTES_MIN

#define LAC_EC_NUM_CONCAT_INPUTS 11

#define LAC_EC_MIN_MOD_BIT_POS_GFP 2
#define LAC_EC_MIN_MOD_BIT_POS_GF2 3

#define LAC_EC_SET_LIST_PARAMS(list, list_size, val)                           \
    do                                                                         \
    {                                                                          \
        int i;                                                                 \
        for (i = 0; i < list_size; i++)                                        \
        {                                                                      \
            list[i] = val;                                                     \
        }                                                                      \
    } while (0);
/**< @ingroup Lac_Ec
 * macro to set elements in list to a specified value */

#ifndef DISABLE_STATS
#define LAC_EC_STAT_INC(statistic, pCryptoService)                             \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bEccStatsEnabled)      \
        {                                                                      \
            osalAtomicInc(                                                     \
                &pCryptoService                                                \
                     ->pLacEcStatsArr[offsetof(CpaCyEcStats64, statistic) /    \
                                      sizeof(Cpa64U)]);                        \
        }                                                                      \
    } while (0)
#else
#define LAC_EC_STAT_INC(statistic, pCryptoService)                             \
    (pCryptoService) = (pCryptoService)
#endif
/**< @ingroup Lac_Ec
 * macro to increment a EC stat (derives offset into array of atomics)
 * assumes pCryptoService has already been validated */

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      return the ECC service QW value for a given size.
 *
 * @description
 *      This function will return the QWs value (LAC_EC_SIZE_QW4_IN_BYTES,
 *      LAC_EC_SIZE_QW8_IN_BYTES or LAC_EC_SIZE_QW9_IN_BYTES) according to the
 *      size.
 *
 * @param[in]  size             input size
 * @param[out] pMax             QW value returned according to size
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_INVALID_PARAM Size is invalid.  In this case, pMax will
 *                                  be set to size
 *
 *****************************************************************************/
CpaStatus LacEc_GetRange(Cpa32U size, Cpa32U *pMax);

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      print the ECC stats to standard output
 *
 * @description
 *      prints all ECC stats (i.e. ec stats, ecdh stats and ecdsa stats)
 *
 *****************************************************************************/
void LacEc_StatsShow(CpaInstanceHandle instanceHandle);

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      Resolves and validates passed instance handle.
 *
 * @description
 *      First resolves passed value to real instance i.e. handles
 *      CPA_INSTANCE_HANDLE_SINGLE.
 *      Next it checks if instance is currently running and if it is of
 *      proper kind: SAL_SERVICE_TYPE_CRYPTO or SAL_SERVICE_TYPE_CRYPTO_ASYM
 *
 * @param[in/out]  pInstanceHandle      in:  Should point to instance handle to
 *                                           be validated or special value of
 *                                           CPA_INSTANCE_HANDLE_SINGLE.
 *                                      out: When CPA_STATUS_SUCCESS is returned,
 *                                           it points to a valid instanceHandle.
 *
 * @retval CPA_STATUS_SUCCESS       Instance resolved and confirmed valid.
 * @retval CPA_STATUS_RESTARTING    Instance is restarting.
 * @retval CPA_STATUS_INVALID_PARAM Instance is NULL.
 * @retval CPA_STATUS_FAIL          Wrong type of instance, instance not
 *                                  running or address translation failed.
 *
 *****************************************************************************/
CpaStatus LacEc_ValidateInstance(CpaInstanceHandle *pInstanceHandle);

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      Check if curve can use the optimized MMP GF2_L256 service
 *
 * @description
 *     If curve is NIST standard B-163, K-163, B-233 or K-233 then optimized
 *     MMP GF2_L256 service can be used. If not, then GF2_L512 can be used.
 *
 * @param[in/out]  pNumQWs      Initially this will have a value
 *                              LAC_EC_SIZE_QW4_IN_BYTES but will be changed to
 *                              LAC_EC_SIZE_QW8_IN_BYTES if curve not NIST
 *                              standard B-163, K-163, B-233 or K-233.
 * @param[in]  pQ               Pointer to FlatBuffer holding modulus.
 * @param[in]  pA               Pointer to FlatBuffer holding curve coeff A.
 * @param[in]  pB               Pointer to FlatBuffer holding curve coeff B.
 * @param[in]  pR               Pointer to FlatBuffer holding order of curve
 *                              (can be NULL if check not required).
 * @param[in]  pH               Pointer to FlatBuffer holding cofactor (can
 *                              be NULL if check not required).
 *
 *
 *****************************************************************************/

void LacEc_CheckCurve4QWGF2(Cpa32U *pNumQWs,
                            const CpaFlatBuffer *pQ,
                            const CpaFlatBuffer *pA,
                            const CpaFlatBuffer *pB,
                            const CpaFlatBuffer *pR,
                            const CpaFlatBuffer *pH);

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      Check if curve is NIST P-521
 *
 * @description
 *     If curve is NIST standard P-521 then PKE GFP_521 service can be used.
 *     If curve is not NIST standard curve then invalid param returned.
 *
 * @param[in]  pQ               Pointer to FlatBuffer holding modulus.
 * @param[in]  pA               Pointer to FlatBuffer holding curve coeff A.
 * @param[in]  pB               Pointer to FlatBuffer holding curve coeff B.
 * @param[in]  pR               Pointer to FlatBuffer holding order of curve
 *                              (can be NULL if check not required).
 * @param[in]  pH               Pointer to FlatBuffer holding cofactor (can
 *                              be NULL if check not required).
 * @param[in]  pX               Pointer to FlatBuffer holding x coordinate
 *                              (can be NULL if check not required).
 * @param[in]  pY               Pointer to FlatBuffer holding y coordinate
 *                              (can be NULL if check not required).
 *
 * @retval CPA_STATUS_SUCCESS       Curve is as required 521 service can be
 *                                  used.
 * @retval CPA_STATUS_INVALID_PARAM Curve is not NIST P-521 or x and y
 *                                  coordinates are greater than 521 bits.
 *
 *****************************************************************************/

CpaStatus LacEc_CheckCurve9QWGFP(const CpaFlatBuffer *pQ,
                                 const CpaFlatBuffer *pA,
                                 const CpaFlatBuffer *pB,
                                 const CpaFlatBuffer *pR,
                                 const CpaFlatBuffer *pH,
                                 const CpaFlatBuffer *pX,
                                 const CpaFlatBuffer *pY);

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      Check if curve is NIST K-571 or B-571
 *
 * @description
 *     If curve is NIST standard K-571 or B-571 then PKE GF2_571 service can be
 *     used. If curve is not NIST standard curve then invalid param returned.
 *
 * @param[in]  pQ               Pointer to FlatBuffer holding modulus.
 * @param[in]  pA               Pointer to FlatBuffer holding curve coeff A.
 * @param[in]  pB               Pointer to FlatBuffer holding curve coeff B.
 * @param[in]  pR               Pointer to FlatBuffer holding order of curve
 *                              (can be NULL if check not required).
 * @param[in]  pH               Pointer to FlatBuffer holding cofactor (can
 *                              be NULL if check not required).
 * @param[in]  pX               Pointer to FlatBuffer holding x coordinate
 *                              (can be NULL if check not required).
 * @param[in]  pY               Pointer to FlatBuffer holding y coordinate
 *                              (can be NULL if check not required).
 *
 * @retval CPA_STATUS_SUCCESS       Curve is as required 571 service can be
 *                                  used.
 * @retval CPA_STATUS_INVALID_PARAM Curve is not NIST K-571 or NIST B-571 curve
 *                                  or x or y coeff have degree greater than
 *                                  or equal to the modulus.
 *
 *
 *****************************************************************************/

CpaStatus LacEc_CheckCurve9QWGF2(const CpaFlatBuffer *pQ,
                                 const CpaFlatBuffer *pA,
                                 const CpaFlatBuffer *pB,
                                 const CpaFlatBuffer *pR,
                                 const CpaFlatBuffer *pH,
                                 const CpaFlatBuffer *pX,
                                 const CpaFlatBuffer *pY);

/**
 ******************************************************************************
 * @ingroup Lac_Ecdsa
 *      Check if there is optimised ecdsa SignRS MMP function id for the curve.
 *
 * @description
 *     If the there is optimised ecdsa SignRS MMP function for the curve it
 *     sends a request to firmware with optimised function ID.
 *
 * @param[in]  instanceHandle   Instance handle.
 * @param[in]  pCb              Callback function pointer. If this is set to a
 *                              NULL value the function will operate
 *                              synchronously.
 * @param[in]  pCallbackTag     User-supplied value to help identify request.
 * @param[in]  pOpData          Structure containing all the data needed to
 *                              perform the operation. The client code
 *                              allocates the memory for this structure. This
 *                              component takes ownership of the memory until
 *                              it is returned in the callback.
 * @param[out] pR               ECDSA message signature r.
 * @param[out] pS               ECDSA message signature s.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Optimised EcdsaSignRS is not supported for
 *                                  the platform or the curve.
 *
 *****************************************************************************/

CpaStatus LacEcdsa_OptimisedSignRS(const CpaInstanceHandle instanceHandle,
                                   const CpaCyEcdsaSignRSCbFunc pCb,
                                   void *pCallbackTag,
                                   const CpaCyEcdsaSignRSOpData *pOpData,
                                   CpaFlatBuffer *pR,
                                   CpaFlatBuffer *pS);

/**
 ******************************************************************************
 * @ingroup Lac_Ec
 *      Check if there is optimised PointMultiply MMP functioIDid for the curve.
 *
 * @description
 *     If the there is optimised PointMultiply MMP function for the curve it
 *     sends a request to firmware with optimised function ID.
 *
 * @param[in]  instanceHandle   Instance handle.
 * @param[in]  pCb              Callback function pointer. If this is set to
 *                              a NULL value the function will operate
 *                              synchronously.
 * @param[in]  pCallbackTag     User-supplied value to help identify request.
 * @param[in]  pOpData          Structure containing all the data needed to
 *                              perform the operation. The client code
 *                              allocates the memory for this structure. This
 *                              component takes ownership of the memory until
 *                              it is returned in the callback.
 * @param[out] pXk              Pointer to xk flat buffer.
 * @param[out] pYk              Pointer to yk flat buffer.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Optimised PointMultiply is not supported for
 *                                  the platform or the curve.
 *
 *****************************************************************************/

CpaStatus LacEc_OptimisedPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcPointMultiplyOpData *pOpData,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk);
#endif /* LAC_EC_H */
