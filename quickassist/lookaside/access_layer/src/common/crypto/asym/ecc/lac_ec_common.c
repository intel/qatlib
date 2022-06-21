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
 * @file lac_ec_common.c
 *
 * @defgroup Lac_Ec Elliptic Curve
 *
 * @ingroup LacAsym
 *
 * Elliptic Curve Cryptography common functions
 *
 * @lld_start
 *
 * @lld_overview
 * This is the Elliptic Curve common functions.
 *
 * @lld_dependencies
 * - \ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @lld_initialisation
 * On initialisation this component clears the stats and allocates memory
 * pool.
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
#include "cpa_cy_ec.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ecdsa.h"

/* OSAL Includes */
#include "Osal.h"

/* adf includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"

/* Look Aside Includes */
#include "lac_common.h"
#include "lac_log.h"
#include "lac_pke_qat_comms.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_hooks.h"
#include "lac_pke_utils.h"
#include "lac_sync.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "lac_ec.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "lac_ec_nist_curves.h"

/* SAL includes */
#include "sal_service_state.h"

#define LAC_EC_NUM_STATS (sizeof(CpaCyEcStats64) / sizeof(Cpa64U))
#define LAC_ECDH_NUM_STATS (sizeof(CpaCyEcdhStats64) / sizeof(Cpa64U))
#define LAC_ECDSA_NUM_STATS (sizeof(CpaCyEcdsaStats64) / sizeof(Cpa64U))

#define LAC_EC_ALL_STATS_CLEAR(pCryptoService)                                 \
    do                                                                         \
    {                                                                          \
        Cpa32U i = 0;                                                          \
                                                                               \
        for (i = 0; i < LAC_EC_NUM_STATS; i++)                                 \
        {                                                                      \
            osalAtomicSet(0, &pCryptoService->pLacEcStatsArr[i]);              \
        }                                                                      \
        for (i = 0; i < LAC_ECDH_NUM_STATS; i++)                               \
        {                                                                      \
            osalAtomicSet(0, &pCryptoService->pLacEcdhStatsArr[i]);            \
        }                                                                      \
        for (i = 0; i < LAC_ECDSA_NUM_STATS; i++)                              \
        {                                                                      \
            osalAtomicSet(0, &pCryptoService->pLacEcdsaStatsArr[i]);           \
        }                                                                      \
    } while (0)
/**< @ingroup Lac_Ec
 * macro to initialize all EC stats (stored in internal array of atomics)
 * assumes pCryptoService has already been validated */

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      ECC Initialisation function
 *
 ***************************************************************************/
CpaStatus LacEc_Init(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&(pCryptoService->pLacEcStatsArr),
                           LAC_EC_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LAC_OS_MALLOC(&(pCryptoService->pLacEcdhStatsArr),
                               LAC_ECDH_NUM_STATS * sizeof(OsalAtomic));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LAC_OS_MALLOC(&(pCryptoService->pLacEcdsaStatsArr),
                               LAC_ECDSA_NUM_STATS * sizeof(OsalAtomic));
    }

    /* initialize stats to zero */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_EC_ALL_STATS_CLEAR(pCryptoService);
    }

    return status;
}

void LacEc_StatsFree(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    if (NULL != pCryptoService->pLacEcStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacEcStatsArr);
    }

    if (NULL != pCryptoService->pLacEcdhStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacEcdhStatsArr);
    }

    if (NULL != pCryptoService->pLacEcdsaStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacEcdsaStatsArr);
    }
}

void LacEc_StatsReset(CpaInstanceHandle instanceHandle)
{
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    LAC_EC_ALL_STATS_CLEAR(pCryptoService);
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      Resolves and validates instanceHandle.
 ***************************************************************************/
CpaStatus LacEc_ValidateInstance(CpaInstanceHandle *pInstanceHandle)
{
    if (CPA_INSTANCE_HANDLE_SINGLE == *pInstanceHandle)
    {
        *pInstanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }
#ifdef ICP_PARAM_CHECK
    /* instance checks - if fail, no inc stats just return */
    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(*pInstanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(*pInstanceHandle);
#endif
    /* ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(*pInstanceHandle);
#ifdef ICP_PARAM_CHECK
    /* ensure this is a crypto or asym instance with pke enabled */
    const Cpa32U instanceType =
        SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM;
    SAL_CHECK_INSTANCE_TYPE(*pInstanceHandle, instanceType);
#endif
    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Ec
 *      Ecc Stats Show function
 ***************************************************************************/
void LacEc_StatsShow(CpaInstanceHandle instanceHandle)
{
    CpaCyEcStats64 ecStats = {0};
    CpaCyEcdhStats64 ecdhStats = {0};
    CpaCyEcdsaStats64 ecdsaStats = {0};

    /* retrieve the stats */
    (void)cpaCyEcQueryStats64(instanceHandle, &ecStats);
    (void)cpaCyEcdhQueryStats64(instanceHandle, &ecdhStats);
    (void)cpaCyEcdsaQueryStats64(instanceHandle, &ecdsaStats);

    /* log the stats to the standard output */

    /* engine info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "  ECDSA Stats                               " BORDER
            "\n" SEPARATOR);

    /* sign r requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " ECDSA Sign R Requests-Succ:     %16llu " BORDER "\n" BORDER
                   " ECDSA Sign R Request-Err:       %16llu " BORDER "\n" BORDER
                   " ECDSA Sign R Completed-Succ:    %16llu " BORDER "\n" BORDER
                   " ECDSA Sign R Completed-Err:     %16llu " BORDER "\n" BORDER
                   " ECDSA Sign R Output Invalid:    %16llu " BORDER
                   "\n" SEPARATOR,
            ecdsaStats.numEcdsaSignRRequests,
            ecdsaStats.numEcdsaSignRRequestErrors,
            ecdsaStats.numEcdsaSignRCompleted,
            ecdsaStats.numEcdsaSignRCompletedErrors,
            ecdsaStats.numEcdsaSignRCompletedOutputInvalid);

    /* s sign requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " ECDSA Sign S Requests-Succ:     %16llu " BORDER "\n" BORDER
                   " ECDSA Sign S Request-Err:       %16llu " BORDER "\n" BORDER
                   " ECDSA Sign S Completed-Succ:    %16llu " BORDER "\n" BORDER
                   " ECDSA Sign S Completed-Err:     %16llu " BORDER "\n" BORDER
                   " ECDSA Sign S Output Invalid:    %16llu " BORDER
                   "\n" SEPARATOR,
            ecdsaStats.numEcdsaSignSRequests,
            ecdsaStats.numEcdsaSignSRequestErrors,
            ecdsaStats.numEcdsaSignSCompleted,
            ecdsaStats.numEcdsaSignSCompletedErrors,
            ecdsaStats.numEcdsaSignSCompletedOutputInvalid);

    /* rs sign requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " ECDSA Sign RS Requests-Succ:    %16llu " BORDER "\n" BORDER
                   " ECDSA Sign RS Request-Err:      %16llu " BORDER "\n" BORDER
                   " ECDSA Sign RS Completed-Succ:   %16llu " BORDER "\n" BORDER
                   " ECDSA Sign RS Completed-Err:    %16llu " BORDER "\n" BORDER
                   " ECDSA Sign RS Output Invalid:   %16llu " BORDER
                   "\n" SEPARATOR,
            ecdsaStats.numEcdsaSignRSRequests,
            ecdsaStats.numEcdsaSignRSRequestErrors,
            ecdsaStats.numEcdsaSignRSCompleted,
            ecdsaStats.numEcdsaSignRSCompletedErrors,
            ecdsaStats.numEcdsaSignRSCompletedOutputInvalid);

    /* verify requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " ECDSA Verify Requests-Succ:     %16llu " BORDER "\n" BORDER
                   " ECDSA Verify Request-Err:       %16llu " BORDER "\n" BORDER
                   " ECDSA Verify Completed-Succ:    %16llu " BORDER "\n" BORDER
                   " ECDSA Verify Completed-Err:     %16llu " BORDER "\n" BORDER
                   " ECDSA Verify Output Invalid:    %16llu " BORDER
                   "\n" SEPARATOR,
            ecdsaStats.numEcdsaVerifyRequests,
            ecdsaStats.numEcdsaVerifyRequestErrors,
            ecdsaStats.numEcdsaVerifyCompleted,
            ecdsaStats.numEcdsaVerifyCompletedErrors,
            ecdsaStats.numEcdsaVerifyCompletedOutputInvalid);

    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "  EC Stats                                  " BORDER
            "\n" SEPARATOR);

    /* ec point multiply requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " EC Pt Multiply Requests-Succ:   %16llu " BORDER "\n" BORDER
                   " EC Pt Multiply Request-Err:     %16llu " BORDER "\n" BORDER
                   " EC Pt Multiply Completed-Succ:  %16llu " BORDER "\n" BORDER
                   " EC Pt Multiply Completed-Err:   %16llu " BORDER "\n" BORDER
                   " EC Pt Multiply Output Invalid:  %16llu " BORDER
                   "\n" SEPARATOR,
            ecStats.numEcPointMultiplyRequests,
            ecStats.numEcPointMultiplyRequestErrors,
            ecStats.numEcPointMultiplyCompleted,
            ecStats.numEcPointMultiplyCompletedError,
            ecStats.numEcPointMultiplyCompletedOutputInvalid);

    /* ec point verify requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " EC Pt Verify Requests-Succ:     %16llu " BORDER "\n" BORDER
                   " EC Pt Verify Request-Err:       %16llu " BORDER "\n" BORDER
                   " EC Pt Verify Completed-Succ:    %16llu " BORDER "\n" BORDER
                   " EC Pt Verify Completed-Err:     %16llu " BORDER "\n" BORDER
                   " EC Pt Verify Output Invalid:    %16llu " BORDER
                   "\n" SEPARATOR,
            ecStats.numEcPointVerifyRequests,
            ecStats.numEcPointVerifyRequestErrors,
            ecStats.numEcPointVerifyCompleted,
            ecStats.numEcPointVerifyCompletedErrors,
            ecStats.numEcPointVerifyCompletedOutputInvalid);

    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "  ECDH Stats                                " BORDER
            "\n" SEPARATOR);

    /* ecdh point multiply requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " ECDH Pt Multiply Requests-Succ: %16llu " BORDER "\n" BORDER
                   " ECDH Pt Multiply Request-Err:   %16llu " BORDER "\n" BORDER
                   " ECDH Pt Multiply Completed-Succ:%16llu " BORDER "\n" BORDER
                   " ECDH Pt Multiply Completed-Err: %16llu " BORDER "\n" BORDER
                   " ECDH Pt Multiply Output Invalid:%16llu " BORDER
                   "\n" SEPARATOR,
            ecdhStats.numEcdhPointMultiplyRequests,
            ecdhStats.numEcdhPointMultiplyRequestErrors,
            ecdhStats.numEcdhPointMultiplyCompleted,
            ecdhStats.numEcdhPointMultiplyCompletedError,
            ecdhStats.numEcdhRequestCompletedOutputInvalid);
}

void LacEc_CheckCurve4QWGF2(Cpa32U *pNumQWs,
                            const CpaFlatBuffer *pQ,
                            const CpaFlatBuffer *pA,
                            const CpaFlatBuffer *pB,
                            const CpaFlatBuffer *pR,
                            const CpaFlatBuffer *pH)
{
    Cpa32U bit_pos = 0;
    Cpa32U index = 0;
    size_t j = 0;
    CpaBoolean possible_curve = CPA_FALSE;
    CpaBoolean isZero = CPA_FALSE;

    /* Check modulus - Never NULL*/
    LacPke_GetBitPos(pQ, &bit_pos, &index, &isZero);
    if (NIST_GF2_Q_163_BIT_POS == bit_pos)
    {
        for (j = 0; j < (pQ->dataLenInBytes - index); j++)
        {
            if (nist_gf2_163_q[j] != pQ->pData[j + index])
            {
                break;
            }
        }
        if (j == (pQ->dataLenInBytes - index))
        {
            possible_curve = CPA_TRUE;
        }

    } /* if(NIST_GF2_Q_163_BIT_POS == bit_pos) */
    else
    {
        if (NIST_GF2_Q_233_BIT_POS == bit_pos)
        {
            for (j = 0; j < (pQ->dataLenInBytes - index); j++)
            {
                if (nist_gf2_233_q[j] != pQ->pData[j + index])
                {
                    break;
                }
            }
            if (j == (pQ->dataLenInBytes - index))
            {
                possible_curve = CPA_TRUE;
            }
        }

    } /* else(NIST_GF2_Q_163_BIT_POS != bit_pos) */

    if (CPA_TRUE != possible_curve)
    {
        /* Modulus not as required - cannot use L256 service */
        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
        return;
    }
    if (NIST_GF2_Q_163_BIT_POS == bit_pos)
    {

        /* Possibly K163 or B163 Curves */

        /* Check coeff A - Never NULL */
        LacPke_GetBitPos(pA, &bit_pos, &index, &isZero);
        /* Coeff A is expected to be 1 -
           therefore no need to check the value of A
           just check the isZero flag and its bit_pos */
        if ((NIST_GF2_A_163_BIT_POS != bit_pos) || (CPA_TRUE == isZero))
        {
            /* Coeff A not as required for K163 or B163 curve */
            *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
            return;
        }

        /* Check cofactor - Can be NULL */
        if (NULL != pH)
        {
            if (NULL != pH->pData)
            {
                LacPke_GetBitPos(pH, &bit_pos, &index, &isZero);
                if ((NIST_GF2_H_163_BIT_POS != bit_pos) ||
                    (nist_gf2_163_h[0] != pH->pData[index]))
                {
                    /* Cofactor not as required for K163 or B163 curve */
                    *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                    return;
                }
            } /* if(NULL != pH->pData) */
        }     /* if(NULL != pH) */

        /* Check coeff B - Never NULL */
        LacPke_GetBitPos(pB, &bit_pos, &index, &isZero);
        /* Coeff B for K163 is expected to be 1 -
           therefore no need to check value just check isZero and bit_pos */
        if ((NIST_GF2_B_K163_BIT_POS == bit_pos) && (CPA_FALSE == isZero))
        {
            /* Check Order - Can be NULL */
            if (NULL != pR)
            {
                LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
                if (NIST_GF2_R_163_BIT_POS == bit_pos)
                {
                    for (j = 0; j < (pR->dataLenInBytes - index); j++)
                    {
                        if (nist_koblitz_gf2_163_r[j] != pR->pData[j + index])
                        {
                            break;
                        }
                    }
                    if (j != (pR->dataLenInBytes - index))
                    {
                        /* Order not as required for K163 curve */
                        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                        return;
                    }

                } /* if(NIST_GF2_R_163_BIT_POS == bit_pos) */
                else
                {
                    /* Order not as required for K163 curve */
                    *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                    return;
                }

            } /* if(NULL != pR) */

            /* Found K163 curve - can use L256 service */
            *(pNumQWs) = LAC_EC_SIZE_QW4_IN_BYTES;
            return;

        } /* if((NIST_GF2_B_K163_BIT_POS == bit_pos) && (CPA_FALSE ==isZero)) */
        else
        {
            /* Check for B163 curve */
            if (NIST_GF2_B_B163_BIT_POS == bit_pos)
            {
                for (j = 0; j < (pB->dataLenInBytes - index); j++)
                {
                    if (nist_binary_gf2_163_b[j] != pB->pData[j + index])
                    {
                        break;
                    }
                }
                if (j != (pB->dataLenInBytes - index))
                {
                    /* Coeff B not as required for B163 curve */
                    *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                    return;
                }

                /* Check Order - Can be NULL */
                if (NULL != pR)
                {
                    LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
                    if (NIST_GF2_R_163_BIT_POS == bit_pos)
                    {
                        for (j = 0; j < (pR->dataLenInBytes - index); j++)
                        {
                            if (nist_binary_gf2_163_r[j] !=
                                pR->pData[j + index])
                            {
                                break;
                            }
                        }
                        if (j != (pR->dataLenInBytes - index))
                        {
                            /* Order not as required for B163 curve */
                            *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                            return;
                        }
                    }
                    else
                    {
                        /* Order not as required for B163 curve */
                        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                        return;
                    }

                } /* if(NULL != pR) */

                /* Found B163 curve - can use L256 service */
                *(pNumQWs) = LAC_EC_SIZE_QW4_IN_BYTES;
                return;
            } /* if(NIST_GF2_B_B163_BIT_POS == bit_pos) */
            else
            {
                /* Coeff B not as required for K163 or B163 curve */
                *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                return;
            }
        } /*else((NIST_GF2_B_K163_BIT_POS != bit_pos)||(CPA_FALSE !=isZero))*/

    } /* if(NIST_GF2_Q_163_BIT_POS == bit_pos) */
    else
    {
        /* Possibly K233 or B233 Curves - pQ has been validated */

        /* Check coeff A - Never NULL*/
        LacPke_GetBitPos(pA, &bit_pos, &index, &isZero);
        if (CPA_TRUE == isZero)
        {
            /* coeff A = 0 - possibly K233 */

            /* Check Cofactor - Can be NULL */
            if (NULL != pH)
            {
                if (NULL != pH->pData)
                {
                    LacPke_GetBitPos(pH, &bit_pos, &index, &isZero);
                    if ((NIST_GF2_H_K233_BIT_POS != bit_pos) ||
                        (nist_koblitz_gf2_233_h[0] != pH->pData[index]))
                    {
                        /* Cofactor not as required for K233 curve */
                        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                        return;
                    }
                }
            } /* if(NULL != pH) */

            /* Check Coeff B */
            LacPke_GetBitPos(pB, &bit_pos, &index, &isZero);
            /* Coeff B is expected to be 1 -
               therefore no need to check value just check isZero
               and bit_pos */
            if ((NIST_GF2_B_K233_BIT_POS != bit_pos) || (CPA_TRUE == isZero))
            {
                /* Coeff B not as required for K233 curve */
                *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                return;
            }

            /* Check R */
            if (NULL != pR)
            {
                LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
                if (NIST_GF2_R_K233_BIT_POS == bit_pos)
                {
                    for (j = 0; j < (pR->dataLenInBytes - index); j++)
                    {
                        if (nist_koblitz_gf2_233_r[j] != pR->pData[j + index])
                        {
                            break;
                        }
                    }
                    if (j != (pR->dataLenInBytes - index))
                    {
                        /* Order not as required for K233 curve */
                        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                        return;
                    }
                }
                else
                {
                    /* Order not as required for K233 curve */
                    *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                    return;
                }

            } /* if(NULL != pR) */

            /* Found K233 curve - can use L256 service */
            *(pNumQWs) = LAC_EC_SIZE_QW4_IN_BYTES;
            return;

        } /* if(CPA_TRUE == isZero) */
        else
        {
            /* Check if coeff A = 1 */
            if (NIST_GF2_A_233_BIT_POS == bit_pos)
            {
                /* Possibly B233 */
                /* Check Cofactor - Can be NULL */
                if (NULL != pH)
                {
                    if (NULL != pH->pData)
                    {
                        LacPke_GetBitPos(pH, &bit_pos, &index, &isZero);
                        if ((NIST_GF2_H_B233_BIT_POS != bit_pos) ||
                            (nist_binary_gf2_233_h[0] != pH->pData[index]))
                        {
                            /* Cofactor not as required for B233 curve */
                            *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                            return;
                        }
                    }
                } /* if(NULL != pH)*/

                /* Check Coeff B */
                LacPke_GetBitPos(pB, &bit_pos, &index, &isZero);
                if (NIST_GF2_B_B233_BIT_POS == bit_pos)
                {
                    for (j = 0; j < (pB->dataLenInBytes - index); j++)
                    {
                        if (nist_binary_gf2_233_b[j] != pB->pData[j + index])
                        {
                            break;
                        }
                    }
                    if (j != (pB->dataLenInBytes - index))
                    {
                        /* Coeff B not as required for B233 curve */
                        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                        return;
                    }
                } /* if(NIST_GF2_B_B233_BIT_POS == bit_pos) */
                else
                {
                    /* Coeff B not as required for B233 curve */
                    *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                    return;
                }

                /* Check R */
                if (NULL != pR)
                {
                    LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
                    if (NIST_GF2_R_B233_BIT_POS == bit_pos)
                    {
                        for (j = 0; j < (pR->dataLenInBytes - index); j++)
                        {
                            if (nist_binary_gf2_233_r[j] !=
                                pR->pData[j + index])
                            {
                                break;
                            }
                        }
                        if (j != (pR->dataLenInBytes - index))
                        {
                            /* Order not as required for B233 curve */
                            *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                            return;
                        }
                    }
                    else
                    {
                        /* Order not as required for B233 curve */
                        *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                        return;
                    }
                } /* if(NULL != pR) */

                /* Found B233 curve - can use L256 service */
                *(pNumQWs) = LAC_EC_SIZE_QW4_IN_BYTES;
                return;

            } /* if(NIST_GF2_A_233_BIT_POS == bit_pos) */
            else
            {
                /* Coeff A not as required for K233 or B233 curve */
                *(pNumQWs) = LAC_EC_SIZE_QW8_IN_BYTES;
                return;
            }

        } /* else(CPA_TRUE != isZero) */

    } /* else(NIST_GF2_Q_163_BIT_POS != bit_pos) */

    return;
}

CpaStatus LacEc_CheckCurve9QWGFP(const CpaFlatBuffer *pQ,
                                 const CpaFlatBuffer *pA,
                                 const CpaFlatBuffer *pB,
                                 const CpaFlatBuffer *pR,
                                 const CpaFlatBuffer *pH,
                                 const CpaFlatBuffer *pX,
                                 const CpaFlatBuffer *pY)
{
    /* status invalid unless curve is found */
    CpaStatus status = CPA_STATUS_INVALID_PARAM;
    Cpa32U bit_pos = 0;
    Cpa32U index = 0;
    size_t j = 0;
    CpaBoolean isZero = CPA_FALSE;

    /* Check modulus - Never NULL*/
    LacPke_GetBitPos(pQ, &bit_pos, &index, &isZero);
    if (NIST_GFP_Q_521_BIT_POS != bit_pos)
    {
        /* Length of modulus not 521 */
        LAC_INVALID_PARAM_LOG("Modulus not as expected for NIST P-521 curve");
        return status;
    }
    else
    {
        /* Modulus correct length - check value */
        for (j = 0; j < (pQ->dataLenInBytes - index); j++)
        {
            if (nist_p521_q[j] != pQ->pData[j + index])
            {
                break;
            }
        }
        if (j != (pQ->dataLenInBytes - index))
        {
            /* Modulus != 2^521-1 */
            LAC_INVALID_PARAM_LOG("Modulus not as expected for NIST "
                                  "P-521 curve");
            return status;
        }
    }
    /* Modulus as required for NIST GFP-521 curve - next check A coeff */
    LacPke_GetBitPos(pA, &bit_pos, &index, &isZero);
    if (NIST_GFP_A_521_BIT_POS != bit_pos)
    {
        /* Length not correct for P-521 curve */
        LAC_INVALID_PARAM_LOG("Coeff A not as expected for NIST P-521 curve");
        return status;
    }
    else
    {
        /* Valid length - check value */
        for (j = 0; j < (pA->dataLenInBytes - index); j++)
        {
            if (nist_p521_a[j] != pA->pData[j + index])
            {
                break;
            }
        }
        if (j != (pA->dataLenInBytes - index))
        {
            /* Value not as required for P_521 curve */
            LAC_INVALID_PARAM_LOG("Coeff A not as expected for NIST "
                                  "P-521 curve");
            return status;
        }
    }
    /* Modulus and A coeff as required - next check B coeff */
    LacPke_GetBitPos(pB, &bit_pos, &index, &isZero);
    if (NIST_GFP_B_521_BIT_POS != bit_pos)
    {
        /* Length not correct for P-521 curve */
        LAC_INVALID_PARAM_LOG("Coeff B not as expected for NIST P-521 curve");
        return status;
    }
    else
    {
        /* Valid length - check value */
        for (j = 0; j < (pB->dataLenInBytes - index); j++)
        {
            if (nist_p521_b[j] != pB->pData[j + index])
            {
                break;
            }
        }
        if (j != (pB->dataLenInBytes - index))
        {
            /* Value not as required for P-521 curve */
            LAC_INVALID_PARAM_LOG("Coeff B not as expected for NIST "
                                  "P-521 curve");
            return status;
        }
    }
    /* Modulus, A and B coeffs as required - next check Order */
    if (NULL != pR)
    {
        LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
        if (NIST_GFP_R_521_BIT_POS != bit_pos)
        {
            /* Length not correct for P-521 curve */
            LAC_INVALID_PARAM_LOG("Order not as expected for NIST "
                                  "P-521 curve");
            return status;
        }
        else
        {
            /* Valid length - check value */
            for (j = 0; j < (pR->dataLenInBytes - index); j++)
            {
                if (nist_p521_r[j] != pR->pData[j + index])
                {
                    break;
                }
            }
            if (j != (pR->dataLenInBytes - index))
            {
                /* Value not as required for P-521 curve */
                LAC_INVALID_PARAM_LOG("Order not as expected for NIST "
                                      "P-521 curve");
                return status;
            }
        }
    } /* if(NULL !== pR) */

    /* Modulus, A and B coeffs and Order as required - next check Cofactor */
    if (NULL != pH)
    {
        if (NULL != pH->pData)
        {
            LacPke_GetBitPos(pH, &bit_pos, &index, &isZero);
            if ((NIST_GFP_H_521_BIT_POS != bit_pos) || (CPA_TRUE == isZero))
            {
                /* Length not correct for P-521 curve */
                LAC_INVALID_PARAM_LOG("Cofactor not as expected for NIST "
                                      "P-521 curve");
                return status;
            }
        }
    }

    /* Curve as required - now check that x and y <= Modulus (2^521-1) */
    if (NULL != pX)
    {
        LacPke_GetBitPos(pX, &bit_pos, &index, &isZero);
        if (bit_pos > NIST_GFP_Q_521_BIT_POS)
        {
            /* x greater than Modulus */
            LAC_INVALID_PARAM_LOG("X coordinate not as expected for NIST "
                                  "P-521 curve");
            return status;
        }
    }
    if (NULL != pY)
    {
        LacPke_GetBitPos(pY, &bit_pos, &index, &isZero);
        if (bit_pos > NIST_GFP_Q_521_BIT_POS)
        {
            /* y coeff greater than Modulus */
            LAC_INVALID_PARAM_LOG("Y coordinate not as expected for NIST "
                                  "P-521 curve");
            return status;
        }
    }
    /* Curve as required - return success */
    return CPA_STATUS_SUCCESS;
}

CpaStatus LacEc_CheckCurve9QWGF2(const CpaFlatBuffer *pQ,
                                 const CpaFlatBuffer *pA,
                                 const CpaFlatBuffer *pB,
                                 const CpaFlatBuffer *pR,
                                 const CpaFlatBuffer *pH,
                                 const CpaFlatBuffer *pX,
                                 const CpaFlatBuffer *pY)
{
    /* status invalid unless curve is found */
    CpaStatus status = CPA_STATUS_INVALID_PARAM;
    Cpa32U bit_pos = 0;
    Cpa32U index = 0;
    size_t j = 0;
    CpaBoolean isZero = CPA_FALSE;

    /* Check modulus - Never NULL*/
    LacPke_GetBitPos(pQ, &bit_pos, &index, &isZero);
    if (NIST_GF2_Q_571_BIT_POS != bit_pos)
    {
        /* Length of modulus not as required */
        LAC_INVALID_PARAM_LOG("Modulus not as expected for NIST 571 curves");
        return status;
    }
    else
    {
        /* Modulus correct length - check value */
        for (j = 0; j < (pQ->dataLenInBytes - index); j++)
        {
            if (nist_gf2_571_q[j] != pQ->pData[j + index])
            {
                break;
            }
        }
        if (j != (pQ->dataLenInBytes - index))
        {
            /* Modulus value not as required */
            LAC_INVALID_PARAM_LOG("Modulus not as expected for NIST "
                                  "571 curves");
            return status;
        }
    }
    /* Modulus as required for NIST 571 curves - next check A coeff */
    LacPke_GetBitPos(pA, &bit_pos, &index, &isZero);
    if (NIST_GF2_A_571_BIT_POS != bit_pos)
    {
        /* For K-571 A coeff = 0 and for B-571 A coeff = 1, therefore
           bit_pos = 1 is only valid cases */
        /* Length of A coeff not as required for K-571 or B-571 */
        LAC_INVALID_PARAM_LOG("Coeff A not as expected for NIST 571 curves");
        return status;
    }
    if (CPA_TRUE == isZero)
    {
        /* Check for K-571 curve */
        /* Check B Coeff */
        LacPke_GetBitPos(pB, &bit_pos, &index, &isZero);
        if ((NIST_GF2_B_K571_BIT_POS != bit_pos) || (CPA_TRUE == isZero))
        {
            /* Length not correct for K-571 curve */
            LAC_INVALID_PARAM_LOG("Coeff B not as expected for NIST "
                                  "K571 curve");
            return status;
        }
        /* Modulus, Coeff A and B as required for K-571 */
        /* Check Order */
        if (NULL != pR)
        {
            LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
            if (NIST_GF2_R_K571_BIT_POS != bit_pos)
            {
                /* Length not correct for K-571 curve */
                LAC_INVALID_PARAM_LOG("Order not as expected for NIST "
                                      "K571 curve");
                return status;
            }
            else
            {
                /* Valid length - check value */
                for (j = 0; j < (pR->dataLenInBytes - index); j++)
                {
                    if (nist_koblitz_gf2_571_r[j] != pR->pData[j + index])
                    {
                        break;
                    }
                }
                if (j != (pR->dataLenInBytes - index))
                {
                    /* Value not as required for K-571 curve */
                    LAC_INVALID_PARAM_LOG("Order not as expected for NIST "
                                          "K571 curve");
                    return status;
                }
            }
        } /* if(NULL = pR) */

        /* Check Cofactor */
        if (NULL != pH)
        {
            if (NULL != pH->pData)
            {
                LacPke_GetBitPos(pH, &bit_pos, &index, &isZero);
                if (NIST_GF2_H_K571_BIT_POS != bit_pos)
                {
                    /* Length not correct for K-571 curve */
                    LAC_INVALID_PARAM_LOG("Cofactor not as expected for NIST "
                                          "K571 curve");
                    return status;
                }
                else
                {
                    /* Valid length - check value */
                    for (j = 0; j < (pH->dataLenInBytes - index); j++)
                    {
                        if (nist_koblitz_gf2_571_h[j] != pH->pData[j + index])
                        {
                            break;
                        }
                    }
                    if (j != (pH->dataLenInBytes - index))
                    {
                        /* Value not as required for K-571 curve */
                        LAC_INVALID_PARAM_LOG(
                            "Cofactor not as expected for NIST"
                            " K571 curve");
                        return status;
                    }
                }

            } /* if(NULL != pH->pData) */

        } /* if(NULL != pH) */

        /* Found K-571 curve - now check degree of X and Y is required */
        if (NULL != pX)
        {
            LacPke_GetBitPos(pX, &bit_pos, &index, &isZero);
            if (bit_pos >= NIST_GF2_Q_571_BIT_POS)
            {
                /* deg X should be less than deg modulus */
                LAC_INVALID_PARAM_LOG("X coordinate not as expected for NIST "
                                      "K571 curve");
                return status;
            }
        }
        if (NULL != pY)
        {

            LacPke_GetBitPos(pY, &bit_pos, &index, &isZero);
            if (bit_pos >= NIST_GF2_Q_571_BIT_POS)
            {
                /* deg Y should be less than deg modulus */
                LAC_INVALID_PARAM_LOG("Y coordinate not as expected for NIST "
                                      "K571 curve");
                return status;
            }
        }
        status = CPA_STATUS_SUCCESS;

    } /* if(CPA_TRUE==isZero) */
    else
    {
        /* Check for B-571 curve */
        /* Check B Coeff */
        LacPke_GetBitPos(pB, &bit_pos, &index, &isZero);
        if (NIST_GF2_B_B571_BIT_POS != bit_pos)
        {
            /* Length not correct for B-571 curve */
            LAC_INVALID_PARAM_LOG("Coeff B not as expected for NIST "
                                  "B571 curve");
            return status;
        }
        else
        {
            /* Valid length - check value */
            for (j = 0; j < (pB->dataLenInBytes - index); j++)
            {
                if (nist_binary_gf2_571_b[j] != pB->pData[j + index])
                {
                    break;
                }
            }
            if (j != (pB->dataLenInBytes - index))
            {
                /* Value not as required for B-571 curve */
                LAC_INVALID_PARAM_LOG("Coeff B not as expected for NIST "
                                      "B571 curve");
                return status;
            }
        }

        /* Modulus, Coeff A and B as required for B-571 */
        /* Check Order */
        if (NULL != pR)
        {
            LacPke_GetBitPos(pR, &bit_pos, &index, &isZero);
            if (NIST_GF2_R_B571_BIT_POS != bit_pos)
            {
                /* Length not correct for B-571 curve */
                LAC_INVALID_PARAM_LOG("Order not as expected for NIST "
                                      "B571 curve");
                return status;
            }
            else
            {
                /* Valid length - check value */
                for (j = 0; j < (pR->dataLenInBytes - index); j++)
                {
                    if (nist_binary_gf2_571_r[j] != pR->pData[j + index])
                    {
                        break;
                    }
                }
                if (j != (pR->dataLenInBytes - index))
                {
                    /* Value not as required for B-571 curve */
                    LAC_INVALID_PARAM_LOG("Order not as expected for NIST "
                                          "B571 curve");
                    return status;
                }
            }
        } /* if(NULL != pR) */

        /* Check Cofactor */
        if (NULL != pH)
        {
            if (NULL != pH->pData)
            {
                LacPke_GetBitPos(pH, &bit_pos, &index, &isZero);
                if (NIST_GF2_H_B571_BIT_POS != bit_pos)
                {
                    /* Length not correct for B-571 curve */
                    LAC_INVALID_PARAM_LOG("Cofactor not as expected for NIST "
                                          "B571 curve");
                    return status;
                }
                else
                {
                    /* Valid length - check value */
                    for (j = 0; j < (pH->dataLenInBytes - index); j++)
                    {
                        if (nist_binary_gf2_571_h[j] != pH->pData[j + index])
                        {
                            break;
                        }
                    }
                    if (j != (pH->dataLenInBytes - index))
                    {
                        /* Value not as required for B-571 curve */
                        LAC_INVALID_PARAM_LOG(
                            "Cofactor not as expected for NIST"
                            " B571 curve");
                        return status;
                    }
                }

            } /* if(NULL != pH->pData) */

        } /* if(NULL != pH) */

        /* Found B-571 curve */
        if (NULL != pX)
        {

            LacPke_GetBitPos(pX, &bit_pos, &index, &isZero);
            if (bit_pos >= NIST_GF2_Q_571_BIT_POS)
            {
                /* deg X should be less than deg modulus */
                LAC_INVALID_PARAM_LOG("X coordinate not as expected for NIST "
                                      "B571 curve");
                return status;
            }
        }
        if (NULL != pY)
        {

            LacPke_GetBitPos(pY, &bit_pos, &index, &isZero);
            if (bit_pos >= NIST_GF2_Q_571_BIT_POS)
            {
                /* deg Y should be less than deg modulus */
                LAC_INVALID_PARAM_LOG("Y coordinate not as expected for NIST "
                                      "B571 curve");
                return status;
            }
        }

        status = CPA_STATUS_SUCCESS;

    } /* else(CPA_TRUE != isZero) */

    return status;
}

CpaStatus LacEc_GetRange(Cpa32U size, Cpa32U *pMax)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    LAC_ASSERT_NOT_NULL(pMax);

    if (LAC_EC_SIZE_QW4_IN_BYTES >= size)
    {
        size = LAC_EC_SIZE_QW4_IN_BYTES;
    }
    else if (LAC_EC_SIZE_QW8_IN_BYTES >= size)
    {
        size = LAC_EC_SIZE_QW8_IN_BYTES;
    }
    else if (LAC_EC_SIZE_QW9_IN_BYTES >= size)
    {
        size = LAC_EC_SIZE_QW9_IN_BYTES;
    }
    else
    {
        status = CPA_STATUS_INVALID_PARAM;
    }

    *pMax = size;

    return status;
}
