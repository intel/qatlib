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
 * @file lac_dsa.c
 *
 * @ingroup Lac_Dsa
 *
 * This file contains the implementation of DSA functions
 *
 ***************************************************************************/

/*
****************************************************************************
* Include public/global header files
****************************************************************************
*/

/* Include API files */
#include "cpa.h"
#include "cpa_cy_dsa.h"

/*
****************************************************************************
* Include private header files
****************************************************************************
*/
/* Osal includes */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

/* FW includes */
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_mmp.h"
#include "icp_qat_fw_mmp_ids.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "lac_list.h"
#include "lac_sym_qat.h"
#include "lac_sal_types_crypto.h"
#include "icp_adf_init.h"
#include "lac_sal.h"
#include "sal_service_state.h"
#include "lac_sal_ctrl.h"
#include "lac_pke_mmp.h"
#include "lac_common.h"
#include "lac_dsa.h"
#include "lac_hooks.h"
#include "lac_pke_qat_comms.h"
#include "lac_pke_utils.h"
#include "sal_statistics.h"

/*
****************************************************************************
* Global Variables
****************************************************************************
*/

/*
****************************************************************************
* Static Variables
****************************************************************************
*/

static const Cpa32U lacDsaGenPSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_1024_160_PAIR, PKE_DSA_GEN_P_1024_160},
    {LAC_DSA_2048_224_PAIR, PKE_DSA_GEN_P_2048_224},
    {LAC_DSA_2048_256_PAIR, PKE_DSA_GEN_P_2048_256},
    {LAC_DSA_3072_256_PAIR, PKE_DSA_GEN_P_3072_256}};
/**<
 * Maps between operation sizes and PKE GEN_P function ids */

static const Cpa32U lacDsaGenGSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_L_1024, PKE_DSA_GEN_G_1024},
    {LAC_DSA_L_2048, PKE_DSA_GEN_G_2048},
    {LAC_DSA_L_3072, PKE_DSA_GEN_G_3072}};
/**<
 * Maps between operation sizes and PKE GEN_G function ids */

static const Cpa32U lacDsaGenYSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_L_1024, PKE_DSA_GEN_Y_1024},
    {LAC_DSA_L_2048, PKE_DSA_GEN_Y_2048},
    {LAC_DSA_L_3072, PKE_DSA_GEN_Y_3072}};
/**<
 * Maps between operation size and PKE GEN_Y function ids */

static const Cpa32U lacDsaSignRSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_1024_160_PAIR, PKE_DSA_SIGN_R_1024_160},
    {LAC_DSA_2048_224_PAIR, PKE_DSA_SIGN_R_2048_224},
    {LAC_DSA_2048_256_PAIR, PKE_DSA_SIGN_R_2048_256},
    {LAC_DSA_3072_256_PAIR, PKE_DSA_SIGN_R_3072_256}};
/**<
 * Maps between operation sizes and PKE SIGN_R function ids */

static const Cpa32U lacDsaSignSSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_N_160, PKE_DSA_SIGN_S_160},
    {LAC_DSA_N_224, PKE_DSA_SIGN_S_224},
    {LAC_DSA_N_256, PKE_DSA_SIGN_S_256}};
/**<
 * Maps between operation size and PKE SIGN_S function ids */

static const Cpa32U lacDsaSignRsSizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_1024_160_PAIR, PKE_DSA_SIGN_R_S_1024_160},
    {LAC_DSA_2048_224_PAIR, PKE_DSA_SIGN_R_S_2048_224},
    {LAC_DSA_2048_256_PAIR, PKE_DSA_SIGN_R_S_2048_256},
    {LAC_DSA_3072_256_PAIR, PKE_DSA_SIGN_R_S_3072_256}};
/**<
 * Maps between operation sizes and PKE SIGN_R_S function ids */

static const Cpa32U lacDsaVerifySizeIdMap[][LAC_PKE_NUM_COLUMNS] = {
    {LAC_DSA_1024_160_PAIR, PKE_DSA_VERIFY_1024_160},
    {LAC_DSA_2048_224_PAIR, PKE_DSA_VERIFY_2048_224},
    {LAC_DSA_2048_256_PAIR, PKE_DSA_VERIFY_2048_256},
    {LAC_DSA_3072_256_PAIR, PKE_DSA_VERIFY_3072_256}};
/**<
 * Maps between operation sizes and PKE VERIFY function ids */

/**< Number of DSA stats */
#define LAC_DSA_NUM_STATS (sizeof(CpaCyDsaStats64) / sizeof(Cpa64U))

/**< macro to initialize all DSA stats (stored in internal array of atomics) */
#define LAC_DSA_STATS_INIT(pCryptoService)                                     \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_DSA_NUM_STATS; i++)                                \
        {                                                                      \
            osalAtomicSet(0, &(pCryptoService)->pLacDsaStatsArr[i]);           \
        }                                                                      \
    } while (0)

/* macro to increment a DSA stat (derives offset into array of atomics) */
#ifndef DISABLE_STATS
#define LAC_DSA_STAT_INC(statistic, pCryptoService)                            \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE ==                                                        \
            pCryptoService->generic_service_info.stats->bDsaStatsEnabled)      \
        {                                                                      \
            osalAtomicInc(                                                     \
                &(pCryptoService)                                              \
                     ->pLacDsaStatsArr[offsetof(CpaCyDsaStats64, statistic) /  \
                                       sizeof(Cpa64U)]);                       \
        }                                                                      \
    } while (0)
#else
#define LAC_DSA_STAT_INC(statistic, pCryptoService)
#endif

/**< macro to get all 32bit DSA stats (from internal array of atomics) */
#define LAC_DSA_STATS32_GET(dsaStats, pCryptoService)                          \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_DSA_NUM_STATS; i++)                                \
        {                                                                      \
            ((Cpa32U *)&(dsaStats))[i] =                                       \
                (Cpa32U)osalAtomicGet(&(pCryptoService)->pLacDsaStatsArr[i]);  \
        }                                                                      \
    } while (0)

/**< macro to get all 64bit DSA stats (from internal array of atomics) */
#define LAC_DSA_STATS64_GET(dsaStats, pCryptoService)                          \
    do                                                                         \
    {                                                                          \
        Cpa32U i;                                                              \
                                                                               \
        for (i = 0; i < LAC_DSA_NUM_STATS; i++)                                \
        {                                                                      \
            ((Cpa64U *)&(dsaStats))[i] =                                       \
                osalAtomicGet(&(pCryptoService)->pLacDsaStatsArr[i]);          \
        }                                                                      \
    } while (0)

/*
****************************************************************************
* Define static function definitions
****************************************************************************
*/

/*
****************************************************************************
* Define public/global function definitions
****************************************************************************
*/

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      Given DSA {L,N} Pair (L is the bit len of P and N is the
 *       bit len of Q as defined in FIPS186-3) this function returns
 *       a value from the lac_dsa_ln_pair_t enum
 ***************************************************************************/

STATIC
lac_dsa_ln_pairs_t LacDsa_GetLNPair(Cpa32U opSizeLBits, Cpa32U opSizeNBits)
{
    if ((LAC_1024_BITS == opSizeLBits) && (LAC_160_BITS == opSizeNBits))
    {
        return LAC_DSA_1024_160_PAIR;
    }
    else if ((LAC_2048_BITS == opSizeLBits) && (LAC_224_BITS == opSizeNBits))
    {
        return LAC_DSA_2048_224_PAIR;
    }
    else if ((LAC_2048_BITS == opSizeLBits) && (LAC_256_BITS == opSizeNBits))
    {
        return LAC_DSA_2048_256_PAIR;
    }
    else if ((LAC_3072_BITS == opSizeLBits) && (LAC_256_BITS == opSizeNBits))
    {
        return LAC_DSA_3072_256_PAIR;
    }
    else
    {
        return LAC_DSA_INVALID_PAIR;
    }
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      Given DSA the bit len of P this function returns
 *       a value from the lac_dsa_l_values_t enum
 ***************************************************************************/

STATIC
lac_dsa_l_values_t LacDsa_GetL(Cpa32U sizeLBits)
{
    if (LAC_1024_BITS == sizeLBits)
    {
        return LAC_DSA_L_1024;
    }
    else if (LAC_2048_BITS == sizeLBits)
    {
        return LAC_DSA_L_2048;
    }
    else if (LAC_3072_BITS == sizeLBits)
    {
        return LAC_DSA_L_3072;
    }
    else
    {
        return LAC_DSA_L_INVALID;
    }
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      Given DSA the bit len of Q this function returns
 *       a value from the lac_dsa_n_values_t enum
 ***************************************************************************/

STATIC
lac_dsa_n_values_t LacDsa_GetN(Cpa32U sizeNBits)
{
    if (LAC_160_BITS == sizeNBits)
    {
        return LAC_DSA_N_160;
    }
    else if (LAC_224_BITS == sizeNBits)
    {
        return LAC_DSA_N_224;
    }
    else if (LAC_256_BITS == sizeNBits)
    {
        return LAC_DSA_N_256;
    }
    else
    {
        return LAC_DSA_N_INVALID;
    }
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      Given the bit len of P (i.e. L) this function checks if GenY
 *      input param X is in appropriate range
 ***************************************************************************/

STATIC
CpaStatus LacDsa_CheckSizeX(Cpa32U bitLenL, Cpa32U sizeXBits)
{

    if (((LAC_1024_BITS == bitLenL) && (sizeXBits <= LAC_160_BITS)) ||
        ((LAC_1024_BITS != bitLenL) && (sizeXBits <= LAC_256_BITS)))
    {
        return CPA_STATUS_SUCCESS;
    }

    return CPA_STATUS_INVALID_PARAM;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA P Parameter Generation internal callback
 ***************************************************************************/
STATIC
void LacDsaPParamGenCallback(CpaStatus status,
                             CpaBoolean protocolStatus,
                             CpaInstanceHandle instanceHandle,
                             lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaGenCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaPParamGenOpData *pOpData = NULL;
    CpaFlatBuffer *pP = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaGenCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData =
        (CpaCyDsaPParamGenOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pP = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pP);

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaPParamGenCompleted, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaPParamGenCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, protocolStatus, pP);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA P Parameter Generation parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaPParamGenParamCheck(CpaCyDsaGenCbFunc pCb,
                                    const CpaCyDsaPParamGenOpData *pOpData,
                                    CpaBoolean *pProtocolStatus,
                                    CpaFlatBuffer *pP)
{
    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pProtocolStatus);
    LAC_CHECK_NULL_PARAM(pP);
    LAC_ENSURE_NOT_NULL(pCb);

    /* check parameters for null, zero len and LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);

    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->X, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Q, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->Q);
    LAC_CHECK_FLAT_BUFFER_PARAM(pP, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA P Parameter Generation synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaPParamGenSyn(const CpaInstanceHandle instanceHandle,
                                    const CpaCyDsaPParamGenOpData *pOpData,
                                    CpaBoolean *pProtocolStatus,
                                    CpaFlatBuffer *pP)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaGenPParam(instanceHandle,
                                   LacSync_GenFlatBufVerifyCb,
                                   pSyncCallbackData,
                                   pOpData,
                                   pProtocolStatus,
                                   pP);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaPParamGenRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pProtocolStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
            /*
             * Inc stats only if the wait for callback failed.
             */
#ifndef DISABLE_STATS
            LAC_DSA_STAT_INC(numDsaPParamGenCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA P Parameter Generation API function
 ***************************************************************************/
CpaStatus cpaCyDsaGenPParam(const CpaInstanceHandle instanceHandle_in,
                            const CpaCyDsaGenCbFunc pCb,
                            void *pCallbackTag,
                            const CpaCyDsaPParamGenOpData *pOpData,
                            CpaBoolean *pProtocolStatus,
                            CpaFlatBuffer *pP)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOut[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U bitLenX = 0, bitLenQ = 0;
    Cpa32U byteLenX = 0;
    lac_dsa_ln_pairs_t opIndex = LAC_DSA_INVALID_PAIR;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status =
            LacDsaPParamGenSyn(instanceHandle, pOpData, pProtocolStatus, pP);
        if (NULL != pProtocolStatus)
        {
            LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx[%d], 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     *pProtocolStatus,
                     (LAC_ARCH_UINT)pP);
        }
        else
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     (LAC_ARCH_UINT)pP);
        }
        return status;
#else
        return LacDsaPParamGenSyn(instanceHandle, pOpData, pProtocolStatus, pP);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaPParamGenParamCheck(pCb, pOpData, pProtocolStatus, pP);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->X), &bitLenX);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->Q), &bitLenQ);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetLNPair(bitLenX, bitLenQ);
        byteLenX = LAC_BITS_TO_BYTES(bitLenX);
#ifdef ICP_PARAM_CHECK
        if (LAC_DSA_INVALID_PAIR == opIndex)
        {
            LAC_INVALID_PARAM_LOG("X is not such that 2^(L-1) <= X < 2^L "
                                  "or Q is not such that 2^(N-1) <= Q < 2^N. "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure output buffer is the required size */
        if (pP->dataLenInBytes < byteLenX)
        {
            LAC_INVALID_PARAM_LOG("Output Buffer has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* If output buffer is larger than L we need to zero MS bytes */
        osalMemSet(pP->pData, 0, (pP->dataLenInBytes - byteLenX));

        functionalityId = LacPke_GetMmpId(
            opIndex, lacDsaGenPSizeIdMap, LAC_ARRAY_LEN(lacDsaGenPSizeIdMap));

        /* Note: Using mmp_dsa_gen_p_1024_160 for all functionalityIds -
           checked at compile time (see lac_dsa_interface_check.c) that
           this is a valid assumption */

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_p_1024_160.x, &pOpData->X);
        /* bitLenX is either 1024, 2048 or 3072 - all multiples of 64 bits
           so no need to round up the size to nearest QW */
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_input_t, x)] =
            byteLenX;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_input_t, x)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_p_1024_160.q, &pOpData->Q);
        /* bitLenQ is either 160, 224 or 256 - not all multiples of 64 bits
           so we need to round out to nearest QW */
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_input_t, q)] =
            LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(bitLenQ),
                                   LAC_QUAD_WORD_IN_BYTES);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_input_t, q)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_gen_p_1024_160.p, pP);
        outArgSizeList[0] = byteLenX;
        internalMemOut[0] = CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pP;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          internalMemOut,
                                          LacDsaPParamGenCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaPParamGenRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaPParamGenRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA G Parameter Generation internal callback
 ***************************************************************************/
STATIC
void LacDsaGParamGenCallback(CpaStatus status,
                             CpaBoolean protocolStatus,
                             CpaInstanceHandle instanceHandle,
                             lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaGenCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaGParamGenOpData *pOpData = NULL;
    CpaFlatBuffer *pG = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaGenCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData =
        (CpaCyDsaGParamGenOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pG = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pG);
#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaGParamGenCompleted, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaGParamGenCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, protocolStatus, pG);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA G Parameter Generation parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaGParamGenParamCheck(const CpaCyDsaGenCbFunc pCb,
                                    const CpaCyDsaGParamGenOpData *pOpData,
                                    CpaBoolean *pProtocolStatus,
                                    CpaFlatBuffer *pG)
{
    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);

    /* check for valid output pointers */
    LAC_CHECK_NULL_PARAM(pProtocolStatus);
    LAC_CHECK_NULL_PARAM(pG);

    /* check parameters for null, zero len and LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->P, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->P);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Q, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->Q);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->H, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pG, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA G Parameter Generation synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaGParamGenSyn(const CpaInstanceHandle instanceHandle,
                                    const CpaCyDsaGParamGenOpData *pOpData,
                                    CpaBoolean *pProtocolStatus,
                                    CpaFlatBuffer *pG)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaGenGParam(instanceHandle,
                                   LacSync_GenFlatBufVerifyCb,
                                   pSyncCallbackData,
                                   pOpData,
                                   pProtocolStatus,
                                   pG);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaGParamGenRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pProtocolStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_DSA_STAT_INC(numDsaGParamGenCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA G Parameter Generation API function
 ***************************************************************************/
CpaStatus cpaCyDsaGenGParam(const CpaInstanceHandle instanceHandle_in,
                            const CpaCyDsaGenCbFunc pCb,
                            void *pCallbackTag,
                            const CpaCyDsaGParamGenOpData *pOpData,
                            CpaBoolean *pProtocolStatus,
                            CpaFlatBuffer *pG)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOut[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U bitLenL = 0, nonceN = 0;
    Cpa32U opSizeLInBytes = 0;
    lac_dsa_l_values_t opIndex = LAC_DSA_L_INVALID;
#ifdef ICP_PARAM_CHECK
    lac_dsa_ln_pairs_t lnPair = LAC_DSA_INVALID_PAIR;
#endif

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status =
            LacDsaGParamGenSyn(instanceHandle, pOpData, pProtocolStatus, pG);
        if (NULL != pProtocolStatus)
        {
            LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx[%d], 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     *pProtocolStatus,
                     (LAC_ARCH_UINT)pG);
        }
        else
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     (LAC_ARCH_UINT)pG);
        }
        return status;
#else
        return LacDsaGParamGenSyn(instanceHandle, pOpData, pProtocolStatus, pG);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaGParamGenParamCheck(pCb, pOpData, pProtocolStatus, pG);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->P), &bitLenL);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->Q), &nonceN);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetL(bitLenL);
        opSizeLInBytes = LAC_BITS_TO_BYTES(bitLenL);
#ifdef ICP_PARAM_CHECK
        lnPair = LacDsa_GetLNPair(bitLenL, nonceN);
        if (LAC_DSA_INVALID_PAIR == lnPair)
        {
            LAC_INVALID_PARAM_LOG("P, Q out of range "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 1 < h < p-1 */
        if ((LacPke_CompareZero(&(pOpData->H), -1) <= 0) ||
            (LacPke_Compare(&(pOpData->H), 0, &(pOpData->P), -1) >= 0))
        {
            LAC_INVALID_PARAM_LOG("H out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
        /* Ensure output buffer is the required size */
        if (pG->dataLenInBytes < opSizeLInBytes)
        {
            LAC_INVALID_PARAM_LOG("Output Buffer has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* If output buffer is larger than L we need to zero MS bytes */
        osalMemSet(pG->pData, 0, (pG->dataLenInBytes - opSizeLInBytes));

        functionalityId = LacPke_GetMmpId(
            opIndex, lacDsaGenGSizeIdMap, LAC_ARRAY_LEN(lacDsaGenGSizeIdMap));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_g_1024.p, &pOpData->P);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_input_t, p)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_g_1024.q, &pOpData->Q);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_input_t, q)] =
            LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(nonceN),
                                   LAC_QUAD_WORD_IN_BYTES);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_g_1024.h, &pOpData->H);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_input_t, h)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_input_t, h)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_gen_g_1024.g, pG);
        outArgSizeList[0] = opSizeLInBytes;
        internalMemOut[0] = CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pG;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          internalMemOut,
                                          LacDsaGParamGenCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaGParamGenRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaGParamGenRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Y Parameter Generation internal callback
 ***************************************************************************/
STATIC
void LacDsaYParamGenCallback(CpaStatus status,
                             CpaBoolean protocolStatus,
                             CpaInstanceHandle instanceHandle,
                             lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaGenCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaYParamGenOpData *pOpData = NULL;
    CpaFlatBuffer *pY = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaGenCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData =
        (CpaCyDsaYParamGenOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pY = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pY);
#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaYParamGenCompleted, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaYParamGenCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, protocolStatus, pY);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Y Parameter Generation parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaYParamGenParamCheck(const CpaCyDsaGenCbFunc pCb,
                                    const CpaCyDsaYParamGenOpData *pOpData,
                                    CpaBoolean *pProtocolStatus,
                                    CpaFlatBuffer *pY)
{

    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);

    /* check for valid output pointers */
    LAC_CHECK_NULL_PARAM(pProtocolStatus);
    LAC_CHECK_NULL_PARAM(pY);

    /* check parameters for null, zero size, or LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->P, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->P);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->G, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->X, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pY, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Y Parameter Generation synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaYParamGenSyn(const CpaInstanceHandle instanceHandle,
                                    const CpaCyDsaYParamGenOpData *pOpData,
                                    CpaBoolean *pProtocolStatus,
                                    CpaFlatBuffer *pY)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaGenYParam(instanceHandle,
                                   LacSync_GenFlatBufVerifyCb,
                                   pSyncCallbackData,
                                   pOpData,
                                   pProtocolStatus,
                                   pY);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaYParamGenRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pProtocolStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_DSA_STAT_INC(numDsaYParamGenCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA Y Parameter Generation API function
 ***************************************************************************/
CpaStatus cpaCyDsaGenYParam(const CpaInstanceHandle instanceHandle_in,
                            const CpaCyDsaGenCbFunc pCb,
                            void *pCallbackTag,
                            const CpaCyDsaYParamGenOpData *pOpData,
                            CpaBoolean *pProtocolStatus,
                            CpaFlatBuffer *pY)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOut[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U bitLenL = 0, opSizeLInBytes = 0;
    Cpa32U bitLenX = 0;
    lac_dsa_l_values_t opIndex = LAC_DSA_L_INVALID;

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status =
            LacDsaYParamGenSyn(instanceHandle, pOpData, pProtocolStatus, pY);
        if (NULL != pProtocolStatus)
        {
            LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx[%d], 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     *pProtocolStatus,
                     (LAC_ARCH_UINT)pY);
        }
        else
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     (LAC_ARCH_UINT)pY);
        }
        return status;
#else
        return LacDsaYParamGenSyn(instanceHandle, pOpData, pProtocolStatus, pY);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaYParamGenParamCheck(pCb, pOpData, pProtocolStatus, pY);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif

    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->P), &bitLenL);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetL(bitLenL);
        opSizeLInBytes = LAC_BITS_TO_BYTES(bitLenL);
#ifdef ICP_PARAM_CHECK
        if (LAC_DSA_L_INVALID == opIndex)
        {
            LAC_INVALID_PARAM_LOG("P does not support size L "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* Check 1 < g < p */
        if ((LacPke_CompareZero(&(pOpData->G), -1) <= 0) ||
            (LacPke_Compare(&(pOpData->G), 0, &(pOpData->P), 0) >= 0))

        {
            LAC_INVALID_PARAM_LOG("G out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check the bit length of X */
        bitLenX = LAC_BYTES_TO_BITS(LacPke_GetMinBytes(&(pOpData->X)));
        if (CPA_STATUS_SUCCESS != LacDsa_CheckSizeX(bitLenL, bitLenX))
        {
            LAC_INVALID_PARAM_LOG("X out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure output buffer is the required size */
        if (pY->dataLenInBytes < opSizeLInBytes)
        {
            LAC_INVALID_PARAM_LOG("Output Buffer has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* If output buffer is larger than L we need to zero MS bytes */
        osalMemSet(pY->pData, 0, (pY->dataLenInBytes - opSizeLInBytes));

        functionalityId = LacPke_GetMmpId(
            opIndex, lacDsaGenYSizeIdMap, LAC_ARRAY_LEN(lacDsaGenYSizeIdMap));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_y_1024.p, &pOpData->P);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_input_t, p)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_y_1024.g, &pOpData->G);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_input_t, g)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_input_t, g)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_gen_y_1024.x, &pOpData->X);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_input_t, x)] =
            LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(bitLenX),
                                   LAC_QUAD_WORD_IN_BYTES);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_input_t, x)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_gen_y_1024.y, pY);
        outArgSizeList[0] = opSizeLInBytes;
        internalMemOut[0] = CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pY;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          internalMemOut,
                                          LacDsaYParamGenCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaYParamGenRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaYParamGenRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA R Sign internal callback
 ***************************************************************************/
STATIC
void LacDsaRSignCallback(CpaStatus status,
                         CpaBoolean protocolStatus,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaGenCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaRSignOpData *pOpData = NULL;
    CpaFlatBuffer *pR = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif

    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaGenCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyDsaRSignOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pR = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pR);
#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaRSignCompleted, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaRSignCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, protocolStatus, pR);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA R Sign parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaRSignParamCheck(const CpaCyDsaGenCbFunc pCb,
                                const CpaCyDsaRSignOpData *pOpData,
                                CpaBoolean *pProtocolStatus,
                                CpaFlatBuffer *pR)
{

    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);

    /* check for output pointers */
    LAC_CHECK_NULL_PARAM(pProtocolStatus);
    LAC_CHECK_NULL_PARAM(pR);

    /* check parameters for null, zero len and LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->K, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->P, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->P);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Q, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->Q);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->G, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pR, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA R Sign synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaRSignSyn(const CpaInstanceHandle instanceHandle,
                                const CpaCyDsaRSignOpData *pOpData,
                                CpaBoolean *pProtocolStatus,
                                CpaFlatBuffer *pR)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaSignR(instanceHandle,
                               LacSync_GenFlatBufVerifyCb,
                               pSyncCallbackData,
                               pOpData,
                               pProtocolStatus,
                               pR);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaRSignRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pProtocolStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_DSA_STAT_INC(numDsaRSignCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA R Sign API function
 ***************************************************************************/
CpaStatus cpaCyDsaSignR(const CpaInstanceHandle instanceHandle_in,
                        const CpaCyDsaGenCbFunc pCb,
                        void *pCallbackTag,
                        const CpaCyDsaRSignOpData *pOpData,
                        CpaBoolean *pProtocolStatus,
                        CpaFlatBuffer *pR)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOut[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U bitLenL = 0, nonceN = 0;
    Cpa32U opSizeNInBytes = 0;
    lac_dsa_ln_pairs_t opIndex = LAC_DSA_INVALID_PAIR;

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status = LacDsaRSignSyn(instanceHandle, pOpData, pProtocolStatus, pR);
        if (NULL != pProtocolStatus)
        {
            LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx[%d], 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     *pProtocolStatus,
                     (LAC_ARCH_UINT)pR);
        }
        else
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     (LAC_ARCH_UINT)pR);
        }
        return status;
#else
        return LacDsaRSignSyn(instanceHandle, pOpData, pProtocolStatus, pR);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaRSignParamCheck(pCb, pOpData, pProtocolStatus, pR);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->P), &bitLenL);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->Q), &nonceN);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetLNPair(bitLenL, nonceN);

        /* N values of 160 or 224 do not result in an even number of QW
           so we need to round up */
        opSizeNInBytes = LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(nonceN),
                                                LAC_QUAD_WORD_IN_BYTES);
#ifdef ICP_PARAM_CHECK
        if (LAC_DSA_INVALID_PAIR == opIndex)
        {
            LAC_INVALID_PARAM_LOG("P, Q out of range "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < k < q */
        if ((LacPke_CompareZero(&(pOpData->K), 0) == 0) ||
            (LacPke_Compare(&(pOpData->K), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("K out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 1 < g < p */
        if ((LacPke_CompareZero(&(pOpData->G), -1) <= 0) ||
            (LacPke_Compare(&(pOpData->G), 0, &(pOpData->P), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("G out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }

        /* Ensure output buffer is the required size (note does not need to be
           rounded up to nearest QW) */
        if (pR->dataLenInBytes < LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Output Buffer has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* If output buffer is larger than N we need to zero MS bytes */
        osalMemSet(
            pR->pData, 0, (pR->dataLenInBytes - LAC_BITS_TO_BYTES(nonceN)));

        functionalityId = LacPke_GetMmpId(
            opIndex, lacDsaSignRSizeIdMap, LAC_ARRAY_LEN(lacDsaSignRSizeIdMap));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_1024_160.k,
                                      &pOpData->K);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, k)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, k)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_1024_160.p,
                                      &pOpData->P);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, p)] =
            LAC_BITS_TO_BYTES(bitLenL);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_1024_160.q,
                                      &pOpData->Q);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, q)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_1024_160.g,
                                      &pOpData->G);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, p)] =
            LAC_BITS_TO_BYTES(bitLenL);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_input_t, g)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_sign_r_1024_160.r, pR);
        outArgSizeList[0] = opSizeNInBytes;
        internalMemOut[0] = CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pR;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          internalMemOut,
                                          LacDsaRSignCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaRSignRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaRSignRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA S Sign internal callback
 ***************************************************************************/
STATIC
void LacDsaSSignCallback(CpaStatus status,
                         CpaBoolean protocolStatus,
                         CpaInstanceHandle instanceHandle,
                         lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaGenCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaSSignOpData *pOpData = NULL;
    CpaFlatBuffer *pS = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaGenCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData = (CpaCyDsaSSignOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pS = pCbData->pOutputData1;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pS);

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaSSignCompleted, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaSSignCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, protocolStatus, pS);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA S Sign parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaSSignParamCheck(const CpaCyDsaGenCbFunc pCb,
                                const CpaCyDsaSSignOpData *pOpData,
                                CpaBoolean *pProtocolStatus,
                                CpaFlatBuffer *pS)
{
    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);

    /* check for valid out buffer and data pointers */
    LAC_CHECK_NULL_PARAM(pS);
    LAC_CHECK_NULL_PARAM(pProtocolStatus);

    /* check parameters for null, 0 size, and LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Z, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->K, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Q, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->Q);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->R, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->X, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pS, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA S Sign synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaSignSSyn(const CpaInstanceHandle instanceHandle,
                                const CpaCyDsaSSignOpData *pOpData,
                                CpaBoolean *pProtocolStatus,
                                CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaSignS(instanceHandle,
                               LacSync_GenFlatBufVerifyCb,
                               pSyncCallbackData,
                               pOpData,
                               pProtocolStatus,
                               pS);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaSSignRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pProtocolStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_DSA_STAT_INC(numDsaSSignCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA S Sign API function
 ***************************************************************************/
CpaStatus cpaCyDsaSignS(const CpaInstanceHandle instanceHandle_in,
                        const CpaCyDsaGenCbFunc pCb,
                        void *pCallbackTag,
                        const CpaCyDsaSSignOpData *pOpData,
                        CpaBoolean *pProtocolStatus,
                        CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOut[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U nonceN = 0, opSizeInByte = 0;
#ifdef ICP_PARAM_CHECK
    Cpa32U byteLen = 0;
#endif
    lac_dsa_n_values_t opIndex = LAC_DSA_N_INVALID;

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status = LacDsaSignSSyn(instanceHandle, pOpData, pProtocolStatus, pS);
        if (NULL != pProtocolStatus)
        {
            LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx[%d], 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     *pProtocolStatus,
                     (LAC_ARCH_UINT)pS);
        }
        else
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pProtocolStatus,
                     (LAC_ARCH_UINT)pS);
        }
        return status;
#endif
        return LacDsaSignSSyn(instanceHandle, pOpData, pProtocolStatus, pS);
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaSSignParamCheck(pCb, pOpData, pProtocolStatus, pS);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->Q), &nonceN);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetN(nonceN);
        opSizeInByte = LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(nonceN),
                                              LAC_QUAD_WORD_IN_BYTES);
#ifdef ICP_PARAM_CHECK
        if (LAC_DSA_N_INVALID == opIndex)
        {
            LAC_INVALID_PARAM_LOG("Q not support size N "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check byte len of z */
        byteLen = LacPke_GetMinBytes(&(pOpData->Z));
        if (byteLen > LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Z out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < k < q */
        if ((LacPke_CompareZero(&(pOpData->K), 0) == 0) ||
            (LacPke_Compare(&(pOpData->K), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("K out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < r < q */
        if ((LacPke_CompareZero(&(pOpData->R), 0) == 0) ||
            (LacPke_Compare(&(pOpData->R), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("R out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < x < q */
        if ((LacPke_CompareZero(&(pOpData->X), 0) == 0) ||
            (LacPke_Compare(&(pOpData->X), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("X out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure output buffer is the required size */
        if (pS->dataLenInBytes < LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Output Buffer has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* If output buffer is larger than N we need to zero MS bytes */
        osalMemSet(
            pS->pData, 0, (pS->dataLenInBytes - LAC_BITS_TO_BYTES(nonceN)));

        functionalityId = LacPke_GetMmpId(
            opIndex, lacDsaSignSSizeIdMap, LAC_ARRAY_LEN(lacDsaSignSSizeIdMap));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_s_160.m, &pOpData->Z);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, m)] =
            opSizeInByte;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, m)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_s_160.k, &pOpData->K);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, k)] =
            opSizeInByte;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, k)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_s_160.q, &pOpData->Q);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, q)] =
            opSizeInByte;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_s_160.r, &pOpData->R);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, r)] =
            opSizeInByte;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, r)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_s_160.x, &pOpData->X);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, x)] =
            opSizeInByte;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_input_t, x)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_sign_s_160.s, pS);
        outArgSizeList[0] = opSizeInByte;
        internalMemOut[0] = CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pS;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          internalMemOut,
                                          LacDsaSSignCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaSSignRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaSSignRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA RS Sign internal callback
 ***************************************************************************/
STATIC
void LacDsaRSSignCallback(CpaStatus status,
                          CpaBoolean protocolStatus,
                          CpaInstanceHandle instanceHandle,
                          lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaRSSignCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaRSSignOpData *pOpData = NULL;
    CpaFlatBuffer *pR = NULL;
    CpaFlatBuffer *pS = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaRSSignCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData =
        (CpaCyDsaRSSignOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);
    pR = pCbData->pOutputData1;
    pS = pCbData->pOutputData2;

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);
    LAC_ASSERT_NOT_NULL(pR);
    LAC_ASSERT_NOT_NULL(pS);

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaRSSignCompleted, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaRSSignCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, protocolStatus, pR, pS);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA RS Sign parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaRSSignParamCheck(const CpaCyDsaRSSignCbFunc pCb,
                                 const CpaCyDsaRSSignOpData *pOpData,
                                 CpaBoolean *pProtocolStatus,
                                 CpaFlatBuffer *pR,
                                 CpaFlatBuffer *pS)
{

    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);

    /* check for valid out buffer pointers */
    LAC_CHECK_NULL_PARAM(pProtocolStatus);
    LAC_CHECK_NULL_PARAM(pR);
    LAC_CHECK_NULL_PARAM(pS);

    /* check parameters for null, zero size and LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Z, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->K, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->P, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->P);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Q, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->Q);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->G, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->X, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pR, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(pS, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA RS Sign synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaRSSignSyn(const CpaInstanceHandle instanceHandle,
                                 const CpaCyDsaRSSignOpData *pOpData,
                                 CpaBoolean *pProtocolStatus,
                                 CpaFlatBuffer *pR,
                                 CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);
    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaSignRS(instanceHandle,
                                LacSync_GenDualFlatBufVerifyCb,
                                pSyncCallbackData,
                                pOpData,
                                pProtocolStatus,
                                pR,
                                pS);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaRSSignRequestErrors, pCryptoService);
#endif
        return status;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus wCbStatus = CPA_STATUS_FAIL;
        wCbStatus = LacSync_WaitForCallback(pSyncCallbackData,
                                            LAC_PKE_SYNC_CALLBACK_TIMEOUT,
                                            &status,
                                            pProtocolStatus);
        if (CPA_STATUS_SUCCESS != wCbStatus)
        {
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_DSA_STAT_INC(numDsaRSSignCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA RS Sign API function
 ***************************************************************************/
CpaStatus cpaCyDsaSignRS(const CpaInstanceHandle instanceHandle_in,
                         const CpaCyDsaRSSignCbFunc pCb,
                         void *pCallbackTag,
                         const CpaCyDsaRSSignOpData *pOpData,
                         CpaBoolean *pProtocolStatus,
                         CpaFlatBuffer *pR,
                         CpaFlatBuffer *pS)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    Cpa32U outArgSizeList[LAC_MAX_MMP_OUTPUT_PARAMS] = {0};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    CpaBoolean internalMemOut[LAC_MAX_MMP_OUTPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U bitLenL = 0, nonceN = 0;
    Cpa32U opSizeNInBytes = 0;
#ifdef ICP_PARAM_CHECK
    Cpa32U byteLen = 0;
#endif
    lac_dsa_ln_pairs_t opIndex = LAC_DSA_INVALID_PAIR;

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status =
            LacDsaRSSignSyn(instanceHandle, pOpData, pProtocolStatus, pR, pS);
        if (NULL != pProtocolStatus)
        {
            LAC_LOG7("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx[%d]"
                     ", 0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     *pProtocolStatus,
                     (LAC_ARCH_UINT)pR,
                     (LAC_ARCH_UINT)pS);
        }
        else
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx"
                     ", 0x%lx, 0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pR,
                     (LAC_ARCH_UINT)pS);
        }
        return status;
#else
        return LacDsaRSSignSyn(
            instanceHandle, pOpData, pProtocolStatus, pR, pS);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaRSSignParamCheck(pCb, pOpData, pProtocolStatus, pR, pS);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->P), &bitLenL);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->Q), &nonceN);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetLNPair(bitLenL, nonceN);
        opSizeNInBytes = LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(nonceN),
                                                LAC_QUAD_WORD_IN_BYTES);
#ifdef ICP_PARAM_CHECK
        if (LAC_DSA_INVALID_PAIR == opIndex)
        {
            LAC_INVALID_PARAM_LOG("P, Q out of range "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check byte len of z */
        byteLen = LacPke_GetMinBytes(&(pOpData->Z));
        if (byteLen > LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Z out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < k < q */
        if ((LacPke_CompareZero(&(pOpData->K), 0) == 0) ||
            (LacPke_Compare(&(pOpData->K), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("K out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {

        /* Check 1 < g < p */
        if ((LacPke_CompareZero(&(pOpData->G), -1) <= 0) ||
            (LacPke_Compare(&(pOpData->G), 0, &(pOpData->P), 0) >= 0))

        {
            LAC_INVALID_PARAM_LOG("G out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < x < q */
        if ((LacPke_CompareZero(&(pOpData->X), 0) == 0) ||
            (LacPke_Compare(&(pOpData->X), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("X out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Ensure output buffers are the required size */
        if (pR->dataLenInBytes < LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Output Buffer R has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }

        if (pS->dataLenInBytes < LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Output Buffer S has incorrect length");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* If output buffers are larger than N we need to zero MS bytes */
        osalMemSet(
            pR->pData, 0, (pR->dataLenInBytes - LAC_BITS_TO_BYTES(nonceN)));
        osalMemSet(
            pS->pData, 0, (pS->dataLenInBytes - LAC_BITS_TO_BYTES(nonceN)));

        functionalityId = LacPke_GetMmpId(opIndex,
                                          lacDsaSignRsSizeIdMap,
                                          LAC_ARRAY_LEN(lacDsaSignRsSizeIdMap));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_s_1024_160.m,
                                      &pOpData->Z);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, m)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, m)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_s_1024_160.k,
                                      &pOpData->K);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, k)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, k)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_s_1024_160.p,
                                      &pOpData->P);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, p)] =
            LAC_BITS_TO_BYTES(bitLenL);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_s_1024_160.q,
                                      &pOpData->Q);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, q)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_s_1024_160.g,
                                      &pOpData->G);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, g)] =
            LAC_BITS_TO_BYTES(bitLenL);
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, g)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_sign_r_s_1024_160.x,
                                      &pOpData->X);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, x)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_input_t, x)] =
            CPA_FALSE;

        /* populate output parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_sign_r_s_1024_160.r, pR);
        outArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_output_t, r)] =
            opSizeNInBytes;
        internalMemOut[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_output_t, r)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(out.mmp_dsa_sign_r_s_1024_160.s, pS);
        outArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_output_t, s)] =
            opSizeNInBytes;
        internalMemOut[LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_output_t, s)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        cbData.pOutputData1 = pR;
        cbData.pOutputData2 = pS;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          outArgSizeList,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          internalMemOut,
                                          LacDsaRSSignCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaRSSignRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaRSSignRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Verify internal callback
 ***************************************************************************/
STATIC
void LacDsaVerifyCallback(CpaStatus status,
                          CpaBoolean pass,
                          CpaInstanceHandle instanceHandle,
                          lac_pke_op_cb_data_t *pCbData)
{
    CpaCyDsaVerifyCbFunc pCb = NULL;
    void *pCallbackTag = NULL;
    CpaCyDsaVerifyOpData *pOpData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    /* extract info from callback data structure */
    LAC_ASSERT_NOT_NULL(pCbData);
    pCb = (CpaCyDsaVerifyCbFunc)LAC_CONST_PTR_CAST(pCbData->pClientCb);
    pCallbackTag = pCbData->pCallbackTag;
    pOpData =
        (CpaCyDsaVerifyOpData *)LAC_CONST_PTR_CAST(pCbData->pClientOpData);

    LAC_ASSERT_NOT_NULL(pCb);
    LAC_ASSERT_NOT_NULL(pOpData);

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaVerifyCompleted, pCryptoService);
        if (CPA_FALSE == pass)
        {
            LAC_DSA_STAT_INC(numDsaVerifyFailures, pCryptoService);
        }
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaVerifyCompletedErrors, pCryptoService);
    }
#endif
    /* invoke the user callback */
    pCb(pCallbackTag, status, pOpData, pass);
}

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Verify parameter check
 ***************************************************************************/
STATIC
CpaStatus LacDsaVerifyParamCheck(const CpaCyDsaVerifyCbFunc pCb,
                                 const CpaCyDsaVerifyOpData *pOpData,
                                 CpaBoolean *pVerifyStatus)
{
    /* check for valid callback function pointer */
    LAC_CHECK_NULL_PARAM(pCb);

    /* check for valid output pointer */
    LAC_CHECK_NULL_PARAM(pVerifyStatus);

    /* check parameters for null, zero len and LSB not set */
    LAC_CHECK_NULL_PARAM(pOpData);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->R, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->S, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Z, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->P, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->P);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Q, CHECK_NONE, 0);
    LAC_CHECK_ODD_PARAM(&pOpData->Q);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->G, CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&pOpData->Y, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Verify synchronous function
 ***************************************************************************/
STATIC CpaStatus LacDsaVerifySyn(const CpaInstanceHandle instanceHandle,
                                 const CpaCyDsaVerifyOpData *pOpData,
                                 CpaBoolean *pVerifyStatus)
{

    CpaStatus status = CPA_STATUS_FAIL;
    lac_sync_op_data_t *pSyncCallbackData = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    status = LacSync_CreateSyncCookie(&pSyncCallbackData);

    /*
     * Call the async version of the function
     * with the sync callback function as a parameter.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCyDsaVerify(instanceHandle,
                                LacSync_GenVerifyCb,
                                pSyncCallbackData,
                                pOpData,
                                pVerifyStatus);
    }
    else
    {
#ifndef DISABLE_STATS
        LAC_DSA_STAT_INC(numDsaVerifyRequests, pCryptoService);
#endif
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
#ifndef DISABLE_STATS
            /*
             * Inc stats only if the wait for callback failed.
             */
            LAC_DSA_STAT_INC(numDsaVerifyCompletedErrors, pCryptoService);
#endif
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
 * @ingroup Lac_Dsa
 *      DSA Verify API function
 ***************************************************************************/
CpaStatus cpaCyDsaVerify(const CpaInstanceHandle instanceHandle_in,
                         const CpaCyDsaVerifyCbFunc pCb,
                         void *pCallbackTag,
                         const CpaCyDsaVerifyOpData *pOpData,
                         CpaBoolean *pVerifyStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_qat_fw_mmp_input_param_t in = {.flat_array = {0}};
    icp_qat_fw_mmp_output_param_t out = {.flat_array = {0}};
    Cpa32U inArgSizeList[LAC_MAX_MMP_INPUT_PARAMS] = {0};
    CpaBoolean internalMemIn[LAC_MAX_MMP_INPUT_PARAMS] = {CPA_FALSE};
    lac_pke_op_cb_data_t cbData = {0};
    CpaInstanceHandle instanceHandle = NULL;
#ifndef DISABLE_STATS
    sal_crypto_service_t *pCryptoService = NULL;
#endif
    Cpa32U functionalityId = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U bitLenL = 0, nonceN = 0;
    Cpa32U opSizeLInBytes = 0, opSizeNInBytes = 0;
#ifdef ICP_PARAM_CHECK
    Cpa32U byteLen = 0;
#endif
    lac_dsa_ln_pairs_t opIndex = LAC_DSA_INVALID_PAIR;

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
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
    /* check for valid acceleration handle - can't update stats otherwise */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle);
#endif
    /* check LAC is initialised*/
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));
#endif

    /* Check if the API has been called in sync mode */
    if (NULL == pCb)
    {
#ifdef ICP_TRACE
        status = LacDsaVerifySyn(instanceHandle, pOpData, pVerifyStatus);
        if (NULL != pVerifyStatus)
        {
            LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx[%d])\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pVerifyStatus,
                     *pVerifyStatus);
        }
        else
        {
            LAC_LOG5("Called with params (0x%lx, 0x%lx, 0x%lx, 0x%lx, "
                     "0x%lx)\n",
                     (LAC_ARCH_UINT)instanceHandle_in,
                     (LAC_ARCH_UINT)pCb,
                     (LAC_ARCH_UINT)pCallbackTag,
                     (LAC_ARCH_UINT)pOpData,
                     (LAC_ARCH_UINT)pVerifyStatus);
        }
        return status;
#else
        return LacDsaVerifySyn(instanceHandle, pOpData, pVerifyStatus);
#endif
    }

#ifdef ICP_PARAM_CHECK
    /* check remaining parameters */
    status = LacDsaVerifyParamCheck(pCb, pOpData, pVerifyStatus);
#endif

#ifndef DISABLE_STATS
    pCryptoService = (sal_crypto_service_t *)instanceHandle;
#endif
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->P), &bitLenL);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = LacPke_GetBitLen(&(pOpData->Q), &nonceN);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        opIndex = LacDsa_GetLNPair(bitLenL, nonceN);
        opSizeLInBytes = LAC_BITS_TO_BYTES(bitLenL);
        opSizeNInBytes = LAC_ALIGN_POW2_ROUNDUP(LAC_BITS_TO_BYTES(nonceN),
                                                LAC_QUAD_WORD_IN_BYTES);
#ifdef ICP_PARAM_CHECK
        if (LAC_DSA_INVALID_PAIR == opIndex)
        {
            LAC_INVALID_PARAM_LOG("P, Q out of range "
                                  "Supported {L,N} = {1024, 160}, {2048, 224} "
                                  "{2048, 256}, {3072, 256}");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 1 < g < p */
        if ((LacPke_CompareZero(&(pOpData->G), -1) <= 0) ||
            (LacPke_Compare(&(pOpData->G), 0, &(pOpData->P), 0) >= 0))

        {
            LAC_INVALID_PARAM_LOG("G out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check y < p */
        if (LacPke_Compare(&(pOpData->Y), 0, &(pOpData->P), 0) >= 0)
        {
            LAC_INVALID_PARAM_LOG("Y out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check byte len of z */
        byteLen = LacPke_GetMinBytes(&(pOpData->Z));
        if (byteLen > LAC_BITS_TO_BYTES(nonceN))
        {
            LAC_INVALID_PARAM_LOG("Z out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < r < q */
        if ((LacPke_CompareZero(&(pOpData->R), 0) == 0) ||
            (LacPke_Compare(&(pOpData->R), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("R out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check 0 < s < q */
        if ((LacPke_CompareZero(&(pOpData->S), 0) == 0) ||
            (LacPke_Compare(&(pOpData->S), 0, &(pOpData->Q), 0) >= 0))
        {
            LAC_INVALID_PARAM_LOG("S out of Range");
            status = CPA_STATUS_INVALID_PARAM;
        }
#endif
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        functionalityId = LacPke_GetMmpId(opIndex,
                                          lacDsaVerifySizeIdMap,
                                          LAC_ARRAY_LEN(lacDsaVerifySizeIdMap));

        /* populate input parameters */
        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.r,
                                      &pOpData->R);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, r)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, r)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.s,
                                      &pOpData->S);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, s)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, s)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.m,
                                      &pOpData->Z);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, m)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, m)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.p,
                                      &pOpData->P);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, p)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, p)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.q,
                                      &pOpData->Q);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, q)] =
            opSizeNInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, q)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.g,
                                      &pOpData->G);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, g)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, g)] =
            CPA_FALSE;

        LAC_MEM_SHARED_WRITE_FROM_PTR(in.mmp_dsa_verify_1024_160.y,
                                      &pOpData->Y);
        inArgSizeList[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, y)] =
            opSizeLInBytes;
        internalMemIn[LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_input_t, y)] =
            CPA_FALSE;

        /* populate callback data */
        cbData.pClientCb = pCb;
        cbData.pCallbackTag = pCallbackTag;
        cbData.pClientOpData = pOpData;
        cbData.pOpaqueData = NULL;
        /* send a PKE request to the QAT */
        status = LacPke_SendSingleRequest(functionalityId,
                                          inArgSizeList,
                                          NULL,
                                          &in,
                                          &out,
                                          internalMemIn,
                                          NULL,
                                          LacDsaVerifyCallback,
                                          &cbData,
                                          instanceHandle);
    }

#ifndef DISABLE_STATS
    /* increment stats */
    if (CPA_STATUS_SUCCESS == status)
    {
        LAC_DSA_STAT_INC(numDsaVerifyRequests, pCryptoService);
    }
    else
    {
        LAC_DSA_STAT_INC(numDsaVerifyRequestErrors, pCryptoService);
    }
#endif
    return status;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Statistics Query API function
 ***************************************************************************/
CpaStatus cpaCyDsaQueryStats(CpaInstanceHandle instanceHandle,
                             CpaCyDsaStats *pDsaStats)
{
    sal_crypto_service_t *pCryptoService = NULL;
#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
#endif
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pDsaStats);
#endif
    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }

    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);

    /* ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);

    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pDsaStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* get stats into user supplied stats structure */
    LAC_DSA_STATS32_GET(*pDsaStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA 64bit Statistics Query API function
 ***************************************************************************/
CpaStatus cpaCyDsaQueryStats64(CpaInstanceHandle instanceHandle,
                               CpaCyDsaStats64 *pDsaStats)
{
    sal_crypto_service_t *pCryptoService = NULL;
#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pDsaStats);
#endif

#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        instanceHandle = Lac_GetFirstHandle(SAL_SERVICE_TYPE_CRYPTO_ASYM);
    }

    /* check for valid acceleration handle */
    LAC_CHECK_INSTANCE_HANDLE(instanceHandle);

    /* ensure LAC is running - return error if not */
    SAL_RUNNING_CHECK(instanceHandle);

    /* check this is a crypto or asym instance */
    SAL_CHECK_INSTANCE_TYPE(
        instanceHandle,
        (SAL_SERVICE_TYPE_CRYPTO | SAL_SERVICE_TYPE_CRYPTO_ASYM));

    /* check for null parameters */
    LAC_CHECK_NULL_PARAM(pDsaStats);

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    /* get stats into user supplied stats structure */
    LAC_DSA_STATS64_GET(*pDsaStats, pCryptoService);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Initialization function
 ***************************************************************************/
CpaStatus LacDsa_Init(CpaInstanceHandle instanceHandle)
{
#ifndef QAT_LEGACY_ALGORITHMS
    return CPA_STATUS_UNSUPPORTED;
#else
    sal_crypto_service_t *pCryptoService = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    pCryptoService = (sal_crypto_service_t *)instanceHandle;

    status = LAC_OS_MALLOC(&(pCryptoService->pLacDsaStatsArr),
                           LAC_DSA_NUM_STATS * sizeof(OsalAtomic));

    if (CPA_STATUS_SUCCESS == status)
    {
        /* initialize stats to zero */
        LAC_DSA_STATS_INIT(pCryptoService);
    }

    /* Call compile time param check function to ensure it is included
       in the build by the compiler */
    LacDsa_CompileTimeAssertions();

    return status;
#endif
}

/**
 * @ingroup Lac_Dsa
 */
void LacDsa_StatsFree(CpaInstanceHandle instanceHandle)
{
#ifdef QAT_LEGACY_ALGORITHMS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    if (NULL != pCryptoService->pLacDsaStatsArr)
    {
        LAC_OS_FREE(pCryptoService->pLacDsaStatsArr);
    }
#endif
}

/**
 * @ingroup Lac_Dsa
 */
void LacDsa_StatsReset(CpaInstanceHandle instanceHandle)
{
#ifdef QAT_LEGACY_ALGORITHMS
    sal_crypto_service_t *pCryptoService =
        (sal_crypto_service_t *)instanceHandle;

    LAC_DSA_STATS_INIT(pCryptoService);
#endif
}

/**
 ***************************************************************************
 * @ingroup Lac_Dsa
 *      DSA Stats Show function
 ***************************************************************************/
void LacDsa_StatsShow(CpaInstanceHandle instanceHandle)
{
#ifdef QAT_LEGACY_ALGORITHMS
    CpaCyDsaStats64 dsaStats = {0};


    /* retrieve the stats */
    (void)cpaCyDsaQueryStats64(instanceHandle, &dsaStats);

    /* log the stats to the standard output */

    /* engine info */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            SEPARATOR BORDER
            "  DSA Stats                                 " BORDER
            "\n" SEPARATOR);

    /* p parameter generation requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA P Param Gen Requests-Succ:  %16llu " BORDER "\n" BORDER
                   " DSA P Param Gen Requests-Err:   %16llu " BORDER "\n" BORDER
                   " DSA P Param Gen Completed-Succ: %16llu " BORDER "\n" BORDER
                   " DSA P Param Gen Completed-Err:  %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaPParamGenRequests,
            dsaStats.numDsaPParamGenRequestErrors,
            dsaStats.numDsaPParamGenCompleted,
            dsaStats.numDsaPParamGenCompletedErrors);

    /* g parameter generation requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA G Param Gen Requests-Succ:  %16llu " BORDER "\n" BORDER
                   " DSA G Param Gen Requests-Err:   %16llu " BORDER "\n" BORDER
                   " DSA G Param Gen Completed-Succ: %16llu " BORDER "\n" BORDER
                   " DSA G Param Gen Completed-Err:  %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaGParamGenRequests,
            dsaStats.numDsaGParamGenRequestErrors,
            dsaStats.numDsaGParamGenCompleted,
            dsaStats.numDsaGParamGenCompletedErrors);

    /* y parameter generation requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA Y Param Gen Requests-Succ:  %16llu " BORDER "\n" BORDER
                   " DSA Y Param Gen Requests-Err:   %16llu " BORDER "\n" BORDER
                   " DSA Y Param Gen Completed-Succ: %16llu " BORDER "\n" BORDER
                   " DSA Y Param Gen Completed-Err:  %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaYParamGenRequests,
            dsaStats.numDsaYParamGenRequestErrors,
            dsaStats.numDsaYParamGenCompleted,
            dsaStats.numDsaYParamGenCompletedErrors);

    /* r sign requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA R Sign Requests-Succ:       %16llu " BORDER "\n" BORDER
                   " DSA R Sign Request-Err:         %16llu " BORDER "\n" BORDER
                   " DSA R Sign Completed-Succ:      %16llu " BORDER "\n" BORDER
                   " DSA R Sign Completed-Err:       %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaRSignRequests,
            dsaStats.numDsaRSignRequestErrors,
            dsaStats.numDsaRSignCompleted,
            dsaStats.numDsaRSignCompletedErrors);

    /* s sign requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA S Sign Requests-Succ:       %16llu " BORDER "\n" BORDER
                   " DSA S Sign Request-Err:         %16llu " BORDER "\n" BORDER
                   " DSA S Sign Completed-Succ:      %16llu " BORDER "\n" BORDER
                   " DSA S Sign Completed-Err:       %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaSSignRequests,
            dsaStats.numDsaSSignRequestErrors,
            dsaStats.numDsaSSignCompleted,
            dsaStats.numDsaSSignCompletedErrors);

    /* rs sign requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA RS Sign Requests-Succ:      %16llu " BORDER "\n" BORDER
                   " DSA RS Sign Request-Err:        %16llu " BORDER "\n" BORDER
                   " DSA RS Sign Completed-Succ:     %16llu " BORDER "\n" BORDER
                   " DSA RS Sign Completed-Err:      %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaRSSignRequests,
            dsaStats.numDsaRSSignRequestErrors,
            dsaStats.numDsaRSSignCompleted,
            dsaStats.numDsaRSSignCompletedErrors);

    /* verify requests */
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            BORDER " DSA Verify Requests-Succ:       %16llu " BORDER "\n" BORDER
                   " DSA Verify Request-Err:         %16llu " BORDER "\n" BORDER
                   " DSA Verify Completed-Succ:      %16llu " BORDER "\n" BORDER
                   " DSA Verify Completed-Err:       %16llu " BORDER "\n" BORDER
                   " DSA Verify Completed-Failure:   %16llu " BORDER
                   "\n" SEPARATOR,
            dsaStats.numDsaVerifyRequests,
            dsaStats.numDsaVerifyRequestErrors,
            dsaStats.numDsaVerifyCompleted,
            dsaStats.numDsaVerifyCompletedErrors,
            dsaStats.numDsaVerifyFailures);
#else
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "  DSA not suppported \n");
#endif
}
