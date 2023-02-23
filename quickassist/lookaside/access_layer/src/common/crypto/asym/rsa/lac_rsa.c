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
 *****************************************************************************
 * @file lac_rsa.c
 *
 * @defgroup LacRsa RSA
 *
 * @ingroup LacAsym
 *
 * This file implements functions for RSA.
 *
 * @lld_start
 *
 * @lld_overview
 * This is the RSA feature implementation.  It implements 3 RSA API
 * services: keygen, encrypt and decrypt.  Statistics are maintained for each
 * service.
 * For each service the parameters supplied by the client are checked, and then
 * input/output argument lists are constructed before calling the PKE QAT
 * Comms layer to create and send a request to the QAT.
 *
 * For encrypt operations there is only one type of public key so only one
 * QAT message can be constructed. however for keygen and decrypt there are two
 * types of private key to be dealt with. This means that one of two messages
 * can be sent to the QAT. In these cases all common processing shall be done
 * first. Then we branch depending on the key type and perform key specific
 * processing.
 *
 * In all cases the service implementations are a straightforward
 * marshalling of client-supplied parameters for the QAT. i.e. there is
 * minimal logic handled by this component. Resize buffers are handled by
 * the PKE QAT Comms layer.
 *
 * The user's input buffers are checked for null params, correct length, msb
 * and lsb set where necessary. The following parameter checks based on the
 * standard are also performed for RSA
 *
 * RSA Keygen:
 *             Test: p and q must have the msb /lsb  set.
 *             Test: Will check that e > = 3 before sending to the QAT.
 *                      e is odd
 *             Test: Once the QAT has returned can check that e < n
 *             Test: Once the QAT has returned can check that the top bit of
 *                      n is set
 *
 * Encrypt:
 *             Test: The message parameter must satisfy 0 < m < =  n-1
 *             Test: The Modulus n must have the msb/lsb  set.
 *
 * Decrypt:
 *             Form 1:
 *                         Test: The ciphertext must satisfy 0 < c < =  n-1.
 *                         Test: Modulus n has msb /lsb  set.
 *             Form 2:
 *                         Test: p and q must have the msb /lsb  set.
 *                         Test: For prime tests will just check that p and q
 *                                  are odd.
 *                         Test: 1 < Dp < p-1
 *                         Test: 1 < Dq < q-1
 *                         Test: 1 < =  qInv < p   (this could be 1)
 *
 * @lld_dependencies
 * - @ref LacAsymCommonQatComms "PKE QAT Comms" : For creating and sending
 * messages to the QAT
 * - @ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - @ref LacAsymCommon "PKE Common" : For MMP generic structures and param
 * checking macros
 * - OSAL : For atomics and logging
 *
 * @lld_initialisation
 * On initialization this component clears the stats.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

/* Include API files */
#include "cpa.h"
#include "cpa_cy_rsa.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/* Include Osal files */
#include "Osal.h"

/* Include LAC files */
#include "lac_mem.h"
#include "lac_common.h"
#include "lac_pke_utils.h"
#include "lac_pke_qat_comms.h"
#include "lac_rsa_p.h"

/*
********************************************************************************
* Static Variables
********************************************************************************
*/

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

CpaBoolean LacRsa_IsValidRsaSize(Cpa32U opSizeInBytes)
{
    Cpa32U opSizeInBits = LAC_NUM_BITS_IN_BYTE * opSizeInBytes;

#ifdef QAT_LEGACY_ALGORITHMS
    if ((LAC_512_BITS != opSizeInBits) && (LAC_1024_BITS != opSizeInBits) &&
        (LAC_1536_BITS != opSizeInBits) && (LAC_2048_BITS != opSizeInBits) &&
        (LAC_3072_BITS != opSizeInBits) && (LAC_4096_BITS != opSizeInBits) &&
        (LAC_8192_BITS != opSizeInBits))
#else
    if ((LAC_2048_BITS != opSizeInBits) && (LAC_3072_BITS != opSizeInBits) && 
        (LAC_4096_BITS != opSizeInBits) && (LAC_8192_BITS != opSizeInBits))
#endif
    {
#ifdef QAT_LEGACY_ALGORITHMS
        LAC_INVALID_PARAM_LOG(
            "Invalid operation size. Valid op sizes for "
            "RSA are 512, 1024, 1536, 2048, 3072, 4096 and 8192 bits.");
#else
        LAC_INVALID_PARAM_LOG(
            "Invalid operation size. Valid op sizes for "
            "RSA are 2048, 3072, 4096 and 8192 bits.");
#endif
        return CPA_FALSE;
    }

    return CPA_TRUE;
}

CpaStatus LacRsa_Type2StdsCheck(CpaCyRsaPrivateKeyRep2 *pPrivateKeyRep2)
{
    /*
     * @note ideally we we check for type two keys that c < n. However
     * we cannot guarantee that the a type 2 key struct has the correct
     * values set for the type 1 fields (n is a type 1 field).
     */

    /* Standards based check: 1 < Dp < p-1 */
    if (LacPke_CompareZero(&(pPrivateKeyRep2->exponent1Dp), -1) <= 0)
    {
        LAC_INVALID_PARAM_LOG("exponent1Dp must be > 1");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (LacPke_Compare(&(pPrivateKeyRep2->exponent1Dp),
                       0,
                       &(pPrivateKeyRep2->prime1P),
                       -1) >= 0)
    {
        LAC_INVALID_PARAM_LOG("exponent1Dp must be < prime1P - 1");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Standards based check: 1 < Dq < q-1 */
    if (LacPke_CompareZero(&(pPrivateKeyRep2->exponent2Dq), -1) <= 0)
    {
        LAC_INVALID_PARAM_LOG("exponent2Dq must be > 1");
        return CPA_STATUS_INVALID_PARAM;
    }
    if (LacPke_Compare(&(pPrivateKeyRep2->exponent2Dq),
                       0,
                       &(pPrivateKeyRep2->prime2Q),
                       -1) >= 0)
    {
        LAC_INVALID_PARAM_LOG("exponent2Dq must be < pPrime2Q - 1");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Standards based check: 1 <=  qInv < p */
    LAC_CHECK_NON_ZERO_PARAM(&(pPrivateKeyRep2->coefficientQInv));
    if (LacPke_Compare(&(pPrivateKeyRep2->coefficientQInv),
                       0,
                       &(pPrivateKeyRep2->prime1P),
                       0) >= 0)
    {
        LAC_INVALID_PARAM_LOG("coefficientQInv must be < prime1P");
        return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus LacRsa_CheckPrivateKeyParam(CpaCyRsaPrivateKey *pPrivateKey)
{
    LAC_CHECK_NULL_PARAM(pPrivateKey);

    if (CPA_CY_RSA_VERSION_TWO_PRIME != pPrivateKey->version)
    {
        LAC_INVALID_PARAM_LOG("Invalid pPrivateKey->version");
        return CPA_STATUS_INVALID_PARAM;
    }

    switch (pPrivateKey->privateKeyRepType)
    {
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1:
        {
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep1.modulusN), CHECK_NONE, 0);
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep1.privateExponentD), CHECK_NONE, 0);
        }
        break;

        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2:
        {
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep2.prime1P), CHECK_NONE, 0);
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep2.prime2Q), CHECK_NONE, 0);
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep2.exponent1Dp), CHECK_NONE, 0);
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep2.exponent2Dq), CHECK_NONE, 0);
            LAC_CHECK_FLAT_BUFFER_PARAM(
                &(pPrivateKey->privateKeyRep2.coefficientQInv), CHECK_NONE, 0);
        }
        break;

        default:
        {
            /* Invalid Key Type */
            LAC_INVALID_PARAM_LOG("Invalid pPrivateKey->privateKeyRepType");
            return CPA_STATUS_INVALID_PARAM;
        }
    }

    return CPA_STATUS_SUCCESS;
}

Cpa32U LacRsa_GetPrivateKeyOpSize(const CpaCyRsaPrivateKey *pPrivateKey)
{
    Cpa32U sizeInBytes = 0;
    LAC_ASSERT_NOT_NULL(pPrivateKey);

    switch (pPrivateKey->privateKeyRepType)
    {
        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1:
        {
            sizeInBytes +=
                LacPke_GetMinBytes(&(pPrivateKey->privateKeyRep1.modulusN));
        }
        break;

        case CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2:
        {
            sizeInBytes =
                LacPke_GetMinBytes(&(pPrivateKey->privateKeyRep2.prime1P));
            if (sizeInBytes !=
                LacPke_GetMinBytes(&(pPrivateKey->privateKeyRep2.prime2Q)))
            {
                LAC_LOG_ERROR(
                    "prime1P.dataLenInBytes != prime2Q.dataLenInBytes");
                sizeInBytes = 0;
            }
            else
            {
                sizeInBytes = sizeInBytes << 1;
            }
        }
        break;

        default:
        {
            /* Invalid Key Type */
            LAC_LOG_ERROR("Invalid Private Key Type.");
        }
    }

    return sizeInBytes;
}
