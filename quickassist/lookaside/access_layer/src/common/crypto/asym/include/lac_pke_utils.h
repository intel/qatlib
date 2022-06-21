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
 * @file lac_pke_utils.h
 *
 * @defgroup LacAsymCommonUtils Lac Pke Utils
 *
 * @ingroup LacAsymCommon
 *
 * utils that are PKE specific
 *
 ******************************************************************************/

/******************************************************************************/

#ifndef _LAC_PKE_UTILS_H_
#define _LAC_PKE_UTILS_H_

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include <stdarg.h>
#include "cpa.h"
#include "cpa_cy_common.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/
#include "Osal.h"
#include "lac_mem.h"

/******************************************************************************/

/*
*******************************************************************************
* LAC PKE Operation sizes
*******************************************************************************
*/

#define LAC_128_BITS (128)
#define LAC_160_BITS (160)
#define LAC_192_BITS (192)
#define LAC_224_BITS (224)
#define LAC_256_BITS (256)
#define LAC_384_BITS (384)
#define LAC_512_BITS (512)
#define LAC_576_BITS (576)
#define LAC_768_BITS (768)
#define LAC_1024_BITS (1024)
#define LAC_1536_BITS (1536)
#define LAC_2048_BITS (2048)
#define LAC_2560_BITS (2560)
#define LAC_3072_BITS (3072)
#define LAC_3584_BITS (3584)
#define LAC_4096_BITS (4096)
#define LAC_8192_BITS (8192)

#define LAC_MAX_OP_SIZE_IN_BITS LAC_8192_BITS
/**< @ingroup LacAsymCommon
 * Maximum PKE operation in bits */

#define LAC_MAX_PRIME_SIZE_IN_BITS LAC_4096_BITS
/**< @ingroup LacAsymCommon
 * Maximum prime size in bits */

#define LAC_QAT_ASYM_REQ_SZ_LW 16
/**< @ingroup LacAsymCommon
 * LAC PKE QAT Request message size) */

#define LAC_QAT_ASYM_RESP_SZ_LW 8
/**< @ingroup LacAsymCommon
 * LAC PKE QAT Response message size) */

#ifdef MAX_MR_ROUND
#define LAC_PRIME_MAX_MR MAX_MR_ROUND
#else
#define LAC_PRIME_MAX_MR 50
#endif
/**<
 * MAX number of MR rounds can be decided
   at compile time */

#define LAC_PKE_MAX_CHAIN_LENGTH (LAC_PRIME_MAX_MR + 3)
/**< @ingroup LacAsymCommon
 * LAC PKE Max number of PKE requests that can be chained per QAT message.
 *  In the case of prime we can have LAC_PRIME_MAX_MR MR messages, 1 gcd
 * message, 1 fermat message and 1 lucas message per QAT message (on the ring).
 *  In the case of ECDH we chain 2 request (pt_mul and pt_verify). We should
 *  scale our asym request memory pool for the worst case */

#define LAC_PKE_BUFFERS_PER_OP_MAX 14
/**< @ingroup LacAsymCommon
 * LAC PKE Max number of Alignment buffers required per QAT message
 *  In the case of prime we can have 1 gcd message (1 input), 1 fermat message
 *  (1 input) and 1 lucas message (1 input) per QAT message.
 *  We only resize the prime twice however, once in the GCD case and once for
 * all other cases. MR buffer never needs to be resize. This is ensured by API
 *  definition.
 *
 *  In the case of ECDH we can have 14 inputs and outputs.
 *
 *  For all other cases the number of inputs and outputs sum to
 *  (ICP_QAT_FW_PKE_INPUT_COUNT_MAX+ICP_QAT_FW_PKE_OUTPUT_COUNT_MAX) per
 *  QAT message.
 */

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      This macro calculates the length of the given array
 *
 * @param[in] array         the array whose length we are calculating
 *
 ******************************************************************************/
#define LAC_ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      This macro returns the greater value - x or y
 *
 * @param[in] x parameter to compare
 * @param[in] y parameter to compare against
 * @sideeffect this macro is false if x and/or y are not constant
 *
 ******************************************************************************/
#define LAC_MAX(x, y) (x > y) ? x : y

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      This macro converts all negative 32 bit numbers to -1 and all positive
 *      32 bit numbers to +1
 *
 * @param[in] num               32-bit signed number to convert
 *
 ******************************************************************************/
#define LAC_SIGNED_CONVERT32(num) ((((num) >> 31) << 1) + 1)

/**
 *****************************************************************************
 * @ingroup LacAsymCommonUtils
 *
 * @description
 *      This enum lists the types of param check that can be performed on the #
 * size of a buffer.
 *
 *****************************************************************************/
typedef enum
{
    CHECK_EQUALS = 0,
    CHECK_LESS_EQUALS,
    CHECK_GREATER_EQUALS,
    CHECK_NONE
} lac_pke_size_check_type_t;

/**
*******************************************************************************
* @ingroup LacAsymCommonUtils
*      This macro checks if the flat buffer data is ODD
*
* @param[in] pBuffer           pointer to the flat buffer to check
*
* @return CPA_STATUS_INVALID_PARAM  Not odd
* @return void                      Odd
*
******************************************************************************/
#define LAC_CHECK_ODD_PARAM(pBuffer)                                           \
    do                                                                         \
    {                                                                          \
        if (!((pBuffer)->pData[(pBuffer)->dataLenInBytes - 1] & 0x01))         \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " doesn't have LSB set");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Checks that a flat buffer's size is correct.
 *
 * @description
 *      Checks that a flat buffer's size is correct. The check type specifies
 * the type of check to be performed e.g. less than or equals, equals etc.
 * If any check fails an error is logged and the calling function is
 * returned out of with an error.
 *
 * @param[in] pBuffer           pointer to the flat buffer to check
 * @param[in] checkType         type of check performed on the buffer's length
 * @param[in] lenInBytes        the required length
 *
 * @return CPA_STATUS_INVALID_PARAM  Length check failed
 * @return void                 All checks passed
 ******************************************************************************/
#define LAC_CHECK_SIZE(pBuffer, checkType, lenInBytes)                         \
    do                                                                         \
    {                                                                          \
        if ((pBuffer)->dataLenInBytes == 0)                                    \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " has incorrect length of zero");   \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
                                                                               \
        if ((CHECK_EQUALS == checkType) &&                                     \
            ((pBuffer)->dataLenInBytes != lenInBytes))                         \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " has incorrect length");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        else if ((CHECK_LESS_EQUALS == checkType) &&                           \
                 ((pBuffer)->dataLenInBytes > lenInBytes))                     \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " has incorrect length");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        else if ((CHECK_GREATER_EQUALS == checkType) &&                        \
                 ((pBuffer)->dataLenInBytes < lenInBytes))                     \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " has incorrect length");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
                                                                               \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *     Checks that a flat buffer is valid and the size of the buffer is correct.
 *
 * @description
 *      This macro checks that a flat buffer is not null, that its length is
 * correct.
 * If any check fails an error is logged and the calling function is
 * returned out of with an error.
 *
 * @param[in] pBuffer           pointer to the flat buffer to check
 * @param[in] checkType         type of check performed on the buffer's length
 * @param[in] lenInBytes        the required length
 *
 * @return CPA_STATUS_INVALID_PARAM  Null, Length, LSB and/or MSB checks failed
 * @return void                 All checks passed
 ******************************************************************************/
#define LAC_CHECK_FLAT_BUFFER_PARAM(pBuffer, checkType, lenInBytes)            \
    do                                                                         \
    {                                                                          \
        LAC_CHECK_FLAT_BUFFER(pBuffer);                                        \
        LAC_CHECK_SIZE((pBuffer), checkType, lenInBytes);                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Checks that a number in a flat buffer is valid.
 *
 * @description
 *      This macro checks that a flat buffer is not null, that its length is
 * non-zero, checks the byte length of the number in the buffer relative to
 * lenInBytes and optionally checks that the LSB is set.
 * If any check fails an error is logged and the calling function is
 * returned out of with an error.
 *
 * @param[in] pBuffer           pointer to the flat buffer to check
 * @param[in] checkType         type of check performed on the buffer's length
 * @param[in] lenInBytes        the required byte length
 * @param[in] checkLsb          flag to indicate whether (true) or not (false)
 *                              to check that the LSB is set
 *
 * @return CPA_STATUS_INVALID_PARAM  Null, Length, LSB checks failed
 * @return void                 All checks passed
 ******************************************************************************/
#define LAC_CHECK_FLAT_BUFFER_PARAM_PKE(                                       \
    pBuffer, checkType, lenInBytes, checkLsb)                                  \
    do                                                                         \
    {                                                                          \
        LAC_CHECK_FLAT_BUFFER(pBuffer);                                        \
        if ((pBuffer)->dataLenInBytes == 0)                                    \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " has incorrect length of zero");   \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        if ((CHECK_EQUALS == checkType) &&                                     \
            (lenInBytes != LacPke_GetMinBytes(pBuffer)))                       \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer                                     \
                                  " contains number of incorrect size");       \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        else if ((CHECK_LESS_EQUALS == checkType) &&                           \
                 (LacPke_GetMinBytes(pBuffer) > lenInBytes))                   \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer                                     \
                                  " contains number that is too large");       \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        else if ((CHECK_GREATER_EQUALS == checkType) &&                        \
                 (LacPke_GetMinBytes(pBuffer) < lenInBytes))                   \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer                                     \
                                  " contains number that is too small");       \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        if (checkLsb)                                                          \
        {                                                                      \
            LAC_CHECK_ODD_PARAM(pBuffer);                                      \
        }                                                                      \
    } while (0)

/* define MSB/LSB check flags */
#define LAC_CHECK_MSB_YES 1
#define LAC_CHECK_MSB_NO 0
#define LAC_CHECK_LSB_YES 1
#define LAC_CHECK_LSB_NO 0

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *     Checks msb/lsb of a number in a flatbuffer given the bytelen of
 *     the number.
 *
 * @description
 *     This macro optionally checks that the MSB and/or the LSB of a number
 * in a flat buffer (given the byteLen of the number) is set.
 * If any check fails an error is logged and the calling function is
 * returned out of with an error.
 *
 * @param[in] pBuffer           pointer to the flat buffer to check (MUST have
 *                              dataLenInBytes >= lenInbytes)
 * @param[in] lenInBytes        the byte length of the number in the buffer
 * @param[in] checkMsb          flag to indicate whether (true) or not (false)
 *                              to check that the MSB is set
 * @param[in] checkLsb          flag to indicate whether (true) or not (false)
 *                              to check that the LSB is set
 *
 * @return CPA_STATUS_INVALID_PARAM  LSB and/or MSB checks failed
 * @return void                 All checks passed
 ******************************************************************************/
#define LAC_CHECK_FLAT_BUFFER_MSB_LSB(pBuffer, lenInBytes, checkMsb, checkLsb) \
    do                                                                         \
    {                                                                          \
        if (checkMsb &&                                                        \
            !((pBuffer)->pData[(pBuffer)->dataLenInBytes - lenInBytes] &       \
              0x80))                                                           \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " doesn't have MSB set");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
        if (checkLsb)                                                          \
        {                                                                      \
            LAC_CHECK_ODD_PARAM(pBuffer);                                      \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Checks that a flat buffer is non zero.
 *
 * @description
 *      This macro checks that a flat buffer's data is non zero.
 *
 * @param[in] pBuffer           pointer to the flat buffer to check
 *                              dataLenInBytes MUST be greater than 0
 *
 * @return CPA_STATUS_INVALID_PARAM  Non zero check failed
 * @return void                 All checks passed
 ******************************************************************************/
#define LAC_CHECK_NON_ZERO_PARAM(pBuffer)                                      \
    do                                                                         \
    {                                                                          \
        if (0 == LacPke_CompareZero((pBuffer), 0))                             \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " cannot be zero");                 \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Checks that a flat buffer data size is non zero.
 *
 * @description
 *      This macro checks that a flat buffer's data size is non zero.
 *
 * @param[in] pBuffer           pointer to the flat buffer to check
 *
 * @return CPA_STATUS_INVALID_PARAM  Non zero check failed
 * @return void                 Check passed
 ******************************************************************************/
#define LAC_CHECK_ZERO_SIZE(pBuffer)                                           \
    do                                                                         \
    {                                                                          \
        if ((pBuffer)->dataLenInBytes == 0)                                    \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#pBuffer " has incorrect length of zero");   \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Compare one large integer (+- delta) to another (+- delta)
 *
 * @description
 *      This function compares two large integers. The deltas are added to
 * the large integers and may be negative. The sum of the sizes of the buffers
 * containing the large numbers must be greater than 0.
 *
 * @param[in] pBufferA          first integer
 * @param[in] lengthA           length of first integer in bytes
 * @param[in] deltaA            delta, -(1<<30)< deltaA < (1<<30)
 * @param[in] pBufferB          second integer
 * @param[in] lengthB           length of second integer in bytes
 * @param[in] deltaB            delta, -(1<<30)< deltaB < (1<<30)
 *
 * @retval less than 0 if integerA + deltaA < integerB + deltaB
 * @retval 0 if integerA + deltaA = integerB + deltaB
 * @retval greater than 0 if integerA + deltaA > integerB + deltaB
 *
 ******************************************************************************/
Cpa32S LacPke_CompareIntPtrs(const Cpa8U *pBufferA,
                             Cpa32U lengthA,
                             const Cpa32S deltaA,
                             const Cpa8U *pBufferB,
                             Cpa32U lengthB,
                             const Cpa32S deltaB);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Compare one large integer (+- delta) to another (+- delta)
 *
 * @description
 *      This function compares two large integers. The deltas are added to
 * the large integers and may be negative. The sum of the sizes of the buffers
 * containing the large numbers must be greater than 0.
 *
 * @param[in] pFlatBufferA      first integer
 * @param[in] deltaA            delta, -(1<<30)< deltaA < (1<<30)
 * @param[in] pFlatBufferB      second integer
 * @param[in] deltaB            delta, -(1<<30)< deltaB < (1<<30)
 *
 * @retval less than 0 if integerA + deltaA < integerB + deltaB
 * @retval 0 if integerA + deltaA = integerB + deltaB
 * @retval greater than 0 if integerA + deltaA > integerB + deltaB
 *
 ******************************************************************************/
Cpa32S LacPke_Compare(const CpaFlatBuffer *pFlatBufferA,
                      const Cpa32S deltaA,
                      const CpaFlatBuffer *pFlatBufferB,
                      const Cpa32S deltaB);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Compare one large integer (+- delta) to 0
 *
 * @description
 *      This function compares a large integer to 0. The delta is added to
 * the large integer and may be negative.
 *
 * @param[in] pFlatBuffer       buffer containing large integer MUST have
 *                              dataLenInBytes > 0
 * @param[in] delta             delta
 *
 * @retval less than 0 if integerA + deltaA < 0
 * @retval 0 if integerA + deltaA = 0
 * @retval greater than 0 if integerA + deltaA > 0
 *
 ******************************************************************************/
Cpa32S LacPke_CompareZero(const CpaFlatBuffer *pFlatBuffer, const Cpa32S delta);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Compare one large integer to another
 *
 * @description
 *      This function checks whether two large integers are equal.
 *
 * @param[in] pFlatBufferA      first integer in a flat buffer
 * @param[in] pBufferB          second integer
 * @param[in] lengthB           length of second integer in bytes
 *
 * @retval CPA_TRUE             if integers are equal
 *         CPA_FALSE            otherwise
 *
 ******************************************************************************/
CpaBoolean LacPke_CompareFlatAndPtr(const CpaFlatBuffer *pFlatBufferA,
                                    const Cpa8U *pBufferB,
                                    Cpa32U lengthB);

/**
 ******************************************************************************
 * @ingroup LacAsymCommonUtils
 *     Returns the min length in bytes required to represent a number in a flat
 *     buffer
 *
 * @description
 *     Returns the min length in bytes required to represent a number in a flat
 *     buffer. If the buffer is 0 this dataLenInBytes will be returned.
 *
 * @param[in]  pBuffer            pointer to FlatBuffer (should NOT be NULL).
 *                                pData of the FlatBuffer can be NULL iff
 *                                dataLenInBytes=0
 * @retval                        most significant byte of number in FlatBuffer
 *
 *****************************************************************************/
Cpa32U LacPke_GetMinBytes(const CpaFlatBuffer *pBuffer);

/**
 ******************************************************************************
 * @ingroup LacAsymCommonUtils
 *     Returns the highest bit position of a number in a flat buffer
 *     (except if number is zero, see below).
 *     Also returns index to access most significant byte of flat buffer
 *
 * @description
 *     If X is a number in a FlatBuffer then this function calculates
 *     floor[log2(X)] for X>0.
 *     This can be used to locate the position of the msb (position indexed
 *     from 0). For example, floor[log2(1)] = 0 = b1 (the 0th bit is set).
 *     For example, floor[log2(8)] = 3 = b1000 (the 3rd bit is set).
 *     For example, floor[log2(21)] = 4 = b10101 (the 4th bit is set).
 *
 *     If X=0 floor[log2(X)] is "undefined" but in this function it is
 *     convenient to set the isZero flag CPA_TRUE and BitPos=0.
 *
 *     Currently limited to buffers with max 4096 bits (we have no pke service
 *     for bigger numbers)
 *
 * @param[in]  pBuffer          pointer to FlatBuffer (should NOT be NULL).
 *                              pData of the FlatBuffer can be NULL iff
 *                              dataLenInBytes=0
 * @param[in/out]  pBitPos      value will be updated to floor[log2(X)] for X>0
 *                              or if X=0 it will be set to 0, where X is the
 *                              number in FlatBuffer. If dataLenInBytes=0 then
 *                              this will be set to 0.
 * @param[in/out]  pIndexMsb    value will be updated to access most
 *                              significant byte of number in FlatBuffer
 *                              If number in buffer is 0 then index will be set
 *                              to dataLenInBytes-1. If dataLenInBytes=0
 *                              (i.e. pData == NULL) then index will
 *                              be set to -1
 * @param[in/out]  pIsZero      will be set CPA_TRUE if number in FlatBuffer =
 *                              0. If dataLenInBytes=0 then this will be set
 *                              CPA_TRUE
 *
 * @retval CPA_STATUS_INVALID_PARAM if number is greater than 512 bytes
 *         CPA_STATUS_SUCCESS       otherwise
 *
 *****************************************************************************/
CpaStatus LacPke_GetBitPos(const CpaFlatBuffer *pBuffer,
                           Cpa32U *pBitPos,
                           Cpa32U *pIndexMsb,
                           CpaBoolean *pIsZero);

/**
 ******************************************************************************
 * @ingroup LacAsymCommonUtils
 *     Returns the bit length of a number in a flat buffer. Note if number is
 *     zero bitLen = 0;
 *
 * @description
 *     Returns the minimum number of bits need to represent a number in a
 *     buffer. If more than 4096 bits are required we return _INVALID_PARAM
 *     (we have no pke service for bigger numbers)
 *
 * @param[in]  pBuffer          pointer to FlatBuffer (should NOT be NULL).
 *                              pData of the FlatBuffer can be NULL iff
 *                              dataLenInBytes=0
 * @param[in/out]  pBitLen      value will be updated to minimum number of bits
 *                              needed to represent number in FlatBuffer.
 *
 * @retval CPA_STATUS_INVALID_PARAM if number is greater than 4096 bytes
 *         CPA_STATUS_SUCCESS       otherwise
 *
 *****************************************************************************/
CpaStatus LacPke_GetBitLen(const CpaFlatBuffer *pBuffer, Cpa32U *pBitLen);

/**
 ***************************************************************************
 * @ingroup LacAsymCommonUtils
 *      Return the size in bytes of biggest number in provided n buffers
 *
 * @description
 *      Return the size of the biggest number in provided buffers where n
 *      specify buffer count. If NULL pointer was detected is skipped from
 *      comparision.
 *
 * @param[in]  n                number of buffers to compare
 * @param[in]  ...              list of pointers to a flat buffers
 *
 * @retval max  the size of the biggest number
 *
 ***************************************************************************/
Cpa32U LacPke_GetMaxLnOfNBuffers(int n, ...);

#endif /* _LAC_PKE_UTILS_H_ */
