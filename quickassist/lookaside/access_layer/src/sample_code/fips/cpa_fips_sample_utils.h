/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 ******************************************************************************
 * @file cpa_fips_sample_utils.h
 *
 * @defgroup fipsSampleUtils FIPS sample utility code
 *
 * @ingroup fipsSample
 *
 * @description
 * This header file contains function prototypes and structure definitions for
 * running the FIPS implementation utility functions
 *
 *****************************************************************************/

#ifndef _CPA_FIPS_SAMPLE_UTILS_H_
#define _CPA_FIPS_SAMPLE_UTILS_H_

/**
 * C99 header available from GCC v4.5
 **/
#include <stdbool.h>
#include "icp_sal_user.h"

/**
 *****************************************************************************
 * Utils definitions, enums and structures
 *****************************************************************************/
/**
 * If there is 1 crypto accelerator module, then this is the max supported
 * instances
 **/
/*32 crypto instances per dh89xxcc:
  -> 2 crypto instances per ring bank,
     8 ring banks per cpm,
     2 cpm per dh89xxcc
*/

#define MAX_SUPPORTED_QA_INSTANCES (32)

/**
 * maximum number of retries for a call to the Quick Assist API
 **/
#define FIPS_MAX_CY_RETRIES (100)

/**
 * number used to offset the number generation bias introduced by the
 * modulus operation
 **/
#define FIPS_OFFSET_MODULO_BIAS (8)
/**
 * size of a byte = 8 bits
 **/
#define BYTE_SIZE (0x08)
/**
 * Number of bytes in a (32 bit) word
 **/
#define WORD_BYTE_LEN_32U (sizeof(Cpa32U))
/**
 * Mask used to get a 4 byte aligned byte value
 **/
#define MAX_BYTE_VALUE (0xFF)
/**
 * Maximum index of a four byte array
 **/
#define FOUR_BYTE_ARRAY_MAX_INDEX (0x03)
/**
 * Min size for a Miller Rabin random data buffer is 64 for the QA API
 **/
#define FIPS_SAMPLE_PRIME_MIN_MR_ROUND_SIZE (64)
/**
 * Prime generation involves incrementing a number, but no point in checking
 * the even ones
 **/
#define ADD_2_TO_KEEP_ODD (2)

/**
 * Byte alignment for memory allocation
 **/
#define BYTE_ALIGNMENT_8 (8)

/**
 * Supported digest sizes in bytes
 **/
#define SHA1_DIGEST_SIZE_IN_BYTES (20)
#define SHA224_DIGEST_SIZE_IN_BYTES (28)
#define SHA256_DIGEST_SIZE_IN_BYTES (32)
#define SHA384_DIGEST_SIZE_IN_BYTES (48)
#define SHA512_DIGEST_SIZE_IN_BYTES (64)
#ifdef __x86_64__
#define SAMPLE_CODE_UINT Cpa64U
#define SAMPLE_CODE_INT Cpa64S
#else
#define SAMPLE_CODE_UINT Cpa32U
#define SAMPLE_CODE_INT Cpa32S
#endif

/**
 * Number of Miller Rabin rounds used in checking the primality of a number
 **/
#define MAX_MILLER_RABIN_ROUNDS (38)

#define PRINT(args...) printf(args)
/*schedule function not required in userspace*/
#define schedule()

#define PRINT_ERR(args...)                                                     \
    do                                                                         \
    {                                                                          \
        PRINT("%s(%d)", __FUNCTION__, __LINE__);                               \
        PRINT(args);                                                           \
    } while (0)

#ifdef DEBUG
#define PRINT_DBG(args...) PRINT_ERR(args)
#else
#define PRINT_DBG(args...)
#endif

#define FIPS_SAMPLE_TOP_BIT (0x80)
/**
 * Set the top bit of a byte to 1
 **/
#define FIPS_SAMPLE_SET_TOP_BIT(byte)                                          \
    do                                                                         \
    {                                                                          \
        byte |= 0x80;                                                          \
    } while (0)

/**
 * Set the top bit of a byte to 1
 **/
#define FIPS_SAMPLE_UNSET_TOP_BIT(byte)                                        \
    do                                                                         \
    {                                                                          \
        byte &= 0x7F;                                                          \
    } while (0)

/**
 * Set the bottom bit of a byte to 1
 **/
#define FIPS_SAMPLE_SET_BOTTOM_BIT(byte)                                       \
    do                                                                         \
    {                                                                          \
        byte |= 1;                                                             \
    } while (0)

/**
 * Set the bottom bit of a byte to 0
 **/
#define FIPS_SAMPLE_UNSET_BOTTOM_BIT(byte)                                     \
    do                                                                         \
    {                                                                          \
        byte &= ~1;                                                            \
    } while (0)

#define FIPS_SAMPLE_UNSIGNED_MULT_BY_TWO(cpa32Uval) (cpa32Uval << 1)

#define FIPS_SAMPLE_UNSIGNED_DIVIDE_BY_TWO(cpa32Uval) (cpa32Uval >> 1)

/**
 * put a 32U value into a 4 byte array (MSB byte order)
 **/
#define COPY_32_BIT_UNSIGNED_VAL_TO_4_BYTE_ARRAY(val_array, val)               \
    do                                                                         \
    {                                                                          \
        int i;                                                                 \
        for (i = 0; i < FOUR_BYTE_ARRAY_MAX_INDEX; i++)                        \
        {                                                                      \
            val_array[FOUR_BYTE_ARRAY_MAX_INDEX - i] =                         \
                ((val >> (i * BYTE_SIZE))) & MAX_BYTE_VALUE;                   \
        }                                                                      \
    } while (0)

/**
 * Copy a flatbuffer pData and dataLengthInBytes
 **/
#define COPY_FLATBUFF(dest, src)                                               \
    do                                                                         \
    {                                                                          \
        (void)memcpy((dest)->pData, (src)->pData, (src)->dataLenInBytes);      \
        (dest)->dataLenInBytes = (src)->dataLenInBytes;                        \
    } while (0)

/**
 * set flatbuffer pData to zero
 **/
#define ZERO_FLATBUFF(fb)                                                      \
    do                                                                         \
    {                                                                          \
        (void)memset((fb)->pData, 0, (fb)->dataLenInBytes);                    \
    } while (0)

/**
 * This is to avoid large amounts of repetition in the code
 **/
#define RETURN_IF_CPA_STATUS_FAIL(fn)                                          \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != (fn))                                        \
        {                                                                      \
            PRINT_DBG("return fail at line %d\n", __LINE__);                   \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

#define CHECK_MAX_RETRIES(maxRetries, status)                                  \
    do                                                                         \
    {                                                                          \
        if (FIPS_MAX_CY_RETRIES == maxCyRetries)                               \
        {                                                                      \
            PRINT_ERR("Too many retries (%u) from QA API\n",                   \
                      FIPS_MAX_CY_RETRIES);                                    \
            status = CPA_STATUS_FAIL;                                          \
        }                                                                      \
    } while (0)

/**
 *****************************************************************************
 *
 * Utils function prototypes
 *
 *****************************************************************************/
/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      displayHexArray
 *
 * @description
 *      Display the contents of a buffer
 *
 * @param[in]  pLabel      String to giving a short description of the printed
 *                         value
 * @param[in]  pBuff       pointer to the data to be printed
 * @param[in]  len         len of the data to be printed
 *
 * @retval none
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline void displayHexArray(const char *restrict pLabel,
                                   const Cpa8U *restrict pBuff,
                                   Cpa32U len)
{

    int i = 0;
    PRINT("%s(%d)", pLabel, len);
    if (NULL == pBuff)
    {
        PRINT("%s(%d) Buff is NULL!!\n", __FUNCTION__, __LINE__);
        return;
    }
    for (i = 0; i < len; i++)
    {
        PRINT("%02x", pBuff[i]);
    }
    PRINT("\n");
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      displayHexArrayFB
 *
 * @description
 *      Display the contents of a CpaFlatBuffer
 *
 * @param[in]  pLabel      String to giving a short description of the printed
 *                         value
 * @param[in]  pFb         pointer to the CpaFlatBuffer to be printed
 *
 * @retval none
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline void displayHexArrayFB(const char *restrict pLabel,
                                     const CpaFlatBuffer *restrict pFb)
{
    if (NULL == pFb)
    {
        PRINT("%s -- Buff is NULL!!\n", pLabel);
        return;
    }
    displayHexArray(pLabel, pFb->pData, pFb->dataLenInBytes);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osMemInit
 *
 * @description
 *      Opens the qae mem alloc file descriptor if compiled for user space
 *
 * @retval CPA_STATUS_SUCCESS   Operation completed successfully
 *         CPA_STATUS_FAIL      Operation completed unsuccessfully
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus osMemInit(void);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osMemDestroy
 *
 * @description
 *      Closes mem alloc file descriptor if compiled for user space
 *
 * @retval none
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
void osMemDestroy(void);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osZalloc
 *
 * @description
 *      Allocate some contiguous memory. The Quick Assist driver requires
 *      memory to be contiguous for processing with its cryptographic module
 *      Allocated memory is also set to zero.
 *
 * @param[in]  size               Amount of memory to be allocated
 * @param[in]  instanceHandle     QA instance handle.
 *
 * @retval     NULL               Memory allocation failed
 *             Cpa8U *            Pointer to allocated memory area.
 *
 * @pre
 *     none
 * @post
 *     Memory should be eventually freed using the osFree function.
 *****************************************************************************/
Cpa8U *osZalloc(Cpa32U size, const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osFree
 *
 * @description
 *      Free memory allocated by osMalloc
 *
 * @param[in]  ppPtr         Pointer to a pointer to an the allocated memory
 *                           address
 *
 * @retval none
 *
 * @pre
 *     *ppPtr should have been allocated by osZalloc
 * @post
 *     none
 *****************************************************************************/
void osFree(Cpa8U **const ppPtr);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osVirtToPhysNuma
 *
 * @description
 *      Specifies the function to be used for converting a pointer value from
 *      virtual to it's physical equivalent. This function is passed to and
 *      only called from the Quick Assist Driver
 *
 * @param[in]  pVirtAddr         Pointer to the virtual address to be
 *                               converted
 *
 * @retval CpaVirtualToPhysical  Physical address pointer associated with
 *                               pVirtAddr
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaPhysicalAddr osVirtToPhysNuma(void *pVirtAddr);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      fipsSampleBufXOR
 *
 * @description
 *     Perform an XOR operation two buffers of the same length
 *
 * @param[in,out] pBuf1     First operand for the XOR
 *                          Result is stored in this operand
 *
 * @param[in]     pBuf2    Second operand for the XOR
 * @param[in]     length   Length of data in the two operands
 *
 * @retval none
 *
 * @pre
 *     pFb1 and pFb2 should point at allocated memory
 * @post
 *     none
 *****************************************************************************/
static inline void fipsSampleBufXOR(Cpa8U *pBuf1, Cpa8U *pBuf2, Cpa32U length)
{
    Cpa32U i = 0;

    for (i = 0; i < length; i++)
    {
        pBuf1[i] ^= pBuf2[i];
    }
    return;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      doModExp
 *
 * @description
 *      Do a Modular Exponentiation operation
 *      target = (base ^ exponent) mod (modulus);
 *
 * @param[in]  pBase             base value
 * @param[in]  pExponent         exponent value, if this value is NULL, an
 *                               exponent of 1 is used.
 * @param[in]  pModulus          modulus value
 * @param[in]  instanceHandle    QA instance handle
 *
 * @param[out] pTarget           result value
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus doModExp(const CpaFlatBuffer *restrict pBase,
                   const CpaFlatBuffer *restrict pExponent,
                   const CpaFlatBuffer *restrict pModulus,
                   CpaFlatBuffer *pTarget,
                   const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      doModInv
 *
 * @description
 *      Get the inverse modulus of a number:
 *      target = (base ^ -1) mod (modulus);
 *
 * @param[in]  pBase             base value
 * @param[in]  pModulus          modulus value
 * @param[out] pTarget           Result is stored here
 * @param[in]  instanceHandle    QA instance handle
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus doModInv(const CpaFlatBuffer *restrict pBase,
                   const CpaFlatBuffer *restrict pModulus,
                   CpaFlatBuffer *pTarget,
                   const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      checkFlatBuffer
 *
 * @description
 *      Check whether a CpaFlatBuffer pointer is NULL and if it has an
 *      associated data buffer. This function is generally used in initial
 *      checks before performing an operation.
 *
 * @param[in]  pLabel      String to giving a short description of the printed
 *                         value
 * @param[in]  pFb         pointer to the CpaFlatBuffer to be checked
 *
 * @retval CPA_STATUS_SUCCESS   CpaFlatBuffer pointer is not NULL and has an
 *                              associated data buffer
 *         CPA_STATUS_FAIL      CpaFlatBuffer may be NULL or may have no
 *                              associated data buffer.
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline CpaStatus checkFlatBuffer(const char *restrict pLabel,
                                        const CpaFlatBuffer *restrict pFb)
{
    if (NULL == pLabel)
    {
        PRINT_ERR("pLabel is NULL\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == pFb)
    {
        PRINT_ERR("%s pFb is NULL\n", pLabel);
        return CPA_STATUS_FAIL;
    }
    if (NULL == pFb->pData)
    {
        PRINT_ERR("%s pFb pData is NULL\n", pLabel);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      checkOne
 *
 * @description
 *      Make sure the value of a CpaFlatBuffer is 1
 *
 * @param[in]  pFb         pointer to the CpaFlatBuffer to be printed
 *
 * @retval CpaBoolean      If this is true, the buffer contains a 1. If it is
 *                         false, the buffer contains a different number
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline CpaBoolean checkOne(const CpaFlatBuffer *restrict pFb)
{
    Cpa32U i = 0;

    if (1 != pFb->pData[pFb->dataLenInBytes - 1])
    {
        return CPA_FALSE;
    }

    for (i = 0; i < (pFb->dataLenInBytes - 1); i++)
    {
        if (pFb->pData[i] != 0)
        {
            return CPA_FALSE;
        }
    }
    return CPA_TRUE;
}

/**
 * ***************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      isFlatBufValGreaterThanOrEqualTo32UVal
 *
 * @description
 *      Check that a CpaFlatBuffer stores a value equal to or larger than
 *      a Cpa32U value
 *
 * @param[in]  pFb                      Flat buffer pointer with
 *                                      associated data
 * @param[in]  val                      32 bit value that could be larger than
 *                                      the pFb stored value
 *
 * @retval  CPA_TRUE                    Larger buffer stores an equal or
 *                                      larger number
 *          CPA_FALSE                   32 bit value is larger
 * @pre
 *      pFb is not NULL and it has an associated data area
 * @post
 *****************************************************************************/
CpaBoolean isFlatBufValGreaterThanOrEqualTo32UVal(const CpaFlatBuffer *restrict
                                                      pFb,
                                                  Cpa32U val);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      isFbALessThanFbB
 *
 * @description
 *      Check that the first operand stores a smaller number than the second.
 *
 * @param[in]  pFbA                     First operand
 * @param[in]  pFbB                     Second operand
 *
 * @retval  CPA_TRUE                    second operand stores a larger number
 *          CPA_FALSE                   first operand stores an equal or larger
 *                                      number
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
CpaBoolean isFbALessThanFbB(const CpaFlatBuffer *restrict pFbA,
                            const CpaFlatBuffer *restrict pFbB);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      isFbOdd
 *
 * @description
 *      Check if a CpaFlatBuffer contains an odd value
 *
 * @param[in]  pFb         pointer to the CpaFlatBuffer to be checked
 *
 * @retval  CPA_TRUE       Stored number is odd
 *          CPA_FALSE      Stored number is even
 *
 * @pre
 *     pFb is not NULL and it's pData argument is also not NULL
 * @post
 *     none
 *****************************************************************************/
static inline CpaBoolean isFbOdd(const CpaFlatBuffer *restrict pFb)
{

    if (1 != (pFb->pData[pFb->dataLenInBytes - 1] & 1))
    {
        return CPA_FALSE;
    }
    return CPA_TRUE;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      checkZero
 *
 * @description
 *      Check if a CpaFlatBuffer is zero
 *
 * @param[in]  pFb         pointer to the CpaFlatBuffer to be checked
 *
 * @retval  CPA_TRUE       Stored number is zero
 *          CPA_FALSE      Stored number is not zero
 *
 * @pre
 *     pFb is not NULL and it's pData argument is also not NULL
 * @post
 *     none
 *****************************************************************************/
static inline CpaBoolean checkZero(const CpaFlatBuffer *restrict pFb)
{
    Cpa32U i = 0;

    for (i = 0; i < pFb->dataLenInBytes; i++)
    {
        if (0 != pFb->pData[i])
        {
            return CPA_FALSE;
        }
    }
    return CPA_TRUE;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      incrementFlatBuffer8U
 *
 * @description
 *      This function increments value stored in pCurrentTarget by increment.
 *      If pCheckTarget is provided the result will be stored in pCheckTarget,
 *      otherwise in pCurrentTarget'
 *
 * @param[in,out]  pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                                copied to this buffer and this is used to
 *                                store the result
 * @param[in,out]  pCurrentTarget Stores the number to be incremented
 *                                If pCheckTarget is NULL, this is used to
 *                                store the result
 * @param[in]  increment          amount to increment the buffer by
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_INVALID_PARAM
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus incrementFlatBuffer8U(CpaFlatBuffer *pCheckTarget,
                                CpaFlatBuffer *pCurrentTarget,
                                Cpa8U increment);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      incrementFlatBuffer32U
 *
 * @description
 *      increment a CpaFlatBuffer value by an amount stored in 32 bits. This
 *      is useful as it means every number does not have to have be associated
 *      with a CpaFlatBuffer.
 *
 * @param[in,out] pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                               copied to this buffer and this is used to
 *                               store the result
 * @param[in,out] pCurrentTarget Stores the number to be incremented
 *                               If pCheckTarget is NULL, this is used to
 *                               store the result
 * @param[in]  increment         amount to increment the buffer by
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus incrementFlatBuffer32U(CpaFlatBuffer *pCheckTarget,
                                 CpaFlatBuffer *pCurrentTarget,
                                 Cpa32U increment);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      addFlatBuffer
 *
 * @description
 *      Adds two flat buffers together. If there is an
 *      overflow of the result buffer, it returns CPA_STATUS_FAIL.
 *      If 'pCheckTarget' is NULL, then the result is stored in
 *      'pCurrentTarget'.
 *
 * @param[in,out] pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                               copied to this buffer and this is used to
 *                               store the result
 * @param[in,out] pCurrentTarget Stores the number to be incremented
 *                               If pCheckTarget is NULL, this is used to
 *                               store the result
 * @param[in]  pFbIncrement      Amount to add to the other CpaFlatBuffer
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     Input/output values should not be NULL and should have a data buffer
 *     associated with them.
 * @post
 *     none
 *****************************************************************************/
CpaStatus addFlatBuffer(CpaFlatBuffer *pCheckTarget,
                        CpaFlatBuffer *pCurrentTarget,
                        CpaFlatBuffer *pFbIncrement);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getOffsetToBufferedData
 *
 * @description
 *      get the offset to the MSB of the number stored within pFb
 *
 * @param[in]  pFb         pointer to the CpaFlatBuffer to be checked
 *
 * @retval     Cpa32U      offset to the start of the number
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline Cpa32U getOffsetToBufferedData(const CpaFlatBuffer *restrict pFb)
{

    Cpa32U bufDataOffset = 0;

    for (bufDataOffset = 0; bufDataOffset < pFb->dataLenInBytes;
         bufDataOffset++)
    {
        if (pFb->pData[bufDataOffset] != 0)
        {
            break;
        }
    }
    return bufDataOffset;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getHashBytes
 *
 * @description
 *      Get the output length of the specified hash function
 *
 * @param[in]  shaAlg           SHA algorithm to check
 * @param[out] pHashLenBytes    Output length in bytes of the SHA algorithm
 *
 * @retval CPA_STATUS_SUCCESS   The output length has been found
 * @retval CPA_STATUS_FAIL      The output length could not be found
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
static inline CpaStatus getHashBytes(CpaCySymHashAlgorithm shaAlg,
                                     Cpa32U *pHashLenBytes)
{
    switch (shaAlg)
    {
        case CPA_CY_SYM_HASH_SHA1:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA1 (160 bits)\n");
            *pHashLenBytes = SHA1_DIGEST_SIZE_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA224:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA224\n");
            *pHashLenBytes = SHA224_DIGEST_SIZE_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA256:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA256\n");
            *pHashLenBytes = SHA256_DIGEST_SIZE_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA384:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA384\n");
            *pHashLenBytes = SHA384_DIGEST_SIZE_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA512:
            PRINT_DBG("CPA_CY_SYM_HASH_SHA512\n");
            *pHashLenBytes = SHA512_DIGEST_SIZE_IN_BYTES;
            break;
        default:
            PRINT_ERR("Operation not supported\n");
            return CPA_STATUS_FAIL;
            break;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      rightShift
 *
 * @description
 *      Right shift all buffer data by 1 bit.
 *
 * @param[in,out] pBuf       A pointer to the memory to be right shifted
 * @param[in]     bufLength  Length of the buffer to be shifted
 *
 * @retval This function returns void
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *
 *****************************************************************************/
static inline void rightShift(Cpa8U *pBuf, Cpa32U bufLength)
{
    Cpa32U i = 0;
    bool bitCheck = false;
    bool lastBitCheck = false;

    for (i = 0; i < bufLength; i++)
    {
        lastBitCheck = bitCheck;
        bitCheck = pBuf[i] & 1;
        pBuf[i] >>= 1;
        if (lastBitCheck)
        {
            FIPS_SAMPLE_SET_TOP_BIT(pBuf[i]);
        }
    }
    return;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      mulFlatBuffer8U
 *
 * @description
 *      Multiplies a flat buffer by an Cpa8U value. 'pTarget' should be 1 byte
 *      larger than 'pSource' to avoid overflow.
 *      N.B. If 'pTarget' already has a value, this is not overwritten, but
 *      added to, i.e. result = (pSource * multiplier) + pTarget
 *      Not overwriting pTarget allows for multiplication of two CpaFlatBuffer
 *      values.
 *
 * @param[in]  pSource         pointer to the CpaFlatBuffer to be multiplied
 * @param[in]  multiplier      Value to multiply by
 *
 * @param[out] pTarget         pointer to the CpaFlatBuffer to store the
 *                             result.
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_INVALID_PARAM
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus mulFlatBuffer8U(CpaFlatBuffer *pTarget,
                          CpaFlatBuffer *pSource,
                          const Cpa8U multiplier);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      mulFlatBuffer
 *
 * @description
 *      Multiply two CpaFlatBuffers together and store the result.
 *
 * @param[in]  pFb1            Flat buffer to be multiplied
 * @param[in]  pFb2            Flat buffer to be multiplied
 *
 * @param[out] pTarget         pointer to the CpaFlatBuffer to store the
 *                             result.
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     Result must be allocated with mem length =  len(pFb1) + len(pFb2)
 * @post
 *     none
 *****************************************************************************/
CpaStatus mulFlatBuffer(CpaFlatBuffer *pTarget,
                        const CpaFlatBuffer *restrict pFb1,
                        const CpaFlatBuffer *restrict pFb2);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      decrementFlatBuffer8U
 *
 * @description
 *      Subtracts a small value (max 1 byte) from a Flat Buffer. If there
 *      is an underflow of the buffer, it returns CPA_STATUS_FAIL.
 *
 * @param[in,out] pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                               copied to this buffer and this is used to
 *                               store the result
 * @param[in,out] pCurrentTarget Stores the number to be decremented
 *                               If pCheckTarget is NULL, this is used to
 *                               store the result
 * @param[in]  decrement         Amount to decrement the CpaFlatBuffer
 *                               value
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus decrementFlatBuffer8U(CpaFlatBuffer *pCheckTarget,
                                CpaFlatBuffer *pCurrentTarget,
                                Cpa8U decrement);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      decrementFlatBuffer32U
 *
 * @description
 *      Subtracts a small value (max 4 bytes) from a Flat Buffer. If there
 *      is an underflow of the buffer, it returns CPA_STATUS_FAIL.
 *
 * @param[in,out] pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                               copied to this buffer and this is used to
 *                               store the result
 * @param[in,out] pCurrentTarget Stores the number to be decremented
 *                               If pCheckTarget is NULL, this is used to
 *                               store the result
 * @param[in]  fBincrement       Amount to decrement the CpaFlatBuffer
 *                               value
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus decrementFlatBuffer32U(CpaFlatBuffer *pCheckTarget,
                                 CpaFlatBuffer *pCurrentTarget,
                                 Cpa32U decrement);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      subFlatBuffer
 *
 * @description
 *      Subtracts the value stored in pFbDecrement from pCurrentTarget. If
 *      pCheckTarget is not NULL, it stores the result.
 *      Otherwise pCurrentTarget is used to store the result (overwriting the
 *      original value).
 *
 * @param[in,out] pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                               copied to this buffer and this is used to
 *                               store the result
 * @param[in,out] pCurrentTarget Stores the number to subtracted from
 *                               If pCheckTarget is NULL, this is used to
 *                               store the result
 * @param[in]  pFbDecrement      Amount to subtract from the other
 *                               CpaFlatBuffer
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     pFbDecrement must be less than or equal to pCurrentTarget in size
 * @post
 *     none
 *****************************************************************************/
CpaStatus subFlatBuffer(CpaFlatBuffer *pCheckTarget,
                        CpaFlatBuffer *pCurrentTarget,
                        CpaFlatBuffer *pFbDecrement);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      fipsSampleGetQaInstance
 *
 * @description
 *      The function returns a started QA instance handle.
 *
 * @param[in,out] pInstanceHandle   QA instance handle to be initialized
 *
 * @retval CPA_STATUS_SUCCESS       QA instance has been started successfully
 *         CPA_STATUS_FAIL          Failed to start QA instance
 *
 * @pre
 *     Note, the sample_code/performance qae memory allocation driver must be
 *     build and added to the system before this step is reached!
 *
 *     cd $SAMPLE_CODE_DIR/performance/qae/linux/kernel_space
 *     make PERF_SAMPLE_SRC_ROOT=$SAMPLE_CODE_DIR/performance/
 *     insmod build/linux_2.6/kernel_space/qaeMemDrv.ko
 * @post
 *      pInstanceHandle needs to be deactivated after calling this function
 *
 *****************************************************************************/
CpaStatus fipsSampleGetQaInstance(CpaInstanceHandle *pInstanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      fipsSampleStopQAinstance
 *
 * @description
 *      Stops the Cy instance
 *
 * @param[in]  instanceHandle      QA instance handle for instance to be
 *                                 stopped.
 *
 * @retval CPA_STATUS_SUCCESS      QA instance has been stopped successfully
 *         CPA_STATUS_FAIL         Failed to start QA instance
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus fipsSampleStopQAinstance(CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getTrueRandomBytes
 *
 * @description
 *      Use the Quick Assist Non Deterministic Random Bit Generator to get a
 *      random value
 *
 * @param[in]  pBuffer     Buffer to store the random number in
 * @param[in]  length      length of required random data
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus getTrueRandomBytes(CpaFlatBuffer *pBuffer, Cpa32U length);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      generateRandomBytes
 *
 * @description
 *      Generate some random bytes using the Quick Assist Deterministic Random
 *      Number Generator
 *
 * @param[out] pRandBuf          Buffer to be populated with random values
 * @param[in]  len               Length of data to be populated
 * @param[in]  securityStrength  Security Strength to be used
 * @param[in]  instanceHandle    QA instance handle
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus generateRandomBytes(CpaFlatBuffer *pRandBuf,
                              Cpa32U len,
                              CpaCyDrbgSecStrength securityStrength,
                              const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getRandomLessThanN
 *
 * @description
 *      Get a random number less than 'N' by calculating
 *      target = (R ^ 1) mod(N);
 *
 * @param[out]  pTarget          Result value.
 * @param[in]  pNvalue           Value of N
 * @param[in]  securityStrength  Security Strength to be used
 * @param[in]  instanceHandle    QA instance handle
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     pTarget should be allocated with data length >= pNvalue
 * @post
 *     none
 *****************************************************************************/
CpaStatus getRandomLessThanN(CpaFlatBuffer *pTarget,
                             const CpaFlatBuffer *pNvalue,
                             CpaCyDrbgSecStrength securityStrength,
                             const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      checkPrimality
 *
 * @description
 *      Check if a Flat Buffer contains a prime number (conforms with
 *      FIPS 186-3 Appendix C.3 prime checks). Table C.1 is used for DSA
 *      prime check and table C.3 is used for RSA. That is to say,
 *      'performLucasTest' should be set to CPA_TRUE for DSA and is optional for
 *      RSA. 'numMillerRabinRounds' should be set to at least the minimum
 *      number of Miller Rabin rounds shown in the respective tables.
 *
 * @param[in]  pPrime                   Value to be checked
 * @param[in]  numMillerRabinRounds     Number of Miller Rabin rounds to use
 *                                      in the prime check
 * @param[in]  performLucasTest         do a Lucas prime test after the
 *                                      Miller Rabin checks are complete
 * @param[out] pPrime                   input value is prime
 * @param[in]  instanceHandle           QA instance handle
 * @param[in]  securityStrength         Required DRNG security strength for (L,
 *N)
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus checkPrimality(const CpaFlatBuffer *restrict pPrime,
                         Cpa32U numMillerRabinRounds,
                         CpaBoolean performLucasTest,
                         CpaBoolean *pIsPrime,
                         const CpaInstanceHandle instanceHandle,
                         Cpa32U securityStrength);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getMesgDigest
 *
 * @description
 *      Get a message digest based on the Session Setup Data
 *
 * @param[in,out] pMesg          Message to be Hashed. The message value is
 *                               overwritten if pMesgDigestResult is NULL
 * @param[out] pMesgDigestResult If this is NULL, the hash result is stored
 *                               in pMesg (overwriting the value stored there)
 *
 * @param[in]  pSessionSetupData Values for algorithm and digest
 *                               length are filled in before passing this
 *                               to the getMesgDigest function.
 * @param[in]  instanceHandle    QA instance handle
 *
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus getMesgDigest(CpaFlatBuffer *pMesg,
                        CpaFlatBuffer *pMesgDigestResult,
                        CpaCySymSessionSetupData *pSessionSetupData,
                        const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      symSetupBufferLists
 *
 * @description
 *      Setup some buffer list structures for Quick Assist Symmetric
 *      operations. If the caller wishes to use out of place processing (as
 *      defined by the QA API), pBufferListOutOfPlace parameter may be used
 *      to setup a second buffer list.
 *
 * @param[in]  numBuffers        Number of buffers that are going to be added
 *                               to the list
 *
 * @param[out] pBufferList       Buffer List to be populated
 * @param[out] pBufferListOutOfPlace
 *                               If this value is not NULL, it is also
 *                               populated.
 *
 * @param[in]  instanceHandle    QA instance handle
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus symSetupBufferLists(Cpa32U numBuffers,
                              CpaBufferList *pBufferList,
                              CpaBufferList *pBufferListOutOfPlace,
                              const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      symSessionInit
 *
 * @description
 *      Initialize a Symmetric Crypto Session using the Quick Assist API
 *
 * @param[in]  pSessionSetupData All values must be set in this structure
 *                               before calling this function
 * @param[in]  instanceHandle    QA instance handle
 *
 * @param[out] ppSessionCtxIn    Session Context to be set
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     If the function returns CPA_STATUS_SUCCESS, it is up to the calling
 *     function to free the memory associated with 'ppSessionCtxIn'
 *****************************************************************************/
CpaStatus symSessionInit(const CpaCySymSessionSetupData *sessionSetupData,
                         CpaCySymSessionCtx **ppSessinCtxIn,
                         const CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      symSessionRemove
 *
 * @description
 *      Wait for in-flight request and removes a Symmetric Crypto
 *      Session using the Quick Assist API, free allocated memory.
 *
 * @param[in]  instanceHandle    QA instance handle
 *
 * @param[out] pSessionCtx       Session Context to be removed
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus symSessionRemove(CpaInstanceHandle instanceHandle,
                           CpaCySymSessionCtx *pSessionCtx);

#endif /*_CPA_FIPS_SAMPLE_UTILS_H_*/
