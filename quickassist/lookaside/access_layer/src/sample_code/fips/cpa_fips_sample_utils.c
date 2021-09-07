/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 * @file cpa_fips_sample_utils.c
 *
 * @ingroup fipsSampleCodeUtils
 *
 * Common functions for the FIPS sample code.
 *
 *****************************************************************************/

#include "cpa_fips_sample.h"
#include "cpa_fips_sample_utils.h"

/* Check for CY API version */
#define CY_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_CY_API_VERSION_NUM_MAJOR > major ||                                   \
     (CPA_CY_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_CY_API_VERSION_NUM_MINOR >= minor))

/**
 ******************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      EXPORT_SYMBOLs
 *
 * Functions which are exported for the kernel module interface
 *****************************************************************************/

/*functions defined in the Performance Code qae module that are only used in
  user space*/
extern CpaStatus qaeMemInit(void);
extern void qaeMemDestroy(void);

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
CpaStatus osMemInit(void)
{
    return qaeMemInit();
}

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
void osMemDestroy(void)
{
    (void)qaeMemDestroy();
}

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
CpaPhysicalAddr osVirtToPhysNuma(void *pVirtAddr)
{

    return (CpaPhysicalAddr)(SAMPLE_CODE_UINT)qaeVirtToPhysNUMA(pVirtAddr);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osZalloc
 *
 * @description
 *      Allocate some contiguous memory. The Quick Assist driver requires
 *      memory to be contiguous for processing with its cryptographic module.
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
Cpa8U *osZalloc(Cpa32U size, const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceInfo2 instanceInfo2 = {
        0,
    };
    Cpa8U *pPtr = NULL;

    status = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo2);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get node for instance\n");
        return NULL;
    }

    if (CPA_OPER_STATE_UP != instanceInfo2.operState)
    {
        PRINT_ERR("Mem alloc fail - node is not initialized\n");
        return NULL;
    }

    /*NULL return value is checked in the calling function*/
    pPtr = (Cpa8U *)qaeMemAllocNUMA(
        size, instanceInfo2.nodeAffinity, BYTE_ALIGNMENT_8);
    if (NULL != pPtr)
    {
        (void)memset(pPtr, 0, size);
    }
    return pPtr;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      osFree
 *
 * @description
 *      Free memory allocated by osZalloc
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
void osFree(Cpa8U **const ppPtr)
{
    if (NULL == *ppPtr)
    {
        // PRINT_DBG("pPtr is NULL\n");
        return;
    }
    qaeMemFreeNUMA((void **)ppPtr);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      checkBufferCommonAreaContainsLargerValue
 *
 * @description
 *      The common area here is the area of the larger buffer that is the
 *      same size as that of the smaller buffer, and the smaller buffer.
 *      This function is called when the larger buffer most significant bytes
 *      which are not in the common area are zero.
 *      The value difference of the numbers stored in the two input buffers
 *      to this function is checked.
 *
 * @param[in]  storageSizeDifference    size difference between the two buffer
 *                                      inputs.
 * @param[in]  pLargerSizeBuffer        Larger buffer input
 * @param[in]  pSmallerSizeBuffer       Smaller buffer input
 *
 * @param[out] pBuffersAreEqual         If the buffers are equal, this is set
 *                                      to CPA_TRUE. The value referenced by
 *                                      this pointer is only set if the
 *                                      pointer is not NULL.
 *
 * @retval  CPA_TRUE                    Larger buffer stores a larger number
 *          CPA_FALSE                   smaller buffer stores an equal or
 *                                      larger number
 * @pre
 *      Bytes stored from pLargerSizeBuffer->pData[0] to
 *      pLargerSizeBuffer->pData[storageSizeDifference -1] are equal to zero
 * @post
 *      none
 *****************************************************************************/
static inline CpaBoolean checkBufferCommonAreaContainsLargerValue(
    Cpa32U storageSizeDifference,
    const CpaFlatBuffer *restrict pLargerSizeBuffer,
    const CpaFlatBuffer *restrict pSmallerSizeBuffer,
    CpaBoolean *pBuffersAreEqual)
{
    Cpa32U i = 0;
    for (i = 0; i < pSmallerSizeBuffer->dataLenInBytes; i++)
    {
        if (pLargerSizeBuffer->pData[i + storageSizeDifference] >
            pSmallerSizeBuffer->pData[i])
        {
            return CPA_TRUE;
            /*If the bytes are equal at this point, a larger number may still be
              found at a less significant byte*/
        }
        else if (pLargerSizeBuffer->pData[i + storageSizeDifference] <
                 pSmallerSizeBuffer->pData[i])
        {
            return CPA_FALSE;
        }
        else
        {
            /*equal*/
            continue;
        }
    }
    /*buffers are equal (i.e. the larger buffer does not contain a larger
      value)*/
    if (NULL != pBuffersAreEqual)
    {
        *pBuffersAreEqual = CPA_TRUE;
    }
    return CPA_FALSE;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      checkLargerBufferStoresLargerValue
 *
 * @description
 *      The value difference of the numbers stored in the two input buffers
 *      to this function is checked.
 *
 * @param[in]  storageSizeDifference    size difference between the two buffer
 *                                      inputs in bytes.
 * @param[in]  pLargerSizeBuffer        Larger buffer input
 * @param[in]  pSmallerSizeBuffer       Smaller buffer input
 *
 * @param[out] pBuffersAreEqual         If the buffers are equal, this is set
 *                                      to CPA_TRUE. The value referenced by
 *                                      this pointer is only set if the
 *                                      pointer is not NULL.
 *
 * @retval  CPA_TRUE                    Larger buffer stores a larger number
 *          CPA_FALSE                   smaller buffer stores an equal or
 *                                      larger number
 * @pre
 *      none
 * @post
 *      none
 *****************************************************************************/
static inline CpaBoolean checkLargerBufferStoresLargerValue(
    const Cpa32U storageSizeDifference,
    const CpaFlatBuffer *restrict pLargerSizeBuffer,
    const CpaFlatBuffer *restrict pSmallerSizeBuffer,
    CpaBoolean *pBuffersAreEqual)
{
    Cpa32U i = 0;
    for (i = 0; i < storageSizeDifference; i++)
    {
        if (pLargerSizeBuffer->pData[i] > 0)
        {
            return CPA_TRUE;
        }
    }
    return checkBufferCommonAreaContainsLargerValue(storageSizeDifference,
                                                    pLargerSizeBuffer,
                                                    pSmallerSizeBuffer,
                                                    pBuffersAreEqual);
}

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
                            const CpaFlatBuffer *restrict pFbB)
{
    Cpa32U storageSizeDifference = 0;
    CpaBoolean buffersAreEqual = CPA_FALSE;

    if (pFbA->dataLenInBytes > pFbB->dataLenInBytes)
    {
        storageSizeDifference = pFbA->dataLenInBytes - pFbB->dataLenInBytes;
        /*If function returns true, the number in pFbA is greater than
          the number stored in pFbB*/
        if (CPA_FALSE ==
            checkLargerBufferStoresLargerValue(
                storageSizeDifference, pFbA, pFbB, &buffersAreEqual))
        {
            if (CPA_TRUE == buffersAreEqual)
            {
                /*pFbA stored value is equal to that of pFbB*/
                return CPA_FALSE;
            }
            else
            {
                /*pFbA stores a smaller value than pFbB*/
                return CPA_TRUE;
            }
        }
        else
        {
            /*pFbA stored value is greater than that of pFbB*/
            return CPA_FALSE;
        }
    }
    else
    {
        storageSizeDifference = pFbB->dataLenInBytes - pFbA->dataLenInBytes;
        /*if buffers are equal in this case, CPA_FALSE is returned*/
        return checkLargerBufferStoresLargerValue(
            storageSizeDifference, pFbB, pFbA, NULL);
    }
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
 *      none
 *****************************************************************************/
CpaBoolean isFlatBufValGreaterThanOrEqualTo32UVal(const CpaFlatBuffer *restrict
                                                      pFb,
                                                  Cpa32U val)
{
    CpaFlatBuffer smallBuf = {.dataLenInBytes = 0, .pData = NULL};
    Cpa8U valArray[WORD_BYTE_LEN_32U] = {
        0,
    };
    COPY_32_BIT_UNSIGNED_VAL_TO_4_BYTE_ARRAY(valArray, val);

    smallBuf.pData = valArray;
    smallBuf.dataLenInBytes = sizeof(valArray);

    /*'isFbALessThanFbB' returns false if buffers are equal*/
    if (CPA_TRUE == isFbALessThanFbB(pFb, &smallBuf))
    {
        return CPA_FALSE;
    }
    else
    {
        return CPA_TRUE;
    }
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      setResultStorageLocation
 *
 * @description
 *      Add/Subtract functions in this code base have been written to allow
 *      'in place' or 'out of place' operations. The former means an input
 *      buffer is overwritten. The latter means a third buffer has the
 *      result written to it. This function is what enables the choice.
 *      If pCheckTarget is not NULL (out of place operation), then
 *      'pCurrentTarget' is copied to 'pCheckTarget' and 'pResultTarget'
 *      CpaFlatBuffer values are set to those of 'pCheckTarget'. Otherwise
 *      'pResultTarget' CpaFlatBuffer values are set to those of
 *      'pCurrentTarget' (in place). It is expected that the calling function
 *      uses 'pResultTarget' in computing the result.
 *
 * @param[out] pResultTarget     The buffer that should be written to with
 *                               the result of the calling function.
 * @param[in,out] pCheckTarget   If this value is not NULL, pCurrentTarget is
 *                               copied to this buffer and pResultTarget
 *                               values are set equal to it.
 * @param[in]  pCurrentTarget    If pCheckTarget is NULL, pResultTarget
 *                               values are set equal to it.
 *
 * @retval none
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline void setResultStorageLocation(CpaFlatBuffer *pResultTarget,
                                            CpaFlatBuffer *pCheckTarget,
                                            const CpaFlatBuffer *restrict
                                                pCurrentTarget)
{

    if (NULL != pCheckTarget)
    {
        Cpa32U currentTargetDataLen = pCurrentTarget->dataLenInBytes -
                                      getOffsetToBufferedData(pCurrentTarget);
        if (pCheckTarget->pData != pCurrentTarget->pData)
        {
            if (pCheckTarget->dataLenInBytes < currentTargetDataLen)
            {
                PRINT_ERR("Attempt to set result with too small a buffer\n"
                          "pCheckTarget Size = %u,"
                          "pCurrentTarget Data Len = %u\n",
                          pCurrentTarget->dataLenInBytes,
                          currentTargetDataLen);
                return;
            }
            (void)memset(pCheckTarget->pData, 0, pCheckTarget->dataLenInBytes);

            (void)memcpy(
                pCheckTarget->pData +
                    (pCheckTarget->dataLenInBytes - currentTargetDataLen),
                pCurrentTarget->pData +
                    (pCurrentTarget->dataLenInBytes - currentTargetDataLen),
                currentTargetDataLen);
        }
        pResultTarget->pData = pCheckTarget->pData;
        pResultTarget->dataLenInBytes = pCheckTarget->dataLenInBytes;
    }
    else
    {
        pResultTarget->pData = pCurrentTarget->pData;
        pResultTarget->dataLenInBytes = pCurrentTarget->dataLenInBytes;
    }
    return;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      incrementByte
 *
 * @description
 *      Add two bytes together, return overflow if one occurs. Note max
 *      increment is 0xFF
 *
 * @param[in]  pByte         pointer to the byte to be incremented
 * @param[in]  increment     amount to be added
 *
 * @param[out] pByte         pointer to incremented byte
 *
 * @retval 1                 if there was an overflow from the addition
 *         0                 No overflow (result count fully be stored
 *                           in pByte.
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline Cpa8U incrementByte(Cpa8U *pByte, const Cpa8U increment)
{

    Cpa8U space = MAX_BYTE_VALUE - *pByte;

    if (space >= increment)
    {
        *pByte += increment;
        return 0;
    }
    else
    {
        *pByte = increment - (space + 1);
        return 1;
    }
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
                                Cpa8U increment)
{

    Cpa8U carry = increment;
    Cpa32S loop_counter = 0;
    CpaFlatBuffer target = {.dataLenInBytes = 0, .pData = NULL};

    if (0 == increment)
    {
        return CPA_STATUS_SUCCESS;
    }
    if (0 == pCurrentTarget->dataLenInBytes)
    {
        PRINT_ERR("zero length source buffer\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    setResultStorageLocation(&target, pCheckTarget, pCurrentTarget);

    for (loop_counter = target.dataLenInBytes - 1; loop_counter >= 0;
         loop_counter--)
    {
        if (0 != carry)
        {
            carry = incrementByte(&(target.pData[loop_counter]), carry);
        }
        else
        {
            break;
        }
    }
    if (0 != carry)
    {
        /*overflow*/
        PRINT_ERR("overflow - carry not zero\n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

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
                                 Cpa32U increment)
{
    CpaFlatBuffer smallBuf = {.dataLenInBytes = 0, .pData = NULL};
    Cpa8U valArray[WORD_BYTE_LEN_32U] = {
        0,
    };

    if (0 == increment)
    {
        return CPA_STATUS_SUCCESS;
    }

    COPY_32_BIT_UNSIGNED_VAL_TO_4_BYTE_ARRAY(valArray, increment);
    smallBuf.pData = valArray;
    smallBuf.dataLenInBytes = sizeof(valArray);

    return addFlatBuffer(pCheckTarget, pCurrentTarget, &smallBuf);
}

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
                        CpaFlatBuffer *pFbIncrement)
{

    Cpa32S i = 0;
    CpaFlatBuffer target = {.dataLenInBytes = 0, .pData = NULL};
    CpaStatus status = CPA_STATUS_SUCCESS;


    setResultStorageLocation(&target, pCheckTarget, pCurrentTarget);


    for (i = pFbIncrement->dataLenInBytes - 1; i >= 0; i--)
    {
        status = incrementFlatBuffer8U(NULL, &target, pFbIncrement->pData[i]);
        if (CPA_STATUS_FAIL == status)
        {
            /*overflow*/
            PRINT_ERR("Overflow during addition\n");
            return CPA_STATUS_FAIL;
        }
        else if (CPA_STATUS_INVALID_PARAM == status)
        {
            /*overflow*/
            PRINT_ERR("Error - zero size result buffer\n");
            return CPA_STATUS_FAIL;
        }
        target.dataLenInBytes--;
    }
    return CPA_STATUS_SUCCESS;
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
                          const Cpa8U multiplier)
{
    Cpa32S i = 0;

    if (NULL == pTarget)
    {
        PRINT_ERR("Multiply result buffer is NULL!\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    for (i = 0; i < multiplier; i++)
    {
        if (CPA_STATUS_SUCCESS != addFlatBuffer(NULL, pTarget, pSource))
        {
            PRINT_ERR("Overflow during multiplication\n");
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

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
                        const CpaFlatBuffer *restrict pFb2)
{

    Cpa32S i = 0, lastByte = 0;
    Cpa32U largeValDataOffset = 0;
    Cpa32U smallValDataOffset = 0;
    Cpa32U storedResultLen = pTarget->dataLenInBytes;
    Cpa32U mulResultLen = 0;
    CpaFlatBuffer intermediateVal = {.dataLenInBytes = 0, .pData = NULL};
    const CpaFlatBuffer *restrict pLargerValueBuffer = pFb1;
    const CpaFlatBuffer *restrict pSmallerValueBuffer = pFb2;

    /*Intermediate data buffer must be equal to the sum of the two buffer
      sizes*/
    Cpa8U intermediateValueData[pFb1->dataLenInBytes + pFb2->dataLenInBytes];

    if (0 == pTarget->dataLenInBytes)
    {
        PRINT_ERR("result buffer has no length\n");
        return CPA_STATUS_FAIL;
    }

    (void)memset(intermediateValueData, 0, sizeof(intermediateValueData));
    intermediateVal.dataLenInBytes = sizeof(intermediateValueData);
    intermediateVal.pData = intermediateValueData;

    (void)memset(pTarget->pData, 0, pTarget->dataLenInBytes);

    /*Check larger number*/
    if (CPA_TRUE == isFbALessThanFbB(pFb1, pFb2))
    {
        PRINT_DBG("Fb2 greater than Fb1\n");
        pLargerValueBuffer = pFb2;
        pSmallerValueBuffer = pFb1;
    }

    /*Get offsets into the buffer*/
    largeValDataOffset = getOffsetToBufferedData(pLargerValueBuffer);
    smallValDataOffset = getOffsetToBufferedData(pSmallerValueBuffer);

    PRINT_DBG("OFFSETS: larger = %d, smaller = %d\n",
              largeValDataOffset,
              smallValDataOffset);

    /*Check whether the stored number is zero (offset to data == buffer len*/
    if ((largeValDataOffset == pLargerValueBuffer->dataLenInBytes - 1) ||
        (smallValDataOffset == pSmallerValueBuffer->dataLenInBytes - 1))
    {
        PRINT_DBG("Warning, number in buffer == 0\n");
        return CPA_STATUS_SUCCESS;
    }
    else if ((largeValDataOffset > pLargerValueBuffer->dataLenInBytes - 1) ||
             (smallValDataOffset > pSmallerValueBuffer->dataLenInBytes - 1))
    {
        PRINT_ERR("Number size calculation error\n");
        return CPA_STATUS_FAIL;
    }

    mulResultLen = pLargerValueBuffer->dataLenInBytes - largeValDataOffset +
                   pSmallerValueBuffer->dataLenInBytes - smallValDataOffset;

    if (pTarget->dataLenInBytes < mulResultLen)
    {
        PRINT_ERR("pTarget buffer too small, %d (len must be at least %d)\n",
                  pTarget->dataLenInBytes,
                  mulResultLen);
        return CPA_STATUS_FAIL;
    }

    /*Copy value to top of buffer, as a shifting operation is employed to do
      the multiplication*/
    (void)memcpy(intermediateVal.pData,
                 pLargerValueBuffer->pData + largeValDataOffset,
                 pLargerValueBuffer->dataLenInBytes - largeValDataOffset);

    intermediateVal.dataLenInBytes =
        pLargerValueBuffer->dataLenInBytes - largeValDataOffset;

    lastByte = pSmallerValueBuffer->dataLenInBytes - 1;
    /*Calculate the result*/
    for (i = 0; i < pSmallerValueBuffer->dataLenInBytes; i++)
    {
        if (pSmallerValueBuffer->pData[lastByte - i] != 0)
        {
            if (CPA_STATUS_SUCCESS !=
                mulFlatBuffer8U(pTarget,
                                &intermediateVal,
                                pSmallerValueBuffer->pData[lastByte - i]))
            {
                return CPA_STATUS_FAIL;
            }
        }
        /*next round of additions added to 'pLargerValueBuffer'
          shifted right by 1 byte*/
        intermediateVal.dataLenInBytes++;
    }

    pTarget->dataLenInBytes = storedResultLen;
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      decrementByte
 *
 * @description
 *      Subtract one byte from another. Return 1 if underflow occurs.
 *      If underflow occurs, byte is set to the amount of underflow from
 *      0x100.
 *
 * @param[in]  pByte       Byte to be subtracted from
 * @param[in]  decrement   Amount to be decremented
 *
 * @param[out] pByte       Value after subtraction
 *
 * @retval     1           decrement was greater than *pByte
 *             0           decrement was less than *pByte
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
static inline Cpa8U decrementByte(Cpa8U *pByte, Cpa8U decrement)
{

    if (0 == decrement)
    {
        return 0;
    }

    if (decrement <= *pByte)
    {
        *pByte -= decrement;
        return 0;
    }
    else
    { /*decrement > pByte*/
        /*functionally it is 0x0100 - decrement + byte*/
        *pByte = (MAX_BYTE_VALUE - (decrement - 1)) + *pByte;
        return 1;
    }
}

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
 * @retval CPA_STATUS_SUCCESS    'decrement' has been subtracted successfully
 *         CPA_STATUS_FAIL       'decrement' is larger than the stored number
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus decrementFlatBuffer8U(CpaFlatBuffer *pCheckTarget,
                                CpaFlatBuffer *pCurrentTarget,
                                Cpa8U decrement)
{
    Cpa32S i = 0;
    Cpa8U carry = decrement;
    CpaFlatBuffer target = {.dataLenInBytes = 0, .pData = NULL};

    /*copy data to the result target if necessary*/
    setResultStorageLocation(&target, pCheckTarget, pCurrentTarget);

    if (0 == decrement)
    {
        return CPA_STATUS_SUCCESS;
    }

    for (i = target.dataLenInBytes - 1; i >= 0; i--)
    {
        /*'carry' result can be anything less than 0x100.
         It is returned if 'carry' is greater than the 'target.pData[i] byte*/
        carry = decrementByte(&(target.pData[i]), carry);

        if (0 == carry)
        {
            return CPA_STATUS_SUCCESS;
        }
    }
    /*carry is non zero, so the result is negative (this is not supported)*/
    return CPA_STATUS_FAIL;
}

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
                                 Cpa32U decrement)
{
    CpaFlatBuffer smallbuff = {.dataLenInBytes = 0, .pData = NULL};
    Cpa8U val_array[WORD_BYTE_LEN_32U] = {
        0,
    };

    if (0 == decrement)
    {
        return CPA_STATUS_SUCCESS;
    }
    COPY_32_BIT_UNSIGNED_VAL_TO_4_BYTE_ARRAY(val_array, decrement);
    smallbuff.pData = val_array;
    smallbuff.dataLenInBytes = sizeof(val_array);

    return subFlatBuffer(pCheckTarget, pCurrentTarget, &smallbuff);
}

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
                        CpaFlatBuffer *pFbDecrement)
{

    Cpa32S i = 0;
    CpaFlatBuffer target = {.dataLenInBytes = 0, .pData = NULL};
    Cpa32U fBDecrementDataOffset = getOffsetToBufferedData(pFbDecrement);
    Cpa32U currentTargetDataOffset = getOffsetToBufferedData(pCurrentTarget);
    Cpa32U fBDecrementDataLen =
        pFbDecrement->dataLenInBytes - fBDecrementDataOffset;
    Cpa32U currentTargetDataLen =
        pCurrentTarget->dataLenInBytes - currentTargetDataOffset;

    pCurrentTarget->pData += currentTargetDataOffset;
    pCurrentTarget->dataLenInBytes -= currentTargetDataOffset;

    pFbDecrement->pData += fBDecrementDataOffset;
    pFbDecrement->dataLenInBytes -= fBDecrementDataOffset;

    if (CPA_TRUE != isFbALessThanFbB(pFbDecrement, pCurrentTarget))
    {
        /*Have to check if buffers are equal*/
        CpaBoolean buffersAreEqual = CPA_FALSE;

        if (fBDecrementDataLen == currentTargetDataLen)
        {
            for (i = 0; i < fBDecrementDataLen; i++)
            {
                if (pCurrentTarget->pData[i] < pFbDecrement->pData[i])
                {
                    buffersAreEqual = CPA_FALSE;
                    break;
                }
            }
        }
        else if (fBDecrementDataLen > currentTargetDataLen)
        {
            buffersAreEqual = CPA_FALSE;
        }
        else
        {
            buffersAreEqual = CPA_TRUE;
        }

        if (CPA_TRUE != buffersAreEqual)
        {
            PRINT_ERR("subFlatBuffer Fail - pCurrentTarget < pFbDecrement\n");
            pCurrentTarget->pData -= currentTargetDataOffset;
            pCurrentTarget->dataLenInBytes += currentTargetDataOffset;

            pFbDecrement->pData -= fBDecrementDataOffset;
            pFbDecrement->dataLenInBytes += fBDecrementDataOffset;
            return CPA_STATUS_FAIL;
        }
    }
    setResultStorageLocation(&target, pCheckTarget, pCurrentTarget);

    if (1 == pFbDecrement->dataLenInBytes)
    {
        return decrementFlatBuffer8U(NULL, &target, pFbDecrement->pData[0]);
    }
    for (i = pFbDecrement->dataLenInBytes - 1; i >= 0; i--)
    {
        if (0 != pFbDecrement->pData[i])
        {
            if (CPA_STATUS_FAIL ==
                decrementFlatBuffer8U(NULL, &target, pFbDecrement->pData[i]))
            {
                /*underflow*/
                pCurrentTarget->pData -= currentTargetDataOffset;
                pCurrentTarget->dataLenInBytes += currentTargetDataOffset;

                pFbDecrement->pData -= fBDecrementDataOffset;
                pFbDecrement->dataLenInBytes += fBDecrementDataOffset;
                return CPA_STATUS_FAIL;
            }
        }
        target.dataLenInBytes--;
        if (0 == target.dataLenInBytes)
        {
            break;
        }
    }
    pCurrentTarget->pData -= currentTargetDataOffset;
    pCurrentTarget->dataLenInBytes += currentTargetDataOffset;

    pFbDecrement->pData -= fBDecrementDataOffset;
    pFbDecrement->dataLenInBytes += fBDecrementDataOffset;

    return CPA_STATUS_SUCCESS;
}

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
CpaStatus fipsSampleGetQaInstance(CpaInstanceHandle *pInstanceHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U num_inst = 0;
    Cpa16U instance_idx = 0;

    CpaInstanceHandle pCyInsts[MAX_SUPPORTED_QA_INSTANCES] = {0};

    status = cpaCyGetNumInstances(&num_inst);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error getting number of instances\n");
        return CPA_STATUS_FAIL;
    }

    if (0 == num_inst)
    {
        PRINT_ERR("Num Instances is zero\n");
        return CPA_STATUS_FAIL;
    }

    status = cpaCyGetInstances(num_inst, pCyInsts);
    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }

    *pInstanceHandle = pCyInsts[instance_idx];

    status = cpaCySetAddressTranslation(*pInstanceHandle,
                                        (CpaVirtualToPhysical)osVirtToPhysNuma);

    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error setting memory config for instance %d\n",
                  instance_idx);
        return CPA_STATUS_FAIL;
    }

    status = cpaCyStartInstance(*pInstanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Start Instance Fail \n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

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
CpaStatus fipsSampleStopQAinstance(CpaInstanceHandle instanceHandle)
{

    if (CPA_STATUS_SUCCESS != cpaCyStopInstance(instanceHandle))
    {
        PRINT_ERR("Stop Instance Fail \n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

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
CpaStatus getTrueRandomBytes(CpaFlatBuffer *pBuffer, Cpa32U length)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaCyNrbgOpData nrbgOpData = {.lengthInBytes = 0};

    if (pBuffer->dataLenInBytes < length)
    {
        PRINT_ERR("Requested random bytes length is larger than the buffer"
                  " length \n");
        return CPA_STATUS_FAIL;
    }

    nrbgOpData.lengthInBytes = length;

    status = fipsSampleGetQaInstance(&instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("get QA instance fail\n");
        return CPA_STATUS_FAIL;
    }
    do
    {
        status = cpaCyNrbgGetEntropy(
            instanceHandle, NULL, NULL, &nrbgOpData, pBuffer);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Nrbg get entropy function Fail -- %s\n",
                      statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

finish:
    if (CPA_STATUS_SUCCESS != fipsSampleStopQAinstance(instanceHandle))
    {
        PRINT_ERR("NRBG stop QA instance Fail \n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("NRBG entropy Fail \n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

#ifndef CPM_LACKS_DRBG
/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getEntropyInputFunc
 *
 * @description
 *      Function to give Entropy input to the Quick Assist Deterministic
 *      Random Bit Generator (DRBG). This is done through a call to the Quick
 *      Assist Non-Deterministic Random Bit Generator (NRBG). If the NRBG is
 *      not used, it may be possible to predict the output of the DRBG.
 *
 * @param[in]  pCb             Callback function. If NULL, the function just
 *                             exits after populating 'pBuffer'
 * @param[in]  pCallbackTag    Opaque data not touched by this function
 * @param[in]  pOpData         Contains information for generating the random
 *                             bits
 *
 * @param[out] pBuffer         This Buffer is populated with random data
 * @param[out] pLengthReturned Length of returned random data
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus getEntropyInputFunc(IcpSalDrbgGetEntropyInputCbFunc pCb,
                              void *pCallbackTag,
                              icp_sal_drbg_get_entropy_op_data_t *pOpData,
                              CpaFlatBuffer *pBuffer,
                              Cpa32U *pLengthReturned)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    *pLengthReturned = pOpData->maxLength;

    status = getTrueRandomBytes(pBuffer, pOpData->maxLength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("NRBG entropy Fail \n");
        return CPA_STATUS_FAIL;
    }

    if (NULL != pCb)
    {
        pCb(pCallbackTag,
            CPA_STATUS_SUCCESS,
            pOpData,
            pOpData->maxLength,
            pBuffer);
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      getNonceFunc
 *
 * @description
 *      This function is used to generate a random nonce for the Quick Assist
 *      Deterministic Random Bit Generator (DRBG).
 *
 * @param[in]  pOpData         Contains information for generating the random
 *                             bits
 *
 * @param[out] pBuffer         This Buffer is populated with random data
 * @param[out] pLengthReturned Length of returned random data
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
CpaStatus getNonceFunc(icp_sal_drbg_get_entropy_op_data_t *pOpData,
                       CpaFlatBuffer *pBuffer,
                       Cpa32U *pLengthReturned)
{

    CpaStatus status = CPA_STATUS_SUCCESS;

    status = getTrueRandomBytes(pBuffer, pOpData->maxLength);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("NRBG entropy Fail \n");
        return CPA_STATUS_FAIL;
    }
    *pLengthReturned = pOpData->maxLength;

    return CPA_STATUS_SUCCESS;
}

#endif

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      isDFReqFunc
 *
 * @description
 *      Returns whether a derivation function should be used for the Quick
 *      Assist Deterministic Random Number Generator.
 *
 *      Derivation functions are internal functions that are used during DRBG
 *      instantiation and reseeding to either derive internal state values or
 *      to distribute entropy throughout a bit string.
 *
 *      Derivation function use is not required for FIPS certification of PKE
 *      functionality.
 *
 * @retval CPA_FALSE    The use of a derivation function is not required for
 *                      FIPS sample code
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaBoolean isDFReqFunc(void)
{
    return CPA_FALSE;
}

#ifndef CPM_LACKS_DRBG
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
 * @retval CPA_STATUS_SUCCESS    Random bytes generated
 *         CPA_STATUS_FAIL       Random bytes could not be generated
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus generateRandomBytes(CpaFlatBuffer *pRandBuf,
                              Cpa32U len,
                              CpaCyDrbgSecStrength securityStrength,
                              const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };

    CpaCyDrbgSessionSetupData setupData = {
        .predictionResistanceRequired = CPA_FALSE,
        .secStrength = securityStrength,
        .personalizationString = {.dataLenInBytes = 0, .pData = NULL}};
    Cpa32U sessionSize = 0;
    Cpa32U seedLen = 0;
    CpaCyDrbgSessionHandle DRBGsessionHandle = NULL;
    CpaCyDrbgGenOpData opData = {
        .sessionHandle = NULL,
        .lengthInBytes = len,
        .secStrength = securityStrength,
        .predictionResistanceRequired = CPA_FALSE,
        .additionalInput = {.dataLenInBytes = 0, .pData = NULL}};

    IcpSalDrbgGetEntropyInputFunc pOldGetEntropyInputFunc = NULL;
    IcpSalDrbgGetNonceFunc pOldGetNonceFunc = NULL;
    IcpSalDrbgIsDFReqFunc pOldIsDFReqFunc = NULL;

    if (NULL == pRandBuf->pData)
    {
        PRINT_DBG("pRandBuf is NULL \n");
        return CPA_STATUS_FAIL;
    }

    pOldGetEntropyInputFunc = icp_sal_drbgGetEntropyInputFuncRegister(
        (IcpSalDrbgGetEntropyInputFunc)&getEntropyInputFunc);
    pOldGetNonceFunc =
        icp_sal_drbgGetNonceFuncRegister((IcpSalDrbgGetNonceFunc)&getNonceFunc);
    pOldIsDFReqFunc =
        icp_sal_drbgIsDFReqFuncRegister((IcpSalDrbgIsDFReqFunc)&isDFReqFunc);

    status = cpaCyDrbgSessionGetSize(instanceHandle, &setupData, &sessionSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DRBG Get SessionSize Fail \n");
        goto finish;
    }

    DRBGsessionHandle =
        (CpaCyDrbgSessionHandle *)osZalloc(sessionSize, instanceHandle);
    if (NULL == DRBGsessionHandle)
    {
        PRINT_DBG("DRBG Session handle alloc Fail \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    status = cpaCyDrbgInitSession(instanceHandle,
                                  NULL, /*generate callback*/
                                  NULL, /*reseed callback*/
                                  &setupData,
                                  DRBGsessionHandle,
                                  &seedLen);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DRBG Init Session Fail \n");
        goto finish;
    }

    opData.sessionHandle = DRBGsessionHandle;

    do
    {
        status = cpaCyDrbgGen(instanceHandle,
                              NULL, /*callback tag*/
                              &opData,
                              pRandBuf);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Drbg Gen function Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DRBG Gen Fail \n");
        goto finish;
    }

finish:
    if (CPA_STATUS_SUCCESS !=
        cpaCyDrbgRemoveSession(instanceHandle, DRBGsessionHandle))
    {
        PRINT_ERR("DRBG Remove Session Fail \n");
    }
    /*Registering the old functions is not mandatory*/
    if (NULL != pOldGetEntropyInputFunc)
    {
        icp_sal_drbgGetEntropyInputFuncRegister(pOldGetEntropyInputFunc);
    }
    if (NULL != pOldGetNonceFunc)
    {
        icp_sal_drbgGetNonceFuncRegister(pOldGetNonceFunc);
    }
    if (NULL != pOldIsDFReqFunc)
    {
        icp_sal_drbgIsDFReqFuncRegister(pOldIsDFReqFunc);
    }
    osFree((Cpa8U **)&DRBGsessionHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        /*no need for more granularity*/
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}
#endif

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
                   const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaCyLnModExpOpData modExpOpData = {
        .modulus = {.dataLenInBytes = pModulus->dataLenInBytes,
                    .pData = pModulus->pData},
        .base = {.dataLenInBytes = pBase->dataLenInBytes,
                 .pData = pBase->pData},
        .exponent = {.dataLenInBytes = 0, .pData = NULL}};

    /*if exponent is NULL, set value to 1*/
    if (NULL == pExponent)
    {
        modExpOpData.exponent.pData = osZalloc(1, instanceHandle);
        if (NULL == modExpOpData.exponent.pData)
        {
            PRINT_ERR("internal exponent alloc fail \n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        *modExpOpData.exponent.pData = 1;
        modExpOpData.exponent.dataLenInBytes = 1;
    }
    else
    {
        modExpOpData.exponent.pData = pExponent->pData;
        modExpOpData.exponent.dataLenInBytes = pExponent->dataLenInBytes;
    }

    do
    {
        status = cpaCyLnModExp(instanceHandle,
                               NULL, /*callback function*/
                               NULL, /*callback tag*/
                               &modExpOpData,
                               pTarget);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("doModExp Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

finish:
    if (NULL == pExponent)
    {
        osFree(&modExpOpData.exponent.pData);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

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
                   const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    CpaCyLnModInvOpData modInvOpData = {
        .A = {.dataLenInBytes = pBase->dataLenInBytes, .pData = pBase->pData},
        .B = {.dataLenInBytes = pModulus->dataLenInBytes,
              .pData = pModulus->pData}};

    do
    {
        status = cpaCyLnModInv(instanceHandle,
                               NULL, /*callback function*/
                               NULL, /*callback tag*/
                               &modInvOpData,
                               pTarget);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Mod Inv Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            break;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

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
                             const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U nValueDataOffset = getOffsetToBufferedData(pNvalue);
    Cpa32U nValueDataLen =
        pNvalue->dataLenInBytes - getOffsetToBufferedData(pNvalue);
    CpaFlatBuffer nValue = {.dataLenInBytes = pNvalue->dataLenInBytes,
                            .pData = pNvalue->pData};
    CpaFlatBuffer randomBuff = {.dataLenInBytes = 0, .pData = NULL};

    /*Make sure the functions are dealing with the buffered value only*/
    nValue.dataLenInBytes -= nValueDataOffset;
    nValue.pData += nValueDataOffset;

    if (0 == nValue.dataLenInBytes)
    {
        PRINT_ERR("N len is zero Fail! \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    if (pTarget->dataLenInBytes < nValueDataLen)
    {
        PRINT_ERR("Target buffer is too small \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }
    /*Extra buffer added to offset the number generation bias
      caused by using the modulus operation. See FIPS 186-3 section
      B.4.1 for more information.*/
    randomBuff.pData =
        osZalloc(nValueDataLen + FIPS_OFFSET_MODULO_BIAS, instanceHandle);
    if (NULL == randomBuff.pData)
    {
        PRINT_ERR("Could not allocate memory for random buffer \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    randomBuff.dataLenInBytes = nValueDataLen;
    /* Set input data */
    status = generateRandomBytes(
        &randomBuff, nValue.dataLenInBytes, securityStrength, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("DRBG Gen Fail \n");
        goto finish;
    }
    randomBuff.pData[0] |= (0x80);
    status = doModExp(&randomBuff, /*Base*/
                      NULL, /*If this value is null, the function set it to 1*/
                      pNvalue, /*Modulus*/
                      pTarget, /*Result*/
                      instanceHandle);

finish:
    osFree(&randomBuff.pData);
    if (CPA_STATUS_SUCCESS != status)
    {
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

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
                         Cpa32U securityStrength)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa32U primeDataLen =
        pPrime->dataLenInBytes - getOffsetToBufferedData(pPrime);
    Cpa32U mrRoundSize = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };
    /*Initial settings are for a fast primality check*/
    CpaCyPrimeTestOpData primeOpData = {
        .primeCandidate = {.dataLenInBytes = pPrime->dataLenInBytes,
                           .pData = pPrime->pData},
        .performGcdTest = CPA_TRUE,
        .performFermatTest = CPA_TRUE,
        .numMillerRabinRounds = 0,
        .millerRabinRandomInput = {.dataLenInBytes = 0, .pData = NULL},
        .performLucasTest = CPA_FALSE};
    CpaFlatBuffer millerRabinRandBuf = {.dataLenInBytes = 0, .pData = NULL};

    CpaFlatBuffer tempBuf = {.dataLenInBytes = 0, .pData = NULL};
    Cpa32U i = 0;
    Cpa8U *pRandData = NULL;

    /*Initialize result to 'not prime'*/
    *pIsPrime = CPA_FALSE;

    if (MAX_MILLER_RABIN_ROUNDS < numMillerRabinRounds)
    {
        PRINT_ERR("Prime Test given an even number!!\n");
        return CPA_FALSE;
    }

    if (!(pPrime->pData[pPrime->dataLenInBytes - 1] & 1))
    {
        PRINT_ERR("Prime Test given an even number!!\n");
        /*pIsPrime is already set to CPA_FALSE;*/
        return CPA_STATUS_SUCCESS;
    }

    do
    {
        status = cpaCyPrimeTest(instanceHandle,
                                NULL, /*callback function*/
                                NULL, /*callback tag*/
                                &primeOpData,
                                pIsPrime);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Prime test Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Prime Test Execution Fail \n");
        return CPA_STATUS_FAIL;
    }
    if (CPA_TRUE != *pIsPrime)
    {
        return CPA_STATUS_SUCCESS;
    }

    /*Minimum buffer size for a Miller Rabin round is 64 bytes*/
    mrRoundSize = (primeDataLen < FIPS_SAMPLE_PRIME_MIN_MR_ROUND_SIZE)
                      ? FIPS_SAMPLE_PRIME_MIN_MR_ROUND_SIZE
                      : primeDataLen;

    millerRabinRandBuf.dataLenInBytes = mrRoundSize * numMillerRabinRounds;
    pRandData = osZalloc(millerRabinRandBuf.dataLenInBytes, instanceHandle);
    if (NULL == pRandData)
    {
        PRINT_ERR("Could not allocate pRandData\n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

    millerRabinRandBuf.pData = pRandData;
    tempBuf.pData = pRandData;
    tempBuf.dataLenInBytes = mrRoundSize;

    for (i = 0; i < numMillerRabinRounds; i++)
    {
        tempBuf.pData = pRandData + (tempBuf.dataLenInBytes * i);
        status = getRandomLessThanN(&tempBuf,
                                    pPrime,
                                    securityStrength, /* must match (L, N) */
                                    instanceHandle);
        if (tempBuf.pData >
            (pRandData + (tempBuf.dataLenInBytes * numMillerRabinRounds)))
        {

            PRINT_ERR("Buffer Overrun!! \n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Miller Rabin get rand bytes Fail \n");
            goto finish;
        }
    }
    /*Miller Rabin is followed by Lucas in the F/W*/
    primeOpData.primeCandidate.pData = pPrime->pData;
    primeOpData.primeCandidate.dataLenInBytes = pPrime->dataLenInBytes;
    primeOpData.performGcdTest = CPA_FALSE;
    primeOpData.performFermatTest = CPA_FALSE;
    primeOpData.numMillerRabinRounds = numMillerRabinRounds;
    primeOpData.millerRabinRandomInput.pData = millerRabinRandBuf.pData;
    primeOpData.millerRabinRandomInput.dataLenInBytes =
        millerRabinRandBuf.dataLenInBytes;
    /*Lucas prime test is not required for RSA prime check*/
    primeOpData.performLucasTest = performLucasTest;

    maxCyRetries = 0;
    do
    {
        status = cpaCyPrimeTest(instanceHandle,
                                NULL, /*callback function*/
                                NULL, /*callback tag*/
                                &primeOpData,
                                pIsPrime);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Prime test Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

finish:
    if (NULL != pRandData)
    {
        osFree(&pRandData);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Prime Test algorithm fail\n");
        *pIsPrime = CPA_FALSE;
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

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
                        const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U maxCyRetries = 0;
    Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
        0,
    };

    CpaCySymOpData symOpData = {.sessionCtx = NULL,
                                .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
                                .hashStartSrcOffsetInBytes = 0,
                                .messageLenToHashInBytes =
                                    pMesg->dataLenInBytes,
                                /*set later*/
                                .pDigestResult = NULL};
    CpaBufferList bufferList = {.pPrivateMetaData = NULL,
                                .numBuffers = 0,
                                .pBuffers = NULL,
                                .pUserData = NULL};
    CpaCySymSessionCtx *pSessionCtx = NULL;
    CpaBoolean VerifyResult = CPA_FALSE;

    pSessionSetupData->sessionPriority = CPA_CY_PRIORITY_NORMAL;

    status = symSessionInit(pSessionSetupData, &pSessionCtx, instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Session setup fail \n");
        goto finish;
    }
    /*We only ever need to used a single buffer in this code base, so the
      first argument to the 'symSetupBufferLists' function is always 1.
      In future, the number of buffers may need to be an argument to all
      functions using 'symSetupBufferLists'.*/
    status = symSetupBufferLists(1,
                                 &bufferList,
                                 NULL, /*pBufferListOutOfPlace,*/
                                 instanceHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Buffer List setup fail \n");
        goto finish;
    }
    bufferList.pBuffers = pMesg;

    /*setup Op Data*/
    symOpData.sessionCtx = pSessionCtx;

    if (NULL == pMesgDigestResult)
    {
        symOpData.pDigestResult = pMesg->pData;
    }
    else
    {
        symOpData.pDigestResult = pMesgDigestResult->pData;
    }

    do
    {
        status = cpaCySymPerformOp(instanceHandle,
                                   NULL, /*callback tag*/
                                   &symOpData,
                                   &bufferList,
                                   &bufferList,
                                   &VerifyResult);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("Hash Perform Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;
    } while ((CPA_STATUS_RETRY == status) &&
             FIPS_MAX_CY_RETRIES != maxCyRetries);

    /*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Hash verify process Fail \n");
        status = CPA_STATUS_FAIL;
    }

    if (CPA_TRUE != VerifyResult)
    {
        PRINT_ERR("Hash verify Fail \n");
        status = CPA_STATUS_FAIL;
    }

finish:
    if (CPA_STATUS_SUCCESS != symSessionRemove(instanceHandle, pSessionCtx))
    {
        PRINT_ERR("Hash session free Fail \n");
        /*no need for more granularity*/
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

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
                              const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U bufferMetaSize = 0;
    /*setup Buffer List*/
    status =
        cpaCyBufferListGetMetaSize(instanceHandle, numBuffers, &bufferMetaSize);

    if (bufferMetaSize == 0)
    {
        PRINT_DBG("Buf list meta space alloc not needed \n");
    }
    else
    {
        pBufferList->pPrivateMetaData =
            (void *)osZalloc(bufferMetaSize, instanceHandle);
        if (NULL == pBufferList->pPrivateMetaData)
        {
            PRINT_ERR("Allocation of Buffer Meta failed\n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }

        if (NULL != pBufferListOutOfPlace)
        {
            pBufferListOutOfPlace->pPrivateMetaData =
                (void *)osZalloc(bufferMetaSize, instanceHandle);
            if (NULL == pBufferListOutOfPlace->pPrivateMetaData)
            {
                PRINT_ERR("Allocation of Buffer Meta failed\n");
                status = CPA_STATUS_FAIL;
                goto finish;
            }
        }
    }
    /* Assign BufferList fields */
    pBufferList->numBuffers = numBuffers;
    if (NULL != pBufferListOutOfPlace)
    {
        pBufferListOutOfPlace->numBuffers = numBuffers;
    }

finish:
    if (CPA_STATUS_SUCCESS != status)
    {
        /*no need for more granularity*/
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

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
CpaStatus symSessionInit(const CpaCySymSessionSetupData *pSessionSetupData,
                         CpaCySymSessionCtx **ppSessionCtxIn,
                         const CpaInstanceHandle instanceHandle)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;

    status = cpaCySymSessionCtxGetSize(
        instanceHandle, pSessionSetupData, &sessionCtxSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Ctx Get Size Fail \n");
        goto finish;
    }
    if (sessionCtxSize == 0)
    {
        PRINT_DBG("Ctx alloc not needed \n");
    }
    else
    {
        *ppSessionCtxIn =
            (CpaCySymSessionCtx *)osZalloc(sessionCtxSize, instanceHandle);
        if (NULL == *ppSessionCtxIn)
        {
            PRINT_ERR("Ctx alloc Fail \n");
            status = CPA_STATUS_FAIL;
            goto finish;
        }
    }

    status = cpaCySymInitSession(
        instanceHandle, NULL, pSessionSetupData, *ppSessionCtxIn);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Init Session Fail \n");
        status = CPA_STATUS_FAIL;
        goto finish;
    }

finish:
    if (CPA_STATUS_SUCCESS != status)
    {
        osFree((Cpa8U **)ppSessionCtxIn);
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      symSessionRemove
 *
 * @description
 *      Wait for in-flight request and removes a Symmetric Crypto
 *      Session using the Quick Assist AP, free allocated memory.
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
                           CpaCySymSessionCtx *pSessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#if CY_API_VERSION_AT_LEAST(2, 2)
    /* Wait for in-flight requests before removing session */
    CpaBoolean sessionInUse = CPA_FALSE;

    do
    {
        cpaCySymSessionInUse(pSessionCtx, &sessionInUse);
    } while (sessionInUse);
#endif

    /* Free up resources allocated */
    status = cpaCySymRemoveSession(instanceHandle, pSessionCtx);

    osFree((Cpa8U **)&pSessionCtx);

    return status;
}
