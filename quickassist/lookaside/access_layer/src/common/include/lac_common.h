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
 * @file lac_common.h Common macros
 *
 * @defgroup  Lac   Look Aside Crypto LLD Doc
 *
 *****************************************************************************/


/**
 *****************************************************************************
 * @defgroup  LacCommon   LAC Common
 * Common code for Lac which includes init/shutdown, memory, logging and
 * hooks.
 *
 * @ingroup Lac
 *
 *****************************************************************************/

/***************************************************************************/

#ifndef LAC_COMMON_H
#define LAC_COMMON_H

/*
******************************************************************************
* Include public/global header files
******************************************************************************
*/

#include "cpa.h"
#include "lac_log.h"
#include "cpa_cy_common.h"
#include "icp_adf_init.h"
#include "Osal.h"

#ifndef ICP_KERNEL64_USER32
#ifdef __x86_64__
#define LAC_ARCH_UINT Cpa64U
#define LAC_ARCH_INT Cpa64S
#else
#define LAC_ARCH_UINT Cpa32U
#define LAC_ARCH_INT Cpa32S
#endif
#else /* ICP_KERNEL64_USER32 */

#ifdef USER_SPACE
#define LAC_ARCH_UINT Cpa32U
#define LAC_ARCH_INT Cpa32S
#else
#define LAC_ARCH_UINT Cpa64U
#define LAC_ARCH_INT Cpa64S
#endif

#endif
/*
*****************************************************************************
*  Max range values for some primitive param checking
*****************************************************************************
*/

/**< Maximum number of instances */
#define SAL_MAX_NUM_INSTANCES_PER_DEV 512

#define SAL_DEFAULT_RING_SIZE 256
/**<  Default ring size */

#define SAL_64_CONCURR_REQUESTS 64
#define SAL_128_CONCURR_REQUESTS 128
#define SAL_256_CONCURR_REQUESTS 256
#define SAL_512_CONCURR_REQUESTS 512
#define SAL_1024_CONCURR_REQUESTS 1024
#define SAL_2048_CONCURR_REQUESTS 2048
#define SAL_4096_CONCURR_REQUESTS 4096
#define SAL_MAX_CONCURR_REQUESTS 65536
/**< Valid options for the num of concurrent requests per ring pair read
     from the config file. These values are used to size the rings */

#define SAL_BATCH_SUBMIT_FREE_SPACE 2
/**< For data plane batch submissions ADF leaves 2 spaces free on the ring */

/*
******************************************************************************
* Some common settings for QA API queries
******************************************************************************
*/

#define SAL_INFO2_VENDOR_NAME "Intel(R)"
/**< @ingroup LacCommon
 * Name of vendor of this driver  */
#define SAL_INFO2_PART_NAME "%s with Intel(R) QuickAssist Technology"
/**< @ingroup LacCommon
 */

/*
********************************************************************************
* User process name defines and functions
********************************************************************************
*/

#define LAC_USER_PROCESS_NAME_MAX_LEN 32
/**< @ingroup LacCommon
 * Max length of user process name */

#define LAC_KERNEL_PROCESS_NAME "KERNEL_QAT"
/**< @ingroup LacCommon
 * Default name for kernel process */

/*
********************************************************************************
* response mode indicator from Config file
********************************************************************************
*/

#define SAL_RESP_POLL_CFG_FILE 1
#define SAL_RESP_EPOLL_CFG_FILE 2

/*
 * @ingroup LacCommon
 * @description
 *      This function sets the process name
 *
 * @context
 *      This functions is called from module_init or from user space process
 *      initialization function
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      No
 *
 * param[in]  processName    Process name to be set
 */
CpaStatus icpSetProcessName(const char *processName);

/*
 * @ingroup LacCommon
 * @description
 *      This function gets the process name
 *
 * @context
 *      This functions is called from LAC context
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 */
char *icpGetProcessName(void);

/* Sections of the config file */
#define LAC_CFG_SECTION_GENERAL "GENERAL"
#define LAC_CFG_SECTION_INTERNAL "INTERNAL"

/*
********************************************************************************
* Debug Macros and settings
********************************************************************************
*/

/* DEBUG  */
#ifdef ICP_DEBUG
#undef STATIC
#undef INLINE

#define STATIC
/**< @ingroup LacCommon
 * When DEBUG is set STATIC evaluates to nothing. */

#define INLINE
/**< @ingroup LacCommon
 * When DEBUG is set INLINE evaluates to nothing. */

#else

#define STATIC static
/**< @ingroup LacCommon
 * otherwise it evaluates to the static keyword */

#define INLINE inline
/**< @ingroup LacCommon
 * otherwise it evaluates to the inline keyword */

#endif

#define SEPARATOR "+--------------------------------------------------+\n"
/**< @ingroup LacCommon
 * seperator used for printing stats to standard output*/

#define BORDER "|"
/**< @ingroup LacCommon
 * seperator used for printing stats to standard output*/

/**
*****************************************************************************
* @ingroup LacCommon
*      Component state
*
* @description
*      This enum is used to indicate the state that the component is in. Its
*      purpose is to prevent components from being initialised or shutdown
*      incorrectly.
*
*****************************************************************************/
typedef enum
{
    LAC_COMP_SHUT_DOWN = 0,
    /**< Component in the Shut Down state */
    LAC_COMP_SHUTTING_DOWN,
    /**< Component in the Process of Shutting down */
    LAC_COMP_INITIALISING,
    /**< Component in the Process of being initialised */
    LAC_COMP_INITIALISED,
    /**< Component in the initialised state */
} lac_comp_state_t;

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks if a parameter is NULL
 *
 * @param[in] param                 Parameter
 *
 * @return CPA_STATUS_INVALID_PARAM Parameter is NULL
 * @return void                     Parameter is not NULL
 ******************************************************************************/
#define LAC_CHECK_NULL_PARAM(param)                                            \
    do                                                                         \
    {                                                                          \
        if (NULL == (param))                                                   \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#param " is NULL");                          \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks if a parameter is within a specified range
 *
 * @param[in] param                 Parameter
 * @param[in] min                   Parameter must be greater than OR equal to
 *min
 * @param[in] max                   Parameter must be less than max
 *
 * @return CPA_STATUS_INVALID_PARAM Parameter is outside range
 * @return void                     Parameter is within range
 ******************************************************************************/
#define LAC_CHECK_PARAM_RANGE(param, min, max)                                 \
    do                                                                         \
    {                                                                          \
        if (((param) < (min)) || ((param) >= (max)))                           \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#param " is outside valid range");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This assert checks if an param is zero.
 *      This will be compiled out for non debug releases
 *
 ******************************************************************************/
#define LAC_ASSERT_NOT_ZERO(param)                                             \
    LAC_ASSERT((0 == (param)), "Parameter " #param " is not zero.\n")

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This checks if a param is 8 byte aligned.
 *
 ******************************************************************************/
#define LAC_CHECK_8_BYTE_ALIGNMENT(param)                                      \
    do                                                                         \
    {                                                                          \
        if ((Cpa64U)param % 8 != 0)                                            \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#param " is NOT 8 byte ALIGNED");            \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This checks if a parameter is 16 byte aligned.
 *
 ******************************************************************************/
#define LAC_CHECK_16_BYTE_ALIGNMENT(param)                                     \
    do                                                                         \
    {                                                                          \
        if ((Cpa64U)param % 16 != 0)                                           \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#param " is NOT 16 byte ALIGNED");           \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This checks if a param is 64 byte aligned.
 *
 ******************************************************************************/
#define LAC_CHECK_64_BYTE_ALIGNMENT(param)                                     \
    do                                                                         \
    {                                                                          \
        if ((LAC_ARCH_UINT)param % 64 != 0)                                    \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#param " is NOT 64byte ALIGNED");            \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This checks if a statement is true
 *
 ******************************************************************************/
#define LAC_CHECK_STATEMENT(param)                                             \
    do                                                                         \
    {                                                                          \
        if ((param))                                                           \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#param " is invalid");                       \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This checks if a statement is true.
 *
 ******************************************************************************/
#define LAC_CHECK_STATEMENT_LOG(param, log, ...)                               \
    do                                                                         \
    {                                                                          \
        if ((param))                                                           \
        {                                                                      \
            LAC_LOG_ERROR_PARAMS(log, __VA_ARGS__);                            \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This assert checks if a param is set to be Lite.
 *      This will be compiled out for non debug releases
 *
 ******************************************************************************/
#define LAC_ASSERT_LITE(param)                                                 \
    LAC_ASSERT((CPA_TRUE == (param)),                                          \
               "Parameter " #param " is not set to be Lite.\n")

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro returns the size of the buffer list structure given the
 *      number of elements in the buffer list - note: only the sizeof the
 *      buffer list structure is returned.
 *
 * @param[in] numBuffers    The number of flatbuffers in a buffer list
 *
 * @return size of the buffer list structure
 ******************************************************************************/
#define LAC_BUFFER_LIST_SIZE_GET(numBuffers)                                   \
    (sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer)))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks that a flatbuffer is valid i.e. that it is not
 *      null and the data it points to is not null
 *
 * @param[in] pFlatBuffer           Pointer to flatbuffer
 *
 * @return CPA_STATUS_INVALID_PARAM Invalid flatbuffer pointer
 * @return void                     flatbuffer is ok
 ******************************************************************************/
#define LAC_CHECK_FLAT_BUFFER(pFlatBuffer)                                     \
    do                                                                         \
    {                                                                          \
        LAC_CHECK_NULL_PARAM((pFlatBuffer));                                   \
        LAC_CHECK_NULL_PARAM((pFlatBuffer)->pData);                            \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *   This macro verifies that the status is ok i.e. equal to CPA_STATUS_SUCCESS
 *
 * @param[in] status    status we are checking
 *
 * @return void         status is ok (CPA_STATUS_SUCCESS)
 * @return status       The value in the status parameter is an error one
 *
 ******************************************************************************/
#define LAC_CHECK_STATUS(status)                                               \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != (status))                                    \
        {                                                                      \
            return status;                                                     \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *   This macro verifies that the status is ok i.e. equal to CPA_STATUS_SUCCESS
 *   and prints a message and returns if it is not equal.
 *
 * @param[in] status    status we are checking
 * @param[in] log       message to print if status is not CPA_STATUS_SUCCESS
 *
 * @return void         status is ok (CPA_STATUS_SUCCESS)
 * @return status       The value in the status parameter is an error one
 *
 ******************************************************************************/
#define LAC_CHECK_STATUS_LOG(status, log, ...)                                 \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != (status))                                    \
        {                                                                      \
            LAC_LOG_ERROR_PARAMS(log, __VA_ARGS__);                            \
            return status;                                                     \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro verifies that the Instance Handle is valid.
 *
 * @param[in] instanceHandle    Instance Handle
 *
 * @return CPA_STATUS_INVALID_PARAM Parameter is NULL
 * @return void                     Parameter is not NULL
 *
 ******************************************************************************/
#define LAC_CHECK_INSTANCE_HANDLE(instanceHandle)                              \
    do                                                                         \
    {                                                                          \
        if (NULL == (instanceHandle))                                          \
        {                                                                      \
            LAC_INVALID_PARAM_LOG(#instanceHandle " is NULL");                 \
            return CPA_STATUS_INVALID_PARAM;                                   \
        }                                                                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro verifies that the address translation routine is set up
 *      correctly for the given instance
 *
 * @param[in] instanceHandle    Instance Handle
 *
 * @return CPA_STATUS_FAIL          Address translation set up incorrectly
 * @return void                     Address translation set up correctly
 *
 ******************************************************************************/
#ifdef KERNEL_SPACE
#define SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle)
#else
#define SAL_CHECK_ADDR_TRANS_SETUP(instanceHandle)                             \
    do                                                                         \
    {                                                                          \
        sal_service_t *pGenericService = NULL;                                 \
        pGenericService = (sal_service_t *)instanceHandle;                     \
        if (NULL == pGenericService->virt2PhysClient)                          \
        {                                                                      \
            switch (pGenericService->type)                                     \
            {                                                                  \
                case SAL_SERVICE_TYPE_CRYPTO:                                  \
                    LAC_LOG_ERROR1(                                            \
                        "Address translation function not set for CY"          \
                        " instance %d",                                        \
                        pGenericService->instance);                            \
                    break;                                                     \
                case SAL_SERVICE_TYPE_COMPRESSION:                             \
                    LAC_LOG_ERROR1(                                            \
                        "Address translation function not set for DC"          \
                        " instance %d",                                        \
                        pGenericService->instance);                            \
                    break;                                                     \
                case SAL_SERVICE_TYPE_QAT:                                     \
                    LAC_LOG_ERROR1(                                            \
                        "Address translation function not set for QAT"         \
                        " instance %d",                                        \
                        pGenericService->instance);                            \
                    break;                                                     \
                case SAL_SERVICE_TYPE_UNKNOWN:                                 \
                default:                                                       \
                    LAC_LOG_ERROR1("Address translation function not set for"  \
                                   " unknown instance %d",                     \
                                   pGenericService->instance);                 \
                    break;                                                     \
            }                                                                  \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)
#endif

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro copies a string from one location to another
 *
 * @param[out] pDestinationBuffer   Pointer to destination buffer
 * @param[in] pSource               Pointer to source buffer
 *
 ******************************************************************************/
#define LAC_COPY_STRING(pDestinationBuffer, pSource)                           \
    do                                                                         \
    {                                                                          \
        memcpy(pDestinationBuffer, pSource, (sizeof(pSource) - 1));            \
        pDestinationBuffer[(sizeof(pSource) - 1)] = '\0';                      \
    } while (0)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro fills a memory zone with ZEROES
 *
 * @param[in] pBuffer               Pointer to buffer
 * @param[in] count                 Buffer length
 *
 * @return void
 *
 ******************************************************************************/
#define LAC_OS_BZERO(pBuffer, count) osalMemSet(pBuffer, 0, count);

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro calculates the position of the given member in a struct
 *      Only for use on a struct where all members are of equal size to map
 *      the struct member position to an array index
 *
 * @param[in] structType        the struct
 * @param[in] member            the member of the given struct
 *
 ******************************************************************************/
#define LAC_IDX_OF(structType, member)                                         \
    (offsetof(structType, member) / sizeof(((structType *)0)->member))

/*
********************************************************************************
* Alignment, Bid define and Bit Operation Macros
********************************************************************************
*/

#define LAC_BIT31_SET 0x80000000 /**< bit 31 == 1 */
#define LAC_BIT7_SET 0x80        /**< bit 7 == 1  */
#define LAC_BIT6_SET 0x40        /**< bit 6 == 1  */
#define LAC_BIT5_SET 0x20        /**< bit 5 == 1  */
#define LAC_BIT4_SET 0x10        /**< bit 4 == 1  */
#define LAC_BIT3_SET 0x08        /**< bit 3 == 1  */
#define LAC_BIT2_SET 0x04        /**< bit 2 == 1  */
#define LAC_BIT1_SET 0x02        /**< bit 1 == 1  */
#define LAC_BIT0_SET 0x01        /**< bit 0 == 1  */

#define LAC_NUM_BITS_IN_BYTE (8)
/**< @ingroup LacCommon
 * Number of bits in a byte */

#define LAC_LONG_WORD_IN_BYTES (4)
/**< @ingroup LacCommon
 * Number of bytes in an IA word */

#define LAC_QUAD_WORD_IN_BYTES (8)
/**< @ingroup LacCommon
 * Number of bytes in a QUAD word */

#define LAC_QAT_MAX_MSG_SZ_LW (32)
/**< @ingroup LacCommon
 * Maximum size in Long Words for a QAT message */

/**
*****************************************************************************
* @ingroup LacCommon
*      Alignment shift requirements of a buffer.
*
* @description
*      This enum is used to indicate the alignment shift of a buffer.
*      All alignments are to power of 2
*
*****************************************************************************/
typedef enum lac_aligment_shift_s
{
    LAC_NO_ALIGNMENT_SHIFT = 0,
    /**< No alignment shift (to a power of 2)*/
    LAC_8BYTE_ALIGNMENT_SHIFT = 3,
    /**< 8 byte alignment shift (to a power of 2)*/
    LAC_16BYTE_ALIGNMENT_SHIFT = 4,
    /**< 16 byte alignment shift (to a power of 2)*/
    LAC_64BYTE_ALIGNMENT_SHIFT = 6,
    /**< 64 byte alignment shift (to a power of 2)*/
    LAC_4KBYTE_ALIGNMENT_SHIFT = 12,
    /**< 4k byte alignment shift (to a power of 2)*/
} lac_aligment_shift_t;

/**
*****************************************************************************
* @ingroup LacCommon
*      Alignment of a buffer.
*
* @description
*      This enum is used to indicate the alignment requirements of a buffer.
*
*****************************************************************************/
typedef enum lac_aligment_s
{
    LAC_NO_ALIGNMENT = 0,
    /**< No alignment */
    LAC_1BYTE_ALIGNMENT = 1,
    /**< 1 byte alignment */
    LAC_8BYTE_ALIGNMENT = 8,
    /**< 8 byte alignment*/
    LAC_64BYTE_ALIGNMENT = 64,
    /**< 64 byte alignment*/
    LAC_4KBYTE_ALIGNMENT = 4096,
    /**< 4k byte alignment */
} lac_aligment_t;

/**
*****************************************************************************
* @ingroup LacCommon
*      Size of a buffer.
*
* @description
*      This enum is used to indicate the required size.
*      The buffer must be a multiple of the required size.
*
*****************************************************************************/
typedef enum lac_expected_size_s
{
    LAC_NO_LENGTH_REQUIREMENTS = 0,
    /**< No requirement for size */
    LAC_4KBYTE_MULTIPLE_REQUIRED = 4096,
    /**< 4k multiple requirement for size */
} lac_expected_size_t;

#define LAC_OPTIMAL_ALIGNMENT_SHIFT LAC_64BYTE_ALIGNMENT_SHIFT
/**< @ingroup LacCommon
 * optimal alignment to a power of 2 */

#define LAC_SHIFT_8 (1 << LAC_8BYTE_ALIGNMENT_SHIFT)
/**< shift by 8 bits  */
#define LAC_SHIFT_24                                                           \
    ((1 << LAC_8BYTE_ALIGNMENT_SHIFT) + (1 << LAC_16BYTE_ALIGNMENT_SHIFT))
/**< shift by 24 bits */

#define LAC_MAX_16_BIT_VALUE ((1 << 16) - 1)
/**< @ingroup LacCommon
 * maximum value a 16 bit type can hold */

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro can be used to avoid an unused variable warning from the
 *      compiler
 *
 * @param[in] variable  unused variable
 *
 ******************************************************************************/
#define LAC_UNUSED_VARIABLE(x) (void)(x)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks if an address is aligned to the specified power of 2
 *      Returns 0 if alignment is ok, or non-zero otherwise
 *
 * @param[in] address   the address we are checking
 *
 * @param[in] alignment the byte alignment to check (specified as power of 2)
 *
 ******************************************************************************/
#define LAC_ADDRESS_ALIGNED(address, alignment)                                \
    (!((LAC_ARCH_UINT)(address) & ((1 << (alignment)) - 1)))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro rounds up a number to a be a multiple of the alignment when
 *      the alignment is a power of 2.
 *
 * @param[in] num   Number
 * @param[in] align Alignment (must be a power of 2)
 *
 ******************************************************************************/
#define LAC_ALIGN_POW2_ROUNDUP(num, align) (((num) + (align)-1) & ~((align)-1))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro generates a bit mask to select a particular bit
 *
 * @param[in] bitPos    Bit position to select
 *
 ******************************************************************************/
#define LAC_BIT(bitPos) (0x1 << (bitPos))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro converts a size in bits to the equivalent size in bytes,
 *      using a bit shift to divide by 8
 *
 * @param[in] x     size in bits
 *
 ******************************************************************************/
#define LAC_BITS_TO_BYTES(x) ((x) >> 3)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro converts a size in bytes to the equivalent size in bits,
 *      using a bit shift to multiply by 8
 *
 * @param[in] x     size in bytes
 *
 ******************************************************************************/
#define LAC_BYTES_TO_BITS(x) ((x) << 3)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro converts a size in bytes to the equivalent size in longwords,
 *      using a bit shift to divide by 4
 *
 * @param[in] x     size in bytes
 *
 ******************************************************************************/
#define LAC_BYTES_TO_LONGWORDS(x) ((x) >> 2)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro converts a size in longwords to the equivalent size in bytes,
 *      using a bit shift to multiply by 4
 *
 * @param[in] x     size in long words
 *
 ******************************************************************************/
#define LAC_LONGWORDS_TO_BYTES(x) ((x) << 2)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro converts a size in bytes to the equivalent size in quadwords,
 *      using a bit shift to divide by 8
 *
 * @param[in] x     size in bytes
 *
 ******************************************************************************/
#define LAC_BYTES_TO_QUADWORDS(x) (((x) >> 3) + (((x) % 8) ? 1 : 0))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro converts a size in quadwords to the equivalent size in bytes,
 *      using a bit shift to multiply by 8
 *
 * @param[in] x     size in quad words
 *
 ******************************************************************************/
#define LAC_QUADWORDS_TO_BYTES(x) ((x) << 3)

/*
*******************************************************************************
* Assert Macros
*******************************************************************************
*/

/* LAC_ASSERT usage: call with a boolean condition and text to be logged if
 * that condition fails */

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks a condition and if the condition is false, logs an
 *      error message for debug releases but gets compiled out for non-debug
 *      releases
 * @note
 *      For debug releases osal needs to be compiled with OSAL_ENSURE_ON defined
 *
 * @param[in] condition     condition to check
 * @param[in] errorText     Text to printed if condition is false
 *
 ******************************************************************************/
#define LAC_ASSERT(condition, errorText) OSAL_ENSURE((condition), (errorText))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks a condition and if the condition is false, logs an
 *      error message for debug releases but gets compiled out for non-debug
 *      releases
 *
 * @param[in] condition     condition to check
 * @param[in] errorText     Text to printed if condition is false
 *
 ******************************************************************************/
#define LAC_ENSURE(condition, errorText) LAC_ASSERT((condition), (errorText))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks a condition and if the condition is false, logs an
 *      error message for debug releases and returns from current function
 *
 * @param[in] condition     condition to check
 * @param[in] errorText     Text to printed if condition is false
 *
 ******************************************************************************/
#define LAC_ENSURE_RETURN_VOID(condition, errorText)                           \
    OSAL_ENSURE_JUST_RETURN((condition), (errorText))

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This assert checks if an address is not null.
 *      This will be compiled out for non debug releases
 *
 * @param[in] address the address we are checking
 *
 ******************************************************************************/
#define LAC_ASSERT_NOT_NULL(address)                                           \
    LAC_ASSERT((NULL != (address)), "Parameter " #address " is null.\n")

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This assert checks if an address is not null.
 *      This will be compiled out for non debug releases
 *
 * @param[in] address the address we are checking
 *
 ******************************************************************************/
#define LAC_ENSURE_NOT_NULL(address) LAC_ASSERT_NOT_NULL(address)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks if a parameter is within a specified range
 *
 * @param[in] param                 Parameter
 * @param[in] min                   Parameter must be greater than OR equal to
 *min
 * @param[in] max                   Parameter must be less than max
 *
 ******************************************************************************/
#define LAC_ENSURE_RANGE(param, min, max)                                      \
    LAC_ASSERT(((param >= (min)) && (param < (max))),                          \
               #param " is outside valid range\n")

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This assert checks if an address is quad word aligned and is not null.
 *      This will be compiled out for non debug releases
 *
 * @param[in] address the address we are checking
 *
 ******************************************************************************/
#define LAC_QAT_ALIGNED_ASSERT(address)                                        \
    LAC_ASSERT(((NULL != (address)) &&                                         \
                (LAC_ADDRESS_ALIGNED((address), LAC_8BYTE_ALIGNMENT_SHIFT))),  \
               "Parameter " #address " is not correctly aligned for QAT.\n")

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This assert checks if an address is quad word aligned and is not null.
 *      This will be compiled out for non debug releases
 *
 * @param[in] address the address we are checking
 *
 ******************************************************************************/
#define LAC_QAT_ALIGNED_ENSURE(address) LAC_QAT_ALIGNED_ASSERT(address)

/******************************************************************************/

/*
*******************************************************************************
* Mutex Macros
*******************************************************************************
*/

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro tries to acquire a mutex and returns the status
 *
 * @param[in] pLock             Pointer to Lock
 * @param[in] timeout           Timeout
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with Mutex
 ******************************************************************************/
#define LAC_LOCK_MUTEX(pLock, timeout)                                         \
    ((OSAL_SUCCESS != osalMutexLock((pLock), (timeout))) ? CPA_STATUS_RESOURCE \
                                                         : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro unlocks a mutex and returns the status
 *
 * @param[in] pLock             Pointer to Lock
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with Mutex
 ******************************************************************************/
#define LAC_UNLOCK_MUTEX(pLock)                                                \
    ((OSAL_SUCCESS != osalMutexUnlock((pLock))) ? CPA_STATUS_RESOURCE          \
                                                : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro initialises a mutex and returns the status
 *
 * @param[in] pLock             Pointer to Lock
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with Mutex
 ******************************************************************************/
#define LAC_INIT_MUTEX(pLock)                                                  \
    ((OSAL_SUCCESS != osalMutexInit((pLock))) ? CPA_STATUS_RESOURCE            \
                                              : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro destroys a mutex and returns the status
 *
 * @param[in] pLock             Pointer to Lock
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with Mutex
 ******************************************************************************/
#define LAC_DESTROY_MUTEX(pLock)                                               \
    ((OSAL_SUCCESS != osalMutexDestroy((pLock))) ? CPA_STATUS_RESOURCE         \
                                                 : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro calls a trylock on a mutex
 *
 * @param[in] pLock             Pointer to Lock
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with Mutex
 ******************************************************************************/
#define LAC_TRYLOCK_MUTEX(pLock)                                               \
    ((OSAL_SUCCESS != osalMutexTryLock((pLock), OSAL_WAIT_NONE))               \
         ? CPA_STATUS_RESOURCE                                                 \
         : CPA_STATUS_SUCCESS)

/*
*******************************************************************************
* Semaphore Macros
*******************************************************************************
*/

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro waits on a semaphore and returns the status
 *
 * @param[in] sid               The semaphore
 * @param[in] timeout           Timeout
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with semaphore
 ******************************************************************************/
#define LAC_WAIT_SEMAPHORE(sid, timeout)                                       \
    ((OSAL_SUCCESS != osalSemaphoreWait(&sid, (timeout)))                      \
         ? CPA_STATUS_RESOURCE                                                 \
         : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro checks a semaphore and returns the status
 *
 * @param[in] sid               The semaphore
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with semaphore
 ******************************************************************************/
#define LAC_CHECK_SEMAPHORE(sid)                                               \
    ((OSAL_SUCCESS != osalSemaphoreTryWait(&sid)) ? CPA_STATUS_RETRY           \
                                                  : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro post a semaphore and returns the status
 *
 * @param[in] sid               The semaphore
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with semaphore
 ******************************************************************************/
#define LAC_POST_SEMAPHORE(sid)                                                \
    ((OSAL_SUCCESS != osalSemaphorePost(&sid)) ? CPA_STATUS_RESOURCE           \
                                               : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro initialises a semaphore and returns the status
 *
 * @param[in] sid               The semaphore
 * @param[in] semValue          Initial semaphore value
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with semaphore
 ******************************************************************************/
#define LAC_INIT_SEMAPHORE(sid, semValue)                                      \
    ((OSAL_SUCCESS != osalSemaphoreInit(&sid, semValue)) ? CPA_STATUS_RESOURCE \
                                                         : CPA_STATUS_SUCCESS)

/**
 *******************************************************************************
 * @ingroup LacCommon
 *      This macro destroys a semaphore and returns the status
 *
 * @param[in] sid               The semaphore
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully.
 * @retval CPA_STATUS_RESOURCE  Error with semaphore
 ******************************************************************************/
#define LAC_DESTROY_SEMAPHORE(sid)                                             \
    ((OSAL_SUCCESS != osalSemaphoreDestroy(&sid)) ? CPA_STATUS_RESOURCE        \
                                                  : CPA_STATUS_SUCCESS)

/*
*******************************************************************************
* Spinlock Macros
*******************************************************************************
*/

#ifdef ENABLE_SPINLOCK
typedef OsalLock lac_lock_t;

#define LAC_SPINLOCK_INIT(lock)                                                \
    ((OSAL_SUCCESS != osalLockInit(lock, TYPE_IGNORE)) ? CPA_STATUS_RESOURCE   \
                                                       : CPA_STATUS_SUCCESS)
#define LAC_SPINLOCK(lock) (void)osalLockBh(lock)
#define LAC_SPINUNLOCK(lock) (void)osalUnlockBh(lock)
#define LAC_SPINLOCK_DESTROY(lock)

#else

typedef OsalMutex lac_lock_t;

#define LAC_SPINLOCK_INIT LAC_INIT_MUTEX
#define LAC_SPINLOCK(lock) LAC_LOCK_MUTEX(lock, OSAL_WAIT_FOREVER)
#define LAC_SPINUNLOCK LAC_UNLOCK_MUTEX
#define LAC_SPINLOCK_DESTROY(lock) LAC_DESTROY_MUTEX(lock)

#endif

#define LAC_CONST_PTR_CAST(castee) ((void *)(LAC_ARCH_UINT)(castee))
#define LAC_CONST_VOLATILE_PTR_CAST(castee) ((void *)(LAC_ARCH_UINT)(castee))

/* Type of ring */
#define SAL_RING_TYPE_NONE 0
#define SAL_RING_TYPE_A_SYM_HI 1
#define SAL_RING_TYPE_A_SYM_LO 2
#define SAL_RING_TYPE_A_ASYM 3
#define SAL_RING_TYPE_B_SYM_HI 4
#define SAL_RING_TYPE_B_SYM_LO 5
#define SAL_RING_TYPE_B_ASYM 6
#define SAL_RING_TYPE_DC 7
#define SAL_RING_TYPE_ADMIN 8
#define SAL_RING_TYPE_TRNG 9

/* Maps Ring Service to generic service type */
static inline icp_adf_ringInfoService_t lac_getRingType(int type)
{
    switch (type)
    {
        case SAL_RING_TYPE_NONE:
            return ICP_ADF_RING_SERVICE_0;
        case SAL_RING_TYPE_A_SYM_HI:
            return ICP_ADF_RING_SERVICE_1;
        case SAL_RING_TYPE_A_SYM_LO:
            return ICP_ADF_RING_SERVICE_2;
        case SAL_RING_TYPE_A_ASYM:
            return ICP_ADF_RING_SERVICE_3;
        case SAL_RING_TYPE_B_SYM_HI:
            return ICP_ADF_RING_SERVICE_4;
        case SAL_RING_TYPE_B_SYM_LO:
            return ICP_ADF_RING_SERVICE_5;
        case SAL_RING_TYPE_B_ASYM:
            return ICP_ADF_RING_SERVICE_6;
        case SAL_RING_TYPE_DC:
            return ICP_ADF_RING_SERVICE_7;
        case SAL_RING_TYPE_ADMIN:
            return ICP_ADF_RING_SERVICE_8;
        case SAL_RING_TYPE_TRNG:
            return ICP_ADF_RING_SERVICE_9;
        default:
            return ICP_ADF_RING_SERVICE_0;
    }
    return ICP_ADF_RING_SERVICE_0;
}

/* Maps generic service type to Ring Service type  */
static inline int lac_getServiceType(icp_adf_ringInfoService_t type)
{
    switch (type)
    {
        case ICP_ADF_RING_SERVICE_0:
            return SAL_RING_TYPE_NONE;
        case ICP_ADF_RING_SERVICE_1:
            return SAL_RING_TYPE_A_SYM_HI;
        case ICP_ADF_RING_SERVICE_2:
            return SAL_RING_TYPE_A_SYM_LO;
        case ICP_ADF_RING_SERVICE_3:
            return SAL_RING_TYPE_A_ASYM;
        case ICP_ADF_RING_SERVICE_4:
            return SAL_RING_TYPE_B_SYM_HI;
        case ICP_ADF_RING_SERVICE_5:
            return SAL_RING_TYPE_B_SYM_LO;
        case ICP_ADF_RING_SERVICE_6:
            return SAL_RING_TYPE_B_ASYM;
        case ICP_ADF_RING_SERVICE_7:
            return SAL_RING_TYPE_DC;
        case ICP_ADF_RING_SERVICE_8:
            return SAL_RING_TYPE_ADMIN;
        default:
            return SAL_RING_TYPE_NONE;
    }
    return SAL_RING_TYPE_NONE;
}

#endif /* LAC_COMMON_H */
