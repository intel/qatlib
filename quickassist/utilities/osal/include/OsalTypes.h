/**
 * @file OsalTypes.h
 *
 * @brief Define OSAL basic data types.
 *
 * This file contains fundamental data types used by OSAL.
 *
 * @par
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
 */

#ifndef OSAL_TYPES_H
#define OSAL_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Include the OS-specific type definitions
 */
#include "OsalOsTypes.h"

/**
 * @defgroup OsalTypes Osal basic data types.
 *
 * @brief Basic data types for Osal
 *
 * @{
 */

/**
 * @typedef OSAL_STATUS
 * @brief OSAL status
 *
 * @note Possible OSAL return status include OSAL_SUCCESS, OSAL_FAIL,
 *       OSAL_RETRY, OSAL_RESOURCE, OSAL_INVALID_PARAM, OSAL_FATAL
 *       and OSAL_UNSUPPORTED.
 */
typedef UINT32 OSAL_STATUS;

/**
 * @brief VUINT32
 *
 * @note volatile UINT32
 */
typedef volatile UINT32 VUINT32;

/**
 * @brief VINT32
 *
 * @note volatile INT32
 */
typedef volatile INT32 VINT32;

/**
 * @ingroup Osal
 *
 * @def NUMELEMS
 *
 * @brief  Calculate number of elements
 */
#ifndef NUMELEMS
#define NUMELEMS(x) (sizeof(x) / sizeof((x)[0]))
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_BILLION
 *
 * @brief  Alias for 1,000,000,000
 *
 */
#define OSAL_BILLION (1000000000)

/**
 * @ingroup Osal
 *
 * @def OSAL_MILLION
 *
 * @brief  Alias for 1,000,000
 *
 */
#define OSAL_MILLION (1000000)

/**
 * @ingroup Osal
 *
 * @def OSAL_THOUSAND
 *
 * @brief  Alias for 1,000
 *
 */
#define OSAL_THOUSAND (1000)

/**
 * @ingroup Osal
 *
 * @def OSAL_HUNDRED
 *
 * @brief  Alias for 100
 *
 */
#define OSAL_HUNDRED (100)

#if defined(__x86_64__) || defined(__aarch64__)
#define ARCH_INT INT64
#else
#define ARCH_INT INT32
#endif

#if defined(__x86_64__) || defined(__aarch64__)
#define UARCH_INT UINT64
#else
#define UARCH_INT UINT32
#endif

/**
 * @ingroup Osal
 *
 * @def NULL
 *
 * @brief Define for Null
 */
#ifndef NULL
#define NULL 0L
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_SUCCESS
 *
 * @brief Success status
 */
#ifndef OSAL_SUCCESS
#define OSAL_SUCCESS (0)        /**< #defined as 0 */
#define OSAL_STATUS_SUCCESS (0) /**< #defined as 0 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_FAIL
 *
 * @brief Failure status
 */
#ifndef OSAL_FAIL
#define OSAL_FAIL (-1)        /**< #defined as -1 */
#define OSAL_STATUS_FAIL (-1) /**< #defined as -1 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_RETRY
 *
 * @brief Retry status
 */
#ifndef OSAL_RETRY
#define OSAL_RETRY (-2)        /**< #defined as -2 */
#define OSAL_STATUS_RETRY (-2) /**< #defined as -2 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_RESOURCE
 *
 * @brief The resource that has been requested is unavailable.
 * 	  Refer to the relevant sections of the API for specifics
 * 	  on what the suggested course of action is.
 */
#ifndef OSAL_RESOURCE
#define OSAL_RESOURCE (-3)        /**< #defined as -3 */
#define OSAL_STATUS_RESOURCE (-3) /**< #defined as -3 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_INVALID_PARAM
 *
 * @brief Invalid parameter has been passed in.
 */
#ifndef OSAL_INVALID_PARAM
#define OSAL_INVALID_PARAM (-4)        /**< #defined as -4 */
#define OSAL_STATUS_INVALID_PARAM (-4) /**< #defined as -4 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_FATAL
 *
 * @brief A serious error has occurred.
 */
#ifndef OSAL_FATAL
#define OSAL_FATAL (-5)        /**< #defined as -5 */
#define OSAL_STATUS_FATAL (-5) /**< #defined as -5 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_UNSUPPORTED
 *
 * @brief Function is not supported/implemented.
 */
#ifndef OSAL_UNSUPPORTED
#define OSAL_UNSUPPORTED (-6)        /**< #defined as -6 */
#define OSAL_STATUS_UNSUPPORTED (-6) /**< #defined as -6 */
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_PRIVATE
 *
 * @brief Private define
 */
#ifndef OSAL_PRIVATE
#ifdef OSAL_PRIVATE_OFF
#define OSAL_PRIVATE /* nothing */
#else
#define OSAL_PRIVATE                                                           \
    static /**< #defined as static, except for debug builds                    \
            */
#endif     /* OSAL_PRIVATE_OFF */
#endif     /* OSAL_PRIVATE */

/*
 *  Placeholder for future use
 */
#ifndef OSAL_RESTRICTED
#define OSAL_RESTRICTED
#endif /* OSAL_RESTRICTED */

/**
 * @ingroup Osal
 *
 * @def OSAL_INLINE
 *
 * @brief Alias for __inline
 *
 */
#ifndef _DIAB_TOOL

#ifndef OSAL_INLINE
#define OSAL_INLINE __inline
#endif /* OSAL_INLINE */

/**
 * @ingroup Osal
 *
 * @def __inline__
 *
 * @brief Alias for __inline
 */
#ifndef __inline__
#define __inline__ OSAL_INLINE
#endif

#else

/**
 * @ingroup Osal
 *
 * @def OSAL_INLINE
 *
 * @brief Alias for __inline
 */
#ifndef OSAL_INLINE
#define OSAL_INLINE                                                            \
    __inline__ /* Diab Compiler uses __inline__ (compiler di                   \
                     rective) */
#endif         /* OSAL_INLINE */

#endif /*_DIAB_TOOL*/

/* Each OS can define its own OSAL_PUBLIC, otherwise it will be empty. */
#ifndef OSAL_PUBLIC
#define OSAL_PUBLIC
#endif /* OSAL_PUBLIC */

/**
 * @ingroup Osal
 *
 * @def OSAL_INLINE_EXTERN
 *
 * @brief Alias for __inline extern
 *
 */
#ifndef OSAL_INLINE_EXTERN
#define OSAL_INLINE_EXTERN OSAL_INLINE extern
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_USES_ATTRIBUTE_PACKED
 *
 * @brief Defining packed attribute type in compiler/OS that supports it.
 *
 */
#ifndef OSAL_USES_ATTRIBUTE_PACKED
#define OSAL_USES_ATTRIBUTE_PACKED TRUE
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_MAX_ALIGNMENT
 *
 * @brief Defining maximum alignment supported for aligned memory allocation.
 *
 */
#define OSAL_MAX_ALIGNMENT 256

#ifndef MILLISEC_TO_SEC_FACTOR
#define MILLISEC_TO_SEC_FACTOR 1000
#endif /* MILLISEC_TO_SEC_FACTOR */

/**
 * @ingroup Osal
 * @enum OsalLogDevice
 * @brief This is an emum for OSAL log devices.
 */
typedef enum
{
    OSAL_LOG_OUTPUT_NONE = 0,   /**<no output */
    OSAL_LOG_OUTPUT_STD = 1,    /**<Set output to stdout/stderr */
    OSAL_LOG_OUTPUT_SYSLOG = 2, /**<Set output to syslog file */
    OSAL_LOG_OUTPUT_ALL         /**<Set output to all */
} OutputType;

/**
 * @ingroup Osal
 * @enum OsalLogDevice
 * @brief This is an emum for OSAL log devices.
 */
typedef enum
{
    OSAL_LOG_DEV_STDOUT = 0, /**< standard output (implemented by default) */
    OSAL_LOG_DEV_STDERR = 1, /**< standard error (implemented */
    OSAL_LOG_DEV_HEX_DISPLAY = 2, /**< hexadecimal display (not implemented) */
    OSAL_LOG_DEV_ASCII_DISPLAY =
        3 /**< ASCII-capable display (not implemented) */
} OsalLogDevice;

/**
 * @ingroup Osal
 *
 * @def OSAL_LOG_ERROR
 *
 * @brief Alias for -1, used as log function error status
 *
 */
#define OSAL_LOG_ERROR (-1)
#define OSAL_NO_LOG (0)

/**
 * @ingroup Osal
 * @enum OsalLogLevel
 * @brief This is an emum for OSAL log trace level.
 */
typedef enum
{
    OSAL_LOG_LVL_NONE = 0,    /**<No trace level */
    OSAL_LOG_LVL_USER = 1,    /**<Set trace level to user */
    OSAL_LOG_LVL_FATAL = 2,   /**<Set trace level to fatal */
    OSAL_LOG_LVL_ERROR = 3,   /**<Set trace level to error */
    OSAL_LOG_LVL_WARNING = 4, /**<Set trace level to warning */
    OSAL_LOG_LVL_MESSAGE = 5, /**<Set trace level to message */
    OSAL_LOG_LVL_DEBUG1 = 6,  /**<Set trace level to debug1 */
    OSAL_LOG_LVL_DEBUG2 = 7,  /**<Set trace level to debug2 */
    OSAL_LOG_LVL_DEBUG3 = 8,  /**<Set trace level to debug3 */
    OSAL_LOG_LVL_ALL          /**<Set trace level to all */
} OsalLogLevel;

/**
 *@ingroup Osal
 *
 *@def OSAL_PAGE_SIZE
 *
 *@note Macro for page size
 */
#define OSAL_PAGE_SIZE OSAL_OS_PAGE_SIZE

/**
 * @ingroup Osal
 * @brief Void function pointer prototype
 *
 * @note accepts a void pointer parameter
 * and does not return a value.
 */
typedef void (*OsalVoidFnVoidPtr)(void *);

/**
 * @ingroup Osal
 * @brief Void function pointer prototype
 *
 * @note accepts a void parameter
 * and does not return a value.
 */
typedef void (*OsalVoidFnPtr)(void);

/**
 * @brief Timeval structure
 *
 * @note Contain subfields of seconds and nanoseconds..
 */
typedef struct
{
    UINT64 secs;  /**< seconds */
    UINT64 nsecs; /**< nanoseconds */
} OsalTimeval;

/**
 * @ingroup Osal
 * @brief OsalTimer
 *
 * @note OSAL timer handle
 *
 */
#ifndef USE_NATIVE_OS_TIMER_API
typedef UINT32 OsalTimer;
#else
typedef OsalOsTimer OsalTimer;
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_WAIT_FOREVER
 *
 * @brief Definition for timeout forever, OS-specific.
 *
 */
#define OSAL_WAIT_FOREVER OSAL_OS_WAIT_FOREVER

/**
 * @ingroup Osal
 *
 * @def OSAL_WAIT_NONE
 *
 * @brief Definition for timeout 0, OS-specific.
 *
 */
#define OSAL_WAIT_NONE OSAL_OS_WAIT_NONE

/**
 * @brief Thread Attribute
 * @note Default thread attribute
 */
typedef struct
{
    char *name;       /**< name */
    UINT32 stackSize; /**< stack size */
    UINT32 priority;  /**< priority */
    INT32 policy;     /**< policy */
} OsalThreadAttr;

/**
 * @ingroup Osal
 *
 * @def OSAL_THREAD_DEFAULT_SCHED_POLICY
 *
 * @brief Default Thread Scheduling Policy, OS-specific.
 *
 */
#define OSAL_THREAD_DEFAULT_SCHED_POLICY (OSAL_OS_THREAD_DEFAULT_SCHED_POLICY)

/**
 * @ingroup Osal
 *
 * @def OSAL_THREAD_DEFAULT_STACK_SIZE
 *
 * @brief Default thread stack size, OS-specific.
 *
 */
#define OSAL_THREAD_DEFAULT_STACK_SIZE (OSAL_OS_THREAD_DEFAULT_STACK_SIZE)

/**
 * @ingroup Osal
 *
 * @def OSAL_THREAD_MAX_STACK_SIZE
 *
 * @brief Max stack size, OS-specific.
 *
 */
#define OSAL_THREAD_MAX_STACK_SIZE (OSAL_OS_THREAD_MAX_STACK_SIZE)

/**
 * @ingroup Osal
 *
 * @def OSAL_MAX_THREAD_NAME_LEN
 *
 * @brief Max size of thread name
 *
 */
#define OSAL_MAX_THREAD_NAME_LEN 16

/**
 * @ingroup Osal
 *
 * @def OSAL_MAX_MODULE_NAME_LENGTH
 *
 * @brief Max size of module Name Length to be prefixed for OSAL Log
 *
 */
#define OSAL_MAX_MODULE_NAME_LENGTH 20

/**
 * @ingroup Osal
 *
 * @def OSAL_MIN_THREAD_PRIORITY
 *
 * @brief Min thread priority, OS-specific.
 *
 */
#ifdef OSAL_OS_MIN_THREAD_PRIORITY
#define OSAL_MIN_THREAD_PRIORITY (OSAL_OS_MIN_THREAD_PRIORITY)
#else
#define OSAL_MIN_THREAD_PRIORITY 0
#endif

/**
 * @ingroup Osal
 *
 * @def OSAL_DEFAULT_THREAD_PRIORITY
 *
 * @brief Default thread priority, OS-specific.
 *
 */
#define OSAL_DEFAULT_THREAD_PRIORITY (OSAL_OS_DEFAULT_THREAD_PRIORITY)

/**
 * @ingroup Osal
 *
 * @def OSAL_MAX_THREAD_PRIORITY
 *
 * @brief Max thread priority, OS-specific.
 *
 */
#define OSAL_MAX_THREAD_PRIORITY (OSAL_OS_MAX_THREAD_PRIORITY)
/**
 * @ingroup Osal
 *
 * @typedef OsalPciDev
 * @brief OsalPciDev
 *
 * @note This is a data type that serves as a handle for allocated PCI device.
 *
 */
typedef UINT8 *OsalPciDev;

/**
 * @brief UINT128
 *
 * @note Union to hold UINT128 value
 */
typedef union UINT128_t {
    UINT8 mUINT8[16];  /**< 16 UINT8 values */
    UINT16 mUINT16[8]; /**< 8 UINT16 values */
    UINT32 mUINT32[4]; /**< 4 UINT32 values */
    UINT64 mUINT64[2]; /**< 2 UINT64 values */
} UINT128;

/**
 * @brief Ensure macro, ensure the condition is true.
 *        This will be conditionally compiled out and
 *        may be used for test purposes.
 */
#ifdef OSAL_ENSURE_ON
#ifndef __WPP_EN__
#define __FILENAME__ (strrchr("/" __FILE__, '/') + 1)
#define OSAL_ENSURE(c, str)                                                    \
    do                                                                         \
    {                                                                          \
        if (!(c))                                                              \
            osalLog(OSAL_LOG_LVL_MESSAGE,                                      \
                    OSAL_LOG_DEV_STDOUT,                                       \
                    "%s in file %s at line %d\n",                              \
                    str,                                                       \
                    __FILENAME__,                                              \
                    __LINE__);                                                 \
    } while (0)

#define OSAL_ENSURE_RETURN(c, str)                                             \
    if (!(c))                                                                  \
    {                                                                          \
        osalLog(OSAL_LOG_LVL_MESSAGE,                                          \
                OSAL_LOG_DEV_STDOUT,                                           \
                "%s in file %s at line %d\n",                                  \
                str,                                                           \
                __FILENAME__,                                                  \
                __LINE__);                                                     \
        return OSAL_FAIL;                                                      \
    }

#define OSAL_LOCAL_ENSURE(c, str, ret)                                         \
    if (!(c))                                                                  \
    {                                                                          \
        osalLog(OSAL_LOG_LVL_ERROR,                                            \
                OSAL_LOG_DEV_STDOUT,                                           \
                "%s in file %s\n",                                             \
                str,                                                           \
                __FILENAME__);                                                 \
        return ret;                                                            \
    }

#define OSAL_PTR_ENSURE(c, str, ret)                                           \
    if (!(c) || !(*c))                                                         \
    {                                                                          \
        osalLog(OSAL_LOG_LVL_ERROR,                                            \
                OSAL_LOG_DEV_STDOUT,                                           \
                "%s in file %s\n",                                             \
                str,                                                           \
                __FILENAME__);                                                 \
        return ret;                                                            \
    }

#define OSAL_ENSURE_JUST_RETURN(c, str)                                        \
    if (!(c))                                                                  \
    {                                                                          \
        osalLog(OSAL_LOG_LVL_ERROR,                                            \
                OSAL_LOG_DEV_STDOUT,                                           \
                "%s in file %s at line %d\n",                                  \
                str,                                                           \
                __FILENAME__,                                                  \
                __LINE__);                                                     \
        return;                                                                \
    }

#define OSAL_ENSURE_CHECK_OSAL_SUCCESS(c, str)                                 \
    if (OSAL_SUCCESS != c)                                                     \
    {                                                                          \
        osalLog(OSAL_LOG_LVL_ERROR,                                            \
                OSAL_LOG_DEV_STDOUT,                                           \
                "%s in file %s at line %d\n",                                  \
                str,                                                           \
                __FILENAME__,                                                  \
                __LINE__);                                                     \
        return OSAL_FAIL;                                                      \
    }
#endif // #ifndef __WPP_EN__
#else
#define OSAL_ENSURE(c, str)                                                    \
    do                                                                         \
    {                                                                          \
    } while (0);
#define OSAL_ENSURE_RETURN(c, str)                                             \
    do                                                                         \
    {                                                                          \
    } while (0);
#define OSAL_LOCAL_ENSURE(c, str, ret)                                         \
    do                                                                         \
    {                                                                          \
    } while (0);
#define OSAL_PTR_ENSURE(c, str, ret)                                           \
    do                                                                         \
    {                                                                          \
    } while (0);
#define OSAL_ENSURE_JUST_RETURN(c, str)                                        \
    do                                                                         \
    {                                                                          \
    } while (0);
#define OSAL_ENSURE_CHECK_OSAL_SUCCESS(c, str)                                 \
    do                                                                         \
    {                                                                          \
    } while (0);
#endif

#ifdef __cplusplus
}
#endif
#endif /* OSAL_TYPES_H */
