/**
 * @file OsalOsTypes.h
 *
 * @brief 0S-specific data types and macros
 *
 *
 * @par
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
 */

#ifndef OSAL_OS_TYPES_H
#define OSAL_OS_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifndef ICP_WITHOUT_THREAD
#include <pthread.h>
#endif
#include <errno.h>
#include <semaphore.h>
#include <time.h>
#include <asm/param.h>
#include <syslog.h>
#include <unistd.h>

#include <mqueue.h>

#ifndef ICP_WITHOUT_THREAD
typedef pthread_t OsalThread;
typedef pthread_mutex_t *OsalMutex;
typedef pthread_mutex_t *OsalFastMutex;
typedef pthread_spinlock_t OsalLock;
typedef pthread_attr_t OsalPosixThreadAttr;
#else
typedef int OsalThread;
typedef void *OsalMutex;
typedef void *OsalFastMutex;
typedef int OsalLock;
typedef int OsalPosixThreadAttr;
#endif
typedef sem_t *OsalSemaphore;

typedef int64_t INT64;   /**< 64-bit signed integer */
typedef uint64_t UINT64; /**< 64-bit unsigned integer */
typedef int32_t INT32;   /**< 32-bit signed integer */
typedef uint32_t UINT32; /**< 32-bit unsigned integer */
typedef int16_t INT16;   /**< 16-bit signed integer */
typedef uint16_t UINT16; /**< 16-bit unsigned integer */
typedef int8_t INT8;     /**< 8-bit signed integer */
typedef char CHAR;
typedef unsigned char UINT8; /**< 8-bit unsigned integer */
typedef UINT32 ULONG;        /**< alias for UINT32 */
typedef UINT16 USHORT;       /**< alias for UINT16 */
typedef UINT8 UCHAR;         /**< alias for UINT8 */
typedef UINT32 BOOL;         /**< alias for UINT32 */
typedef void VOID;           /**< alias for void */

typedef volatile INT64 OsalAtomic;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define ATOMIC_INIT(i)                                                         \
    {                                                                          \
        (i)                                                                    \
    }

#define OSAL_POSIX_UNSHARED_SEMAPHORE 0
#define OSAL_POSIX_SHARED_SEMAPHORE 1

#define OSAL_OS_WAIT_FOREVER (-1)
#define OSAL_OS_WAIT_NONE 0

#define OSAL_OS_PAGE_SIZE 4096

/* Default stack limit is 10 KB */
#define OSAL_OS_THREAD_DEFAULT_STACK_SIZE (10240)

/* Maximum stack limit is 32 MB */
#define OSAL_OS_THREAD_MAX_STACK_SIZE (33554432) /* 32 MBytes */

/* Thread minimum priority : PTHREAD_MIN_PRIORITY */
#define OSAL_OS_MIN_THREAD_PRIORITY (1)

/* Default thread priority */
#define OSAL_OS_DEFAULT_THREAD_PRIORITY (15)

/* Thread maximum priority : PTHREAD_MAX_PRIORITY */
#define OSAL_OS_MAX_THREAD_PRIORITY (99)

/* Thread default scheduling policy */
#define OSAL_OS_THREAD_DEFAULT_SCHED_POLICY SCHED_RR

/* Thread scheduling policy - Round Robin */
#define OSAL_THREAD_SCHED_RR SCHED_RR

/* Thread scheduling policy - FiFo */
#define OSAL_THREAD_SCHED_FIFO SCHED_FIFO

/* Thread scheduling policy - Other */
#define OSAL_THREAD_SCHED_OTHER SCHED_OTHER

/* error numbers */
/*
#define EAGAIN                   EAGAIN
#define EBADF                    EBADF
#define EMSGSIZE                 EMSGSIZE
#define EINTR                    EINTR
#define EINVAL                   EINVAL
#define ETIMEDOUT                ETIMEDOUT
#define EBADMSG                  EBADMSG
#define EFAULT                   EFAULT
*/

/* Maximum alignment allowed */
#ifndef OSAL_MAX_ALIGNMENT
#define OSAL_MAX_ALIGNMENT 256
#endif

/* In case of SCHED_OTHER the supported priority value is only zero */

/* Thread minimum priority : PTHREAD_MIN_PRIORITY */
#define OSAL_POSIX_THREAD_MIN_PRIORITY (1)

/* Default thread priority */
#define OSAL_POSIX_THREAD_DEFAULT_PRIORITY (31)

/* Thread maximum priority : PTHREAD_MAX_PRIORITY */
#define OSAL_POSIX_THREAD_MAX_PRIORITY (99)

/* Thread default scheduling policy - SCHED_RR, SCHED_FIFO or SCHED_OTHER */
#define OSAL_POSIX_THREAD_DEFAULT_SCHED_POLICY SCHED_RR

/* String manipulation definitions */
#define OSAL_OS_GET_STRING_LENGTH(str, n) strnlen(str, n)

#define OSAL_OS_MMU_VIRT_TO_PHYS(addr) ((UINT64)(addr))

#define OSAL_OS_MMU_PHYS_TO_VIRT(addr) (addr)

#define OSAL_ASSERT(c)                                                         \
    if (!(c))                                                                  \
    {                                                                          \
        abort();                                                               \
    }

#define OSAL_MEM_ASSERT(c)                                                     \
    if (!(c))                                                                  \
    {                                                                          \
        abort();                                                               \
    }

typedef enum
{
    TYPE_IGNORE = 0,             /**< Spin Lock type Ignore */
    NON_QUEUED = 1,              /**< Non Queued Spin Lock type */
    QUEUED = 2,                  /**< Queued Spin Lock type  */
    NON_QUEUED_AT_DPC_LEVEL = 3, /**< Non Queued Spin Lock type at DPC level */
    QUEUED_AT_DPC_LEVEL          /**< Queued Spin Lock type at DPC level */
} OsalLockType;

#define OSAL_OS_HOST_TO_NW_16(uData)                                           \
    ((0xff & ((uData) >> 8)) | (((uData)&0xff) << 8))

#define OSAL_OS_HOST_TO_NW_32(uData)                                           \
    (((uData) >> 24) | (((uData)&0x00ff0000) >> 8) |                           \
     (((uData)&0x0000ff00) << 8) | (((uData)&0x000000ff) << 24))

#define OSAL_OS_HOST_TO_NW_64(uData)                                           \
    ((((uData) >> 56) & 0xffull) | (((uData) >> 40) & 0x000000000000ff00ull) | \
     (((uData) >> 24) & 0x0000000000ff0000ull) |                               \
     (((uData) >> 8) & 0x00000000ff000000ull) |                                \
     (((uData) << 56) & 0xff00000000000000ull) |                               \
     (((uData) << 40) & 0x00ff000000000000ull) |                               \
     (((uData) << 24) & 0x0000ff0000000000ull) |                               \
     (((uData) << 8) & 0x000000ff00000000ull))

#define OSAL_OS_NW_TO_HOST_16(uData)                                           \
    ((0xff & ((uData) >> 8)) | (((uData)&0xff) << 8))

#define OSAL_OS_NW_TO_HOST_32(uData)                                           \
    (((uData) >> 24) | (((uData) >> 8) & 0x0000ff00) |                         \
     (((uData) << 8) & 0x00ff0000) | ((uData) << 24))

#define OSAL_OS_NW_TO_HOST_64(uData)                                           \
    ((((uData) >> 56) & 0xffull) | (((uData) >> 40) & 0x000000000000ff00ull) | \
     (((uData) >> 24) & 0x0000000000ff0000ull) |                               \
     (((uData) >> 8) & 0x00000000ff000000ull) |                                \
     (((uData) << 56) & 0xff00000000000000ull) |                               \
     (((uData) << 40) & 0x00ff000000000000ull) |                               \
     (((uData) << 24) & 0x0000ff0000000000ull) |                               \
     (((uData) << 8) & 0x000000ff00000000ull))

#define OSAL_OS_UDIV64_32(dividend, divisor) (dividend / divisor);

#define OSAL_OS_UMOD64_32(dividend, divisor) (dividend % divisor);

#ifdef __cplusplus
}
#endif

#endif /* OsalTypes_H */
