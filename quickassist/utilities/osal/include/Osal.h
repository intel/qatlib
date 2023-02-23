/**
 * @file    Osal.h
 *
 * @brief    Top include file for OSAL
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

#ifndef OSAL_H
#define OSAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "OsalOsTypes.h"
#include "OsalTypes.h"
#ifndef DISABLE_NUMA_ALLOCATION
#include "OsalDevDrvCommon.h"
#endif

#define OSAL_HOST_TO_NW_16(uData) OSAL_OS_HOST_TO_NW_16(uData)
#define OSAL_HOST_TO_NW_32(uData) OSAL_OS_HOST_TO_NW_32(uData)
#define OSAL_HOST_TO_NW_64(uData) OSAL_OS_HOST_TO_NW_64(uData)

#define OSAL_NW_TO_HOST_16(uData) OSAL_OS_NW_TO_HOST_16(uData)
#define OSAL_NW_TO_HOST_32(uData) OSAL_OS_NW_TO_HOST_32(uData)
#define OSAL_NW_TO_HOST_64(uData) OSAL_OS_NW_TO_HOST_64(uData)

#define OSAL_UDIV64_32(dividend, divisor) OSAL_OS_UDIV64_32(dividend, divisor)

#define OSAL_UMOD64_32(dividend, divisor) OSAL_OS_UMOD64_32(dividend, divisor)

/**
 * @ingroup Osal
 *
 * @brief Interrupt-safe logging function
 *
 * @param level - identifier prefix for the message
 * @param device - output device
 * @param format - message format, in a printf format
 * @param va_list - takes a variable list
 *
 * IRQ-safe logging function, similar to printf. Accepts up to 6 arguments
 * to print (excluding the level, device and the format). This function will
 * actually display the message only if the level is lower than the current
 * verbosity level or if the OSAL_LOG_LVL_USER level is used. An output device
 * must be specified (see OsalTypes.h).
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - BepSide the exceptions documented in the note below, the returned
 * value is the number of printed characters, or -1 if the parameters are
 * incorrect (NULL format, unknown output device)
 *
 * @note The exceptions to the return value are:
 * VxWorks*: The return value is 32 if the specified level is 1 and 64
 * if the specified level is greater than 1 and less or equal than 9.
 * WinCE*: If compiled for EBOOT then the return value is always 0.
 *
 * @note The given print format should take into account the specified
 * output device. OSAL_STDOUT supports all the usual print formats,
 * however a custom hex display specified by OSAL_HEX would support
 * only a fixed number of hexadecimal digits.
 */
OSAL_PUBLIC INT32 osalLog(OsalLogLevel level,
                          OsalLogDevice device,
                          char *format,
                          ...);

/**
 * @ingroup Osal
 *
 * @brief Setting the module name
 *
 * @param moduleName - the string to be prepended with OSAL log message
 *
 * A facility provided to the user to prepend module name with OSAL
 * log messages. Example usage of this API to help the user to separate
 * messages from other modules. After the API called the subsequent calls to
 * osalLog or osalStdLog API's shall log the module name followed with
 * regular OSAL log message. To disable module name prepend users need to
 * invoke this API as osalLogSetPrefix("");
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - None.
 *
 */
OSAL_PUBLIC void osalLogSetPrefix(CHAR *moduleName);

/**
 * @ingroup Osal
 *
 * @brief simple logging function
 *
 * @param arg_pFmtString  - message format, in printf format
 * @param ...             - variable arguments
 *
 * Logging function, similar to printf. This provides a barebones logging
 * mechanism for users without differing verbosity levels. This interface
 * is not guaranteed to be IRQ safe.
 *
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalStdLog(const char *arg_pFmtString, ...);

/**
 * @ingroup Osal
 *
 * @brief sets the current logging verbosity level
 *
 * @param level - new log verbosity level
 *
 * Sets the log verbosity level. The default value is OSAL_LOG_ERROR.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - Old log verbosity level
 */
OSAL_PUBLIC UINT32 osalLogLevelSet(UINT32 level);

OSAL_PUBLIC void osalLogModuleSet(const char *name);

OSAL_PUBLIC void osalLogOutputSet(UINT32 output);

/**
 * @ingroup Osal
 *
 * @brief Atomically read the value of atomic variable
 *
 * @param  pAtomicVar  IN   - atomic variable
 *
 * Atomically reads the value of pAtomicVar to the outValue
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return  pAtomicVar value
 */
OSAL_PUBLIC INT64 osalAtomicGet(OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief Atomically set the value of atomic variable
 *
 * @param  inValue    IN   -  atomic variable to be set equal to inValue
 *
 * @param  pAtomicVar  OUT  - atomic variable
 *
 * Atomically sets the value of pAtomicVar to the value given
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return none
 */
OSAL_PUBLIC void osalAtomicSet(INT64 inValue, OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief Atomically set the value of atomic variable
 *
 * @param  inValue (in)   -  atomic variable to be set equal to inValue
 *
 * @param  pAtomicVar (in & out)   - atomic variable
 *
 * Atomically sets the value of pAtomicVar to the inValue given
 * This function calls an atomic builtin which is not a full barrier,
 * but rather an acquire barrier to lock the variable.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return previous value of pAtomicVar value
 */
OSAL_PUBLIC INT64 osalAtomicTestAndSet(INT64 inValue, OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief Reset the value of atomic variable
 *
 * @param  pAtomicVar (in)   - atomic variable
 *
 * Writes the constant 0 to *pAtomicVar
 * This function calls an atomic builtin which releases the lock
 * acquired by osalAtomicTestAndSet function.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return none
 */
OSAL_PUBLIC void osalAtomicRelease(OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief add the value to atomic variable
 *
 * @param  inValue (in)   -  value to be added to the atomic variable
 *
 * @param  pAtomicVar (in & out)   - atomic variable
 *
 * Atomically adds the value of inValue to the pAtomicVar
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return pAtomicVar value after the addition
 */
OSAL_PUBLIC INT64 osalAtomicAdd(INT64 inValue, OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief subtract the value from atomic variable
 *
 * @param  inValue   IN     -  atomic variable value to be subtracted by value
 *
 * @param  pAtomicVar IN/OUT - atomic variable
 *
 * Atomically subtracts the value of pAtomicVar by inValue
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return pAtomicVar value after the subtraction
 */
OSAL_PUBLIC INT64 osalAtomicSub(INT64 inValue, OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief increment value of atomic variable by 1
 *
 * @param  pAtomicVar IN/OUT   - atomic variable
 *
 * Atomically increments the value of pAtomicVar by 1.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return pAtomicVar value after the increment
 */
OSAL_PUBLIC INT64 osalAtomicInc(OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief decrement value of atomic variable by 1
 *
 * @param  pAtomicVar IN/OUT  - atomic variable
 *
 * Atomically decrements the value of pAtomicVar by 1.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return pAtomic value after the decrement
 */
OSAL_PUBLIC INT64 osalAtomicDec(OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief decrement atomic variable value by 1 and test result
 *
 * @param  pAtomicVar (IN/OUT)   - atomic variable
 *
 * Atomically decrements the value of pAtomicVar by 1 and test
 * result for zero.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return OSAL_FAIL if the result is zero or OSAL_SUCCESS otherwise
 */
OSAL_PUBLIC OSAL_STATUS osalAtomicDecAndTest(OsalAtomic *pAtomicVar);

/**
 * @ingroup Osal
 *
 * @brief Yielding sleep for a number of milliseconds
 *
 * @param milliseconds - number of milliseconds to sleep
 *
 * The calling thread will sleep for the specified number of milliseconds.
 * This sleep is yielding, hence other tasks will be scheduled by the
 * operating system during the sleep period. Calling this function with an
 * argument of 0 will place the thread at the end of the current scheduling
 * loop.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalSleep(UINT32 milliseconds);

/**
 * @ingroup Osal
 *
 * @brief Yields execution of current thread
 *
 * Yields the execution of the current thread
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - none
 */
OSAL_PUBLIC void osalYield(void);

/**************************************
 * Memory functions
 *************************************/
/**
 * @ingroup Osal
 *
 * @brief Initialize the user-space allocator
 *
 * @param path - path to the specific device
 *
 * Initialize the user-space allocator opening the device driver used
 * to communicate with the kernel-space.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return OSAL_SUCCESS if the open of the device was successful and
 * OSAL_FAIL otherwise
 */
OSAL_STATUS
osalMemInitialize(char *path);

/**
 * @ingroup Osal
 *
 * @brief Finalize the user-space allocator
 *
 * It closes the file descriptor associated with the device driver
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 */
void osalMemDestroy(void);

/**
 * @ingroup Osal
 *
 * @brief Allocates memory
 *
 * @param size - memory size to allocate, in bytes
 *
 * Allocates a memory zone of the specified size.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return Pointer to the allocated zone or NULL if the allocation failed
 */
void *osalMemAlloc(UINT32 size);

/**
 * @ingroup Osal
 *
 * @brief Allocates memory atomically
 *
 * @param size - memory size to allocate, in bytes
 *
 * Allocates a memory zone of a given size, and in kernel space
 * the allocation is high priority.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return Pointer to the allocated zone or NULL if the allocation failed
 */
void *osalMemAllocAtomic(UINT32 size);

/**
 * @ingroup Osal
 *
 * @brief NUMA aware memory allocation; available on Linux OS only.
 *
 * @param size - memory size to allocate, in bytes
 * @param node - node
 * @param alignment - memory boundary alignment (alignment can not be 0)
 *
 * Allocates a memory zone of a given size on the specified node
 * The returned memory is guaraunteed to be physically contiguous if the
 * given size is less than 128KB and belonging to the node specified
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return Pointer to the allocated zone or NULL if the allocation failed
 */
void *osalMemAllocContiguousNUMA(UINT32 size, UINT32 node, UINT32 alignment);

/**
 * @ingroup Osal
 *
 * @brief Frees memory allocated by OsalMemAllocNUMA; available on Linux OS
 * only.
 *
 * @param ptr - pointer to the memory zone
 * @param size - size of the pointer previously allocated
 *
 * Frees a previously allocated memory zone
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - none
 */
void osalMemFreeNUMA(void *ptr);

/**
 * @ingroup Osal
 *
 * @brief Frees memory allocated by OsalMemAlloc
 *
 * @param ptr - pointer to the memory zone
 *
 * Frees a previously allocated memory zone
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - none
 */
void osalMemFree(void *ptr);

/**
 * @ingroup Osal
 *
 * @brief Converts a virtual address to a physical one
 *
 * @param pVirtAddr - pointer to the memory zone
 *
 * Converts a virtual address to a physical one. It's implementation
 * works only for user-space.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - physical address in a form of UINT64
 */
UINT64
osalVirtToPhysNUMA(void *pVirtAddr);

/**
 * @ingroup Osal
 *
 * @brief Allocation of a page of memory from a specific
 * NUMA node and return physical address.
 *
 * @param node - NUMA node to allocate from
 * @param physAddr - The physical address of the allocated page.
 *
 * Allocates memory of a given size on the specified node.
 * The size of the PAGE is OS dependent.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return Pointer to the allocated memory or NULL if the allocation failed
 */
void *osalMemAllocPage(UINT32 node, UINT64 *physAddr);

/**
 * @ingroup Osal
 *
 * @brief Frees memory allocated by osalMemAllocPage
 *
 * @param ptr - pointer to the memory
 *
 * Frees a previously allocated memory
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - none
 */
void osalMemFreePage(void *ptr);

/*
 * Using the intrinsic OS memcpy/memset
 * yields greater performance
 */
/**
 * @ingroup Osal
 *
 * @brief Copies data bytes from pSrc memory zone to pDest memory zone
 *
 * @param pDest  - pDestination memory zone
 * @param pSrc   - source memory zone
 * @param count - number of bytes to copy
 *
 * Copies count bytes from the source memory zone pointed by pSrc into the
 * memory zone pointed by pDest.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return Pointer to the pDestination memory zone
 */
void *osalMemCopy(void *pDest, const void *pSrc, UINT32 count);

/**
 * @ingroup Osal
 *
 * @brief Fills a memory zone
 *
 * @ ptr - pointer to the memory zone
 * @param filler - byte to fill the memory zone with
 * @param count - number of bytes to fill
 *
 * Fills a memory zone with a given constant byte
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return Pointer to the memory zone
 */
void *osalMemSet(void *ptr, UINT8 filler, UINT32 count);

/**
 * @ingroup Osal
 *
 * @brief Fills a memory zone
 *
 * @ ptr - pointer to the memory zone
 * @param count - number of bytes to fill
 *
 * Function for unoptimized calls
 * Fills a memory zone with 0
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return Pointer to the memory zone
 */
void *osalMemZeroExplicit(void *ptr, UINT32 count);

/*****************************
 *  Time
 *****************************/

/* Retrieve current system time
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalTimeGet(OsalTimeval *pTime);

/**
 * @ingroup Osal
 *
 * @brief Allocates aligned memory
 *
 * @param space - (Unused right now ) kernel_space or user_space
 * @param size - malloc memory size required to be allocated
 * @param alignment - alignment required in bytes
 *
 * Allocate an aligned memory zone
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - void pointer to malloced memory
 */
OSAL_PUBLIC VOID *osalMemAllocAligned(UINT32 space,
                                      UINT32 size,
                                      UINT32 alignment);

/**
 * @ingroup Osal
 *
 * @brief Frees memory allocated by OsalMemAllocAligned
 *
 * @param ptr - pointer to contiguous aligned memory zone
 *
 * Frees a previously allocated Aligned memory zone
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - none
 */
OSAL_PUBLIC void osalMemAlignedFree(void *ptr);

/**
 * @ingroup Osal
 *
 * @brief Converts milliseconds to OsalTimeval
 *
 * @param milliseconds - number of milliseconds to convert
 * @param pTv - pointer to the pDestination structure
 *
 * Converts a millisecond value into an OsalTimeval structure
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - Corresponding OsalTimeval structure
 * Note: This function is OS-independent. Implemented by core.
 */
#define OSAL_MS_TO_TIMEVAL(milliseconds, pTv)                                  \
    ((OsalTimeval *)pTv)->secs = milliseconds / 1000;                          \
    ((OsalTimeval *)pTv)->nsecs = (milliseconds % 1000) * 1000000

/**
 * @ingroup Osal
 *
 * @brief "add" operator for OsalTimeval
 *
 * @param tvA, tvB - OsalTimeval structures to add
 *
 * Adds the second OsalTimevalStruct to the first one (equivalent to
 * tvA += tvB)
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - none
 * Note: This function is OS-independent.
 */
#define OSAL_TIME_ADD(tvA, tvB)                                                \
    (tvA).secs += (tvB).secs;                                                  \
    (tvA).nsecs += (tvB).nsecs;                                                \
    if ((tvA).nsecs >= OSAL_BILLION)                                           \
    {                                                                          \
        (tvA).secs++;                                                          \
        (tvA).nsecs -= OSAL_BILLION;                                           \
    }

/**
 * @ingroup Osal
 *
 * @brief "subtract" operator for OsalTimeval
 *
 * @param tvA, tvB - OsalTimeval structures to subtract
 *
 * Subtracts the second OsalTimevalStruct from the first one (equivalent
 * to tvA -= tvB)
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - none
 * Note: This function is OS-independent. Implemented by core.
 */
#define OSAL_TIME_SUB(tvA, tvB)                                                \
    if ((tvA).nsecs >= (tvB).nsecs)                                            \
    {                                                                          \
        (tvA).secs -= (tvB).secs;                                              \
        (tvA).nsecs -= (tvB).nsecs;                                            \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        (tvA).secs -= ((tvB).secs + 1);                                        \
        (tvA).nsecs += OSAL_BILLION - (tvB).nsecs;                             \
    }

/**
 * @ingroup Osal
 *
 * @brief Converts OsalTimeVal to milliseconds
 *
 * @param tv - OsalTimeval structure to convert
 *
 * Converts an OsalTimeval structure into milliseconds
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - Corresponding number of milliseconds
 * Note: This function is OS-independent. Implemented by core.
 */
#define OSAL_TIMEVAL_TO_MS(tv) ((tv.secs * 1000) + (tv.nsecs / OSAL_MILLION))

#define OSAL_OEM_TIMESTAMP_RESOLUTION_GET (846596000) /**< 846.596 MHz    */
#define OSAL_OEM_OS_NAME_GET(name, limit) OsalPosixOsNameGet(name, limit)
#define OSAL_OEM_OS_VERSION_GET(version, limit)                                \
    OsalPosixOsVersionGet(version, limit)

/**
 * @ingroup IxOsal
 *
 * @brief virtual to physical address translation
 *
 * @param virtAddr - virtual address
 *
 * Converts a virtual address into its equivalent MMU-mapped physical address
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return Corresponding physical address, as UINT32
 */
#define OSAL_MMU_VIRT_TO_PHYS(virtAddr) OSAL_OS_MMU_VIRT_TO_PHYS(virtAddr)

/**
 * @ingroup IxOsal
 *
 * @brief physical to virtual address translation
 *
 * @param physAddr - physical address
 *
 * Converts a physical address into its equivalent MMU-mapped virtual address
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return Corresponding virtual address, as UINT32
 */
#define OSAL_MMU_PHYS_TO_VIRT(physAddr) OSAL_OS_MMU_PHYS_TO_VIRT(physAddr)

/**
 * @ingroup Osal
 *
 * @brief Converts ticks into OsalToTimeval
 *
 * @param ticks - number of ticks
 * @param pTv - pointer to the destination structure
 *
 * Internal function to convert the specified number of ticks into
 * an OsalTimeval structure
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - Corresponding OsalTimeval structure
 * Note: This function is OS-independent and internal to OSAL
 */
OSAL_PUBLIC void osalTicksToTimeval(UINT64 ticks, OsalTimeval *pTv);

/**
 * @ingroup Osal
 *
 * @brief Converts OsalTimeVal into ticks
 *
 * @param tv - an OsalTimeval structure
 *
 * Internal function to convert an OsalTimeval structure into OS ticks
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - Corresponding number of ticks
 *
 * Note: This function is OS-independent and internal to OSAL.
 */
OSAL_PUBLIC UINT32 osalTimevalToTicks(OsalTimeval tv);

/**
 * @ingroup Osal
 *
 * @brief Retrieves the current timestamp
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - The current timestamp
 *
 * @note The implementation of this function is platform-specific. Not
 * all the platforms provide a high-resolution timestamp counter.
 */
OSAL_PUBLIC UINT64 osalTimestampGet(void);

/**
 * @ingroup Osal
 *
 * @brief Retrieves the current timestamp in nanoseconds units
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - The current timestamp in nanoseconds units
 *
 * @note The implementation of this function is platform-specific. Not
 * all the platforms provide a nanosecond resolution timestamp but the
 * lower resolutions ones will be converted to the nanoseconds units.
 */
OSAL_PUBLIC UINT64 osalTimestampGetNs(void);

/**
 * @ingroup Osal
 *
 * @brief System clock rate, in ticks
 *
 * Retrieves the resolution (number of ticks per second) of the system clock
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - The system clock rate
 *
 * @note The implementation of this function is platform and OS-specific.
 * The system clock rate is not always available -
 */
OSAL_PUBLIC UINT32 osalSysClockRateGet(void);

/**
 ***********************************************************
 * @param:     pLock - IN - pointer to a spinlock_t type
 *
 * @return: OSAL_STATUS - OSAL_SUCCESS or OSAL_FAIL
 *
 * @brief:  Initialize the SpinLock
 ***********************************************************
 */
/**
 * @ingroup Osal
 *
 * @brief Initializes the SpinLock object
 *
 * @param pLock - Spinlock handle
 * @param pLockType - Spinlock type
 *
 * Initializes the SpinLock object and its type.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalLockInit(OsalLock *pLock, OsalLockType pLockType);

/**
 * @ingroup Osal
 *
 * @brief Acquires a spin lock
 *
 * @param pLock - Spinlock handle
 *
 * This routine acquires a spin lock so the
 * caller can synchronize access to shared data in a
 * multiprocessor-safe way by raising IRQL.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - Returns OSAL_SUCCESS if the spinlock is acquired. Returns OSAL_FAIL
 * if
 *           spinlock handle is NULL. If spinlock is already acquired by any
 *           other thread of execution then it tries in busy loop/spins till it
 *           gets spinlock.
 */
OSAL_PUBLIC OSAL_STATUS osalLock(OsalLock *pLock);

/**
 * @ingroup Osal
 *
 * @brief Releases the spin lock
 *
 * @param pLock - Spinlock handle
 *
 * This routine releases the spin lock which the thread had acquired
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - return OSAL_SUCCESS if the spinlock is released. Returns OSAL_FAIL
 * if
 *           spinlockhandle passed is NULL.
 */
OSAL_PUBLIC OSAL_STATUS osalUnlock(OsalLock *pLock);

/**
 * @ingroup Osal
 *
 * @brief Destroy the spin lock object
 *
 * @param pLock - Spinlock handle
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - returns OSAL_SUCCESS if plock is destroyed.
 *           returns OSAL_FAIL if plock is NULL.
 *           returns OSAL_UNSUPPORTED if current operating system does not
 *                   support this operation.
 */
OSAL_PUBLIC OSAL_STATUS osalLockDestroy(OsalLock *pLock);

/**
 * @ingroup Osal
 *
 * @brief Acquires a spinlock; kernel-space only.
 *
 * @param pLock - Spinlock handle
 * @param flags - local irqs saved in flags
 *
 * @usage   This API can be used when critical section is shared between
 *          irq routines
 *
 * This routine saves local irqs in flags & then acquires a spinlock
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - returns OSAL_SUCCESS if spinlock acquired. If the spinlock is not
 *           available then it busy loops/spins till pLock available.
 *           If the spinlock handle passed is NULL then returns OSAL_FAIL.
 */
OSAL_PUBLIC OSAL_STATUS osalLockIrqSave(OsalLock *pLock, unsigned long *flags);

/**
 * @ingroup Osal
 *
 * @brief Releases the spin lock; kernel-space only.
 *
 * @param pLock - Spinlock handle
 * @param flags - local irqs saved in flags
 *
 * @usage   This API can be used when critical section is shared between
 *          irq routines
 *
 * This routine releases the acquired spin lock & restores irqs in flags
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - returns OSAL_SUCCESS if pLock is unlocked. Returns OSAL_FAIL if the
 *           pLock is NULL.
 */
OSAL_PUBLIC OSAL_STATUS osalUnlockIrqRestore(OsalLock *pLock,
                                             unsigned long *flags);

/**
 * @ingroup Osal
 *
 * @brief Acquires a spinlock
 *
 * @param slock - Spinlock handle
 *
 * This routine disables bottom half & then acquires a slock
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @usage   This API can be used in user context when critical section is
 *           shared between user context & bottom half handler
 *
 * @return - returns OSAL_SUCCESS if spinlock is acquired. If spinlock is
 *                   not available then it busy loops/spins till slock is
 *                   available.
 *           returns OSAL_FAIL if spinlock handle passed is NULL.
 *           returns OSAL_UNSUPPORTED if current operating system does not
 *                   support this operation.
 */
OSAL_PUBLIC OSAL_STATUS osalLockBh(OsalLock *slock);

/**
 * @ingroup Osal
 *
 * @brief Releases the spin lock
 *
 * @param slock - Spinlock handle
 *
 * This routine releases the acquired spinlock & enables the
 * bottom half handler
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @usage   This API can be used in user context when critical section is
 *           shared between user context & bottom half handler
 *
 * @return - returns OSAL_SUCCESS if slock is released or unlocked.
 *           returns OSAL_FAIL if slock is NULL.
 *           returns OSAL_UNSUPPORTED if current operating system does not
 *                   support this operation.
 */
OSAL_PUBLIC OSAL_STATUS osalUnlockBh(OsalLock *slock);

/**
 * @ingroup Osal
 *
 * @brief Initializes a semaphore
 *
 * @param pSid - semaphore handle
 * @param start_value - initial semaphore value
 *
 * Initializes a semaphore object
 * Note: Semaphore initialization OsalSemaphoreInit API must be called
 * first before using any OSAL Semaphore APIs
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreInit(OsalSemaphore *pSid,
                                          UINT32 start_value);

/**
 * @ingroup Osal
 *
 * @brief Destroys a semaphore object
 *
 * @param pSid - semaphore handle
 *
 * Destroys a semaphore object; the caller should ensure that no thread is
 * blocked on this semaphore. If call made when thread blocked on semaphore the
 * behaviour is unpredictable
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreDestroy(OsalSemaphore *pSid);

/**
 * @ingroup Osal
 *
 * @brief Waits on (decrements) a semaphore for specified time; available for
 * kernel-space
 * on Linux OS.
 *
 * @param pSid - semaphore handle
 * @param timeout - timeout, in ms; OSAL_WAIT_FOREVER (-1) if the thread
 * is to block indefinitely or OSAL_WAIT_NONE (0) if the thread is to
 * return immediately even if the call fails
 *
 * Decrements a semaphore, blocking for specified time if the semaphore is
 * unavailable (value is 0).The current thread or process can be interrupted
 * by a signal.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreWaitInterruptible(OsalSemaphore *pSid,
                                                       INT32 timeout);

/**
 * @ingroup Osal
 *
 * @brief  Wakes up thread blocked on semapohore. Increments a semaphore if
 * the value leass than one and wakes up threads waiting on wait queue;
 * available
 * for kernel-space on Linux OS.
 *
 * @param pSid - semaphore handle
 *
 * increments a semaphore if the value less than one and wakes up the thread
 * which is waiting for the semaphore.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphorePostWakeup(OsalSemaphore *pSid);

/**
 * @ingroup Osal
 *
 * @brief Waits on (decrements) a semaphore
 *
 * @param pSid - semaphore handle
 * @param timeout - timeout, in ms; OSAL_WAIT_FOREVER (-1) if the thread
 * is to block indefinitely or OSAL_WAIT_NONE (0) if the thread is to
 * return immediately even if the call fails
 *
 * Decrements a semaphore, blocking if the semaphore is
 * unavailable (value is 0).
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreWait(OsalSemaphore *pSid, INT32 timeout);

/**
 * @ingroup IxOsal
 *
 * @brief Non-blocking wait on semaphore
 *
 * @param semaphore - semaphore handle
 *
 * Decrements a semaphore, not blocking the calling thread if the semaphore
 * is unavailable
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreTryWait(OsalSemaphore *semaphore);

/**
 * @ingroup Osal
 *
 * @brief Posts to (increments) a semaphore
 *
 * @param pSid - semaphore handle
 *
 * Increments a semaphore object
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphorePost(OsalSemaphore *pSid);

/**
 * @ingroup Osal
 *
 * @brief Gets semaphore value
 *
 * @param sid - semaphore handle
 * @param value - location to store the semaphore value
 *
 * Retrieves the current value of a semaphore object
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreGetValue(OsalSemaphore *sid,
                                              UINT32 *value);

/**
 * @ingroup Osal
 *
 * @brief initializes a pMutex
 *
 * @param pMutex - pMutex handle
 *
 * Initializes a pMutex object
 * @note Mutex initialization OsalMutexInit API must be called
 * first before using any OSAL Mutex APIs
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalMutexInit(OsalMutex *pMutex);

/**
 * @ingroup Osal
 *
 * @brief locks a pMutex
 *
 * @param pMutex - pMutex handle
 * @param timeout - timeout in ms; OSAL_WAIT_FOREVER (-1) to wait forever
 *                  or OSAL_WAIT_NONE to return immediately
 *
 * Locks a pMutex object
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalMutexLock(OsalMutex *pMutex, INT32 timeout);

/**
 * @ingroup Osal
 *
 * @brief Unlocks a pMutex
 *
 * @param pMutex - pMutex handle
 *
 * Unlocks a pMutex object
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalMutexUnlock(OsalMutex *pMutex);

/**
 * @ingroup Osal
 *
 * @brief Destroys a pMutex object
 *
 * @param pMutex - pMutex handle
 *
 * Destroys a pMutex object; the caller should ensure that no thread is
 * blocked on this pMutex. If call made when thread blocked on pMutex the
 * behaviour is unpredictable
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalMutexDestroy(OsalMutex *pMutex);

/**
 * @ingroup Osal
 *
 * @brief Non-blocking attempt to lock a pMutex
 *
 * @param pMutex - pMutex handle
 *
 * Attempts to lock a pMutex object, returning immediately with OSAL_SUCCESS if
 * the lock was successful or OSAL_FAIL if the lock failed
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_PUBLIC OSAL_STATUS osalMutexTryLock(OsalMutex *pMutex);

/**
 * @ingroup Osal
 *
 * @brief Creates a new thread
 *
 * @param pTid - handle of the thread to be created
 * @param threadAttr - pointer to a thread attribute object
 * @param entryPoint - thread entry point
 * @param arg - argument to be passed to the startRoutine
 *
 * Creates a thread given a thread handle and a thread attribute object. The
 * same thread attribute object can be used to create separate threads. "NULL"
 * can be specified as the attribute, in which case the default values will
 * be used. The thread needs to be explicitly started using osalThreadStart().
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 * @note In certain operating systems, this API function will both create and
 * start a thread in the same call.
 */
OSAL_PUBLIC OSAL_STATUS osalThreadCreate(OsalThread *pTid,
                                         OsalThreadAttr *threadAttr,
                                         OsalVoidFnVoidPtr entryPoint,
                                         void *arg);

/**
 * @ingroup Osal
 *
 * @brief Sticks the thread to a specific CPU
 *
 * @param pTid - handle of the thread to be binded
 * @param cpu - the number of the CPU
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - None
 */
OSAL_PUBLIC void osalThreadBind(OsalThread *pTid, UINT32 cpu);

/**
 * @ingroup Osal
 *
 * @brief Starts a newly created thread
 *
 * @param pTid - handle of the thread to be started
 *
 * Starts a thread given its thread handle. This function is to be called
 * only once, following the thread initialization.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalThreadStart(OsalThread *pTid);

/**
 * @ingroup Osal
 *
 * @brief Sets the priority of a thread
 *
 * @param pTid - handle of the thread
 * @param priority - new priority, between 0 and 255 (0 being the highest)
 *
 * Sets the thread priority
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalThreadPrioritySet(OsalThread *pTid,
                                              UINT32 priority);

OSAL_PUBLIC OSAL_STATUS osalThreadSetPolicyAndPriority(OsalThread *thread,
                                                       UINT32 policy,
                                                       UINT32 priority);

/**
 * @ingroup Osal
 *
 * @brief Terminates a thread execution
 *
 * @param pTid - handle of the thread to be terminated
 *
 * Kills a thread given its thread handle.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @note This function does not guarantee to kill the thread immediately.
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL/OSAL_UNSUPPORTED depending on implementation
 */
OSAL_PUBLIC OSAL_STATUS osalThreadKill(OsalThread *pTid);

/**
 * @ingroup Osal
 *
 * @brief Exits a running thread
 *
 * Terminates the calling thread
 *
 * @li Reentrant: yes
 * @li IRQ safe:  no
 *
 * @return - This function never returns
 */
OSAL_PUBLIC void osalThreadExit(void);

/**
 * @ingroup Osal
 *
 * @brief  map physical memory into virtual address space
 *
 * @param  physAddr - physical address to map
 * @param  size     - size of the memory to map
 *
 * @return start address of the virtual memory zone.
 *
 */
OSAL_PUBLIC UARCH_INT osalIoRemap(UINT64 physAddr, UINT32 size);

/**
 * @ingroup Osal
 *
 * @brief  unmap virtual address space which was mapped using osalIoRemap
 *
 * @param  virtAddr - virtual address
 *
 * Return value: void
 *
 */
OSAL_PUBLIC void osalIoUnmap(UARCH_INT virtAddr, UINT32 size);

/**
 * @ingroup Osal
 *
 * @brief  Calculate MD5 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least md5 block size long as defined in
 *         rfc1321 (64 bytes)
 *         out - output pointer for state data after single md5 transform
 *         operation.
 *         The buffer needs to be at least md5 state size long as defined in
 *         rfc1321 (16 bytes)
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashMD5(UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Calculate MD5 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least md5 block size long as defined in
 *         rfc1321 (64 bytes)
 *         out - output pointer for state data after single md5 transform
 *         operation.
 *         The buffer needs to be at least md5 state size long as defined in
 *         rfc1321 (16 bytes)
 *         len - Length on the input to be processed.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashMD5Full(UINT8 *in, UINT8 *out, UINT32 len);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA1 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha1 block size long as defined in
 *         rfc3174 (64 bytes)
 *         out - output pointer for state data after single sha1 transform
 *         operation.
 *         The buffer needs to be at least sha1 state size long as defined in
 *         rfc3174 (20 bytes)
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA1(UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA1 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha1 block size long as defined in
 *         rfc3174 (64 bytes)
 *         out - output pointer for state data after single sha1 transform
 *         operation.
 *         The buffer needs to be at least sha1 state size long as defined in
 *         rfc3174 (20 bytes)
 *         len - Length on the input to be processed.
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA1Full(UINT8 *in, UINT8 *out, UINT32 len);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA224 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha224 block size long as defined in
 *         rfc3874 and rfc4868 (64 bytes)
 *         out - output pointer for state data after single sha224 transform
 *         operation.
 *         The buffer needs to be at least sha224 state size long as defined in
 *         rfc3874 and rfc4868 (32 bytes)
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA224(UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA256 transform operation
 *
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha256 block size long as defined in
 *         rfc4868 (64 bytes)
 *         out - output pointer for state data after single sha256 transform
 *         operation.
 *         The buffer needs to be at least sha256 state size long as defined in
 *         rfc4868 (32 bytes)
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA256(UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA256 transform operation
 *
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha256 block size long as defined in
 *         rfc4868 (64 bytes)
 *         out - output pointer for state data after single sha256 transform
 *         operation.
 *         The buffer needs to be at least sha256 state size long as defined in
 *         rfc4868 (32 bytes)
 *         len - Length on the input to be processed.
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA256Full(UINT8 *in, UINT8 *out, UINT32 len);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA384 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha384 block size long as defined in
 *         rfc4868 (128 bytes)
 *         out - output pointer for state data after single sha384 transform
 *         operation.
 *         The buffer needs to be at least sha384 state size long as defined in
 *         rfc4868 (64 bytes)
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA384(UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA384 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha384 block size long as defined in
 *         rfc4868 (128 bytes)
 *         out - output pointer for state data after single sha384 transform
 *         operation.
 *         The buffer needs to be at least sha384 state size long as defined in
 *         rfc4868 (64 bytes)
 *         len - Length on the input to be processed.
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA384Full(UINT8 *in, UINT8 *out, UINT32 len);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA512 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha512 block size long as defined in
 *         rfc4868 (128 bytes)
 *         out - output pointer for state data after single sha512 transform
 *         operation.
 *         The buffer needs to be at least sha512 state size long as defined in
 *         rfc4868 (64 bytes)
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA512(UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Calculate SHA512 transform operation
 *
 * @param  in - pointer to data to be processed.
 *         The buffer needs to be at least sha512 block size long as defined in
 *         rfc4868 (128 bytes)
 *         out - output pointer for state data after single sha512 transform
 *         operation.
 *         The buffer needs to be at least sha512 state size long as defined in
 *         rfc4868 (64 bytes)
 *         len - Length on the input to be processed.
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalHashSHA512Full(UINT8 *in, UINT8 *out, UINT32 len);

/**
 * @ingroup Osal
 *
 * @brief  Single block AES encrypt
 *
 * @param  key - pointer to symetric key.
 *         keyLenInBytes - key lenght
 *         in - pointer to data to encrypt
 *         out - pointer to output buffer for encrypted text
 *         The in and out buffers need to be at least AES block size long
 *         as defined in rfc3686 (16 bytes)
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalAESEncrypt(UINT8 *key, UINT32 keyLenInBytes, UINT8 *in, UINT8 *out);

/**
 * @ingroup Osal
 *
 * @brief  Converts AES forward key to reverse key
 *
 * @param  key - pointer to symetric key.
 *         keyLenInBytes - key length
 *         out - pointer to output buffer for reversed key
 *         The in and out buffers need to be at least AES block size long
 *         as defined in rfc3686 (16 bytes)
 *
 * @li Reentrant: yes
 * @li IRQ safe:  yes
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS
osalAESKeyExpansionForward(UINT8 *key, UINT32 keyLenInBytes, UINT32 *out);

/**
 * @ingroup Osal
 *
 * @brief  Crypto interface init function
 *
 * @param  void
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 *
 */
OSAL_STATUS osalCryptoInterfaceInit(void);

/**
 * @ingroup Osal
 *
 * @brief  Crypto interface exit function
 *
 * @param  void
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - void
 *
 */
void osalCryptoInterfaceExit(void);

       /**
        * @ingroup Osal
        *
        * @brief  Function adds mapping from io virtual address
        *         to a physical address.
        *
        * @param  in - Host phisical address.
        *         in - IO virtual address.
        *         in - Memory size to be remapped obtained from
        *              osalIOMMUgetRemappingSize() function.
        *
        * @li Reentrant: no
        * @li IRQ safe:  no
        *
        * @return - OSAL_SUCCESS/OSAL_FAIL
        */
int osalIOMMUMap(UINT64 phaddr, UINT64 iova, size_t size);

/**
 * @ingroup Osal
 *
 * @brief  Function removes mapping from io virtual
 *         address to a physical address.
 *
 * @param  in - IO virtual address.
 *         in - Memory size to be remapped obtained from
 *              osalIOMMUgetRemappingSize() function.
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
int osalIOMMUUnmap(UINT64 iova, size_t size);

/**
 * @ingroup Osal
 *
 * @brief  Function translates io virtual address
 *         to a physical address.
 *
 * @param  in - IO virtual address.
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - host physical address
 */
UINT64 osalIOMMUVirtToPhys(UINT64 iova);

/**
 * @ingroup Osal
 *
 * @brief  Function attaches pci dev to iommu domain.
 *
 * @param  in - Device to be attached.
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
int osalIOMMUAttachDev(void *dev);

/**
 * @ingroup Osal
 *
 * @brief  Function detaches pci dev to iommu domain.
 *
 * @param  in - Device to be detached.
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - void
 */
void osalIOMMUDetachDev(void *dev);

/**
 * @ingroup Osal
 *
 * @brief  Function calculates size for remapping.
 *
 * @param  in - size.
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - Remapping size.
 */
size_t osalIOMMUgetRemappingSize(size_t size);

/**
 * @ingroup Osal
 *
 * @brief  Function creates iommu domain.
 *
 * @param  none
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
int osalIOMMUInit(void);

/**
 * @ingroup Osal
 *
 * @brief  Function removes iommu domain.
 *
 * @param  none
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - void
 */
void osalIOMMUExit(void);

/**
 * @ingroup Osal
 *
 * @brief  Function saves pci configuration.
 *
 * @param  in - pci device with configuration data to be saved
 *         in - node number
 *         out - pointer to the pointer of saved data
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - pointer to memory on heap with saved data or NULL
 */
void *osalPCIStateStore(void *dev, UINT32 node);

/**
 * @ingroup Osal
 *
 * @brief  Function restores pci configuration.
 *
 * @param  in - pci device with configuration to be restored
 *         in - pointer to the saved data
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - OSAL_SUCCESS/OSAL_FAIL
 */
OSAL_STATUS
osalPCIStateRestore(void *dev, void *state);

/**
 * @ingroup Osal
 *
 * @brief  Function sets PCIe Capabilities Offset
 *
 * Set PCIe Capabilities Offset
 *
 * @param  in - dev pci device
 *
 * @li Reentrant: no
 * @li IRQ safe:  no
 *
 * @return - none
 */
void osalSetPCICapabilitiesOffset(void *dev);


#ifdef __cplusplus
}
#endif

#endif
