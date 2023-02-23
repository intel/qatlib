/**
 * @file OsalAtomic.c (user space)
 *
 * @brief OS-specific Atomics implementation.
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

#include "Osal.h"

#if defined(__GNUC__) && !defined(__llvm__) && !defined(__INTEL_COMPILER)
#define GCC_VER (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#else
#define GCC_VER 0
#endif

OSAL_PUBLIC OSAL_INLINE INT64 osalAtomicGet(OsalAtomic *atomicVar)
{
#if GCC_VER >= 40700
    return __atomic_load_n(atomicVar, __ATOMIC_ACQUIRE);
#else
    return __sync_fetch_and_and(atomicVar, (INT64)0xFFFFFFFFFFFFFFFFULL);
#endif
}

OSAL_PUBLIC OSAL_INLINE void osalAtomicSet(INT64 inValue, OsalAtomic *atomicVar)
{
    __sync_lock_test_and_set(atomicVar, inValue);
}

OSAL_PUBLIC OSAL_INLINE INT64 osalAtomicTestAndSet(INT64 inValue,
                                                   OsalAtomic *pAtomicVar)
{
    return __sync_lock_test_and_set(pAtomicVar, inValue);
}

OSAL_PUBLIC OSAL_INLINE void osalAtomicRelease(OsalAtomic *pAtomicVar)
{
    __sync_lock_release(pAtomicVar);
}

OSAL_PUBLIC OSAL_INLINE INT64 osalAtomicAdd(INT64 inValue,
                                            OsalAtomic *atomicVar)
{
    return __sync_add_and_fetch(atomicVar, inValue);
}

OSAL_PUBLIC OSAL_INLINE INT64 osalAtomicSub(INT64 inValue,
                                            OsalAtomic *atomicVar)
{
    return __sync_sub_and_fetch(atomicVar, inValue);
}

OSAL_PUBLIC OSAL_INLINE INT64 osalAtomicInc(OsalAtomic *atomicVar)
{
    return __sync_add_and_fetch(atomicVar, 1);
}

OSAL_PUBLIC OSAL_INLINE INT64 osalAtomicDec(OsalAtomic *atomicVar)
{
    return __sync_sub_and_fetch(atomicVar, 1);
}

OSAL_PUBLIC OSAL_INLINE OSAL_STATUS osalAtomicDecAndTest(OsalAtomic *atomicVar)
{
    return (OSAL_STATUS)(__sync_sub_and_fetch(atomicVar, 1) == 0);
}
