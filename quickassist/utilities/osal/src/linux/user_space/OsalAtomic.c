/**
 * @file OsalAtomic.c (user space)
 *
 * @brief OS-specific Atomics implementation.
 *
 *
 * @par
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
