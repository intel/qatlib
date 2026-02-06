/**
 * @file OsalSpinLock.c (linux user space)
 *
 * @brief Implementation for spinlocks
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

OSAL_PUBLIC OSAL_STATUS osalLockInit(OsalLock *slock, OsalLockType slockType)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_LOCAL_ENSURE(
        slock, "osalLockInit():   Null spinlock pointer", OSAL_FAIL);

    /* Spinlock type is ignored in case of Linux */
    return pthread_spin_init(slock, PTHREAD_PROCESS_PRIVATE) ? OSAL_FAIL
                                                             : OSAL_SUCCESS;
#else
    return OSAL_SUCCESS;
#endif
}

OSAL_PUBLIC OSAL_STATUS osalLock(OsalLock *slock)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_LOCAL_ENSURE(
        slock, "osalLockLock():   Null spinlock pointer", OSAL_FAIL);

    return pthread_spin_lock(slock) ? OSAL_FAIL : OSAL_SUCCESS;
#else
    return OSAL_SUCCESS;
#endif
}

OSAL_PUBLIC OSAL_STATUS osalUnlock(OsalLock *slock)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_LOCAL_ENSURE(
        slock, "osalLockUnlock():   Null spinlock pointer", OSAL_FAIL);

    return pthread_spin_unlock(slock) ? OSAL_FAIL : OSAL_SUCCESS;
#else
    return OSAL_SUCCESS;
#endif
}

OSAL_PUBLIC OSAL_STATUS osalLockDestroy(OsalLock *slock)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_LOCAL_ENSURE(
        slock, "osalLockDestroy():   Null spinlock pointer", OSAL_FAIL);

    return pthread_spin_destroy(slock) ? OSAL_FAIL : OSAL_SUCCESS;
#else
    return OSAL_SUCCESS;
#endif
}

OSAL_PUBLIC OSAL_STATUS osalLockBh(OsalLock *slock)
{
    return osalLock(slock);
}

OSAL_PUBLIC OSAL_STATUS osalUnlockBh(OsalLock *slock)
{
    return osalUnlock(slock);
}
