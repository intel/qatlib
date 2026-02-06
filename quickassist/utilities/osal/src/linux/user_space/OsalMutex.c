/**
 * @file OsalMutex.c (user space)
 *
 * @brief Implementation for Mutexes.
 *
 *
 * @par
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

#include <time.h>
#include "Osal.h"

OSAL_PUBLIC OSAL_STATUS osalMutexInit(OsalMutex *mutex)
{
#ifndef ICP_WITHOUT_THREAD
    pthread_mutex_t *pMutex;
    if (NULL == mutex)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "OsalMutexInit: NULL Mutex handle \n");

        return OSAL_FAIL;
    }

    pMutex = (pthread_mutex_t *)osalMemAlloc(sizeof(pthread_mutex_t));

    if (!(pMutex))
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "OsalMutexInit: fail to allocate for Mutex \n");

        return OSAL_FAIL;
    }

    if (pthread_mutex_init(pMutex, NULL) != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "OsalMutexInit: mutex init failed\n");

        /* free the allocated pthread_mutex_t structure */
        osalMemFree((void *)pMutex);
        return OSAL_FAIL;
    }
    *mutex = pMutex;
#else
    *mutex = osalMemAlloc(sizeof(OsalMutex));
#endif
    return OSAL_SUCCESS;
}

/*
 * timeout expressed in milliseconds.
 */
OSAL_PUBLIC OSAL_STATUS osalMutexLock(OsalMutex *mutex, INT32 timeout)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_STATUS status;
    OsalTimeval timeoutVal;
    OsalTimeval currTime;
    struct timespec tspec;

    OSAL_PTR_ENSURE(mutex, "osalMutexLock():   Null mutex pointer", OSAL_FAIL);

    if ((timeout < 0) && (timeout != OSAL_WAIT_FOREVER))
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "OsalMutexLock(): illegal timeout value \n");

        return OSAL_FAIL;
    }

    if (timeout == OSAL_WAIT_NONE)
    {
        status = pthread_mutex_trylock(*mutex);
        if (status)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "OsalMutexLock(): Failed to Lock Mutex \n");

            return OSAL_FAIL;
        }
    }
    else if (timeout == OSAL_WAIT_FOREVER)
    {
        status = pthread_mutex_lock(*mutex);
        if (status)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "OsalMutexLock(): Failed to Lock Mutex \n");

            return OSAL_FAIL;
        }
    }
    else /* Finite Timeout case */
    {
        /*
         * Convert the inputted time into appropriate timespec struct.
         * Since timespec and OSAL timeval are of the the same type.
         * Reuse the timeval to timespec macros.
         */
        OSAL_MS_TO_TIMEVAL(timeout, &timeoutVal);

        /* Get the current timestamp */
        if (OSAL_SUCCESS != osalTimeGet(&currTime))
        {
            return OSAL_FAIL;
        }

        /* Add this to the timeout so that it gives absolute
         * timeout value... */
        OSAL_TIME_ADD(timeoutVal, currTime);
        /* ...and assign it to the timespec structure */
        tspec.tv_sec = timeoutVal.secs;
        tspec.tv_nsec = timeoutVal.nsecs;
        status = pthread_mutex_timedlock(*mutex, &tspec);

        if (status)
        {
            osalLog(OSAL_LOG_LVL_ERROR,
                    OSAL_LOG_DEV_STDOUT,
                    "OsalMutexLock(): Failed to Lock Mutex \n");

            return OSAL_FAIL;
        }
    }
#endif
    return OSAL_SUCCESS;
}

OSAL_PUBLIC OSAL_STATUS osalMutexUnlock(OsalMutex *mutex)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_STATUS status;

    OSAL_PTR_ENSURE(
        mutex, "osalMutexUnlock():   Null mutex pointer", OSAL_FAIL);

    status = pthread_mutex_unlock(*mutex);
    if (status)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "OsalMutexUnlock(): Failed to Unlock Mutex \n");

        return OSAL_FAIL;
    }
#endif
    return OSAL_SUCCESS;
}

OSAL_PUBLIC OSAL_STATUS osalMutexDestroy(OsalMutex *mutex)
{
#ifndef ICP_WITHOUT_THREAD
    OSAL_STATUS status;

    OSAL_PTR_ENSURE(
        mutex, "osalMutexDestroy():   Null mutex pointer", OSAL_FAIL);

    status = pthread_mutex_destroy(*mutex);
    if (!status)
    {
        /* free the associated mutex structure */
        osalMemFree((void *)*mutex);
        *mutex = NULL;
    }
    else
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "OsalMutexDestroy(): Failed to Destroy Mutex \n");
    }
    return (status ? OSAL_FAIL : OSAL_SUCCESS);
#else
    osalMemFree((void *)*mutex);
    return OSAL_SUCCESS;
#endif
}
