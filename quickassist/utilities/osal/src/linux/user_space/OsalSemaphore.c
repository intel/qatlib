/**
 * @file OsalSemaphore.c (linux user space)
 *
 * @brief Implementation for semaphore.
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

#include <semaphore.h>
#include <time.h>
#include "Osal.h"

/**********************************************
 * OSAL Semaphore Functions implemented using
 * POSIX interfaces.
 *********************************************/
/*
 *   Initializes a semaphore object
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreInit(OsalSemaphore *sid,
                                          UINT32 start_value)
{
    OSAL_LOCAL_ENSURE(
        sid, "osalSemaphoreInit():   Null semaphore pointer", OSAL_FAIL);
    /*
     *  Allocate memory for the sempahore object.
     */
    *sid = osalMemAlloc(sizeof(sem_t));
    if (!(*sid))
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "osalSemaphoreInit: fail to allocate for semaphore \n");

        return OSAL_FAIL;
    }

    /*
     *  Initialize the semaphore object.
     */
    if (sem_init(*sid, OSAL_POSIX_UNSHARED_SEMAPHORE, start_value) == -1)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "osalSemaphoreInit: Failed to \
                   initialize semaphore, exceeds the max counter value %d \n",
                SEM_VALUE_MAX);

        osalMemFree(*sid);
        *sid = NULL;
        return OSAL_FAIL;
    }

    return OSAL_SUCCESS;
}

/*
 * Decrements a semaphore, blocking if the
 * semaphore is unavailable (value is 0).
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreWait(OsalSemaphore *sid, INT32 timeout)
{
    INT32 status;
    OsalTimeval timeoutVal, currTime;
    struct timespec ts;

    OSAL_LOCAL_ENSURE(
        sid, "osalSemaphoreWait():   Null semaphore pointer", OSAL_FAIL);

    /*
     * Guard against illegal timeout values
     * OSAL_WAIT_FORVER = -1
     */
    if (timeout < OSAL_WAIT_FOREVER)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "osalSemaphoreWait(): illegal timeout value \n");
        return OSAL_FAIL;
    }
    /*
     * The return value can take OSAL_SUCCESS or OSAL_FAIL.
     * For this reason the caller can not distinguish
     * between recoverable/unrecoverable errors.
     * Semaphore wait can be interrupted, which is a
     * recoverable error; the retry is implemented
     * in OSAL with a loop.
     */
    if (timeout == OSAL_WAIT_FOREVER)
    {
        do
        {
            status = sem_wait(*sid);
        } while (status < 0 && EINTR == errno);
    }
    else if (timeout == OSAL_WAIT_NONE)
    {
        do
        {
            status = sem_trywait(*sid);
        } while (status < 0 && EINTR == errno);
    }
    else
    {
        /*
         * Convert the inputted time into appropriate timespec struct.
         * Since timespec and OSAL timeval are of the the same type.
         * Reuse the timeval to timespec macros.
         */
        OSAL_MS_TO_TIMEVAL(timeout, &timeoutVal);

        /* Get current time */
        if (OSAL_SUCCESS != osalTimeGet(&currTime))
        {
            return OSAL_FAIL;
        }

        /* Add this to the timeout so that it gives absolute timeout value */
        OSAL_TIME_ADD(timeoutVal, currTime);

        do
        {
            ts.tv_sec = timeoutVal.secs;
            ts.tv_nsec = timeoutVal.nsecs;
            status = sem_timedwait(*sid, &ts);
        } while ((status == -1) && (errno == EINTR));
    }

    if (status < 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "osalSemaphoreWait(): %s\n",
                strerror(errno));
        return OSAL_FAIL;
    }
    else
    {
        return OSAL_SUCCESS;
    }
}

/*
 *  Increments a semaphore object
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphorePost(OsalSemaphore *sid)
{
    INT32 status;

    OSAL_LOCAL_ENSURE(
        sid, "osalSemaphorePost():   Null semaphore pointer", OSAL_FAIL);

    /*
     *  Increment the semaphore object.
     */
    status = sem_post(*sid);

    if (status < 0)
    {
        return OSAL_FAIL;
    }
    else
    {
        return OSAL_SUCCESS;
    }
}

/*
 * Destroys the semaphore object
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreDestroy(OsalSemaphore *sid)
{
    INT32 status;

    OSAL_LOCAL_ENSURE(
        sid, "osalSemaphoreDestroy():   Null semaphore pointer", OSAL_FAIL);
    /*
     * Destory the semaphore object.
     */
    status = sem_destroy(*sid);

    if (status != 0)
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDOUT,
                "osalSemaphoreDestroy() : Semaphore Destroy failed\n");
        return OSAL_FAIL;
    }

    /*
     * Free space allocated for the semaphore object.
     */
    osalMemFree(*sid);

    *sid = NULL;

    return OSAL_SUCCESS;
}

/*
 * Decrements a semaphore, not blocking the calling thread
 * if the semaphore is unavailable
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreTryWait(OsalSemaphore *sid)
{
    OSAL_LOCAL_ENSURE(
        sid, "osalSemaphoreTryWait():   Null semaphore pointer", OSAL_FAIL);
    if (sem_trywait(*sid))
    {
        return OSAL_FAIL;
    }
    else
    {
        return OSAL_SUCCESS;
    }
}

/*
 * Retrieves the current value of a semaphore object
 */
OSAL_PUBLIC OSAL_STATUS osalSemaphoreGetValue(OsalSemaphore *sid, UINT32 *value)
{
    OSAL_LOCAL_ENSURE(
        sid, "osalSemaphoreTryWait():   Null semaphore pointer", OSAL_FAIL);
    if (sem_getvalue(*sid, (int *)value))
    {
        return OSAL_FAIL;
    }
    else
    {
        return OSAL_SUCCESS;
    }
}
