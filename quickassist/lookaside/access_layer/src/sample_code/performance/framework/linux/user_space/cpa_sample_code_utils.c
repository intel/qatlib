
/******************************************************************************
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
 *****************************************************************************/

/**
*****************************************************************************
* @file cpa_sample_code_utils.c
*
* This file provides linux kernel os abstraction functions
*
*****************************************************************************/

#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_utils_common.h"
#include "icp_sal_poll.h"

#include <string.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/utsname.h>
#include <errno.h>
#include <utmpx.h>
#include <asm/param.h>
#include <sys/epoll.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#define EPOLL_MAX_EVENTS 1
#define _4K_PAGE_SIZE (4 * 1024)

#if UINT_MAX == 0xFFFFFFFF
typedef unsigned uint32_t;
#endif

volatile Cpa32U numArrivedThreads_g;
extern volatile Cpa32U numCreatedThreads_g;
extern int verboseOutput;
extern sample_code_thread_mutex_t threadControlMutex_g;
extern sample_code_thread_cond_t threadConditionControl_g;

extern sample_code_thread_mutex_t startThreadControlMutex_g;
extern sample_code_thread_cond_t startThreadConditionControl_g;

extern CpaBoolean dc_service_started_g;
extern CpaBoolean cy_service_started_g;

extern volatile Cpa32U numThreadsAtBarrier_g;

Cpa32U cpu_freq_g = 0;

extern volatile CpaBoolean isChangingThreadQaInstanceRequired_g;

static char *firmwarePath = SAMPLE_CODE_CORPUS_PATH;

sample_code_thread_barrier_t barr;

#define UPPER_HALF_OF_REGISTER (32)

// check GLIBC version used.
#define GLIBC_VERSION_AT_LEAST(major, minor)                                   \
    (__GLIBC__ > major || (__GLIBC__ == major && __GLIBC_MINOR__ >= minor))

static __inline__ Cpa64U sampleCoderdtsc(void)
{
    volatile unsigned long a, d;

    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (((Cpa64U)a) | (((Cpa64U)d) << UPPER_HALF_OF_REGISTER));
}

ChipRec_u64 getCPUTick()
{
    //================================================== =
    // Use RDTSC To Read CPU Time Stamp Counter
    //================================================== =
    ChipRec_u64 u64Ret;
    __asm__ __volatile__("rdtsc" : "=A"(u64Ret) :);
    return u64Ret;
}

#define __CPUID(in, a, b, c, d)                                                \
    asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(in));

static __inline__ void sampleCodeCpuid(void)
{
    unsigned int a = 0x00, b = 0x00, c = 0x00, d = 0x00;
    __CPUID(0x00, a, b, c, d);
}

static __inline__ Cpa64U sampleCodeRdtscp(void)
{
    Cpa64U returnval = 0;
#ifdef __x86_64__
    volatile unsigned long a = 0, d = 0;

    sampleCodeCpuid();
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    returnval = (((Cpa64U)d) << UPPER_HALF_OF_REGISTER);
    returnval |= ((Cpa64U)a);
#else
    asm volatile("rdtsc" : "=A"(returnval));
#endif
    return returnval;
}

perf_cycles_t sampleCodeTimestamp(void)
{
    /*get time stamp twice, because we need to prime the timestamp counter*/
    sampleCodeRdtscp();
    return (perf_cycles_t)sampleCodeRdtscp();
}

void sampleCodeSleep(Cpa32U seconds)
{
    sleep(seconds);
}

static void sampleCodeSleepUsingNanoSleep(Cpa32U milliseconds,
                                          Cpa32U nanoseconds)
{
    struct timespec reqTime;
    struct timespec tmleft;
    int ret;

    reqTime.tv_sec = milliseconds / NUM_MILLISEC_IN_SEC;
    reqTime.tv_nsec = nanoseconds + ((milliseconds % NUM_MILLISEC_IN_SEC) *
                                     NUM_NANOSEC_IN_MILLISEC);
    do
    {
        ret = nanosleep(&reqTime, &tmleft);
        reqTime = tmleft;
    } while (ret != 0 && errno == EINTR);

    if (ret != 0)
    {
        PRINT_ERR("Failed to Sleep! errno:%d\n", errno);
    }

    return;
}

void sampleCodeSleepMilliSec(Cpa32U milliseconds)
{
    sampleCodeSleepUsingNanoSleep(milliseconds, 0);
}

void sleepNano(Cpa32U nanoseconds)
{
    sampleCodeSleepUsingNanoSleep(0, nanoseconds);
}

Cpa32U sampleCodeGetNumberOfCpus(void)
{
    return (Cpa32U)sysconf(_SC_NPROCESSORS_ONLN);
}

#include <sys/time.h>

ChipRec_u32 timeGetTime(void)
{
    //================================================== =
    // Using Linux Time Functions To Determine Time
    //================================================== =
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

Cpa32U getCPUSpeed()
{
    ChipRec_s64 startTick, endTick;
    static Cpa32U cpuSpeed = 0;

    if (cpuSpeed == 0)
    {
        /*get the number of ticks in 1 second*/
        startTick = getCPUTick();
        sampleCodeSleep(1);
        endTick = getCPUTick();
        cpuSpeed = endTick - startTick;
    }
    cpu_freq_g = cpuSpeed / 1000;
    //================================================== =
    // Return The Processors Speed In Hertz
    //================================================== =
    return cpuSpeed;
}

Cpa32U updateCPUSpeed()
{
    ChipRec_s64 startTick, endTick;
    Cpa32U cpuSpeed = 0;
    /*get the number of ticks in 1 second*/
    startTick = getCPUTick();
    sampleCodeSleep(1);
    endTick = getCPUTick();
    cpuSpeed = endTick - startTick;
    cpu_freq_g = cpuSpeed / 1000;
    return cpuSpeed;
}

Cpa32U sampleCodeGetCpuFreq()
{
    return cpu_freq_g;
}

void generateRandomData(Cpa8U *pWriteRandData, Cpa32U lengthOfRand)
{
    Cpa32U i = 0;
    srand(sampleCoderdtsc());
    for (i = 0; i < lengthOfRand; i++)
    {
        pWriteRandData[i] = (Cpa8U)rand();
    }
}

CpaStatus sampleCodeThreadCreate(sample_code_thread_t *thread,
                                 sample_code_thread_attr_t *threadAttr,
                                 performance_func_t function,
                                 void *params)
{
    // CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    // CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(function);

    int status = 1;
    pthread_attr_t attr;
    struct sched_param param;
    Cpa32U pmin = 0;
    Cpa32U pmax = 0;

    status = pthread_attr_init(&attr);
    if (status != 0)
    {
        PRINT_ERR("%d\n", errno);
        return CPA_STATUS_FAIL;
    }

    /* Setting scheduling parameter will fail for non root user,
     * as the default value of inheritsched is PTHREAD_EXPLICIT_SCHED in
     * POSIX. It is not required to set it explicitly before setting the
     * scheduling policy */

    if (threadAttr == NULL)
    {
        status = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        if (status != 0)
        {
            pthread_attr_destroy(&attr);
            PRINT_ERR("%d\n", errno);
            return CPA_STATUS_FAIL;
        }

        status =
            pthread_attr_setschedpolicy(&attr, THREAD_DEFAULT_SCHED_POLICY);
        if (status != 0)
        {
            pthread_attr_destroy(&attr);
            PRINT_ERR("%d\n", errno);
            return CPA_STATUS_FAIL;
        }

        /* Set priority based on value in threadAttr */
        memset(&param, 0, sizeof(param));
        param.sched_priority = THREAD_PRIORITY_SCHED_OTHER;

        status = pthread_attr_setschedparam(&attr, &param);
        if (status != 0)
        {
            pthread_attr_destroy(&attr);
            PRINT_ERR("%d\n", errno);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        /* Set scheduling policy based on value in threadAttr */

        if ((threadAttr->policy != SCHED_RR) &&
            (threadAttr->policy != SCHED_FIFO) &&
            (threadAttr->policy != SCHED_OTHER))
        {
            threadAttr->policy = THREAD_DEFAULT_SCHED_POLICY;
        }

        status = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        if (status != 0)
        {
            PRINT_ERR("%d\n", errno);
            pthread_attr_destroy(&attr);
            return CPA_STATUS_FAIL;
        }

        status = pthread_attr_setschedpolicy(&attr, threadAttr->policy);
        if (status != 0)
        {
            PRINT_ERR("%d\n", errno);
            pthread_attr_destroy(&attr);
            return CPA_STATUS_FAIL;
        }

        /* Set priority based on value in threadAttr */
        memset(&param, 0, sizeof(param));

        pmin = sched_get_priority_min(threadAttr->policy);
        pmax = sched_get_priority_max(threadAttr->policy);
        if (threadAttr->priority > pmax)
        {
            threadAttr->priority = pmax;
        }
        if (threadAttr->priority < pmin)
        {
            threadAttr->priority = pmin;
        }
        param.sched_priority = threadAttr->priority;
        if (threadAttr->policy != SCHED_OTHER)
        {
            status = pthread_attr_setschedparam(&attr, &param);
            if (status != 0)
            {
                PRINT_ERR("%d\n", errno);
                pthread_attr_destroy(&attr);
                return CPA_STATUS_FAIL;
            }
        }
    }

    status = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (status != 0)
    {
        PRINT_ERR("%d\n", errno);
        pthread_attr_destroy(&attr);
        return CPA_STATUS_FAIL;
    }

    status = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    if (status != 0)
    {
        PRINT_ERR("%d\n", errno);
        pthread_attr_destroy(&attr);
        return CPA_STATUS_FAIL;
    }

    /*pthread_create expects "void *(*start_routine)(void*)" as the 3rd argument
     * but we are calling functions with return void instead of void*, normally
     * the return value of the start_routine contains the exit status, in this
     * sample code we track any internal errors in the start_routine, to allow
     * this to compile we need to cast "function" parameter, this is the same
     * as calling it as  void *(*function)(void*)*/
    status = pthread_create(thread, &attr, (void *(*)(void *))function, params);
    if (status != 0)
    {
        PRINT_ERR("%d\n", errno);
        pthread_attr_destroy(&attr);
        return CPA_STATUS_FAIL;
    }
    /*destroy the thread attributes as they are no longer required, this does
     * not affect the created thread*/
    pthread_attr_destroy(&attr);
    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadBind(sample_code_thread_t *thread, Cpa32U logicalCore)
{
    int status = 1;
    cpu_set_t cpuset;
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    CPU_ZERO(&cpuset);
    CPU_SET(logicalCore, &cpuset);

    status = pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpuset);
    if (status != 0)
    {
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadStart(sample_code_thread_t *thread)
{
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    return CPA_STATUS_SUCCESS;
}

void sampleCodeThreadExit(void)
{
    pthread_exit(NULL);
}

CpaStatus sampleCodeThreadKill(sample_code_thread_t *thread)
{
    Cpa32U status = 0;
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);

    /* To avoid the deadlock, before killing all
     * createdThreads confirm that barrier condition is not
     * waiting for any thread arrival.
     */
    if ((numArrivedThreads_g) && (numArrivedThreads_g >= numCreatedThreads_g))
    {
        sample_code_thread_mutex_lock(&threadControlMutex_g);
        sample_code_thread_cond_broadcast(&threadConditionControl_g);
        sample_code_thread_mutex_unlock(&threadControlMutex_g);
    }

    if (*thread != 0x00)
    {
        status = pthread_cancel(*thread);
    }
    else
    {
        PRINT_ERR("sampleCodeThreadKill: Thread not exist\n");
    }

    if (status)
    {
        PRINT_ERR("sampleCodeThreadKill: Failed to cancel the thread!\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadPrioritySet(sample_code_thread_t *thread,
                                      Cpa32U priority)
{
    Cpa32S status;
    struct sched_param param1;
    int policy1;
    Cpa32U minPrio;
    Cpa32U maxPrio;

    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);

    status = pthread_getschedparam(*thread, &policy1, &param1);
    if (status != 0)
    {
        PRINT_ERR("pthread_getschedparam, failed with status %d\n", status);
        return CPA_STATUS_FAIL;
    }

    minPrio = sched_get_priority_min(policy1);
    maxPrio = sched_get_priority_max(policy1);

    if ((priority < minPrio) || (priority > maxPrio))
    {
        PRINT_ERR("priority outside valid range\n");
        return CPA_STATUS_FAIL;
    }

    status = pthread_setschedprio(*thread, priority);
    if (status != 0)
    {
        PRINT_ERR("pthread_setschedprio, failed with status %d\n", status);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadSetPolicyAndPriority(sample_code_thread_t *thread,
                                               Cpa32U policy,
                                               Cpa32U priority)
{
    CpaStatus status = CPA_STATUS_FAIL;
    struct sched_param param;
    int policy1;
    Cpa32U minPrio, maxPrio;

    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    /* check for a valid value for 'policy' */
    if ((policy != SCHED_RR) && (policy != SCHED_FIFO) &&
        (policy != SCHED_OTHER))
    {
        PRINT_ERR("policy error\n");
        return CPA_STATUS_FAIL;
    }

    memset(&param, 0, sizeof(param));

    status = pthread_getschedparam(*thread, &policy1, &param);
    if (status != 0)
    {
        PRINT_ERR("%d\n", errno);
        return CPA_STATUS_FAIL;
    }

    minPrio = sched_get_priority_min(policy);
    maxPrio = sched_get_priority_max(policy);

    if ((priority < minPrio) || (priority > maxPrio))
    {
        return CPA_STATUS_FAIL;
    }

    param.sched_priority = priority;

    status = pthread_setschedparam(*thread, policy, &param);
    if (status != 0)
    {
        PRINT_ERR("%d\n", errno);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadJoin(sample_code_thread_t *thread)
{
    Cpa32S status = 0;
    status = pthread_join(*thread, NULL);
    if (status != 0)
    {
        PRINT_ERR("pthread_join failed, Error Code: %d - %s\n",
                  status,
                  strerror(status));
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadTimedJoin(sample_code_thread_t *thread,
                                    Cpa64U *pTimeOutInMs)
{
    struct timespec ts = {0};
    Cpa32S status = 0;
#if GLIBC_VERSION_AT_LEAST(2, 17)
    status = clock_gettime(CLOCK_REALTIME, &ts);
    if (status != 0)
    {
        PRINT_ERR("clock_gettime failed, Error Code: %d - %s\n",
                  status,
                  strerror(status));
        return CPA_STATUS_FAIL;
    }
#else
    struct timeval tv = {0};
    status = gettimeofday(&tv, NULL);
    if (status != 0)
    {
        PRINT_ERR("gettimeofday failed, Error Code: %d - %s\n",
                  status,
                  strerror(status));
        return CPA_STATUS_FAIL;
    }
    // converting results from msec to nanonseconds
    TIMEVAL_TO_TIMESPEC(&tv, &ts);
#endif

    ts.tv_sec += *pTimeOutInMs / 1000;
    ts.tv_nsec += (*pTimeOutInMs % 1000) * 1000000;

    status = pthread_timedjoin_np(*thread, NULL, &ts);
    if (status != 0)
    {
        PRINT_ERR("pthread_timedjoin_np failed, Error Code: %d - %s\n",
                  status,
                  strerror(status));
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/**********************************************
 * Time module
 **********************************************/
/*
 *  Retrieve current system time.
 */
CpaStatus sampleCodeTimeTGet(sample_code_time_t *ptime)
{
    struct timeval tval;

    if (gettimeofday(&tval, NULL) == -1)
    {
        PRINT_ERR("sampleCodeTimeTGet(): gettimeofday system call failed \n");

        return CPA_STATUS_FAIL;
    }
    ptime->secs = tval.tv_sec;
    /*
     * gettimeofday returns in terms of sec and uSec.
     * Convert it into sec and nanoseconds into sample_code_time_t type
     */
    ptime->nsecs = tval.tv_usec * 1000;

    return CPA_STATUS_SUCCESS;
}

/********************************************************
 * Semaphore Functions implemented using POSIX interfaces.
 ********************************************************/
/*
 *   Initializes a semaphore object
 */
CpaStatus sampleCodeSemaphoreInit(sample_code_semaphore_t *semPtr,
                                  Cpa32U start_value)
{
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(semPtr);
    /*
     *  Allocate memory for the sempahore object.
     */
    *semPtr = qaeMemAlloc(sizeof(sem_t));
    if (!(*semPtr))
    {
        PRINT_ERR("failed to allocate for semaphore \n");
        return CPA_STATUS_FAIL;
    }

    /*
     *  Initialize the semaphore object.
     */
    if (sem_init(*semPtr, SAMPLECODE_POSIX_SHARED_SEMAPHORE, start_value) == -1)
    {
        PRINT_ERR("sample_code_semaphoreInit Failed to initialize semaphore\n");
        qaeMemFree((void **)&*semPtr);
        *semPtr = NULL;
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * Decrements a semaphore, blocking if the semaphore is unavailable (value is 0)
 */
CpaStatus sampleCodeSemaphoreWait(sample_code_semaphore_t *semPtr,
                                  Cpa32S timeout)
{

    Cpa32S status;
    sample_code_time_t timeoutVal, currTime;

    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(semPtr);
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(*semPtr);

    /*
     * Guard against illegal timeout values
     * WAIT_FORVER = -1
     */
    if (timeout < SAMPLE_CODE_WAIT_FOREVER)
    {
        PRINT_ERR("sample_code_semaphoreWait(): illegal timeout value \n");
        return CPA_STATUS_FAIL;
    }

    if (timeout == SAMPLE_CODE_WAIT_FOREVER)
    {
        status = sem_wait(*semPtr);
    }
    else if (timeout == SAMPLE_CODE_WAIT_NONE)
    {
        status = sem_trywait(*semPtr);
    }
    else
    {
        /*
         * Convert the inputted time into appropriate timespec struct.
         * Since timespec and sample_code_time_t timeval are of the the same
         * type.
         * Reuse the timeval to timespec macros.
         */
        SAMPLE_CODE_TIMEVAL_TO_MS(timeout, &timeoutVal);

        /* Get current time */
        if (CPA_STATUS_SUCCESS != sampleCodeTimeTGet(&currTime))
        {
            return CPA_STATUS_FAIL;
        }
        /* Add this to the timeout so that it gives absolute timeout value */
        SAMPLE_CODE_TIME_ADD(timeoutVal, currTime);

        /*this loop waits until the timeout, when timeout occurs sem_timedwait
         * returns -1 with errno = ETIMEDOUT, EINTR means that some signal
         * caused a premature exit of sem_timedwait and it loops again for the
         * specified timeout*/
        do
        {
            status =
                sem_timedwait(*semPtr, (const struct timespec *)&timeoutVal);
        } while ((status == -1) && (errno == EINTR));
    }

    if (status < 0)
    {
        PRINT_ERR("sample_code_semaphoreWait(): errno: %d \n", errno);
        return CPA_STATUS_FAIL;
    }
    else
    {

        return CPA_STATUS_SUCCESS;
    }
}

/*
 *  Increments a semaphore object
 */
CpaStatus sampleCodeSemaphorePost(sample_code_semaphore_t *semPtr)
{
    Cpa32S status;

    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(semPtr);
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(*semPtr);

    /*
     *  Increment the semaphore object.
     */
    status = sem_post(*semPtr);

    if (status < 0)
    {
        PRINT_ERR("errno: %d\n", errno);
        return CPA_STATUS_FAIL;
    }
    else
    {
        return CPA_STATUS_SUCCESS;
    }
}

/*
 * Destroys the semaphore object
 */
CpaStatus sampleCodeSemaphoreDestroy(sample_code_semaphore_t *semPtr)
{
    Cpa32S Status;

    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(semPtr);
    /*
     * Destroy the semaphore object.
     */
    Status = sem_destroy(*semPtr);

    if (Status != 0)
    {
        PRINT_ERR("sample_code_semaphoreDestroy() : \
                 Semaphore Destroy failed\n");
        return CPA_STATUS_FAIL;
    }

    /*
     * Free space allocated for the semaphore object.
     */
    qaeMemFree((void **)&*semPtr);

    *semPtr = NULL;

    return CPA_STATUS_SUCCESS;
}

void sampleCodeBarrierInit(void)
{
    sample_code_thread_mutex_init(&threadControlMutex_g);
    sample_code_thread_cond_init(&threadConditionControl_g);
    numArrivedThreads_g = 0;
    SampleCodeBarrierLifted = CPA_FALSE;
    getCPUSpeed();
}

void sampleCodeBarrierDestroy(void)
{
    sample_code_thread_mutex_destroy(&threadControlMutex_g);
    sample_code_thread_cond_destroy(&threadConditionControl_g);
    sample_code_thread_mutex_destroy(&startThreadControlMutex_g);
    sample_code_thread_cond_destroy(&startThreadConditionControl_g);
    SampleCodeBarrierLifted = CPA_FALSE;
    numArrivedThreads_g = 0;
}

/*This is a barrier function that all performance threads_g need to call after
 * setting up sessions and population of bufferList, but prior to the "Do Work"
 * functions, this allows all threads_g to be ready and start "Work" all at the
 * same time*/
void sampleCodeBarrier(void)
{
    sample_code_thread_mutex_lock(&threadControlMutex_g);
    numArrivedThreads_g++;
    if (numArrivedThreads_g < numCreatedThreads_g)
    {
        sample_code_thread_cond_wait(&threadConditionControl_g,
                                     &threadControlMutex_g);
    }
    else
    {
        sample_code_thread_cond_broadcast(&threadConditionControl_g);
        SampleCodeBarrierLifted = CPA_TRUE;
    }
    sample_code_thread_mutex_unlock(&threadControlMutex_g);
}

void startBarrierInit(void)
{
    sample_code_thread_mutex_init(&startThreadControlMutex_g);
    sample_code_thread_cond_init(&startThreadConditionControl_g);
}

void startBarrier(void)
{
    sample_code_thread_mutex_lock(&startThreadControlMutex_g);
    /* Count the number of threads reached to barrier for unblock
     * the below condition */

    numThreadsAtBarrier_g++;

    if ((numThreadsAtBarrier_g < numCreatedThreads_g) ||
        (isChangingThreadQaInstanceRequired_g == CPA_TRUE))
    {
        sample_code_thread_cond_wait(&startThreadConditionControl_g,
                                     &startThreadControlMutex_g);
    }
    else
    {
        sample_code_thread_cond_broadcast(&startThreadConditionControl_g);
    }

    sample_code_thread_mutex_unlock(&startThreadControlMutex_g);
}

CpaStatus getCorpusFile(Cpa8U **ppSrcBuff, char *filename, Cpa32U *size)
{
    FILE *corpusFilePtr = NULL;
    long lSize;
    char fullpath[MAX_CORPUS_FILE_PATH_LEN];
    Cpa32S strSize = 0;

    strSize =
        snprintf(fullpath, sizeof(fullpath), "%s%s", firmwarePath, filename);
    CHECK_PARAM_RANGE(strSize, 1, sizeof(fullpath));
    corpusFilePtr = fopen(fullpath, "rb");
    if (corpusFilePtr == NULL)
    {
        PRINT("Could not open corpus file: %s\n", fullpath);
        return CPA_STATUS_FAIL;
    }
    fseek(corpusFilePtr, 0, SEEK_END);
    lSize = ftell(corpusFilePtr);
    if (fseek(corpusFilePtr, 0, SEEK_SET) != 0)
    {
        PRINT("Could not move to beginning of file\n");
        fclose(corpusFilePtr);
        return CPA_STATUS_FAIL;
    }
    *ppSrcBuff = qaeMemAlloc(lSize);

    if (*ppSrcBuff == NULL)
    {
        PRINT("%s:: Can't Allocate Memory for srcBuff!\n", __FUNCTION__);
        fclose(corpusFilePtr);
        return CPA_STATUS_FAIL;
    }

    *size = fread(*ppSrcBuff, 1, lSize, corpusFilePtr);
    if (*size != lSize)
    {
        PRINT_ERR("%s Input Error! size(%ul) != lSize(%ld)\n",
                  fullpath,
                  *size,
                  lSize);
        fclose(corpusFilePtr);
        return CPA_STATUS_FAIL;
    }
    fclose(corpusFilePtr);
    return CPA_STATUS_SUCCESS;
}

CpaStatus calcSWDigest(CpaFlatBuffer *msg,
                       CpaFlatBuffer *digest,
                       CpaCySymHashAlgorithm hashAlg)
{
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(msg);
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(digest);

    switch (hashAlg)
    {

        case CPA_CY_SYM_HASH_SHA1:
            return (SHA1(msg->pData, msg->dataLenInBytes, digest->pData) ==
                    NULL)
                       ? CPA_STATUS_FAIL
                       : CPA_STATUS_SUCCESS;
        case CPA_CY_SYM_HASH_SHA224:
            return (SHA224(msg->pData, msg->dataLenInBytes, digest->pData) ==
                    NULL)
                       ? CPA_STATUS_FAIL
                       : CPA_STATUS_SUCCESS;
        case CPA_CY_SYM_HASH_SHA256:
            return (SHA256(msg->pData, msg->dataLenInBytes, digest->pData) ==
                    NULL)
                       ? CPA_STATUS_FAIL
                       : CPA_STATUS_SUCCESS;
        case CPA_CY_SYM_HASH_SHA512:
            return (SHA512(msg->pData, msg->dataLenInBytes, digest->pData) ==
                    NULL)
                       ? CPA_STATUS_FAIL
                       : CPA_STATUS_SUCCESS;
        default:
            PRINT_ERR("Unsupported algorithm %d\n", hashAlg);
            return CPA_STATUS_UNSUPPORTED;
    }
}

CpaStatus getCompressedFile(Cpa8U **ppSrcBuff, char *filename, Cpa32U *size)
{
    FILE *corpusFilePtr = NULL;
    long lSize;
    char fullpath[MAX_CORPUS_FILE_PATH_LEN];
    Cpa32S strSize = 0;

    strSize =
        snprintf(fullpath, sizeof(fullpath), "%s%s", firmwarePath, filename);
    CHECK_PARAM_RANGE(strSize, 1, sizeof(fullpath));
    corpusFilePtr = fopen(fullpath, "rb");
    if (corpusFilePtr == NULL)
    {
        PRINT("Could not open file\n");
        return CPA_STATUS_FAIL;
    }

    fseek(corpusFilePtr, 0, SEEK_END);
    lSize = ftell(corpusFilePtr);
    if (fseek(corpusFilePtr, 0, SEEK_SET) != 0)
    {
        PRINT("Could not move to beginning of file\n");
        fclose(corpusFilePtr);
        return CPA_STATUS_FAIL;
    }
    *ppSrcBuff = qaeMemAlloc(lSize);

    if (*ppSrcBuff == NULL)
    {
        PRINT("%s:: Can't Allocate Memory for srcBuff!\n", __FUNCTION__);
        fclose(corpusFilePtr);
        return CPA_STATUS_FAIL;
    }

    *size = fread(*ppSrcBuff, 1, lSize, corpusFilePtr);
    if (*size != lSize)
    {
        PRINT_ERR("Error Input Error!");
        fclose(corpusFilePtr);
        return CPA_STATUS_FAIL;
    }
    fclose(corpusFilePtr);
    return CPA_STATUS_SUCCESS;
}

int parseArg(int argc, char **argv, option_t *optArray, int numOpt)
{
    int indexArgv = 1;
    int indexOpt = 0;
    int value = 0;
    char name[CLI_OPT_LEN];
    CpaBoolean matchFound = CPA_FALSE;

    if (NULL == optArray)
        return 1;

    while (indexArgv < argc)
    {
        if (NULL != argv[indexArgv])
        {
            memset((void *)name, 0, sizeof(name));
            if (strlen(argv[indexArgv]) > CLI_OPT_LEN)
            {
                PRINT_ERR("input argument %d, exceeds permitted length\n",
                          indexArgv);
                return -1;
            }
            sscanf(argv[indexArgv], "%24[^'=']=%d", name, &value);
            for (indexOpt = 0; indexOpt < numOpt; indexOpt++)
            {
                if (0 ==
                    strncmp(name, optArray[indexOpt].optName, sizeof(name)))
                {
                    optArray[indexOpt].optValue = value;
                    matchFound = CPA_TRUE;
                }
            }
            if (matchFound == CPA_FALSE)
            {
                PRINT_ERR("%s not recognized\n", name);
                return -1;
            }
        }
        indexArgv++;
        matchFound = CPA_FALSE;
    }

    return 0;
}
static int sampleCodeEventPoll(CpaInstanceHandle instanceHandle,
                               CpaAccelerationServiceType accelServieType)
{
#ifndef SC_EPOLL_DISABLED
    int fd = 0;
    int i = 0;
    int n = 0;
    int efd = 0;
    struct epoll_event event;
    struct epoll_event *events;
    CpaStatus status = CPA_STATUS_FAIL;
    CpaBoolean volatile *pServiceStarted = NULL;

    typedef CpaStatus (*ptr2_icp_sal_GetFileDescriptor)(CpaInstanceHandle,
                                                        int *);
    typedef CpaStatus (*ptr2_icp_sal_PutFileDescriptor)(CpaInstanceHandle, int);
    typedef CpaStatus (*ptr2_icp_sal_PollInstance)(CpaInstanceHandle, Cpa32U);
    ptr2_icp_sal_GetFileDescriptor getFileDescriptorFn = NULL;
    ptr2_icp_sal_PollInstance pollInstanceFn = NULL;
    ptr2_icp_sal_PutFileDescriptor putFileDescriptorFn = NULL;
#ifdef DO_CRYPTO
    if (accelServieType == CPA_ACC_SVC_TYPE_CRYPTO)
    {
        getFileDescriptorFn = icp_sal_CyGetFileDescriptor;
        pollInstanceFn = icp_sal_CyPollInstance;
        putFileDescriptorFn = icp_sal_CyPutFileDescriptor;
        pServiceStarted = &cy_service_started_g;
    }
#endif
    if (accelServieType == CPA_ACC_SVC_TYPE_DATA_COMPRESSION)
    {
        getFileDescriptorFn = icp_sal_DcGetFileDescriptor;
        pollInstanceFn = icp_sal_DcPollInstance;
        putFileDescriptorFn = icp_sal_DcPutFileDescriptor;
        pServiceStarted = &dc_service_started_g;
    }
    if (getFileDescriptorFn == NULL || pollInstanceFn == NULL ||
        putFileDescriptorFn == NULL)
    {
        PRINT_ERR("Error initializing event polling mechanism for service %d\n",
                  accelServieType);
        return -1;
    }

    if (CPA_STATUS_SUCCESS != getFileDescriptorFn(instanceHandle, &fd))
    {
        PRINT_ERR("Error getting CY file descriptor for epoll instance\n");
        return -1;
    }

    efd = epoll_create1(0);
    if (-1 == efd)
    {
        PRINT_ERR("Error creating epoll fd for instance\n");
        return -1;
    }
    event.data.fd = fd;
    event.events = EPOLLIN;
    if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
    {
        PRINT_ERR("Error adding fd to epoll: %d\n", errno);
        return -1;
    }

    events = qaeMemAlloc(EPOLL_MAX_EVENTS * sizeof(event));
    if (NULL == events)
    {
        PRINT_ERR("Error allocating memory for epoll events\n");
        return -1;
    }

    while (*pServiceStarted == CPA_TRUE)
    {
        n = epoll_wait(efd, events, EPOLL_MAX_EVENTS, 100);
        for (i = 0; i < n; i++)
        {
            if (fd == events[i].data.fd && (events[i].events & EPOLLIN))
            {
                status = pollInstanceFn(instanceHandle, 0);
                if ((CPA_STATUS_SUCCESS != status) &&
                    (CPA_STATUS_RETRY != status))
                {
                    PRINT_ERR("Error:poll instance returned status %d\n",
                              status);
                }
            }
        }
    }
    if (-1 == epoll_ctl(efd, EPOLL_CTL_DEL, fd, &event))
    {
        PRINT_ERR("Error removing fd from epoll\n");
    }
    qaeMemFree((void **)&events);
    putFileDescriptorFn(instanceHandle, fd);
    close(efd);
    return 0;
#else
    PRINT_ERR("Event based polling not enabled during compile\n");
    return -1;
#endif
}

void sampleCodeDcEventPoll(CpaInstanceHandle instanceHandle)
{
    if (0 !=
        sampleCodeEventPoll(instanceHandle, CPA_ACC_SVC_TYPE_DATA_COMPRESSION))
    {
        PRINT_ERR("Error enabling sample code event poll\n");
    }
}

void sampleCodeCyEventPoll(CpaInstanceHandle instanceHandle)
{
    if (0 != sampleCodeEventPoll(instanceHandle, CPA_ACC_SVC_TYPE_CRYPTO))
    {
        PRINT_ERR("Error enabling sample code event poll\n");
    }
}

void sample_code_wait_threads_arrived(Cpa32U sleepTimeout, Cpa32U maxRetries)
{
    Cpa32U retryValue = 0;
    do
    {
        sampleCodeSleep(sleepTimeout);
        if (maxRetries == retryValue)
        {
            PRINT("startThreads: MAX RETRY reached and all threads are not "
                  "reached to barrier \n");
            break;
        }
        retryValue++;
    } while (numThreadsAtBarrier_g < numCreatedThreads_g);
}

/* The three functions below are needed to sync performance threads in
 * kernel space in the user space they don't do much
 */
void sampleCodeCompletionInit(Cpa32U threadId)
{
    return;
}

CpaStatus sampleCodeThreadCollect(sample_code_thread_t *thread, Cpa32U threadId)
{
    return sampleCodeThreadJoin(thread);
}

void sampleCodeThreadComplete(Cpa32U threadId)
{
    sampleCodeThreadExit();
}
