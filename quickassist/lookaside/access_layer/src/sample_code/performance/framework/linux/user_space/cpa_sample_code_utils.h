
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
* @file cpa_sample_code_utils.h
*
* This file provides linux kernel os abstraction functions
*
*****************************************************************************/
#ifndef _USER_SPACE_SAMPLECODEUTILS_H__
#define _USER_SPACE_SAMPLECODEUTILS_H__

#include "cpa.h"

#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <cpa_cy_sym.h>
#include "openssl/sha.h"

/**
*****************************************************************************
*      these variables are used to keep status of the backoff timer settings
*       CpaBoolean backoff_timer_g - indicates if backoff timer is enabled
*            true - enabled
*            false - disabled
*       backoff_dynamic_g - indicates if dynamic algorithm is enabled
*           true - enabled (determine backoff delay dynamically)
*           false - disabled (use static backoff delay)
*        backoff_static_timer_g - number of busy loop cycles for the static
*            backoff timer
*****************************************************************************/
extern volatile CpaBoolean backoff_timer_g;
extern volatile CpaBoolean backoff_dynamic_g;
extern uint32_t backoff_static_timer_g;

/**
 *****************************************************************************/
typedef long ChipRec_s32;      ///< 32 bit signed integer
typedef long long ChipRec_s64; ///< 64 bit signed integer

typedef unsigned long ChipRec_u32;      ///< 32 bit unsigned integer
typedef unsigned long long ChipRec_u64; ///< 64 bit unsigned integer

#define sample_code_thread_t pthread_t
typedef sem_t *sample_code_semaphore_t;

#define EXPORT_SYMBOL(doNothing)

#define SAMPLECODE_POSIX_SHARED_SEMAPHORE (1)

/* A minimum of 512  buffers should be used in the sample code to ensure that
 * both RX/TX rings are full during performance operations. This also ensures
 * that in-flight requests are not being resubmitted before being returned by
 * the driver.
 */
#define CY_SYM_DP_NUM_BUFFERS (1000)

#define CY_SYM_DP_NUM_LOOPS (100)
#define CLI_OPT_LEN (25)
#define RUN_ALL_TESTS (127)
#define DEFAULT_SIGN_OF_LIFE (0)
#define USE_V1_CONFIG_FILE (1)
#define USE_V2_CONFIG_FILE (2)
#define MAX_NUMOPT (15)

typedef struct option_s
{
    const char optName[CLI_OPT_LEN];
    int optValue;
} option_t;

extern int parseArg(int argc, char **argv, option_t *optArray, int numOpt);

#define THREAD_DEFAULT_SCHED_POLICY SCHED_OTHER

#define sample_code_thread_mutex_t pthread_mutex_t
#define sample_code_thread_cond_t pthread_cond_t
#define sample_code_thread_barrier_t pthread_barrier_t

#define PTHREAD_CHECK_RETURN_VALUE(fn)                                         \
    do                                                                         \
    {                                                                          \
        int ret = (fn);                                                        \
        if (ret != 0)                                                          \
        {                                                                      \
            PRINT_ERR("pthread function failed with errro:%d\n", ret);         \
        }                                                                      \
    } while (0)

#define sample_code_thread_mutex_init(mutex_ptr)                               \
    PTHREAD_CHECK_RETURN_VALUE(pthread_mutex_init(mutex_ptr, NULL))
#define sample_code_thread_mutex_lock(mutex_ptr)                               \
    PTHREAD_CHECK_RETURN_VALUE(pthread_mutex_lock(mutex_ptr))
#define sample_code_thread_mutex_unlock(mutex_ptr)                             \
    PTHREAD_CHECK_RETURN_VALUE(pthread_mutex_unlock(mutex_ptr))
#define sample_code_thread_mutex_destroy(mutex_ptr)                            \
    PTHREAD_CHECK_RETURN_VALUE(pthread_mutex_destroy(mutex_ptr))

#define sample_code_thread_cond_init(condPtr)                                  \
    PTHREAD_CHECK_RETURN_VALUE(pthread_cond_init(condPtr, NULL))
#define sample_code_thread_cond_wait(condPtr, mutex_ptr)                       \
    PTHREAD_CHECK_RETURN_VALUE(pthread_cond_wait(condPtr, mutex_ptr))
#define sample_code_thread_cond_broadcast(condPtr)                             \
    PTHREAD_CHECK_RETURN_VALUE(pthread_cond_broadcast(condPtr))
#define sample_code_thread_cond_destroy(cPtr)                                  \
    PTHREAD_CHECK_RETURN_VALUE(pthread_cond_destroy(cPtr))

#define PRINT(args...)                                                         \
    do                                                                         \
    {                                                                          \
        printf(args);                                                          \
    } while (0)

#define do_div(n, base) (n = n / base)

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadExit
 *
 * @description
 *      This function is called by threads_g on exit, for user space it cleans
 *      up pthreads_g, for kernel space it does nothing and is provided to allow
 *      an application to be compiled to run in user or kernel
 *
 *
 * @param[in] none, this function is called within the thread context
 *
 * @retval none
 *
 * @pre
 *      thread is executing
 * @post
 *      thread is closed
 *
 *****************************************************************************/
void sampleCodeThreadExit(void);

#ifdef BLOCKOUT
typedef unsigned long long ticks_t;

/* cpuid for intel e gnu compiler */
#if defined(__INTEL_COMPILER)
#define __CPUID(a, b) __cpuid((a), (b))
#else /* #if defined (__INTEL_COMPILER) */
#define __CPUID(in, a, b, c, d)                                                \
    asm volatile("cpuid"                                                       \
                 : "=a"(a), "=b"(b), "=c"(c), "=d"(d)                          \
                 : "a"(in)                                                     \
                 : "ebx");
#endif /* #if defined (__INTEL_COMPILER) */

static void __inline__ cpuid(void)
{
#if defined(__INTEL_COMPILER)
    int CPUInfo[4] = {-1};
    __CPUID(CPUInfo, 1);
#else  /* #if defined (__INTEL_COMPILER) */
    unsigned int a = 0x00, b = 0x00, c = 0x00, d = 0x00;
    __CPUID(0x00, a, b, c, d);
#endif /* #if defined (__INTEL_COMPILER) */
}

static __inline__ ticks_t rdtsc(void)
{
    unsigned long a, d;

    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (((ticks_t)a) | (((ticks_t)d) << 32));
}

/*
    Serialized version of the rdtsc instruction
    to properly count cycles need to remove the cpuid overhead

    ticks_t cpuid_cycles = get_cpuid_cycles();
    ticks_t s1 = rdtscp();
    {
        code_to_benchmark();
    }
    ticks_t s2 = rdtscp();
    ticks_t measured_time = s2 - s1 - cpuid_cycles;
*/
static __inline__ ticks_t rdtscp(void)
{
    volatile unsigned long a = 0, d = 0;
    ticks_t returnval = 0;

    cpuid();
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    returnval = (((ticks_t)d) << 32);
    returnval |= ((ticks_t)a);

    return returnval;
}

/*
    This function estimates the number of clock
    cycles for the cpuid instruction
    Needs to be run at least 3 times to "warm-up"
    and report a stable number
*/
static __inline__ ticks_t rdtscll()
{
    volatile ticks_t cpuid_cycles = 0;
    volatile ticks_t s1;

    cpuid();
    s1 = rdtsc();
    cpuid();
    cpuid_cycles = rdtsc();
    cpuid_cycles -= s1;
    // printf("cpuid_cycles: %llu \n", cpuid_cycles);

    cpuid();
    s1 = rdtsc();
    cpuid();
    cpuid_cycles = rdtsc();
    cpuid_cycles -= s1;
    // printf("cpuid_cycles: %llu \n", cpuid_cycles);

    cpuid();
    s1 = rdtsc();
    cpuid();
    cpuid_cycles = rdtsc();
    cpuid_cycles -= s1;
    // printf("cpuid_cycles: %llu \n", cpuid_cycles);

    return cpuid_cycles;
}
#endif

/**
 *****************************************************************************
 * @ingroup sampleCode
 *      enableBackoffTimer
 *
 * @description
 *      enables backoff timer;
 *
 * @param[in] none
 *
 * @retval status of execution
 *
 * @pre
 *      none
 * @post
 *      the backoff timer is enabled
 *
 *****************************************************************************/
CpaStatus enableBackoffTimer();

/**
 *****************************************************************************
 * @ingroup sampleCode
 *     disableBackoffTimer
 *
 * @description
 *      disables backoff timer;
 *
 * @param[in] none
 *
 * @retval status of execution
 *
 * @pre
 *      none
 * @post
 *      the backoff timer is disabled
 *
 *****************************************************************************/
CpaStatus disableBackoffTimer();

/**
 *****************************************************************************
 * @ingroup sampleCode
 *    e nableBackoffDynamic
 *
 * @description
 *      enables the dynamic algorithm for the backoff timer.
 *      The function also calls enableBackoffTimer();
 *
 * @param[in] none
 *
 * @retval status of execution
 *
 * @pre
 *      none
 * @post
 *      the dynamic backoff timer is switched on
 *
 *****************************************************************************/
CpaStatus enableBackoffDynamic();

/**
 *****************************************************************************
 * @ingroup sampleCode
 *      enableBackoffStatic
 *
 * @description
 *     enables the static delay for the backoff timer. The delay value is to
 *     be passed as a parameter. The delay value will be used as a number
 *     of cycles for the busy_loop.
 *
 * @param[in] number of busy loop cycles
 *
 * @retval status of execution
 *
 * @pre
 *      none
 * @post
 *      the static backoff timer is switched on. The delay value is set.
 *
 *****************************************************************************/
CpaStatus enableBackoffStatic(uint32_t numBusyLoops);

/**
*****************************************************************************
* @ingroup sampleCode
*      sample_code_wait_threads_arrived
*
* @description
*     Checks if all the threads arrived and prints error is they are not after .
*
* @param[in] sleepTimeout - sleep between reties
*            maxRetries - maximum number of retries
*
* @retval
*     none
*
* @pre
*      none
* @post
*      none
*
*****************************************************************************/
void sample_code_wait_threads_arrived(Cpa32U sleepTimeout, Cpa32U maxRetries);

#endif
