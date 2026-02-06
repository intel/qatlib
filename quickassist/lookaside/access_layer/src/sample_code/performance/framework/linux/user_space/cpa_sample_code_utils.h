
/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
#include <cpa_dc.h>
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
#define CLI_OPT_LEN (50)
#define RUN_ALL_TESTS (127)
#define DEFAULT_SIGN_OF_LIFE (0)
#define USE_V1_CONFIG_FILE (1)
#define USE_V2_CONFIG_FILE (2)
#define MAX_NUMOPT (18)

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
            PRINT_ERR("pthread function failed with error:%d\n", ret);         \
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

/**
 *****************************************************************************
 * @ingroup sampleCode
 *      sampleCodeDynamicPoll
 *
 * @description
 *      Performs dynamic polling on a QAT instance with automatic mode
 *      switching between event-driven (epoll) and traditional polling modes.
 *      The function monitors the instance's response mode at runtime and
 *      adapts the polling mechanism accordingly for optimal performance.
 *
 * @param[in] instanceHandle - Handle to the QAT acceleration instance
 * @param[in] serviceType    - Type of acceleration service (CRYPTO_SYM,
 *                             CRYPTO_ASYM, DATA_COMPRESSION, or
 *                             DATA_DECOMPRESSION)
 *
 * @retval
 *     none
 *
 * @pre
 *      Instance must be initialized and started
 * @post
 *      Polling thread runs until service is stopped
 *
 *****************************************************************************/
void sampleCodeDynamicPoll(CpaInstanceHandle instanceHandle,
                           CpaAccelerationServiceType serviceType);


/**
 *****************************************************************************
 * @ingroup sampleCode
 *      sampleCodeDcDynamicPollWrapper
 *
 * @description
 *      Thread wrapper function for Data Compression dynamic polling.
 *      This function is designed to be used as a pthread entry point and
 *      calls the service-specific DC dynamic polling implementation.
 *
 * @param[in] instanceHandle - Pointer to CpaInstanceHandle for DC service
 *
 * @retval
 *     none (void* for pthread compatibility)
 *
 * @pre
 *      DC instance must be initialized
 * @post
 *      Polling continues until DC service is stopped
 *
 *****************************************************************************/
void sampleCodeDcDynamicPollWrapper(void* instanceHandle);

/**
 *****************************************************************************
 * @ingroup sampleCode
 *      sampleCodeSymDynamicPollWrapper
 *
 * @description
 *      Thread wrapper function for Crypto Symmetric dynamic polling.
 *      This function is designed to be used as a pthread entry point and
 *      calls the generic dynamic polling implementation for symmetric crypto.
 *
 * @param[in] instanceHandle - Pointer to CpaInstanceHandle for CY SYM service
 *
 * @retval
 *     none (void* for pthread compatibility)
 *
 * @pre
 *      CY SYM instance must be initialized
 * @post
 *      Polling continues until CY service is stopped
 *
 *****************************************************************************/
void sampleCodeSymDynamicPollWrapper(void* instanceHandle);

/**
 *****************************************************************************
 * @ingroup sampleCode
 *      sampleCodeAsymDynamicPollWrapper
 *
 * @description
 *      Thread wrapper function for Crypto Asymmetric dynamic polling.
 *      This function is designed to be used as a pthread entry point and
 *      calls the generic dynamic polling implementation for asymmetric crypto.
 *
 * @param[in] instanceHandle - Pointer to CpaInstanceHandle for CY ASYM service
 *
 * @retval
 *     none (void* for pthread compatibility)
 *
 * @pre
 *      CY ASYM instance must be initialized
 * @post
 *      Polling continues until CY service is stopped
 *
 *****************************************************************************/
void sampleCodeAsymDynamicPollWrapper(void* instanceHandle);

#endif
