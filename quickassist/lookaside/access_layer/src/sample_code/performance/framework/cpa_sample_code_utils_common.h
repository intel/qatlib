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
* @file cpa_sample_code_utils_common.h
*
* This file provides linux kernel os abstraction functions
*
*****************************************************************************/
#ifndef _COMMON_SAMPLECODEUTILS_H__
#define _COMMON_SAMPLECODEUTILS_H__

#include "cpa_sample_code_utils.h"

#include "cpa.h"

#ifdef USER_SPACE
#include "qae_mem.h"
#else
#include "qae_mem_utils.h"
#endif

#ifndef SAMPLE_CODE_CORPUS_PATH
#define SAMPLE_CODE_CORPUS_PATH "/lib/firmware/"
#endif

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE (64)
#endif
#define ALL_BITS_SET64U (0xFFFFFFFFFFFFFFFFL)
#define __cpa_cache_aligned __attribute__((__aligned__(CACHE_LINE_SIZE)))

/* *****************************************************************************
 * Types & Structures
 * ****************************************************************************/

typedef enum
{
    CAT_CIPHER = 0,
    CAT_HASH,
    CAT_ALG_CHAIN,
    CAT_NESTED,
    CAT_PKE,
    CAT_COMP,
    CAT_CNV
} algo_category_e;
#define MAX_ALGO_CATEGORY (8)

/*This is used to define a pointer to a function*/
typedef void (*performance_func_t)(void *);
typedef CpaStatus (*stats_print_func_t)(void *);

/*this type def is used to count the clock cycles taken to perform quick
 * assist operations*/
typedef unsigned long long perf_cycles_t;
extern volatile Cpa32U numArrivedThreads_g;
extern CpaBoolean SampleCodeBarrierLifted;
/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      time structure
 * @description
 *      used to store thread execution time
 ****************************************************************************/
typedef struct sample_code_time_s
{
    long secs;  /**< seconds */
    long nsecs; /**< nanoseconds */
} sample_code_time_t;

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      thread attribute structure
 * @description
 *      used to store thread attributes
 ****************************************************************************/
typedef struct sample_code_thread_attr_s
{
    char *name;       /**< name */
    Cpa32U stackSize; /**< stack size */
    Cpa32U priority;  /**< priority */
    Cpa32S policy;    /**< policy */
} sample_code_thread_attr_t;


/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      Performance Data Structure
 * @description
 *      used to store performance data on a per thread basis
 ****************************************************************************/
typedef struct perf_data_s
{
    /* used to correlate requests and responses so that last request */
    /* can be figured out in the callback to get timestamp */
    volatile Cpa64U responses;
    /*store number of submissions*/
    Cpa32U submissions;
    Cpa64U retries;
    Cpa32U pollRetries;
    Cpa64U nextPoll;
    perf_cycles_t startCyclesTimestamp; /* start TS before perform */
    perf_cycles_t midCyclesTimestamp;   /* start TS before perform */
    perf_cycles_t
        endCyclesTimestamp; /* end TS for last perform captured in CB */
    /*rate variables*/
    Cpa32U sleepTime;
    Cpa32U compRate;
    Cpa32S currentThroughput;
    sample_code_semaphore_t comp;
    Cpa64U numOperations;
    /*flag to indicate rings were full at least once during session*/
    Cpa32U averagePacketSizeInBytes;
    sample_code_thread_mutex_t mutex;
    CpaStatus threadReturnStatus;
    /* Collect additional status from the result data
     * structure reported by the compression/decompression
     * operation to indicate the exact reason for failure.
     */
    CpaStatus additionalStatus;
    /*logical core affinity of test*/
    Cpa32U logicalCoreAffinity;
    /*device used by thread*/
    Cpa32U packageId;
#if defined(_WIN64) || defined(WIN32)
    Cpa32U cpuCoreUtilPercentage;
    Cpa32U cpuOverallUtilPercentage;
#endif
    perf_cycles_t req_temp;
    perf_cycles_t cost_temp;
    Cpa64U req_count;
    Cpa64U req_cost_count;
    Cpa64U poll_cost_count;
    perf_cycles_t req_sum_cycles;
    perf_cycles_t req_cost_sum_cycles;
    perf_cycles_t poll_sum_cycles;
    perf_cycles_t poll_cost_sum_cycles;
    Cpa32U bytesConsumedPerLoop;
    Cpa32U bytesProducedPerLoop;
    Cpa32U numLoops;
    Cpa32U pollCount;
    Cpa32U overflow;
    Cpa32U busyLoopValue;
    Cpa32U cyclesPerBusyLoop;
    Cpa32U busyLoopCount;
    perf_cycles_t offloadCycles;
    perf_cycles_t totalBusyLoopCycles;
    Cpa64U busyLoopResponses;
    CpaBoolean isIACycleCountProfiled;
    Cpa32U latencyCount;
    Cpa32U nextCount;
    Cpa32U countIncrement;
    perf_cycles_t response_process_time;
    perf_cycles_t *start_times;
    perf_cycles_t *response_times;
    perf_cycles_t minLatency;
    perf_cycles_t aveLatency;
    perf_cycles_t maxLatency;
    CpaFlatBuffer *expectedResults;
    Cpa32U numBuffers;
    Cpa64U preTestRecoveryCount;
    Cpa64U postTestRecoveryCount;
} perf_data_t;

/* *****************************************************************************
 * MACROS
 * ****************************************************************************/

#define SEMAPHORE_MAX_COUNT 100
#define POST_PRIORITY_INCREMENT 0
#define POST_COUNT_INCREMENT 1

#define NUM_NANOSEC_IN_SEC (1000000000)
#define NUM_MICROSEC_IN_SEC (1000000)
#define NUM_MILLISEC_IN_SEC (1000)
#define NUM_NANOSEC_IN_MILLISEC (1000000)
#define SAMPLE_CODE_WAIT_FOREVER (-1)

#ifdef ICP_DELAYED_RESPONSE
#define SAMPLE_CODE_WAIT_DEFAULT (90000)
#else
#define SAMPLE_CODE_WAIT_DEFAULT (30000)
#endif
#define SAMPLE_CODE_WAIT_PRIMES (90000)

#define SAMPLE_CODE_WAIT_NONE (0)
#define DEFAULT_THREAD_PRIORITY (15)
#define THREAD_PRIORITY_SCHED_OTHER (0)
#define MAX_PRIORITY_VALUE (39)
#define NICE_VAL_DIFFERENCE (20)
#define SAMPLE_CODE_THOUSAND (1000)

#define MAX_CORPUS_FILE_PATH_LEN (100)

/*the limit of the number of different types of threads to be created*/
#ifdef KERNEL_SPACE
#ifndef MAX_KERNEL_THREAD_VARIATION
#define MAX_THREAD_VARIATION (300)
#else
#define MAX_THREAD_VARIATION (MAX_KERNEL_THREAD_VARIATION)
#endif
#else
#define MAX_THREAD_VARIATION (600)
#endif
#define THREAD_NAME_LEN (4)
#define CORE_MASK_MSB (0x10000000)

/*the limit of the number of one type of thread, should be at least the number
 * of cores on the system we want to test*/
#define MAX_NUM_OF_ONE_TYPE_OF_THREAD (512)

/*total number of threads that the framework will support*/
#define MAX_THREADS MAX_THREAD_VARIATION *MAX_NUM_OF_ONE_TYPE_OF_THREAD

#define MAX_LATENCY_LIMIT (__LONG_LONG_MAX__ - 1UL)
/* Must have this many buffers being submitted before
 * latency statistics can be calculated */
#define LATENCY_SUBMISSION_LIMIT (1000000000)

/* Total number of latency measurements being made. Spread
 * over total buffer count */
#define MAX_LATENCY_COUNT (100)

#define ZLIB_HEADER_SIZE (2)

/* Define types which need to vary between 32 and 64 bit OS and 32bit
 * application
 * on 64bit OS.
 * */
#ifndef SAMPLE_KERNEL64_USER32
#ifdef __x86_64__
#define SAMPLE_CODE_UINT Cpa64U
#define SAMPLE_CODE_INT Cpa64S
#else
#define SAMPLE_CODE_UINT Cpa32U
#define SAMPLE_CODE_INT Cpa32S
#endif
#else
#define SAMPLE_CODE_UINT Cpa32U
#define SAMPLE_CODE_INT Cpa32S
#endif

/*add 2 sampe_code_time_t structs together*/
#define SAMPLE_CODE_TIME_ADD(tvA, tvB)                                         \
    (tvA).secs += (tvB).secs;                                                  \
    (tvA).nsecs += (tvB).nsecs;                                                \
    if ((tvA).nsecs >= NUM_NANOSEC_IN_SEC)                                     \
    {                                                                          \
        (tvA).secs++;                                                          \
        (tvA).nsecs -= NUM_NANOSEC_IN_SEC;                                     \
    }

/*convert sample_code_time_t to milliseconds*/
#define SAMPLE_CODE_TIMEVAL_TO_MS(milliseconds, pTv)                           \
    ((sample_code_time_t *)pTv)->secs = milliseconds / 1000;                   \
    ((sample_code_time_t *)pTv)->nsecs = (milliseconds % 1000) * 1000000

/*print the function name, line number and user defined message,  print
 *macros for Windows are defined in platform-specific header files*/
#if !defined(_WIN64) && !defined(WIN32)

#define PRINT_ERR(args...)                                                     \
    do                                                                         \
    {                                                                          \
        PRINT("%s, %s():%d ", __FILE__, __func__, __LINE__);                   \
        PRINT(args);                                                           \
    } while (0)


#endif


#define FUNC_ENTRY()
#define FUNC_EXIT()

/* Check if the value returned by a function was ICP_STATUS_SUCCESS print
 * and error if not successful */
#define CHECK_FOR_SUCCESS(value)                                               \
    if (value != CPA_STATUS_SUCCESS)                                           \
    {                                                                          \
        PRINT("%s():%d ", __func__, __LINE__);                                 \
        PRINT("ERROR value: %d\n", value);                                     \
    }

/* Check if the value returned by a function was ICP_STATUS_SUCCESS print
 * an error and return ICP_STATUS_FAIL if not successful */
#define CHECK_STATUS_AND_RETURN_FAIL_IF_NOT_SUCCESS(value)                     \
    if (value != CPA_STATUS_SUCCESS)                                           \
        do                                                                     \
        {                                                                      \
            PRINT("%s():%d ", __func__, __LINE__);                             \
            PRINT("ERROR value: %d\n", value);                                 \
            return CPA_STATUS_FAIL;                                            \
    } while (0)

/* Check if pointer is null, print an error and return if pointer is null */
#define CHECK_POINTER_AND_RETURN_IF_NULL(ptr)                                  \
    if (ptr == NULL)                                                           \
    {                                                                          \
        PRINT_ERR(                                                             \
            "%s():%d NULL pointer error: [" #ptr "]", __func__, __LINE__);     \
        return;                                                                \
    }

/* Check if pointer is null, print an error and return ICP_STATUS_FAIL if
 * pointer is NULL */
#define CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(ptr)                             \
    if (ptr == NULL)                                                           \
    {                                                                          \
        PRINT_ERR(                                                             \
            "%s():%d NULL pointer error: [" #ptr "]", __func__, __LINE__);     \
        return CPA_STATUS_FAIL;                                                \
    }

/* Check if pointer is null, print an error and return NULL if pointer is null
 */
#define CHECK_POINTER_AND_RETURN_NULL_IF_NULL(ptr)                             \
    if (ptr == NULL)                                                           \
    {                                                                          \
        PRINT_ERR(                                                             \
            "%s():%d NULL pointer error: [" #ptr "]", __func__, __LINE__);     \
        return NULL;                                                           \
    }

/* Check if expression evaluates to CPA_TRUE. If not, then print error message
 * whose format and arguments are passed. */
#define CHECK_EXPRESSION_AND_LOG_FAIL(exp, errMsgfmt, ...)                     \
    {                                                                          \
        if (!(exp))                                                            \
        {                                                                      \
            PRINT_ERR(errMsgfmt, __VA_ARGS__);                                 \
        }                                                                      \
    }

/* Check if expression evaluates to CPA_TRUE. If not, then print error message
 * whose format and arguments are passed and return failure. */
#define CHECK_EXPRESSION_AND_RETURN_FAIL(exp, errMsgfmt, ...)                  \
    {                                                                          \
        if (!(exp))                                                            \
        {                                                                      \
            PRINT_ERR(errMsgfmt, __VA_ARGS__);                                 \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    }

/* Check if expression evaluates to CPA_TRUE. If not, then print error message
 * whose format and arguments are passed and return error code specified. */
#define CHECK_EXPRESSION_AND_RETURN_CODE(exp, errCode, errMsgfmt, ...)         \
    {                                                                          \
        if (!(exp))                                                            \
        {                                                                      \
            PRINT_ERR(errMsgfmt, __VA_ARGS__);                                 \
            return errCode;                                                    \
        }                                                                      \
    }

/* Check if expression evaluates to CPA_TRUE. If not, then print error message
 * whose format and arguments are passed and goto Exit */
#define CHECK_EXPRESSION_AND_GOTO_EXIT(exp, errMsgfmt, ...)                    \
    {                                                                          \
        if (!(exp))                                                            \
        {                                                                      \
            PRINT_ERR(errMsgfmt, __VA_ARGS__);                                 \
            goto Exit;                                                         \
        }                                                                      \
    }

/* Check if expression evaluates to CPA_TRUE. If not, then print error message
 * whose format and arguments are passed, failVariable to CPA_STATUS_FAIL,
 * and goto Exit */
#define CHECK_EXPRESSION_AND_GOTO_EXIT_WITH_FAILURE_SET(                       \
    exp, failVariable, errMsgfmt, ...)                                         \
    {                                                                          \
        if (!(exp))                                                            \
        {                                                                      \
            PRINT_ERR(errMsgfmt, __VA_ARGS__);                                 \
            failVariable = CPA_STATUS_FAIL;                                    \
            goto Exit;                                                         \
        }                                                                      \
    }

/* Check if a parameter is within a specified range */
#define CHECK_PARAM_RANGE(param, min, max)                                     \
    do                                                                         \
    {                                                                          \
        if (param > max || param < min)                                        \
        {                                                                      \
            PRINT_ERR("%s(): param out of range: [" #param "]\n", __func__);   \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

/* *****************************************************************************
 * FUNCTION PROTOTYPES
 * ****************************************************************************/

perf_cycles_t sampleCodeTimestamp(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeGetCpuFreq
 *
 * @description
 *      This function returns the frequency of the IA core
 *
 *
 * @retval This function returns the frequency of the IA core
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
Cpa32U sampleCodeGetCpuFreq(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeSleep
 *
 * @description
 *      This function will forces the executing code to sleep for the specified
 *      number of seconds
 *
 *
 * @param[in]      seconds    the number of seconds to sleep
 *
 *
 * @retval This function returns void
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
void sampleCodeSleep(Cpa32U seconds);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeSleep
 *
 * @description
 *      This function will forces the executing code to sleep for the specified
 *      number of milliseconds
 *
 *
 * @param[in]      seconds    the number of seconds to sleep
 *
 *
 * @retval This function returns void
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
void sampleCodeSleepMilliSec(Cpa32U milliseconds);

/**
 * Function used to create delay in nanoseconds
 */
void sleepNano(Cpa32U nanoseconds);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeGetNumberOfCpus
 *
 * @description
 *      This function will gets the number of logical CPU's on the system.
 *      note: A hyper threaded enabled core will return 2 logical CPUs
 *
 *
 * @param[in] none
 *
 * @retval The number of logical CPU's on the system
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
Cpa32U sampleCodeGetNumberOfCpus(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeGetCpu
 *
 * @description
 *      This function gets the logical CPU that the executing code is running
 *       on
 *
 *
 * @param[in] none
 *
 * @retval The number of logical CPU's on the system, that the executing code is
 * running on
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
Cpa32S sampleCodeGetCpu(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeGetNode
 *
 * @description
 *      This function gets the physical node that the executing code is
 *      running on
 *
 *
 * @param[in] none
 *
 * @retval The node, that the executing code is running on
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeGetCpu
 *
 * @description
 *      This function gets the logical CPU that the executing code is running on
 *
 *
 * @param[in] none
 *
 * @retval The number of logical CPU's on the system, that the executing code is
 * running on
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
Cpa32S sampleCodeGetCpu(void);
;

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeGetNode
 *
 * @description
 *      This function gets the node that the executing code is running
 *       on
 *
 *
 * @param[in] none
 *
 * @retval The node that the executing code is
 * running on
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
Cpa32S sampleCodeGetNode(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      generateRandomData
 *
 * @description
 *      This function generates random data for CpaFlatBuffers
 *
 *
 * @param[in] pWriteRandData pointer to CpaFlatBuffer pData
 * @param[in] lengthOfRand CpaFlatBuffer Data length specified in bytes
 *
 * @retval none
 *
 * @pre
 *      none
 * @post
 *      None
 *
 *****************************************************************************/
void generateRandomData(Cpa8U *pWriteRandData, Cpa32U lengthOfRand);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadCreate
 *
 * @description
 *      This function creates a thread to run the specified function as set by
 *      the function pointer param which takes an argument specified by the
 *      params pointer
 *
 *
 * @param[out] *thread pointer to sample_code_thread_t which is populated
 *              by the function
 * @param[in] *threadAttr pointer to sample_code_thread_attr_t which defines the
 *              attributes of the thread
 * @param[in] function pointer to the function to be executed in thread context
 * @param[in] params pointer to a structure containing the parameters to be
 *              passed to the function
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      none
 * @post
 *      thread is created
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadCreate(sample_code_thread_t *thread,
                                 sample_code_thread_attr_t *threadAttr,
                                 performance_func_t function,
                                 void *params);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadBind
 *
 * @description
 *      This function forces a thread to run on a specified logical IA core
 *
 *
 * @param[in] *thread pointer which identifies the thread to be tied to a core
 * @param[in] logicalCore in which the thread will run on
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      thread is created
 * @post
 *      thread is bound to run on a specific IA core
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadBind(sample_code_thread_t *thread,
                               Cpa32U logicalCore);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadStart
 *
 * @description
 *      This function executes the specified function
 *
 *
 * @param[in] *thread pointer which identifies the thread to be started
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 *
 * @pre
 *      thread is created
 * @post
 *      function pointed to is started in thread context
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadStart(sample_code_thread_t *thread);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadKill
 *
 * @description
 *      This function is kills a created thread
 *
 *
 * @param[in] *thread pointer which identifies the thread to be killed
 *
 * @retval none
 *
 * @pre
 *      thread is created
 * @post
 *      threads is closed
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadKill(sample_code_thread_t *thread);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadPrioritySet
 *
 * @description
 *      This function sets the priority of the thread
 *
 *
 * @param[in] *thread pointer which identifies the thread to prioritized
 *
 * @retval none
 *
 * @pre
 *      thread is created
 * @post
 *      thread priority is set
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadPrioritySet(sample_code_thread_t *thread,
                                      Cpa32U priority);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadPrioritySet
 *
 * @description
 *      This function sets the policy and priority of user space threads_g, in
 *      kernel space this function does nothing
 *
 *
 * @param[in] *thread pointer which identifies the thread to prioritized
 *
 * @retval none
 *
 * @pre
 *      thread is created
 * @post
 *      thread priority is set
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadSetPolicyAndPriority(sample_code_thread_t *thread,
                                               Cpa32U policy,
                                               Cpa32U priority);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadJoin
 *
 * @description
 *      Blocks and Waits for a thread as set by thread id to exit
 *
 *
 * @param[in] *thread pointer which identifies the thread to wait on
 *
 * @retval none
 *
 * @pre
 *      thread is created
 * @post
 *      thread waited on has completed
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadJoin(sample_code_thread_t *thread);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeThreadTimedJoin
 *
 * @description
 *      Blocks and Waits for a thread as set by thread id to exit
 *
 *
 * @param[in] *thread pointer which identifies the thread to wait on
 *            *pTimeOutInMs pointer which identifies time to wait
 *
 * @retval none
 *
 * @pre
 *      thread is created
 * @post
 *      thread waited on has completed or timeout
 *
 *****************************************************************************/
CpaStatus sampleCodeThreadTimedJoin(sample_code_thread_t *thread,
                                    Cpa64U *pTimeOutInMs);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeTimeTGet
 *
 * @description
 *      populates a time_t structure
 *
 *
 * @param[out] *pTime, time_t structure that is populated
 *
 * @retval none
 *
 * @pre
 *      none
 * @post
 *      pTime contains current time_t
 *
 *****************************************************************************/
CpaStatus sampleCodeTimeTGet(sample_code_time_t *pTime);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeSemaphoreInit
 *
 * @description
 *      initilises a semaphore type with start value
 *
 *
 * @param[out] *semPtr, is the semaphore to be initialized
 * @param[in] start_value, is the value to init the semaphore to 0 = free
 *              >0 is not free
 *
 * @retval none
 *
 * @pre
 *      none
 * @post
 *      none
 *
 *****************************************************************************/
CpaStatus sampleCodeSemaphoreInit(sample_code_semaphore_t *semPtr,
                                  Cpa32U start_value);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeSemaphorePost
 *
 * @description
 *      increments the semaphore count. In this code the
 *      sampleCodeSemaphoreWaitInterruptible is called and if count is 0,
 *      then it decrements the count to -1, blocks
 *      and waits for this function increment the count back to zero to free it
 *
 *
 * @param[out] *semPtr, is the semaphore to be initialized
 *
 * @retval none
 *
 * @pre
 *      semaphore is initialized
 * @post
 *      semaphore count is incremented
 *
 *****************************************************************************/
CpaStatus sampleCodeSemaphorePost(sample_code_semaphore_t *semPtr);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeSemaphoreDestroy
 *
 * @description
 *      free and memory internal allocated by the semaphore
 *
 *
 * @param[out] *semPtr, is the semaphore to be initialized
 *
 * @retval none
 *
 * @pre
 *      semaphore is initialized
 * @post
 *      semaphore is destroyed
 *
 *****************************************************************************/
CpaStatus sampleCodeSemaphoreDestroy(sample_code_semaphore_t *semPtr);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeSemaphoreWaitInterruptible
 *
 * @description
 *      This function decrements the usage count of the semaphore.
 *      If the new value is less than zero, the calling process is added to the
 *      wait queue and blocked. If the new value is zero or greater,
 *      the process obtains the semaphore
 *
 *
 * @param[out] *semPtr, is the semaphore to be initialized
 *
 * @retval none
 *
 * @pre
 *      semaphore is initialized
 * @post
 *      semaphore is decremented
 *
 *****************************************************************************/
CpaStatus sampleCodeSemaphoreWait(sample_code_semaphore_t *semPtr,
                                  Cpa32S timeout);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      startBarrier
 *
 * @description
 *      this function is provided specifically to pause user space threads
 *      from executing. until signaled to do so
 *
 *
 * @param[out] *semPtr, is the semaphore to be initialized
 *
 * @retval none
 *
 * @pre
 *      sample_code_thread_mutex_t threadControlMutex_g and
 *      sample_code_thread_cond_t threadConditionControl_g are initialized
 * @post
 *      calling function is blocked until the a broadcast is sent to the
 *      threadConditionControl_g conditional variable
 *
 *****************************************************************************/
void startBarrier(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeBarrier
 *
 * @description
 *      pauses a thread from executing until a proscribed number have all
 *      reached the barrier. This is only used to stop threads_g from
 *      starting there main work function until all threads_g are ready
 *      to start work
 *
 * @param[out] *semPtr, is the semaphore to be initialized
 *
 * @retval none
 *
 * @pre
 *      semaphore is initialized
 * @post
 *      semaphore is decremented
 *
 *****************************************************************************/
void sampleCodeBarrier(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeBarrierInit
 *
 * @description
 *      Initialized the barrier for threads_g to stop at
 *
 *
 *
 * @retval none
 *
 * @pre
 *      barrier is initialized
 * @post
 *      barrier is decremented
 *
 *****************************************************************************/
void sampleCodeBarrierInit(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeBarrierDestroy
 *
 * @description
 *      Destroys the barrier and all dependent resources
 *
 *
 *
 * @retval none
 *
 * @pre
 *      barrier is initialized
 * @post
 *      barrier is destroyed
 *
 *****************************************************************************/
void sampleCodeBarrierDestroy(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      startBarrierInit
 *
 * @description
 *      Initialized the barrier for threads_g to stop at
 *
 *
 *
 * @retval none
 *
 * @pre
 *      barrier is initialized
 * @post
 *      barrier is decremented
 *
 *****************************************************************************/
void startBarrierInit(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeDcEventPoll
 *
 * @description
 *      Perform an event based poll for Compression Instances
 *
 *
 *
 * @retval none
 *
 *
 *****************************************************************************/
void sampleCodeDcEventPoll(CpaInstanceHandle instanceHandle);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      sampleCodeCyEventPoll
 *
 * @description
 *      Perform an event based poll for Crypto Instances
 *
 *
 *
 * @retval none
 *
 *
 *****************************************************************************/
void sampleCodeCyEventPoll(CpaInstanceHandle instanceHandle);

void sampleCodeCompletionInit(Cpa32U threadId);

CpaStatus sampleCodeThreadCollect(sample_code_thread_t *thread,
                                  Cpa32U threadId);

void sampleCodeThreadComplete(Cpa32U threadId);

Cpa32U getCPUSpeed(void);
Cpa32U updateCPUSpeed(void);

#endif /*_COMMON_SAMPLECODEUTILS_H__*/
