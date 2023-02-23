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
* @file cpa_sample_code_framework.h
*
* This file provides prototypes, macros and structures required in the sample
* code framework
*
*****************************************************************************/
#ifndef _SAMPLECODEFRAMEWORK_H__
#define _SAMPLECODEFRAMEWORK_H__

#include "busy_loop.h"
#include "cpa.h"
#include "cpa_cy_common.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_dc.h"

/* after terminate the loop, we need adjust loop offset */
#define OFFSET_LOOP_EXIT 1
#define EXIT_OFF 0
#define EXIT_IMMEDIATELY 1
#define EXIT_WHEN_THREADS_COMPLETE 2
/* The global variable dc_bufferCount_g should be initialized by
 *  * DEFAULT_NUM_OF_BUFF_PER_LIST */
#define DEFAULT_NUM_OF_BUFF_PER_LIST 1

/* this is used to allocate space for all types test setups, this is unknown to
 * the framework.
 * the size of this is based on the assumption that the CpaCySymSessionSetupData
 * is the largest setup structure in the QA API's so we set our size to be 2
 * times the size of CpaCySymSessionSetupData ~90bytes to allow enough room for
 * all setup types*/
#ifdef USER_SPACE
#define MAX_SETUP_STRUCT_SIZE_IN_BYTES (800)
#else
#define MAX_SETUP_STRUCT_SIZE_IN_BYTES (500)
#endif

/*the following macros are defined for default cores to be used in tests,
 * */
/*some functions, such as symmetric crypto have multi purpose (hash, cipher)
 * this means that some parameters passed to functions are not used, we define
 * and use this macro in the code where this an input parameter is not used*/
#define NOT_USED (0)

/*flag to indicate to createThreads function to create and bind a thread on all
 *  Available cores or just one core*/
#define USE_ALL_CORES (0)
#define USE_ONE_CORE (1)

/*flag to indicate to createThreads function start creating threads for this
 * core id and upwards*/
#define DEFAULT_CORE_OFFSET (0)

/*flag to the createThread function to attempt to use as many qa logical
 * instances as possible, however as the framework applies 1 thread per core
 * and each threads uses its own qaInstance, and there is generally more
 * qaInstances available then cores means that use of all qaLogicalInstances
 * is normally not possible*/
#define USE_ALL_QA_LOGICAL_INSTANCES (0)
#define USE_ONE_QA_LOGICAL_INSTANCE (1)

/*this defines the 1st qaLogicalInstance to be used with the 1st create thread
 * the each threads uses and incremental instance from this offset*/
#define DEFAULT_LOGICAL_INST_INSTANCE_OFFSET (0)

#define DEFAULT_MAP (0x1)
#define CRYPTO (1)
#define COMPRESSION (2)
#define SYM (3)
#define ASYM (4)
#define MAX_RETRY (10)
#define SLEEP_ONE_SEC (1)
#define SLEEP_ONE_HUNDRED_MILLISEC (100)



/* Common macro definitions */
#ifndef DC_API_VERSION_AT_LEAST
#define DC_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_DC_API_VERSION_NUM_MAJOR > major ||                                   \
     (CPA_DC_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_DC_API_VERSION_NUM_MINOR >= minor))
#endif

typedef CpaStatus (*compute_test_result_func_t)(void *);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      Thread Creation Setup Data.
 * @description
 *      This structure contains data relating to setting and replicating a
 *      thread across cores
 *
 ****************************************************************************/
typedef struct thread_creation_data_s
{
    performance_func_t performance_function;
    /*function to launch as a thread to measure performance */
    void *setupPtr;
    /*pointer to setup data specific to the performance Test type*/
    Cpa32U numberOfThreads;
    /*stores the number of threads to be created with the data store in
     * setupPtr*/
    perf_data_t *performanceStats[MAX_THREADS];
    /*stores performance stats for all threads of same test_type and same
     * setup*/
    Cpa32U packetSize;
    /*flat buffer size to be tested*/
    stats_print_func_t *statsPrintFunc;
    /*pointer to function capable of printing our stat related to specific
     * test varation*/
    Cpa32U megaRowId;
    /* mega row id reference */
    CpaBoolean isUsedByMega;
    /* indicates if this thread is created by mega api */
} thread_creation_data_t;

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      Thread Creation Setup Data.
 * @description
 *      This structure contains data relating to a single thread
 *
 ****************************************************************************/
typedef struct single_thread_test_data_s
{
    void *setupPtr;
    /*pointer to setup data specific to the performance Test type*/
    Cpa32U numberOfThreads;
    perf_data_t *performanceStats;
    /*performance stats points to one of the performanceStats of
     * thread_creation_data*/
    Cpa32U packetSize;
    /*flat buffer size to be tested*/
    Cpa32U logicalQaInstance;
    /*the logicalQaInstance for the thread to use*/
    stats_print_func_t statsPrintFunc;
    /*pointer to function capable of printing our status related to specific
     * test variation*/
    Cpa32U threadID;
    /* Unique Thread ID based on the order in which the thread is created */
    compute_test_result_func_t passCriteria;
    /* policy function that is called after the results have been collected
     * to determine pass criteria. Users can populate this pointer to add
     * specific pass criteria for the tests on per thread basis.
     */
    Cpa32U megaRowId;
    /* mega row id reference */
    CpaBoolean isUsedByMega;
    /* indicates if this thread is created by mega api */
} single_thread_test_data_t;

extern int useStaticPrime;
extern volatile CpaBoolean reliability_g;
extern volatile CpaBoolean cnverr_g;
extern volatile CpaBoolean cnvnrerr_g;
extern volatile CpaBoolean error_flag_g;
extern volatile CpaBoolean dataIntegrity_g;
extern volatile CpaBoolean dataIntegrityVerify_g;
extern volatile CpaBoolean hwVerify_g;
extern volatile CpaBoolean keyCorrupt_g;
CpaStatus setReliability(CpaBoolean val);
CpaStatus setUseStaticPrime(int val);

CpaStatus printReliability(void);

extern volatile CpaBoolean fineTune_g;
extern volatile Cpa16U iaCycleCount_g;
CpaStatus setFineTune(CpaBoolean val);

CpaStatus set_cy_slv(Cpa32U arg);
CpaStatus set_dc_slv(Cpa32U arg);
CpaStatus set_rsa_slv(Cpa32U arg);
CpaStatus set_buffer_count(Cpa32U arg);
void setVerboseOutput(int a);
int getVerboseOutput(void);
CpaStatus initPerfStats(Cpa32U testTypeIndex, Cpa32U numberOfThreads);
CpaStatus printPerfStats(Cpa32U testTypeNumber, Cpa32U threadNumber);

CpaStatus printFineTune(void);

CpaStatus enableSleeptime(void);
CpaStatus disableSleeptime(void);
CpaStatus enableAdjustSleepTime(void);
CpaStatus disableAdjustSleepTime(void);

/* Defines a global value for Trad API CPR rate */
extern volatile Cpa32U cprRate_g;
/* Controls cprRate_g via API */
CpaStatus setCprRate(Cpa32U rate);

/* Defines value iaCycleCount_g - disabled */
#define CPA_CC_DISABLE 0
/* Defines value iaCycleCount_g - enabled in timestamp mode */
#define CPA_CC_REQ_POLL_STAMP 1
/* Defines value iaCycleCount_g - enabled in busy loop mode */
#define CPA_CC_BUSY_LOOPS 2

/* Function for enabling cycle count in default mode */
CpaStatus enableCycleCount(void);
/* Function for disabling cycle count */
CpaStatus disableCycleCount(void);
/* Function used to set cycle count mode */
CpaStatus setCycleCountMode(int mode);

#include "cpa_dc.h"
/* after terminate the loop, we need adjust loop offset */
#define OFFSET_LOOP_EXIT 1
/*this global variable is used to terminate the stress cases from the loop
 * operation.
 * When it's set to CPA_TRUE, stress case will be terminated from the current
 * loop operation,
 * return successful. */
typedef struct stress_test_threads_params_s
{
    Cpa32U numBuffers;
    /*number of buffers */
    Cpa32U numDpBatchOp;
    /*number of Dp Batch Operation */
    Cpa32U numRequests;
    /*number of Dp requests */
    Cpa32U numSessions;
    /*number of Dp Session */
    Cpa32U numLoops;
    /*number of loop operation */
    Cpa32U numDcLoops;
    /*number of DC loop operation */
    Cpa32U modSizeInBits;
    Cpa32U expSizeInBits;
    CpaStatus threadReturnStatus;
    Cpa32U corpus;
    /*corpus for compression test */
    Cpa32U mask;
    /*bitmask */
    Cpa32U testType;
    /* Compression Test Type */
    CpaBoolean isStaticAndDynamic;
    /* Test both static and dynamic in a single function call */
    CpaDcCompType algorithm;
    /* Compression Algorithm to run */
    CpaDcSessionDir direction;
    /* Compression Direction */
    CpaDcHuffType huffmanType;
    /* Static or Dynamic Huffman trees */
    CpaDcSessionState state;
    /* Stateful or Stateless Compression */
    Cpa16U numSymInstances;
    /* Number of Sym instances required */
    Cpa16U numPkeInstances;
    /* Number of Pke instances required */
    Cpa16U numDcInstances;
    /* Number of Dc instances required */
    Cpa32U numDcStatefulThreads;
    /* Number of threads to create for Stateful compression tests */
    Cpa32U numPfsThreads;
    /* Number of threads to create for PFS tests */
    Cpa32U numCipherThreads;
    /* Number of threads to create for Cipher tests */
    Cpa32U numAlgChainThreads;
    /* Number of threads to create for Alg Chain tests */
    Cpa32U numHashThreads;
    /* Number of threads to create for Hash tests */
    Cpa32U numChainingThreads;
    /* Number of threads to create for Chaining tests */
} stress_test_threads_params_t;

extern sample_code_thread_t stress_test_threads_g;
extern stress_test_threads_params_t stress_test_threads_params_g;
typedef enum
{
    THREAD_NOT_STARTED = 0,
    THREAD_STARTED,
    THREAD_COMPLETED,
} thread_state_e;
extern volatile thread_state_e threadState_g;
extern volatile Cpa32U numCreatedThreads_g;
extern volatile CpaBoolean exitLoopFlag_g;
extern volatile CpaBoolean stopTestsIsEnabled_g;
extern int verboseOutput;
CpaStatus enableStopTests(void);
CpaStatus disableStopTests(void);
extern CpaStatus setExitLoopFlag(Cpa32U value);
void checkStopTestExitFlag(perf_data_t *performanceStats,
                           Cpa32U *numLoops,
                           Cpa32U *numLists,
                           Cpa32U localNumLoops);
extern CpaStatus getTestReturn(void);
extern volatile CpaBoolean xltOverflow_g;
extern CpaStatus enableXltOverflow(Cpa32U value);
extern volatile CpaBoolean poll_inline_g;
extern CpaBoolean sleepTime_enable;
extern CpaBoolean adjust_sleepTime_enable_g;
extern Cpa32U dc_slv_g;
extern Cpa32U cy_slv_g;
extern Cpa32U rsa_slv_g;
extern Cpa32U dc_bufferCount_g;
#ifdef POLL_INLINE
CpaStatus enablePollInline(void);
CpaStatus disablePollInline(void);
#endif

#define CHECK_TEST_TYPE_COUNT()                                                \
    if (testTypeCount_g >= MAX_THREAD_VARIATION)                               \
    {                                                                          \
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");     \
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g); \
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);                       \
        return CPA_STATUS_FAIL;                                                \
    }

/**
 * *****************************************************************************
 * *      these variables are used to keep status of the backoff timer settings
 * *       CpaBoolean backoff_timer_g - indicates if backoff timer is enabled
 * *            true - enabled
 * *            false - disabled
 * *       backoff_dynamic_g - indicates if dynamic algorithm is enabled
 * *           true - enabled (determine backoff delay dynamically)
 * *           false - disabled (use static backoff delay)
 * *        backoff_static_timer_g - number of busy loop cycles for the static
 * *            backoff timer
 * *****************************************************************************/
extern volatile CpaBoolean backoff_timer_g;
extern volatile CpaBoolean backoff_dynamic_g;
extern uint32_t backoff_static_timer_g;
extern Cpa32U testTypeCount_g;

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
CpaStatus enableBackoffTimer(void);

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
CpaStatus disableBackoffTimer(void);

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
CpaStatus enableBackoffDynamic(void);

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

/* *****************************************************************************
 * FUNCTION PROTOTYPES
 * ****************************************************************************/
/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      setCoreLimit
 *
 * @description
 *      this function limits the number of cores to be used in the create
 *      threads function
 *
 * @threadSafe
 *      No
 *
 *
 *
 * @param[in]      limit    the number of cores to create  threads on
 *
 *
 * @retval This function returns
 *  CPA_STATUS_SUCCESS when the limit is less than the number of cores on the
 *  system
 *  CPA_STATUS_FAIL when limit is > number of cores on the system
 *
 * @pre
 *      none
 * @post
 *      threads will be created on the limited number or cores
 *
 *****************************************************************************/
CpaStatus setCoreLimit(Cpa32U limit);

/* *****************************************************************************
 * FUNCTION PROTOTYPES
 * ****************************************************************************/
/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      createPerfomanceThreads
 *
 * @description
 *      This function creates threads. The threads are created across cores
 *      and to use separate qaLogicalInstances
 *
 * @threadSafe
 *      No
 *
 *
 *
 * @param[in]      numLogicalIaCoresToUse    the number of cores to create
 *                  threads on
 *
 * @param[in]   logicalIaCore - array containing cores to bind threads to
 *
 * @param[in]   numberLogicalInstancesToUse the number of qaLogicalInstancs to
 *              use, note the implementation will create the number of threads
 *              bases on the lower of numberOfIaCores to use or
 *              numberLogicalInstancesToUse
 *
 * @param[in]   startingLogicalInstanceOffset qaLogicalInstance to be used in
 *              1st threads, each subsequent thread increments this value
 *
 * @retval This function returns
 *  CPA_STATUS_SUCCESS when all threads were created
 *  CPA_STATUS_FAIL when some thing went wrong, an error should be printed to
 *      STDOUT in this case
 *
 * @pre
 *      user defined setup has been called which populates thread_setup_g with
 *      all the
 *      parameters and the function required to start the thread
 * @post
 *      Threads are created (but not started in the case of kernel threads, user
 *      threads have a barrier at the start to stop them until all threads
 *      have been created
 *
 *****************************************************************************/
CpaStatus createPerfomanceThreads(Cpa32U numLogicalIaCoresToUse,
                                  Cpa32U *logicalIaCore,
                                  Cpa32U numberLogicalInstancesToUse,
                                  Cpa32U startingLogicalInstanceOffset);
/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      qatModifyCyThreadLogicalQaInstance
 *
 * @description
 *      This function creates threads. The threads are created across cores
 *      and to use separate qaLogicalInstances
 *
 *
 * @param[in]   threadoffset : The thread number to start with reprocessing.
 *
 * @param[in]   cyIaCore     : The Crypto Instances array that includes both sym
 *                             and asym instances.
 *
 * @param[in]   symOrasymIaCore : The Symmetric or Asymetric Crypto array.
 *                             and asym instances.
 * @param[in]   numCyInstances  : size of cyIaCore array.
 *
 */
void qatModifyCyThreadLogicalQaInstance(Cpa8U threadOffset,
                                        CpaInstanceHandle *cyIaCore,
                                        CpaInstanceHandle *symOrAsymIaCore,
                                        Cpa8U numCyInstances);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      waitForThreadCompletion
 *
 * @description
 *      This function waits for all created threads to complete, then print all
 *      stats to STDOUT
 *
 * @threadSafe
 *      No
 *
 * @retval This function returns the success of the performance threads
 *
 * @pre
 *      threads have been started
 * @post
 *      threads are complete and stats printed to STDOUT
 *
 *****************************************************************************/
CpaStatus waitForThreadCompletion(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      Memory and thread Data cleanup.
 * @description
 *      This function reset the thread related variable and release memory
 * on error exit
 *
 ****************************************************************************/
void threadExitCleanup(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      startThreads
 *
 * @description
 *      This function starts all the created threads, or in the case of user
 *      threads frees the barrier to let them continue
 *
 * @threadSafe
 *      No
 *
 * @retval This function returns
 *  CPA_STATUS_SUCCESS when all threads were started
 *  CPA_STATUS_FAIL when some thing went wrong, an error should be printed to
 *      STDOUT in this case
 *
 * @pre
 *      threads have been started
 * @post
 *      threads are complete and stats printed to STDOUT
 *
 *****************************************************************************/
CpaStatus startThreads(void);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      killCreatedThreads
 *
 * @description
 *      This function kills the the last "numThreadsToKill" created threads
 *
 *
 * @threadSafe
 *      No
 *
 * @param[in]   numThreadsToKill this defines how many threads from the last one
 *              created to be killed
 *
 * @retval This function returns void
 *
 * @pre
 *      threads have been started
 * @post
 *      threads are complete and stats printed to STDOUT
 *
 *****************************************************************************/
void killCreatedThreads(Cpa32U numThreadsToKill);
CpaStatus createStartandWaitForCompletion(Cpa32U instType);
CpaStatus createStartandWaitForCompletionCrypto(Cpa32U instType);

/**
 *****************************************************************************
 * @ingroup perfCodeFramework
 *      clearPerfStats
 *
 * @description
 *      clears (zeros) an instance of perf_data_t
 *
 *
 * @threadSafe
 *      No
 *
 * @param[in]   *stats pointer to perf_data_t structure to be cleared
 *
 * @retval This function returns void
 *
 * @pre
 *      none
 * @post
 *      perf_data_t structure pointed to contains all 0's
 *
 *****************************************************************************/
void clearPerfStats(perf_data_t *stats);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      getLongestCycleCount
 *
 * @description
 *      get the smallest starting cycle and the largest end cycle from a list
 *      of perf_data_t structures. This function should be used on a collection
 *      of threads all testing the same thread Variation. the src data is set to
 *      zero once read.
 *****************************************************************************/
void getLongestCycleCount(perf_data_t *dest, perf_data_t *src[], Cpa32U count);

void getLongestCycleCount2(perf_data_t *dest,
                           perf_data_t *src[],
                           Cpa32U count,
                           Cpa32U *perfDataDeviceOffsets,
                           Cpa32U *threadCountPerDevice);

/**
 *****************************************************************************
 * The variables needed to control latency measurement at runtime
 *****************************************************************************
 */
extern int latency_debug;  /* set to 1 for debug PRINT() */
extern int latency_enable; /* set to 1 for enable latency testing */
extern CpaInstanceHandle *cyInst_g;
extern CpaInstanceHandle *symCyInst_g;
extern CpaInstanceHandle *asymCyInst_g;
extern CpaInstanceHandle *dcInst_g;
extern Cpa32U *cyInstMap_g;
extern Cpa32U *symCyInstMap_g;
extern Cpa32U *asymCyInstMap_g;
extern Cpa32U *dcInstMap_g;
extern Cpa32U instMap_g;
extern Cpa16U numInst_g;
extern Cpa8U singleInstRequired_g;

CpaStatus createStartandWaitForCompletion(Cpa32U instType);
CpaBoolean isSampleCodeBarrierLifted(void);

void freeInstanceMapping(void);

CpaStatus getCryptoInstanceMapping(void);
CpaStatus getSymInstanceMapping(Cpa16U *numSymInstances);
CpaStatus getAsymInstanceMapping(Cpa16U *numAsymInstances);

CpaStatus getCompressionInstanceMapping(void);

CpaStatus getCoreAffinity(CpaInstanceHandle instance,
                          Cpa32U *coreAffinity,
                          Cpa32U instType);


compute_test_result_func_t getPassCriteria(void);
void setPassCriteria(compute_test_result_func_t pfunc);
void saveClearRestorePerfStats(perf_data_t *perf);


#endif /*_SAMPLECODEFRAMEWORK_H__*/
