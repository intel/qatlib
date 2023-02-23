/***************************************************************************
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
 ***************************************************************************/

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file cpa_sample_code_framework.c
 *
 * @defgroup perfCodeFramework performance sample code framework
 *
 * @ingroup perfCodeFramework
 *
 * @description
 *      This file contains the test creation functions of the performance sample
 *      code framework.
 *      Functions contained in this file:
 *        - startThreads
 *        - waitForThreadCompletion
 *        - createPerformanceThreads
 *        - killCreatedThreads
 *        - clearPerfStats
 *
 *      functions within allow to create and run multiple threads.
 *
 *      The user defines the test setup(s) and function(s) to run and uses
 *      functions implemented here to create, start and wait for the threads to
 *      complete
 *
 *      the setup and functions called are defined elsewhere, but they must fit
 *      within the thread_creation_data_t and single_thread_test_data_t
 *      structures. Examples of how these are set can be seen in the crypto
 *      folder cpa_sample_code_crypto_utils.c ->setupSymetricTest
 *****************************************************************************/

#include "cpa_sample_code_framework.h"
#include "cpa_sample_code_crypto_utils.h"

/******************************************************************************
 * GLOBAL VARIABLES
 * These variables are used in the framework to provide setup information, a
 * location to write performance stats, count the number of threads and types of
 * threads, and to control the start of user space threads. THEY ARE NOT THREAD
 * SAFE. The only variable that the user should need to use is the
 * thread_setup_g array
 * The user will be required to write some setup data to this array.
 *
 * testTypeCount_g is used to control where the user writes there setup
 * data in thread_setup_g array
 *
 * The framework code ensures that writing to these variables is only done
 * before threads start and after they all complete. The only exception to this
 * is performance stats, where each thread as a unique location to store stats
 *
 ******************************************************************************/

/*store the threadId, this only used for thread setup and after threads are
 * complete, so it not required to be atomic*/
sample_code_thread_t threads_g[MAX_THREADS];

/*declare array of perf_stats pointers. Each thread is provided is own
 * perf_stats */
perf_data_t *perfStats_g[MAX_THREAD_VARIATION];

/*global flag to track if the perfStats_g array is initialized*/
CpaBoolean perfStatsInit_g = CPA_FALSE;

int useStaticPrime = 1;


volatile CpaBoolean isChangingThreadQaInstanceRequired_g = CPA_FALSE;
EXPORT_SYMBOL(isChangingThreadQaInstanceRequired_g);

/*this array stores the setup and performance data of all threads created.
 * there is duplication between this and testSetupData_g,
 * however this makes it easier for collation of stats when there are
 * multiple creations of one type of thread.
 * There is no sharing data between threads*/
single_thread_test_data_t singleThreadData_g[MAX_THREADS] = {{0}};

/*this array stores the setup and performance data of ONE_TYPE_OF_THREAD. This
 * is updated on thread setup and read and clear once all threads are complete*/
thread_creation_data_t testSetupData_g[MAX_THREAD_VARIATION] = {{0}};

/*declare space to store setup structures in. This stores all the setup of each
 * thread, there is no sharing between threads, so each section of the array
 * is autonomous to 1 thread*/
Cpa8U thread_setup_g[MAX_THREAD_VARIATION][MAX_SETUP_STRUCT_SIZE_IN_BYTES];
Cpa8U thread_name_g[MAX_THREAD_VARIATION][THREAD_NAME_LEN];

/*global variables -note syntax is to use _g for all global variables*/

/*this is used to count the total number of threads created, this is
 * incremented during the thread creation phase once threads are started it
 * is read only and set to zero when all threads are finished*/
volatile Cpa32U numCreatedThreads_g = 0;

int numThreadsToCreate_g = 0;

/**
 * Boolean flag used to indicate if any error occurred in submit,
 * polling threads or callback function
 */
volatile CpaBoolean error_flag_g = CPA_FALSE;

/*this is used to count the total number of threads reached to start barrier,
 * this is incremented during the thread reach to start barrier phase and
 * set to zero when all threads are executed */
volatile Cpa32U numThreadsAtBarrier_g = 0;

/*this is used to count the number of different thread variations created,
 * it is incremented during thread setup and is read only once threads are
 * started. It is set to zero one all threads are complete*/
Cpa32U testTypeCount_g = 0;
Cpa32U packageIdCount_g = 0;
EXPORT_SYMBOL(packageIdCount_g);
CpaBoolean devicesCounted_g = CPA_FALSE;
/*this is used to limit the maximum number of cores uses in the thread
 * creation*/
Cpa32U coreLimit_g = 0;

/*this is used to stop user space threads from executing to the main barrier
 * before all threads are created*/
/*this is a shared mutex between user space threads, if one thread locks this
 * all other threads wait until its released, which is done by calling the
 * cpa_sample_code_mutex_unlock ot cpa_sample_code_barrier_wait function*/
sample_code_thread_mutex_t threadControlMutex_g;

/*this is the conditional variable that user space threads wait on to start, the
 * conditional variable is broadcast on call of startThreads, sends a broadcast
 * to all user space threads waiting at cpa_sample_code_barrier, each thread
 * attempts to lock the mutex above, restart its code, then release the mutex*/
sample_code_thread_cond_t threadConditionControl_g;

/* this is used to stop user space threads from executing once registered with
 * the framework.
 * This mutex is initialized by startBarrierInit() and the locking/unlocking
 * mechanism is supported in startBarrier().
 */
sample_code_thread_mutex_t startThreadControlMutex_g;

/*this is the conditional variable that user space threads wait on to start, the
 * conditional variable is broadcast on call of startThreads, sends a broadcast
 * to all user space threads waiting at cpa_sample_code_barrier, each thread
 * attempts to lock the mutex above, restart its code, then release the mutex*/
sample_code_thread_cond_t startThreadConditionControl_g;

/*this is local to this file and it only used once thread setup to indicate
 * whether threadControlMutex_g and threadConditionControl_g have been
 * initialized. It is reset to false once all threads are complete*/
CpaBoolean threadControlInitilised_g = CPA_FALSE;

/* Threads other then the performance threads may like the know if the
 * barrier has been lifted and the performance threads have started to load
 * the QAT. SampleCodeBarrierLifted is set to CPA_TRUE when barrier is
 * lifted.
 */
CpaBoolean SampleCodeBarrierLifted = CPA_FALSE;

/*this is used to check if all the threads have
 * been started, before that waitForCompletion function will hang forever
 * waiting for threads to end their work.*/
volatile thread_state_e threadState_g = THREAD_NOT_STARTED;

volatile CpaBoolean reliability_g = CPA_FALSE;
volatile CpaBoolean cnverr_g = CPA_FALSE;
volatile CpaBoolean cnvnrerr_g = CPA_FALSE;
volatile CpaBoolean dataIntegrity_g = CPA_FALSE;
volatile CpaBoolean dataIntegrityVerify_g = CPA_FALSE;
volatile CpaBoolean hwVerify_g = CPA_FALSE;
volatile CpaBoolean keyCorrupt_g = CPA_FALSE;
int verboseOutput = 1;

CpaStatus setDataIntegrity(CpaBoolean val)
{
    dataIntegrity_g = val;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dataIntegrity_g);
EXPORT_SYMBOL(setDataIntegrity);

CpaStatus setDataIntegrityVerify(CpaBoolean val)
{
    dataIntegrity_g = val;
    dataIntegrityVerify_g = val;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(dataIntegrityVerify_g);
EXPORT_SYMBOL(setDataIntegrityVerify);

CpaStatus setReliability(CpaBoolean val)
{
    if (val != 0)
    {
        reliability_g = CPA_TRUE;
    }
    else
    {
        reliability_g = CPA_FALSE;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus setUseStaticPrime(int val)
{
    if (val != 0)
    {
        useStaticPrime = 1;
    }
    else
    {
        useStaticPrime = 0;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(useStaticPrime);

CpaStatus printReliability(void)
{
    if (CPA_TRUE == reliability_g)
    {
        PRINT("reliability_g = %s", "CPA_TRUE\n");
    }
    else
    {
        PRINT("reliability_g = %s", "CPA_FALSE\n");
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus setHwVerify(CpaBoolean val)
{
    if (val != 0)
    {
        hwVerify_g = CPA_TRUE;
    }
    else
    {
        hwVerify_g = CPA_FALSE;
    }
    return CPA_STATUS_SUCCESS;
}
CpaStatus setKeyCorrupt(CpaBoolean val)
{
    if (val != 0)
    {
        keyCorrupt_g = CPA_TRUE;
    }
    else
    {
        keyCorrupt_g = CPA_FALSE;
    }
    return CPA_STATUS_SUCCESS;
}

EXPORT_SYMBOL(reliability_g);
EXPORT_SYMBOL(setReliability);
EXPORT_SYMBOL(setUseStaticPrime);
EXPORT_SYMBOL(printReliability);
EXPORT_SYMBOL(hwVerify_g);
EXPORT_SYMBOL(setHwVerify);
EXPORT_SYMBOL(setKeyCorrupt);
EXPORT_SYMBOL(keyCorrupt_g);

/*Global flag to enable sleep function that is used to slow down pulling for
 *request on thread RETRY e.g. concurrent performance measurements*/
CpaBoolean sleepTime_enable = CPA_FALSE;
CpaStatus enableSleeptime(void)
{
    sleepTime_enable = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableSleeptime);

CpaStatus disableSleeptime(void)
{
    sleepTime_enable = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableSleeptime);

/*Global flag to enable adjustable sleep value*/
CpaBoolean adjust_sleepTime_enable_g = CPA_FALSE;

CpaStatus enableAdjustSleepTime(void)
{
    adjust_sleepTime_enable_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableAdjustSleepTime);

CpaStatus disableAdjustSleepTime(void)
{
    adjust_sleepTime_enable_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableAdjustSleepTime);

/*Global sleep values for DC/SYM/RSA must be set for sleeptime functionality*/
Cpa32U dc_slv_g;
Cpa32U cy_slv_g;
Cpa32U rsa_slv_g;
Cpa32U dc_bufferCount_g = DEFAULT_NUM_OF_BUFF_PER_LIST;
CpaStatus set_dc_slv(Cpa32U arg)
{
    dc_slv_g = arg;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(set_dc_slv);

CpaStatus set_cy_slv(Cpa32U arg)
{
    cy_slv_g = arg;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(set_cy_slv);

CpaStatus set_rsa_slv(Cpa32U arg)
{
    rsa_slv_g = arg;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(set_rsa_slv);
CpaStatus set_buffer_count(Cpa32U arg)
{
    dc_bufferCount_g = arg;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(set_buffer_count);
EXPORT_SYMBOL(dc_bufferCount_g);
volatile CpaBoolean fineTune_g = CPA_FALSE;
volatile Cpa16U iaCycleCount_g = CPA_CC_DISABLE;

/* Global Gbps rate for compression requests */
volatile Cpa32U cprRate_g = 0xFFFFFFFE;

/* Setter function for lobal Gbps rate for compression requests */
CpaStatus setCprRate(Cpa32U rate)
{
    cprRate_g = rate;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setCprRate);

CpaStatus setFineTune(CpaBoolean val)
{
    fineTune_g = val;
    return CPA_STATUS_SUCCESS;
}

CpaStatus printFineTune(void)
{
    if (CPA_TRUE == fineTune_g)
    {
        PRINT("fineTune_g = %s", "CPA_TRUE\n");
    }
    else
    {
        PRINT("fineTune_g = %s", "CPA_FALSE\n");
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus enableCycleCount(void)
{
    /* fail if already enabled */
    if (CPA_CC_DISABLE != iaCycleCount_g)
        return CPA_STATUS_FAIL;

    iaCycleCount_g = CPA_CC_REQ_POLL_STAMP;
    return CPA_STATUS_SUCCESS;
}

CpaStatus disableCycleCount(void)
{
    iaCycleCount_g = CPA_CC_DISABLE;
    return CPA_STATUS_SUCCESS;
}

CpaStatus setCycleCountMode(int mode)
{
    iaCycleCount_g = mode;
    return CPA_STATUS_SUCCESS;
}

/*this function enables extra output from sample code such as: per thread and
 * per device performance.*/
int getVerboseOutput(void)
{
    return verboseOutput;
}

/*this function disables extra output from sample code such as: per thread and
 * per device performance.*/
void setVerboseOutput(int a)
{
    verboseOutput = a;
    return;
}
EXPORT_SYMBOL(iaCycleCount_g);
EXPORT_SYMBOL(getVerboseOutput);
EXPORT_SYMBOL(setVerboseOutput);
EXPORT_SYMBOL(enableCycleCount);
EXPORT_SYMBOL(disableCycleCount);
EXPORT_SYMBOL(setFineTune);
EXPORT_SYMBOL(printFineTune);

volatile CpaBoolean poll_inline_g = CPA_FALSE;
volatile CpaBoolean xltOverflow_g = CPA_FALSE;
volatile CpaBoolean exitLoopFlag_g = CPA_FALSE;
volatile CpaBoolean stopTestsIsEnabled_g = CPA_FALSE;



/* This is function is used to save and restore members
 * of perf stats that should persist after clearing all
 * others.
 */
void saveClearRestorePerfStats(perf_data_t *perf)
{

    memset(perf, 0, sizeof(perf_data_t));

}

sample_code_thread_t stress_test_threads_g;
stress_test_threads_params_t stress_test_threads_params_g = {0};
CpaStatus getTestReturn(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    sampleCodeThreadJoin(&stress_test_threads_g);

    if (error_flag_g == CPA_TRUE)
    {
        stress_test_threads_params_g.threadReturnStatus = CPA_STATUS_FAIL;
        error_flag_g = CPA_FALSE;
    }

    status = stress_test_threads_params_g.threadReturnStatus;
    stress_test_threads_params_g.threadReturnStatus = CPA_STATUS_SUCCESS;

    return status;
}
EXPORT_SYMBOL(getTestReturn);

#ifdef POLL_INLINE
CpaStatus enablePollInline(void)
{
    poll_inline_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enablePollInline);

CpaStatus disablePollInline(void)
{
    poll_inline_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disablePollInline);
#endif

CpaStatus enableStopTests(void)
{
    stopTestsIsEnabled_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableStopTests);
EXPORT_SYMBOL(stopTestsIsEnabled_g);

CpaStatus disableStopTests(void)
{
    stopTestsIsEnabled_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(disableStopTests);

CpaStatus setExitLoopFlag(Cpa32U value)
{
    switch (value)
    {
        case EXIT_OFF:
            exitLoopFlag_g = CPA_FALSE;
            return CPA_STATUS_SUCCESS;
        case EXIT_IMMEDIATELY:
            /*setExitLoop flag to complete thread in their current loop*/
            exitLoopFlag_g = CPA_TRUE;
            break;
        case EXIT_WHEN_THREADS_COMPLETE:
            /*wait for thread control flag to be set to false in
             * waitForThreadCompletion. Break if error flag was set*/
            while (threadState_g != THREAD_COMPLETED &&
                   error_flag_g == CPA_FALSE)
            {
                /*wait for all threads to complete*/
                sampleCodeSleepMilliSec(SLEEP_ONE_HUNDRED_MILLISEC);
            }
            break;
        default:
            PRINT_ERR("Invalid input to %s\n", __func__);
            return CPA_STATUS_FAIL;
    }
    return getTestReturn();
}

/*exit loop mechanism to leave early if numLoops is large
 * note that this might not work if the we get stuck in the
 * do-while loop below*/
/**
 *****************************************************************************
 * @file cpa_sample_code_framework.c
 *
 * @defgroup perfCodeFramework performance sample code framework
 *
 * @ingroup perfCodeFramework
 *
 * @description
 *      Exit loop mechanism to leave early if the exitLoopFlag is set
 *      as it will change the value of numLoops in the setup structure to the
 *      current index value of the loop + EXIT_OFFSET
 *      numLoops is indicating how many time program will loop over the files.
 *
 * @param[in]   performanceStats        Pointer to perf_data_t structure
 * @param[in]   numLoops                Pointer to numLoops element in the setup
 *                                      structure
 * @param[in]   numLists                Pointer to numLists element in the setup
 *                                      structure
 * @param[in]   localNumLoops           current value of iteration over numLoops
 *                                      numLoops from the structure will be
 *                                      allocated to this value + OFFSET
 *
 *****************************************************************************/
void checkStopTestExitFlag(perf_data_t *performanceStats,
                           Cpa32U *numLoops,
                           Cpa32U *numLists,
                           Cpa32U localNumLoops)
{

    if (CPA_TRUE == stopTestsIsEnabled_g)
    {
        /* Check if terminated by global flag.
         * If yes, update numOperations and numLoops completed
         */
        if (CPA_TRUE == exitLoopFlag_g)
        {
            *numLoops = localNumLoops + OFFSET_LOOP_EXIT;
            performanceStats->numOperations = (Cpa64U)(*numLoops) * (*numLists);
            performanceStats->numLoops = (*numLoops);
        }
    }
}

CpaStatus enableXltOverflow(Cpa32U value)
{
    if (0 == value)
    {
        xltOverflow_g = CPA_FALSE;
    }
    else
    {
        xltOverflow_g = CPA_TRUE;
    }
    return CPA_STATUS_SUCCESS;
}
/*
 * The default values for the backoff timer
 */
volatile CpaBoolean backoff_timer_g = CPA_TRUE;
volatile CpaBoolean backoff_dynamic_g = CPA_TRUE;
uint32_t backoff_static_timer_g = 10;

EXPORT_SYMBOL(backoff_timer_g);
EXPORT_SYMBOL(backoff_dynamic_g);
EXPORT_SYMBOL(backoff_static_timer_g);

CpaStatus enableBackoffTimer()
{
    backoff_timer_g = CPA_TRUE;
    return CPA_STATUS_SUCCESS;
}
CpaStatus disableBackoffTimer()
{
    backoff_timer_g = CPA_FALSE;
    return CPA_STATUS_SUCCESS;
}

CpaStatus enableBackoffDynamic()
{
    backoff_dynamic_g = CPA_TRUE;
    enableBackoffTimer();
    return CPA_STATUS_SUCCESS;
}

CpaStatus enableBackoffStatic(uint32_t numBusyLoops)
{
    backoff_static_timer_g = numBusyLoops;
    backoff_dynamic_g = CPA_FALSE;
    enableBackoffTimer();
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableBackoffStatic);

/***************************************************************************
 * FUNCTION IMPLEMENTATIONS
 * *************************************************************************/

/* This function calls the OS to start all the created threads*/
CpaStatus startThreads(void)
{
    Cpa32U threadId = 0;
    Cpa32U i = 0;

    FUNC_ENTRY();

    /* Wait for all the threads arrived to start barrier state and then
     * send broadcast message to all threads for execution */
    sample_code_wait_threads_arrived(SLEEP_ONE_SEC, MAX_RETRY);

    /* broadcast to user space threads that they can start, this does nothing
     * in kernel space*/
    sample_code_thread_mutex_lock(&startThreadControlMutex_g);
    sample_code_thread_cond_broadcast(&startThreadConditionControl_g);
    sample_code_thread_mutex_unlock(&startThreadControlMutex_g);

    /*start all threads*/
    for (threadId = 0; threadId < numCreatedThreads_g; threadId++)
    {
        if (sampleCodeThreadStart(&threads_g[threadId]) != CPA_STATUS_SUCCESS)
        {
            /* if we cant start one thread we kill all created threads
             * and return fail*/
            for (threadId = 0; threadId < numCreatedThreads_g; threadId++)
            {
                if (numCreatedThreads_g > 0)
                {
                    sampleCodeThreadKill(&threads_g[numCreatedThreads_g - 1]);
                    numCreatedThreads_g--;
                }
            }
            for (i = 0; i < testTypeCount_g; i++)
            {
                if (NULL != perfStats_g[i])
                {
                    qaeMemFree((void **)&perfStats_g[i]);
                }
            }
            PRINT_ERR("cant start threads\n");
            return CPA_STATUS_FAIL;
        }
    }
    /* after that each thread has started, set the flag that indicate
     * startThreads has been called*/
    threadState_g = THREAD_STARTED;
    /* Reset the flag, when all threads are executed */
    numThreadsAtBarrier_g = 0;
    FUNC_EXIT();
    return CPA_STATUS_SUCCESS;
}

/*This functions waits for all threads to complete including all perform
 * operations. It is required to wait for all threads to complete so that
 * performance stats can be collated*/
CpaStatus waitForThreadCompletion(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    stats_print_func_t statsPrintFunc;
    FUNC_ENTRY();

    /* Check if starThread has been called*/
    if (threadState_g == THREAD_STARTED)
    {
        /* Wait for all threads_g to complete */
        for (i = 0; i < numCreatedThreads_g; i++)
        {
            if (CPA_STATUS_SUCCESS != sampleCodeThreadCollect(&threads_g[i], i))
            {
                PRINT_ERR("sampleCodeThreadCollect failed\n");
                status = CPA_STATUS_FAIL;
            }
            /* If user supplied specific pass criteria,
             * determine test status using it.
             */
            if (singleThreadData_g[i].passCriteria != NULL)
            {
                if (CPA_STATUS_SUCCESS != singleThreadData_g[i].passCriteria(
                                              (void *)(&singleThreadData_g[i])))
                    status = CPA_STATUS_FAIL;
            }
            else
            {
                if ((CPA_STATUS_FAIL ==
                     singleThreadData_g[i]
                         .performanceStats->threadReturnStatus) ||
                    (error_flag_g == CPA_TRUE))
                {
                    status = CPA_STATUS_FAIL;
                }
            }
            if (CPA_TRUE == singleThreadData_g[i].isUsedByMega)
            {
                if (CPA_STATUS_FAIL == status)
                {
                    PRINT_ERR("Mega Thread using row %d failed\n",
                              singleThreadData_g[i].megaRowId);
                }
                else
                {
                    PRINT("Mega Thread using row %d passed\n",
                          singleThreadData_g[i].megaRowId);
                }
            }
        }
/*print out collated stats for all types of threads*/
#ifndef NEWDISLAY
        PRINT("---------------------------------------\n");
#endif
        for (i = 0; i < testTypeCount_g; i++)
        {
            statsPrintFunc = *(testSetupData_g[i].statsPrintFunc);
            if (statsPrintFunc != NULL)
            {
                statsPrintFunc(&testSetupData_g[i]);
            }
            else
            {
                PRINT_ERR("Unable to print stats for thread variation %d\n", i);
            }
            if (NULL != perfStats_g[i])
            {
                qaeMemFree((void **)&perfStats_g[i]);
            }
            if (i < testTypeCount_g - 1)
            {
                PRINT("---------------------------------------\n\n");
            }
        }
#ifndef NEWDISLAY
        PRINT("---------------------------------------\n\n");
#endif
        /* Clean up and exit */
        error_flag_g = CPA_FALSE;
        threadControlInitilised_g = CPA_FALSE;
        threadState_g = THREAD_COMPLETED;
        numCreatedThreads_g = 0;
        testTypeCount_g = 0;
        packageIdCount_g = 0;
        devicesCounted_g = CPA_FALSE;
        sampleCodeBarrierDestroy();
    }
    else
    {
        PRINT_ERR("startThreads() has not been called\n");
    }
    FUNC_EXIT();

    return status;
}

/*this function reset the thread related variables and release memory on error
 * exit */
void threadExitCleanup(void)
{
    Cpa32U i = 0;
    for (i = 0; i < testTypeCount_g; i++)
    {
        if (NULL != perfStats_g[i])
        {
            qaeMemFree((void **)&perfStats_g[i]);
        }
    }
    threadControlInitilised_g = CPA_FALSE;
    threadState_g = THREAD_COMPLETED;
    testTypeCount_g = 0;
    packageIdCount_g = 0;
    devicesCounted_g = CPA_FALSE;
}

/*this function limits the number of cores to be used in the create threads
 * function*/
CpaStatus setCoreLimit(Cpa32U limit)
{
    Cpa32U nProcessorsOnline = sampleCodeGetNumberOfCpus();
    if (limit > nProcessorsOnline)
    {
        PRINT_ERR("exceeds number of cores (%u) on system\n",
                  nProcessorsOnline);
        return CPA_STATUS_FAIL;
    }
    coreLimit_g = limit;
    return CPA_STATUS_SUCCESS;
}

/*Init perfStats_g for all thread types to NULL*/
CpaStatus initPerfStats(Cpa32U testTypeIndex, Cpa32U numberOfThreads)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;

    if (perfStatsInit_g == CPA_FALSE)
    {
        for (i = 0; i < MAX_THREAD_VARIATION; i++)
        {
            perfStats_g[i] = NULL;
        }
        perfStatsInit_g = CPA_TRUE;
    }
    /*free if not already free, this should not happen, so print a warning
     * in the event that it needed to be free'd*/
    if (NULL != perfStats_g[testTypeIndex])
    {
        PRINT("Warning perfStats not free'd from previous use\n");
        qaeMemFree((void **)&perfStats_g[testTypeIndex]);
    }
    /*allocate memory to store perfStats for each thread created*/
    perfStats_g[testTypeIndex] =
        qaeMemAlloc(sizeof(perf_data_t) * numberOfThreads);
    if (NULL == perfStats_g[testTypeIndex])
    {
        PRINT_ERR("Could not allocate memory for perfStats_g[%u]\n",
                  testTypeIndex);
        status = CPA_STATUS_FAIL;
    }
    return status;
}

/*This function creates threads based on the pre-condition that the user has
 * called a setup function that has populated the oneTypeOfThreadData. This
 * function creates threads based on what is in the oneTypeOfThreadData at the
 * current threadVariationCount (which is an index into the oneTypeOfThreadData
 * array.
 * This function replicates threads across cores*/
CpaStatus createPerfomanceThreads(Cpa32U numLogicalIaCoresToUse,
                                  Cpa32U *logicalIaCore,
                                  Cpa32U numberLogicalInstancesToUse,
                                  Cpa32U startingQaLogicalInstanceOffset)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;

    Cpa32U qaLogicalInstance = startingQaLogicalInstanceOffset;
    Cpa32U totalNumberOfThreads = 0;
    /*this is the total number of threads to create of the current setup and
     * depends on either how many cores are on the SUT or how many the user
     * wants to use*/

    performance_func_t functionPtr = NULL;
    Cpa32U nProcessorsOnline = 0;
    sample_code_thread_attr_t *threadAttr = NULL;

    /*1st we check that we still have room to store details of the threads to
     * be created*/
    if (testTypeCount_g >= MAX_THREAD_VARIATION)
    {
        PRINT_ERR("Maximum Support Thread Variation has been exceeded\n");
        PRINT_ERR("Number of Thread Variations created: %d", testTypeCount_g);
        PRINT_ERR(" Max is %d\n", MAX_THREAD_VARIATION);
        return CPA_STATUS_FAIL;
    }

    if (testSetupData_g[testTypeCount_g].performance_function == NULL)
    {
        PRINT_ERR("No thread function has been set\n");
        return CPA_STATUS_FAIL;
    }
    /*initialize thread control for user space, in kernel space this code
     * does nothing, we only do this once*/
    if (threadControlInitilised_g == CPA_FALSE)
    {
        sampleCodeBarrierInit();
        startBarrierInit();
        threadControlInitilised_g = CPA_TRUE;
    }
    /*get the number of cores on the system*/
    nProcessorsOnline = sampleCodeGetNumberOfCpus();
    /*calculate the number of threads to be setup*/
    if (numLogicalIaCoresToUse != USE_ALL_CORES)
    {
        totalNumberOfThreads = numLogicalIaCoresToUse;
    }
    else
    {
        if (coreLimit_g > 0)
        {
            totalNumberOfThreads = coreLimit_g;
        }
        else
        {
            totalNumberOfThreads = nProcessorsOnline;
        }
    }
    /*populate the threadData we area creating*/
    /*&thread_setup_g[testTypeCount_g][0] is a pointer to an area of memory
     * that contains the setup, so get the base address of this memory location
     * */
    testSetupData_g[testTypeCount_g].setupPtr =
        &thread_setup_g[testTypeCount_g][0];
    testSetupData_g[testTypeCount_g].numberOfThreads = totalNumberOfThreads;

    functionPtr = testSetupData_g[testTypeCount_g].performance_function;

    /* Set numThreadsToCreate so that if any thread rushes to doing its actual
     * processing,
     * it's stopped by sampleCodeBarrier until number of threads reaching
     * barrier becomes
     * equal to this variable
     */
    numThreadsToCreate_g = totalNumberOfThreads;

    status = initPerfStats(testTypeCount_g, numThreadsToCreate_g);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
    /*populate threadData with performance stats,
     * setupData and sessions etc...*/
    for (i = 0; i < totalNumberOfThreads; i++)
    {
        /*wrap around core to use if we have exceed max number of cores*/
        if (logicalIaCore[i] >= nProcessorsOnline)
        {
            PRINT("Warning we have reached core limit ");
            PRINT("resetting core to 0\n");
            logicalIaCore[i] = 0;
        }
        /*check that we have not reached allocated memory limit to store
         * thread data*/
        if (numCreatedThreads_g >= MAX_THREADS)
        {
            PRINT_ERR("Maximum Support Thread has been reached\n");
            PRINT_ERR("Number of Threads created: %d ", numCreatedThreads_g);
            PRINT_ERR("Max is %d\n", MAX_THREADS);
            /*kill any threads we have created in this current function
             * context*/
            killCreatedThreads(i);
            if (NULL != perfStats_g[testTypeCount_g])
            {
                qaeMemFree((void **)&perfStats_g[testTypeCount_g]);
            }
            return CPA_STATUS_FAIL;
        }

        if ((testTypeCount_g < MAX_THREAD_VARIATION))
        {
            clearPerfStats(&perfStats_g[testTypeCount_g][i]);
            testSetupData_g[testTypeCount_g].performanceStats[i] =
                &perfStats_g[testTypeCount_g][i];
            testSetupData_g[testTypeCount_g].statsPrintFunc =
                &singleThreadData_g[numCreatedThreads_g].statsPrintFunc;
            /*&thread_setup_g[testTypeCount_g][0] is a pointer to an area of
             * memory that contains the setup, so get the base address of this
             * memory location, the thread that we call is expected to be able
             * to cast this memory location into the structure that it expects*/
            singleThreadData_g[numCreatedThreads_g].setupPtr =
                &thread_setup_g[testTypeCount_g][0];
            singleThreadData_g[numCreatedThreads_g].performanceStats =
                &perfStats_g[testTypeCount_g][i];
            singleThreadData_g[numCreatedThreads_g].packetSize =
                testSetupData_g[testTypeCount_g].packetSize;
            singleThreadData_g[numCreatedThreads_g].logicalQaInstance =
                qaLogicalInstance;
            singleThreadData_g[numCreatedThreads_g].threadID =
                numCreatedThreads_g;
            singleThreadData_g[numCreatedThreads_g].passCriteria = NULL;

            singleThreadData_g[numCreatedThreads_g].megaRowId =
                testSetupData_g[testTypeCount_g].megaRowId;
            singleThreadData_g[numCreatedThreads_g].isUsedByMega =
                testSetupData_g[testTypeCount_g].isUsedByMega;

            /*Initialize completion structure for kernel space thread
             * management.*/
            sampleCodeCompletionInit(numCreatedThreads_g);
            /*we need to increment numCreatedThreads_g here otherwise if it
             * is used in the new thread there could be timing issue*/
            numCreatedThreads_g++;
            status = sampleCodeThreadCreate(
                &threads_g[numCreatedThreads_g - 1],
                threadAttr,
                functionPtr,
                &singleThreadData_g[numCreatedThreads_g - 1]);
        }
        else
        {
            PRINT_ERR("testTypeCount_g or thread variations hit max limit");
            status = CPA_STATUS_FAIL;
        }
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Failed to create thread: %d", i);
            /*we can safely kill all threads in kernel space because
             *  they have not started...in user space,  dynamically
             *  allocated memory is assumed to be freed by the OS*/
            numCreatedThreads_g--;
            killCreatedThreads(i);
            if (NULL != perfStats_g[testTypeCount_g])
            {
                qaeMemFree((void **)&perfStats_g[testTypeCount_g]);
            }
            return CPA_STATUS_FAIL;
        }
        else
        {

/*tie a create thread to a specific core */
#if defined(_WIN64) || defined(WIN32)
            singleThreadData_g[numCreatedThreads_g - 1]
                .performanceStats->logicalCoreAffinity = logicalIaCore[i];
#endif
            if (CPA_STATUS_SUCCESS !=
                sampleCodeThreadBind(&threads_g[numCreatedThreads_g - 1],
                                     logicalIaCore[i]))
            {
                PRINT_ERR("Failed to bind thread: %d", i);
                killCreatedThreads(i);
                if (NULL != perfStats_g[testTypeCount_g])
                {
                    qaeMemFree((void **)&perfStats_g[testTypeCount_g]);
                }
                return CPA_STATUS_FAIL;
            }
        }
        qaLogicalInstance++;
        /*wrap around qaLogicalInstance if we have used all that was intended
         * to use
         * WARNING this framework is not aware of the number of QA instances
         * in the system it assumes the user will pass in the right
         * information*/
        if (qaLogicalInstance - startingQaLogicalInstanceOffset ==
            numberLogicalInstancesToUse)
        {
            qaLogicalInstance = startingQaLogicalInstanceOffset;
        }
    }
    testTypeCount_g++;

    return CPA_STATUS_SUCCESS;
}

/* This function reprocesses the threads setting the logicalQaCoreIndex
 * correctly within each already created Crypto Thread
 * Input Arguments:
 * threadoffset : The thread number to start with reprocessing.
 * cyIaCore     : The Crypto Instances array that includes both sym
 *                and asym instances.
 * symOrasymIaCore : The Symmetric or Asymetric Crypto array.
 * numCyInstances : size of cyIaCore array.
 */
void qatModifyCyThreadLogicalQaInstance(Cpa8U threadOffset,
                                        CpaInstanceHandle *cyIaCore,
                                        CpaInstanceHandle *symOrAsymIaCore,
                                        Cpa8U numCyInstances)
{
    Cpa32U i = 0;
    Cpa8U j = 0;

    for (i = threadOffset; i < numCreatedThreads_g; i++)
    {
        for (j = 0; j < numCyInstances; j++)
        {
            if (symOrAsymIaCore[singleThreadData_g[i].logicalQaInstance] ==
                cyIaCore[j])
            {
                singleThreadData_g[i].logicalQaInstance = j;
                break;
            }
        }
    }
}

CpaBoolean isSampleCodeBarrierLifted(void)
{
    return SampleCodeBarrierLifted;
}
EXPORT_SYMBOL(isSampleCodeBarrierLifted);

void killCreatedThreads(Cpa32U numThreadsToKill)
{
    Cpa32U j = 0;

    /*kill any create threads*/
    if (numThreadsToKill > numCreatedThreads_g)
    {
        numThreadsToKill = numCreatedThreads_g;
    }

    for (j = 0; j < numThreadsToKill; j++)
    {
        if (numCreatedThreads_g > 0)
        {
            sampleCodeThreadKill(&threads_g[numCreatedThreads_g - 1]);
            numCreatedThreads_g--;
        }
    }
}

void clearPerfStats(perf_data_t *stats)
{
    memset(stats, 0, sizeof(perf_data_t));
}

void getLongestCycleCount(perf_data_t *dest, perf_data_t *src[], Cpa32U count)
{
    Cpa32U i = 0;

    if (NULL != dest && NULL != src && NULL != src[0])
    {
        dest->startCyclesTimestamp = src[0]->startCyclesTimestamp;
        dest->endCyclesTimestamp = src[0]->endCyclesTimestamp;
    }
    else
    {
        PRINT_ERR("Cannot get cycle counts,"
                  " performance data points to NULL\n");
        return;
    }
    for (i = 1; i < count; i++)
    {
        /*get the lowest start time*/
        if ((src[i]->startCyclesTimestamp < dest->startCyclesTimestamp))
        {
            dest->startCyclesTimestamp = src[i]->startCyclesTimestamp;
        }
        /*get the high finish time*/
        if ((src[i]->endCyclesTimestamp > dest->endCyclesTimestamp))
        {
            dest->endCyclesTimestamp = src[i]->endCyclesTimestamp;
        }
    }
}

void getLongestCycleCount2(perf_data_t *dest,
                           perf_data_t *src[],
                           Cpa32U count,
                           Cpa32U *perfDataDeviceOffsets,
                           Cpa32U *threadCountPerDevice)
{
    Cpa32U i = 0;
    Cpa32U j = 0;

    /*zero out perfDataDeviceOffsets*/
    for (i = 0; i < (packageIdCount_g + 1); i++)
    {
        threadCountPerDevice[i] = 0;
        perfDataDeviceOffsets[i] = 0;
    }

    /* Count the threadPerDevice value based on
     * package Id of first thread */
    j = src[0]->packageId;
    threadCountPerDevice[j] = 1;
    for (i = 1; i < count; i++)
    {
        if (src[i]->packageId > src[i - 1]->packageId)
        {
            j++;
            perfDataDeviceOffsets[j] = i;
        }
        if (j < (packageIdCount_g + 1))
        {
            threadCountPerDevice[j]++;
        }
    }
    for (i = 0; i < (packageIdCount_g + 1); i++)
    {
        getLongestCycleCount(
            &dest[i], &src[perfDataDeviceOffsets[i]], threadCountPerDevice[i]);
    }
}

/* get the core affinity of a given instance handle */
CpaStatus getCoreAffinity(CpaInstanceHandle instance,
                          Cpa32U *coreAffinity,
                          Cpa32U instType)
{
    CpaInstanceInfo2 info = {0};
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_FAIL;

    switch (instType)
    {
#ifdef DO_CRYPTO
        case CRYPTO:
        {
            status = cpaCyInstanceGetInfo2(instance, &info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                return status;
            }
        }
        break;
#endif /* DO_CRYPTO */

#ifdef INCLUDE_COMPRESSION
        case COMPRESSION:
        {
            status = cpaDcInstanceGetInfo2(instance, &info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                return status;
            }
        }
        break;
#endif /*INCLUDE_COMPRESSION*/

        default:
        {
            PRINT_ERR("Unknown Instance type\n");
            return CPA_STATUS_FAIL;
        }
        break;
    } /* End Switch */

    /*loop of the instanceInfo coreAffinity bitmask to find the core affinity*/
    for (i = 0; i < CPA_MAX_CORES; i++)
    {
        if (CPA_BITMAP_BIT_TEST(info.coreAffinity, i))
        {
            *coreAffinity = i;
            return CPA_STATUS_SUCCESS;
        }
    }
    PRINT_ERR("Could not find core affinity\n");
    return CPA_STATUS_FAIL;
}

void freeInstanceMapping(void)
{
    if (NULL != cyInst_g)
    {
        qaeMemFree((void **)&cyInst_g);
    }
    if (NULL != symCyInst_g)
    {
        qaeMemFree((void **)&symCyInst_g);
    }
    if (NULL != asymCyInst_g)
    {
        qaeMemFree((void **)&asymCyInst_g);
    }
    if (NULL != dcInst_g)
    {
        qaeMemFree((void **)&dcInst_g);
    }
    if (NULL != cyInstMap_g)
    {
        qaeMemFree((void **)&cyInstMap_g);
    }
    if (NULL != symCyInstMap_g)
    {
        qaeMemFree((void **)&symCyInstMap_g);
    }
    if (NULL != asymCyInstMap_g)
    {
        qaeMemFree((void **)&asymCyInstMap_g);
    }
    if (NULL != dcInstMap_g)
    {
        qaeMemFree((void **)&dcInstMap_g);
    }
    numInst_g = 0;
}
EXPORT_SYMBOL(freeInstanceMapping);

CpaStatus getCryptoInstanceMapping(void)
{

    CpaStatus status = CPA_STATUS_FAIL;
#ifdef DO_CRYPTO /* Called from within this file */
    Cpa32U i = 0;
    Cpa32U coreAffinity = 0;
    CpaInstanceInfo2 info = {0};

    /*get the number of crypto instances*/
    status = cpaCyGetNumInstances(&numInst_g);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", status);
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
    if (numInst_g > 0)
    {
        /* use single instance for latency and COO */
        if (singleInstRequired_g)
        {
            numInst_g = 1;
        }
        /*allocate memory to store the instance handles*/
        cyInst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInst_g);
        if (cyInst_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instances\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }
        /*get the instances handles and place in allocated memory*/
        status = cpaCyGetInstances(numInst_g, cyInst_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyGetInstances failed with status: %d\n", status);
            freeInstanceMapping();
            return status;
        }
        /*allocate memory for the instance core mapping*/
        cyInstMap_g = qaeMemAlloc(sizeof(Cpa32U) * numInst_g);
        if (cyInstMap_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instance mapping\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < numInst_g; i++)
        {
            status = cpaCyInstanceGetInfo2(cyInst_g[i], &info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                freeInstanceMapping();
                return status;
            }
            if (CPA_STATUS_SUCCESS ==
                getCoreAffinity(cyInst_g[i], &coreAffinity, CRYPTO))
            {
                if ((packageIdCount_g < info.physInstId.packageId) &&
                    (info.operState == CPA_OPER_STATE_UP) &&
                    (CPA_FALSE == devicesCounted_g))
                {
                    packageIdCount_g = info.physInstId.packageId;
                }
                if (verboseOutput)
                {
                    PRINT("Inst %u, Affin: %u, Dev: %u, Accel %u, "
                          "EE %u, BDF %02X:%02X:%02X\n",
                          i,
                          coreAffinity,
                          info.physInstId.packageId,
                          info.physInstId.acceleratorId,
                          info.physInstId.executionEngineId,
                          (Cpa8U)((info.physInstId.busAddress) >> 8),
                          (Cpa8U)((info.physInstId.busAddress) & 0xFF) >> 3,
                          (Cpa8U)((info.physInstId.busAddress) & 7));
                }
                if (info.isPolled)
                    cyInstMap_g[i] = coreAffinity;
                else
                    cyInstMap_g[i] = coreAffinity + 1;
            }
            else
            {
                freeInstanceMapping();
                return CPA_STATUS_FAIL;
            }
        }
        devicesCounted_g = CPA_TRUE;
    }
    else
    {
        PRINT("There are no crypto instances\n");
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
#endif /* DO_CRYPTO*/
    return status;
}
EXPORT_SYMBOL(getCryptoInstanceMapping);

#if CY_API_VERSION_AT_LEAST(3, 0)
CpaStatus getSymInstanceMapping(Cpa16U *numSymInstances)
{

    CpaStatus status = CPA_STATUS_FAIL;
#ifdef DO_CRYPTO /* Called from within this file */
    Cpa32U i = 0;
    Cpa32U coreAffinity = 0;
    CpaInstanceInfo2 info = {0};

    /*get the number of Sym crypto instances*/
    status = cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_SYM, numSymInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaGetNumInstances failed with status: %d\n", status);
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
    if (*numSymInstances > 0)
    {
        /*allocate memory to store the instance handles*/
        /* use single instance for latency and COO */
        if (singleInstRequired_g)
        {
            *numSymInstances = 1;
        }
        symCyInst_g =
            qaeMemAlloc(sizeof(CpaInstanceHandle) * (*numSymInstances));
        if (symCyInst_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instances\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }
        /*get the instances handles and place in allocated memory*/
        status = cpaGetInstances(
            CPA_ACC_SVC_TYPE_CRYPTO_SYM, *numSymInstances, symCyInst_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaGetInstances failed with status: %d\n", status);
            freeInstanceMapping();
            return status;
        }
        /*allocate memory for the instance core mapping*/
        symCyInstMap_g = qaeMemAlloc(sizeof(Cpa32U) * (*numSymInstances));
        if (symCyInstMap_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instance mapping\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < *numSymInstances; i++)
        {
            status = cpaCyInstanceGetInfo2(symCyInst_g[i], &info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                freeInstanceMapping();
                return status;
            }
            if (CPA_STATUS_SUCCESS ==
                getCoreAffinity(symCyInst_g[i], &coreAffinity, CRYPTO))
            {
                if ((packageIdCount_g < info.physInstId.packageId) &&
                    (info.operState == CPA_OPER_STATE_UP) &&
                    (CPA_FALSE == devicesCounted_g))
                {
                    packageIdCount_g = info.physInstId.packageId;
                }
                if (verboseOutput)
                {
                    PRINT("Inst %u, Affin: %u, Dev: %u, Accel %u, "
                          "EE %u, BDF %02X:%02X:%02X\n",
                          i,
                          coreAffinity,
                          info.physInstId.packageId,
                          info.physInstId.acceleratorId,
                          info.physInstId.executionEngineId,
                          (Cpa8U)((info.physInstId.busAddress) >> 8),
                          (Cpa8U)((info.physInstId.busAddress) & 0xFF) >> 3,
                          (Cpa8U)((info.physInstId.busAddress) & 7));
                }
                if (info.isPolled)
                    symCyInstMap_g[i] = coreAffinity;
                else
                    symCyInstMap_g[i] = coreAffinity + 1;
            }
            else
            {
                freeInstanceMapping();
                return CPA_STATUS_FAIL;
            }
        }
        devicesCounted_g = CPA_TRUE;
    }
    else
    {
        PRINT("There are no Sym crypto instances\n");
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
#endif /* DO_CRYPTO*/
    return status;
}
EXPORT_SYMBOL(getSymInstanceMapping);

CpaStatus getAsymInstanceMapping(Cpa16U *numAsymInstances)
{

    CpaStatus status = CPA_STATUS_FAIL;
#ifdef DO_CRYPTO /* Called from within this file */
    Cpa32U i = 0;
    Cpa32U coreAffinity = 0;
    CpaInstanceInfo2 info = {0};

    /*get the number of Asym crypto instances*/
    status = cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_ASYM, numAsymInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaGetNumInstances failed with status: %d\n", status);
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
    if (*numAsymInstances > 0)
    {
        /*allocate memory to store the instance handles*/
        /* use single instance for latency and COO */
        if (singleInstRequired_g)
        {
            *numAsymInstances = 1;
        }
        asymCyInst_g =
            qaeMemAlloc(sizeof(CpaInstanceHandle) * (*numAsymInstances));
        if (asymCyInst_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instances\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }
        /*get the instances handles and place in allocated memory*/
        status = cpaGetInstances(
            CPA_ACC_SVC_TYPE_CRYPTO_ASYM, *numAsymInstances, asymCyInst_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaGetInstances failed with status: %d\n", status);
            freeInstanceMapping();
            return status;
        }
        /*allocate memory for the instance core mapping*/
        asymCyInstMap_g = qaeMemAlloc(sizeof(Cpa32U) * (*numAsymInstances));
        if (asymCyInstMap_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instance mapping\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < *numAsymInstances; i++)
        {
            status = cpaCyInstanceGetInfo2(asymCyInst_g[i], &info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                freeInstanceMapping();
                return status;
            }
            if (CPA_STATUS_SUCCESS ==
                getCoreAffinity(asymCyInst_g[i], &coreAffinity, CRYPTO))
            {
                if ((packageIdCount_g < info.physInstId.packageId) &&
                    (info.operState == CPA_OPER_STATE_UP) &&
                    (CPA_FALSE == devicesCounted_g))
                {
                    packageIdCount_g = info.physInstId.packageId;
                }
                if (verboseOutput)
                {
                    PRINT("Inst %u, Affin: %u, Dev: %u, Accel %u, "
                          "EE %u, BDF %02X:%02X:%02X\n",
                          i,
                          coreAffinity,
                          info.physInstId.packageId,
                          info.physInstId.acceleratorId,
                          info.physInstId.executionEngineId,
                          (Cpa8U)((info.physInstId.busAddress) >> 8),
                          (Cpa8U)((info.physInstId.busAddress) & 0xFF) >> 3,
                          (Cpa8U)((info.physInstId.busAddress) & 7));
                }
                if (info.isPolled)
                    asymCyInstMap_g[i] = coreAffinity;
                else
                    asymCyInstMap_g[i] = coreAffinity + 1;
            }
            else
            {
                freeInstanceMapping();
                return CPA_STATUS_FAIL;
            }
        }
        devicesCounted_g = CPA_TRUE;
    }
    else
    {
        PRINT("There are no Asym crypto instances\n");
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
#endif /* DO_CRYPTO*/
    return status;
}
EXPORT_SYMBOL(getAsymInstanceMapping);
#endif

#ifdef INCLUDE_COMPRESSION
/*get the instance to core affinity mapping of the compression instances and
 * populate the InstMap structure*/
CpaStatus getCompressionInstanceMapping(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U i = 0;
    Cpa32U coreAffinity = 0;
    CpaInstanceInfo2 info = {0};

    /*get the number of compression instances*/
    status = cpaDcGetNumInstances(&numInst_g);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaDcGetNumInstances failed with status: %d\n", status);
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
    if (numInst_g > 0)
    {
        /* use single instance for latency and COO */
        if (singleInstRequired_g)
        {
            numInst_g = 1;
        }
        /*allocate memory to store the instance handles*/
        dcInst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInst_g);
        if (dcInst_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instances\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }
        /*get the instances handles and place in allocated memory*/
        status = cpaDcGetInstances(numInst_g, dcInst_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcGetInstances failed with status: %d\n", status);
            freeInstanceMapping();
            return status;
        }
        /*allocate memory for the instance core mapping*/
        dcInstMap_g = qaeMemAlloc(sizeof(Cpa32U) * numInst_g);
        if (dcInstMap_g == NULL)
        {
            PRINT_ERR("Failed to allocate memory for instance mapping\n");
            freeInstanceMapping();
            return CPA_STATUS_FAIL;
        }

        for (i = 0; i < numInst_g; i++)
        {
            status = cpaDcInstanceGetInfo2(dcInst_g[i], &info);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("could not get instance info\n");
                freeInstanceMapping();
                return status;
            }
            if (CPA_STATUS_SUCCESS ==
                getCoreAffinity(dcInst_g[i], &coreAffinity, COMPRESSION))
            {
                if ((packageIdCount_g < info.physInstId.packageId) &&
                    (info.operState == CPA_OPER_STATE_UP) &&
                    CPA_FALSE == devicesCounted_g)
                {
                    packageIdCount_g = info.physInstId.packageId;
                }
                if (verboseOutput)
                {
                    PRINT("Inst %u, Affin: %u, Dev: %u, Accel %u, "
                          "EE %u, BDF %02X:%02X:%02X\n",
                          i,
                          coreAffinity,
                          info.physInstId.packageId,
                          info.physInstId.acceleratorId,
                          info.physInstId.executionEngineId,
                          (Cpa8U)((info.physInstId.busAddress) >> 8),
                          (Cpa8U)((info.physInstId.busAddress) & 0xFF) >> 3,
                          (Cpa8U)((info.physInstId.busAddress) & 7));
                }
                if (info.isPolled)
                    dcInstMap_g[i] = coreAffinity;
                else
                    dcInstMap_g[i] = coreAffinity + 1;
            }
            else
            {
                freeInstanceMapping();
                return CPA_STATUS_FAIL;
            }
        }
        devicesCounted_g = CPA_TRUE;
    }
    else
    {
        PRINT("There are no compression instances\n");
        freeInstanceMapping();
        return CPA_STATUS_FAIL;
    }
    return status;
}
EXPORT_SYMBOL(getCompressionInstanceMapping);
#endif

CpaStatus createStartandWaitForCompletionCrypto(Cpa32U instType)
{
    CpaStatus status = CPA_STATUS_FAIL;

#if CY_API_VERSION_AT_LEAST(3, 0)
    status = createStartandWaitForCompletion(instType);
#endif

#if !CY_API_VERSION_AT_LEAST(3, 0)
    status = createStartandWaitForCompletion(CRYPTO);
#endif

    return status;
}

/*this function can only be called after the last setup function has been
 * called, it creates the threads for the last setup function called, then
 * starts all threads and waits for all threads to complete. */
CpaStatus createStartandWaitForCompletion(Cpa32U instType)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U *instMap = NULL;
    Cpa16U numInst = 0;
#if CY_API_VERSION_AT_LEAST(3, 0)
    CpaBoolean isSymAsymConf = CPA_FALSE;
    CpaInstanceHandle *sym_asymInst = NULL;
    Cpa16U nSymInstances = 0;
    Cpa16U nAsymInstances = 0;

    if (instType != COMPRESSION)
    {
        cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_SYM, &nSymInstances);
        cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_ASYM, &nAsymInstances);

        if ((nSymInstances > 0) && (nAsymInstances > 0))
        {
            isSymAsymConf = CPA_TRUE;
        }
    }
#endif

    switch (instType)
    {
#ifdef DO_CRYPTO
#if CY_API_VERSION_AT_LEAST(3, 0)
        case SYM:
            if (CPA_STATUS_SUCCESS != getCryptoInstanceMapping())
            {
                PRINT_ERR("Could not get Crypto Instance mapping\n");
                return CPA_STATUS_FAIL;
            }

            instMap = cyInstMap_g;
            numInst = numInst_g;

            if (isSymAsymConf == CPA_TRUE)
            {
                if (CPA_STATUS_SUCCESS != getSymInstanceMapping(&nSymInstances))
                {
                    PRINT_ERR("Could not get Crypto Instance mapping\n");
                    return CPA_STATUS_FAIL;
                }

                numInst = nSymInstances;
                instMap = symCyInstMap_g;
                sym_asymInst = symCyInst_g;
            }
            break;

        case ASYM:
            if (CPA_STATUS_SUCCESS != getCryptoInstanceMapping())
            {
                PRINT_ERR("Could not get Crypto Instance mapping\n");
                return CPA_STATUS_FAIL;
            }

            instMap = cyInstMap_g;
            numInst = numInst_g;

            if (isSymAsymConf == CPA_TRUE)
            {
                if (CPA_STATUS_SUCCESS !=
                    getAsymInstanceMapping(&nSymInstances))
                {
                    PRINT_ERR("Could not get Crypto Instance mapping\n");
                    return CPA_STATUS_FAIL;
                }

                numInst = nAsymInstances;
                instMap = asymCyInstMap_g;
                sym_asymInst = asymCyInst_g;
            }
            break;
#endif
        case CRYPTO:
        {
            if (CPA_STATUS_SUCCESS != getCryptoInstanceMapping())
            {
                PRINT_ERR("Could not get Crypto Instance mapping\n");
                return CPA_STATUS_FAIL;
            }
            instMap = cyInstMap_g;
            numInst = numInst_g;
        }
        break;
#endif /* DO_CRYPTO */

#ifdef INCLUDE_COMPRESSION
        case COMPRESSION:
        {
            if (CPA_STATUS_SUCCESS != getCompressionInstanceMapping())
            {
                PRINT_ERR("Could not get Compression Instance mapping\n");
                return CPA_STATUS_FAIL;
            }
            instMap = dcInstMap_g;
            numInst = numInst_g;
        }
        break;
#endif
        default:
        {
            PRINT_ERR("Invalid instance type\n");
            return CPA_STATUS_FAIL;
        }
        break;
    } /* End Switch */

#if CY_API_VERSION_AT_LEAST(3, 0)
    if ((isSymAsymConf == CPA_TRUE) && (instType == SYM || instType == ASYM))
    {
        isChangingThreadQaInstanceRequired_g = CPA_TRUE;
    }
#endif
    status = createPerfomanceThreads(numInst,
                                     instMap,
                                     USE_ALL_QA_LOGICAL_INSTANCES,
                                     DEFAULT_LOGICAL_INST_INSTANCE_OFFSET);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not create threads, status: %d\n", status);
        return status;
    }
#if CY_API_VERSION_AT_LEAST(3, 0)
    if ((isSymAsymConf == CPA_TRUE) && (instType == SYM || instType == ASYM))
    {

        qatModifyCyThreadLogicalQaInstance(
            0, cyInst_g, sym_asymInst, numInst_g);
        isChangingThreadQaInstanceRequired_g = CPA_FALSE;
    }
#endif
    status = startThreads();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not start threads, status: %d\n", status);
        return status;
    }
    /*wait for threads_g to finished and print out stats*/
    status = waitForThreadCompletion();
    freeInstanceMapping();
    return status;
}

int latency_debug = 0; /* set to 1 for debug PRINT() */
EXPORT_SYMBOL(latency_debug);
int latency_enable = 0; /* set to 1 for enable latency testing */
EXPORT_SYMBOL(latency_enable);
