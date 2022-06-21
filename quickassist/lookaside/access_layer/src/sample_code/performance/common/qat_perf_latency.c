/****************************************************************************
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
#include "cpa_dc.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "qat_compression_main.h"
#include "icp_sal_poll.h"
#include "qat_perf_latency.h"
#include "qat_perf_utils.h"

#define MAX_LATENCY_COUNT (100)
#define READ_ALL_RESPONSES (0)

int latency_single_buffer_mode = 1; /* set to 1 for single buffer processing */

CpaCySymCipherDirection latencyCipherDirection =
    CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

#ifdef DO_CRYPTO
extern CpaCySymCipherDirection cipherDirection_g;
#endif

/* This function is used for enabling debug when latency_g is set to true
 * for the build. Where a non-zero argument enables debug and a 0 disables it.
 */
void setLatencyDebug(int value)
{
    latency_debug = value;
    PRINT("%s: latency_debug now %d\n", __FUNCTION__, latency_debug);
}
EXPORT_SYMBOL(setLatencyDebug);

/* This function is used for ensuring only a single buffer at a time
 * is processed when latency_g is set to true for the build.
 * Where a non-zero argument enables this mode and a 0 disables it.
 */
CpaStatus setLatencySingleBufferMode(int value)
{
    latency_single_buffer_mode = value;
    PRINT("%s: latency_single_buffer_mode now %d\n",
          __FUNCTION__,
          latency_single_buffer_mode);
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setLatencySingleBufferMode);

/* This function is used for enable gathering of latency timings.
 * Where a non-zero argument enables this mode and a 0 disables it.
 */
CpaStatus enableLatencyMeasurements(int value)
{
    latency_enable = value;
    PRINT("Latency computation %s\n",
          latency_enable != 0 ? "Enabled" : "Disabled");
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(enableLatencyMeasurements);

/* This function is used for allow other files to check if
 * latency testing is enabled. Return of a non-zero value
 * signifies that it is.
 */
int isLatencyEnabled(void)
{
    return latency_enable;
}
EXPORT_SYMBOL(isLatencyEnabled);

/*
 * The setupSymmetricDpTest() function has the encrypt / decrypt
 * direction hard coded to CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT.
 * This function overrides this for the builds in which latency_g
 * is set to true.
 * Use setLatencyCipherDirection() before calling setupCipherDpTest().
 */
CpaCySymCipherDirection getLatencyCipherDirection(void)
{
    return latencyCipherDirection;
}
EXPORT_SYMBOL(getLatencyCipherDirection);

#ifdef DO_CRYPTO
/*
 * The setupSymmetricDpTest() function has the encrypt / decrypt
 * direction hard coded to CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT.
 * This function overrides this for builds in which latency_g
 * is set to true.
 * Use setLatencyCipherDirection() before calling setupCipherDpTest().
 */
void setLatencyCipherDirection(CpaCySymCipherDirection direction)
{
    latencyCipherDirection = direction;
    cipherDirection_g = latencyCipherDirection;
}
EXPORT_SYMBOL(setLatencyCipherDirection);
#endif

CpaStatus qatFreeLatency(perf_data_t *performanceStats)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    QAT_PERF_FREE_MEM_AND_UPDATE_STATUS(performanceStats->response_times,
                                        status);
    QAT_PERF_FREE_MEM_AND_UPDATE_STATUS(performanceStats->start_times, status);
    return status;
}

CpaStatus qatInitLatency(perf_data_t *performanceStats,
                         Cpa32U numberOfLists,
                         Cpa32U numberOfLoops)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    if (latency_enable)
    {
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(performanceStats, status);
        if (CPA_STATUS_SUCCESS == status)
        {
            if (performanceStats->numOperations > LATENCY_SUBMISSION_LIMIT)
            {
                PRINT_ERR("Error max submissions for latency  must be <= %d\n",
                          LATENCY_SUBMISSION_LIMIT);
                status = CPA_STATUS_FAIL;
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                /*countIncrement is how many submission are made between
                 * each latency measurement. It is the total submission divided
                 * by MAX_LATENCY_COUNT
                 *
                 * nextCount is used to keep track of when the next latency
                 * measurement needs to be taken in relation to the total
                 * submissions made
                 *
                 * latencyCount records the number of latency measurements taken
                 *
                 * start_time is an array to record time-stamp just before a
                 * submission is made
                 *
                 * response_time array is a location to record time-stamp when a
                 * response is received. The corresponding submit time is stored
                 *  in start_time at the same index into the array.
                 *  The difference reflects the latency time of that request
                 * */
                performanceStats->countIncrement =
                    (numberOfLists * numberOfLoops) / MAX_LATENCY_COUNT;
                performanceStats->nextCount = performanceStats->countIncrement;
                performanceStats->latencyCount = 0;
                performanceStats->response_times =
                    qaeMemAlloc(sizeof(perf_cycles_t) * MAX_LATENCY_COUNT + 1);
                QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(
                    performanceStats->response_times, status);
                if (CPA_STATUS_SUCCESS == status)
                {
                    performanceStats->start_times = qaeMemAlloc(
                        sizeof(perf_cycles_t) * MAX_LATENCY_COUNT + 1);
                    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(
                        performanceStats->start_times, status);
                }
            }
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            qatFreeLatency(performanceStats);
        }
    }
    return status;
}

CpaStatus qatStartLatencyMeasurement(perf_data_t *performanceStats,
                                     Cpa32U submissions)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;

    if (latency_enable)
    {
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(performanceStats, status);
        if (CPA_STATUS_SUCCESS == status)
        {
            i = performanceStats->latencyCount;
            if ((submissions + 1 == performanceStats->nextCount) &&
                (i < MAX_LATENCY_COUNT))
            {
                performanceStats->start_times[i] = sampleCodeTimestamp();
            }
        }
    }
    return status;
}

CpaStatus qatLatencyPollForResponses(perf_data_t *performanceStats,
                                     Cpa32U submissions,
                                     CpaInstanceHandle instanceHandle,
                                     CpaBoolean instanceIsCrypto,
                                     CpaBoolean instanceIsDP)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (latency_enable)
    {
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(performanceStats, status);
        if (CPA_STATUS_SUCCESS == status)
        {
            /* Have we been requested to process one buffer at a time. This
             * will result in no retries and so the best latency times.
             */
            if (0 != latency_single_buffer_mode)
            {
                /* Must now wait until this buffer is processed by the CPM */
                while (performanceStats->responses != submissions)
                {
                    /* Keep polling until compression of the buffer completes
                     * and dcPerformCallback() increments perfData->responses */
                    if (instanceIsCrypto)
                    {
#ifdef DO_CRYPTO
                        if (instanceIsDP)
                        {
                            icp_sal_CyPollDpInstance(instanceHandle,
                                                     READ_ALL_RESPONSES);
                        }
                        else
                        {
                            icp_sal_CyPollInstance(instanceHandle,
                                                   READ_ALL_RESPONSES);
                        }
#else
                        PRINT_ERR(
                            "Crypto is not enabled. Polling is impossible.\n");
                        status = CPA_STATUS_FAIL;
#endif
                    }
                    else
                    {
                        if (instanceIsDP)
                        {
                            icp_sal_DcPollDpInstance(instanceHandle,
                                                     READ_ALL_RESPONSES);
                        }
                        else
                        {
                            icp_sal_DcPollInstance(instanceHandle,
                                                   READ_ALL_RESPONSES);
                        }
                    }
                }
            }
        }
    }
    return status;
}

CpaStatus qatSummariseLatencyMeasurements(perf_data_t *performanceStats)
{
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (latency_enable)
    {
        QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(performanceStats, status);
        if (CPA_STATUS_SUCCESS == status)
        {
            performanceStats->minLatency =
                MAX_LATENCY_LIMIT;            /* Will be less than this */
            performanceStats->maxLatency = 0; /* Will be more than this */

            /* Let's accumulate in 'aveLatency' all the individual 'latency'
             * times. Typically, there should be MAX_LATENCY_COUNT of these.
             * We also calculate min/max so we can get a sense of the variance.
             */

            for (i = 0; i < performanceStats->latencyCount; i++)
            {
                perf_cycles_t latency = performanceStats->response_times[i] -
                                        performanceStats->start_times[i];
                performanceStats->aveLatency += latency;

                if (latency < performanceStats->minLatency)
                    performanceStats->minLatency = latency;
                if (latency > performanceStats->maxLatency)
                    performanceStats->maxLatency = latency;
            }

            if (performanceStats->latencyCount > 0)
            {
                /* Then scale down this accumulated value to get the average.
                 * This will be reported by dcPrintStats() at the end of the
                 * test */
                do_div(performanceStats->aveLatency,
                       performanceStats->latencyCount);
            }
            status = qatFreeLatency(performanceStats);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("error in freeing latency stats memory\n");
            }
        }
    }
    return status;
}
