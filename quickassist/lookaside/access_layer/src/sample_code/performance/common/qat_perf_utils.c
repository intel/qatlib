/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#include "qat_perf_utils.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_dc_utils.h"
#include "qat_perf_latency.h"

void qatPerfInitStats(perf_data_t *performanceStats,
                      Cpa32U numLists,
                      Cpa32U numLoops,
                      Cpa32U pollingInterval)
{
    /* Resetting only specific perf stats to 0, as some of the element in the
     * structure should not be reset
     * e.g. bytesConsumedPerLoop from compression when testing decompression*/
    performanceStats->submissions = 0;
    performanceStats->responses = 0;
    performanceStats->retries = 0;
    performanceStats->pollRetries = 0;
    performanceStats->nextPoll = pollingInterval;
    performanceStats->sleepTime = 0;
    performanceStats->compRate = 0;
    performanceStats->currentThroughput = 0;
    performanceStats->pollCount = 0;
    performanceStats->overflow = 0;
    performanceStats->busyLoopCount = 0;
    if (!iaCycleCount_g)
    {
        performanceStats->busyLoopValue = 0;
    }
    else
    {
        performanceStats->bytesConsumedPerLoop = 0;
        performanceStats->bytesProducedPerLoop = 0;
    }
    performanceStats->cyclesPerBusyLoop = 0;
    performanceStats->offloadCycles = 0;
    performanceStats->totalBusyLoopCycles = 0;
    performanceStats->busyLoopResponses = 0;
    performanceStats->isIACycleCountProfiled = 0;
    performanceStats->response_process_time = 0;
    qatFreeLatency(performanceStats);

    performanceStats->numLoops = numLoops;
    performanceStats->numOperations = (Cpa64U)numLists * (Cpa64U)numLoops;
    return;
}

char *cpaStatusToString(CpaStatus status)
{
    char *retString = NULL;

    switch (status)
    {
        case CPA_STATUS_RETRY:
            retString = "CPA_STATUS_RETRY";
            break;

        case CPA_STATUS_RESTARTING:
            retString = "CPA_STATUS_RESTARTING";
            break;

        case CPA_STATUS_UNSUPPORTED:
            retString = "CPA_STATUS_UNSUPPORTED";
            break;

        case CPA_STATUS_FATAL:
            retString = "CPA_STATUS_FATAL";
            break;

        case CPA_STATUS_INVALID_PARAM:
            retString = "CPA_STATUS_INVALID_PARAM";
            break;

        case CPA_STATUS_RESOURCE:
            retString = "CPA_STATUS_RESOURCE";
            break;

        case CPA_STATUS_FAIL:
            retString = "CPA_STATUS_FAIL";
            break;

        case CPA_STATUS_SUCCESS:
            retString = "CPA_STATUS_SUCCESS";
            break;

        default:
            retString = "CPA_STATUS_UNKNOWN";
    }
    return (retString);
}
EXPORT_SYMBOL(cpaStatusToString);

CpaStatus printDriverVersion(Cpa32U deviceNum)
{
    icp_sal_dev_version_info_t qaVersionInfo = {.devId = 0,
                                                .softwareVersion = {0}};
    if (CPA_STATUS_SUCCESS !=
        icp_sal_getDevVersionInfo(deviceNum, &qaVersionInfo))
    {
        PRINT_ERR("Could not get QA version information\n");
    }
    else
    {
        PRINT("*** QA version information ***\n");
        PRINT("device ID\t\t= %d\n", qaVersionInfo.devId);
        PRINT("software \t\t= %s\n", qaVersionInfo.softwareVersion);
        PRINT("*** END QA version information ***\n");
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(printDriverVersion);
