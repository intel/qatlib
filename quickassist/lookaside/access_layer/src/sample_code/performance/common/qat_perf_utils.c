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

#include "qat_perf_utils.h"
#include "cpa_sample_code_dc_perf.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_dc_utils.h"

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
    performanceStats->start_times = 0;
    performanceStats->response_times = 0;

    performanceStats->numLoops = numLoops;
    performanceStats->numOperations = (Cpa64U)numLists * (Cpa64U)numLoops;
    return;
}

char *cpaStatusToString(CpaStatus status)
{
    char *retString = "NOT_SET";

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
