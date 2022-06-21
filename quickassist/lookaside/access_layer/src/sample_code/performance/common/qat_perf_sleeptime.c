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
#include "cpa_sample_code_dc_utils.h"
#include "cpa_dc.h"
#include "qat_compression_main.h"
#include "qat_perf_sleeptime.h"
#include "qat_sym_utils.h"

void adjustSleeptime(perf_data_t *pPerfData,
                     sleeptime_data_t *data,
                     Cpa32U *compRate,
                     Cpa32U *sleepTime,
                     Cpa32U bufferSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(pPerfData, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(data, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(compRate, status);
    QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(sleepTime, status);
    if (CPA_STATUS_SUCCESS == status)
    {
        data->loopResponses =
            pPerfData->responses - data->previousNoOfResponses;
        data->previousNoOfResponses = pPerfData->responses;
        data->endLoopTimestamp = sampleCodeTimestamp();
        data->numOfCycles = data->endLoopTimestamp - data->startLoopTimestamp;
        data->loopRetries = pPerfData->retries - data->previousNoOfRetries;
        data->previousNoOfRetries = pPerfData->retries;

        /* take no. of responses for x no. of loops */
        data->currentThroughput =
            getThroughput(data->loopResponses, bufferSize, data->numOfCycles);
        pPerfData->currentThroughput = data->currentThroughput;
        if (*sleepTime == 0 && data->firstRunFlag)
        {
            pPerfData->retries =
                0; // clear tries as its adding unnecessary overhead
            data->firstRunFlag = 0;
            data->baseThroughput = data->currentThroughput;
            /* set different sleep time depending on packet size to safe some
             * number of loops packet size below MIN_PACKET_SIZE will get no
             * benefit from nanosleep function */
            if (bufferSize >= QAT_COMP_MIN_PACKET_SIZE)
            {
                if (bufferSize <= QAT_COMP_LOW_SLEEPTIME_STATING_VALUE)
                {
                    *sleepTime = QAT_COMP_LOW_SLEEPTIME_STATING_VALUE;
                }
                else
                {
                    *sleepTime = QAT_COMP_HIGH_SLEEPTIME_STATING_VALUE;
                }
            }
            else
            {
                *sleepTime = QAT_COMP_DEFAULT_SLEEPTIME_STARTING_VALUE;
            }
            if (*compRate > 0)
            {
                /* check if passed throughput is not grater then base throughput
                 * as it would be impossible to limit current throughput to
                 * base. */
                if (*compRate < (Cpa32U)data->baseThroughput)
                {
                    data->desiredThroughput = *compRate;
                    data->percentRate =
                        QAT_COMP_SCALING_FACTOR -
                        (data->desiredThroughput * QAT_COMP_SCALING_FACTOR /
                         data->baseThroughput);
                }
                else
                {
                    PRINT("Too large throughput passed , capped to: %d\n",
                          data->baseThroughput);
                    data->desiredThroughput = data->baseThroughput;
                    *compRate = data->baseThroughput;
                    data->percentRate = QAT_COMP_FIVE_PERCENT;
                }
            }
            else
            {
                data->desiredThroughput = data->baseThroughput;
                /*TO DO decide if  different packet size need different % margin
                 * e.g packetSize<= 8192 ? 50 : 35; */
                data->percentRate = QAT_COMP_FIVE_PERCENT;
            }
        }
        /* check if currentThroughput is with n % of base when true increase
         * sleeptime, when false set limitFlagFound */
        if (findSleeptimeMargin(data->baseThroughput,
                                data->currentThroughput,
                                data->percentRate) &&
            data->limitFoundFlag == 0)
        {
            data->lowerBound = *sleepTime;
            *sleepTime = *sleepTime << 1;
        }
        else if (data->upperBound == 0)
        {
            data->limitFoundFlag = 1;
            data->upperBound = *sleepTime;
        }
        /*TO DO decide if need to check margin at this point as well
         * withinMargin(desiredThroughput,currentThroughput, packetSize <= 8192
         * ? 30 : 6) != 1
         */
        if (data->upperBound != 0)
        {
            /* check for ERROR_MARGIN of throughput and adjust sleep time
             * accordingly increase if current throughput is higher then desired
             * decrease when margin is higher the x amount
             * Then take a average of both*/
            if (data->currentThroughput >= data->desiredThroughput)
            {
                data->lowerBound = *sleepTime + 1;
            }
            else
            {
                if (findSleeptimeMargin(
                        data->desiredThroughput,
                        data->currentThroughput,
                        (data->packetSize <= QAT_COMP_PACKET_SIZE_8K
                             ? QAT_COMP_THREE_PERCENT
                             : QAT_COMP_POINT_SIX_PERCENT)) == 1)
                {
                    data->lowerBound = *sleepTime + 1;
                }
                else
                {
                    data->upperBound = *sleepTime - 1;
                }
            }
            *sleepTime = (data->upperBound + data->lowerBound) / 2;
        }
        data->startLoopTimestamp = sampleCodeTimestamp();
    }
}

void sleep_parsing(Cpa32U sleepTime)
{
    Cpa32U sleepInterval, k = 0;
    sleepInterval = sleepTime;
    if (sleepTime < QAT_COMP_SLEEP_INTERVAL)
    {
        sleepNano(sleepTime);
    }
    else
    {
        /* divide sleeptime into 100k blocks for more accurate sleeptime */
        for (k = 0; k < (sleepTime / QAT_COMP_SLEEP_INTERVAL); k++)
        {
            sleepNano(QAT_COMP_SLEEP_INTERVAL);
            sleepInterval -= QAT_COMP_SLEEP_INTERVAL;
        }
        if (sleepInterval != 0)
        {
            sleepNano(sleepInterval);
        }
    }
}

uint8_t findSleeptimeMargin(uint32_t baseVal,
                            uint32_t currentVal,
                            uint32_t margin)
{
    uint32_t difference = 0;

    if (currentVal >= baseVal)
    {
        return 1;
    }

    difference = baseVal - currentVal;
    difference *= QAT_COMP_SCALING_FACTOR;
    do_div(difference, baseVal);
    if (difference <= margin)
    {
        return 1;
    }
    return 0;
}
