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
#ifndef QAT_PERF_SLEEPTIME_H_
#define QAT_PERF_SLEEPTIME_H_
typedef struct sleeptime_data_s
{
    Cpa32S baseThroughput, currentThroughput, desiredThroughput;
    Cpa32S packetSize;
    Cpa32U percentRate, previousNoOfResponses, previousNoOfRetries, loopRetries;
    Cpa32U firstRunFlag, upperBound, lowerBound, limitFoundFlag;
    perf_cycles_t numOfCycles;
    Cpa64U loopResponses;
    perf_cycles_t endLoopTimestamp;   /* end TS for x no of loops */
    perf_cycles_t startLoopTimestamp; /* start TS for x no of loops */
} sleeptime_data_t;

/*****************************************************************************
 * @file qat_perf_sleeptime.h
 *
 * @ingroup sample_code
 *
 * @description
 * Function used by rate limiting feature to adjust sleeptime based on current
 * throughout measured. This function is called every n amount of loops, it will
 * start by increasing the sleeptime and once it will exceed the threshold
 * of the throughput it will decrease and self adjust in other words "fine tune"
 *
 * @param[in]   pPerfData               pointer to the performance stats
 *structure
 * @param[in]   data                    pointer to the sleeptime_data_t
 *structure
 * @param[in]   compRate                pointer to compRate stored in setup
 *structure
 * @param[in]   sleepTime               pointer to sleepTime stored in setup
 *structure
 * @param[in]   bufferSize              bufferSize stored in setup structure
 *
 *****************************************************************************/
void adjustSleeptime(perf_data_t *pPerfData,
                     sleeptime_data_t *data,
                     Cpa32U *compRate,
                     Cpa32U *sleepTime,
                     Cpa32U bufferSize);

/*****************************************************************************
 * @file qat_perf_sleeptime.h
 *
 * @ingroup sample_code
 *
 * @description
 * This function will divide global sleeptime value into 100k parts,
 * as it was discovered that there is a higher margin of error
 * with high sleeptime numbers
 *
 * @param[in]   sleepTime               bufferSize stored in setup structure
 *
 *****************************************************************************/
void sleep_parsing(Cpa32U sleepTime);

/*****************************************************************************
 * @file qat_perf_sleeptime.h
 *
 * @ingroup sample_code
 *
 * @description
 * Re-used function from old busy loop code it will calculate the % margin
 * between two passed parameters using integer math
 *
 * @param[in]   baseVal                 baseValue to calculate margin
 * @param[in]   currentVal              value which will be calculate percentage
 *                                      difference from base
 * @param[in]   margin                  value of percentage margin in tens
 *                                      e.g. 0.5% margin is 5
 *                                           5% is 50
 *****************************************************************************/
uint8_t findSleeptimeMargin(uint32_t baseVal,
                            uint32_t currentVal,
                            uint32_t margin);

#endif
