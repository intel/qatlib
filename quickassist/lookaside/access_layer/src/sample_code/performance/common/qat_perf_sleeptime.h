/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
 * Reused function from old busy loop code it will calculate the % margin
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
