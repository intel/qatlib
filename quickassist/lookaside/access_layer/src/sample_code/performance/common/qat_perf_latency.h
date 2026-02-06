/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef QAT_PERF_LATENCY_H_
#define QAT_PERF_LATENCY_H_

#include "cpa_sample_code_framework.h"
#include "cpa_cy_sym.h"

extern int latency_single_buffer_mode;

void setLatencyDebug(int value);
CpaStatus setLatencySingleBufferMode(int value);
CpaStatus enableLatencyMeasurements(int value);
CpaCySymCipherDirection getLatencyCipherDirection(void);
void setLatencyCipherDirection(CpaCySymCipherDirection direction);
int isLatencyEnabled(void);

CpaStatus qatFreeLatency(perf_data_t *performanceStats);
CpaStatus qatInitLatency(perf_data_t *performanceStats,
                         Cpa32U numberOfLists,
                         Cpa32U numberOfLoops);

CpaStatus qatStartLatencyMeasurement(perf_data_t *performanceStats,
                                     Cpa32U submissions);

CpaStatus qatSummariseLatencyMeasurements(perf_data_t *performanceStats);
CpaStatus qatLatencyPollForResponses(perf_data_t *performanceStats,
                                     Cpa32U submissions,
                                     CpaInstanceHandle instanceHandle,
                                     CpaBoolean instanceIsCrypto,
                                     CpaBoolean instanceIsDP);

#endif
