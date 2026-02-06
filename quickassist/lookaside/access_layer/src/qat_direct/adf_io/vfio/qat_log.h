/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef QAT_LOG_H
#define QAT_LOG_H

extern int debug_level;

#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_DEBUG 2

int qat_log(int log_level, const char *fmt, ...);

#ifdef ADF_ERROR
#undef ADF_ERROR
#endif
#define ADF_ERROR(format, args...)                                             \
    qat_log(LOG_LEVEL_ERROR, "err: %s: " format, (__func__), ##args)

#ifdef ADF_DEBUG
#undef ADF_DEBUG
#endif
#define ADF_DEBUG(format, args...)                                             \
    qat_log(LOG_LEVEL_DEBUG, "debug: %s: " format, (__func__), ##args)

#define ADF_INFO(format, args...)                                              \
    qat_log(LOG_LEVEL_INFO, "info: %s: " format, (__func__), ##args)

#endif /* QAT_LOG_H */
