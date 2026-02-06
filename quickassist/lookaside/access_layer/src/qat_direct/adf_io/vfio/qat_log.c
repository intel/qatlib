/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/
#include <stdarg.h>
#include <stdio.h>
#include "qat_log.h"

#ifdef ICP_DEBUG
int debug_level = LOG_LEVEL_DEBUG;
#else
int debug_level = LOG_LEVEL_ERROR;
#endif

static int pr_err(const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static int pr_info(const char *fmt, va_list args)
{
    int ret;

    if (debug_level < LOG_LEVEL_INFO)
        return 1;

    ret = vprintf(fmt, args);

    return ret;
}

static int pr_dbg(const char *fmt, va_list args)
{
    int ret;

    if (debug_level < LOG_LEVEL_DEBUG)
        return 1;

    ret = vprintf(fmt, args);

    return ret;
}

int qat_log(int log_level, const char *fmt, ...)
{
    va_list args;
    int ret = 1;

    va_start(args, fmt);
    switch (log_level)
    {
        case LOG_LEVEL_ERROR:
            ret = pr_err(fmt, args);
            break;
        case LOG_LEVEL_INFO:
            ret = pr_info(fmt, args);
            break;
        case LOG_LEVEL_DEBUG:
            ret = pr_dbg(fmt, args);
            break;
    }
    va_end(args);
    return ret;
}
