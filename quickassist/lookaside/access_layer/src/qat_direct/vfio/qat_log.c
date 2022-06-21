/*****************************************************************************
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
