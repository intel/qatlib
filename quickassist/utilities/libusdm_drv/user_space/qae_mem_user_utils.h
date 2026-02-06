/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
/**
 ****************************************************************************
 * @file qae_mem_user_utils.h
 *
 * This file provides for API of Linux user space memory allocation
 *
 ***************************************************************************/

#ifndef QAE_MEM_USER_UTILS_H
#define QAE_MEM_USER_UTILS_H

#include <stdarg.h>
#include <stdio.h>

#ifndef SKIP_BUILTIN_FUNC
#define unlikely(x) __builtin_expect((x), 0)
#else
#define unlikely(x) (0 == (x))
#endif

#if __GNUC__ >= 4
#define API_PUBLIC __attribute__((visibility("default")))
#define API_LOCAL __attribute__((visibility("hidden")))
#else
#define API_PUBLIC
#define API_LOCAL
#endif

#ifdef ICP_DEBUG
static inline void CMD_DEBUG(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#else
#define CMD_DEBUG(...)
#endif

static inline void CMD_ERROR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

#endif
