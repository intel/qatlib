/***************************************************************************
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
