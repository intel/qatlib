/***************************************************************************
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

/**
 ***************************************************************************
 * @file lac_log.h
 *
 * @defgroup LacLog     Log
 *
 * @ingroup LacCommon
 *
 * Logging Macros. These macros also log the function name they are called in.
 *
 ***************************************************************************/

/***************************************************************************/

#ifndef LAC_LOG_H
#define LAC_LOG_H

/***************************************************************************
 * Include public/global header files
 ***************************************************************************/
#include "cpa.h"
#include "Osal.h"
#include "lac_common.h"
#include "icp_accel_devices.h"

#define LAC_OSAL_LOG osalLog

#define LAC_OSAL_LOG_STRING osalLog

#define LAC_OSAL_LOG_PARAMS osalStdLog

#define _LAC_LOG_PARAM0_(level, log)                                           \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts no parameters in the string to be logged */

#define _LAC_LOG_PARAM1_(level, log, param1)                                   \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts 1 parameter in the string to be logged */

#define _LAC_LOG_PARAM2_(level, log, param1, param2)                           \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       (int)param2,                                            \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts 2 parameters in the string to be logged */

#define _LAC_LOG_PARAM3_(level, log, param1, param2, param3)                   \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       (int)param2,                                            \
                       (int)param3,                                            \
                       0,                                                      \
                       0,                                                      \
                       0,                                                      \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts 3 parameters in the string to be logged */

#define _LAC_LOG_PARAM4_(level, log, param1, param2, param3, param4)           \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       (int)param2,                                            \
                       (int)param3,                                            \
                       (int)param4,                                            \
                       0,                                                      \
                       0,                                                      \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts 4 parameters in the string to be logged */

#define _LAC_LOG_PARAM5_(level, log, param1, param2, param3, param4, param5)   \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       (int)param2,                                            \
                       (int)param3,                                            \
                       (int)param4,                                            \
                       (int)param5,                                            \
                       0,                                                      \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts 5 parameters in the string to be logged */

#define _LAC_LOG_PARAM6_(                                                      \
    level, log, param1, param2, param3, param4, param5, param6)                \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       (int)param2,                                            \
                       (int)param3,                                            \
                       (int)param4,                                            \
                       (int)param5,                                            \
                       (int)param6,                                            \
                       0)
/**< @ingroup LacLog
 * Internal macro that accepts 6 parameters in the string to be logged */

#define _LAC_LOG_PARAM7_(                                                      \
    level, log, param1, param2, param3, param4, param5, param6, param7)        \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       (LAC_ARCH_UINT) __func__,                               \
                       (int)param1,                                            \
                       (int)param2,                                            \
                       (int)param3,                                            \
                       (int)param4,                                            \
                       (int)param5,                                            \
                       (int)param6,                                            \
                       (int)param7)
/**< @ingroup LacLog
 * Internal macro that accepts 7 parameters in the string to be logged */

#define _LAC_LOG_STRING_PARAM1_(level, log, param1)                            \
    (void)LAC_OSAL_LOG_STRING(level,                                           \
                              OSAL_LOG_DEV_STDERR,                             \
                              "%s() - : " log "\n",                            \
                              (char *)__func__,                                \
                              (char *)param1,                                  \
                              0,                                               \
                              0,                                               \
                              0,                                               \
                              0)

/**< @ingroup LacLog
 * Internal macro that accepts 1 parameter in the string to be logged */
#define _LAC_LOG_PARAMS_(log, ...)                                             \
    (void)LAC_OSAL_LOG_PARAMS(                                                 \
        "[error] %s() - : " log "\n", __func__, __VA_ARGS__)
/**< @ingroup LacLog
 * Internal macro that accepts 1 parameter in the string to be logged */

/************************** Lac Invalid Param Macros **************************/

#define LAC_INVALID_PARAM_LOG(log)                                             \
    _LAC_LOG_PARAM0_(OSAL_LOG_LVL_ERROR, "Invalid API Param - " log)
/**< @ingroup LacLog
 * Invalid parameter log macro. Has the prefix "[error]" */

#define LAC_INVALID_PARAM_LOG1(log, param1)                                    \
    _LAC_LOG_PARAM1_(OSAL_LOG_LVL_ERROR, "Invalid API Param - " log, param1)
/**< @ingroup LacLog
 * Invalid parameter log macro. Has the prefix "[error]" and also
 * (1 parameter in the string to be logged). */

#define LAC_INVALID_PARAM_LOG2(log, param1, param2)                            \
    _LAC_LOG_PARAM2_(                                                          \
        OSAL_LOG_LVL_ERROR, "Invalid API Param - " log, param1, param2)
/**< @ingroup LacLog
 * Invalid parameter log macro. Has the prefix "[error]" and also accepts
 * 2 parameters in the string to be logged. */

/************************** Lac UnSupported Param Macros ****************/

#define LAC_UNSUPPORTED_PARAM_LOG(log)                                         \
    _LAC_LOG_PARAM0_(OSAL_LOG_LVL_ERROR, "UnSupported API Param - " log)
/**< @ingroup LacLog
 *  * UnSupported parameter log macro. Has the prefix "[error]" */

/************************** Lac Logging Macros **************************/

#define LAC_LOG(log) _LAC_LOG_PARAM0_(OSAL_LOG_LVL_USER, log)
/**< @ingroup LacLog
 * Log a string with no prefix */

#define LAC_LOG1(log, param1) _LAC_LOG_PARAM1_(OSAL_LOG_LVL_USER, log, param1)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (1 parameter in the string to be logged). */

#define LAC_LOG2(log, param1, param2)                                          \
    _LAC_LOG_PARAM2_(OSAL_LOG_LVL_USER, log, param1, param2)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (2 parameter in the string to be logged). */

#define LAC_LOG3(log, param1, param2, param3)                                  \
    _LAC_LOG_PARAM3_(OSAL_LOG_LVL_USER, log, param1, param2, param3)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (3 parameters in the string to be logged). */

#define LAC_LOG4(log, param1, param2, param3, param4)                          \
    _LAC_LOG_PARAM4_(OSAL_LOG_LVL_USER, log, param1, param2, param3, param4)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (4 parameters in the string to be logged). */

#define LAC_LOG5(log, param1, param2, param3, param4, param5)                  \
    _LAC_LOG_PARAM5_(                                                          \
        OSAL_LOG_LVL_USER, log, param1, param2, param3, param4, param5)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (5 parameters in the string to be logged). */

#define LAC_LOG6(log, param1, param2, param3, param4, param5, param6)          \
    _LAC_LOG_PARAM6_(OSAL_LOG_LVL_USER,                                        \
                     log,                                                      \
                     param1,                                                   \
                     param2,                                                   \
                     param3,                                                   \
                     param4,                                                   \
                     param5,                                                   \
                     param6)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (6 parameters in the string to be logged). */

#define LAC_LOG7(log, param1, param2, param3, param4, param5, param6, param7)  \
    _LAC_LOG_PARAM7_(OSAL_LOG_LVL_USER,                                        \
                     log,                                                      \
                     param1,                                                   \
                     param2,                                                   \
                     param3,                                                   \
                     param4,                                                   \
                     param5,                                                   \
                     param6,                                                   \
                     param7)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (7 parameters in the string to be logged). */

/************************** Lac Error Log Macros **************************/

#define LAC_LOG_ERROR(log) _LAC_LOG_PARAM0_(OSAL_LOG_LVL_ERROR, log)
/**< @ingroup LacLog
 * Log an error with the prefix "[error]" */

#define LAC_LOG_ERROR1(log, param1)                                            \
    _LAC_LOG_PARAM1_(OSAL_LOG_LVL_ERROR, log, param1)
/**< @ingroup LacLog
 * Log an error with the prefix "[error]"
 * (1 parameter in the string to be logged). */

#define LAC_LOG_ERROR2(log, param1, param2)                                    \
    _LAC_LOG_PARAM2_(OSAL_LOG_LVL_ERROR, log, param1, param2)
/**< @ingroup LacLog
 * Log an error with the prefix "[error]"
 * (2 parameters in the string to be logged). */

#define LAC_LOG_STRING_ERROR1(log, param1)                                     \
    _LAC_LOG_STRING_PARAM1_(OSAL_LOG_LVL_ERROR, log, param1)
/**< @ingroup LacLog
 * Log an error with the prefix "[error]"
 * (1 parameter in the string to be logged). */

#define LAC_LOG_ERROR_PARAMS(log, ...) _LAC_LOG_PARAMS_(log, __VA_ARGS__)
/**< @ingroup LacLog
 * Log an error with the prefix "[error]"
 * with more than 2 params */

/************************** Lac Debug Macros **************************/

#ifdef ICP_DEBUG

#define LAC_LOG_DEBUG(log) _LAC_LOG_PARAM0_(OSAL_LOG_LVL_DEBUG1, log)
/**< @ingroup LacLog
 * Log a message with the prefix "[debug]" */

#define LAC_LOG_DEBUG1(log, param1)                                            \
    _LAC_LOG_PARAM1_(OSAL_LOG_LVL_DEBUG1, log, param1)
/**< @ingroup LacLog
 * Log a message with the prefix "[debug]"
 * (1 parameter in the string to be logged). */

#define LAC_LOG_DEBUG2(log, param1, param2)                                    \
    _LAC_LOG_PARAM2_(OSAL_LOG_LVL_DEBUG1, log, param1, param2)
/**< @ingroup LacLog
 * Log a message with the prefix "[debug]"
   (2 parameters in the string to be logged). */

#else

#define LAC_LOG_DEBUG(log)
#define LAC_LOG_DEBUG1(log, param1)
#define LAC_LOG_DEBUG2(log, param1, param2)

#endif /* ICP_DEBUG */

#define LAC_LOG_BLOCK 0
#define LAC_LOG_PARTIAL_REQUEST 1
#define LAC_LOG_REQUEST 2
#define LAC_LOG_RESPONSE 3

#define LAC_LOG_MSG_ANY_SERVICE 0
#define LAC_LOG_MSG_SYMCYBULK 1
#define LAC_LOG_MSG_SYMCYTRNG 2
#define LAC_LOG_MSG_SYMCYKEY 3
#define LAC_LOG_MSG_PKE 4
#define LAC_LOG_MSG_DC 5

void LacLogMsg_SetConfig(icp_accel_dev_t *device);
void set_osal_log_debug_level(void);


#endif /* LAC_LOG_H */
