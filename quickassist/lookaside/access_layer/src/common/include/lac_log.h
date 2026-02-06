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
#include "icp_accel_devices.h"

#define LAC_OSAL_LOG osalLog

#define LAC_OSAL_LOG_STRING osalLog

#define LAC_OSAL_LOG_PARAMS osalStdLog

#define _LAC_LOG_PARAM0_(level, log)                                           \
    (void)LAC_OSAL_LOG(                                                        \
        level, OSAL_LOG_DEV_STDERR, "%s() - : " log "\n", __func__)
/**< @ingroup LacLog
 * Internal macro that accepts no parameters in the string to be logged */

#define _LAC_LOG_PARAM1_(level, log, param1)                                   \
    (void)LAC_OSAL_LOG(                                                        \
        level, OSAL_LOG_DEV_STDERR, "%s() - : " log "\n", __func__, param1)
/**< @ingroup LacLog
 * Internal macro that accepts 1 parameter in the string to be logged */

#define _LAC_LOG_PARAM2_(level, log, param1, param2)                           \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2)
/**< @ingroup LacLog
 * Internal macro that accepts 2 parameters in the string to be logged */

#define _LAC_LOG_PARAM3_(level, log, param1, param2, param3)                   \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3)
/**< @ingroup LacLog
 * Internal macro that accepts 3 parameters in the string to be logged */

#define _LAC_LOG_PARAM4_(level, log, param1, param2, param3, param4)           \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3,                                                 \
                       param4)
/**< @ingroup LacLog
 * Internal macro that accepts 4 parameters in the string to be logged */

#define _LAC_LOG_PARAM5_(level, log, param1, param2, param3, param4, param5)   \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3,                                                 \
                       param4,                                                 \
                       param5)
/**< @ingroup LacLog
 * Internal macro that accepts 5 parameters in the string to be logged */

#define _LAC_LOG_PARAM6_(                                                      \
    level, log, param1, param2, param3, param4, param5, param6)                \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3,                                                 \
                       param4,                                                 \
                       param5,                                                 \
                       param6)
/**< @ingroup LacLog
 * Internal macro that accepts 6 parameters in the string to be logged */

#define _LAC_LOG_PARAM7_(                                                      \
    level, log, param1, param2, param3, param4, param5, param6, param7)        \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3,                                                 \
                       param4,                                                 \
                       param5,                                                 \
                       param6,                                                 \
                       param7)
/**< @ingroup LacLog
 * Internal macro that accepts 7 parameters in the string to be logged */

#define _LAC_LOG_PARAM8_(level,                                                \
                         log,                                                  \
                         param1,                                               \
                         param2,                                               \
                         param3,                                               \
                         param4,                                               \
                         param5,                                               \
                         param6,                                               \
                         param7,                                               \
                         param8)                                               \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3,                                                 \
                       param4,                                                 \
                       param5,                                                 \
                       param6,                                                 \
                       param7,                                                 \
                       param8)
/**< @ingroup LacLog
 * Internal macro that accepts 8 parameters in the string to be logged */

#define _LAC_LOG_PARAM9_(level,                                                \
                         log,                                                  \
                         param1,                                               \
                         param2,                                               \
                         param3,                                               \
                         param4,                                               \
                         param5,                                               \
                         param6,                                               \
                         param7,                                               \
                         param8,                                               \
                         param9)                                               \
    (void)LAC_OSAL_LOG(level,                                                  \
                       OSAL_LOG_DEV_STDERR,                                    \
                       "%s() - : " log "\n",                                   \
                       __func__,                                               \
                       param1,                                                 \
                       param2,                                                 \
                       param3,                                                 \
                       param4,                                                 \
                       param5,                                                 \
                       param6,                                                 \
                       param7,                                                 \
                       param8,                                                 \
                       param9)
/**< @ingroup LacLog
 * Internal macro that accepts 9 parameters in the string to be logged */

#define _LAC_LOG_STRING_PARAM1_(level, log, param1)                            \
    (void)LAC_OSAL_LOG_STRING(                                                 \
        level, OSAL_LOG_DEV_STDERR, "%s() - : " log "\n", __func__, param1)

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

#define LAC_LOG8(                                                              \
    log, param1, param2, param3, param4, param5, param6, param7, param8)       \
    _LAC_LOG_PARAM8_(OSAL_LOG_LVL_USER,                                        \
                     log,                                                      \
                     param1,                                                   \
                     param2,                                                   \
                     param3,                                                   \
                     param4,                                                   \
                     param5,                                                   \
                     param6,                                                   \
                     param7,                                                   \
                     param8)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (8 parameters in the string to be logged). */

#define LAC_LOG9(log,                                                          \
                 param1,                                                       \
                 param2,                                                       \
                 param3,                                                       \
                 param4,                                                       \
                 param5,                                                       \
                 param6,                                                       \
                 param7,                                                       \
                 param8,                                                       \
                 param9)                                                       \
    _LAC_LOG_PARAM9_(OSAL_LOG_LVL_USER,                                        \
                     log,                                                      \
                     param1,                                                   \
                     param2,                                                   \
                     param3,                                                   \
                     param4,                                                   \
                     param5,                                                   \
                     param6,                                                   \
                     param7,                                                   \
                     param8,                                                   \
                     param9)
/**< @ingroup LacLog
 * Log a string with no prefix
 * (9 parameters in the string to be logged). */

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
