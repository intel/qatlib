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
 *****************************************************************************
 * @file sal_string_parse.c
 *
 * @ingroup SalStringParse
 *
 * @description
 *    This file contains string parsing functions for both user space and kernel
 *    space
 *
 *****************************************************************************/
#include "cpa.h"
#include "lac_mem.h"
#include "sal_string_parse.h"

CpaStatus Sal_StringParsing(char *string1,
                            Cpa32U instanceNumber,
                            char *string2,
                            char *result)
{
    char instNumStr[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};

    LAC_ASSERT_NOT_NULL(string1);
    LAC_ASSERT_NOT_NULL(string2);

    snprintf(instNumStr, SAL_CFG_MAX_VAL_LEN_IN_BYTES, "%u", instanceNumber);

    if ((strnlen(string1, SAL_CFG_MAX_VAL_LEN_IN_BYTES) +
         strnlen(instNumStr, SAL_CFG_MAX_VAL_LEN_IN_BYTES) +
         strnlen(string2, SAL_CFG_MAX_VAL_LEN_IN_BYTES) + 1) >
        SAL_CFG_MAX_VAL_LEN_IN_BYTES)
    {
        LAC_LOG_ERROR("Size of result too small\n");
        return CPA_STATUS_FAIL;
    }

    LAC_OS_BZERO(result, SAL_CFG_MAX_VAL_LEN_IN_BYTES);
    snprintf(result,
             SAL_CFG_MAX_VAL_LEN_IN_BYTES,
             "%s%u%s",
             string1,
             instanceNumber,
             string2);

    return CPA_STATUS_SUCCESS;
}

Cpa64U Sal_Strtoul(const char *cp, char **endp, unsigned int cfgBase)
{
    Cpa64U ulResult = 0;

    ulResult = strtoull(cp, endp, cfgBase);

    return ulResult;
}
