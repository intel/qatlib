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

#ifdef KERNEL_SPACE
    ulResult = (Cpa64U)simple_strtoull(cp, endp, cfgBase);
#else
    ulResult = strtoull(cp, endp, cfgBase);
#endif

    return ulResult;
}
