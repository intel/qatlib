/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 * @file sal_string_parse.h
 *
 * @defgroup SalStringParse
 *
 * @ingroup SalStringParse
 *
 * @description
 *     This file contains string parsing functions
 *
 *****************************************************************************/

#ifndef SAL_STRING_PARSE_H
#define SAL_STRING_PARSE_H

/* Maximum size of the strings used by SAL */
#define SAL_CFG_MAX_VAL_LEN_IN_BYTES 64

/**
*******************************************************************************
* @ingroup SalStringParse
*      Builds a string and store it in result
*
* @description
*      The result string will be the concatenation of string1, instanceNumber
*      and string2. The size of result has to be SAL_CFG_MAX_VAL_LEN_IN_BYTES.
*      We can't check this in this function, this is the user responsibility
*
* @param[in]  string1          First string to concatenate
* @param[in]  instanceNumber   Instance number
* @param[in]  string2          Second string to concatenate
* @param[out] result           Resulting string of concatenation
*
* @retval CPA_STATUS_SUCCESS   Function executed successfully
* @retval CPA_STATUS_FAIL      Function failed
*
*****************************************************************************/
CpaStatus Sal_StringParsing(char *string1,
                            Cpa32U instanceNumber,
                            char *string2,
                            char *result);

/**
*******************************************************************************
* @ingroup SalStringParse
*      Convert a string to an unsigned long
*
* @description
*      Parses the string cp in the specified base, and returned it as an
*      unsigned long value.
*
* @param[in]  cp       String to be converted
* @param[in]  endp     Pointer to the end of the string. This parameter
*                      can also be NULL and will not be used in this case
* @param[in]  cfgBase  Base to convert the string
*
* @retval  The string converted to an unsigned long
*
*****************************************************************************/
Cpa64U Sal_Strtoul(const char *cp, char **endp, unsigned int cfgBase);

#endif /* SAL_STRING_PARSE_H */
