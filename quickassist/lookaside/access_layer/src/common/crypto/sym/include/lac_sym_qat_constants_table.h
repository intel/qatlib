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
 * @file lac_sym_qat_constants_table.h
 *
 * @ingroup  LacSymQat
 *
 * API to be used for the CySym constants table.
 *
 *****************************************************************************/

#ifndef LAC_SYM_QAT_CONSTANTS_TABLE_H
#define LAC_SYM_QAT_CONSTANTS_TABLE_H

#include "cpa.h"
#include "icp_qat_fw_la.h"

typedef struct lac_sym_qat_constants_s
{
    /* Note these arrays must match the tables in lac_sym_qat_constants.c
     * icp_qat_hw_cipher_lookup_tbl and icp_qat_hw_auth_lookup_tbl */
    uint8_t cipher_offset[ICP_QAT_HW_CIPHER_DELIMITER]
                         [ICP_QAT_HW_CIPHER_MODE_DELIMITER][2][2];
    uint8_t auth_offset[ICP_QAT_HW_AUTH_ALGO_DELIMITER]
                       [ICP_QAT_HW_AUTH_MODE_DELIMITER][2];
} lac_sym_qat_constants_t;

/**
 *******************************************************************************
 * @ingroup LacSymQat
 *      LacSymQat_ConstantsInitLookupTables
 *
 *
 * @description
 *      The SymCy constants table is 1K of static data which is passed down
 *      to the FW to be stored in SHRAM for use by the FW.
 *      This function populates the associated lookup tables which the IA
 *      driver uses.
 *      Where there is config data available in the constants table the lookup
 *      table stores the offset into the constants table.
 *      Where there's no suitable config data available in the constants table
 *      zero is stored in the lookup table.
 *
 * @return none
 *
 *****************************************************************************/
void LacSymQat_ConstantsInitLookupTables(CpaInstanceHandle instanceHandle);

/**
*******************************************************************************
* @ingroup LacSymQat
*      LacSymQat_ConstantsGetCipherOffset
*
* @description
*      This function looks up the cipher constants lookup array for
*      a specific cipher algorithm, mode, direction and convert flag.
*      If the lookup table value is zero then there's no suitable config data
*      available in the constants table.
*      If the value > zero, then there is config data available in the constants
*      table which is stored in SHRAM for use by the FW. The value is the offset
*      into the constants table, it is returned to the caller in poffset.
*
*
* @param[in]       Cipher Algorithm
* @param[in]       Cipher Mode
* @param[in]       Direction - encrypt/decrypt
* @param[in]       convert / no convert
* @param[out]      offset into constants table
*
* @return none
*
*****************************************************************************/
void LacSymQat_ConstantsGetCipherOffset(CpaInstanceHandle instanceHandle,
                                        uint8_t algo,
                                        uint8_t mode,
                                        uint8_t direction,
                                        uint8_t convert,
                                        uint8_t *poffset);

/**
*******************************************************************************
* @ingroup LacSymQat
*      LacSymQat_ConstantsGetAuthOffset
*
* @description
*      This function looks up the auth constants lookup array for
*      a specific auth algorithm, mode, direction and convert flag.
*      If the lookup table value is zero then there's no suitable config data
*      available in the constants table.
*      If the value > zero, then there is config data available in the constants
*      table which is stored in SHRAM for use by the FW. The value is the offset
*      into the constants table, it is returned to the caller in poffset.
*
*
* @param[in]       auth Algorithm
* @param[in]       auth Mode
* @param[in]       nested / no nested
* @param[out]      offset into constants table
*
* @return none
*
*****************************************************************************/
void LacSymQat_ConstantsGetAuthOffset(CpaInstanceHandle instanceHandle,
                                      uint8_t algo,
                                      uint8_t mode,
                                      uint8_t nested,
                                      uint8_t *poffset);

#endif /* LAC_SYM_QAT_SHRAM_CONSTANTS_TABLE_H */
