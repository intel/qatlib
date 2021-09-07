/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2021 Intel Corporation. All rights reserved.
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
 */

/**
 *****************************************************************************
 * @file icp_qat_hw_2x_comp.h
 * @defgroup ICP QAT HW accessors for using the for 2.x Compression Slice
 * definitions
 * @ingroup icp_qat_hw_2x_comp
 * @description
 *      This file documents definitions for the QAT HW COMP SLICE
 *
 *****************************************************************************/

#ifndef _ICP_QAT_HW_20_COMP_H_
#define _ICP_QAT_HW_20_COMP_H_

#include "icp_qat_hw_20_comp_defs.h" /* For HW definitions */
#include "icp_qat_fw.h"              /* For Set Field Macros. */


#define BYTE_SWAP_32 __builtin_bswap32

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the hw config csr. This representation has to be further
* processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_comp_20_config_csr_lower_s
{
    /* Fields programmable directly by the SW. */
    icp_qat_hw_comp_20_extended_delay_match_mode_t edmm;
    icp_qat_hw_comp_20_hw_comp_format_t algo;
    icp_qat_hw_comp_20_search_depth_t sd;
    icp_qat_hw_comp_20_hbs_control_t hbs;
    /* Fields programmable directly by the FW. */
    /* Reserved1 (Set by FW) */
    icp_qat_hw_comp_20_reserved1_t res1;
    icp_qat_hw_comp_20_reserved2_ctrl_t res2;
    /* Advanced HW control (Set to default vals) */
    icp_qat_hw_comp_20_reserved3_control_t res3;
    icp_qat_hw_comp_20_skip_hash_collision_t hash_col;
    icp_qat_hw_comp_20_skip_hash_update_t hash_update;
    icp_qat_hw_comp_20_byte_skip_t skip_ctrl;

} icp_qat_hw_comp_20_config_csr_lower_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_COMP_20_BUILD_CONFIG_LOWER(
    icp_qat_hw_comp_20_config_csr_lower_t csr)
{
    uint32_t val32 = 0;
    /* Programmable values */
    QAT_FIELD_SET(val32,
                  csr.algo,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_HW_COMP_FORMAT_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_HW_COMP_FORMAT_MASK);

    QAT_FIELD_SET(val32,
                  csr.sd,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SEARCH_DEPTH_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SEARCH_DEPTH_MASK);

    QAT_FIELD_SET(
        val32,
        csr.edmm,
        ICP_QAT_HW_COMP_20_CONFIG_CSR_EXTENDED_DELAY_MATCH_MODE_BITPOS,
        ICP_QAT_HW_COMP_20_CONFIG_CSR_EXTENDED_DELAY_MATCH_MODE_MASK);

    QAT_FIELD_SET(val32,
                  csr.hbs,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_HBS_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_HBS_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.res3,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RESERVED3_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RESERVED3_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.hash_col,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SKIP_HASH_COLLISION_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SKIP_HASH_COLLISION_MASK);

    QAT_FIELD_SET(val32,
                  csr.hash_update,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SKIP_HASH_UPDATE_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SKIP_HASH_UPDATE_MASK);

    QAT_FIELD_SET(val32,
                  csr.skip_ctrl,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_BYTE_SKIP_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_BYTE_SKIP_MASK);
    /* Default values. */

    QAT_FIELD_SET(val32,
                  csr.res1,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RESERVED1_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RESERVED1_MASK);

    QAT_FIELD_SET(val32,
                  csr.res2,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RESERVED2_CTRL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RESERVED2_CTRL_MASK);

    return BYTE_SWAP_32(val32);
}

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the hw config csr. This representation has to be further
* processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_comp_20_config_csr_upper_s
{
    icp_qat_hw_comp_20_scb_control_t scb_ctrl;
    icp_qat_hw_comp_20_rmb_control_t rmb_ctrl;
    icp_qat_hw_comp_20_som_control_t som_ctrl;
    icp_qat_hw_comp_20_skip_hash_rd_control_t skip_hash_ctrl;
    icp_qat_hw_comp_20_scb_unload_control_t scb_unload_ctrl;
    icp_qat_hw_comp_20_disable_token_fusion_control_t disable_token_fusion_ctrl;
    uint16_t lazy;
    uint16_t nice;
} icp_qat_hw_comp_20_config_csr_upper_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_COMP_20_BUILD_CONFIG_UPPER(
    icp_qat_hw_comp_20_config_csr_upper_t csr)
{
    uint32_t val32 = 0;

    QAT_FIELD_SET(val32,
                  csr.scb_ctrl,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SCB_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SCB_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.rmb_ctrl,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RMB_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_RMB_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.som_ctrl,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SOM_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SOM_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.skip_hash_ctrl,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SKIP_HASH_RD_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SKIP_HASH_RD_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.scb_unload_ctrl,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SCB_UNLOAD_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_SCB_UNLOAD_CONTROL_MASK);

    QAT_FIELD_SET(
        val32,
        csr.disable_token_fusion_ctrl,
        ICP_QAT_HW_COMP_20_CONFIG_CSR_DISABLE_TOKEN_FUSION_CONTROL_BITPOS,
        ICP_QAT_HW_COMP_20_CONFIG_CSR_DISABLE_TOKEN_FUSION_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.lazy,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_LAZY_PARAM_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_LAZY_PARAM_MASK);

    QAT_FIELD_SET(val32,
                  csr.nice,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_NICE_PARAM_BITPOS,
                  ICP_QAT_HW_COMP_20_CONFIG_CSR_NICE_PARAM_MASK);

    return BYTE_SWAP_32(val32);
}

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the hw config csr. This representation has to be further
* processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_decomp_20_config_csr_lower_s
{
    /* Fields programmable directly by the SW. */
    icp_qat_hw_decomp_20_hbs_control_t hbs;
    /* Advanced HW control (Set to default vals) */
    icp_qat_hw_decomp_20_hw_comp_format_t algo;
    icp_qat_hw_decomp_20_reserved3_control_t res3;
} icp_qat_hw_decomp_20_config_csr_lower_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_DECOMP_20_BUILD_CONFIG_LOWER(
    icp_qat_hw_decomp_20_config_csr_lower_t csr)
{
    uint32_t val32 = 0;

    QAT_FIELD_SET(val32,
                  csr.hbs,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_HBS_CONTROL_BITPOS,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_HBS_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.algo,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_HW_DECOMP_FORMAT_BITPOS,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_HW_DECOMP_FORMAT_MASK);

    QAT_FIELD_SET(val32,
                  csr.res3,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_RESERVED3_CONTROL_BITPOS,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_RESERVED3_CONTROL_MASK);

    return BYTE_SWAP_32(val32);
}

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the hw config csr. This representation has to be further
* processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_decomp_20_config_csr_upper_s
{
    /* Advanced HW control (Set to default vals) */
    icp_qat_hw_decomp_20_speculative_decoder_control_t sdc;
    icp_qat_hw_decomp_20_reserved4_control_t res4;
} icp_qat_hw_decomp_20_config_csr_upper_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_DECOMP_20_BUILD_CONFIG_UPPER(
    icp_qat_hw_decomp_20_config_csr_upper_t csr)
{
    uint32_t val32 = 0;

    QAT_FIELD_SET(
        val32,
        csr.sdc,
        ICP_QAT_HW_DECOMP_20_CONFIG_CSR_SPECULATIVE_DECODER_CONTROL_BITPOS,
        ICP_QAT_HW_DECOMP_20_CONFIG_CSR_SPECULATIVE_DECODER_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.res4,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_RESERVED4_CONTROL_BITPOS,
                  ICP_QAT_HW_DECOMP_20_CONFIG_CSR_RESERVED4_CONTROL_MASK);

    return BYTE_SWAP_32(val32);
}
#endif /* ICP_QAT_HW__2X_COMP_H_ */
