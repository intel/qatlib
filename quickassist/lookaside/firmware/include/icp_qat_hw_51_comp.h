/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *****************************************************************************
 * @file icp_qat_hw_51_comp.h
 * @defgroup ICP QAT HW accessors for using the for 5.1 Compression Slice
 * definitions
 * @ingroup icp_qat_hw_51_comp
 * @description
 *      This file documents definitions for the QAT5.1 HW COMP SLICE
 *
 *****************************************************************************/

#ifndef _ICP_QAT_HW_51_COMP_H_
#define _ICP_QAT_HW_51_COMP_H_

#include "icp_qat_hw_51_comp_defs.h" /* For HW definitions */
#include "icp_qat_fw.h"              /* For Set Field Macros. */

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the HW config CSR. This representation has to be further
*     processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_comp_51_config_csr_lower_s
{
    /* Fields programmable directly by the SW. */
    icp_qat_hw_comp_51_abd_t abd;
    icp_qat_hw_comp_51_lllbd_ctrl_t lllbd;
    icp_qat_hw_comp_51_search_depth_t sd;
    /* Advanced HW control (set to default values) */
    icp_qat_hw_comp_51_min_match_control_t mmctrl;
    icp_qat_hw_comp_51_lz4_block_checksum_t lbc;
} icp_qat_hw_comp_51_config_csr_lower_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_COMP_51_BUILD_CONFIG_LOWER(
    icp_qat_hw_comp_51_config_csr_lower_t csr)
{
    uint32_t val32 = 0;

    /* Programmable values */
    QAT_FIELD_SET(val32,
                  csr.abd,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_ABD_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_ABD_MASK);

    QAT_FIELD_SET(val32,
                  csr.lllbd,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_LLLBD_CTRL_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_LLLBD_CTRL_MASK);

    QAT_FIELD_SET(val32,
                  csr.sd,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_SEARCH_DEPTH_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_SEARCH_DEPTH_MASK);

    QAT_FIELD_SET(val32,
                  csr.mmctrl,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_MIN_MATCH_CONTROL_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_MIN_MATCH_CONTROL_MASK);

    QAT_FIELD_SET(val32,
                  csr.lbc,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_LZ4_BLOCK_CHECKSUM_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_LZ4_BLOCK_CHECKSUM_MASK);

    return val32;
}

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the HW config CSR. This representation has to be further
*     processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_comp_51_config_csr_upper_s
{
    icp_qat_hw_comp_51_dmm_algorithm_t edmm;
    icp_qat_hw_comp_51_bms_t bms;
    icp_qat_hw_comp_51_scb_mode_reset_mask_t scb_mode_reset;
} icp_qat_hw_comp_51_config_csr_upper_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_COMP_51_BUILD_CONFIG_UPPER(
    icp_qat_hw_comp_51_config_csr_upper_t csr)
{
    uint32_t val32 = 0;

    QAT_FIELD_SET(val32,
                  csr.edmm,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_DMM_ALGORITHM_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_DMM_ALGORITHM_MASK);

    QAT_FIELD_SET(val32,
                  csr.bms,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_BMS_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_BMS_MASK);

    QAT_FIELD_SET(val32,
                  csr.scb_mode_reset,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_SCB_MODE_RESET_MASK_BITPOS,
                  ICP_QAT_HW_COMP_51_CONFIG_CSR_SCB_MODE_RESET_MASK_MASK);

    return val32;
}

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the HW config CSR. This representation has to be further
*     processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_decomp_51_config_csr_lower_s
{
    /* Advanced HW control (set to default values) */
    icp_qat_hw_decomp_51_lz4_block_checksum_t lbc;
} icp_qat_hw_decomp_51_config_csr_lower_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_DECOMP_51_BUILD_CONFIG_LOWER(
    icp_qat_hw_decomp_51_config_csr_lower_t csr)
{
    uint32_t val32 = 0;

    QAT_FIELD_SET(val32,
                  csr.lbc,
                  ICP_QAT_HW_DECOMP_51_CONFIG_CSR_LZ4_BLOCK_CHECKSUM_BITPOS,
                  ICP_QAT_HW_DECOMP_51_CONFIG_CSR_LZ4_BLOCK_CHECKSUM_MASK);

    return val32;
}

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Definition of the HW config CSR. This representation has to be further
*     processed by the corresponding config build function.
*
*****************************************************************************/
typedef struct icp_qat_hw_decomp_51_config_csr_upper_s
{
    /* Advanced HW control (set to default values) */
    icp_qat_hw_decomp_51_bms_t bms;
} icp_qat_hw_decomp_51_config_csr_upper_t;

/**
*****************************************************************************
* @ingroup icp_qat_fw_comn
*
* @description
*     Build the longword as expected by the HW
*
*****************************************************************************/
static inline uint32_t ICP_QAT_FW_DECOMP_51_BUILD_CONFIG_UPPER(
    icp_qat_hw_decomp_51_config_csr_upper_t csr)
{
    uint32_t val32 = 0;

    QAT_FIELD_SET(val32,
                  csr.bms,
                  ICP_QAT_HW_DECOMP_51_CONFIG_CSR_BMS_BITPOS,
                  ICP_QAT_HW_DECOMP_51_CONFIG_CSR_BMS_MASK);

    return val32;
}

#endif /* ICP_QAT_HW_51_COMP_H_ */
