/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 ***************************************************************************
 * @file lac_pke_mmp.h
 *
 * @defgroup LacAsymCommonMmp Lac Pke Mmp
 *
 * @ingroup LacAsymCommon
 *
 * This file defines the structs and constants necessary to communicate
 * with the QAT.
 ******************************************************************************/

#ifndef _LAC_PKE_MMP_H_
#define _LAC_PKE_MMP_H_

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include "cpa.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/
#include "icp_qat_fw_mmp.h"

/******************************************************************************/

/* A functionality id that is guaranteed to be invalid */
#define LAC_PKE_INVALID_FUNC_ID 0
/* A index for mapping table that is guaranteed to be invalid */
#define LAC_PKE_INVALID_INDEX -1
/* Current total of input/output parameters */
#define LAC_MAX_MMP_PARAMS 8
/*PKE offset in status flags*/
#define PKE_STATUS_FLAG_OFFSET 8

/*
 * The QAT interface provides us with structs for each operation size.
 * They all have the same parameters (validated at compile time)  so to
 * get generic structs we simply typedef one of the size specific structs.
 */

typedef icp_qat_fw_mmp_dh_768_input_t icp_qat_fw_mmp_dh_input_t;
typedef icp_qat_fw_mmp_dh_768_output_t icp_qat_fw_mmp_dh_output_t;

typedef icp_qat_fw_mmp_dh_g2_768_input_t icp_qat_fw_mmp_dh_g2_input_t;
typedef icp_qat_fw_mmp_dh_g2_768_output_t icp_qat_fw_mmp_dh_g2_output_t;

typedef icp_qat_fw_mmp_rsa_dp1_1024_input_t icp_qat_fw_mmp_rsa_dp1_input_t;
typedef icp_qat_fw_mmp_rsa_dp1_1024_output_t icp_qat_fw_mmp_rsa_dp1_output_t;

typedef icp_qat_fw_mmp_rsa_dp2_1024_input_t icp_qat_fw_mmp_rsa_dp2_input_t;
typedef icp_qat_fw_mmp_rsa_dp2_1024_output_t icp_qat_fw_mmp_rsa_dp2_output_t;

typedef icp_qat_fw_mmp_rsa_kp1_1024_input_t icp_qat_fw_mmp_rsa_kp1_input_t;
typedef icp_qat_fw_mmp_rsa_kp1_1024_output_t icp_qat_fw_mmp_rsa_kp1_output_t;

typedef icp_qat_fw_mmp_rsa_kp2_1024_input_t icp_qat_fw_mmp_rsa_kp2_input_t;
typedef icp_qat_fw_mmp_rsa_kp2_1024_output_t icp_qat_fw_mmp_rsa_kp2_output_t;

typedef icp_qat_fw_mmp_rsa_ep_1024_input_t icp_qat_fw_mmp_rsa_ep_input_t;
typedef icp_qat_fw_mmp_rsa_ep_1024_output_t icp_qat_fw_mmp_rsa_ep_output_t;

/* Similarly for DSA */
typedef icp_qat_fw_mmp_dsa_gen_g_1024_input_t icp_qat_fw_mmp_dsa_gen_g_input_t;
typedef icp_qat_fw_mmp_dsa_gen_y_1024_input_t icp_qat_fw_mmp_dsa_gen_y_input_t;
typedef icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t
    icp_qat_fw_mmp_dsa_gen_p_input_t;
typedef icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t
    icp_qat_fw_mmp_dsa_sign_r_input_t;
typedef icp_qat_fw_mmp_dsa_sign_s_160_input_t icp_qat_fw_mmp_dsa_sign_s_input_t;
typedef icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t
    icp_qat_fw_mmp_dsa_sign_r_s_input_t;
typedef icp_qat_fw_mmp_dsa_verify_1024_160_input_t
    icp_qat_fw_mmp_dsa_verify_input_t;
typedef icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t
    icp_qat_fw_mmp_dsa_sign_r_s_output_t;

#define LAC_MAX_MMP_INPUT_PARAMS                                               \
    (sizeof(icp_qat_fw_mmp_input_param_t) / sizeof(Cpa64U))

#define LAC_MAX_MMP_OUTPUT_PARAMS                                              \
    (sizeof(icp_qat_fw_mmp_output_param_t) / sizeof(Cpa64U))

/*
 * This enumeration defines the column array indexes for the
 * various SIZE:ID tables.
 */
typedef enum
{
    LAC_PKE_SIZE_COLUMN = 0,
    LAC_PKE_ID_COLUMN,
    LAC_PKE_NUM_COLUMNS
} lac_size_id_map_columns_t;

/**
 *******************************************************************************
 * @ingroup LacAsymCommonMmp
 *      Returns the MMP Id for the given size in bits from the given table.
 *
 * @param[in] sizeInBits        the size of the operation
 * @param[in] pSizeIdTable      table of mmp ids for that operation
 * @param[in] numTableEntries   number of mmp ids for that operation
 ******************************************************************************/
Cpa32U LacPke_GetMmpId(Cpa32U sizeInBits,
                       const Cpa32U pSizeIdTable[][LAC_PKE_NUM_COLUMNS],
                       Cpa32U numTableEntries);

/**
 *******************************************************************************
 * @ingroup LacAsymCommonMmp
 *      Returns the table entry for the given data size in bits that can be
 *      treated with the shortest operation size from the given table.
 *
 * @param[in] sizeInBits        the size of the operation
 * @param[in] pSizeIdTable      table of mmp ids for that operation
 * @param[in] numTableEntries   number of mmp ids for that operation
 *****************************************************************************/
Cpa32U LacPke_GetIndex_VariableSize(
    Cpa32U sizeInBits,
    const Cpa32U pSizeIdTable[][LAC_PKE_NUM_COLUMNS],
    Cpa32U numTableEntries);

#endif /* _LAC_PKE_MMP_H_ */
