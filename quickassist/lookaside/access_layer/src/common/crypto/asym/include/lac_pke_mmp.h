/*
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
/* A index for maping table that is guaranteed to be invalid */
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
