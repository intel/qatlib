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
 * @file lac_rsa_interface_check.c
 *
 * @ingroup Lac_Rsa
 *
 * This file checks at compile time that the IA/FW interface is as expected
 * For example, in lac_rsa_keygen.c we use the fact that the index of p in the
 * structure icp_qat_fw_mmp_rsa_kp1_1024_input_t is equal to the index of
 * p in the structure icp_qat_fw_mmp_rsa_kp1_2048_input_t. If this
 * assumption becomes invalid (FW interface changes to break the assumption
 * or the compiler moves things around) this file will fail to compile.
 *
 * Note for structures with only 1 member no check is required.
 *
 ***************************************************************************/

#include "cpa.h"

#include "icp_qat_fw_pke.h"
#include "icp_qat_fw_mmp.h"
#include "lac_common.h"

#define COMPILE_TIME_ASSERT(pred)                                              \
    switch (0)                                                                 \
    {                                                                          \
        case 0:                                                                \
        case pred:;                                                            \
    }

void LacRsa_CompileTimeAssertions(void)
{

    /* *************************************************************
     * KEY GEN TYPE 1 Checks
     * ************************************************************* */

    /* Check that icp_qat_fw_mmp_rsa_kp1_512_input_t,
       icp_qat_fw_mmp_rsa_kp1_1024_input_t,
       icp_qat_fw_mmp_rsa_kp1_1536_input_t,
       icp_qat_fw_mmp_rsa_kp1_2048_input_t,
       icp_qat_fw_mmp_rsa_kp1_3072_input_t,
       icp_qat_fw_mmp_rsa_kp1_4096_input_t structures are equivalent */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_512_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_512_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_512_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1536_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1536_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1536_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_2048_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_2048_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_2048_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_3072_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_3072_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_3072_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_4096_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_4096_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_4096_input_t, e));

    /* Check outputs */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_512_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_512_output_t, d));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1536_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1536_output_t, d));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_2048_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_2048_output_t, d));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_3072_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_3072_output_t, d));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_4096_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp1_4096_output_t, d));

    /* *************************************************************
     * KEY GEN TYPE 2 Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_input_t, e));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_input_t, e))

    /* Check outputs */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_output_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_output_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_output_t, dq));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, qinv) ==
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_512_output_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_output_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_output_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_output_t, dq));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, qinv) ==
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1536_output_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_output_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_output_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_output_t, dq));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, qinv) ==
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_2048_output_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_output_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_output_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_output_t, dq));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, qinv) ==
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_3072_output_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_output_t, n));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_output_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_output_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_output_t, dq));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_1024_output_t, qinv) ==
        LAC_IDX_OF(icp_qat_fw_mmp_rsa_kp2_4096_output_t, qinv));

    /* *************************************************************
     * ENCRYPT Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_512_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_512_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_512_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1536_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1536_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1536_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_2048_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_2048_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_2048_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_3072_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_3072_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_3072_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_4096_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_4096_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_4096_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_8192_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_8192_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_ep_8192_input_t, n));

    /* *************************************************************
     * DECRYPT TYPE 1 Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_512_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_512_input_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_512_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1536_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1536_input_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1536_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_2048_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_2048_input_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_2048_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_3072_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_3072_input_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_3072_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_4096_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_4096_input_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_4096_input_t, n));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_8192_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, d) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_8192_input_t, d));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_1024_input_t, n) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp1_8192_input_t, n));

    /* *************************************************************
     * DECRYPT TYPE 2 Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_512_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_512_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_512_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_512_input_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_512_input_t, dq));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, qinv) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_512_input_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1536_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1536_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1536_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1536_input_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1536_input_t, dq));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, qinv) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1536_input_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_2048_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_2048_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_2048_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_2048_input_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_2048_input_t, dq));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, qinv) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_2048_input_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_3072_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_3072_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_3072_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_3072_input_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_3072_input_t, dq));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, qinv) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_3072_input_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_4096_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_4096_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_4096_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_4096_input_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_4096_input_t, dq));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, qinv) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_4096_input_t, qinv));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, c) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_8192_input_t, c));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_8192_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_8192_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dp) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_8192_input_t, dp));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, dq) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_8192_input_t, dq));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_1024_input_t, qinv) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_rsa_dp2_8192_input_t, qinv));
}
