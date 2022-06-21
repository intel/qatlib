/***************************************************************************
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
 * Note for strutures with only 1 member no check is required.
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
