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
 * @file lac_dsa_interface_check.c
 *
 * @ingroup Lac_Dsa
 *
 * This file checks at compile time that the IA/FW interface is as expected
 * For example, in lac_dsa.c we use the fact that the index of x in the
 * structure icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t is equal to the index of
 * x in the structure icp_qat_fw_mmp_dsa_gen_p_2048_224_input_t. If this
 * assumption becomes invalid (FW interface changes to break the assumption
 * or the compiler moves things around) this file will fail to compile.
 *
 * Note for strutures with only 1 member no check is required.
 *
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

void LacDsa_CompileTimeAssertions(void)
{
    /* *************************************************************
     * GEN P Checks
     * ************************************************************* */

    /* Check that icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t,
       icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t,
       icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t,
       icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t structures are equivalent */
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t, x) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_2048_224_input_t, x));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_2048_224_input_t, q));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t, x) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_2048_256_input_t, x));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_2048_256_input_t, q));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t, x) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_3072_256_input_t, x));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_p_3072_256_input_t, q));

    /* *************************************************************
     * GEN G Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_2048_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_2048_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_1024_input_t, h) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_2048_input_t, h));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_3072_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_1024_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_3072_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_1024_input_t, h) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_g_3072_input_t, h));

    /* *************************************************************
     * GEN Y Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_2048_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_1024_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_2048_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_1024_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_2048_input_t, x));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_1024_input_t, p) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_3072_input_t, p));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_1024_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_3072_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_1024_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_gen_y_3072_input_t, x));

    /* *************************************************************
     * SIGN R Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, k) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_224_input_t, k));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_224_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_224_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_224_input_t, g));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, k) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_256_input_t, k));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_256_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_256_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_2048_256_input_t, g));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, k) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_3072_256_input_t, k));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_3072_256_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_3072_256_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_3072_256_input_t, g));

    /* *************************************************************
     * SIGN S Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_224_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, k) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_224_input_t, k));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_224_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, r) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_224_input_t, r));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_224_input_t, x));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_256_input_t, m));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, k) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_256_input_t, k));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, q) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_256_input_t, q));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, r) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_256_input_t, r));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_s_256_input_t, x));

    /* *************************************************************
     * SIGN RS Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, m) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_input_t, m));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, k) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_input_t, k));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_input_t, g));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, x) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_input_t, x));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, m) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_input_t, m));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, k) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_input_t, k));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_input_t, g));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, x) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_input_t, x));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, m) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_input_t, m));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, k) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_input_t, k));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_input_t, g));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_input_t, x) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_input_t, x));

    /* Check outputs */
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_output_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_224_output_t, s));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_output_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_2048_256_output_t, s));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_output_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_output_t, s));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_output_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_1024_160_output_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_sign_r_s_3072_256_output_t, s));

    /* *************************************************************
     * VERIFY Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, s));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, m) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, m));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, g));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, y) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_224_input_t, y));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, s));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, m) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, m));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, g));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, y) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_2048_256_input_t, y));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, r) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, r));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, s) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, s));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, m) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, m));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, p) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, p));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, q) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, q));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, g) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, g));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_1024_160_input_t, y) ==
        LAC_IDX_OF(icp_qat_fw_mmp_dsa_verify_3072_256_input_t, y));
}
