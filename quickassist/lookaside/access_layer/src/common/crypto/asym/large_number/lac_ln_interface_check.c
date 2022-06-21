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
 * @file lac_ln_interface_check.c
 *
 * @ingroup Lac_Ln
 *
 * This file checks at compile time that the IA/FW interface is as expected
 * For example, in lac_ln.c we use the fact that the index of g in the
 * structure icp_qat_fw_maths_modexp_l512_input_t is equal to the index of
 * g in the structure icp_qat_fw_maths_modexp_l1024_input_t. If this
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

void LacLn_CompileTimeAssertions(void)
{
    /* *************************************************************
     * MOD EXP Checks
     * ************************************************************* */

    /* Check that icp_qat_fw_maths_modexp_l512_input_t,
       icp_qat_fw_maths_modexp_l1024_input_t,
       icp_qat_fw_maths_modexp_l1536_input_t,
       icp_qat_fw_maths_modexp_l2048_input_t,
       icp_qat_fw_maths_modexp_l2560_input_t,
       icp_qat_fw_maths_modexp_l3072_input_t,
       icp_qat_fw_maths_modexp_l3584_input_t,
       icp_qat_fw_maths_modexp_l4096_input_t,
       icp_qat_fw_maths_modexp_l8192_input_t structures are equivalent */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l1024_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l1024_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l1024_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l1536_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l1536_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l1536_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l2048_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l2048_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l2048_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l2560_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l2560_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l2560_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l3072_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l3072_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l3072_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l3584_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l3584_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l3584_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l4096_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l4096_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l4096_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l8192_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l8192_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_maths_modexp_l512_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_maths_modexp_l8192_input_t, m));

    /* *************************************************************
     * MOD INV Checks - ODD
     * ************************************************************* */

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l192_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l192_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l256_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l256_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l384_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l384_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l512_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l512_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l768_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l768_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l1024_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l1024_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l1536_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l1536_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l2048_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l2048_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l3072_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l3072_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l4096_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l4096_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l8192_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l8192_input_t, b));

    /* *************************************************************
     * MOD INV Checks - EVEN
     * ************************************************************* */

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l192_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l192_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l256_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l256_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l384_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l384_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l512_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l512_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l768_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l768_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l1024_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l1024_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l1536_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l1536_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l2048_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l2048_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l3072_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l3072_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l4096_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l4096_input_t, b));

    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, a) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l8192_input_t, a));
    COMPILE_TIME_ASSERT(
        LAC_IDX_OF(icp_qat_fw_maths_modinv_odd_l128_input_t, b) ==
        LAC_IDX_OF(icp_qat_fw_maths_modinv_even_l8192_input_t, b));
}
