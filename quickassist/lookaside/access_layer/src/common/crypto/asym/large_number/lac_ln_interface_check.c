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
 * Note for structures with only 1 member no check is required.
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
