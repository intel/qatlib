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
 * @file lac_prime_interface_check.c
 *
 * @ingroup Lac_Prime
 *
 * This file checks at compile time that the IA/FW interface is as expected
 * For example, in lac_prime.c we use the fact that the index of x in the
 * structure icp_qat_fw_mmp_mr_pt_160_input_t is equal to the index of
 * x in the structure icp_qat_fw_mmp_mr_pt_512_input_t. If this
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
#include "lac_pke_utils.h"

#define MAX_MR_ROUNDS_SUPPORTED 50
#define MIN_MR_ROUNDS_SUPPORTED 1
/**<
 * MAX number of MR rounds can be decided
   at compile time - use these a limits for
   compile time check on this number */

#define COMPILE_TIME_ASSERT(pred)                                              \
    switch (0)                                                                 \
    {                                                                          \
        case 0:                                                                \
        case pred:;                                                            \
    }

void LacPrime_CompileTimeAssertions(void)
{

    /* ************************************************************
     * Check 0 < LAC_PRIME_MAX_MR <= 50
     * ************************************************************ */

    COMPILE_TIME_ASSERT(LAC_PRIME_MAX_MR <= MAX_MR_ROUNDS_SUPPORTED);
    COMPILE_TIME_ASSERT(LAC_PRIME_MAX_MR >= MIN_MR_ROUNDS_SUPPORTED);

    /* *************************************************************
     * MR interface check - note for all other prime services there
     * is only 1 member in the structure
     * ************************************************************* */

    /* Check that icp_qat_fw_mmp_mr_pt_160_input_t,
       icp_qat_fw_mmp_mr_pt_512_input_t,
       icp_qat_fw_mmp_mr_pt_768_input_t,
       icp_qat_fw_mmp_mr_pt_1024_input_t,
       icp_qat_fw_mmp_mr_pt_1536_input_t,
       icp_qat_fw_mmp_mr_pt_2048_input_t,
       icp_qat_fw_mmp_mr_pt_3072_input_t,
       icp_qat_fw_mmp_mr_pt_4096_input_t,
       icp_qat_fw_mmp_mr_pt_l512_input_t structures are equivalent */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_512_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_512_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_768_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_768_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_1024_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_1024_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_1536_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_1536_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_2048_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_2048_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_3072_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_3072_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_4096_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_4096_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, x) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_l512_input_t, x));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_160_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_mr_pt_l512_input_t, m));
}
