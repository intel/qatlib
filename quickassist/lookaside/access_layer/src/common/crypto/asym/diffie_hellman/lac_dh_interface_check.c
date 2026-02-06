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
 * @file lac_dh_interface_check.c
 *
 * @ingroup Lac_Dh
 *
 * This file checks at compile time that the IA/FW interface is as expected
 * For example, in lac_dh_data_path.c we use the fact that the index of g in the
 * structure icp_qat_fw_mmp_dh_768_input_t is equal to the index of g in the
 * structure icp_qat_fw_mmp_dh_768_input_t. If this assumption becomes invalid
 * (FW interface changes to break the assumption or the compiler moves things
 * around) this file will fail to compile.
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

void LacDh_CompileTimeAssertions(void)
{
    /* *************************************************************
     * DH Checks
     * ************************************************************* */

    /* Check that icp_qat_fw_mmp_dh_768_input_t,
       icp_qat_fw_mmp_dh_1024_input_t, icp_qat_fw_mmp_dh_1536_input_t,
       icp_qat_fw_mmp_dh_2048_input_t, icp_qat_fw_mmp_dh_3072_input_t,
       icp_qat_fw_mmp_dh_4096_input_t, icp_qat_fw_mmp_dh_8192_input_t
       structures are equivalent */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_1024_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_1024_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_1024_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_1536_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_1536_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_1536_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_2048_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_2048_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_2048_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_3072_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_3072_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_3072_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_4096_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_4096_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_4096_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, g) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_8192_input_t, g));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_8192_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_8192_input_t, m));

    /* *************************************************************
     * DH G2 Checks
     * ************************************************************* */
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_1024_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_1024_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_1536_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_1536_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_2048_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_2048_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_3072_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_3072_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_4096_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_4096_input_t, m));

    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, e) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_8192_input_t, e));
    COMPILE_TIME_ASSERT(LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_768_input_t, m) ==
                        LAC_IDX_OF(icp_qat_fw_mmp_dh_g2_8192_input_t, m));
}
