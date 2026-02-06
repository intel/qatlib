/***************************************************************************
 *
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *
 ***************************************************************************/

/****************************************************************************
 * @file  cpa_ec_montedwds_sample_user.c
 *
 * @description
 *     This file contains main function used in EDDSA sample.
 *
 ****************************************************************************/

#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

extern CpaStatus ecMontEdwdsDsaSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (argc > 1)
        gDebugParam = atoi(argv[1]);

    PRINT_DBG("Starting EDDSA sample code ...\n");

    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialise memory driver\n");
        return (int)status;
    }

    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)status;
    }

    status = ecMontEdwdsDsaSample();
    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("EDDSA sample code failed\n");
    else
        PRINT_DBG("EDDSA code finished\n");

    icp_sal_userStop();
    qaeMemDestroy();

    return (int)status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
