/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/**
 ******************************************************************************
 * @file  cpa_ec_montedwds_sample_user.c
 *
 *****************************************************************************/
#include "cpa.h"
#include "icp_sal_user.h"
#include "cpa_sample_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
extern CpaStatus ecMontEdwdsSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    PRINT_DBG("Starting elliptic curves Edwards,Montgomery sample code ...\n");

    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialize memory driver\n");
        return (int)status;
    }

    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)status;
    }

    status = ecMontEdwdsSample();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("\nElliptic curves sample code failed\n");
    }
    else
    {
        PRINT_DBG("\nElliptic curves sample code finished\n");
    }

    icp_sal_userStop();
    qaeMemDestroy();

    return (int)status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
