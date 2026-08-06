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
 * @file  kpt_rsa_sample_main.c
 *
 *****************************************************************************/
#include "cpa_types.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

extern CpaStatus kptRsaOp(void);

int main(int argc, const char **argv)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    PRINT("Starting KPT RSA Sample Code App ...\n");

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

    status = kptRsaOp();
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT("\nKPT RSA Sample Code App finished\n");
    }
    else
    {
        PRINT_ERR("\nKPT RSA Sample Code App failed\n");
    }

    icp_sal_userStop();
    qaeMemDestroy();

    return (int)status;
}
