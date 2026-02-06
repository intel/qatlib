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
 * @file  cpa_algchaining_sample_user.c
 *
 *****************************************************************************/
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

extern CpaStatus algChainSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    PRINT_DBG("Starting Alg Chain Sample Code App ...\n");

    stat = qaeMemInit();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to initialize memory driver\n");
        return (int)stat;
    }

    stat = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)stat;
    }

    stat = algChainSample();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("\nAlg Chain Sample Code App failed\n");
    }
    else
    {
        PRINT_DBG("\nAlg Chain Sample Code App finished\n");
    }

    icp_sal_userStop();

    qaeMemDestroy();

    return (int)stat;
}
