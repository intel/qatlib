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
 * @file  cpa_decomp_sample_user.c
 *
 *****************************************************************************/

#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

#define FILE_NAME_LENGTH 100
char *gFileNameComp = NULL;
char *gFileNameOut = NULL;

extern CpaStatus dcStatelessDecompSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;
    char fileComp[FILE_NAME_LENGTH] = "paper4.gz";
    char fileRes[FILE_NAME_LENGTH] = "paper4_decompressed";

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    PRINT_DBG("Starting Stateless Decompression Sample Code App ...\n");

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

    gFileNameComp = fileComp;
    gFileNameOut = fileRes;

    stat = dcStatelessDecompSample();

    if (CPA_STATUS_SUCCESS == stat)
    {
        PRINT_DBG("\nStateless Decompression Sample Code App finished\n");
    }
    else
    {
        PRINT_ERR("\nStateless Decompression Sample Code App failed\n");
    }

    icp_sal_userStop();

    qaeMemDestroy();
    gFileNameComp = NULL;
    gFileNameOut = NULL;

    return (int)stat;
}
