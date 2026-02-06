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
 * @file  cpa_chaining_sample_user.c
 * argv[1], 1 = Enable 0 = Disable -> gDebugParam
 * argv[2], 1 = Enable 0 = Disable -> useHardCodedCrc
 * argv[3], 1 = Enable 0 = Disable -> useXstorExtensions
 * By default gDebugParam and useHardCodedCrc are enabled.
 * By default useXstorExtensions is disabled.
 * Example to run, ./chaining_sample 1 0 0
 *****************************************************************************/
#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_dc.h"
#include "cpa_dc_chain.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

int gDebugParam = 1;
int useHardCodedCrc = 1;
int useXstorExtensions = 0;

extern CpaStatus dcChainSample(void);

int main(int argc, const char **argv)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;

    if (argc > 1 && argc < 5)
    {
        if (argc == 2)
        {
            gDebugParam = atoi(argv[1]);
        }
        else if (argc == 3)
        {
            gDebugParam = atoi(argv[1]);
            useHardCodedCrc = atoi(argv[2]);
        }
        else if (argc == 4)
        {
            gDebugParam = atoi(argv[1]);
            useHardCodedCrc = atoi(argv[2]);
            useXstorExtensions = atoi(argv[3]);
        }
    }

    PRINT_DBG("Starting Chaining Sample Code App ...\n");

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

    /* Legacy DC Chaining Sample Code */
    stat = dcChainSample();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("\nLegacy DC Chaining Sample Code App failed\n");
    }
    else
    {
        PRINT_DBG("\nLegacy DC Chaining Sample Code App finished\n");
    }

    icp_sal_userStop();

    qaeMemDestroy();

    return (int)stat;
}
