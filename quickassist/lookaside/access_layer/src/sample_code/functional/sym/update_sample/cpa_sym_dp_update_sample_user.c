/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

#include <unistd.h>

#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

extern CpaStatus symDpUpdateSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
#if CY_API_VERSION_AT_LEAST(2, 2)
    CpaStatus stat = CPA_STATUS_SUCCESS;

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    PRINT_DBG("Starting Sym Dp Update Sample Code App ...\n");

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

    stat = symDpUpdateSample();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("\nSym Dp Update Sample Code App failed\n");
    }
    else
    {
        PRINT_DBG("\nSym Dp Update Sample Code App finished\n");
    }

    icp_sal_userStop();
    qaeMemDestroy();

    return (int)stat;
#else
    printf("The Session Reuse is not supported in this release\n");
    return CPA_STATUS_UNSUPPORTED;
#endif /* CY_API_VERSION_AT_LEAST(2, 2) */
}
