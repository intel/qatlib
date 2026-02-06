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
 * @file  cpa_hkdf_sample_user.c
 *
 *****************************************************************************/
#include "cpa.h"
#include "icp_sal_user.h"
#include "cpa_sample_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
extern CpaStatus hkdfSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    /*    status = sampleDeviceStart("SSL", CFG_ALL_DEVICES,
                                 NUM_PROCESSES_DEFAULT,
                                 NUM_INSTANCES_DEFAULT,
                                 NUM_SYM_CONCURRENT_REQUESTS_DEFAULT,
                                 NUM_ASYM_CONCURRENT_REQUESTS_DEFAULT,
                                 LIMIT_DEVICE_ACCESS_DEFAULT);
        if(CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to start device(s)\n");
            return (int) status;
        }
    */
    PRINT_DBG("Starting HKDF sample code ...\n");

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

    status = hkdfSample();
    if ((CPA_STATUS_SUCCESS != status) && (CPA_STATUS_UNSUPPORTED != status))
    {
        PRINT_ERR("\nHKDF sample code failed\n");
    }
    else
    {
        PRINT_DBG("\nHKDF sample code finished\n");
    }

    icp_sal_userStop();
    qaeMemDestroy();
    /*

        if(CPA_STATUS_SUCCESS != sampleDeviceStop(CFG_ALL_DEVICES))
        {
            PRINT_ERR("Failed to stop device(s)\n");
        }
    */
    return (int)status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
