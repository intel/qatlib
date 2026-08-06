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
 * @file  cpa_dc_sample_user_dict.c
 *
 * To run this sample code : "./dc_stateless_sample_dict"
 *****************************************************************************/
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

#define FILE_NAME_LENGTH 100
int gDebugParam = 1;
char *gInputFileName = NULL;
char *gDictFileName = NULL;

extern CpaStatus dcStatelessSampleDict();

int main(int argc, char **argv)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus processStatus = CPA_STATUS_SUCCESS;
    char inputFile[FILE_NAME_LENGTH] = "paper4";
    char dictFile[FILE_NAME_LENGTH] = "paper4.dict";

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    PRINT("Starting Stateless Dictionary Compression Sample Code App ...\n");

    gInputFileName = inputFile;
    gDictFileName = dictFile;

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

    status = dcStatelessSampleDict();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("\nStateless Dict Compression Sample Code App failed\n");
    }
    else
    {
        PRINT("\nStateless Dict Compression Sample Code App finished "
              "successfully\n");
    }

    processStatus = icp_sal_userStop();
    if (CPA_STATUS_SUCCESS != processStatus)
    {
        PRINT_ERR("Failed to stop user process SSL\n");
        status = processStatus;
    }

    qaeMemDestroy();

    return (int)status;
}
