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
 * @file  cpa_hash_file_sample_user.c
 *
 *****************************************************************************/
#include <limits.h>
#include <unistd.h>
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"

char *gFileName = NULL;

extern CpaStatus hashFileSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;
    char fileToHash[PATH_MAX] = {0};
    size_t fileToHashLen;

    fileToHashLen = readlink("/proc/self/exe", fileToHash, sizeof(fileToHash));

    /* Read in debug setting if present */
    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    PRINT_DBG("Starting Hash File Sample Code App ...\n");

    if (fileToHashLen <= 0)
    {
        PRINT_ERR("Failed to get path to binary to hash\n");
        return (int)CPA_STATUS_FAIL;
    }
    gFileName = fileToHash;

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

    stat = hashFileSample();
    if (CPA_STATUS_SUCCESS != stat)
    {
        PRINT_ERR("\nHash File Sample Code App failed\n");
    }
    else
    {
        PRINT_DBG("\nHash File Sample Code App finished\n");
    }

    icp_sal_userStop();
    qaeMemDestroy();
    gFileName = NULL;

    return (int)stat;
}
