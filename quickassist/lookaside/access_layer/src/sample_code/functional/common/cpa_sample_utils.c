/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file cpa_sample_utils.c
 *
 * @ingroup sampleCode
 *
 * @description
 * Defines functions to get an instance and poll an instance
 *
 ***************************************************************************/

#include "cpa_sample_utils.h"
#include "cpa_dc.h"
#include "cpa_cy_sym.h"
#include "icp_sal_poll.h"

/*
 * Maximum number of instances to query from the API
 */
#ifdef USER_SPACE
#define MAX_INSTANCES 1024
#else
#define MAX_INSTANCES 1
#endif

#define UPPER_HALF_OF_REGISTER 32

#ifdef DO_CRYPTO
static sampleThread gPollingThread;
static volatile int gPollingCy = 0;
#endif

static sampleThread gPollingThreadDc;
static volatile int gPollingDc = 0;

#ifdef SC_ENABLE_DYNAMIC_COMPRESSION
CpaDcHuffType huffmanType_g = CPA_DC_HT_FULL_DYNAMIC;
#else
CpaDcHuffType huffmanType_g = CPA_DC_HT_STATIC;
#endif
/* *************************************************************
 *
 * Common instance functions
 *
 * *************************************************************
 */

/*
 * This function returns a handle to an instance
 * specified by the acceleration service type. It returns the first instance
 * of the desired type.
 */
static void sampleGetInstance(CpaAccelerationServiceType accelSrvType,
                              CpaInstanceHandle *pInstHandle)
{
    CpaInstanceHandle instHandles[MAX_INSTANCES];
    Cpa16U numInstances = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    *pInstHandle = NULL;
    status = cpaGetNumInstances(accelSrvType, &numInstances);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Error while getting number of instances.\n");
        return;
    }

#ifdef DO_CRYPTO
    /*
     * Try to get specific crypto instance type
     * if not found try to get generic legacy crypto instance.
     */
    if (0 == numInstances && (accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO_SYM ||
                              accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO_ASYM))
    {
        accelSrvType = CPA_ACC_SVC_TYPE_CRYPTO;
        status = cpaGetNumInstances(accelSrvType, &numInstances);
        if (status != CPA_STATUS_SUCCESS)
        {
            PRINT_ERR("Error while getting number of instances.\n");
            return;
        }
    }
#endif
    if (numInstances > MAX_INSTANCES)
    {
        numInstances = MAX_INSTANCES;
    }
    if (0 == numInstances)
    {
        PRINT_ERR(
            "No %s instance found.\n",
            accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO_SYM    ? "symmetric crypto"
            : accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO_ASYM ? "asymmetric crypto"
            : accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO      ? "crypto"
            : accelSrvType == CPA_ACC_SVC_TYPE_DATA_COMPRESSION
                ? "data compression"
            : accelSrvType == CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION
                ? "data decompression"
                : "unknown");
        return;
    }
    if (status == CPA_STATUS_SUCCESS)
    {
        status = cpaGetInstances(accelSrvType, numInstances, instHandles);
        if (status == CPA_STATUS_SUCCESS)
            *pInstHandle = instHandles[0];
    }
    else
    {
        PRINT_ERR(
            "Error while getting %s instance.\n",
            accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO_SYM    ? "symmetric crypto"
            : accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO_ASYM ? "asymmetric crypto"
            : accelSrvType == CPA_ACC_SVC_TYPE_CRYPTO      ? "crypto"
            : accelSrvType == CPA_ACC_SVC_TYPE_DATA_COMPRESSION
                ? "data compression"
            : accelSrvType == CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION
                ? "data decompression"
                : "unknown");
        return;
    }
}

#ifdef DO_CRYPTO
void sampleSymGetInstance(CpaInstanceHandle *pSymInstHandle)
{
    sampleGetInstance(CPA_ACC_SVC_TYPE_CRYPTO_SYM, pSymInstHandle);
}

void sampleAsymGetInstance(CpaInstanceHandle *pAsymInstHandle)
{
    sampleGetInstance(CPA_ACC_SVC_TYPE_CRYPTO_ASYM, pAsymInstHandle);
}

void sampleCyGetInstance(CpaInstanceHandle *pCyInstHandle)
{
    sampleGetInstance(CPA_ACC_SVC_TYPE_CRYPTO, pCyInstHandle);
}

void symSessionWaitForInflightReq(CpaCySymSessionCtx pSessionCtx)
{

/* Session reuse is available since Cryptographic API version 2.2 */
#if CY_API_VERSION_AT_LEAST(2, 2)
    CpaBoolean sessionInUse = CPA_FALSE;

    do
    {
        cpaCySymSessionInUse(pSessionCtx, &sessionInUse);
    } while (sessionInUse);
#endif

    return;
}
#endif

/*
 * This function polls a crypto instance.
 *
 */
#ifdef DO_CRYPTO
static void sal_polling(CpaInstanceHandle cyInstHandle)
{
    gPollingCy = 1;
    while (gPollingCy)
    {
        icp_sal_CyPollInstance(cyInstHandle, 0);
        OS_SLEEP(10);
    }

    sampleThreadExit();
}
#endif
/*
 * This function checks the instance info. If the instance is
 * required to be polled then it starts a polling thread.
 */

#ifdef DO_CRYPTO
void sampleCyStartPolling(CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 info2 = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaCyInstanceGetInfo2(cyInstHandle, &info2);
    if ((status == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE))
    {
        /* Start thread to poll instance */
        sampleThreadCreate(
            &gPollingThread, sal_polling, cyInstHandle, CPA_TRUE);
    }
}
#endif
/*
 * This function stops the polling of a crypto instance.
 */
#ifdef DO_CRYPTO
void sampleCyStopPolling(void)
{
    gPollingCy = 0;
    OS_SLEEP(10);
}
#endif

void sampleDcGetInstance(CpaInstanceHandle *pDcInstHandle)
{
    sampleGetInstance(CPA_ACC_SVC_TYPE_DATA_COMPRESSION, pDcInstHandle);
}

void sampleDecompGetInstance(CpaInstanceHandle *pDecompInstHandle)
{
    sampleGetInstance(CPA_ACC_SVC_TYPE_DATA_DECOMPRESSION, pDecompInstHandle);
}

/*
 * This function polls a compression instance.
 *
 */
static void sal_dc_polling(CpaInstanceHandle dcInstHandle)
{

    gPollingDc = 1;
    while (gPollingDc)
    {
        icp_sal_DcPollInstance(dcInstHandle, 0);
        OS_SLEEP(10);
    }

    sampleThreadExit();
}

/*
 * This function checks the instance info. If the instance is
 * required to be polled then it starts a polling thread.
 */
void sampleDcStartPolling(CpaInstanceHandle dcInstHandle)
{
    CpaInstanceInfo2 info2 = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaDcInstanceGetInfo2(dcInstHandle, &info2);
    if ((status == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE))
    {
        /* Start thread to poll instance */
        sampleThreadCreate(
            &gPollingThreadDc, sal_dc_polling, dcInstHandle, CPA_TRUE);
    }
}

/*
 * This function stops the thread polling the compression instance.
 */
void sampleDcStopPolling(void)
{
    gPollingDc = 0;
    OS_SLEEP(10);
}

/*
 * This function reads the value of Time Stamp Counter (TSC) and
 * returns a 64-bit value.
 */
Cpa64U sampleCoderdtsc(void)
{
    volatile unsigned long a, d;

    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (((Cpa64U)a) | (((Cpa64U)d) << UPPER_HALF_OF_REGISTER));
}

/*
 * This function prints out a hexadecimal representation of bytes.
 */
void hexLog(Cpa8U *pData, Cpa32U numBytes, const char *caption)
{
    int i = 0;

    if (NULL == pData)
    {
        return;
    }

    if (caption != NULL)
    {
        PRINT("\n=== %s ===\n", caption);
    }

    for (i = 0; i < numBytes; i++)
    {
        PRINT("%02X ", pData[i]);

        if (!((i + 1) % 12))
            PRINT("\n");
    }
    PRINT("\n");
}

CpaPhysicalAddr virtAddrToDevAddr(void *pVirtAddr,
                                  CpaInstanceHandle instanceHandle,
                                  CpaAccelerationServiceType type)
{
    CpaStatus status;
    CpaInstanceInfo2 instanceInfo = { 0 };

    /* Get the address translation mode */
    switch (type)
    {
#ifdef DO_CRYPTO
        case CPA_ACC_SVC_TYPE_CRYPTO:
            status = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo);
            break;
#endif
        case CPA_ACC_SVC_TYPE_DATA_COMPRESSION:
            status = cpaDcInstanceGetInfo2(instanceHandle, &instanceInfo);
            break;
        default:
            status = CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_STATUS_SUCCESS != status)
    {
        return (CpaPhysicalAddr)(uintptr_t)NULL;
    }

    if (instanceInfo.requiresPhysicallyContiguousMemory)
    {
        return sampleVirtToPhys(pVirtAddr);
    }
    else
    {
        return (CpaPhysicalAddr)(uintptr_t)pVirtAddr;
    }
}

#ifdef USER_SPACE
/*
 * This function copies a file to memory
 */
CpaStatus sample_getFile(const char *filename, file_data_t *file_data)
{
    FILE *srcFile = NULL;
    Cpa8U *pBuff = NULL;
    struct stat st = { 0 };
    long file_size = 0;
    int fd = -1;

    /* Validate input parameters */
    if (NULL == filename || NULL == file_data || NULL == file_data->pSrcData ||
        NULL == file_data->bufferSize)
    {
        PRINT_ERR("Invalid NULL parameter passed to sample_getFile\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        PRINT_ERR("Could not open file %s\n", filename);
        return CPA_STATUS_FAIL;
    }

    /* Get filesize using fstat on the opened file descriptor */
    if (0 != fstat(fd, &st))
    {
        PRINT_ERR("Could not get the file %s size\n", filename);
        close(fd);
        return CPA_STATUS_FAIL;
    }
    file_size = st.st_size;

    /* Validate file size is non-negative and reasonable */
    if (file_size <= 0)
    {
        PRINT_ERR("Invalid file size for %s\n", filename);
        close(fd);
        return CPA_STATUS_FAIL;
    }

    /* Allocate memory for the file */
    pBuff = (Cpa8U *)qaeMemAlloc(file_size);
    if (NULL == pBuff)
    {
        PRINT_ERR("Could not allocate memory for the file copy\n");
        close(fd);
        return CPA_STATUS_FAIL;
    }

    memset(pBuff, 0, file_size);
    /* Convert file descriptor to FILE* stream */
    srcFile = fdopen(fd, "r");
    if (NULL == srcFile)
    {
        PRINT_ERR("Could not create file stream for %s\n", filename);
        qaeMemFree((void **)&pBuff);
        close(fd);
        return CPA_STATUS_FAIL;
    }

    /* Read the file */
    *(file_data->bufferSize) = fread(pBuff, 1, file_size, srcFile);
    if (*(file_data->bufferSize) != file_size)
    {
        PRINT_ERR("Filesize doesn't match\n");
        qaeMemFree((void **)&pBuff);
        fclose(srcFile);
        return CPA_STATUS_FAIL;
    }

    /* fclose also closes the underlying file descriptor */
    fclose(srcFile);
    *(file_data->pSrcData) = pBuff;
    return CPA_STATUS_SUCCESS;
}

/* Free the memory after getting the file and copying the data */
CpaStatus sample_freeFile(file_data_t *file_data)
{
    qaeMemFree((void **)(file_data->pSrcData));
    return CPA_STATUS_SUCCESS;
}

CpaStatus sample_getPath(char *filePath, char *fileName)
{
    Cpa32S strSize = 0;

    if (filePath == NULL || fileName == NULL)
    {
        PRINT_ERR("Invalid input: filePath or fileName is NULL\n");
        return CPA_STATUS_FAIL;
    }

    memset(filePath, 0, MAX_CORPUS_FILE_PATH_LEN);

    strSize = snprintf(filePath,
                       MAX_CORPUS_FILE_PATH_LEN,
                       "%s%s",
                       SAMPLE_CODE_CORPUS_PATH,
                       fileName);

    if (strSize < 0 || strSize > MAX_CORPUS_FILE_PATH_LEN)
    {
        PRINT("Error creating file path, incorrect path length: %s\n",
              filePath);
        return CPA_STATUS_FAIL;
    }

    if (access(filePath, F_OK) != 0)
    {
        PRINT("Could not open corpus file: %s\n", filePath);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

#endif
