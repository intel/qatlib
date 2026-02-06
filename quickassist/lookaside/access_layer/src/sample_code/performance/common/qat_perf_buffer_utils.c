/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#include "qat_perf_buffer_utils.h"
#include "cpa_cy_common.h"
#include "cpa_dc.h"

CpaStatus qatAllocateFlatBuffersInDpList(CpaPhysBufferList *list,
                                         Cpa32U node,
                                         Cpa32U numBuffers,
                                         Cpa32U bufferSize,
                                         Cpa32U alignment)
{
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;

    /* return fail if list is null*/
    if (list == NULL)
    {
        PRINT_ERR("bufferList is null");
        return CPA_STATUS_FAIL;
    }

    list->numBuffers = numBuffers;
    if (allocationStatus == CPA_STATUS_SUCCESS)
    {
        for (i = 0; i < numBuffers; i++)
        {
            /*this allocates a virtual ptr to physically contiguous memory.
             * Before being assigned to were its used it must be converted
             * to a physical address ptr using virt2phys conversion function*/
            list->flatBuffers[i].bufferPhysAddr = (CpaPhysicalAddr)(
                uintptr_t)qaeMemAllocNUMA(bufferSize, node, alignment);
            if (NULL == (void *)(uintptr_t)list->flatBuffers[i].bufferPhysAddr)
            {
                PRINT_ERR("pBuffers[%u].pData allocation failed\n", i);
                allocationStatus = CPA_STATUS_FAIL;
                break;
            }
            list->flatBuffers[i].dataLenInBytes = bufferSize;
        }
    }

    // not able to allocate all memory, so free any that was allocated
    if (allocationStatus == CPA_STATUS_FAIL)
    {
        qatFreeFlatBuffersInDpList(list);
    }
    return allocationStatus;
}

CpaStatus qatFreeFlatBuffersInDpList(CpaPhysBufferList *list)
{
    Cpa32U i = 0;
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;

    if (NULL == list)
    {
        PRINT_ERR("Cannot de-allocate: BufferList not allocated\n");
        allocationStatus = CPA_STATUS_FAIL;
    }
    else
    {
        for (i = 0; i < list->numBuffers; i++)
        {
            if (NULL != (void *)(uintptr_t)list->flatBuffers[i].bufferPhysAddr)
            {
                qaeMemFreeNUMA((void **)&(list->flatBuffers[i].bufferPhysAddr));
                if (NULL !=
                    (void *)(uintptr_t)list->flatBuffers[i].bufferPhysAddr)
                {
                    PRINT("could not free pBuffers[%u].pData\n", i);
                    allocationStatus = CPA_STATUS_FAIL;
                }
            }
            else
            {
                PRINT_ERR("pBuffers[%u].pData is already null\n", i);
                allocationStatus = CPA_STATUS_FAIL;
            }
        }
    }
    return allocationStatus;
}

CpaStatus qatAllocateFlatBuffersInList(CpaBufferList *list,
                                       Cpa32U node,
                                       Cpa32U bufferMetaSize,
                                       Cpa32U numBuffers,
                                       Cpa32U bufferSize,
                                       Cpa32U alignment)
{
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;

    /* return fail if list is null*/
    if (list == NULL)
    {
        PRINT_ERR("bufferList is null");
        return CPA_STATUS_FAIL;
    }

    list->pPrivateMetaData = qaeMemAllocNUMA(bufferMetaSize, node, alignment);
    if (NULL == list->pPrivateMetaData)
    {
        PRINT_ERR("pPrivateMetaData allocation failed\n");
        allocationStatus = CPA_STATUS_FAIL;
    }
    if (allocationStatus == CPA_STATUS_SUCCESS)
    {
        list->numBuffers = numBuffers;
        list->pBuffers = qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * numBuffers, node, alignment);
        if (NULL == list->pBuffers)
        {
            PRINT_ERR("pBuffers allocation failed\n");
            allocationStatus = CPA_STATUS_FAIL;
        }
    }
    if (allocationStatus == CPA_STATUS_SUCCESS)
    {
        for (i = 0; i < numBuffers; i++)
        {
            list->pBuffers[i].pData =
                qaeMemAllocNUMA(bufferSize, node, alignment);
            if (NULL == list->pBuffers[i].pData)
            {
                PRINT_ERR("pBuffers[%u].pData allocation failed\n", i);
                allocationStatus = CPA_STATUS_FAIL;
                break;
            }
            list->pBuffers[i].dataLenInBytes = bufferSize;
        }
    }

    // not able to allocate all memory, so free any that was allocated
    if (allocationStatus == CPA_STATUS_FAIL)
    {
        qatFreeFlatBuffersInList(list);
    }
    return allocationStatus;
}

CpaStatus qatFreeFlatBuffersInList(CpaBufferList *list)
{
    Cpa32U i = 0;
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;

    if (NULL == list)
    {
        PRINT_ERR("Cannot de-allocate: BufferList not allocated\n");
        allocationStatus = CPA_STATUS_FAIL;
    }
    else
    {
        for (i = 0; i < list->numBuffers; i++)
        {
            if ((NULL != list->pBuffers) && (NULL != list->pBuffers[i].pData))
            {
                qaeMemFreeNUMA((void **)&(list->pBuffers[i].pData));
                if (NULL != list->pBuffers[i].pData)
                {
                    PRINT("could not free pBuffers[%u].pData\n", i);
                    allocationStatus = CPA_STATUS_FAIL;
                }
            }
            else
            {
                PRINT_ERR("pBuffers[%u].pData is already null\n", i);
                allocationStatus = CPA_STATUS_FAIL;
            }
        }
        qaeMemFreeNUMA((void **)&(list->pBuffers));
        if (NULL != list->pBuffers)
        {
            PRINT("could not free pBuffers\n");
            allocationStatus = CPA_STATUS_FAIL;
        }
        if (NULL != list->pPrivateMetaData)
        {
            qaeMemFreeNUMA((void **)&(list->pPrivateMetaData));
            if (NULL != list->pPrivateMetaData)
            {
                PRINT_ERR("could not free privateMetaData\n");
                allocationStatus = CPA_STATUS_FAIL;
            }
        }
    }
    return allocationStatus;
}

CpaStatus qatPrintBuffListDetails(CpaBufferList *list)
{
    Cpa32U i = 0;

    if (NULL != list)
    {
        PRINT("Addr %p, ", list);
        PRINT("numBuffers %u, ", list->numBuffers);
        PRINT("PrivateMetaData %p, ", (void *)list->pPrivateMetaData);
        PRINT("pBuffer addr: %p, ", list->pBuffers);
        if (NULL != list->pBuffers)
        {
            for (i = 0; i < list->numBuffers; i++)
            {
                if (NULL != list->pBuffers[i].pData)
                {
                    PRINT(
                        "pBuffer[%u].pData = %p, ", i, list->pBuffers[i].pData);
                    PRINT("pBuffer[%u].dataLenInBytes = %u, ",
                          i,
                          list->pBuffers[i].dataLenInBytes);
                }
            }
        }
        PRINT("\n");
    }
    else
    {
        PRINT("BufferList not allocated\n");
    }
    return CPA_STATUS_SUCCESS;
}

void qatPrintFlatBuffer(CpaFlatBuffer *flatBuffer)
{
    Cpa32U i = 0;
    if (NULL != flatBuffer)
    {
        for (i = 0; i < flatBuffer->dataLenInBytes; i++)
        {
            PRINT("%02x", flatBuffer->pData[i]);
            if (((i + 1) % 16) == 0)
            {
                PRINT("\n");
            }
            else
            {
                PRINT(" ");
            }
            if (((i + 1) % 8) == 0 && ((i + 1) % 16) != 0)
            {
                PRINT("- ");
            }
        }
        PRINT("\n");
    }
    else
    {
        PRINT("CpaFlatBuffer not allocated\n");
    }
    return;
}

CpaStatus AllocArrayOfStructures(void **structureArrayPtr,
                                 Cpa32U numStructures,
                                 Cpa32U sizeOfStructure)
{
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;
    Cpa64U *ptr = (Cpa64U *)*structureArrayPtr;

    if (ptr != NULL || numStructures == 0 || sizeOfStructure == 0)
    {
        PRINT_ERR("Invalid parameter passed into AllocArrayOfStructures\n");
        PRINT_ERR("arrayPtr %p, numStructures %d, sizeOfStructure %d\n",
                  ptr,
                  numStructures,
                  sizeOfStructure);
        allocationStatus = CPA_STATUS_FAIL;
    }
    else
    {
        *structureArrayPtr =
            qaeMemAlloc((size_t)sizeOfStructure * numStructures);
        if (*structureArrayPtr == NULL)
        {
            allocationStatus = CPA_STATUS_FAIL;
        }
        else
        {
            memset(
                *structureArrayPtr, 0, (size_t)sizeOfStructure * numStructures);
        }
    }
    return allocationStatus;
}

CpaStatus FreeArrayOfStructures(void **structureArrayPtr)
{
    CpaStatus freeStatus = CPA_STATUS_SUCCESS;

    if (structureArrayPtr == NULL)
    {
        PRINT_ERR("Cannot de-allocate: BufferList not allocated\n");
        freeStatus = CPA_STATUS_FAIL;
    }
    else
    {
        qaeMemFree(structureArrayPtr);
        if (NULL != *structureArrayPtr)
        {
            PRINT_ERR("could not free structure\n");
            freeStatus = CPA_STATUS_FAIL;
        }
    }
    return freeStatus;
}

CpaStatus qatAllocateBuffersInDpLists(CpaPhysBufferList *arrayOfBufferLists,
                                      Cpa32U numberOfLists,
                                      Cpa32U numberOfBuffersPerList,
                                      Cpa32U testBufferSize,
                                      Cpa32U node,
                                      Cpa32U alignment)
{
    Cpa32U i = 0;
    Cpa32U j = 0;
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;

    for (i = 0; i < numberOfLists; i++)
    {
        allocationStatus =
            qatAllocateFlatBuffersInDpList(&arrayOfBufferLists[i],
                                           node,
                                           numberOfBuffersPerList,
                                           testBufferSize,
                                           alignment);
        if (allocationStatus == CPA_STATUS_FAIL)
        {
            /*need to free any list that has already been successfully
             * allocated*/
            for (j = i; j > 0; j--)
            {
                qatFreeFlatBuffersInDpList(&arrayOfBufferLists[j-1]);
            }
            break;
        }
    }
    return allocationStatus;
}

CpaStatus qatFreeBuffersInDpLists(CpaPhysBufferList *arrayOfBufferLists,
                                  Cpa32U numberOfLists)
{
    Cpa32U counter = 0;
    CpaStatus freeStatus = CPA_STATUS_SUCCESS;

    for (counter = 0; counter < numberOfLists; counter++)
    {
        /*attempt to free all lists and capture any failed return status*/
        if (CPA_STATUS_SUCCESS !=
            qatFreeFlatBuffersInDpList(&arrayOfBufferLists[counter]))
        {
            freeStatus = CPA_STATUS_FAIL;
        }
    }
    return freeStatus;
}

CpaStatus freeBuffersInLists(CpaBufferList *arrayOfBufferLists,
                             Cpa32U numberOfLists)
{
    Cpa32U counter = 0;
    CpaStatus freeStatus = CPA_STATUS_SUCCESS;

    for (counter = 0; counter < numberOfLists; counter++)
    {
        /*attempt to free all lists and capture any failed return status*/
        if (CPA_STATUS_SUCCESS !=
            qatFreeFlatBuffersInList(&arrayOfBufferLists[counter]))
        {
            freeStatus = CPA_STATUS_FAIL;
        }
    }
    return freeStatus;
}

CpaStatus AllocateBuffersInLists(CpaBufferList *arrayOfBufferLists,
                                 Cpa32U numberOfLists,
                                 Cpa32U numberOfBuffersPerList,
                                 Cpa32U *testBufferSize,
                                 Cpa32U additionalBufferSize,
                                 Cpa32U metaSize,
                                 Cpa32U node,
                                 Cpa32U alignment)
{
    Cpa32U i = 0;
    Cpa32U j = 0;
    CpaStatus allocationStatus = CPA_STATUS_SUCCESS;

    for (i = 0; i < numberOfLists; i++)
    {
        allocationStatus = qatAllocateFlatBuffersInList(
            &arrayOfBufferLists[i],
            node,
            metaSize,
            numberOfBuffersPerList,
            testBufferSize[i] + additionalBufferSize,
            alignment);
        if (allocationStatus == CPA_STATUS_FAIL)
        {
            /*need to free any list that has already been successfully
             * allocated*/
            for (j = i; j > 0; j--)
            {
                qatFreeFlatBuffersInList(&arrayOfBufferLists[j-1]);
            }
            break;
        }
    }
    return allocationStatus;
}

CpaStatus allocateAndSetArrayOfPacketSizes(Cpa32U **pPacketSize,
                                           Cpa32U packetSize,
                                           Cpa32U numLists)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U packetMix[] = {
        BUFFER_SIZE_64,   BUFFER_SIZE_752,  BUFFER_SIZE_1504, BUFFER_SIZE_64,
        BUFFER_SIZE_752,  BUFFER_SIZE_1504, BUFFER_SIZE_64,   BUFFER_SIZE_64,
        BUFFER_SIZE_1504, BUFFER_SIZE_1504, BUFFER_SIZE_752,  BUFFER_SIZE_64,
        BUFFER_SIZE_752,  BUFFER_SIZE_64,   BUFFER_SIZE_1504, BUFFER_SIZE_1504,
        BUFFER_SIZE_64,   BUFFER_SIZE_8992, BUFFER_SIZE_64,   BUFFER_SIZE_1504};
    Cpa32U mixIndex = sizeof(packetMix) / sizeof(Cpa32U);

    *pPacketSize = qaeMemAlloc(sizeof(Cpa32U) * numLists);
    if (NULL == *pPacketSize)
    {
        PRINT_ERR("Could not allocate memory for pPacketSize\n");
        status = CPA_STATUS_FAIL;
    }
    else
    {
        if (packetSize == PACKET_IMIX)
        {
            /*we are testing IMIX so we copy buffer sizes from pre-allocated
             * array into symTestSetup.numBuffLists*/
            for (i = 0; i < numLists; i++)
            {
                (*pPacketSize)[i] = packetMix[i % mixIndex];
            }
        }
        else
        {
            /*we are testing a uniform bufferSize, so we set the bufferSize
             * array accordingly*/
            for (i = 0; i < numLists; i++)
            {
                (*pPacketSize)[i] = packetSize;
            }
        }
    }
    return status;
}

/*copy the corpus that was read from file into memory in the setupScDcTest
 * function, into the CpaFlatBuffers that have been allocated*/
CpaStatus PopulateBuffers(CpaBufferList *arrayOfSrcBufferLists,
                          Cpa32U numberOfLists,
                          Cpa8U *corpusFilePtr,
                          Cpa32U corpusFileSize,
                          Cpa32U *testBufferSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *filePtr = NULL;
    Cpa32U copiedLen = 0;
    Cpa32U i = 0;
    filePtr = corpusFilePtr;

    /* Copy the data into Flat buffers */
    for (i = 0; i < numberOfLists; i++)
    {
        if (arrayOfSrcBufferLists[i].pBuffers->pData == NULL)
        {
            PRINT_ERR("cannot copy to NULL ptr in pData\n");
            return CPA_STATUS_FAIL;
        }

        if (corpusFilePtr == NULL)
        {
            generateRandomData(arrayOfSrcBufferLists[i].pBuffers->pData,
                               testBufferSize[i]);
        }
        else
        {
            if ((corpusFileSize < testBufferSize[i]) ||
                ((corpusFileSize - copiedLen) < testBufferSize[i]))
            {
                memcpy((arrayOfSrcBufferLists[i].pBuffers->pData),
                       filePtr,
                       (corpusFileSize - copiedLen));
                continue;
            }
            memcpy((arrayOfSrcBufferLists[i].pBuffers->pData),
                   filePtr,
                   testBufferSize[i]);
            filePtr += testBufferSize[i];
            copiedLen += testBufferSize[i];
        }
    }

    return status;
}

CpaStatus copyBuffers(CpaBufferList *srcBufferListArray,
                      CpaBufferList *copyBufferListArray,
                      Cpa32U numberOfLists)
{
    Cpa32U j = 0;
    for (j = 0; j < numberOfLists; j++)
    {
        memcpy((copyBufferListArray[j].pBuffers->pData),
               srcBufferListArray[j].pBuffers->pData,
               srcBufferListArray[j].pBuffers->dataLenInBytes);
    }

    return CPA_STATUS_SUCCESS;
}

CpaPhysicalAddr virtAddrToDevAddr(void *pVirtAddr,
                                  CpaInstanceHandle instanceHandle,
                                  CpaAccelerationServiceType type)
{
    CpaStatus status;
    CpaInstanceInfo2 instanceInfo = {0};

    /*get the addressTranslation mode*/
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
        return qaeVirtToPhysNUMA(pVirtAddr);
    }
    else
    {
        return (CpaPhysicalAddr)(uintptr_t)pVirtAddr;
    }
}
