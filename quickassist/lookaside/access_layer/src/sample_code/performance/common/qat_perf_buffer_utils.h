/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *
 ***************************************************************************/

/*
*****************************************************************************
* Doxygen group definitions
****************************************************************************/
/**
*****************************************************************************
* @file qat_perf_buffer_utils.h
*
* @ingroup sample_code
*
* @description
*     This file defines  memory management functions for structures used
*     in the QuickAssist API such as CpaBufferLists, CpaFlatBuffers and other
*     structures
*
*****************************************************************************/
#ifndef CPA_SAMPLE_CODE_BUFFER_UTILS_H
#define CPA_SAMPLE_CODE_BUFFER_UTILS_H

#include "cpa_sample_code_utils_common.h"

#define BYTE_ALIGNMENT_64 (64)
#define PACKET_IMIX (0)
#define BUFFER_SIZE_0 (0)
#define BUFFER_SIZE_32 (32)
#define BUFFER_SIZE_40 (40)
#define BUFFER_SIZE_64 (64)
#define BUFFER_SIZE_128 (128)
#define BUFFER_SIZE_256 (256)
#define BUFFER_SIZE_304 (304)
#define BUFFER_SIZE_320 (320)
#define BUFFER_SIZE_512 (512)
#define BUFFER_SIZE_752 (752)
#define BUFFER_SIZE_768 (768)
#define BUFFER_SIZE_1024 (1024)
#define BUFFER_SIZE_1152 (1152)
#define BUFFER_SIZE_1280 (1280)
#define BUFFER_SIZE_1504 (1504)
#define BUFFER_SIZE_1536 (1536)
#define BUFFER_SIZE_2048 (2048)
#define BUFFER_SIZE_4096 (4096)
#define BUFFER_SIZE_7680 (7680)
#define BUFFER_SIZE_8192 (8192)
#define BUFFER_SIZE_8992 (8992)
#define BUFFER_SIZE_16384 (16384)
#define BUFFER_SIZE_32768 (32768)
#define BUFFER_SIZE_65536 (65536)

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                     allocate the members of a CpaPhysBufferList
*                                  namely:  cpaPhysFlatBuffers, and set the
*                                  number of FlatBuffers for this list
*
* @param[in]   list                CpaPhysBufferList
* @param[in]   node                Numa node to allocate memory on
* @param[in]   numBuffers          Amount of cpaFlatBuffers to be allocated
*                                     to this list
* @param[in]   bufferSize          size of cpaFlatBuffers to be allocated
* @param[in]   alignment           alignment of pBuffer, pMetaData and pData in
*                                  list
*
* @pre                             bufferList is already allocated
*
* @post                            all flatBuffers  allocated. numBuffers is
*                                  set
*
* @retval CPA_STATUS_SUCCESS       Function executed successfully all
*                                  memory was allocated
*
* @retval CPA_STATUS_FAIL          No memory was allocated (any partial
*                                  allocated memory is free before return of
*                                  function
****************************************************************************/
CpaStatus qatAllocateFlatBuffersInDpList(CpaPhysBufferList *list,
                                         Cpa32U node,
                                         Cpa32U numBuffers,
                                         Cpa32U bufferSize,
                                         Cpa32U alignment);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                    free all memory allocated by
*                                 qatAllocatePhysFlatBuffersInPhysList
*
* @param[in]   list               address of bufferList pointer to be freed
*                                 to this list
*
* @pre                            pointer to bufferList is allocated in memory
*
* @post                           all bufferList memory is freed
*
* @retval CPA_STATUS_SUCCESS      all memory free
* @retval CPA_STATUS_FAIL         one or more parts of the list could
*                                      not be freed
*
****************************************************************************/
CpaStatus qatFreeFlatBuffersInDpList(CpaPhysBufferList *list);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                    allocate the members of a CpaBufferList
*                                 namely: cpaFlatBuffers, privateMetaData and
*                                 set the number of FlatBuffers for this list
*
* @param[in]   list                CpaBufferList
* @param[in]   node                Numa node to allocate memory on
* @param[in]   bufferMetaSize      size of private metaData to be allocated
* @param[in]   numBuffers          Amount of cpaFlatBuffers to be allocated
*                                  to this list
* @param[in]   bufferSize          size of cpaFlatBuffers to be allocated
* @param[in]   alignment           alignment of pBuffer, pMetaData and pData in
*                                  list
*
* @pre                             bufferList is already allocated
*
* @post                            all flatBuffers and PrivateMetaData
*                                  allocated. numBuffers is set
*
* @retval CPA_STATUS_SUCCESS       Function executed successfully all
*                                  memory was allocated
*
* @retval CPA_STATUS_FAIL          No memory was allocated (any partial
*                                  allocated memory is free before return of
*                                  function
****************************************************************************/
CpaStatus qatAllocateFlatBuffersInList(CpaBufferList *list,
                                       Cpa32U node,
                                       Cpa32U bufferMetaSize,
                                       Cpa32U numBuffers,
                                       Cpa32U bufferSize,
                                       Cpa32U alignment);
/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                    free all memory allocated by
*                                 qatAllocateFlatBuffersInList
*
* @param[in]   list               address of bufferList pointer to be freed
*                                 to this list
*
* @pre                            pointer to bufferList is allocated in memory
*
* @post                           all bufferList memory is freed
*
* @retval CPA_STATUS_SUCCESS      all memory free
*  @retval CPA_STATUS_FAIL        one or more parts of the list could
*                                      not be freed
*
****************************************************************************/
CpaStatus qatFreeFlatBuffersInList(CpaBufferList *list);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                     print out the contents of the buffer list
*
* @param[in]   list                address of bufferList to be printed
*
* @pre                             pointer to bufferList is allocated in memory
*
* @post                            all list information is printed to the
*                                  console
*
* @retval CPA_STATUS_SUCCESS      this function only returns success
*
****************************************************************************/
CpaStatus qatPrintBuffListDetails(CpaBufferList *list);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                     print out the contents of the flat buffer
*
* @param[in]   list                address of CpaFlatBuffer to be printed
*
* @pre                             pointer to CpaFlatBuffer is allocated in
*                                  memory
*
* @post                            the buffer data is printed to the
*                                  console
*
****************************************************************************/
void qatPrintFlatBuffer(CpaFlatBuffer *flatBuffer);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                     allocate an array of structures, such as
*                                  bufferLists
*
* @param[in]   structureArrayPtr   pointer to pointer of structure to be
*                                  Allocated
* @param[in]   numStructures       number of structures to be allocated
* @param[in]   sizeOfStructure     size of the structure to be allocated
*
* @pre                             pointer to pointer structureArrayPtr is NULL
*
* @post                            an array of structures is allocated or
*                                  otherwise fail status is returned
*
* @retval CPA_STATUS_SUCCESS       array of structures is allocated
* @retval CPA_STATUS_FAIL            could not allocate memory
*
****************************************************************************/
CpaStatus AllocArrayOfStructures(void **structureArrayPtr,
                                 Cpa32U numStructures,
                                 Cpa32U sizeOfStructure);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                     free an array of structures
*
* @param[in]   structureArrayPtr   pointer to pointer of structure to be
*                                         freed
*
* @pre                             pointer to pointer structureArrayPtr is not
*                                  NULL
*
* @post                            an array of structures is freed or
*                                  otherwise fail status is returned
*
* @retval CPA_STATUS_SUCCESS       array of structures is freed
* @retval CPA_STATUS_FAIL          could not free memory
*
****************************************************************************/
CpaStatus FreeArrayOfStructures(void **structureArrayPtr);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                     free all CpaFlatBuffers and privateMetaData
*                                  in an array of lists
*
* @param[in]                       arrayOfBufferLists  pointer to array of
*                                  cpaBufferLists
*
* @pre                             pointer to pointer arrayOfBufferLists is not
*                                  NULL, CpaPhysFlatBuffers has been allocated
*
* @post                            the internals of the CpaBufferLists have
* been freed
*
* @retval CPA_STATUS_SUCCESS       CpaPhysBufferLists is freed
* @retval CPA_STATUS_FAIL          could not free memory
*
****************************************************************************/
CpaStatus qatFreeBuffersInDpLists(CpaPhysBufferList *arrayOfBufferLists,
                                  Cpa32U numberOfLists);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                           allocate all CpaPhysFlatBuffers in an
*                                        array of lists
*
* @param[in]   arrayOfBufferLists        pointer to array of cpaPhysBufferLists
* @param[in]   numberOfLists             number of lists in the array
* @param[in]   numberOfBuffersPerList    number of CpaPhysFlatBuffers to be
*                                          allocated in each list
* @param[in]   testBufferSize            size of each CpaPhysFlatBuffer
*                                        allocated
* @param[in]   node                      CPU node to allocate the memory on
* @param[in]   alignment                 alignment of the memory to allocation
*
* @pre                                   pointer to pointer arrayOfBufferLists
*                                        is not NULL, CpaPhysFlatBuffers has
*                                        not been allocated
*
* @post                                  the internals of the
*                                        CpaPhysBufferLists are allocated
*
* @retval CPA_STATUS_SUCCESS             CpaPhysBufferLists internals are
*                                        allocated
* @retval CPA_STATUS_FAIL                could not allocate memory
*
****************************************************************************/
CpaStatus qatAllocateBuffersInDpLists(CpaPhysBufferList *arrayOfBufferLists,
                                      Cpa32U numberOfLists,
                                      Cpa32U numberOfBuffersPerList,
                                      Cpa32U testBufferSize,
                                      Cpa32U node,
                                      Cpa32U alignment);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                          free all CpaFlatBuffers and
*                                       privateMetaData in an array of lists
*
* @param[in]  arrayOfBufferLists        pointer to array of cpaBufferLists
*
* @pre                                  pointer to pointer arrayOfBufferLists
*                                       is not NULL, CpaFlatBuffers and
*                                       provateMetaData has been allocated
*
* @post                                 the internals of the CpaBufferLists
*                                       have been freed
*
* @retval CPA_STATUS_SUCCESS            CpaBufferLists an privateMetaData is
*                                       freed
* @retval CPA_STATUS_FAIL               could not free memory
*
****************************************************************************/
CpaStatus freeBuffersInLists(CpaBufferList *arrayOfBufferLists,
                             Cpa32U numberOfLists);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                          allocate all CpaFlatBuffers and
*                                       privateMetaData in an array of lists
*
* @param[in]   arrayOfBufferLists       pointer to array of cpaBufferLists
* @param[in]   numberOfLists            number of lists in the array
* @param[in]   numberOfBuffersPerList   number of CpaPhysFlatBuffers to be
*                                       allocated in each list
* @param[in]   testBufferSize           size of each CpaPhysFlatBuffer
*                                       allocated
* @param[in]   additionalBufferSize     additional buffer spaced that needs to
*                                       be allocated to store digest in the case
*                                       of crypto or expansion of data in the
*                                       case of compression of small buffers
* @param[in]   metaSize
* @param[in]   node                     CPU node to allocate the memory on
* @param[in]   alignment                alignment of the memory to allocation
*
* @pre                                  pointer to pointer arrayOfBufferLists
*                                       is not NULL, CpaFlatBuffers and
*                                       privateMetaData has been yet been
*                                       allocated
*
* @post                                 the internals of the CpaBufferLists are
*                                       Allocated
*
* @retval CPA_STATUS_SUCCESS            CpaBufferLists an privateMetaData are
*                                       Allocated
* @retval CPA_STATUS_FAIL               could not free memory
*
****************************************************************************/
CpaStatus AllocateBuffersInLists(CpaBufferList *arrayOfSrcBufferLists,
                                 Cpa32U numberOfLists,
                                 Cpa32U numberOfBuffersPerList,
                                 Cpa32U *testBufferSize,
                                 Cpa32U additionalBufferSize,
                                 Cpa32U metaSize,
                                 Cpa32U node,
                                 Cpa32U alignment);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                          allocate array of packetSizes, to
*                                       support mixing packet sizes
*
* @param[in]   packetSize               sizes to be set in array, when this
*                                       parameter is 0 the array is populated
*                                       with the IMIX
* @param[in]   numberOfLists            numberOfLists to spread the packetSizes
*                                       over
*
* @pre                                  numLists must be a multiple of 20 for
*                                       the IMIX
*
* @post                                 packetSize array is populated with the
*                                       packetSize to be submitted for each
*                                       request
*
* @retval CPA_STATUS_SUCCESS            CpaBufferLists an privateMetaData are
*                                       Allocated
* @retval CPA_STATUS_FAIL               could not free memory
*
****************************************************************************/
CpaStatus allocateAndSetArrayOfPacketSizes(Cpa32U **pPacketSize,
                                           Cpa32U packetSize,
                                           Cpa32U numLists);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                          populate the arrayOfSrcBufferLists with
*                                       data for compression or encryption
*
* @param[in]   packetSize               numberOfLists to be populated
* @param[in]   corpusFilePtr            pointer to corpus file to be copied
*                                       into bufferLists, when this is NULL,
*                                       the buffers are populated with random
*                                       data
* @param[in]  testBufferSize            size of BufferLists to be populated
*
* @pre                                  buffersLists and there respective flat
*                                       buffers must be allocated with enough
*                                       space
*
* @post                                 buffers contain the corpus data or
*                                       random data
*
* @retval CPA_STATUS_SUCCESS            CpaBufferLists are populated
* @retval CPA_STATUS_FAIL               CpaBufferLists could not be populated
*
****************************************************************************/
CpaStatus PopulateBuffers(CpaBufferList *arrayOfSrcBufferLists,
                          Cpa32U numberOfLists,
                          Cpa8U *corpusFilePtr,
                          Cpa32U corpusFileSize,
                          Cpa32U *testBufferSize);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                          copy the contents from 1 bufferList to
*                                       another
*
* @param[in]   srcBufferListArray       source list to be copied
* @param[in]   copyBufferListArray      destination of copied data
* @param[in]   numberOfLists            number of lists to copy
*
* @pre                                  buffersLists and there respective flat
*                                       buffers must be allocated with enough
*                                       space
*
* @post                                 copyBufferListArray is a copy of
*                                       srcBufferListArray
*
* @retval CPA_STATUS_SUCCESS            CpaBufferLists are copied
* @retval CPA_STATUS_FAIL               CpaBufferLists could not be copied
*
****************************************************************************/
CpaStatus copyBuffers(CpaBufferList *srcBufferListArray,
                      CpaBufferList *copyBufferListArray,
                      Cpa32U numberOfLists);

/**
*****************************************************************************
* @file qat_perf_buffer_utils.c
*
* @ingroup sample_code
*
* @description                          convert virtual address of a buffer
*                                       to address that can be accessed by
*                                       the owner of the instance from
*                                       device point of view
*
* @param[in]   pVirtAddr                virtual address of the buffer
* @param[in]   instance                 crypto instance handle
* @param[in]   type                     service type
*
* @retval CpaPhysicalAddr               address from device point of view,
*                                       or NULL if failed to convert
*
****************************************************************************/
CpaPhysicalAddr virtAddrToDevAddr(void *pVirtAddr,
                                  CpaInstanceHandle instance,
                                  CpaAccelerationServiceType type);

#endif /* CPA_SC_BUFFER_UTILS_H*/
