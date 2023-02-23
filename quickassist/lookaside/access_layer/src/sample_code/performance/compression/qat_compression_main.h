/****************************************************************************
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

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *      These functions specify the API for compression performance code
 *
 * @remarks
 *
 *
 *****************************************************************************/

#ifndef QAT_COMPRESSION_MAIN
#define QAT_COMPRESSION_MAIN

#define QAT_COMP_MIN_LOOPS_FOR_SLEEP_CONTROL (50)
#define QAT_COMP_DEFAULT_COMP_RATE (100)
#define QAT_COMP_SCALING_FACTOR (1000)
#define QAT_COMP_MIN_PACKET_SIZE (1024)
#define QAT_COMP_LOW_SLEEPTIME_STATING_VALUE (2048)
#define QAT_COMP_HIGH_SLEEPTIME_STATING_VALUE (32768)
#define QAT_COMP_DEFAULT_SLEEPTIME_STARTING_VALUE (2)
#define QAT_COMP_FIVE_PERCENT (50)
#define QAT_COMP_THREE_PERCENT (30)
#define QAT_COMP_ONE_POINT_FIVE_PERCENT (15)
#define QAT_COMP_POINT_SIX_PERCENT (6)
#define QAT_COMP_PACKET_SIZE_8K (8192)
#define QAT_COMP_SLEEP_INTERVAL (100000)
#define QAT_COMP_DUMP_MAX_FILE_NAME_LEGNTH (512)
#define QAT_COMP_DUMP_BUFFER_SIZE (1024)

#include "cpa.h"
#include "cpa_dc.h"
#include "cpa_dc_dp.h"
#include "qat_perf_utils.h"
#include "cpa_sample_code_dc_utils.h"
#include "qat_compression_zlib.h"
#include "qat_perf_latency.h"
#include "qat_perf_buffer_utils.h"
#include "icp_sal_poll.h"

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         free the memory used to store a list of CpaBufferLists
 *
 * @param[in]   setup               pointer to the compression setup
 *                                  structure that the list was setup with
 * @param[in]   srcBufferListArray  array of CpaBufferLists to be freed
 * @param[in]   destBufferListArray array of CpaBufferLists to be freed
 * @param[in]   resultArray         array of cpaDcResults  to be freed
 *
 *     @pre                         all these structures are already
 *                                  allocated
 *
 *     @post                        all memory is freed
 *
 *     @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL      some of the memory could not be freed
 ****************************************************************************/
CpaStatus qatFreeCompressionLists(compression_test_params_t *setup,
                                  CpaBufferList **srcBufferListArray,
                                  CpaBufferList **destBufferListArray,
                                  CpaBufferList **cpmBufferListArray,
                                  CpaDcRqResults **resultArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         Perform checksum validation. Compare H/W checksum in results
 *         structure with S/W checksum calculated in the function.
 *
 * @param[in]   setup               pointer to the compression setup
 *                                  structure that the list was setup with
 * @param[in]   srcBufferListArray  array of CpaBufferLists to calculate
                                    S/W checksum
 * @param[in]   resultArray         array of cpaDcResults for H/W checksum
 * @param[in]   listNum             Total number of Buffer lists
 * @param[in]   compressDirection   Compression Direction
 *
 *     @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL      Checksum values does not match
 ****************************************************************************/
CpaStatus qatCompressionValidateChecksum(compression_test_params_t *setup,
                                         CpaDcRqResults *arrayOfResults,
                                         CpaBufferList *arrayOfSrcBufferLists,
                                         Cpa32U listNum,
                                         CpaDcSessionDir compressDirection);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         This API is added to perform overflow validation of the
 *         compression request. With the use of Compress Bound API to get
 *         the destination buffer size for compression request, it is expected
 *         that all the input data will be consumed successfully and there
 should
 *         not be any overflow case. Overflow is considered as Failed result.
 *
 * @param[in]   setup               pointer to the compression setup
 *                                  structure that the list was setup with
 * @param[in]   srcBufferListArray  array of CpaBufferLists to check
                                    totak input data size
 * @param[in]   resultArray         array of cpaDcResults for consumed bytes
 * @param[in]   listNum             Total number of Buffer lists
 *
 *     @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL      Overflow is observed
 ****************************************************************************/
CpaStatus qatCompressionVerifyOverflow(compression_test_params_t *setup,
                                       CpaDcRqResults *arrayOfResults,
                                       CpaBufferList *arrayOfSrcBufferLists,
                                       Cpa32U listNum);
#ifdef SC_CHAINING_ENABLED
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         free the DcChain memory used to store a list of CpaBufferLists
 *
 * @param[in]   chainResultArray    array of CpaDcChainRqResults  to be freed
 * @param[in]   chainOpDataArray    array of CpaDcChainOpData  to be freed
 *
 *     @pre                         all these structures are already
 *                                  allocated
 *
 *     @post                        all memory is freed
 *
 *     @retval CPA_STATUS_SUCCESS   Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL      some of the memory could not be freed
 ****************************************************************************/
CpaStatus qatFreeDcChainLists(void **chainResultArray,
                              CpaDcChainOpData **chainOpDataArray);

#endif
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         allocate the memory used to store a list of CpaBufferLists
 *
 * @param[in]   setup                pointer to the compression setup structure
 * @param[in]   srcBufferListArray   array of CpaBufferLists to be allocated
 * @param[in]   destBufferListArray  array of CpaBufferLists to be allocated
 * @param[in]   resultArray          array of cpaDcResults  to be allocated
 *
 *     @pre                          none
 *
 *     @post                         all memory is allocated
 *
 *     @retval CPA_STATUS_SUCCESS    Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL       some of the memory could not be
 *                                   allocated
 ****************************************************************************/
CpaStatus qatAllocateCompressionLists(compression_test_params_t *setup,
                                      CpaBufferList **srcBufferListArray,
                                      CpaBufferList **destBufferListArray,
                                      CpaBufferList **cpmBufferListArray,
                                      CpaDcRqResults **resultArray);

#ifdef SC_CHAINING_ENABLED
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         allocate the memory used to store a list of DcChain BufferLists
 *
 * @param[in]   setup                pointer to the compression setup structure
 * @param[in]   chainResultArray     array of CpaDcChainRqResults  to be
 *allocated
 * @param[in]   chainOpDataArray     array of CpaDcChainOpData  to be allocated
 *
 *     @pre                          none
 *
 *     @post                         all memory is allocated
 *
 *     @retval CPA_STATUS_SUCCESS    Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL       some of the memory could not be
 *                                   allocated
 ****************************************************************************/
CpaStatus qatAllocateDcChainLists(compression_test_params_t *setup,
                                  void **chainResultArray,
                                  CpaDcChainOpData **chainOpDataArray);
#endif

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         allocate the CpaFlatBuffers and members of the CpaBufferLists
 *
 * @param[in]   setup                 pointer to the compression setup
 *                                    structure
 * @param[in]   srcBufferListArray    array of CpaBufferLists to be allocated
 * @param[in]   numBuffersInSrcList   number of CpaFlatBuffers to be allocated
 *                                     in srcBufferListArray
 * @param[in]   sizeOfBuffersInSrcList  size of CpaBufferLists to be allocated
 *                                      in srcBufferLists
 * @param[in]   destBufferListArray     array of CpaBufferLists to be allocated
 * @param[in]   numBuffersInDstList     number of CpaFlatBuffers to be allocated
 *                                      in dstBufferListArray
 * @param[in]   sizeOfBuffersInDestList size of CpaBufferLists to be allocated
 *                                      in destBufferLists
 *
 *     @pre                             none
 *
 *     @post                            all memory is allocated
 *
 *     @retval CPA_STATUS_SUCCESS       Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL          some of the memory could not be
 *                                      allocated
 ****************************************************************************/
CpaStatus qatAllocateCompressionFlatBuffers(compression_test_params_t *setup,
                                            CpaBufferList *srcBufferListArray,
                                            Cpa32U numBuffersInSrcList,
                                            Cpa32U *sizeOfBuffersInSrcList,
                                            CpaBufferList *destBufferListArray,
                                            Cpa32U numBuffersInDstList,
                                            Cpa32U *sizeOfBuffersInDstList,
                                            CpaBufferList *cpmBufferListArray,
                                            Cpa32U numberBuffersInCpmList,
                                            Cpa32U *sizeOfBuffersInCpmList);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         free the CpaFlatBuffers and members of the CpaBufferLists
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   srcBufferListArray      array of CpaBufferLists to be freed
 * @param[in]   destBufferListArray     array of CpaBufferLists to be freed
 * @param[in]   cpmBufferListArray      array of CpaBufferLists to be freed
 *
 *     @pre                             none
 *
 *     @post                            all memory is allocated
 *
 *     @retval CPA_STATUS_SUCCESS       Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL          some of the memory could not be
 *                                      allocated
 ****************************************************************************/
CpaStatus qatFreeCompressionFlatBuffers(compression_test_params_t *setup,
                                        CpaBufferList *srcBufferListArray,
                                        CpaBufferList *destBufferListArray,
                                        CpaBufferList *cpmBufferListArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         Initialize a session for compression service
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   pSessionHandle          session handle to be allocated and
 *                                      initialized
 * @param[in]   pContextBuffer          pointer to context buffer to be
 *                                      allocated. The context buffer is only
 *                                      used by the driver for stateful
 *                                      compression
 * @param[in]   dcCbFn                  callback function to be registered with
 *                                      session. The callback function is called
 *                                      by the driver to process responses
 *
 *     @pre                             none
 *
 *     @post                            compression session is initialized and
 *                                      ready for use
 *
 *     @retval CPA_STATUS_SUCCESS       Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL          some of the session could not be
 *                                      initialized
 ****************************************************************************/
CpaStatus qatCompressionSessionInit(
    compression_test_params_t *setup,
    CpaDcSessionHandle *pSessionHandle,
    CpaDcSessionHandle *pDecompressSessionHandle,
    CpaBufferList *pContextBuffer,
    CpaDcCallbackFn dcCbFn);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         Remove a compression session
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   pSessionHandle          session handle to be unregistered and
 *                                      freed
 *
 *     @pre                             session is allocated and initialized
 *
 *     @post                            compression session handle unregistered
 *                                      from driver and the    memory for it is
 *                                      freed
 *
 *     @retval CPA_STATUS_SUCCESS       Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL          some of the session could not be
 *     initialized
 ****************************************************************************/
CpaStatus qatCompressionSessionTeardown(
    compression_test_params_t *setup,
    CpaDcSessionHandle *pSessionHandle,
    CpaDcSessionHandle *pDecompressSessionHandle);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         Initialize a session for chaining service
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   pSessionHandle          session handle to be allocated and
 *                                      initialized
 * @param[in]   dcCbFn                  callback function to be registered with
 *                                      session. The callback function is called
 *                                      by the driver to process responses
 *
 *     @pre                             none
 *
 *     @post                            chaining session is initialized and
 *                                      ready for use
 *
 *     @retval CPA_STATUS_SUCCESS       Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL          some of the session could not be
 *                                      initialized
 ****************************************************************************/
CpaStatus qatDcChainSessionInit(compression_test_params_t *setup,
                                CpaDcSessionHandle *pSessionHandle,
                                CpaDcSessionHandle *pDecompressSessionHandle,
                                CpaDcCallbackFn dcCbFn);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @defgroup sample_code
 *
 * @ingroup sampleCode
 *
 * @description
 *         Remove a compression session
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   pSessionHandle          session handle to be unregistered and
 *                                      freed
 *
 *     @pre                             session is allocated and initialized
 *
 *     @post                            chaining session handle unregistered
 *                                      from driver and the    memory for it is
 *                                      freed
 *
 *     @retval CPA_STATUS_SUCCESS       Function executed successfully
 *
 *     @retval CPA_STATUS_FAIL          some of the session could not be
 *     initialized
 ****************************************************************************/
CpaStatus qatDcChainSessionTeardown(
    compression_test_params_t *setup,
    CpaDcSessionHandle *pSessionHandle,
    CpaDcSessionHandle *pDecompressSessionHandle);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         dump the contents of the bufferLists to files:
 *         srcBuffer and scrBufferSizes for the uncompressed data
 *         dstBuffer and dstBufferSizes for the compressed data and
 *         cmpBuffer and cmpBufferSizes for the decompressed data
 *
 * @param[in]   pSrc                    pointer to the uncomressed buffer list
 * @param[in]   pDst                    pointer to the compressed buffer list
 * @param[in]   pCmp                    pointer to the decompressed buffer list
 * @param[in]   listNum                 Specific list number to be
 *                                      structure 0 = all buffers
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                files are dumped with bufferList info
 *                                      if NULL is passed as a pointer that file
 *                                      is not dumped
 *
 ****************************************************************************/
void qatDumpBufferListInfo(compression_test_params_t *setup,
                           CpaBufferList *pSrc,
                           CpaBufferList *pDst,
                           CpaBufferList *pCmp,
                           Cpa32U listNum);
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         compare the contents of two bufferlists upto the length of the
 *         srcBufferList.
 *
 * @param[in]   ppSrc                   pointer to the source buffer list
 * @param[in]   ppDst                   pointer to the destination buffer list
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                none
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the data did not match
 ****************************************************************************/
CpaStatus qatCmpBuffers(compression_test_params_t *setup,
                        CpaBufferList *pSrc,
                        CpaBufferList *pDst);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         check the buffer if contains all zeros.
 *
 * @param[in]   buf                     pointer to buffer
 * @param[in]   ptkSize                 buffer size
 *
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              If buffer doesn't contains all zeros
 ****************************************************************************/
CpaStatus qatIsBufEmpty(Cpa8U *buf, size_t pktSize);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         dump an array of bufferLists containing compressed or decompressed
 *         data to a binary file
 *
 * @param[in]   buffListArray           array of  buffer lists to containing
 *                                      data to be dumped to file
 *                                      compress
 * @param[in]   resultArray             results structure for each bufferList
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   fileName                name of file to dump bufferData to
 * @param[in]   fileNameB               name of file to dump bufferSizes t0
 * @param[in]   list                    if 0 dump the entire array of lists,
 *                                      otherwise dump a specific list
 *                                      note: 1=index 0 into the array of lists
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                destination buffer contains compressed
 *                                      data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the data did not compress
 ****************************************************************************/
void qatCompressDumpToFile(compression_test_params_t *setup,
                           CpaBufferList *buffListArray,
                           char *fileName,
                           char *fileNameB,
                           Cpa32U list);
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         compress source data using zlib software library
 *
 * @param[in]   srcBufferListArray      array of  source buffer lists to
 *                                      compress
 * @param[out]  dstBufferListArray      array of buffer lists to store
 *                                      compressed data
 * @param[in]   cmpResults              results structure for each bufferList
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                destination buffer contains compressed
 *                                      data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the data did not compress
 ****************************************************************************/
CpaStatus qatSwCompress(compression_test_params_t *setup,
                        CpaBufferList *srcBufferListArray,
                        CpaBufferList *dstBufferListArray,
                        CpaDcRqResults *cmpResults);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         decompress source data using zlib software library
 *
 * @param[in]   srcBufferListArray      array of  source buffer lists to
 *                                      decompress
 * @param[in]   dstBufferListArray      array of buffer lists to store
 *                                      decompressed data
 * @param[in]   cmpResults              results structure for each bufferList
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                destination buffer contains decompressed
 *                                      data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the data did not compress
 ****************************************************************************/
CpaStatus qatSwDecompress(compression_test_params_t *setup,
                          CpaBufferList *destBufferListArray,
                          CpaBufferList *cmpBufferListArray,
                          CpaDcRqResults *cmpResults);

#ifdef SC_CHAINING_ENABLED
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         decompress source data using zlib software library
 *
 * @param[in]   srcBufferListArray      array of  source buffer lists to
 *                                      decompress
 * @param[in]   dstBufferListArray      array of buffer lists to store
 *                                      decompressed data
 * @param[in]   cmpResults              results structure for each bufferList
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                destination buffer contains decompressed
 *                                      data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the data did not compress
 ****************************************************************************/
CpaStatus qatSwChainDecompress(compression_test_params_t *setup,
                               CpaBufferList *destBuffListArray,
                               CpaBufferList *cmpBufferListArray,
                               CpaDcChainRqResults *cmpResults);
#endif

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         this function checks if the HW behaviour is expected
 *         if it is expected then function handles the unconsumed
 *         data and returns CPA_STATUS_SUCCESS. If not the function
 *         returns CPA_STATUS_FAIL
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   arrayOfDestBufferLists  pointer to the bufferList to be updated
 *
 * @param[in]   arrayOfResults          pointer to the compression results array
 *
 * @param[in]   listNum                 index into bufferList array containing
 *                                      unconsumed data
 *
 * @param[in]   partName                the part name
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                bufferList is updated with amount of
 *                                      produced data
 *
 * @retval CPA_STATUS_SUCCESS           HW behaviour is expected and unconsumed
 *                                      data has been handled
 *
 * @retval CPA_STATUS_FAIL              it is impossible to handle unconsumed
 *                                      data
 ****************************************************************************/
CpaStatus qatCheckAndHandleUnconsumedData(compression_test_params_t *setup,
                                          CpaBufferList *arrayOfDestBufferLists,
                                          CpaDcRqResults *arrayOfResults,
                                          Cpa32U listNum,
                                          const char *partName);
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         update the dataLengthInBytes field with the amount of data produced
 *         from the compress or decompress operation
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   bufferListArray         bufferList to be updated

 * @param[in]   resultArray             results structure containing the amount
 *                                      of produced data
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                bufferList is updated with amount of
 *                                      produced data
 *
 ****************************************************************************/
void qatDcUpdateProducedBufferLength(compression_test_params_t *setup,
                                     CpaBufferList *bufferListArray,
                                     CpaDcRqResults *resultArray);

#ifdef SC_CHAINING_ENABLED
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         update the dataLengthInBytes field with the amount of data produced
 *         from the compress or decompress operation
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   bufferListArray         bufferList to be updated

 * @param[in]   resultArray             results structure containing the amount
 *                                      of produced data
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data
 *
 * @post                                bufferList is updated with amount of
 *                                      produced data
 *
 ****************************************************************************/
void qatDcChainUpdateProducedBufferLength(compression_test_params_t *setup,
                                          CpaBufferList *bufferListArray,
                                          CpaDcChainRqResults *resultArray);
#endif
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         reset a destination buffer with all 0's so that it does not contain
 *         compressed or decompressed data from previous use
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   buffListArray           array of buffer lists to reset
 * @param[in]   flafBufferSize          pointer to an array that stores the size
 *                                      of each CpaFlatBuffer in buffArrayList.
 * @param[in]   isCmpBuffer             set to true if resetting the
 *                                      cmpBufferList, set to false otherwise
 *
 * @pre                                 bufferLists are allocated and populated
 *                                      with data. flatBufferSize array stores
 *                                      size of each CpaFlatBuffer in
 *                                      buffArrayList (as the size can be
 *                                      updated to reflect the compressed data
 *                                      size
 *
 * @post                                pData in buffer list is all 0's
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the list was not reset
 ****************************************************************************/
CpaStatus qatCompressResetBufferList(compression_test_params_t *setup,
                                     CpaBufferList *buffListArray,
                                     Cpa32U *flafBufferSize,
                                     CpaBoolean isCmpBuffer);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         poll for responses and set the counter for when to poll next
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure

 * @pre                                 setup->perfStats is initialized
 *
 * @post                                the driver has polled for and responses
 *                                      and the counter is set for when to poll
 *                                      next
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the driver failed to poll
 ****************************************************************************/
void qatDcPollAndSetNextPollCounter(compression_test_params_t *setup);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         handles retries from the driver when submit Q's are full. Counts
 *         retries and calls context switch to pause submission
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   instanceInfo2           instance info structure is used to
 *                                      determine if the instance is use is a
 *                                      polled instance
 * @pre                                 setup->perfStats is initialized
 *
 * @post                                retry is counted, OS runs any other
 *                                      thread that was waiting for CPU time
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the driver failed to poll
 ****************************************************************************/
void qatDcRetryHandler(compression_test_params_t *setup,
                       const CpaInstanceInfo2 *pInstanceInfo2);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         checks if the callback function has found an error in any response.
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   arrayOfResults          pointer to the arrayOfResults that is
 *                                      also visible in the callback function
 * @param[in]   listNum                 number of submissions that have been
 *                                      made from the total number of allocated
 *                                      CpaBufferLists
 * @param[out]  status                  pointer to the status, which is updated
 *                                      in the event of a failure detected in
 *                                      response
 * @pre[in]                             all memory to pointers are allocated
 *
 * @post                                threadReturnStatus is checked for any
 *                                      response failures
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              an error was detected a response from
 *                                      the driver
 ****************************************************************************/
void qatCompressionResponseStatusCheck(compression_test_params_t *setup,
                                       CpaDcRqResults *arrayOfResults,
                                       Cpa32U listNum,
                                       CpaStatus *status);

#ifdef SC_CHAINING_ENABLED
/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         checks if the callback function has found an error in any response.
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   arrayOfResults          pointer to the arrayOfResults that is
 *                                      also visible in the callback function
 * @param[in]   listNum                 number of submissions that have been
 *                                      made from the total number of allocated
 *                                      CpaBufferLists
 * @param[out]  status                  pointer to the status, which is updated
 *                                      in the event of a failure detected in
 *                                      response
 * @pre[in]                             all memory to pointers are allocated
 *
 * @post                                threadReturnStatus is checked for any
 *                                      response failures
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              an error was detected a response from
 *                                      the driver
 ****************************************************************************/
void qatDcChainResponseStatusCheck(compression_test_params_t *setup,
                                   CpaDcChainRqResults *arrayOfResults,
                                   Cpa32U listNum,
                                   CpaStatus *status);
#endif

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         copy the a file from disk into memory to be used for compression and
 *         start the driver compression service.
 *
 * @param[in]   testBufferSize          size to break the file to be compressed
 *                                      into

 * @param[out]  corpusType              enum representing the file name to be
 *                                      loaded. The exact enum to file mapping
 *                                      is described in the function:
 *                                      populateCorpusInternal
 *
 * @pre[in]                             the files exist on the system in the
 *                                      path /lib/firmware/ by default
 *
 * @post                                the file is loaded into memory,
 *                                      the compression service is started
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the file could not be loaded or the
 *                                      compression service could not be started
 ****************************************************************************/
CpaStatus populateCorpusAndStartDcService(Cpa32U testBufferSize,
                                          corpus_type_t corpusType);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         set the flush flag to the type of compression being used
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[out]  listNum                 index into array of CpaBufferList.
 *                                      The flushFlag may change on the last
 *                                      buffer to be submitted
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the flush flag could not be set
 ****************************************************************************/
CpaStatus qatCompressionSetFlushFlag(compression_test_params_t *setup,
                                     Cpa32U listNum);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         allocate the memory used to store a list of CpaPhysBufferLists
 *
 * @param[in]   setup                pointer to the compression setup structure
 * @param[in]   srcBufferListArray   array of CpaPhysBufferLists to be allocated
 *                                   to store original file
 * @param[in]   destBufferListArray  array of CpaPhysBufferLists to be allocated
 *                                   to store compressed data
 * @param[in]   cmpBufferListArray   array of CpaPhysBufferLists to be allocated
 *                                   to place decompressed data
 * @param[in]   opDataCmpArray       array of cpaDcResults  to be allocated to
 *                                   store the results of compress operations
 * @param[in]   opDataDcmpArray      array of cpaDcResults  to be allocated to
 *                                   store the results of decompress operations
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 *
 * @retval CPA_STATUS_FAIL           memory could not be allocated
 ****************************************************************************/
CpaStatus qatAllocateCompressionDpLists(compression_test_params_t *setup,
                                        CpaPhysBufferList **srcBufferListArray,
                                        CpaPhysBufferList **destBufferListArray,
                                        CpaPhysBufferList **cmpBufferListArray,
                                        CpaDcDpOpData **opDataCmpArray,
                                        CpaDcDpOpData **opDataDcmpArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         free the memory of CpaPhysBufferLists
 *
 * @param[in]   setup                pointer to the compression setup structure
 * @param[in]   srcBufferListArray   array of CpaPhysBufferLists to be freed
 * @param[in]   destBufferListArray  array of CpaPhysBufferLists to be freed
 * @param[in]   cmpBufferListArray   array of CpaPhysBufferLists to be freed
 * @param[in]   opDataCmpArray       array of cpaDcResults  to be freed
 * @param[in]   opDataDcmpArray      array of cpaDcResults  to be freed
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 *
 * @retval CPA_STATUS_FAIL           memory could not be allocated
 ****************************************************************************/
CpaStatus qatFreeCompressionDpLists(compression_test_params_t *setup,
                                    CpaPhysBufferList **srcBufferListArray,
                                    CpaPhysBufferList **destBufferListArray,
                                    CpaPhysBufferList **cpmBufferListArray,
                                    CpaDcDpOpData **opDataCmpArray,
                                    CpaDcDpOpData **opDataDcmpArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sampleCode
 *
 * @description
 *         allocate the CpaPhysFlatBuffers and members of the CpaPhysBufferLists
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   srcBufferListArray      array of CpaPhysBufferLists to be
 *                                      allocated
 * @param[in]   numBuffersInSrcList     number of CpaPhysFlatBuffers to be
 *                                      allocated in srcBufferListArray
 * @param[in]   sizeOfBuffersInSrcList  size of CpaPhysBufferLists to be
 *                                      allocated in srcBufferLists
 * @param[in]   destBufferListArray     array of CpaPhysBufferLists to be
 *                                      allocated
 * @param[in]   numBuffersInDstList     number of CpaPhysFlatBuffers to be
 *                                      allocated in dstBufferListArray
 * @param[in]   sizeOfBuffersInDestList size of CpaBufferLists to be allocated
 *                                      in destBufferLists

 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              some of the memory could not be
 *                                      allocated
 ****************************************************************************/
CpaStatus qatAllocateCompressionDpFlatBuffers(
    compression_test_params_t *setup,
    CpaPhysBufferList *srcBufferListArray,
    Cpa32U numBuffersInSrcList,
    Cpa32U sizeOfBuffersInSrcList,
    CpaPhysBufferList *destBufferListArray,
    Cpa32U numBuffersInDstList,
    Cpa32U sizeOfBuffersInDstList,
    CpaPhysBufferList *cpmBufferListArray,
    Cpa32U numBuffersInCpmList,
    Cpa32U sizeOfBuffersInCpmList);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         free the CpaPhysFlatBuffers and members of the CpaPhysBufferLists
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   srcBufferListArray      array of CpaPhysBufferLists to be freed
 * @param[in]   destBufferListArray     array of CpaPhysBufferLists to be freed
 * @param[in]   cpmBufferListArray      array of CpaPhysBufferLists to be freed
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              some of the memory could not be
 *                                      allocated
 ****************************************************************************/
CpaStatus qatFreeCompressionDpFlatBuffers(
    compression_test_params_t *setup,
    CpaPhysBufferList *srcBufferListArray,
    CpaPhysBufferList *destBufferListArray,
    CpaPhysBufferList *cpmBufferListArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         copy the corpus data that was loaded into memory by
 *         populateCorpusAndStartDcService into the CpaPhysFlatBuffers of
 *         arrayOfSrcBufferLists
 *
 * @param[in]   arrayOfSrcBufferLists   array of cpaPhysBufferLists which
 *                                      contain allocate cpaPhysBufferLists to
 *                                      copy the corpus data into
 *
 * @param[in]   numberOfLists           number of lists in array
 * @param[in]   corpusFilePtr           pointer to where corpus data has been
 *                                      loaded into memory by
 *                                      populateCorpusAndStartDcService
 * @param[in]   testBufferSize          size of data that each cpaPhysFlarBuffer
 *                                      is allocated and how much from
 *                                      corpusFilePtr that should be copied into
 *                                      each buffer
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the corpus failed to copy into buffers
 ****************************************************************************/
CpaStatus qatPopulateDpBuffers(CpaPhysBufferList *arrayOfSrcBufferLists,
                               Cpa32U numberOfLists,
                               Cpa8U *corpusFilePtr,
                               Cpa32U testBufferSize);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         initialize a session to use for data plane compression service
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   opDataArray             array of Opdata structures in which the
 *                                      initialized session is stored to
 * @param[in]   pSessionHandle          pointer to the session handle that has
 *                                      already been initialized by
 *                                      qatCompressionSessionInit
 * @param[in]   srcBufferListArray      array of CpaPhysBufferLists that can be
 *                                      assigned to the opData.srcBuffer
 * @param[in]   destBufferListArray     aarray of CpaPhysBufferLists that can be
 *                                      assigned to the opData.dstBuffer
 * @param[in]   direction               direction of session
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the corpus failed to copy into buffers
 ****************************************************************************/
void qatCompressionDpOpDataInit(compression_test_params_t *setup,
                                CpaDcDpOpData *opDataArray,
                                CpaDcSessionHandle *pSessionHandle,
                                CpaPhysBufferList *srcBufferListArray,
                                CpaPhysBufferList *destBufferListArray,
                                CpaDcSessionDir direction);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         compress or decompress data using QA-API
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   direction               direction of session
 * @param[in]   opDataArray             array of Opdata structures in which the
 *                                      Initialized session is stored to
 * @param[in]   arrayOfXxxBufferLists   array of CpaPhysBufferLists, Src
 *                                      contains the source data, Dst is the
 *                                      where the compressed data is written,
 *                                      cmp is where decompressed data is
 *                                      written
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the corpus failed to copy into buffers
 ****************************************************************************/
CpaStatus qatCompressDecompressDpData(compression_test_params_t *setup,
                                      CpaDcSessionHandle pSessionHandle,
                                      CpaDcSessionDir compressDirection,
                                      CpaPhysBufferList *arrayOfSrcBufferLists,
                                      CpaPhysBufferList *arrayOfDestBufferLists,
                                      CpaPhysBufferList *arrayOfcpmBufferLists,
                                      CpaDcDpOpData *opDataArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         update the perfData struct with the amount of bytes produced and
 *         consumed by the ongoing compress/decompress operations
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   opDataArray             array of Opdata structures in which the
 *                                      Initialized session is stored to
 * @param[in]   perfData                pointer to perfData in which contains
 *                                      the count of produced and consumed data
 *                                      this is later used for compression ratio
 *                                      calculation
 *
 ****************************************************************************/
void qatDpSetBytesProducedAndConsumed(compression_test_params_t *setup,
                                      CpaDcDpOpData *opdata,
                                      perf_data_t *perfData);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         compare two CpaPhysBufferLists to see if they contain the same data
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   ppSrc                   source data to compare to
 * @param[in]   ppDst                   destination data to be compared
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the corpus failed to copy into buffers
 ****************************************************************************/
CpaStatus qatCmpDpBuffers(compression_test_params_t *setup,
                          CpaPhysBufferList *pSrc,
                          CpaPhysBufferList *pDst);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         use software to compress or decompress data
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   srcBufferListArray      source data to be compressed
 * @param[in]   destBufferListArray     pointer to memory to write out results
 * @param[in]   cmpResults              structure to store produced and consumed
 *                                      data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              the corpus failed to copy into buffers
 ****************************************************************************/
CpaStatus qatSwCompressDp(compression_test_params_t *setup,
                          CpaBufferList *dstBuffListArray,
                          CpaDcRqResults *cmpResults,
                          CpaBufferList *srcBuffListArray);

/**
 *****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *         this is an example thread that combines the sample code functions
 *         to show how to compress or decompress data using the QA-API
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 ****************************************************************************/
CpaStatus qatDpMain(compression_test_params_t *setup);

/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *      Used for profiling IA offload cost using the sleeptime method
 *      on every retry.
 *
 *  Phase One:Iterates over the main compress function, increasing the number
 *  of sleeptime value(setup->sleepTime) on each iteration until performance is
 *  affected within 5% different of base and current throughput
 *
 *  Phase Two: Continues to iterate over the main compress function, increasing
 *  the number of sleeptime cycles on each iteration until performance is
 *  back to the margin of 1.5%. to do it it will increase and decrease sleeptime
 *  value depending on the current throughput
 *
 *  Function should finish with the most suitable sleeptime value for given
 *  packet size, algorithm, compression level etc.
 *****************************************************************************/
CpaStatus performSleeptimeCalculation(
    compression_test_params_t *setup,
    CpaBufferList *arrayOfSrcBufferLists,
    CpaBufferList *arrayOfDestBufferLists,
    CpaBufferList *arrayOfCmpBufferLists,
    CpaDcRqResults *resultArray,
    CpaDcCallbackFn dcCbFn,
    CpaDcSessionDir dcSessDir,
    CpaDcSessionHandle pDecompressSessionHandle);

/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *  Used for profiling IA offload cost using buy loop.
 *
 *  Phase One:Iterates over the main perform function, increasing the number
 *  of busy loop cycles(BUSY_LOOP_INCREMENT) on each iteration until no retries
 *  occur.
 *
 *  Phase Two: Continues to iterate over the main perform function, increasing
 *  the number of busy loop cycles on each iteration until performance is
 *  affected then steps back to the last increment value, i.e. the last
 *  increment step(BUSY_LOOP_INCREMENT) before performance was affected.
 *
 *  Phase three: Calculate Offload cycles by measuring cycles spend on busy
 *loop, taking it away from total cycles and dividing by number of responses.
 *****************************************************************************/
CpaStatus performOffloadCalculationBusyLoop(
    compression_test_params_t *setup,
    CpaBufferList *arrayOfSrcBufferLists,
    CpaBufferList *arrayOfDestBufferLists,
    CpaBufferList *arrayOfCmpBufferLists,
    CpaDcRqResults *resultArray,
    CpaDcCallbackFn dcCbFn,
    CpaDcSessionDir dcSessDir,
    CpaDcSessionHandle pSessionHandle);

#ifdef SC_CHAINING_ENABLED
/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *  Used for profiling IA offload cost using buy loop.
 *
 *  Phase One:Iterates over the main perform function, increasing the number
 *  of busy loop cycles(BUSY_LOOP_INCREMENT) on each iteration until no retries
 *  occur.
 *
 *  Phase Two: Continues to iterate over the main perform function, increasing
 *  the number of busy loop cycles on each iteration until performance is
 *  affected then steps back to the last increment value, i.e. the last
 *  increment step(BUSY_LOOP_INCREMENT) before performance was affected.
 *
 *  Phase three: Calculate Offload cycles by measuring cycles spend on busy
 *loop, taking it away from total cycles and dividing by number of responses.
 *****************************************************************************/
CpaStatus performDcChainOffloadCalculationBusyLoop(
    compression_test_params_t *setup,
    CpaBufferList *arrayOfSrcBufferLists,
    CpaBufferList *arrayOfDestBufferLists,
    CpaBufferList *arrayOfCmpBufferLists,
    CpaDcChainRqResults *resultArray,
    CpaDcChainOpData *chainOpData,
    CpaDcCallbackFn dcCbFn,
    CpaDcSessionDir dcSessDir,
    CpaDcSessionHandle pSessionHandle);
#endif

/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *  This is the performance thread created by the sample code framework
 *  after registering the setupScDcTest and calling createPeformance threads
 *  this function copies the setup into its own local copy and then calls
 *  scDcPoc to measure compression performance
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 *****************************************************************************/
void dcPerformance(single_thread_test_data_t *testSetup);

/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 * This function allocates buffers store a file for compression. The buffers are
 * sent to hardware, performance is recorded and stored in the setup parameter
 * the sample code framework prints out results after the thread completes
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 *****************************************************************************/
CpaStatus qatDcPerform(compression_test_params_t *setup);

/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *  Performance measurement function to compress a file for 'n' number of loops
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   pSessionHandle          handler for a session
 * @param[in]   compressDirection       enum variable storing the direction of
 *the session
 * @param[in]   arrayOfSrcBufferLists   source data to be compressed
 * @param[in]   arrayOfDestBufferLists  pointer to memory to write out results
 * @param[in]   arrayOfCpmBufferLists   pointer to memory compare results
 * @param[in]   arrayOfResults          structure to store produced and consumed
 *                                      data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 *****************************************************************************/
CpaStatus qatCompressData(compression_test_params_t *setup,
                          CpaDcSessionHandle pSessionHandle,
                          CpaDcSessionDir compressDirection,
                          CpaBufferList *arrayOfSrcBufferLists,
                          CpaBufferList *arrayOfDestBufferLists,
                          CpaBufferList *arrayOfCpmBufferLists,
                          CpaDcRqResults *arrayOfResults);

#ifdef SC_CHAINING_ENABLED
/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 * Chaining Performance measurement function to compress a file for 'n' number
 *of loops
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   pSessionHandle          handler for a session
 * @param[in]   compressDirection       enum variable storing the direction of
 *the session
 * @param[in]   arrayOfSrcBufferLists   source data to be compressed
 * @param[in]   arrayOfDestBufferLists  pointer to memory to write out results
 * @param[in]   arrayOfCpmBufferLists   pointer to memory compare results
 * @param[in]   arrayOfResults          structure to store produced and consumed
 *                                      data
 * @param[in]   arrayOfChainOpData      structure to store chain operation data
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 *****************************************************************************/
CpaStatus qatDcChainCompressData(compression_test_params_t *setup,
                                 CpaDcSessionHandle pSessionHandle,
                                 CpaDcSessionDir compressDirection,
                                 CpaBufferList *arrayOfSrcBufferLists,
                                 CpaBufferList *arrayOfDestBufferLists,
                                 CpaBufferList *arrayOfCmpBufferLists,
                                 CpaDcChainRqResults *arrayOfResults,
                                 CpaDcChainOpData *arrayOfChainOpData);
#endif

/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *  Update in sample code framework how much data was consumed and produced by
 *  thread
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   perfData                pointer to the performance
 *                                      data structure
 * @param[in]   result                  structure to store produced and consumed
 *                                      data
 * @param[in]   direction               compress direction
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 *****************************************************************************/
void dcScSetBytesProducedAndConsumed(CpaDcRqResults *result,
                                     perf_data_t *perfData,
                                     compression_test_params_t *setup,
                                     CpaDcSessionDir direction);

#ifdef SC_CHAINING_ENABLED
/*****************************************************************************
 * @file qat_compression_main.h
 *
 * @ingroup sample_code
 *
 * @description
 *  Update in sample code framework how much data was consumed and produced by
 *  thread
 *
 * @param[in]   setup                   pointer to the compression setup
 *                                      structure
 * @param[in]   perfData                pointer to the performance
 *                                      data structure
 * @param[in]   result                  structure to store produced and consumed
 *                                      data
 * @param[in]   direction               compress direction
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully
 *
 * @retval CPA_STATUS_FAIL              failed to complete successfully
 *****************************************************************************/
void dcChainScSetBytesProducedAndConsumed(CpaDcChainRqResults *result,
                                          perf_data_t *perfData,
                                          compression_test_params_t *setup,
                                          CpaDcSessionDir direction);
#endif

#endif /*QAT_COMPRESSION_MAIN_H*/
