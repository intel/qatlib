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

/**
 *****************************************************************************
 * @file cpa_sample_code_dc_perf.h
 *
 * @defgroup compressionThreads
 *
 * @ingroup compressionThreads
 *
 * @description
 * Contains function prototypes and #defines used throughout code
 * and macros
 *
 ***************************************************************************/

#ifndef CPA_SAMPLE_CODE_DC_PERF_H_
#define CPA_SAMPLE_CODE_DC_PERF_H_

#include "cpa.h"
#include "cpa_dc.h"
#ifdef SC_CHAINING_ENABLED
#include "cpa_dc_chain.h"
#endif
#include "cpa_cy_sym.h"
#include "cpa_sample_code_framework.h"
#include "../common/qat_perf_utils.h"
/*
 *******************************************************************************
 * General performance code settings
 *******************************************************************************
 */

#define MIN_DC_LOOPS (1)
#define DEFAULT_DC_LOOPS (100)

/* Common macro definitions */
#ifndef DC_API_VERSION_AT_LEAST
#define DC_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_DC_API_VERSION_NUM_MAJOR > major ||                                   \
     (CPA_DC_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_DC_API_VERSION_NUM_MINOR >= minor))
#endif

/* Dynamic number of buffers to be created while initializing the Compression
 * session
 */
#define TEMP_NUM_BUFFS (5)
#define MIN_BUFFER_SIZE (15)
/* Extra buffer */
#define EXTRA_BUFFER (2)
#define MIN_DST_BUFFER_SIZE (8192)
#if defined(SC_WITH_QAT20) || defined(SC_WITH_QAT20_UPSTREAM)
#define MIN_DST_BUFFER_SIZE_GEN4 (1024)
#endif
#define DEFAULT_INCLUDE_LZ4 (0)
#define DEFAULT_COMPRESSION_LOOPS (100)
#define DEFAULT_COMPRESSION_WINDOW_SIZE (7)
#define INITIAL_RESPONSE_COUNT (-1)
#define SCALING_FACTOR_100 (100)
#define SCALING_FACTOR_1000 (1000)
#define BASE_10 (10)
#define DYNAMIC_BUFFER_AREA (0x20000)
#define SINGLE_REQUEST (1)
#define SINGLE_LOOP (1)
#define ONE_BUFFER_DC (1)
/* 1 MByte all zeros corpus. Enables calibrating latencies among different
 * buffer sizes */
#define ZEROS_CORPUS_LENGTH (64 * 1024 * 16)

/* Defining the available compression levels */
#define SAMPLE_CODE_CPA_DC_L1 (CPA_DC_L1)
#define SAMPLE_CODE_CPA_DC_L2 (CPA_DC_L2)
#define SAMPLE_CODE_CPA_DC_L3 (CPA_DC_L3)
#define SAMPLE_CODE_CPA_DC_L4 (CPA_DC_L4)
#define SAMPLE_CODE_CPA_DC_L5 (CPA_DC_L5)
#define SAMPLE_CODE_CPA_DC_L6 (CPA_DC_L6)
#define SAMPLE_CODE_CPA_DC_L7 (CPA_DC_L7)
#define SAMPLE_CODE_CPA_DC_L8 (CPA_DC_L8)
#define SAMPLE_CODE_CPA_DC_L9 (CPA_DC_L9)
#if DC_API_VERSION_AT_LEAST(3, 0)
#define SAMPLE_CODE_CPA_DC_L10 (CPA_DC_L10)
#define SAMPLE_CODE_CPA_DC_L11 (CPA_DC_L11)
#define SAMPLE_CODE_CPA_DC_L12 (CPA_DC_L12)
#endif

/* the following are defined in the framework, these are used for setup only
 * and are not to be used in functions not thread safe
 */

extern Cpa8U thread_setup_g[MAX_THREAD_VARIATION]
                           [MAX_SETUP_STRUCT_SIZE_IN_BYTES];
extern Cpa32U testTypeCount_g;
extern thread_creation_data_t testSetupData_g[];

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  Corpus Setup Data.
 *   @description
 *       This ENUM  contains data relating to corpus type.
 *       The client needs pass corpus type to setup
 *
 * ****************************************************************************/

typedef enum _corpusType
{
    /* Canterbury Corpus */
    CANTERBURY_CORPUS = 0,
    /* Calgary Corpus*/
    CALGARY_CORPUS,
    RANDOM,
    SIGN_OF_LIFE_CORPUS,
    CALGARY_SIX_FILES,
    CALGARY_FULL_SET,
    ZERO_LENGTH_FILE,
    OVERFLOW_FILE,
    OVERFLOW_AND_ZERO_FILE,
    CORPUS_TYPE_EXTENDED,
    /*All Corpus type should added above
     * CORPUS_TYPE_INVALID.
     */
    CORPUS_TYPE_INVALID
} corpus_type_t;

#define MAX_NUM_CORPUS_TYPE CORPUS_TYPE_INVALID

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  corpus file data.
 *   @description
 *       This structure contains data relating to setup corpus file.
 *       This structure is updated for each file in the corpus by performance
 *       API.
 *
 * ****************************************************************************
 * */
typedef struct corpus_file_s
{
    /* Corpus data in char format */
    Cpa8U *corpusBinaryData;
    /* Corpus data length */
    Cpa32U corpusBinaryDataLen;
} corpus_file_t;

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  enum for Data Plane Request Type
 *   @description
 *       This ENUM will be used to specify whether the compression operations
 *       are enqueued by the driver a single request at a time or in batches of
 *       multiple requests.
 *       The client needs pass provide this information in the setup
 *
 * ****************************************************************************/
typedef enum _dpRequestType
{
    /*Synchronous flag*/
    DC_DP_BATCHING = 0,
    DC_DP_ENQUEUEING
} dp_request_type_t;

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  compression setup Data.
 *   @description
 *    This structure contains setup data relating to setup compression End2End
 *    feature
 *
 * ****************************************************************************/

typedef struct qat_dc_e2e_s
{
    Cpa32U swInputChecksum;
    Cpa32U swOutputChecksum;
    Cpa64U swInputChecksum64b;
    Cpa64U swOutputChecksum64b;
    CpaCrcData compCrcData;
} qat_dc_e2e_t;

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  compression setup Data.
 *   @description
 *    This structure contains data relating to setup compression performance
 *    tests.The client needs to fill this structure before calling performance
 *    API
 *
 * ****************************************************************************/

typedef struct compression_test_params_s
{
    /* Session Direction */
    CpaDcSessionDir dcSessDir;
    /*number of CpaBufferLists to allocate/submit and loop over*/
    Cpa32U numLists;
    /*compression instance handle of service that has already been started*/
    CpaInstanceHandle dcInstanceHandle;
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /* Performance setup data for initializing sessions */
    CpaDcSessionSetupData setupData;
    /* Corpus Type */
    corpus_type_t corpus;
    Cpa32U corpusFileIndex;
    /*Buffer Size */
    Cpa32U bufferSize;
    /* Synchronous Flag */
    sync_mode_t syncFlag;
    /* Number of Loops */
    Cpa32U numLoops;
    /*rate limit variable*/
    Cpa32U compRate;
    Cpa32U sleepTime;
    CpaBoolean specific_sleeptime_flag;
    CpaBoolean adjustSleepTimeEnabled;
    /* Request type (Batch or Enqueue) */
    dp_request_type_t dpTestType;
    /* Number of requests to submit before processing */
    Cpa32U numRequests;
    /* Array of buffers required, indexed by corpus file number */
    Cpa32U *numberOfBuffers;
    /* Unique thread ID based on the order in which the thread was created */
    Cpa32U threadID;
    /* identifies if Data Plane API is used */
    CpaBoolean isDpApi;
    /*store the numa nodeId that the thread is running on*/
    Cpa32U node;
    /*alignment of buffers to be allocated for this setup*/
    Cpa32U alignment;
    Cpa32U fileSize[20];
    // session per file array of FileSize provides the fileSize for each session
    Cpa32U sessions;
    Cpa32U inputListSize;
    Cpa32U *packetSizeInBytesArray;
    Cpa32U outputListSize;
    Cpa32U *numberOfOutputLists;
    Cpa32U flatBuffSize;
    CpaDcFlush flushFlag;
    CpaBoolean useStatefulLite;
    CpaBoolean useE2E;
    CpaDcOpData requestOps;
    /*pointer to function capable of printing our stat related to specific
     * test varation
     */
    compute_test_result_func_t passCriteria;
    /* Set this flag to CPA_TRUE to induce overflow and handle it
     * by setting the destination buffer to be less than source
     * buffer.
     */
    CpaBoolean induceOverflow;
#if defined(SC_CHAINING_ENABLED) || defined(SC_CHAINING_EXT_ENABLED)
    CpaDcChainOperations chainOperation;
    CpaBoolean legacyChainRequest;
    CpaBoolean appendCRC;
    CpaBoolean testIntegrity;
    /* Initial Value Length */
    Cpa32U symIvLength;
    Cpa8U numSessions;
    CpaBoolean keyDerive;
#endif
    /*the logicalQaInstance for the cipher to use*/
    Cpa32U logicalQaInstance;
    /*stores the setup data thread running symmetric operations*/
    CpaCySymSessionSetupData symSetupData;
    sample_code_semaphore_t comp;
    /*flag to enable use of xlt in sample code*/
    CpaBoolean useXlt;
    CpaBoolean useE2EVerify;
    qat_dc_e2e_t *e2e;
    CpaBoolean disableAdditionalCmpbufferSize;
#if DC_API_VERSION_AT_LEAST(3, 2)
#endif
    CpaDcSessionHandle *pSessionHandle;
    /* the Destination Buffer size obtained using
     * Compress Bound API, for Compress operation */
    Cpa32U dcDestBufferSize;
} compression_test_params_t;

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  corpus file data.
 *   @description
 *       This structure contains data relating to setup corpus.
 *       This structure is updated for whole  corpus by performance
 *       API.
 *
 * ****************************************************************************
 * */
typedef struct corpus_data_s
{
    /* Array of files on Corpus */
    corpus_file_t *fileArray;
    /* file name of the corpus files */
    char **fileNameArray;
    /* Number of Files in Corpus */
    Cpa32U numFilesInCorpus;
    /* Flag indicates if the files have been read into buffers */
    CpaBoolean read;
} corpus_data_t;

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *   Callback tag data structure
 *   @description
 *       This structure contains results, bufflist and the performance
 *       data structures . The results structure is used to update the
 *       compressed data length in the bufflist structure and performance
 *       data structure is used to update the performance results.
 *
 * ****************************************************************************
 * */
typedef struct dc_callbacktag_s
{
    /* pointer to the DC results structure */
    CpaDcRqResults *dcResult;
    /* pointer to the performance data structure */
    perf_data_t *perfData;
    /* pointer to the BufferList structure */
    CpaBufferList *pBuffList;
} dc_callbacktag_t;

#ifdef SC_CHAINING_ENABLED
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *   Callback tag data structure
 *   @description
 *       This structure contains results, bufflist and the performance
 *       data structures . The results structure is used to update the
 *       compressed data length in the bufflist structure and performance
 *       data structure is used to update the performance results.
 *
 * ****************************************************************************
 * */
typedef struct chaining_callbacktag_s
{
    /* pointer to the DC results structure */
    CpaDcChainRqResults *dcResult;
    /* pointer to the performance data structure */
    perf_data_t *perfData;
    /* pointer to the BufferList structure */
    CpaBufferList *pBuffList;
} chaining_callbacktag_t;
#endif

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  create Buffers
 *
 *  @description
 *      this API Flat buffers Create Buffers
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *
 *  @param[in]  buffSize size of the buffer
 *  @param[in]  numBuffs Number of Buffers to create
 *  @param[in]  pBuffListArray pointer to the array of the buffer list
 *  @param[in]  nodeId node affinity
 *
 ******************************************************************************/

CpaStatus createBuffers(Cpa32U buffSize,
                        Cpa32U numBuffs,
                        CpaBufferList **pBuffListArray,
                        Cpa32U nodeId);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcPerform
 *
 *  @description
 *      this API creates the buffer List, populate the bufflist with Corpus data
 *      and does compression or decompression based on the session direction
 *  @threadSafe
 *      Yes
 *
 *  @param[out]   status
 *
 *  @param[in]  setup pointer to test setup structure
 *
 ******************************************************************************/

CpaStatus dcPerform(compression_test_params_t *setup);

#if DC_API_VERSION_AT_LEAST(3, 1)
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  setupDcLZ4Test
 *
 *  @description
 *      this API is the main API called by the framework, this is configures
 *      data structure before starting the performance threads
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *  @param[in]  algorithm Algorithm used for compression/decompression
 *  @param[in]  direction session direction
 *  @param[in]  compLevel compression Level
 *  @param[in]  state stateful operation or stateless operation
 *  @param[in]  testBuffersize size of the flat Buffer to use
 *  @parma[in]  corpusType type of corpus calgary/cantrbury corpus
 *  @param[in]  syncFlag synchronous/Asynchronous operation
 *  @param[in]  minMatch size that will be used for the search algorithm.
 *  It is only configurable for LZ4S
 *  @param[in]  lz4BlockMaxSize Maximum LZ4 output block size
 *  @param[in]  numloops Number of loops to compress or decompress
 ******************************************************************************/
CpaStatus setupDcLZ4Test(CpaDcCompType algorithm,
                         CpaDcSessionDir direction,
                         CpaDcCompLvl compLevel,
                         CpaDcSessionState state,
                         Cpa32U testBufferSize,
                         corpus_type_t corpusType,
                         CpaDcCompMinMatch minMatch,
                         CpaDcCompLZ4BlockMaxSize lz4BlockMaxSize,
                         sync_mode_t syncFlag,
                         Cpa32U numLoops);
#endif

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  setupDcTest
 *
 *  @description
 *      this API is the main API called by the framework, this is configures
 *      data structure before starting the performance threads
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *  @param[in]  algorithm Algorithm used for compression/decompression
 *  @param[in]  direction session direction
 *  @param[in]  compLevel compression Level
 *  @param[in]  HuffmanType HuffMantype Dynamic/static
 *  @param[in]  state stateful operation or stateless operation
 *  @param[in]  windowSize window size to be used for compression/decompression
 *  @param[in]  testBuffersize size of the flat Buffer to use
 *  @parma[in]  corpusType type of corpus calgary/cantrbury corpus
 *  @param[in]  syncFlag synchronous/Asynchronous operation
 *  @param[in]  numloops Number of loops to compress or decompress
 ******************************************************************************/
CpaStatus setupDcTest(CpaDcCompType algorithm,
                      CpaDcSessionDir direction,
                      CpaDcCompLvl compLevel,
                      CpaDcHuffType huffmanType,
                      CpaDcSessionState state,
                      Cpa32U windowSize,
                      Cpa32U testBufferSize,
                      corpus_type_t corpusType,
                      sync_mode_t syncFlag,
                      Cpa32U numLoops);


#ifdef SC_CHAINING_ENABLED
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  chainingPerform
 *
 *  @description
 *      this API creates the buffer List, populate the bufflist with Corpus data
 *      and does compression or decompression based on the session direction
 *  @threadSafe
 *      Yes
 *
 *  @param[out]   status
 *
 *  @param[in]  setup pointer to test setup structure
 *
 ******************************************************************************/

CpaStatus qatDcChainPerform(compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  setupDcChainTest
 *
 *  @description
 *      this API is the main API called by the framework, this is configures
 *      data structure before starting the performance threads
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *  @param[in]  chainOperation     chaining operation
 *  @param[in]  numSessions        numbers of sessions in chaining
 *  @param[in]  algorithm          algorithm Algorithm used for
 *compression/decompression
 *  @param[in]  direction          compression/decompression session direction
 *  @param[in]  compLevel          compression Level
 *  @param[in]  huffmanType        HuffMantype Dynamic/static
 *compressed/decompressed
 *  @param[in]  state              stateful operation or stateless operation
 *  @param[in]  windowSize         window size to be used for
 *compression/decompression
 *  @param[in]  testBuffersize     size of the flat Buffer to use
 *  @parma[in]  corpusType         type of corpus calgary/cantrbury corpus
 *  @param[in]  syncFlag           synchronous/Asynchronous operation
 *  @param[in]  opType             operation type
 *  @param[in]  cipherAlg          Indicates cipher algorithms and modes
 *  @param[in]  cipherKeyLengthInBytes cipher key length in bytes
 *  @param[in]  cipherDir          Indicates cipher direction
 *  @param[in]  priority           The level of priority
 *  @param[in]  hashAlg            Indicates hash algorithm
 *  @param[in]  hashMode           Mode of Hash algorithm
 *  @param[in]  authKeyLengthInBytes authentication key length in bytes
 *  @param[in]  numloops           Number of loops to compress or decompress
 ******************************************************************************/
CpaStatus setupDcChainTest(CpaDcChainOperations chainOperation,
                           Cpa8U numSessions,
                           CpaDcCompType algorithm,
                           CpaDcSessionDir direction,
                           CpaDcCompLvl compLevel,
                           CpaDcHuffType huffmanType,
                           CpaDcSessionState state,
                           Cpa32U windowSize,
                           Cpa32U testBufferSize,
                           corpus_type_t corpusType,
                           sync_mode_t syncFlag,
                           CpaCySymOp opType,
                           CpaCySymCipherAlgorithm cipherAlg,
                           Cpa32U cipherKeyLengthInBytes,
                           CpaCySymCipherDirection cipherDir,
                           CpaCyPriority priority,
                           CpaCySymHashAlgorithm hashAlg,
                           CpaCySymHashMode hashMode,
                           Cpa32U authKeyLengthInBytes,
                           Cpa32U numLoops);
#endif

#ifdef SC_CHAINING_EXT_ENABLED
CpaStatus setupDcChainExtTest(CpaDcChainOperations chainOperation,
                              Cpa8U numSessions,
                              CpaDcCompType algorithm,
                              CpaDcSessionDir direction,
                              CpaDcCompLvl compLevel,
                              CpaDcHuffType huffmanType,
                              CpaDcSessionState state,
                              Cpa32U windowsSize,
                              Cpa32U testBufferSize,
                              corpus_type_t corpusType,
                              sync_mode_t syncFlag,
                              CpaCySymOp opType,
                              CpaCySymCipherAlgorithm cipherAlg,
                              Cpa32U cipherKeyLengthInBytes,
                              CpaCySymCipherDirection cipherDir,
                              CpaCySymAlgChainOrder algChainOrder,
                              CpaCyPriority priority,
                              CpaCySymHashAlgorithm hashAlg,
                              CpaCySymHashMode hashMode,
                              Cpa32U authKeyLengthInBytes,
                              Cpa32U numLoops,
                              CpaBoolean appendCrc,
                              CpaBoolean keyDerive,
                              CpaBoolean dropData);
#endif

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  setupDcStatefulTest
 *
 *  @description
 *      this API is the main API called by the framework, this is configures
 *      data structure before starting the performance threads
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *  @param[in]  algorithm Algorithm used for compression/decompression
 *  @param[in]  direction session direction
 *  @param[in]  compLevel compression Level
 *  @param[in]  HuffmanType HuffMantype Dynamic/static
 *  @param[in]  state stateful operation or stateless operation
 *  @param[in]  windowSize window size to be used for compression/decompression
 *  @param[in]  testBuffersize size of the flat Buffer to use
 *  @parma[in]  corpusType type of corpus calgary/cantrbury corpus
 *  @param[in]  syncFlag synchronous/Asynchronous operation
 *  @param[in]  numloops Number of loops to compress or decompress
 ******************************************************************************/
CpaStatus setupDcStatefulTest(CpaDcCompType algorithm,
                              CpaDcSessionDir direction,
                              CpaDcCompLvl compLevel,
                              CpaDcHuffType huffmanType,
                              Cpa32U testBufferSize,
                              corpus_type_t corpusType,
                              sync_mode_t syncFlag,
                              Cpa32U numLoops);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  populateCantrBryCorpus
 *
 *  @description
 *      this API populates the canterbury corpus to the corpus data structure
 *  @threadSafe
 *      No
 *
 *  @param[out]  status
 *
 *  @param[in]  buffSize size of the flat buffer
 *
 ******************************************************************************/
CpaStatus populateCantrBryCorpus(Cpa32U buffSize);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  PopulateCorpus
 *
 *  @description
 *      this API populates the calgary corpus to the corpus data structure
 *  @threadSafe
 *      No
 *
 *  @param[out]  status
 *
 *  @param[in]  buffSize size of the flat buffer
 *
 ******************************************************************************/
CpaStatus populateCalgaryCorpus(Cpa32U buffSize);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  getCorpusFile
 *
 *  @description
 *      This API copies the corpus file in user space to a char buffer
 *      in the kernel space using request_firmware API. this API expects all
 *      corpus file in /lib/firmware directory by default.
 *  @threadSafe
 *      No
 *
 *  @param[in]  ppSrcBuff pointer to char buffer to copy corpus file
 *  @param[in]  filename  corpus file name to be copied
 *  @param[out]  size      size of the file
 *
 ******************************************************************************/
CpaStatus getCorpusFile(Cpa8U **ppSrcBuff, char *filename, Cpa32U *size);
CpaStatus getCompressedFile(Cpa8U **ppSrcBuff, char *filename, Cpa32U *size);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  freeBuffers
 *
 *  @description
 *      this API free all the Flat buffers from Bufflist
 *  @threadSafe
 *      No
 *
 *  @param[in]  pBuffListArray pointer to bufflist
 *  @param[in]  numberOfFiles  number of files in Buffer List
 *  @param[in] pointer to compression_test_params_t structure.
 *
 ******************************************************************************/
void freeBuffers(CpaBufferList ***pBuffListArray,
                 Cpa32U numberOfFiles,
                 compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  compareBuffers
 *
 *  @description
 *      this API compares the buffers before compression and after decompression
 *  @threadSafe
 *      No
 *
 *  @param[in]  ppSrc pointer to source buffer list
 *  @param[in]  ppDst pointer to destination buffer list
 *  @param[in] pointer to compression_test_params_t structure.
 *
 ******************************************************************************/
CpaStatus compareBuffers(CpaBufferList ***ppSrc,
                         CpaBufferList ***ppDst,
                         compression_test_params_t *setup);


/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcPerformCallback
 *
 *  @description
 *      this API is compression call back, called by compress API after
 *      the compression is performed
 *  @threadSafe
 *      No
 *
 *  @param[in]  pcallbackTag call back Tag
 *  @param[in]  status status of the operation performed
 *
 ******************************************************************************/
void dcPerformCallback(void *pCallbackTag, CpaStatus status);
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  deCompressCallback
 *
 *  @description
 *      this API  is decompression call back, called by de-compress API after
 *      the decompression is performed
 *  @threadSafe
 *      No
 *
 *  @param[in]  pCallbackTag call back Tag
 *  @param[in]  status status of the operation performed
 *
 ******************************************************************************/
void deCompressCallback(void *pCallbackTag, CpaStatus status);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  free results Structures
 *
 *  @description
 *      this API frees all the results structures
 *
 *  @threadSafe
 *      No
 *
 *  @param[in] ppDcResult array of cpaDcRqResults structure.
 *  @param[in] numFiles number of files in corpus.
 *  @param[in] pointer to compression_test_params_t structure.
 *
 ******************************************************************************/
void freeResults(CpaDcRqResults ***ppDcResult,
                 Cpa32U numFiles,
                 compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  free callback  Structures
 *
 *  @description
 *      this API frees all the callback structures
 *
 *  @threadSafe
 *      No
 *
 *  @param[in] ppCallbackTag  array of dc_callbacktag_t structure.
 *  @param[in] numFiles number of files in corpus.
 *  @param[in] pointer to compression_test_params_t structure.
 *
 ******************************************************************************/
void freeCbTags(dc_callbacktag_t ***ppCallbackTag,
                Cpa32U numFiles,
                compression_test_params_t *setup);

#ifdef SC_CHAINING_ENABLED
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  free callback  Structures
 *
 *  @description
 *      this API frees all the chain operation structures
 *
 *  @threadSafe
 *      No
 *
 *  @param[in] pOpData   array of CpaDcChainOpData structure.
 *  @param[in] numLists number of buffer list.
 *  @param[in] numSessions number of session in chaining operation.
 *
 ******************************************************************************/
void dcChainOpDataMemFree(CpaDcChainOpData *pOpdata,
                          Cpa32U numLists,
                          Cpa32U numSessions);
#endif

#ifdef SC_CHAINING_EXT_ENABLED
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  free callback  Structures
 *
 *  @description
 *      this API frees all the chain operation structures
 *
 *  @threadSafe
 *      No
 *
 *  @param[in] pOpData   array of CpaDcChainOpData structure.
 *  @param[in] numLists number of buffer list.
 *  @param[in] numSessions number of session in chaining operation.
 *
 ******************************************************************************/
void dcExtChainOpDataMemFree(CpaDcChainOpData *pOpdata,
                             Cpa32U numLists,
                             Cpa32U numSessions);
#endif

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  Perform Compress
 *
 *  @description
 *      this API measures the performance of Compression.
 *
 *  @threadSafe
 *      Yes
 *
 *  @param[in] setup setup pointer to test setup structure.
 *  @param[in] srcBuffListArray pointer to Source array of bufflists
 *  @param[in] dstBuffListArray pointer to destination array of bufflists
 *  @param[in] cmpResult  pointer to Results structure
 *  @param[in] dcCbFn  pointer to Callback Function
 *
 ******************************************************************************/
CpaStatus performCompress(compression_test_params_t *setup,
                          CpaBufferList ***srcBuffListArray,
                          CpaBufferList ***dstBuffListArray,
                          CpaDcRqResults ***cmpResult,
                          CpaDcCallbackFn dcCbFn);
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  Perform DeCompress
 *
 *  @description
 *      this API measures the performance of DeCompression.
 *
 *  @threadSafe
 *      Yes
 *
 *  @param[in] setup setup pointer to test setup structure.
 *  @param[in] srcBuffListArray pointer to Source array of bufflists
 *  @param[in] dstBuffListArray pointer to destination array of bufflists
 *  @param[in] cmpBuffListArray pointr to array of bufferlist for
 *             comparison of source and the result of the decompression
 *  @param[in] dcmpResult  pointer to Results structure
 *  @param[in] dcCbFn  pointer to Callback Function
 *
 ******************************************************************************/
CpaStatus performDeCompress(compression_test_params_t *setup,
                            CpaBufferList ***srcBuffListArray,
                            CpaBufferList ***dstBuffListArray,
                            CpaBufferList ***cmpBuffListArray,
                            CpaDcRqResults ***cmpResult,
                            CpaDcRqResults ***dcmpResult,
                            CpaDcCallbackFn dcCbFn);
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  Perform DeCompress
 *
 *  @description
 *      this API Compress the corpus, the output of this API will be used in the
 *      deCompression performance
 *
 *  @threadSafe
 *      Yes
 *
 *  @param[in] setup setup pointer to test setup structure.
 *  @param[in] srcBuffListArray pointer to Source array of bufferlist
 *  @param[in] dstBuffListArray pointer to destination array of bufferlist
 *  @param[in] cmpResult  pointer to Results structure
 *  @param[in] callbacktag  pointer to Callback Function
 *
 ******************************************************************************/

CpaStatus compressCorpus(compression_test_params_t *setup,
                         CpaBufferList ***srcBuffListArray,
                         CpaBufferList ***dstBuffListArray,
                         CpaDcRqResults ***cmpResult,
                         dc_callbacktag_t ***callbacktag);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcSampleCreateContextBuffer
 *
 *  @description
 *      this API Flat buffers Create Context Buffers
 *  @threadSafe
 *      No
 *
 *  @param[out]   None
 *
 *
 *  @param[in]  buffSize size of the buffer
 *  @param[in]  metaSize meta size of the buffer
 *  @param[in]  pBuffListArray pointer to the array of the buffer list
 *  @param[in]  nodeId node affinity
 *
 ******************************************************************************/

CpaStatus dcSampleCreateContextBuffer(Cpa32U buffSize,
                                      Cpa32U metaSize,
                                      CpaBufferList **pBuffListArray,
                                      Cpa32U nodeId);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcSampleFreeContextBuffer
 *
 *  @description
 *      this API free all the Context Flat buffers from Bufflist
 *  @threadSafe
 *      No
 *
 *  @param[in]  pBuffListArray pointer to bufflist
 *
 ******************************************************************************/
void dcSampleFreeContextBuffer(CpaBufferList *pBuffListArray);
CpaStatus setChecksum(CpaDcChecksum checksum);
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  qatGetCompressBoundDestinationBufferSize
 *
 *  @description
 *      This API gets the destination buffer size for the compression request
 *      by calling corresponding QAT Compress Bound API based on the compresison
 *      type.
 *
 *  @param[in]  setup   Compression Test Params
 *  @param[in]  dcInputBufferSize   The source Buffer size.
 *
 *  @param[out]  dcDestBufferSize   The destination Buffer size.
 *
 *  This API Returns CPA_STATUS_SUCCESS in success case.
 *
 ******************************************************************************/
CpaStatus qatGetCompressBoundDestinationBufferSize(
    compression_test_params_t *setup,
    Cpa32U dcInputBufferSize,
    Cpa32U *dcDestBufferSize);
/**
 * *****************************************************************************
 *  qatDcGetPreTestRecoveryCount
 *
 *  @description
 *      this API fill the CnV Recovery counter value before running the test in
 *      Performance Stats member.
 *
 ******************************************************************************/
CpaStatus qatDcGetPreTestRecoveryCount(compression_test_params_t *dcSetup,
                                       CpaDcInstanceCapabilities *capabilities,
                                       perf_data_t *performanceStats);
/**
 * *****************************************************************************
 *  qatDcGetPostTestRecoveryCount
 *
 *  @description
 *      this API fill the CnV Recovery counter value after running the test in
 *      Performance Stats member. This API should be called after the test run.
 *
 ******************************************************************************/
void qatDcGetPostTestRecoveryCount(compression_test_params_t *dcSetup,
                                   perf_data_t *performanceStats);

#endif /* CPA_SAMPLE_CODE_DC_PERF_H_ */
