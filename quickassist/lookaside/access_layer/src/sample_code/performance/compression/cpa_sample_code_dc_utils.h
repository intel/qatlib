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
 * @file cpa_sample_code_dc_utils.h
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
#ifndef CPA_SAMPLE_CODE_DC_UTILS_H_
#define CPA_SAMPLE_CODE_DC_UTILS_H_

#include "cpa_sample_code_dc_perf.h"
#include "cpa.h"
#include "cpa_dc.h"
#include "cpa_dc_capabilities.h"
#include "cpa_dc_dp.h"
#include "cpa_sample_code_framework.h"
#include "qat_compression_cnv_utils.h"

#ifdef USER_SPACE
#include "zlib.h"
#else
#include <linux/zlib.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#endif

/* Common macro definitions */
#ifndef DC_API_VERSION_AT_LEAST
#define DC_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_DC_API_VERSION_NUM_MAJOR > major ||                                   \
     (CPA_DC_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_DC_API_VERSION_NUM_MINOR >= minor))
#endif

#define DC_API_VERSION_LESS_THAN(major, minor)                                 \
    (CPA_DC_API_VERSION_NUM_MAJOR < major ||                                   \
     (CPA_DC_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_DC_API_VERSION_NUM_MINOR < minor))

#define TEMP_NUM_BUFFS (5)
#define MIN_BUFFER_SIZE (15)
#define KILOBITS_IN_MEGABITS (1000)

#define OPERATIONS_POLLING_INTERVAL (10)

extern Cpa32U dcPollingInterval_g;
extern CpaBoolean gUseStatefulLite;
extern CpaDcChecksum gChecksum;
extern CpaDcAutoSelectBest gAutoSelectBestMode;
extern CpaBoolean testOverFlow_g;
extern volatile CpaBoolean dc_service_started_g;
extern CpaBoolean gRetainPartials;
extern CpaBoolean disableAdditionalCmpbufferSize_g;
extern volatile CpaBoolean enableDcDpFlatsToSGLConv_g;
extern volatile Cpa32U dcDpNumFlatsPerSGL_g;
#if DC_API_VERSION_AT_LEAST(3, 2)
extern volatile Cpa32U dcDpPartialReadBufferMask_g;
extern volatile CpaBoolean dcDpEnableZeroPad_g;
#define IS_PARTREAD_TEST()                                                     \
    ((dcDpPartialReadBufferMask_g > 0) ? CPA_TRUE : CPA_FALSE)
#define IS_ZEROPAD_TEST() (dcDpEnableZeroPad_g)
#endif /* DC_API_VERSION_AT_LEAST(3, 2) */
extern Cpa32U getThroughput(Cpa64U numPackets,
                            Cpa32U packetSize,
                            perf_cycles_t cycles);
#if DC_API_VERSION_AT_LEAST(3, 1)
extern volatile CpaBoolean LZ4BlockIndependence_g;
#endif

void dcPerformCallback(void *pCallbackTag, CpaStatus status);
void dcReadPerformCallback(void *pCallbackTag, CpaStatus status);

CpaStatus setAutoSelectBestMode(CpaDcAutoSelectBest mode);
CpaStatus disableAdditionalCmpbufferSize(CpaBoolean value);
CpaStatus compareBuffers2(CpaBufferList ***ppSrc,
                          CpaBufferList ***ppDst,
                          CpaBufferList ***ppComp,
                          compression_test_params_t *setup);
/* corpus Data structure */
extern CpaBoolean useZlib_g;
extern Cpa32U expansionFactor_g;
extern CpaDcHuffType huffmanType_g;
#ifdef ZERO_BYTE_LAST_REQUEST
extern CpaBoolean zeroByteLastRequest_g;
CpaStatus enableZeroByteRequest(void);
CpaStatus disableZeroByteRequest(void);
#endif
/* Used by ZLIB */
#define DEFLATE_DEF_LEVEL (Z_DEFAULT_COMPRESSION)
#define DEFLATE_DEF_WINBITS (15)
#define DEFLATE_DEF_MEMLEVEL (8)

#define CPA_CRC64_POLYNOMIAL1 0x42F0E1EBA9EA3693ULL
#define CPA_CRC64_POLYNOMIAL2 0x9A6C9329AC4BC9B5ULL
#define CPA_CRC32_POLYNOMIAL1 (((Cpa64U)(0x04c11db7)) << 32)
#define CPA_CRC32_POLYNOMIAL2 (((Cpa64U)(0x1EDC6F41)) << 32)

#define CPA_CRC64_XOROUT_0 0x0ULL
#define CPA_CRC64_XOROUT_1 0xFFFFFFFFFFFFFFFFULL
#define CPA_CRC64_XOROUT_2 0x9465776698231213ULL
#define CPA_CRC32_XOROUT_1 (((Cpa64U)(0xffffffff)) << 32)
#define CPA_CRC32_XOROUT_2 ((Cpa64U)(0xffffffff))

#define CPA_CRC64_INITIAL_VALUE_0 0x0ULL
#define CPA_CRC64_INITIAL_VALUE_1 0x6386926455673254ULL
#define CPA_CRC32_INITIAL_VALUE_1 (((Cpa64U)(0xffffffff)) << 32)

#define CHECK_AND_STOPDCSERVICES()                                             \
    if (dc_service_started_g == CPA_TRUE)                                      \
    {                                                                          \
        stopDcServices();                                                      \
    }

#ifndef DO_CRYPTO
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      getThroughput
 *
 * @description
 *      get the throughput in Megabits per second
 *      =(numPackets*packetSize)*(cycles/cpu_frequency)
 *****************************************************************************/
Cpa32U getThroughput(Cpa64U numPackets,
                     Cpa32U packetSize,
                     perf_cycles_t cycles);
#endif
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  populateCorpus
 *
 *  @description
 *      this API populates the specified corpus to the corpus data structure
 *  @threadSafe
 *      No
 *
 *  @param[out]  status
 *
 *  @param[in]  buffSize size of the flat buffer
 *  @param[in]  corpusType corpus type to load
 *
 ******************************************************************************/
CpaStatus populateCorpus(Cpa32U buffSize, corpus_type_t corpusType);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  startDcServices
 *
 *  @description
 *      this API starts the Data compression services if not already started
 *  @threadSafe
 *      No
 *
 *
 *  @param[in]  buffsize buffer size for intermittent buffers
 *  @param[in]  numBuffs number of intermittent Buffers required
 *
 ******************************************************************************/
CpaStatus startDcServices(Cpa32U buffSize, Cpa32U numBuffs);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  startServices
 *
 *  @description
 *      this API starts the services of the given type if not already started
 *  @threadSafe
 *      No
 *
 *  @param[in]  serviceType Acceleration Service required
 *  @param[in]  buffsize buffer size for intermittent buffers
 *  @param[in]  numBuffs number of intermittent Buffers required
 *
 ******************************************************************************/
CpaStatus startServices(const CpaAccelerationServiceType serviceType,
                        Cpa32U buffSize,
                        Cpa32U numBuffs);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 * dcCreateDecompPollingThreads
 *
 * @description
 *      This function checks whether each instance handle is set for polling
 *      and will allocate create and start the same number polling threads
 *      as they are polling instances.
 * @pre numDecompInstances_g is set and all instances have been started.
 * @post numDecompPolledInstances_g is set by the function to the number of
 * polling instances available.
 *
 *****************************************************************************/
CpaStatus dcCreateDecompPollingThreads(void);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  freeCorpus
 *
 *  @description
 *      this API frees the corpus global data structure.
 *  @threadSafe
 *      No
 *
 ******************************************************************************/
void freeCorpus(void);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  startDcServices
 *
 *  @description
 *      this API stops the Data compression services.
 *  @threadSafe
 *      No
 *
 ******************************************************************************/
CpaStatus stopDcServices(void);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  startDcServices
 *
 *  @description
 *      this API stops the Data compression services.
 *  @threadSafe
 *      No
 *  @param[in] data  pointer to test data structure
 *
 ******************************************************************************/
CpaStatus stopDcServicesFromPrintStats(thread_creation_data_t *data);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  claculateRequireBuffers
 *
 *  @description
 *      this API calculates the number of flat buffer required for the corpus
 *      and populates the setup->numberOfBuffers array
 *  @threadSafe
 *      No
 *
 *  @param[out] status
 *
 *  @param[in]  pointer to compression_test_params_t
 *
 ******************************************************************************/
CpaStatus calculateRequireBuffers(compression_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      dcCreatePollingThreadsIfPollingIsEnabled
 *
 * @description
 *      This function checks whether each instance handle is set for polling
 *      and will allocate create and start the same number polling threads
 *      as they are polling instances.
 * @pre numInstances_g is set and all instances have been started.
 * @post numPolledInstances_g is set by the function to the number of polling
 *         instances available.
 *
 *****************************************************************************/
CpaStatus dcCreatePollingThreadsIfPollingIsEnabled(void);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcDpPollNumOperations
 *
 *  @description
 *      Poll for remaining operations, this function will timeout after
 *      SAMPLE_CODE_WAIT_DEFAULT have elapsed.
 *
 *  @threadSafe
 *      No
 *
 *  @param[in] perfData         pointer to performance structure
 *  @param[in] instanceHandle   API CpaInstanceHandle
 *  @param[in] numOperations    Number of operations to poll for
 *
 *  @retval CPA_STATUS_SUCCESS  No operations to poll for or all remaining
 *                              operations have been polled.
 *  @retval CPA_STATUS_FAIL     Failure from polling operation or timeout.
 ******************************************************************************/
CpaStatus dcDpPollNumOperations(perf_data_t *pPerfData,
                                CpaInstanceHandle instanceHandle,
                                Cpa64U numOperations);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcDpPollNumOperationsRetries
 *
 *  @description
 *      Poll for remaining operations, this function will timeout after
 *      SAMPLE_CODE_WAIT_DEFAULT have elapsed.
 *
 *  @threadSafe
 *      No
 *
 *  @param[in] perfData         pointer to performance structure
 *  @param[in] instanceHandle   API CpaInstanceHandle
 *  @param[in] numOperations    Number of operations to poll for
 *  @param[out] numOperations   Number of retries
 *  @param[out] retries         Number of retries
 *
 *  @retval CPA_STATUS_SUCCESS  No operations to poll for or all remaining
 *                              operations have been polled.
 *  @retval CPA_STATUS_FAIL     Failure from polling operation or timeout.
 ******************************************************************************/
CpaStatus dcDpPollNumOperationsRetries(perf_data_t *pPerfData,
                                       CpaInstanceHandle instanceHandle,
                                       Cpa64U numOperations,
                                       Cpa32U *retries);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  wait for semaphore
 *
 *  @description
 *      this API waits for the semaphore for 30 seconds and checks
 *      if the responses are still pending, if the responses are still pending
 *      wait for another 30 secs and returns error if the responses are not
 *      increased
 *
 *  @threadSafe
 *      Yes
 *
 *  @param[in] perfData  pointer to performance structure
 *
 ******************************************************************************/
CpaStatus waitForSemaphore(perf_data_t *perfData);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  sampleCodeDcGetNode
 *
 *  @description
 *      this API determines the CPU node  for the instance handle
 *
 *  @threadSafe
 *      No
 *
 *  @param[in]  instanceHandle DC instance Handle
 *  @param[out] node node ID of the instance
 *
 ******************************************************************************/
CpaStatus sampleCodeDcGetNode(CpaInstanceHandle instanceHandle, Cpa32U *node);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  sampleCodePoll
 *
 *  @description
 *      this API repeatedly calls the QA API poll function
 *  @threadSafe
 *      No
 *
 *  @param[in]  instanceHandle DC instance Handle
 *
 ******************************************************************************/
void sampleCodeDcPoll(CpaInstanceHandle instanceHandle_in);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcPrintstats
 *
 *  @description
 *      this API prints performance data like number of CPU cycles
 *      consumed for an Operation
 *  @threadSafe
 *      No
 *
 *  @param[in]  data  pointer to test data structure
 *
 ******************************************************************************/
CpaStatus dcPrintStats(thread_creation_data_t *data);
/**
 * *****************************************************************************
 *  @ingroup chainingThreads
 *  chainPrintstats
 *
 *  @description
 *      this API prints performance data like number of CPU cycles
 *      consumed for an Operation
 *  @threadSafe
 *      No
 *
 *  @param[in]  data  pointer to test data structure
 *
 ******************************************************************************/
CpaStatus dcChainPrintStats(thread_creation_data_t *data);

CpaStatus dcGetInstances(CpaAccelerationServiceType accelSrvType,
                         CpaInstanceHandle **pInstHandle,
                         Cpa16U *numInstances);
/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcPrintTestData
 *
 *  @description
 *      this API prints the setup data used to execute the compression test
 *  @threadSafe
 *      No
 *
 *  @param[in]  setup  pointer to compression test data structure
 *
 ******************************************************************************/
void dcPrintTestData(compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup chainingThreads
 *  dcChainPrintTestData
 *
 *  @description
 *      this API prints the setup data used to execute the chaining test
 *  @threadSafe
 *      No
 *
 *  @param[in]  setup  pointer to chaining test data structure
 *
 ******************************************************************************/
void dcChainPrintTestData(compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcDpSetBytesProducedAndConsumed
 *
 *  @description
 *      This function aggregates the total bytes consumed and produced as
 *      reported by the driver in the opData structures (a separate opData
 *      structure is used for each buffer submitted) and stores them in the
 *      perfData totalBytesConsumed and totalBytesProduced fields.
 *  @threadSafe
 *      No
 *
 *  @param[in]      opData  2D array of pointers to a CpaDcDpOpData structure
 *  @param[in,out]  perfData  pointer to performance structure
 *  @param[in]      pointer to compression_test_params_t structure.
 *
 *
 ******************************************************************************/
void dcDpSetBytesProducedAndConsumed(CpaDcDpOpData ***opData,
                                     perf_data_t *perfData,
                                     compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcSetBytesProducedAndConsumed
 *
 *  @description
 *      This function aggregates the total bytes consumed and produced as
 *      reported by the driver in the cmpResult structures (a separate cmpResult
 *      structure is used for each buffer submitted) and stores them in the
 *      perfData totalBytesConsumed and totalBytesProduced fields.
 *  @threadSafe
 *      No
 *
 *  @param[in]  cmpResult  2D array of pointers to a CpaDcRqResults structure
 *  @param[in]  perfData  pointer to performance structure
 *  @param[in] pointer to compression_test_params_t structure.
 *
 *
 ******************************************************************************/
void dcSetBytesProducedAndConsumed(CpaDcRqResults ***cmpResult,
                                   perf_data_t *perfData,
                                   compression_test_params_t *setup);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  dcCalculateAndPrintCompressionRatio
 *
 *  @description
 *      this API calculates and prints the compression ratio
 *  @threadSafe
 *      No
 *
 *  @param[in]  bytesConsumed  Total number of bytes consumed for compression
 *  @param[in]  bytesProduced  Total number of bytes produced after compression
 *
 ******************************************************************************/
CpaStatus dcCalculateAndPrintCompressionRatio(Cpa32U bytesConsumed,
                                              Cpa32U bytesProduced);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      getDcThroughput
 *
 * @description
 *      get the throughput in Megabits per second
 *
 * @param[in]   totalBytes  Total number of bytes consumed by all threads
 * @param[in]   cycles      Total number of clock cycles
 * @param[in]   numOfLoops  Number of loops specified for compression operation
 *****************************************************************************/
Cpa32U getDcThroughput(Cpa32U totalBytes,
                       perf_cycles_t cycles,
                       Cpa32U numOfLoops);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      dynamicHuffmanEnabled
 *
 * @description
 *      Determines if a given instance has Dynamic Huffman enabled.
 *
 * @param[in]       dcInstanceHandle  Pointer to CpaInstanceHandle. If
 *                          dcInstanceHandle is NULL a local instance, i.e. the
 *                          first instance from cpaDcGetNumInstances() will be
 *                          used to determine if dynamic Huffman is enabled.
 * @param[in]       accelSrvType  service type of the instance.
 * @param[in,out]   isEnabled     Pointer to CpaBoolean. When set to CPA_TRUE
 *                          the instance handle has dynamic Huffman enabled.
 *                          Will be set to CPA_FALSE for all error conditions
 *                          or where CpaDcInstanceCapabilities.dynamicHuffman
 *                          is CPA_FALSE.
 * @retval CPA_STATUS_SUCCESS  Instance query for dynamic compression succeeded
 * @retval CPA_STATUS_FAIL     Instance query for dynamic compression failed
 *****************************************************************************/
CpaStatus dynamicHuffmanEnabled(CpaAccelerationServiceType accelSrvType,
                                CpaInstanceHandle *dcInstanceHandle,
                                CpaBoolean *isEnabled);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      staticHuffmanEnabled
 *
 * @description
 *      Determines if a given instance has Static Huffman enabled.
 *
 * @param[in]       dcInstanceHandle  Pointer to CpaInstanceHandle. If
 *                          dcInstanceHandle is NULL a local instance, i.e. the
 *                          first instance from cpaDcGetNumInstances() will be
 *                          used to determine if static Huffman is enabled.
 *@param[in]       accelSrvType service type of the instance.
 * @param[in,out]   isEnabled     Pointer to CpaBoolean. When set to CPA_TRUE
 *                          the instance handle has static Huffman enabled.
 *                          Will be set to CPA_FALSE for all error conditions
 *                          or when static Huffman is not enabled for the
 *                          instance.
 * @retval CPA_STATUS_SUCCESS  Instance query for static compression succeeded
 * @retval CPA_STATUS_FAIL     Instance query for static compression failed
 *****************************************************************************/
CpaStatus staticHuffmanEnabled(CpaAccelerationServiceType accelSrvType,
                               CpaInstanceHandle *dcInstanceHandle,
                               CpaBoolean *isEnabled);

/*This function tells the compression sample code to use zLib software to
 * compress the data prior to calling the decompression*/
CpaStatus useZlib(void);

/*This function tells the compression sample code to use zLib software to
 * compress the data prior to calling the decompression*/
CpaStatus useAccelCompression(void);

CpaStatus dcPollNumOperations(perf_data_t *pPerfData,
                              CpaInstanceHandle instanceHandle,
                              Cpa64U numOperations);

CpaStatus dcSampleCreateStatefulContextBuffer(Cpa32U buffSize,
                                              Cpa32U metaSize,
                                              CpaBufferList **pBuffListArray,
                                              Cpa32U nodeId);

CpaStatus dcSampleFreeStatefulContextBuffer3(CpaBufferList *pBuffListArray);

CpaStatus waitForInflightRequestAfterError(perf_data_t *perfData);

void measureNano(Cpa32U);
Cpa32U getNumFilesInCorpus(corpus_type_t corpus);
char **getFileNamesInCorpus(corpus_type_t corpus);
const corpus_file_t *getFilesInCorpus(corpus_type_t corpusType);
const char *getCorpusName(corpus_type_t corpusType);
corpus_type_t getCorpusTypeFromName(const char *name,
                                    const unsigned long name_max_size);
const char *getFileNameInCorpus(corpus_type_t corpusType, Cpa32U fileIndex);
void setCorpusType(corpus_type_t type);
corpus_type_t getCorpusType(void);
void setCorpusFileIndex(Cpa32U index);
Cpa32U getCorpusFileIndex(void);
Cpa32U getSetupCnVRequestFlag(void);
void setSetupCnVRequestFlag(Cpa32U flag);
void setDcPollingThreadsInterval(long interval);

void getDecompNumInstances(void);

#if defined(USER_SPACE) && defined(SUPPORTED_FEAT_EPOLL) &&                    \
    defined(STV_TEST_CODE)
/* Core response mode configuration functions */
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Set the response mode for DC instances
 *
 * @description
 *      This function sets the CpaInstanceResponseMode that will be
 *      applied to DC instances specified by the mask. This explicitly
 *      overrides the QAT library's default response mode.
 *
 * @param[in]  responseMode    The response mode to set
 *
 *****************************************************************************/
CpaStatus setDcInstanceResponseMode(CpaInstanceResponseMode responseMode);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceResponseModeByValue
 *
 * @description
 *      Unified user-friendly function that accepts response mode as user input
 *      values (0 for polling, 1 for event notification) and configures ALL
 *      available DC instances. This function maps the user input to the correct
 *      CpaInstanceResponseMode enum values and automatically applies to all
 *      instances, making it the primary function for response mode
 * configuration.
 *
 * @param[in]  userMode    User input mode (0 = polling, 1 = event notification)
 *
 *****************************************************************************/
CpaStatus setDcInstanceResponseModeByValue(Cpa32U userMode);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceResponseModeWithMask
 *
 * @description
 *      Combined function that sets both the response mode and instance mask
 *      in a single call. This is the recommended function for most use cases
 *      as it ensures both the mode and target instances are set atomically.
 *
 * @param[in]  userMode    User input mode (0 = polling, 1 = event notification)
 * @param[in]  mask        64-bit mask indicating which instances to configure
 *                         (bit 0 = instance 0, bit 1 = instance 1, etc.)
 *
 *****************************************************************************/
CpaStatus setDcInstanceResponseModeWithMask(Cpa32U userMode, Cpa64U mask);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceResponseModeForRange
 *
 * @description
 *      Convenience function to set response mode for a range of instances.
 *      This is useful when you want to configure consecutive instances.
 *
 * @param[in]  userMode    User input mode (0 = polling, 1 = event notification)
 * @param[in]  startInst   First instance to configure (0-based)
 * @param[in]  endInst     Last instance to configure (inclusive, 0-based)
 *
 *****************************************************************************/
CpaStatus setDcInstanceResponseModeForRange(Cpa32U userMode,
                                            Cpa16U startInst,
                                            Cpa16U endInst);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Get the configured response mode for DC instances
 *
 * @description
 *      This function returns the configured CpaInstanceResponseMode
 *      that will be applied to DC instances, if one has been set.
 *
 * @retval CpaInstanceResponseMode   Configured response mode
 *
 *****************************************************************************/
CpaInstanceResponseMode getDcInstanceResponseMode(void);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Check if response mode has been explicitly configured
 *
 * @description
 *      This function returns whether a response mode has been explicitly
 *      configured, indicating that the QAT library's default should be
 *      overridden.
 *
 * @retval CpaBoolean   CPA_TRUE if configured, CPA_FALSE if using defaults
 *
 *****************************************************************************/
CpaBoolean isDcInstanceResponseModeConfigured(void);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Clear/reset the response mode configuration
 *
 * @description
 *      This function clears any explicitly configured response mode,
 *      allowing the QAT library's default to be used again.
 *
 *****************************************************************************/
CpaStatus clearDcInstanceResponseModeConfiguration(void);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Apply configured response modes to DC instances
 *
 * @description
 *      This function applies the configured response modes to the actual
 *      DC instances based on the current mask and configuration. This should
 *      be called after DC services are started but before polling threads
 *      are created.
 *
 * @retval CpaStatus   Status of the operation
 *
 *****************************************************************************/
CpaStatus applyDcInstanceResponseModeConfiguration(void);

#if defined(USER_SPACE) && defined(SUPPORTED_FEAT_INT_COALESCING_TIMER) &&     \
    defined(STV_TEST_CODE)
/* Coalescing timer configuration functions (require driver APIs only
 * available when SUPPORTED_FEAT_INT_COALESCING_TIMER is set) */
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceCoalescingTimer
 *
 * @description
 *      Sets the interrupt coalescing timer value (in nanoseconds) that will be
 *      applied to DC instances specified by the mask. This explicitly
 *      overrides the QAT library's default coalescing timer.
 *
 * @param[in]  coalescingTimerInNs  Coalescing timer value in nanoseconds
 *
 *****************************************************************************/
CpaStatus setDcInstanceCoalescingTimer(Cpa32U coalescingTimerInNs);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceCoalescingTimerWithMask
 *
 * @description
 *      Combined function that sets both the coalescing timer value and the
 *      instance mask in a single call.
 *
 * @param[in]  coalescingTimerInNs  Coalescing timer value in nanoseconds
 * @param[in]  mask                 64-bit bitmask of instances to configure
 *
 *****************************************************************************/
CpaStatus setDcInstanceCoalescingTimerWithMask(Cpa32U coalescingTimerInNs,
                                               Cpa64U mask);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceCoalescingTimerForRange
 *
 * @description
 *      Convenience function to set the coalescing timer for a range of
 *      consecutive instances.
 *
 * @param[in]  coalescingTimerInNs  Coalescing timer value in nanoseconds
 * @param[in]  startInst            First instance to configure (0-based)
 * @param[in]  endInst              Last instance to configure (inclusive)
 *
 *****************************************************************************/
CpaStatus setDcInstanceCoalescingTimerForRange(Cpa32U coalescingTimerInNs,
                                               Cpa16U startInst,
                                               Cpa16U endInst);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      getDcInstanceCoalescingTimer
 *
 * @description
 *      Returns the configured coalescing timer value (in nanoseconds) that
 *      will be applied to DC instances, if one has been set.
 *
 *****************************************************************************/
Cpa32U getDcInstanceCoalescingTimer(void);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      isDcInstanceCoalescingTimerConfigured
 *
 * @description
 *      Returns whether a coalescing timer value has been explicitly
 *      configured, indicating that the QAT library default should be
 *      overridden.
 *
 *****************************************************************************/
CpaBoolean isDcInstanceCoalescingTimerConfigured(void);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      clearDcInstanceCoalescingTimerConfiguration
 *
 * @description
 *      Clears any explicitly configured coalescing timer, allowing the QAT
 *      library default to be used again.
 *
 *****************************************************************************/
CpaStatus clearDcInstanceCoalescingTimerConfiguration(void);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      setDcInstanceCoalescingTimerMask
 *
 * @description
 *      Sets a 64-bit mask to control which DC instances should have the
 *      configured coalescing timer applied (supports up to 64 instances).
 *
 * @param[in]  mask  64-bit bitmask indicating which instances to configure
 *
 *****************************************************************************/
void setDcInstanceCoalescingTimerMask(Cpa64U mask);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      getDcInstanceCoalescingTimerMask
 *
 * @description
 *      Returns the current 64-bit mask that controls which DC instances will
 *      have the configured coalescing timer applied.
 *
 *****************************************************************************/
Cpa64U getDcInstanceCoalescingTimerMask(void);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      configureDcInstanceCoalescingTimerForAll
 *
 * @description
 *      Convenience function that configures the specified coalescing timer
 *      for all available DC instances (up to 64).
 *
 * @param[in]  coalescingTimerInNs  Coalescing timer value in nanoseconds
 *
 *****************************************************************************/
CpaStatus configureDcInstanceCoalescingTimerForAll(Cpa32U coalescingTimerInNs);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      configureDcInstanceCoalescingTimerForHalf
 *
 * @description
 *      Convenience function that configures the specified coalescing timer
 *      for half of the available DC instances.
 *
 * @param[in]  coalescingTimerInNs  Coalescing timer value in nanoseconds
 *
 *****************************************************************************/
CpaStatus configureDcInstanceCoalescingTimerForHalf(Cpa32U coalescingTimerInNs);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      getDcInstanceRxInterruptMetaData
 *
 * @description
 *      Wrapper around cpaInstanceGetRxInterruptMetaData() for DC instances.
 *      Returns the currently-configured coalescing timer along with the
 *      maximum supported value and granularity.
 *
 * @param[in]   instanceHandle  DC instance handle
 * @param[out]  pInterruptData  Pointer to a CpaRxInterruptMetaData structure
 *                              that will receive the values
 *
 *****************************************************************************/
CpaStatus getDcInstanceRxInterruptMetaData(
    CpaInstanceHandle instanceHandle,
    CpaRxInterruptMetaData *pInterruptData);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      applyDcInstanceCoalescingTimerConfiguration
 *
 * @description
 *      Applies the configured coalescing timer value to the actual DC
 *      instances based on the current mask and configuration. After setting
 *      the timer on each masked instance the value is read back via
 *      cpaInstanceGetRxInterruptMetaData() and verified (taking the
 *      hardware-reported granularity into account). This should be called
 *      after DC services are started but before polling threads are created.
 *
 *****************************************************************************/
CpaStatus applyDcInstanceCoalescingTimerConfiguration(void);
#endif /* USER_SPACE && SUPPORTED_FEAT_INT_COALESCING_TIMER && STV_TEST_CODE   \
        */

/* Instance selection functions - supports up to 64 instances */
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Set the response mode mask for DC instances
 *
 * @description
 *      This function sets a 64-bit mask to control which DC instances should
 *      use the configured response mode. Each bit in the mask corresponds to
 *      an instance index (supports up to 64 instances).
 *
 * @param[in]  mask    64-bit bitmask indicating which instances to apply
 * response mode
 *
 *****************************************************************************/
void setDcInstanceResponseModeMask(Cpa64U mask);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Get the current response mode mask for DC instances
 *
 * @description
 *      This function returns the current 64-bit bitmask that controls which
 *      DC instances will use the configured response mode.
 *
 * @retval Cpa64U   Current instance response mode mask
 *
 *****************************************************************************/
Cpa64U getDcInstanceResponseModeMask(void);
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Configure response mode for all available DC instances
 *
 * @description
 *      This is a convenience function that explicitly configures the specified
 *      response mode for all available DC instances (up to 64), overriding
 *      the QAT library's default. This should be called at the application
 *      level before starting performance tests only when you need to override
 *      the library's default behavior.
 *
 * @param[in]  responseMode    The response mode to apply to all instances
 *
 *****************************************************************************/
CpaStatus configureDcInstanceResponseModeForAll(
    CpaInstanceResponseMode responseMode);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Configure response mode for all available DC instances
 *
 * @description
 *      This is a convenience function that explicitly configures the specified
 *      response mode for half of the available DC instances (up to 64),
 * overriding the QAT library's default. This should be called at the
 * application level before starting performance tests only when you need to
 * override the library's default behavior.
 *
 * @param[in]  responseMode    The response mode to apply to all instances
 *
 *****************************************************************************/
CpaStatus configureDcInstanceResponseModeForHalf(
    CpaInstanceResponseMode responseMode);

/* Response mode iteration functions for data path testing */
/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Set the iteration count for response mode alternation
 *
 * @description
 *      This function sets the number of iterations for response mode
 * alternation in the data path. Used for testing response mode switching
 * behavior. Default is 1 (no iteration).
 *
 * @param[in]  count    Number of iterations to perform
 *
 * @retval CPA_STATUS_SUCCESS   Successfully set iteration count
 * @retval CPA_STATUS_FAIL      Failed to set iteration count
 *
 *****************************************************************************/
CpaStatus setDcResponseModeIterationCount(Cpa32U count);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Get the current iteration count for response mode alternation
 *
 * @description
 *      This function returns the current number of iterations configured
 *      for response mode alternation.
 *
 * @param[out] count    Pointer to store the current iteration count
 *
 * @retval CPA_STATUS_SUCCESS   Successfully retrieved iteration count
 * @retval CPA_STATUS_FAIL      Invalid parameter (NULL pointer)
 *
 *****************************************************************************/
CpaStatus getDcResponseModeIterationCount(Cpa32U *count);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Get response mode with iteration for data path
 *
 * @description
 *      This function returns the response mode after performing n iterations
 *      starting from the currentResponseMode in the test parameters. Each
 *      iteration alternates between the initial mode (from test params) and
 *      its opposite. If iteration count is 1 (default), returns the current
 *      response mode unchanged.
 *
 * @param[in]  testParams  Test parameters containing currentResponseMode
 *
 * @retval CpaInstanceResponseMode   Response mode after iteration
 *
 *****************************************************************************/
CpaInstanceResponseMode getDcResponseModeWithIteration(
    compression_test_params_t *testParams);

/**
 *****************************************************************************
 * @ingroup compressionThreads
 *      Enable or disable response mode iteration
 *
 * @description
 *      Convenience function to enable response mode iteration in the data path.
 *      Set count > 1 to enable iteration, or count = 1 to disable (default).
 *
 * @param[in]  count    Number of iterations (1 = disabled, >1 = enabled)
 *
 * @retval CPA_STATUS_SUCCESS   Successfully configured iteration count
 * @retval CPA_STATUS_FAIL      Failed to configure iteration count
 *
 *****************************************************************************/
CpaStatus enableDcResponseModeIteration(Cpa32U count);
#endif /* USER_SPACE && SUPPORTED_FEAT_EPOLL && STV_TEST_CODE */

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  sampleRemoveDcDpSession
 *
 *  @description
 *      This function check and removes the compression session.
 *
 *  @param[out] status
 *
 *  @param[in]  dcInstance      Instance handle
 *  @param[in]  pSessionHandle  Session handle
 *
 ******************************************************************************/
CpaStatus sampleRemoveDcDpSession(CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle);

CpaStatus getDcCapabilityStatusForAlg(CpaInstanceHandle dcInstance,
                                      Cpa32U capId,
                                      CpaDcCompType algorithm,
                                      CpaDcSessionDir direction,
                                      CpaBoolean *pCapStatus);
#endif /* CPA_SAMPLE_CODE_DC_UTILS_H_ */
