/****************************************************************************
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
 * @file dc_session.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression session parameters.
 *
 *****************************************************************************/
#ifndef DC_SESSION_H
#define DC_SESSION_H

#include "cpa_dc_dp.h"
#include "icp_qat_fw_comp.h"
#include "sal_qat_cmn_msg.h"
#include "sal_types_compression.h"

/* Maximum size of the state registers decompression 128 bytes */
#define DC_QAT_DCPR_STATE_REGISTERS_MAX_SIZE (128)

/* Maximum size of the state registers compression 64 bytes
 * for legacy devices and not for CPM2.0 as it
 * does not support stateful compression */
#define DC_QAT_CPR_STATE_REGISTERS_MAX_SIZE (64)

/* Retrieve the session descriptor pointer from the session context structure
 * that the user allocates. The pointer to the internally realigned address
 * is stored at the start of the session context that the user allocates */
#define DC_SESSION_DESC_FROM_CTX_GET(pSession)                                 \
    (dc_session_desc_t *)(*(LAC_ARCH_UINT *)pSession)

/* Maximum size for the compression part of the content descriptor */
#define DC_QAT_COMP_CONTENT_DESC_SIZE sizeof(icp_qat_fw_comp_cd_hdr_t)

/* Maximum size for the translator part of the content descriptor */
#define DC_QAT_TRANS_CONTENT_DESC_SIZE                                         \
    (sizeof(icp_qat_fw_xlt_cd_hdr_t) + DC_QAT_MAX_TRANS_SETUP_BLK_SZ)

/* Maximum size of the decompression content descriptor */
#define DC_QAT_CONTENT_DESC_DECOMP_MAX_SIZE                                    \
    LAC_ALIGN_POW2_ROUNDUP(DC_QAT_COMP_CONTENT_DESC_SIZE,                      \
                           (1 << LAC_64BYTE_ALIGNMENT_SHIFT))

/* Maximum size of the compression content descriptor */
#define DC_QAT_CONTENT_DESC_COMP_MAX_SIZE                                      \
    LAC_ALIGN_POW2_ROUNDUP(DC_QAT_COMP_CONTENT_DESC_SIZE +                     \
                               DC_QAT_TRANS_CONTENT_DESC_SIZE,                 \
                           (1 << LAC_64BYTE_ALIGNMENT_SHIFT))

/* Xxhash32 accumulator initialisers */
#define XXHASH_PRIME32_A 0x9E3779B1U
#define XXHASH_PRIME32_B 0x85EBCA77U

/* Direction of the request */
typedef enum dc_request_dir_e
{
    DC_COMPRESSION_REQUEST = 1,
    DC_DECOMPRESSION_REQUEST
} dc_request_dir_t;

/* Type of the compression request */
typedef enum dc_request_type_e
{
    DC_REQUEST_FIRST = 1,
    DC_REQUEST_SUBSEQUENT
} dc_request_type_t;

typedef enum dc_block_type_e
{
    DC_CLEARTEXT_TYPE = 0,
    DC_STATIC_TYPE,
    DC_DYNAMIC_TYPE
} dc_block_type_t;

/* Type of ASB modes */
typedef enum dc_asb_mode_e
{
    DC_ASB_THRESHOLD_MODE = 0,
    /* ASB Threshold mode */
    DC_ASB_RATIO_MODE = 1,
    /* ASB Ratio mode */
} dc_asb_mode_t;

/* ASB Max block size */
#define DC_ASB_MAX_BLOCK_SIZE 65536

/* Internal data structure supporting end to end data integrity checks. */
typedef struct dc_integrity_crc_fw_s
{
    Cpa32U crc32;
    /* CRC32 checksum returned for compressed data */
    union {
        Cpa32U adler32;
        /* ADLER32 checksum returned for compressed data */
        Cpa32U xxhash32;
        /* XXHASH32 checksum returned for compressed data */
    };

    union {
        struct
        {
            Cpa32U oCrc32Cpr;
            /* CRC32 checksum returned for data output by compression
             * accelerator */
            Cpa32U iCrc32Cpr;
            /* CRC32 checksum returned for input data to compression accelerator
             */
            Cpa32U oCrc32Xlt;
            /* CRC32 checksum returned for data output by translator accelerator
             */
            Cpa32U iCrc32Xlt;
            /* CRC32 checksum returned for input data to translator accelerator
             */
            Cpa32U xorFlags;
            /* Initialise transactor pCRC controls in state register */
            Cpa32U crcPoly;
            /* CRC32 polynomial used by hardware */
            Cpa32U xorOut;
            /* CRC32 from XOR stage (Input CRC is xor'ed with value in the
             * state) */
            Cpa32U deflateBlockType;
            /* Bit 1 - Bit 0
             *   0        0 -> RAW DATA + Deflate header.
             *                 This will not produced any CRC check because
             *                 the output will not come from the slices.
             *                 It will be a simple copy from input to output
             *                 buffers list.
             *   0        1 -> Static deflate block type
             *   1        0 -> Dynamic deflate block type
             *   1        1 -> Invalid type */
        };

        struct
        {
            Cpa64U iCrc64Cpr;
            /* CRC64 checksum returned for input data to compression accelerator
             */
            Cpa64U oCrc64Cpr;
            /* CRC64 checksum returned for data output by compression
             * accelerator */
            Cpa32U reflectIn;
            /* Flag to indicate if the input should be reflected */
            Cpa32U reflectOut;
            /* Flag to indicate if the output should be reflected */
            Cpa64U oCrc64Xlt;
            /* CRC64 checksum returned for data output by translator accelerator
             */
            Cpa64U crc64Poly;
            /* CRC64 polynomial used by hardware */
            Cpa64U xor64Out;
            /* CRC64 from XOR stage (Input CRC is xor'ed with value in the
             * state) */
            Cpa64U xor64Mask;
            /* XOR mask used by XOR stage */
        };
    };
} dc_integrity_crc_fw_t;

typedef struct dc_sw_checksums_s
{
    union {
        struct
        {
            Cpa32U swCrc32I;
            Cpa32U swCrc32O;
        };

        struct
        {
            Cpa64U swCrc64I;
            Cpa64U swCrc64O;
        };
    };
} dc_sw_checksums_t;

/* Configuration data for CRC operation */
typedef struct dc_crc_config_s
{
    dc_integrity_crc_fw_t crcParam;
    /**< Crc parameters for firmware */
    Cpa64U *pCrcLookupTable;
    /**< Lookup table to speed up CRC calculation at runtime */
    CpaBoolean useProgCrcSetup;
    /**< Flag to indicate if programmable CRC parameters used */
} dc_crc_config_t;

/* Session descriptor structure for compression */
typedef struct dc_session_desc_s
{
    Cpa8U stateRegistersComp[DC_QAT_CPR_STATE_REGISTERS_MAX_SIZE];
    /**< State registers for compression */
    Cpa8U stateRegistersDecomp[DC_QAT_DCPR_STATE_REGISTERS_MAX_SIZE];
    /**< State registers for decompression */
    icp_qat_fw_comp_req_t reqCacheComp;
    /**< Cache as much as possible of the compression request in a pre-built
     * request */
    icp_qat_fw_comp_req_t reqCacheDecomp;
    /**< Cache as much as possible of the decompression request in a pre-built
     * request */
    dc_request_type_t requestType;
    /**< Type of the compression request. As stateful mode do not support more
     * than one in-flight request there is no need to use spinlocks */
    dc_request_type_t previousRequestType;
    /**< Type of the previous compression request. Used in cases where there the
     * stateful operation needs to be resubmitted */
    CpaDcHuffType huffType;
    /**< Huffman tree type */
    CpaDcCompType compType;
    /**< Compression type */
    CpaDcChecksum checksumType;
    /**< Type of checksum */
    CpaDcAutoSelectBest autoSelectBestHuffmanTree;
    /**< Indicates if the implementation selects the best Huffman encoding */
    CpaDcSessionDir sessDirection;
    /**< Session direction */
    CpaDcSessionState sessState;
    /**< Session state */
    Cpa32U deflateWindowSize;
    /**< Window size */
    CpaDcCompLvl compLevel;
    /**< Compression level */
    CpaDcCompLZ4BlockMaxSize lz4BlockMaxSize;
    /**<Window size from CpaDcCompLZ4BlockMaxSize */
    CpaDcCompMinMatch minMatch;
    /**< Min Match size from CpaDcCompMinMatch */
    CpaDcCallbackFn pCompressionCb;
    /**< Callback function defined for the traditional compression session */
    OsalAtomic pendingStatelessCbCount;
    /**< Keeps track of number of pending requests on stateless session */
    OsalAtomic pendingStatefulCbCount;
    /**< Keeps track of number of pending requests on stateful session */
    Cpa64U pendingDpStatelessCbCount;
    /**< Keeps track of number of data plane pending requests on stateless
     * session */
    lac_lock_t sessionLock;
    /**< Lock used to provide exclusive access for number of stateful in-flight
     * requests update */
    CpaBoolean isDcDp;
    /**< Indicates if the data plane API is used */
    Cpa32U minContextSize;
    /**< Indicates the minimum size required to allocate the context buffer */
    CpaBufferList *pContextBuffer;
    /**< Context buffer */
    Cpa32U historyBuffSize;
    /**< Size of the history buffer */
    Cpa64U cumulativeConsumedBytes;
    /**< Cumulative amount of consumed bytes. Used to build the footer in the
     * stateful case */
    CpaBoolean isSopForCompressionProcessed;
    /**< Indicates whether a Compression Request is received in this session */
    CpaBoolean isSopForDecompressionProcessed;
    /**< Indicates whether a Decompression Request is received in this session
     */
    lac_lock_t updateLock;
    /**< Lock used to provide exclusive access for updating the session
     * parameters */
    /* Flag to disable or enable CnV Error Injection mechanism */
    CpaBoolean cnvErrorInjection;
    /**< Flag to disable or enable CnV Error Injection mechanism */
    CpaBoolean accumulateXXHash;
    /**< xxHash calculation accumulated across requests */
    CpaBoolean lz4BlockChecksum;
    /**< Support block checksum during LZ4 decompression */
    CpaBoolean lz4BlockIndependence;
    /**< If set LZ4 blocks will be independent, if reset each block
     * depends on the previous ones and must be decompressed sequentially */
    Cpa32U asb_value;
    /**< Indicates the asb value to be programmed in the firmware interface.
     * if the compressed size is more than the asb value,
     * it produces cleartext */
    Cpa32U asb_max_block_size;
    /**< Indicates the maximum value which can be configured */
    dc_asb_mode_t asb_mode;
    /**< Indicates the asb mode to be used */
    dc_crc_config_t crcConfig;
    /**< Configuration data for CRC operation */
    CpaDcLZ4OutputFormat lz4OutputFormat;
    /**< LZ4 block header mode */
} dc_session_desc_t;

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Initialise a compression session
 *
 * @description
 *      This function will initialise a compression session
 *
 * @param[in]       dcInstance       Instance handle derived from discovery
 *                                   functions
 * @param[in,out]   pSessionHandle   Pointer to a session handle
 * @param[in,out]   pSessionData     Pointer to a user instantiated structure
 *                                   containing session data
 * @param[in]       pContextBuffer   Pointer to context buffer
 *
 * @param[in]       callbackFn       For synchronous operation this callback
 *                                   shall be a null pointer
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESOURCE       Error related to system resources
 *****************************************************************************/
CpaStatus dcInitSession(CpaInstanceHandle dcInstance,
                        CpaDcSessionHandle pSessionHandle,
                        CpaDcSessionSetupData *pSessionData,
                        CpaBufferList *pContextBuffer,
                        CpaDcCallbackFn callbackFn);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Get the size of the memory required to hold the session information
 *
 * @description
 *      This function will get the size of the memory required to hold the
 *      session information
 *
 * @param[in]       dcInstance       Instance handle derived from discovery
 *                                   functions
 * @param[in]       pSessionData     Pointer to a user instantiated structure
 *                                   containing session data
 * @param[out]      pSessionSize     On return, this parameter will be the size
 *                                   of the memory that will be
 *                                   required by cpaDcInitSession() for session
 *                                   data.
 * @param[out]      pContextSize     On return, this parameter will be the size
 *                                   of the memory that will be required
 *                                   for context data.  Context data is
 *                                   save/restore data including history and
 *                                   any implementation specific data that is
 *                                   required for a save/restore operation.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *****************************************************************************/
CpaStatus dcGetSessionSize(CpaInstanceHandle dcInstance,
                           CpaDcSessionSetupData *pSessionData,
                           Cpa32U *pSessionSize,
                           Cpa32U *pContextSize);

#ifdef ICP_DC_ERROR_SIMULATION
/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Set the cnvErrorInjection flag in session descriptor
 *
 * @description
 *      This function enables the CnVError injection for the session
 *      passed in. All Compression requests sent within the session
 *      are injected with CnV errors. This error injection is for the
 *      duration of the session. Resetting the session results in
 *      setting being cleared. CnV error injection does not apply to
 *      Data Plane API.
 *
 * @param[in]       dcInstance       Instance Handle
 * @param[in]       pSessionHandle   Pointer to a session handle
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported feature
 *****************************************************************************/
CpaStatus dcSetCnvError(CpaInstanceHandle dcInstance,
                        CpaDcSessionHandle pSessionHandle);
#endif /* ICP_DC_ERROR_SIMULATION */

#ifdef ICP_PARAM_CHECK
/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check that pSessionData is valid
 *
 * @description
 *      Check that all the parameters defined in the pSessionData are valid
 *
 * @param[in]       pSessionData     Pointer to a user instantiated structure
 *                                   containing session data
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported algorithm/feature
 *
 *****************************************************************************/
CpaStatus dcCheckSessionData(const CpaDcSessionSetupData *pSessionData,
                             CpaInstanceHandle dcInstance);
#endif

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Set the xxhash state to its init state
 *
 * @description
 *      This function initialises the xxhash state buffer.
 *      When a new request is created the state will be initialised,
 *      when a request is sent using the CPA_DC_FLUSH_FINAL flag
 *      the state will be automatically reset using this function.
 *
 * @param[in]       pSessionDesc     Pointer to the session descriptor
 * @param[in]       seed             Seed value for input to xxhash state
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *****************************************************************************/
CpaStatus dcXxhash32SetState(dc_session_desc_t *pSessionDesc, Cpa32U seed);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Get the compression command id for the given session setup data.
 *
 * @description
 *      This function will get the compression command id based on parameters
 *      passed in the given session setup data.
 *
 * @param[in]   pService           Pointer to the service
 * @param[in]   pSessionData       Pointer to a user instantiated
 *                                 structure containing session data
 * @param[out]  pDcCmdId           Pointer to the command id
 *
 * @retval CPA_STATUS_SUCCESS      Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED  Unsupported algorithm/feature
 *
 *****************************************************************************/
CpaStatus dcGetCompressCommandId(sal_compression_service_t *pService,
                                 CpaDcSessionSetupData *pSessionData,
                                 Cpa8U *pDcCmdId);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Get the decompression command id for the given session setup data.
 *
 * @description
 *      This function will get the decompression command id based on parameters
 *      passed in the given session setup data.
 *
 * @param[in]   pService           Pointer to the service
 * @param[in]   pSessionData       Pointer to a user instantiated
 *                                 structure containing session data
 * @param[out]  pDcCmdId           Pointer to the command id
 *
 * @retval CPA_STATUS_SUCCESS      Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED  Unsupported algorithm/feature
 *
 *****************************************************************************/
CpaStatus dcGetDecompressCommandId(sal_compression_service_t *pService,
                                   CpaDcSessionSetupData *pSessionData,
                                   Cpa8U *pDcCmdId);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the translator content descriptor
 *
 * @description
 *      This function will populate the translator content descriptor
 *
 * @param[out]  pMsg                     Pointer to the compression message
 * @param[in]   nextSlice                Next slice
 *
 *****************************************************************************/
void dcTransContentDescPopulate(icp_qat_fw_comp_req_t *pMsg,
                                icp_qat_fw_slice_t nextSlice);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression hardware block for QAT Gen4
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      for QAT Gen4 the size in bytes of the block
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pSetupData              Pointer to setup data
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 * @param[in]   bNsOp                   Boolean to indicate no session operation
 *
 *****************************************************************************/
void dcCompHwBlockPopulateGen4(void *pService,
                               void *pSessionDesc,
                               CpaDcNsSetupData *pSetupData,
                               icp_qat_hw_compression_config_t *pCompConfig,
                               void *compDecomp,
                               CpaBoolean bNsOp);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression hardware block for QAT Gen2
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      for QAT Gen2 the size in bytes of the block
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pSetupData              Pointer to setup data
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 * @param[in]   bNsOp                   Boolean to indicate no session operation
 *
 *****************************************************************************/
void dcCompHwBlockPopulate(void *pService,
                           void *pSessionDesc,
                           CpaDcNsSetupData *pSetupData,
                           icp_qat_hw_compression_config_t *pCompConfig,
                           void *compDecomp,
                           CpaBoolean bNsOp);

/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Populate the compression hardware block for QAT Gen2
 *
 * @description
 *      This function will populate the compression hardware block and update
 *      for QAT Gen2 the size in bytes of the block
 *
 * @param[in]   pService                Pointer to the service
 * @param[in]   pSessionDesc            Pointer to the session descriptor
 * @param[in]   pSetupData              Pointer to setup data
 * @param[in]   pCompConfig             Pointer to slice config word
 * @param[in]   compDecomp              Direction of the operation
 * @param[in]   bNsOp                   Boolean to indicate no session operation
 *
 *****************************************************************************/
void dcNsCompHwBlockPopulate(void *pService,
                             void *pSessionDesc,
                             CpaDcNsSetupData *pSetupData,
                             icp_qat_hw_compression_config_t *pCompConfig,
                             void *compDecomp,
                             CpaBoolean bNsOp);

CpaStatus dcDeflateBoundGen2(void *pServiceType,
                             CpaDcHuffType huffType,
                             Cpa32U inputSize,
                             Cpa32U *outputSize);

CpaStatus dcDeflateBoundGen4(void *pServiceType,
                             CpaDcHuffType huffType,
                             Cpa32U inputSize,
                             Cpa32U *outputSize);

CpaStatus dcLZ4BoundGen4(Cpa32U inputSize, Cpa32U *outputSize);
CpaStatus dcLZ4SBoundGen4(Cpa32U inputSize, Cpa32U *outputSize);
/**
 *****************************************************************************
 * @ingroup Dc_DataCompression
 *      Check that pCrcControlData is valid
 *
 * @description
 *      Check that all the parameters defined in the pCrcControlData are valid
 *
 * @param[in]       pCrcControlData   Pointer to a user instantiated structure
 *                                    containing session CRC control data.
 *
 * @retval CPA_STATUS_SUCCESS         Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM   Invalid parameter passed in
 *
 *****************************************************************************/
CpaStatus dcCheckSessionCrcControlData(
    const CpaCrcControlData *pCrcControlData);

#endif /* DC_SESSION_H */
