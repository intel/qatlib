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

/* Maximum number of intermediate buffers SGLs for devices
 * with a maximum of 6 compression slices */
#define DC_QAT_MAX_NUM_INTER_BUFFERS_6COMP_SLICES (12)

/* Maximum number of intermediate buffers SGLs for devices
 * with a maximum of 10 max compression slices */
#define DC_QAT_MAX_NUM_INTER_BUFFERS_10COMP_SLICES (20)

/* Maximum number of intermediate buffers SGLs for devices
 * with a maximum of 8 compression slices and 24 AEs */
#define DC_QAT_MAX_NUM_INTER_BUFFERS_8COMP_SLICES (48)

/* Maximum number of intermediate buffers SGLs for devices
 * with a maximum of 4 max compression slices and 12 AEs */
#define DC_QAT_MAX_NUM_INTER_BUFFERS_4COMP_SLICES (24)

/* Maximum number of intermediate buffers SGLs for devices
 * with a maximum of 12 max compression slices and 32 AEs */
#define DC_QAT_MAX_NUM_INTER_BUFFERS_12COMP_SLICES (64)

/* Maximum size of the state registers decompression 128 bytes */
#define DC_QAT_DCPR_STATE_REGISTERS_MAX_SIZE (128)

/* Maximum size of the state registers compression 64 bytes
 * for legacy devices and not for CPM2.0 as it
 * does not support stateful compression */
#define DC_QAT_CPR_STATE_REGISTERS_MAX_SIZE (64)

/* Size of the history window.
 * Base 2 logarithm of maximum window size minus 8 */
#define DC_4K_WINDOW_SIZE (4)
#define DC_8K_WINDOW_SIZE (5)
#define DC_16K_WINDOW_SIZE (6)
#define DC_32K_WINDOW_SIZE (7)

/* Context size */
#define DC_DEFLATE_MAX_CONTEXT_SIZE (49152)
#define DC_INFLATE_CONTEXT_SIZE (36864)
#define DC_LZ4_DECOMP_CONTEXT_SIZE (32768)
#define DC_DEFLATE_EH_MAX_CONTEXT_SIZE (65536)
#define DC_DEFLATE_EH_MIN_CONTEXT_SIZE (49152)
#define DC_INFLATE_EH_CONTEXT_SIZE (34032)

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
            Cpa64U iCrc64Xlt;
            /* CRC64 checksum returned for input data to translator accelerator
             */
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

#endif /* DC_SESSION_H */
