/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file cpa_dc_capabilities.h
 *
 * @defgroup cpaDcCap Capability APIs for Data Compression
 *
 * @ingroup cpaDc
 *
 * @description
 *      This file specifies the API for Data Compression capability queries.
 *
 * @remarks
 *
 *
 *****************************************************************************/

#ifndef CPA_DC_CAPABILITIES_H
#define CPA_DC_CAPABILITIES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa.h"
#include "cpa_dc.h"

/**
 *****************************************************************************
 * @ingroup cpaDcCap
 *      Capability IDs
 *
 * @description
 *      This enumeration lists the capabilities that can be queried
 *      using cpaDcQueryCapabilityByType() API.
 *
 *****************************************************************************/
typedef enum
{
    CPA_DC_CAP_BOOL_STATELESS = 0,
    /**< Support for specified algorithm for a stateless session */
    CPA_DC_CAP_BOOL_STATEFUL = 1,
    /**< Support for specified algorithm for a stateful session */
    CPA_DC_CAP_BOOL_STATEFUL_LITE = 2,
    /**< Check if stateful lite is supported */
    CPA_DC_CAP_BOOL_WINDOW_SIZE_4K = 3,
    /**< Support for 4K window size */
    CPA_DC_CAP_BOOL_WINDOW_SIZE_8K = 4,
    /**< Support for 8K window size */
    CPA_DC_CAP_BOOL_WINDOW_SIZE_16K = 5,
    /**< Support for 16K window size */
    CPA_DC_CAP_BOOL_WINDOW_SIZE_32K = 6,
    /**< Support for 32K window size */
    CPA_DC_CAP_BOOL_WINDOW_SIZE_64K = 7,
    /**< Support for 64K window size */
    CPA_DC_CAP_U32_DEFAULT_WINDOW_SIZE = 8,
    /**< Fetch the default supported window size */
    CPA_DC_CAP_BOOL_DYNAMIC_HUFFMAN = 9,
    /**< Support for Dynamic Huffman Tree Deflate algorithm */
    CPA_DC_CAP_BOOL_STATIC_HUFFMAN = 10,
    /**< Support for Static Huffman Tree Deflate algorithm */
    CPA_DC_CAP_BOOL_BLOCK_CHECKSUM = 11,
    /**< Support for block checksum generation */
    CPA_DC_CAP_BOOL_ACCUMULATE_XXHASH = 12,
    /**< Check if algorithm can accumulate xxHash */
    CPA_DC_CAP_BOOL_BLOCK_SIZE_64K = 13,
    /**< Check if algorithm supports 64K block size */
    CPA_DC_CAP_BOOL_BLOCK_SIZE_256K = 14,
    /**< Check if algorithm supports 256K block size */
    CPA_DC_CAP_BOOL_BLOCK_SIZE_1M = 15,
    /**< Check if algorithm supports 1M block size */
    CPA_DC_CAP_BOOL_BLOCK_SIZE_4M = 16,
    /**< Check if algorithm supports 4M block size */
    CPA_DC_CAP_U32_BLOCK_SIZE_BITMASK = 17,
    /**< Bitmask of supported block sizes, enum CpaDcBlockSizeBitmask */
    CPA_DC_CAP_BOOL_CHECKSUM_CRC32 = 18,
    /**< Check if CRC32 checksum is supported */
    CPA_DC_CAP_BOOL_CHECKSUM_ADLER32 = 19,
    /**< Check if Adler32 checksum is supported */
    CPA_DC_CAP_BOOL_CHECKSUM_XXHASH32 = 20,
    /**< Check if XXHash32 checksum is supported */
    CPA_DC_CAP_BOOL_CHECKSUM_XXHASH64 = 21,
    /**< Check if XXHash64 checksum is supported */
    CPA_DC_CAP_BOOL_ASB = 22,
    /**< Check if Auto Select Best is supported.
     * Compression direction only */
    CPA_DC_CAP_BOOL_ASB_THRESHOLD = 23,
    /**< Check if Auto Select Best with threshold is supported.
     * Compression direction only */
    CPA_DC_CAP_BOOL_ASB_RATIO = 24,
    /**< Check if Auto Select Best with ratio is supported.
     * Compression direction only */
    CPA_DC_CAP_BOOL_ASB_ENABLE_PREFERRED = 25,
    /**< Check if it is preferred to keep ASB enabled for the requested
       compression algorithm */
    CPA_DC_CAP_BOOL_DETERMINISM = 26,
    /**< Check if Determinism is supported with compression operation */
    CPA_DC_CAP_BOOL_OVERFLOW_RESUBMIT = 27,
    /**< Check if resubmission of (un)compressed data is supported */
    CPA_DC_CAP_BOOL_COMPRESS_N_VERIFY = 28,
    /**< Check if "compress and verify" error reporting is supported */
    CPA_DC_CAP_BOOL_COMPRESS_N_VERIFY_N_RECOVER = 29,
    /**< Check if instance can produce an uncompressed block in the event of
       "compress and verify" error. */
    CPA_DC_CAP_BOOL_INTEGRITY_CRC32 = 30,
    /**< Check if integrity CRC32 checksum is supported */
    CPA_DC_CAP_BOOL_INTEGRITY_CRC64 = 31,
    /**< Check if integrity CRC64 checksum is supported */
    CPA_DC_CAP_BOOL_CHAIN_HASH_THEN_COMPRESS = 32,
    /**< Check if chain hash then compress is supported */
    CPA_DC_CAP_BOOL_CHAIN_COMPRESS_THEN_AEAD = 33,
    /**< Check if chain compress then aead is supported */
    CPA_DC_CAP_BOOL_CHAIN_AEAD_THEN_DECOMPRESS = 34,
    /**< Check if chain aead then decompress is supported */
    CPA_DC_CAP_BOOL_UNCOMPRESSED_DICT = 35,
    /**< Check if the algorithm supports compression or decompression using an
       uncompressed dictionary */
    CPA_DC_CAP_BOOL_COMPRESSED_DICT = 36,
    /**< Check if the algorithm supports compression or decompression using a
       compressed dictionary */
    CPA_DC_CAP_BOOL_ZERO_LENGTH_REQ = 37,
    /**< Check if submission of zero length requests is supported */
    CPA_DC_CAP_BOOL_PROGRAMMABLE_CRC64 = 38,
    /**< Check if programmable CRC64 is supported */
    CPA_DC_CAP_BOOL_CHAIN_PROGRAMMABLE_CRC64 = 39,
    /**< Check if programmable CRC64 with chaining is supported */
    CPA_DC_CAP_BOOL_E2E_CRC_OVER_COMP_BLOCK = 40,
    /**< Check if E2E CRC is supported over compressed block. This capability
       is only applicable in compression direction. */
    CPA_DC_CAP_BOOL_DICT_ID = 41,
    /**< Support for dictionary ID */
} CpaDcCapabilityId;

/**
 *****************************************************************************
 * @ingroup cpaDcCap
 *      Implementation of the Capability Request structure
 * @description
 *      This structure lists the parameters required for querying capabilities
 * @note
 *      All parameters must be set unless otherwise stated in the
 *      CpaDcCapabilityId capId comment
 *
 ****************************************************************************/
typedef struct
{
    CpaDcCompType algo;
    /**< Algorithm ID from CpaDcCompType being queried */
    CpaDcDir dir;
    /**< Algorithm direction from CpaDcDir being queried.
     * Only COMPRESS and DECOMPRESS directions are supported. */
    CpaDcCapabilityId capId;
    /**< Capability ID from CpaDcCapabilityId being queried */
} CpaDcCapabilityReq;

/**
 *****************************************************************************
 * @ingroup cpaDcCap
 *      Implementation of the Capability Response parameter
 * @description
 *      This union lists the various response types that are supported by the
 *      cpaDcQueryCapabilityByType() API.
 *
 ****************************************************************************/
typedef union {
    CpaBoolean boolStatus;
    /**< A boolean value in response to a capability query with capId name
     * CPA_DC_CAP_BOOL_XXX */
    Cpa32U u32Status;
    /**< A 32bit value in response to a capability query with capId name
     * CPA_DC_CAP_U32_XXX */
    Cpa64U u64Status;
    /**< A 64bit value in response to a capability query with capId name
     * CPA_DC_CAP_U64_XXX */
} CpaDcCapabilityResp;

/**
 *****************************************************************************
 * @ingroup cpaDcCap
 *      Query capabilities for a data compression instance
 *
 * @description
 *      This function is used to query the capabilities supported by a
 *      compression instance.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] dcInstance            Data compression instance handle
 * @param[in] capabilityReq         Request parameter of the type
 *                                  CpaDcCapabilityReq that will identify the
 *                                  capability that is being queried.
 * @param[in,out] pCapabilityResp   Pointer to a CpaDcCapabilityResp structure.
 *                                  On return the result of the query will be
 *                                  stored here.
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_UNSUPPORTED   The function is not supported, or a field
 *                                  in the request is above the top range of its
 *                                  enum. This API may be extended to include
 *                                  additional capability IDs or other
 *                                  algorithms. This return value should be
 *                                  understood as the capability is unknown,
 *                                  rather than that the capability is
 *                                  unsupported as the library cannot answer
 *                                  whether it has the capability or not.
 *
 * @pre
 *      None
 * @post
 *      None
 * @note
 *      This API will accept the capability request parameter that will identify
 *      the capability ID and the algorithm and the algorithm direction that is
 *      being queried. These parameters are used to fetch the instance
 *      capability. The value returned in CpaDcCapabilityResp should be
 *      interpreted based on the name of the capId, e.g. CPA_DC_CAP_BOOL_XXX
 *      will return boolStatus.
 * @see
 *      None
 *
 *****************************************************************************/
CpaStatus cpaDcQueryCapabilityByType(CpaInstanceHandle dcInstance,
                                     CpaDcCapabilityReq capabilityReq,
                                     CpaDcCapabilityResp *pCapabilityResp);
#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_DC_CAPABILITIES_H */
