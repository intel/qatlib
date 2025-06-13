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

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file dc_capabilities.h
 *
 * @defgroup dc_capabilities Capabilitites feature description for dc
 *
 * @ingroup LacCommon
 *
 * @description
 *      This file contains details of the new dc capabilities feature.
 *
 *****************************************************************************/

#ifndef DC_CAPABILITIES_H
#define DC_CAPABILITIES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa_dc.h"
#include "icp_qat_hw.h"

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      DC algo data bitfields
 * @description
 *      Data compression algorithms' data bitfields definitions
 *      to create sufficient place for features; used to create big enough
 *      tables of structs for supported algorithms
 *****************************************************************************/

/**< Deflate related definitions */
#define DC_CAPS_BF_DEFLATE_TYPE_SUPPORT (2) /**< deflate type support */

/**< LZ4 related definitions */

/**< LZ4 block size:
 * 0b0001: 64K
 * 0b0010: 256K
 * 0b0100: 1M
 * 0b1000: 4M
 */
#define DC_CAPS_BF_LZ4_MAXBLSIZE (4)

/**< LZ4s related definitions */

/**< min match sizes
 * 0b01: 3bytes
 * 0b10: 4bytes
 */
#define DC_CAPS_BF_MIN_MATCH (2)

/**< direction
 * 0b01: compression
 * 0b10: decompression
 */
#define DC_CAPS_BF_DIR (2)

/**< dictionary type
 * 0b01: un-compressed
 * 0b10: compressed
 */
#define DC_CAPS_BF_DICT (2)

/**< checksums
 * 0b0001: CRC32
 * 0b0010: ADLER32
 * 0b0100: XXHASH32
 * 0b1000: XXHASH64
 */
#define DC_CAPS_BF_CHECKSUM (4)

/**< ASB */
#define DC_CAPS_BF_ASB (3)       /**< ASB */
#define DC_CAPS_BF_ASB_TSH (3)   /**< ASB Threshold */
#define DC_CAPS_BF_ASB_RATIO (1) /**< ASB Ratio */

/**< session state
 * 0b01: stateful
 * 0b10: stateless
 */
#define DC_CAPS_BF_STATE (2)

/**< window size */
#define DC_CAPS_BF_WINSIZE (3)

/**< Values for setting capabilities */
#define DC_CAPS_COMPRESSION (0x1)
#define DC_CAPS_DECOMPRESSION (0x2)
#define DC_CAPS_CRC32 (0x1)
#define DC_CAPS_ADLER32 (0x2)
#define DC_CAPS_XXHASH32 (0x4)
#define DC_CAPS_XXHASH64 (0x8)
#define DC_CAPS_STATEFUL (0x1)
#define DC_CAPS_STATELESS (0x2)
#define DC_CAPS_LZ4_64K (0x1)
#define DC_CAPS_LZ4_256K (0x2)
#define DC_CAPS_LZ4_1M (0x4)
#define DC_CAPS_LZ4_4M (0x8)
#define DC_CAPS_LZ4S_3B (0x1)
#define DC_CAPS_LZ4S_4B (0x2)
#define DC_CAPS_UNCOMPRESSED_DICT (0x1)
#define DC_CAPS_COMPRESSED_DICT (0x2)
#define DC_CAPS_DEFLATE_SUPPORTED (0x1)
#define DC_CAPS_LZ4_SUPPORTED (0x4)
#define DC_CAPS_LZ4S_SUPPORTED (0x8)
#define DC_CAPS_PCRC (0x4)
#define DC_CAPS_DYNAMIC_HUFF_BUFF_REQ (0x400)
#define DC_CAPS_XXHASH32_OFFSET (1)
#define DC_CAPS_XXHASH64_OFFSET (2)
#define DC_CAPS_DYNAMIC_HUFF_OFFSET (10)
#define DC_CAPS_PCRC_OFFSET (2)
#define DC_CAPS_LZ4_OFFSET (2)
#define DC_CAPS_ADLER32_OFFSET (1)
#define DC_CAPS_PCRC_OFFSET (2)
#define DC_CAPS_LZ4S_OFFSET (3)
#define DC_CAPS_CNVNR_EXTENDED_OFFSET (8)

/* Restriction on the source buffer size for compression due to the firmware
 * processing */
#define DC_SRC_BUFFER_MIN_SIZE (15)

/* Restriction on the destination buffer size for compression due to
 * the management of skid buffers in the firmware */
#define DC_DEST_BUFFER_STA_MIN_SIZE (64)
#define DC_DEST_BUFFER_DYN_MIN_SIZE (128)
#define DC_DEST_BUFFER_DYN_MIN_SIZE_GEN4 (512)
/* Minimum destination buffer size for Gen4 is
 * 2 bytes + skid
 */
#define DC_DEST_BUFFER_STA_MIN_SIZE_GEN4 (1026)

/* Size of the history window.
 * Base 2 logarithm of maximum window size minus 8. Each bit represents a
 * possible window size. Note: In compression direction only one windows size
 * can be set based on the HW generation and the standard. */
#define DC_4K_WINDOW_SIZE (4)
#define DC_8K_WINDOW_SIZE (5)
#define DC_16K_WINDOW_SIZE (6)
#define DC_32K_WINDOW_SIZE (7)
#define DC_64K_WINDOW_SIZE (8)

#define DC_4K_WINDOW_MASK (1 << DC_4K_WINDOW_SIZE)
#define DC_8K_WINDOW_MASK (1 << DC_8K_WINDOW_SIZE)
#define DC_16K_WINDOW_MASK (1 << DC_16K_WINDOW_SIZE)
#define DC_32K_WINDOW_MASK (1 << DC_32K_WINDOW_SIZE)
#define DC_64K_WINDOW_MASK (1 << DC_64K_WINDOW_SIZE)

/* C4xxx device requires minimum 47 bytes for output buffer
 * size for static compression */
#define DC_DEST_BUFFER_MIN_SIZE (47)

/* Context size */
#define DC_DEFLATE_MAX_CONTEXT_SIZE (49152)
#define DC_INFLATE_CONTEXT_SIZE (36864)
#define DC_LZ4_DECOMP_CONTEXT_SIZE (32768)
#define DC_DEFLATE_EH_MAX_CONTEXT_SIZE (65536)
#define DC_DEFLATE_EH_MIN_CONTEXT_SIZE (49152)
#define DC_INFLATE_EH_CONTEXT_SIZE (34032)

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

/* Mask used to check the CompressAndVerify capability bit */
#define DC_CNV_EXTENDED_CAPABILITY (0x01)

/* Mask used to check the CompressAndVerifyAndRecover capability bit */
#define DC_CNVNR_EXTENDED_CAPABILITY (0x100)

/* Mask used to check chaining hash then compress capability bit */
#define DC_CHAIN_HASH_THEN_COMPRESS_EXTENDED_CAPABILITY (0x200000)

/* Mask used to check the LZ4 compress programmable CRC capability bit */
#define DC_LZ4_E2E_COMP_CRC_EXTENDED_CAPABILITY (0x20000000)

/* Mask used to check the LZ4 compress programmable CRC without LZ4 block header
 * capability bit */
#define DC_LZ4_E2E_COMP_CRC_OVER_BLOCK_EXTENDED_CAPABILITY (0x40000000)

typedef enum dc_bit_field_sizes
{
    DC_BITFIELD_SIZE_1 = 1,
    DC_BITFIELD_SIZE_2,
    DC_BITFIELD_SIZE_3,
    DC_BITFIELD_SIZE_4,
    DC_BITFIELD_SIZE_5,
    DC_BITFIELD_SIZE_6,
    DC_BITFIELD_SIZE_7,
    DC_BITFIELD_SIZE_8
} dc_bit_field_sizes_t;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      Capabilitities content for ASB
 * @description
 *      Auto Select Best (ASB) capabilitities struct.
 *****************************************************************************/
typedef struct dc_capabilities_asb_s
{
    /**< Auto Select Best (ASB), see \ref CpaDcAutoSelectBest */
    Cpa8U asb : DC_CAPS_BF_ASB;

    /**< ASB Threshold */
    Cpa8U asbTsh : DC_CAPS_BF_ASB_TSH;

    /**< ASB Ratio */
    Cpa8U asbRatio : DC_CAPS_BF_ASB_RATIO;

    /**< ASB supported */
    Cpa8U supported : DC_BITFIELD_SIZE_1;

    /**< ASB Threshold supported */
    Cpa8U asbTshSupported : DC_BITFIELD_SIZE_1;

    /**< ASB Ratio supported */
    Cpa8U asbRatioSupported : DC_BITFIELD_SIZE_1;

    Cpa8U asbReserved : DC_BITFIELD_SIZE_6;

} dc_capabilities_asb_t;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      Capabilitities content for Compress and Verify (CnV)
 * @description
 *       Compress and Verify (CnV) capabilitities struct.
 *****************************************************************************/
typedef struct dc_capabilities_cnv_s
{
    /**< CnV supported */
    Cpa8U supported : DC_BITFIELD_SIZE_1;

    /**< CnV strict mode supported */
    Cpa8U strict : DC_BITFIELD_SIZE_1;

    /**< CnV recovery supported */
    Cpa8U recovery : DC_BITFIELD_SIZE_1;

    /**< CnV error injection */
    Cpa8U errorInjection : DC_BITFIELD_SIZE_1;

    Cpa8U cnvReserved : DC_BITFIELD_SIZE_4;
} dc_capabilities_cnv_t;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      Capabilitities content for CRC integrity
 * @description
 *       CRC integrity struct.
 *****************************************************************************/
typedef struct dc_capabilities_crc_integrity_s
{
    /**< Integrity supported */
    Cpa8U supported : DC_BITFIELD_SIZE_1;

    /**< If set to true, the implementation will verify that data
     * integrity is preserved through the processing pipeline.
     * Integrity CRC checking is not supported for decompression operations
     * over data that contains multiple gzip headers. */

    /**< 32-bit Integrity CRCs */
    Cpa8U checkCRC32 : DC_BITFIELD_SIZE_1;

    /**< 64-bit integrity CRCs */
    Cpa8U checkCRC64 : DC_BITFIELD_SIZE_1;

    Cpa8U integrityReserved : DC_BITFIELD_SIZE_5;

} dc_capabilities_crc_integrity_t;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      Supported types (index) of deflate compression.
 * @description
 *      - static
 *      - dynamic
 *****************************************************************************/
typedef enum dc_deflate_types
{
    DC_CAPS_DEFLATE_TYPE_STATIC = 0,
    DC_CAPS_DEFLATE_TYPE_DYNAMIC = 1,

} dc_deflate_types_t;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      Type's support of deflate compression.
 * @description
 *      - unsupported
 *      - supported
 *****************************************************************************/
typedef enum dc_deflate_type_support
{
    DC_CAPS_DEFLATE_TYPE_UNSUPPORTED = 0,
    DC_CAPS_DEFLATE_TYPE_SUPPORTED = 1,

} dc_deflate_type_support_t;

#define DC_CAPS_DEFLATE_TYPE_SUPPORT_SET(capability, type, support)            \
    capability &= ~(0x1 << type);  /* Mask others */                           \
    capability |= support << type; /* Add support for type */

#define DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(capability, type, support)            \
    (((capability >> type) & 0x1) == support) ? CPA_TRUE : CPA_FALSE;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      DC deflate capabilitities content
 * @description
 *      Definition of deflate capabilitities data
 *****************************************************************************/
typedef struct dc_capabilities_deflate_s
{
    /**< Number of bytes internally available to be used when
     * constructing dynamic Huffman trees */
    Cpa32U internalHuffmanMem;

    /**< Inflate content size */
    Cpa32U inflateContextSize;

    /**< Bits set to '1' for each valid window size supported by
     * the compression implementation */
    Cpa16U validWindowSizeMaskCompression;

    /**< Bits set to '1' for each valid window size supported by
     * the decompression implementation */
    Cpa16U validWindowSizeMaskDecompression;

    /**< Flag to define if algorithm is supported (TRUE) or not (FALSE) */
    Cpa8U supported : DC_BITFIELD_SIZE_1;

    /**< Flag to indicate if dictionary compression is supported (TRUE) or not
     * (FALSE) */
    Cpa8U dictCompSupported : DC_BITFIELD_SIZE_1;

    /**< Dictionary type, see \ref CpaDcDictType */
    Cpa8U dictCap : DC_BITFIELD_SIZE_2;

    /**< Session direction, see \ref CpaDcDir */
    Cpa8U dirMask : DC_BITFIELD_SIZE_2;

    /**< Bypass incomplete operation if file error */
    Cpa8U bypassIncompleteFileErr : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm is supported by Auto select
     * best feature */
    Cpa8U asbSupported : DC_BITFIELD_SIZE_1;

    /**< Window size, see \ref CpaDcCompWindowSize */
    Cpa8U historyBufferSize : DC_BITFIELD_SIZE_3;

    /**< Support for deflate types, 2-bit matrix based on
     * \ref dc_deflate_types_t and \ref dc_deflate_type_support
     * 0b00: STATIC UNSUPPORTED, DYNAMIC UNSUPPORTED
     * 0b01: STATIC SUPPORTED,   DYNAMIC UNSUPPORTED
     * 0b10: STATIC UNSUPPORTED, DYNAMIC SUPPORTED
     * 0b11: STATIC SUPPORTED,   DYNAMIC SUPPORTED */
    Cpa8U typeSupport : DC_BITFIELD_SIZE_2;

    /**< True if an instance specific buffer is required to perform
     * a dynamic Huffman tree deflate request */
    Cpa8U dynamicHuffmanBufferReq : DC_BITFIELD_SIZE_1;

    /**< True if the Instance supports precompiled Huffman trees in
     * deflate blocks */
    Cpa8U precompiledHuffman : DC_BITFIELD_SIZE_1;

    /**< True if zero length requests */
    Cpa8U zerolengthRequests : DC_BITFIELD_SIZE_1;

    /**< True if the current compression format supports programmable CRC64 */
    Cpa8U programmableCrc64 : DC_BITFIELD_SIZE_1;

    /**< True if its preferred to keep ASB enabled */
    Cpa8U asbEnablePref : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm supports HASH THEN COMPRESS chaining
     * operation */
    Cpa8U hashThenCompressSupported : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm supports COMPRESS_THEN_AEAD
     * chaining operation */
    Cpa8U compressThenAeadSupported : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm supports AEAD_THEN_DECOMPRESS
     * chaining operation */
    Cpa8U aeadThenDecompressSupported : DC_BITFIELD_SIZE_1;

    Cpa8U deflateReserved : DC_BITFIELD_SIZE_3;

} dc_capabilities_deflate_t;

#define DC_CAPS_DEFLATE_LENGTH (sizeof(dc_capabilities_deflate_t))

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      DC lz4 capabilitities content
 * @description
 *      Definition of lz4 capabilitities data
 *****************************************************************************/
typedef struct dc_capabilities_lz4_s
{
    /**< LZ4 decompression context size */
    Cpa32U decompContextSize;

    /**< Bits set to '1' for each valid window size supported by
     * the compression implementation */
    Cpa16U validWindowSizeMaskCompression;

    /**< Bits set to '1' for each valid window size supported by
     * the decompression implementation */
    Cpa16U validWindowSizeMaskDecompression;

    /**< Flag to define if algorithm is supported (TRUE) or not (FALSE) */
    Cpa8U supported : DC_BITFIELD_SIZE_1;

    /**< Flag to indicate if dictionary compression is supported (TRUE) or not
     * (FALSE) */
    Cpa8U dictCompSupported : DC_BITFIELD_SIZE_1;

    /**< Dictionary type, see \ref CpaDcDictType */
    Cpa8U dictCap : DC_BITFIELD_SIZE_2;

    /**< Session direction, see \ref CpaDcDir */
    Cpa8U dirMask : DC_BITFIELD_SIZE_2;

    /**< Bypass incomplete operation if file error */
    Cpa8U bypassIncompleteFileErr : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm is supported by Auto select
     * best feature */
    Cpa8U asbSupported : DC_BITFIELD_SIZE_1;

    /**< Window size, see \ref CpaDcCompWindowSize */
    Cpa8U historyBufferSize : DC_BITFIELD_SIZE_3;

    /**< Maximum LZ4 output block size, see \ref CpaDcCompLZ4BlockMaxSize */
    Cpa8U maxBlockSize : DC_BITFIELD_SIZE_4;

    /**< LZ4 Block Independence Flag setting */
    Cpa8U blockIndependence : DC_BITFIELD_SIZE_1;

    /**< LZ4 Block Checksum setting for the LZ4 request */
    Cpa8U blockChecksum : DC_BITFIELD_SIZE_1;

    /**< If TRUE the xxHash calculation for LZ4 requests using the session
     * based APIs will be accumulated across requests */
    Cpa8U accumulateXXHash : DC_BITFIELD_SIZE_1;

    /**< True if the Instance can calculate an xxHash-32 hash over
     * the uncompressed data */
    Cpa8U checksumXXHash32 : DC_BITFIELD_SIZE_1;

    /**< True if zero length requests */
    Cpa8U zerolengthRequests : DC_BITFIELD_SIZE_1;

    /**< True if the current compression format supports programmable CRC64 */
    Cpa8U programmableCrc64 : DC_BITFIELD_SIZE_1;

    /**< True if its preferred to keep ASB enabled */
    Cpa8U asbEnablePref : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm supports HASH THEN COMPRESS chaining
     * operation */
    Cpa8U hashThenCompressSupported : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm supports COMPRESS_THEN_AEAD
     * chaining operation */
    Cpa8U compressThenAeadSupported : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm supports AEAD_THEN_DECOMPRESS
     * chaining operation */
    Cpa8U aeadThenDecompressSupported : DC_BITFIELD_SIZE_1;

    Cpa8U lz4Reserved : DC_BITFIELD_SIZE_7;

} dc_capabilities_lz4_t;

#define DC_CAPS_LZ4_LENGTH (sizeof(dc_capabilities_lz4_t))

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      DC lz4s capabilitities content
 * @description
 *      Definition of lz4s capabilitities data
 *****************************************************************************/
typedef struct dc_capabilities_lz4s_s
{
    /**< Bits set to '1' for each valid window size supported by
     * the compression implementation */
    Cpa16U validWindowSizeMaskCompression;

    /**< Bits set to '1' for each valid window size supported by
     * the decompression implementation */
    Cpa16U validWindowSizeMaskDecompression;

    /**< Flag to define if algorithm is supported (TRUE) or not (FALSE) */
    Cpa8U supported : DC_BITFIELD_SIZE_1;

    /**< Flag to indicate if dictionary compression is supported (TRUE) or not
     * (FALSE) */
    Cpa8U dictCompSupported : DC_BITFIELD_SIZE_1;

    /**< Dictionary type, see \ref CpaDcDictType */
    Cpa8U dictCap : DC_BITFIELD_SIZE_2;

    /**< Session direction, see \ref CpaDcDir */
    Cpa8U dirMask : DC_BITFIELD_SIZE_2;

    /**< Bypass incomplete operation if file error */
    Cpa8U bypassIncompleteFileErr : DC_BITFIELD_SIZE_1;

    /**< True if the algorithm is supported by Auto select
     * best feature */
    Cpa8U asbSupported : DC_BITFIELD_SIZE_1;

    /**< Window size, see \ref CpaDcCompWindowSize */
    Cpa8U historyBufferSize : DC_BITFIELD_SIZE_3;

    /**< Min Match size, see \ref CpaDcCompMinMatch */
    Cpa8U minMatch : DC_BITFIELD_SIZE_2;

    /**< True if the Instance can calculate an xxHash-32 hash over
     * the uncompressed data */
    Cpa8U checksumXXHash32 : DC_BITFIELD_SIZE_1;

    /**< True if zero length requests */
    Cpa8U zerolengthRequests : DC_BITFIELD_SIZE_1;

    /**< True if the current compression format supports programmable CRC64 */
    Cpa8U programmableCrc64 : DC_BITFIELD_SIZE_1;

    /**< True if its preferred to keep ASB enabled */
    Cpa8U asbEnablePref : DC_BITFIELD_SIZE_1;

    Cpa8U lz4sReserved : DC_BITFIELD_SIZE_7;

} dc_capabilities_lz4s_t;

#define DC_CAPS_LZ4S_LENGTH (sizeof(dc_capabilities_lz4s_t))

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      Supported HW device generations.
 * @description
 *      - QAT supported device generations ranging between Gen2 and Gen4.
 *****************************************************************************/
typedef enum dc_hw_gen_types
{
    DC_CAPS_GEN2_HW = 2,
    DC_CAPS_GEN4_HW,
    DC_CAPS_GEN5_HW,

} dc_hw_gen_types_t;

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      HW device DC capabilitities content
 *
 * @description
 *      Definition of supported compression HW capabilitities
 *
 *****************************************************************************/
typedef struct dc_hw_device_capabilities_s /* sal_compression_device_data */
{
    /**< Device specific minimum output buffer size for static compression */
    Cpa32U minOutputBuffSize;

    /**< Device specific minimum output buffer size for dynamic compression */
    Cpa32U minOutputBuffSizeDynamic;

    /**< Maximum compression depths are supported */
    Cpa8U highestHwCompressionDepth;

    /**< H/W generations */
    Cpa8U hw_gen;

    /**< Enable/disable secureRam/acceleratorRam for intermediate buffers */
    Cpa8U useDevRam : DC_BITFIELD_SIZE_1;

    /**< When set, implies device can decompress interim odd byte length
     * stateful decompression requests */
    Cpa8U oddByteDecompInterim : DC_BITFIELD_SIZE_1;

    /**< When set, implies device can decompress odd byte length
     * stateful decompression requests when bFinal is absent */
    Cpa8U oddByteDecompNobFinal : DC_BITFIELD_SIZE_1;

    /**< Flag to indicate if translator slice overflow is supported */
    Cpa8U translatorOverflow : DC_BITFIELD_SIZE_1;

    /**< Flag to enable/disable delayed match mode */
    Cpa8U enableDmm : DC_BITFIELD_SIZE_1;

    /**< Flag to indicate that uncompressed data are supported */
    Cpa8U uncompressedDataSupported : DC_BITFIELD_SIZE_1;

    /**< decompressionServiceSupported and compressionServiceSupported
     * This combination of 2 flags indicates the supported services. In
     * the table below, each service runs on a dedicated ring pair or
     * queue.
     *
     * Compression | Decompression |          Services
     *   service   |    service    |-----------------------------
     *  supported  |   supported   | compression | decompression
     *===========================================================
     *    false    |     false     |   disabled  |   disabled
     *-----------------------------------------------------------
     *    true     |     false     |   enabled   |   disabled
     *             |               |(legacy mode)|
     *-----------------------------------------------------------
     *    false    |      true     |   disabled  |   enabled
     *-----------------------------------------------------------
     *    true     |      true     |   enabled   |   enabled
     */

    /**< Flag to indicate if device supports decompression as a
     * separate service */
    Cpa8U decompressionServiceSupported : DC_BITFIELD_SIZE_1;

    /**< Flag to indicate if device supports compression as a
     * service. When set, this service supports both compression and
     * decompression direction.
     */
    Cpa8U compressionServiceSupported : DC_BITFIELD_SIZE_1;

} dc_hw_device_capabilities_t /* sal_compression_device_data_t */;

#define DC_CAPS_HW_DATA_LENGTH (sizeof(dc_hw_device_capabilities_t))

/**
 *****************************************************************************
 * @ingroup dc_capabilities
 *      DC capabilitities content
 * @description
 *      Capabilitities struct to define data compression features.
 *****************************************************************************/
typedef struct dc_capabilities_s
{
    /**< Device specific data, see \ref sal_compression_device_data_t */
    dc_hw_device_capabilities_t deviceData;

    /**< CRC integrity */
    dc_capabilities_crc_integrity_t crcIntegrity;

    /**< ASB */
    dc_capabilities_asb_t asb;

    /**< CnV */
    dc_capabilities_cnv_t cnv;

    /**< Algorithms related content, see \ref CpaDcCompType */
    dc_capabilities_deflate_t deflate;
    dc_capabilities_lz4_t lz4;
    dc_capabilities_lz4s_t lz4s;

    /**< Generic data not related to device and not related
     * to the type of algorithm */

    /**< Number of intermediate buffers */
    Cpa16U numInterBuffs;

    /**< Session state, see \ref CpaDcState */
    Cpa8U sessState : DC_BITFIELD_SIZE_2;

    /**< Checksum, see \ref CpaDcChecksum */
    Cpa8U checksum : DC_BITFIELD_SIZE_4;

    /**< True if the instance supports stopping and reporting the end
     * of the last block in a compressed stream during a decompression
     * operation. */
    Cpa8U endOfLastBlock : DC_BITFIELD_SIZE_1;

    /**< True if the instance does not support overflow resubmit */
    Cpa8U overflowResubmitUnsupported : DC_BITFIELD_SIZE_1;

    /**< True if the instance does not support stateful lite */
    Cpa8U statefulLiteUnsupported : DC_BITFIELD_SIZE_1;

    /**< If set to true the instance supports determinism in compression
     * direction */
    Cpa8U determinism : DC_BITFIELD_SIZE_1;

    /**< Partially decompress a payload to fill up a certain amount of the
     * destination buffer */
    Cpa8U partialDecompression : DC_BITFIELD_SIZE_1;

    /**< True if the instance supports 'batch and pack' compression */
    Cpa8U batchAndPack : DC_BITFIELD_SIZE_1;

    /**< True if stored block generation */
    Cpa8U storedBlockGeneration : DC_BITFIELD_SIZE_1;

    Cpa8U genericDeprecatedReserve : DC_BITFIELD_SIZE_1;

    /**< True if the instance supports parity error reporting */
    Cpa8U reportParityError : DC_BITFIELD_SIZE_1;

    Cpa8U genericReserve : DC_BITFIELD_SIZE_1;

    /**< Populate the compression hardware block for QAT */
    void (*dcCompHwBlockPopulate)(
        void *pService,
        void *pSessionDesc,
        CpaDcNsSetupData *pSetupData,
        icp_qat_hw_compression_config_t *pCompConfig,
        void *compDecomp,
        CpaBoolean bNsOp);
    void (*dcNsCompHwBlockPopulate)(
        void *pService,
        void *pSessionDesc,
        CpaDcNsSetupData *pSetupData,
        icp_qat_hw_compression_config_t *pCompConfig,
        void *compDecomp,
        CpaBoolean bNsOp);
    /**< Compress bound API's to calculate destination buffer size */
    CpaStatus (*dcDeflateBound)(void *pService,
                                CpaDcHuffType huffType,
                                Cpa32U inputSize,
                                Cpa32U *outputSize);
    CpaStatus (*dcLZ4Bound)(Cpa32U inputSize, Cpa32U *outputSize);
    CpaStatus (*dcLZ4SBound)(Cpa32U inputSize, Cpa32U *outputSize);
} dc_capabilities_t;

/* Type to access extended features bit fields */
typedef struct dc_extended_features_s
{
    unsigned is_cnv : 1; /* Bit<0> */
    unsigned padding : 7;
    unsigned is_cnvnr : 1; /* Bit<8> */
    unsigned padding1 : 7;
    unsigned is_chain_compress_then_hash : 1;                  /* Bit<16> */
    unsigned is_chain_compress_then_encrypt : 1;               /* Bit<17> */
    unsigned is_chain_compress_then_hash_encrypt : 1;          /* Bit<18> */
    unsigned is_chain_compress_then_encrypt_hash : 1;          /* Bit<19> */
    unsigned is_chain_compress_then_aead : 1;                  /* Bit<20> */
    unsigned is_chain_hash_then_compress : 1;                  /* Bit<21> */
    unsigned is_chain_hash_verify_then_decompress : 1;         /* Bit<22> */
    unsigned is_chain_decrypt_then_decompress : 1;             /* Bit<23> */
    unsigned is_chain_hash_verify_decrypt_then_decompress : 1; /* Bit<24> */
    unsigned is_chain_decrypt_hash_verify_then_decompress : 1; /* Bit<25> */
    unsigned is_chain_aead_then_decompress : 1;                /* Bit<26> */
    unsigned is_chain_decompress_then_hash_verify : 1;         /* Bit<27> */
    unsigned is_chain_compress_then_aead_then_hash : 1;        /* Bit<28> */
    unsigned is_e2e_comp_crc_over_header_plus_block : 1;       /* Bit<29> */
    unsigned is_e2e_comp_crc_over_block : 1;                   /* Bit<30> */
    unsigned reserved : 1;
} __attribute__((__packed__)) dc_extd_ftrs_t;

/* Structure to refer extended FW capabilities */
typedef struct fw_caps_s
{
    Cpa16U comp_algos;
    Cpa16U cksum_algos;
    Cpa32U deflate_caps;
    Cpa16U lz4_caps;
    Cpa16U lz4s_caps;
    Cpa8U is_fw_caps;
} fw_caps_t;

#define DC_CAPS_SECTION_LENGTH (sizeof(dc_capabilities_t))

#define DC_CAPS_BITFIELD_SET(capability, idx) capability |= (1 << idx);

#define DC_CAPS_BITFIELD_CLR(capability, idx) capability &= ~(1 << idx);

#define DC_CAPS_BITFIELD_GET(capability, idx)                                  \
    (capability & (1 << idx)) ? CPA_TRUE : CPA_FALSE;

#define LAC_SHIFT_RIGHT(capability, shift) ((capability) >> (shift))

CpaStatus dcGetAsbAlgoSupportCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus);

CpaStatus dcGetUncompDictSupportCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    Cpa32U dirMask,
    CpaBoolean *pCapStatus);

CpaStatus dcGetZeroLengthReqCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                             Cpa32U algo,
                                             CpaBoolean *pCapStatus);

CpaStatus dcGetPcrc64CapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                      Cpa32U algo,
                                      CpaBoolean *pCapStatus);

CpaStatus SalCtrl_SetDCCaps(dc_capabilities_t *pDcCapabilities,
                            int device_type,
                            Cpa32U dcExtendedFeatures,
                            fw_caps_t *fw_caps);

CpaStatus dcGetHashChainingCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                            Cpa32U algo,
                                            CpaBoolean *pCapStatus);

CpaStatus dcGetCompAeadChainingCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus);

CpaStatus dcGetAeadDecompChainingCapabilityStatus(
    dc_capabilities_t *pDcCapabilities,
    Cpa32U algo,
    CpaBoolean *pCapStatus);

CpaStatus dcGetAsbEnablePrefCapabilityStatus(dc_capabilities_t *pDcCapabilities,
                                             Cpa32U algo,
                                             CpaBoolean *pCapStatus);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* DC_CAPABILITIES_H */
