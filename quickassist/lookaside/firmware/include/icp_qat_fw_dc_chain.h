/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 * @file icp_qat_fw_dc_chain.h
 * @defgroup icp_qat_fw_dc_chain ICP QAT FW CHAIN Processing Definitions
 * @ingroup icp_qat_fw
 * $Revision: 0.1 $
 * @brief
 *      This file documents the external interfaces that the QAT FW running
 *      on the QAT Acceleration Engine provides to clients wanting to
 *      accelerate chaining applications
 */
#include "lac_common.h"

#ifndef __ICP_QAT_FW_DC_CHAIN_H__
#define __ICP_QAT_FW_DC_CHAIN_H__

#define ICP_QAT_FW_COMP_CHAIN_REQ_FLAGS_BUILD(                          \
    append_crc, verify, derive_key, crc_ctx)\
    (((append_crc & ICP_QAT_FW_COMP_CHAIN_APPEND_CRC_MASK)                     \
      << ICP_QAT_FW_COMP_CHAIN_APPEND_CRC_BITPOS) |                            \
     ((verify & ICP_QAT_FW_COMP_CHAIN_VERIFY_MASK)                             \
      << ICP_QAT_FW_COMP_CHAIN_VERIFY_BITPOS) |                                \
    ((derive_key & ICP_QAT_FW_COMP_CHAIN_DERIVE_KEY_MASK)                      \
      << ICP_QAT_FW_COMP_CHAIN_DERIVE_KEY_BITPOS) |                            \
     ((crc_ctx & ICP_QAT_FW_COMP_CHAIN_CRC64_CTX_MASK)                         \
      << ICP_QAT_FW_COMP_CHAIN_CRC64_CTX_BITPOS))

#define ICP_QAT_FW_COMP_CHAIN_APPEND_CRC 1
#define ICP_QAT_FW_COMP_CHAIN_NO_APPEND_CRC 0
#define ICP_QAT_FW_COMP_CHAIN_VERIFY 1
#define ICP_QAT_FW_COMP_CHAIN_NO_VERIFY 0
#define ICP_QAT_FW_COMP_CHAIN_DERIVE_KEY 1
#define ICP_QAT_FW_COMP_CHAIN_NO_DERIVE_KEY 0
#define ICP_QAT_FW_COMP_CHAIN_CRC64_CTX 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CRC64_CTX 0

#define ICP_QAT_FW_COMP_CHAIN_APPEND_CRC_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_APPEND_CRC_BITPOS 0
#define ICP_QAT_FW_COMP_CHAIN_VERIFY_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_VERIFY_BITPOS 1
#define ICP_QAT_FW_COMP_CHAIN_DERIVE_KEY_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_DERIVE_KEY_BITPOS 2
#define ICP_QAT_FW_COMP_CHAIN_CRC64_CTX_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CRC64_CTX_BITPOS 3

#define ICP_QAT_FW_COMP_CHAIN_REQ_EXTEND_FLAGS_BUILD(                          \
    cnv, asb, cbc, xts, ccm, cnvnr)                                            \
    (((cnv & ICP_QAT_FW_COMP_CHAIN_CNV_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_CNV_BITPOS) |                                   \
     ((asb & ICP_QAT_FW_COMP_CHAIN_ASB_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_ASB_BITPOS) |                                   \
     ((cbc & ICP_QAT_FW_COMP_CHAIN_CBC_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_CBC_BITPOS) |                                   \
     ((xts & ICP_QAT_FW_COMP_CHAIN_XTS_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_XTS_BITPOS) |                                   \
     ((ccm & ICP_QAT_FW_COMP_CHAIN_CCM_MASK)                                   \
      << ICP_QAT_FW_COMP_CHAIN_CCM_BITPOS) |                                   \
     ((cnvnr & ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_MASK)                        \
      << ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_BITPOS))

#define ICP_QAT_FW_COMP_CHAIN_NO_CNV 0
#define ICP_QAT_FW_COMP_CHAIN_CNV 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CNV_RECOVERY 0
#define ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY 1
#define ICP_QAT_FW_COMP_CHAIN_NO_ASB 0
#define ICP_QAT_FW_COMP_CHAIN_ASB 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CBC 0
#define ICP_QAT_FW_COMP_CHAIN_CBC 1
#define ICP_QAT_FW_COMP_CHAIN_NO_XTS 0
#define ICP_QAT_FW_COMP_CHAIN_XTS 1
#define ICP_QAT_FW_COMP_CHAIN_NO_CCM 0
#define ICP_QAT_FW_COMP_CHAIN_CCM 1
#define ICP_QAT_FW_COMP_CHAIN_CNV_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CNV_BITPOS 0
#define ICP_QAT_FW_COMP_CHAIN_ASB_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_ASB_BITPOS 4
#define ICP_QAT_FW_COMP_CHAIN_CBC_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CBC_BITPOS 6
#define ICP_QAT_FW_COMP_CHAIN_XTS_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_XTS_BITPOS 10
#define ICP_QAT_FW_COMP_CHAIN_CCM_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CCM_BITPOS 8
#define ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_MASK 0x1
#define ICP_QAT_FW_COMP_CHAIN_CNV_RECOVERY_BITPOS 12
#define DC_CHAIN_MAX_LINK 0x3
typedef enum
{
    ICP_QAT_FW_NO_CHAINING = 0,
    ICP_QAT_FW_CHAINING_CMD_DECRYPT_DECOMPRESS = 1,
    ICP_QAT_FW_CHAINING_CMD_DYNAMIC_COMP_ENCRYT = 2,
    ICP_QAT_FW_CHAINING_CMD_HASH_STATIC_COMP = 3,
    ICP_QAT_FW_CHAINING_CMD_HASH_DYNAMIC_COMP = 4
} icp_qat_comp_chain_cmd_id_t;

typedef enum
{
    ICP_QAT_FW_NO_CHAINING_20 = 0,
    ICP_QAT_FW_CHAINING_20_CMD_DECRYPT_DECOMPRESS = 1,
    ICP_QAT_FW_CHAINING_20_CMD_COMPRESS_ENCRYPT = 2,
    ICP_QAT_FW_CHAINING_20_CMD_HASH_COMPRESS = 3
} icp_qat_comp_chain_20_cmd_id_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *
 * @description
 *     Define the chaining request descriptor header
 *
 *****************************************************************************/
typedef struct icp_qat_comp_chain_req_hdr_s
{
    /* LW0 */
    Cpa8U resrvd1;
    /* Reserved field */
    Cpa8U service_cmd_id;
    /* Service Command Id  - this field is service-specific
     * valid value are in enum icp_qat_comp_chain_cmd_id_t
     * except ICP_QAT_FW_NO_CHAINING
     */
    Cpa8U service_type;
    /* Service type */
    Cpa8U hdr_flags;
    /* This represents a flags field for the Service Request.
     * The most significant bit is the 'valid' flag and the only
     * one used. All remaining bit positions are unused and
     * are therefore reserved and need to be set to 0.
     */

    /* LW1 */
    Cpa16U numLinks;
    /* Number of links for chaining request */
} icp_qat_comp_chain_req_hdr_t;

/**
 ***************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *      Request data for chaining QAT messages
 *
 * @description
 *      This structure defines the request data for chaining QAT messages. This
 * is used to store data which is known when the message is sent and which we
 * wish to retrieve when the response message is processed.
 **************************************************************************/
typedef struct icp_qat_fw_comp_chain_req_s
{
    icp_qat_comp_chain_req_hdr_t hdr;
    /* Chaining request header */
    Cpa16U extendFlags;
    /* Extend flags for CBC, CNV, ASB */
    Cpa32U resrvd1[4];
    Cpa64U opaque_data;
    /* Chaining cookie pointer */
    Cpa32U resrvd2[8];
    Cpa64U compReqAddr;
    /* Physical address for compression request */
    Cpa64U compRespAddr;
    /* Physical address for compression response */
    Cpa64U symCryptoReqAddr;
    /* Physical address for symmetric crypto request */
    Cpa64U symCryptoRespAddr;
    /* Physical address for symmetric crypto response */
    Cpa32U resrvd3[8];
} icp_qat_fw_comp_chain_req_t;

/**
 ***************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *      Request data for chaining Stor2 QAT messages
 *
 * @description
 *      This structure defines the request data for chaining QAT messages. This
 * is used to store data which is known when the message is sent and which we
 * wish to retrieve when the response message is processed.
 **************************************************************************/
typedef struct icp_qat_fw_chain_stor2_req_s
{
    /**< LWs 0-1 */
    icp_qat_fw_comn_req_hdr_t comn_hdr;
    /**< Common request header - for Service Command Id,
     * use service-specific Chain Command Id.
     * Service Specific Flags - use Chain Command Flags */

    /**< LWs 2-5 */
    icp_qat_fw_comn_req_hdr_cd_pars_t cd_pars;
    /**< Common Request content descriptor field which points either to a
     * content descriptor
     * parameter block or contains the service-specific data itself. */

    /**< LWs 6-13 */
    icp_qat_fw_comn_req_mid_t comn_mid;
    /**< Common request middle section */

    /**< LWs 14-15 */
    Cpa32U resrvd3[2];

    /**< LWs 16-23 */
    Cpa64U compReqAddr;
    /* Physical address for compression request */
    Cpa64U compRespAddr;
    /* Physical address for compression response */
    Cpa64U symCryptoReqAddr;
    /* Physical address for symmetric crypto request */
    Cpa64U symCryptoRespAddr;
    /* Physical address for symmetric crypto response */

    /**< LWs 24-31 */
    Cpa32U resrvd4[8];
} icp_qat_fw_chain_stor2_req_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_dc_chain
 *
 * @description
 *     Define the chaining response format
 *
 *****************************************************************************/
typedef struct icp_qat_fw_comp_chain_resp_s
{
    Cpa8U resrvd0;
    Cpa8U cmdID;
    /* Chaining Command id */
    Cpa8U serviceType;
    /* Chaining service type */
    Cpa8U valid;

    Cpa16U resrvd1;
    Cpa8U rspStatus;
    /* Response status */
    Cpa8U chainCmdID;
    /* Chaining Command id */
    Cpa64U opaque_data;
    /*
     * Opaque data pointer, it's a copy of the callback data
     * passed when the request was created
     */
    Cpa32U numLinks;
    /* Number of links in chain */
    Cpa32U resrvd2[3];
} icp_qat_fw_comp_chain_resp_t;
#endif
