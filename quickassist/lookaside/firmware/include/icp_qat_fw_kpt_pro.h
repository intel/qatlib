/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *****************************************************************************
 * @file icp_qat_fw_kpt_pro.h
 * @defgroup icp_qat_fw_kpt_pro ICP QAT FW KPT Provision Processing
 *      Definitions
 * @ingroup icp_qat_fw
 *
 * @description
 *      This file documents the external interfaces that the QAT FW running
 *      on the QAT Acceleration Engine provides to clients wanting to
 *      perform KPT provision services.
 *
 *****************************************************************************/

#ifndef _ICP_QAT_FW_KPT_PRO_H_
#define _ICP_QAT_FW_KPT_PRO_H_

/*
****************************************************************************
* Include local header files
****************************************************************************
*/
#include "icp_qat_fw_pke.h"

/**
 ***************************************************************************
 * @ingroup icp_qat_fw_kpt_pro
 *      Request data for QAT messages
 *
 * @description
 *      This structure defines the request data format for KPT provision
 *      messages. This is used to store data which is known when the message
 *      is sent and which we wish to retrieve when the response message is
 *      processed.
 *
 **************************************************************************/
typedef struct icp_qat_fw_kpt_pro_request_s
{
    uint8_t resrvd0;
    uint8_t cmd_id;
    /**< KPT provision command id */
    uint8_t service_type;
    /**< KPT provision service type */
    uint8_t resrvd1 : 7;
    uint8_t valid : 1;
    /**< 'Valid' flag */
    uint16_t serv_specif_flags;
    /**< Common Request service-specific flags, this field is not used in KPT
     * provision, but a placeholder for PKE Tx request backward compatibility
     * */
    uint8_t comn_req_flags;
    /**< Common Request Flags, this field is not used in KPT provision, but a
     * placeholder for PKE Tx request backward compatibility */
    uint8_t resrvd2;
    uint64_t src_addr;
    /**< Physical address of eSWK, length is fixed to 384 bytes */
    uint64_t key_handle;
    /**< KPT provision key handle */
    uint64_t opaque_data;
    /**< Opaque data passed unmodified from the request to response messages by
     * firmware (fw) */
    uint64_t dst_addr;
    /**< Physical address of destination buffer, length is fixed to 776 bytes */
    uint8_t resrvd3[24];
} icp_qat_fw_kpt_pro_request_t;

/**
 *****************************************************************************
 * @ingroup icp_qat_fw_kpt_pro
 *      Response data for QAT messages
 * @description
 *      Define the KPT provision response format
 *
 *****************************************************************************/
typedef struct icp_qat_fw_kpt_pro_resp_data_s
{
    uint8_t resrvd0;
    uint8_t cmd_id;
    /**< KPT provision request command id, copied from the request
     * to the response */
    uint8_t service_type;
    /**< KPT provision response service type, copied from the
     * request to the response */
    uint8_t resrvd1 : 7;
    uint8_t valid : 1;
    /**< 'Valid' flag */
    icp_qat_fw_pke_resp_status_t rsp_status;
    /**< KPT provision request operation result */
    uint16_t resrvd2;
    /**< KPT provision key handle */
    uint64_t opaque_data;
    /**< Opaque data pointer, it's a copy of the callback data
     * passed when the request was created */
    uint64_t key_handle;
    /**< KPT provision key handle */
    uint64_t dst_addr;
    /**< Physical address of destination flat buffer, copied from the request to
     * the response */
} icp_qat_fw_kpt_pro_resp_data_t;

#endif /* _ICP_QAT_FW_KPT_PRO_H_ */
