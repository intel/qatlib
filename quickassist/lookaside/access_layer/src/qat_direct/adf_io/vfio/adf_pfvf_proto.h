/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/
#ifndef ADF_PFVF_PROTO_H
#define ADF_PFVF_PROTO_H

#include "adf_kernel_types.h"
#include "adf_pfvf_msg.h"

struct fw_caps
{
    uint16_t comp_algos;
    uint16_t cksum_algos;
    uint32_t deflate_caps;
    uint16_t lz4_caps;
    uint16_t lz4s_caps;
    uint8_t is_fw_caps;
};

struct adf_pfvf_dev_data
{
    void *pmiscbar_addr;
    uint32_t dev_id;
    uint32_t local_csr_offset;
    uint32_t remote_csr_offset;
    uint32_t type_shift;
    uint32_t data_shift;
    uint32_t type_mask;
    uint32_t data_mask;
    uint8_t pfvf_initialized;
    uint32_t compat_version;
    uint32_t frequency;
    uint32_t ext_dc_caps;
    struct fw_caps fw_caps;
    uint32_t capabilities;
    uint32_t ring_to_svc_map;
};

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function fills adf_pfvf_dev_data structure for given device.
 *
 * @param[in] pmiscbar_addr	Address of PMISC BAR base
 * @param[in] dev_id	    PCI device id
 *
 * @retval struct adf_pfvf_dev_data initialized for given device.
 */

struct adf_pfvf_dev_data adf_init_pfvf_dev_data(void *pmiscbar_addr,
                                                int dev_id);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends message from VF to PF and waits for ACK from PF.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 * @param[in] msg	Message to be sent to PF.
 *
 * @retval 0		Function executed successfully.
 * @retval -EINVAL	Provided argument is invalid.
 * @retval -EIO		Timed out waiting for ACK from PF.
 */

int adf_send_vf2pf_msg(struct adf_pfvf_dev_data *dev, struct pfvf_message msg);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends request from VF to PF and waits for PF response.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 * @param[in] req	Request message to be sent to PF.
 * @param[out] resp	Response message from PF.
 *
 * @retval 0		Function executed successfully.
 * @retval -EINVAL	Provided argument is invalid.
 * @retval -EIO		Timed out waiting for ACK or response message from PF.
 */

int adf_send_vf2pf_req(struct adf_pfvf_dev_data *dev,
                       struct pfvf_message req,
                       struct pfvf_message *resp);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends block message request from VF to PF and waits for PF
 * response.
 *
 * @param[in] dev		Pointer to VF's pfvf data struct.
 * @param[in] type		Type of request to be sent.
 * @param[out] buffer		Buffer for receiving payload from PF.
 * @param[in/out] buffer_len	Size of buffer in bytes/size of received
 * payload.
 *
 * @retval 0		Function executed successfully.
 * @retval -EINVAL	Provided argument is invalid.
 * @retval -EIO		Timed out waiting for response message from PF or received
 * incorrect data (CRC mismatch).
 */

int adf_send_vf2pf_blkmsg_req(struct adf_pfvf_dev_data *dev,
                              uint8_t type,
                              uint8_t *buffer,
                              uint16_t *buffer_len);
/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function receives message from PF.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 *
 * @retval pfvf_message struct with type set to 0	No pending message from PF.
 */

struct pfvf_message adf_recv_pf2vf_msg(struct adf_pfvf_dev_data *dev);

#endif /* ADF_PFVF_PROTO_H */
