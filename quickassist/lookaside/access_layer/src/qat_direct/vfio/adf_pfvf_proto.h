/******************************************************************************
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
 *****************************************************************************/
#ifndef ADF_PFVF_PROTO_H
#define ADF_PFVF_PROTO_H

#include "adf_kernel_types.h"
#include "adf_pfvf_msg.h"

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
