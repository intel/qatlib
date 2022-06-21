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

#ifndef ADF_PFVF_VF_MSG_H
#define ADF_PFVF_VF_MSG_H

#include "adf_pfvf_proto.h"

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends init message notification from VF to PF.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 *
 * @retval 0        Function executed successfully.
 * @retval -EFAULT  Function failed.
 */
int adf_vf2pf_notify_init(struct adf_pfvf_dev_data *dev);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends shutdown message notification from VF to PF.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 */
void adf_vf2pf_notify_shutdown(struct adf_pfvf_dev_data *dev);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends compatibility version request message and waits for
 * response. Received compatiility version will be set in VF's pfvf data struct.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 *
 * @retval 0        Received "compatible" response.
 * @retval -EFAULT  Received unexpected response or received "incompatible"
 * response
 * @retval -EINVAL  Provided incorrect parameters
 * @retval -EIO	    Timed out waiting for PF response
 */
int adf_vf2pf_check_compat_version(struct adf_pfvf_dev_data *dev);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends capabilities request message and waits for response.
 *      Received data (capabilities, extended DC capabilities and frequency)
 *      will be set in VF's pfvf data struct.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 *
 * @retval 0        Function executed succesfully.
 * @retval -EFAULT  Timed out waiting for PF response or received incorrect
 * response
 */
int adf_vf2pf_get_capabilities(struct adf_pfvf_dev_data *dev);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function sends ring to service request message and waits for
 * response. Received rint to service mapping will be set in VF's pfvf data
 * struct.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 *
 * @retval 0        Function executed succesfully.
 * @retval -EFAULT  Timed out waiting for PF response or received incorrect
 * response
 */
int adf_vf2pf_get_ring_to_svc(struct adf_pfvf_dev_data *dev);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function check for notifications from PF.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 *
 * @retval notification type	0 if there was no notification from PF,
 * otherwise type of received message.
 */
int adf_check_pf2vf_notification(struct adf_pfvf_dev_data *dev);

/**
 * @ingroup adf_vf2pf
 *
 * @description
 *      This function check if VF2PF communication is available.
 *
 * @retval 0	VF2PF is not available
 * @retval 1	VF2PF is available
 */
int adf_vf2pf_available();

#endif /* ADF_PFVF_VF_MSG_H */
