/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

#ifndef ADF_PFVF_VF_MSG_H
#define ADF_PFVF_VF_MSG_H

#include "adf_pfvf_proto.h"

#define VF2PF_UNKNOWN -1
#define VF2PF_AVAILABLE 1
#define VF2PF_NOT_AVAILABLE 0

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
 *      This function sends restarting complete message from VF to PF.
 *
 * @param[in] dev	Pointer to VF's pfvf data struct.
 */
void adf_vf2pf_notify_restarting_complete(struct adf_pfvf_dev_data *dev);

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
 * @retval 0        Function executed successfully.
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
 * @retval 0        Function executed successfully.
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

void adf_set_vf2pf_available(int available);

#endif /* ADF_PFVF_VF_MSG_H */
