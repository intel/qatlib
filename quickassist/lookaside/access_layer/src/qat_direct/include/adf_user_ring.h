/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/*****************************************************************************
 * @file adf_user_uio_ring.h
 *
 * @description
 *      This file contains the ring related interfaces
 *
 *****************************************************************************/

#ifndef ADF_USER_RING_H
#define ADF_USER_RING_H

#include <adf_dev_ring_ctl.h>

int32_t adf_init_ring(adf_dev_ring_handle_t *ring,
                      adf_dev_bank_handle_t *bank,
                      uint32_t ring_num,
                      uint32_t *csr_base_addr,
                      uint32_t num_msgs,
                      uint32_t msg_size,
                      int nodeid);
int32_t adf_reinit_ring(adf_dev_ring_handle_t *ring,
                        adf_dev_bank_handle_t *bank,
                        uint32_t ring_num,
                        uint32_t *csr_base_addr,
                        uint32_t num_msgs,
                        uint32_t msg_size,
                        int nodeid);

void adf_cleanup_ring(adf_dev_ring_handle_t *ring);
void adf_reset_ring(adf_dev_ring_handle_t *ring);

CpaStatus adf_user_put_msg(adf_dev_ring_handle_t *ring,
                           uint32_t *inBuf,
                           uint64_t *seq_num);

/*
 * adf_user_check_ring_error
 *
 * Description
 * Function checks if the rp_exception or rp_halt bits are set in RINGSTAT
 * register
 *
 * Return value
 * -EINVAL if pRingHandle is NULL
 * -EINTR if the rp_exception bit is set
 * -EL2HLT if the rp_halt bit is set
 * -EFAULT if the RINGSTAT rp_exception is not supported
 *  0 if the rp_exception bit is not set
 */
int32_t adf_user_check_ring_error(adf_dev_ring_handle_t *pRingHandle);

CpaBoolean adf_user_check_resp_ring(adf_dev_ring_handle_t *ring);
CpaStatus adf_user_notify_msgs_poll(adf_dev_ring_handle_t *ring);
int32_t adf_user_get_inflight_requests(adf_dev_ring_handle_t *ring,
                                       uint32_t *maxInflightRequests,
                                       uint32_t *numInflightRequests);
#endif /* ADF_USER_RING_H */
