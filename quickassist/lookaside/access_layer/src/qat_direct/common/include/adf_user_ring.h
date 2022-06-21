/*****************************************************************************
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

/*****************************************************************************
 * @file adf_user_uio_ring.h
 *
 * @description
 *      This file contains the ring related interfaces
 *
 *****************************************************************************/

#ifndef ADF_UIO_USER_RING_H
#define ADF_UIO_USER_RING_H

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
int32_t adf_ring_freebuf(adf_dev_ring_handle_t *ring);

int32_t adf_user_put_msg(adf_dev_ring_handle_t *ring,
                         uint32_t *inBuf,
                         uint64_t *seq_num);
CpaBoolean adf_user_check_resp_ring(adf_dev_ring_handle_t *ring);
int32_t adf_user_notify_msgs(adf_dev_ring_handle_t *ring);
int32_t adf_user_notify_msgs_poll(adf_dev_ring_handle_t *ring);
int32_t adf_user_get_inflight_requests(adf_dev_ring_handle_t *ring,
                                       uint32_t *maxInflightRequests,
                                       uint32_t *numInflightRequests);
#endif /* ADF_UIO_USER_RING_H */
