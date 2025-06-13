/***************************************************************************
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
 ***************************************************************************/
#ifndef ADF_IO_RING
#define ADF_IO_RING

#include "cpa.h"
#include "adf_dev_ring_ctl.h"

/**
 * @ingroup adf_io
 *
 * @description
 *      Reserves a ring in a given accel_id and bank.
 *
 * @param[in] accel_id      Id of the accelerator.
 * @param[in] bank_nr       Id of the bank.
 * @param[in] ring_nr       If of the ring to be reserved.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 */
CpaStatus adf_io_reserve_ring(Cpa16U accel_id, Cpa16U bank_nr, Cpa16U ring_nr);

/**
 * @ingroup adf_io
 *
 * @description
 *      Releases a ring in a given accel_id and bank.
 *
 * @param[in] accel_id      Id of the accelerator.
 * @param[in] bank_nr       Id of the bank.
 * @param[in] ring_nr       If of the ring to be released.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 */
CpaStatus adf_io_release_ring(Cpa16U accel_id, Cpa16U bank_nr, Cpa16U ring_nr);

/**
 * @ingroup adf_io
 *
 * @description
 *      Enables a ring represented by an adf_dev_ring_handle_t structure.
 *
 * @param[in] ring          Pointer to an adf_dev_ring_handle_t structure to
 *                          be enabled.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 */
CpaStatus adf_io_enable_ring(adf_dev_ring_handle_t *ring);

/**
 * @ingroup adf_io
 *
 * @description
 *      Disabled a ring represented by an adf_dev_ring_handle_t structure.
 *
 * @param[in] ring          Pointer to an adf_dev_ring_handle_t structure to
 *                          be disabled.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 */
CpaStatus adf_io_disable_ring(adf_dev_ring_handle_t *ring);

#endif
