/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
