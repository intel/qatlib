/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/******************************************************************************
 * @file adf_user_transport.h
 *
 * @description
 * User space transport functions
 *****************************************************************************/
#ifndef ADF_USER_TRANSPORT_H
#define ADF_USER_TRANSPORT_H

#include "adf_dev_ring_ctl.h"

/*
 * adf_pollRing
 *
 * Description
 * Internal functions which polls
 * a polling ring. This function does not check
 * to see if the ring is a polling ring or
 * if the ring exists.
 *
 */
CpaStatus adf_pollRing(icp_accel_dev_t *accel_dev,
                       adf_dev_ring_handle_t *pRingHandle,
                       Cpa32U response_quota);

/*
 * adf_user_transport_init
 *
 * Description
 * Function initializes internal transport data
 */
CpaStatus adf_user_transport_init(icp_accel_dev_t *accel_dev);

/*
 * adf_user_transport_reinit
 *
 * Description
 * Function reinitializes internal transport data
 */
CpaStatus adf_user_transport_reinit(icp_accel_dev_t *accel_dev);

/*
 * adf_user_transport_exit
 *
 * Description
 * Function deinitializes internal transport data
 */
CpaStatus adf_user_transport_exit(icp_accel_dev_t *accel_dev);

/*
 * adf_user_transport_clean
 *
 * Description
 * Function clean internal transport data
 */
CpaStatus adf_user_transport_clean(icp_accel_dev_t *accel_dev);

#endif /* ADF_USER_TRANSPORT_H */
