/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef ADF_IO_BUNDLES_H
#define ADF_IO_BUNDLES_H

#include "icp_accel_devices.h"

struct adf_io_user_bundle
{
    unsigned int device_minor;
    /**< Device minor number */
    int fd;
    /**< File descriptor associated to the bundle */
    int efd;
    /**< File descriptor associated with the event */
    void *ptr;
    /**< Pointer to a memory region that contains the bundle CSRs */
    void *priv;
    /**< Pointer to a private structure which depends on the implementation */
    int number;
    /** Bundle number */
};

/**
 * @ingroup adf_io
 *
 * @description
 *      Given as input the id of an accelerator and a bundle number, this
 *      function allocates and returns a pointer to the adf_io_user_bundle
 *      structure associated to that bundle in that accelerator.
 *
 * @param[in] accelid       Id of the accelerator.
 * @param[in] bundle_nr     Id of the bundle.
 *
 * @retval Pointer to adf_io_user_bundle structure if the function executed
 *         successfully.
 * @retval NULL if the function failed.
 */
struct adf_io_user_bundle *adf_io_get_bundle_from_accelid(int accelid,
                                                          int bundle_nr);
/**
 * @ingroup adf_io
 *
 * @description
 *      Checks if the accelerator dev_id exists in the system.
 *
 * @param[in] dev_id       Id of the accelerator to check.
 *
 * @retval 0               The accelerator dev_id is not present.
 * @retval 1               The accelerator dev_id is present in the system.
 */
int adf_io_accel_dev_exist(int dev_id);

/**
 * @ingroup adf_io
 *
 * @description
 *      Given as input the id of an accelerator, allocates an icp_accel_dev_t
 *      structure and populates it with the parameters associated to the
 *      requested accelerator.
 *
 * @param[in,out] accel_dev Pointer to a pointer to an icp_accel_dev_t
 *                          structure. In case of success *accel_dev is
 *                          populated with a pointer to an allocated
 *                          icp_accel_dev_t structure otherwise it is
 *                          set to NULL.
 * @param[in] dev_id        If of the accelerator.
 *
 * @retval 0                The function executed successfully.
 *                          An icp_accel_dev_t structure has been allocated
 *                          and returned through the accel_dev in-out
 *                          parameter.
 * @retval -ENOMEM          The function failed allocating memory.
 * @retval -EINVAL          The function failed due to an invalid dev_id.
 * @retval -1               The function failed due to internal communication
 *                          with external modules ie qatmgr.
 */
int adf_io_create_accel(icp_accel_dev_t **accel_dev, int dev_id);

/**
 * @ingroup adf_io
 *
 * @description
 *      Checks if accelerator with given id exists and reinitialises *accel_dev
 *      with the parameters associated to the requested accelerator.
 *
 * @param[in,out] accel_dev Pointer to a pointer to an icp_accel_dev_t
 *                          structure. In case of success *accel_dev is
 *                          reinitialised with a icp_accel_dev_t structure
 *                          content related to given accelerator
 *
 * @param[in] dev_id        Id of the accelerator.
 *
 * @retval 0                The function executed successfully.
 *                          An icp_accel_dev_t structure has been updated
 *                          and returned through the accel_dev in-out
 *                          parameter.
 * @retval -EINVAL          The function failed due to an invalid dev_id.
 */
int adf_io_reinit_accel(icp_accel_dev_t **accel_dev, int dev_id);

/**
 * @ingroup adf_io
 *
 * @description
 *      Frees an icp_accel_dev_t allocated using adf_io_create_accel.
 *
 * @param[in] accel_dev     Pointer to an icp_accel_dev_t structure to be
 *                          freed.
 */
void adf_io_destroy_accel(icp_accel_dev_t *accel_dev);

/**
 * @ingroup adf_io
 *
 * @description
 *      Frees an adf_io_user_bundle structure allocated though
 *      adf_io_get_bundle_from_accelid.
 *
 * @param[in] bundle        Pointer to an adf_io_user_bundle structure to
 *                          be freed.
 */
void adf_io_free_bundle(struct adf_io_user_bundle *bundle);

/**
 * @ingroup adf_io
 *
 * @description
 *      Populates the fields of an adf_io_user_bundle structure based
 *      on the accel_dev.
 *
 * @param[in] accel_dev    Pointer to an icp_accel_dev_t structure.
 * @param[out] bundle      Pointer to a user allocate adf_io_user_bundle
 *                         structure.
 *
 * @retval 0               The function executed successfully.
 * @retval -EINVAL         The function failed due to an invalid parameter.
 */
int adf_io_populate_bundle(icp_accel_dev_t *accel_dev,
                           struct adf_io_user_bundle *bundle);

/**
 * @ingroup adf_io
 *
 * @description
 *      Send restarting complete message from vf to pf
 *
 * @param[in] accel_dev    Pointer to an icp_accel_dev_t structure.
 */
void adf_io_vf2pf_notify_restarting_complete(icp_accel_dev_t *accel_dev);

#endif
