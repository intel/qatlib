/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "cpa.h"
#include "qat_mgr.h"
#include "vfio_lib.h"
#include "adf_pfvf_vf_msg.h"
#include "adf_io_user_proxy.h"
#include "adf_io_bundles.h"
#include "icp_platform.h"
#include "adf_kernel_types.h"
#include "icp_accel_devices.h"
#include "icp_adf_accel_mgr.h"
#include "qae_mem.h"

static char currentProcess[QATMGR_MAX_STRLEN];

/* reopen_vfio_dev uses open_vfio_dev to check if the VF has been re-attached
 * and to re-open the vfio dev. When qatlib sends RESTARTING_COMPLETE msg
 * to kernel, then it closes the vfio device, otherwise vfio-pci may
 * block kernel RAS recovery flow as the device appears in use.
 * Once the vfio device is re-opened, register dev to usdm and re-init
 * the adf_pfvf_dev_data.
 */
STATIC int reopen_vfio_dev(vfio_dev_info_t *vfio_dev, int accelId, int pciDevId)
{
    int status = -1;
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    char vfio_file[QATMGR_MAX_STRLEN];
    char device_id[QATMGR_MAX_STRLEN];
    int group_fd;
    int vfio_container_fd;

    ICP_CHECK_FOR_NULL_PARAM(vfio_dev);
    /* Get device identifier */
    req.device_num = accelId;
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_ID))
        goto exit;

    snprintf(device_id, sizeof(device_id), "%s", rsp.device_id);

    /* Get vfio device file name */
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_VFIO_FILE))
        goto exit;

    snprintf(vfio_file, sizeof(vfio_file), "%s", rsp.vfio_file.name);
    group_fd = rsp.vfio_file.fd;

    if (open_vfio_dev(vfio_file, device_id, group_fd, pciDevId, vfio_dev))
    {
        ADF_DEBUG("Open vfio file %s failed!\n", vfio_file);
        goto exit;
    }

    vfio_container_fd = vfio_dev->vfio_container_fd;
    if (qaeRegisterDevice(vfio_container_fd))
    {
        close_vfio_dev(vfio_dev);
        goto exit;
    }

    if (adf_vf2pf_check_compat_version(&(vfio_dev->pfvf)))
    {
        ADF_DEBUG("adf_vf2pf_check_compat_version failed!\n");
        goto cleanup;
    }

    if (adf_vf2pf_notify_init(&vfio_dev->pfvf))
    {
        ADF_DEBUG("adf_vf2pf_notify_init failed!\n");
        goto cleanup;
    }
    status = 0;

exit:
    return status;
cleanup:
    qaeUnregisterDevice(vfio_dev->vfio_container_fd);
    close_vfio_dev(vfio_dev);
    return status;
}

CpaStatus adf_io_userProcessToStart(char const *const name_in,
                                    size_t name_tml_len,
                                    char *name,
                                    size_t name_len)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    int ret;

    qatmgr_transport_init();

    ret = qatmgr_open();
    if (ret)
        return CPA_STATUS_FAIL;

    ICP_CHECK_FOR_NULL_PARAM(name_in);
    ICP_CHECK_FOR_NULL_PARAM(name);

    snprintf(req.name, sizeof(req.name), "%s", name_in);

    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_SECTION_GET))
    {
        goto error;
    }

    if (ADF_CFG_MAX_SECTION_LEN_IN_BYTES <= strnlen(rsp.name, sizeof(rsp.name)))
    {
        goto error;
    }

    snprintf(
        name, name_len, "%.*s", ADF_CFG_MAX_SECTION_LEN_IN_BYTES - 1, rsp.name);

    return CPA_STATUS_SUCCESS;

error:
    qatmgr_close();
    return CPA_STATUS_FAIL;
}

CpaStatus adf_io_userProxyInit(char const *const name)
{
    ICP_CHECK_FOR_NULL_PARAM(name);

    if (strnlen(name, QATMGR_MAX_STRLEN) >= QATMGR_MAX_STRLEN)
    {
        return CPA_STATUS_FAIL;
    }

    snprintf(currentProcess, QATMGR_MAX_STRLEN, "%s", name);

    return CPA_STATUS_SUCCESS;
}

CpaStatus adf_io_userProcessStop(void)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };

    assert(sizeof(req.name) == sizeof(currentProcess));
    snprintf(req.name, sizeof(req.name), "%s", currentProcess);

    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_SECTION_PUT))
        ADF_ERROR("Qatmgr failed msg :%d\n", QATMGR_MSGTYPE_SECTION_PUT);

    memset(currentProcess, 0, QATMGR_MAX_STRLEN);

    return qatmgr_close();
}

void adf_io_userProxyShutdown(void)
{
}

CpaStatus adf_io_resetUserProxy(void)
{
    int ret;

    ret = qatmgr_close();
    if (ret)
        return CPA_STATUS_FAIL;

    return CPA_STATUS_SUCCESS;
}

/* pollProxyEvent function plays an important role during RAS reset/
 * recovery flow. It should be called by an application thread.
 * RAS recovery flow requires that the SAL layer handles three key events:
 * FATAL_ERROR, RESTARTING and RESTARTED.
 *
 * When kernel detects some fatal errors (like HB failed), it sends a
 * FATAL_ERROR event. Qatlib handles FATAL_ERROR by cleaning the ring pair,
 * stopping polling the response ring, and changing instance status to error.
 *
 * qatlib handles RESTARTING by cleaning the transport layer, changing
 * instance status to restarting and sending RESTARTING_COMPLETE msg
 * to kernel. This triggers the kernel to disable sriov, reset PF, then
 * re-enable sriov. During this period, VF/vfio device disappears and the
 * communication between kernel and qatlib is cut off.
 * This could last for a few seconds.
 * reopen_vfio_dev checks if the communication path can be restored.
 * As the RESTARTED message may not be received from the PF due to this
 * loss of communication, this function simulates receipt of this event
 * based on the path being restored.
 */
CpaBoolean adf_vfio_poll_proxy_event(Cpa32U *dev_id, enum adf_event *event)
{
    Cpa16U i;
    Cpa16U msg_type = 0xFFFF;
    vfio_dev_info_t *vfio_dev;
    icp_accel_dev_t *accel_tb[ADF_MAX_DEVICES];
    Cpa16U num_instances;

    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(dev_id, CPA_FALSE);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(event, CPA_FALSE);
    icp_adf_getNumInstances(&num_instances);
    icp_adf_getInstances(num_instances, &accel_tb[0]);
    for (i = 0; i < num_instances; ++i)
    {
        /* If device is in restarting state, check whether
         * VF re-attached and reopen vfio dev
         */
        if (icp_adf_isDevInRestarting(accel_tb[i]))
        {
            /* If reopen_vfio_dev failed, means VF is not
             * re-attached yet, then keep polling.
             */
            if (reopen_vfio_dev(accel_tb[i]->ioPriv,
                                accel_tb[i]->accelId,
                                accel_tb[i]->pciDevId))
                continue;

            msg_type = ADF_PF2VF_MSGTYPE_RESTARTED;
        }
        else
        {
            vfio_dev = accel_tb[i]->ioPriv;
            msg_type = adf_check_pf2vf_notification(&vfio_dev->pfvf);
        }

        if (msg_type == ADF_PF2VF_MSGTYPE_RESTARTING)
        {
            *event = ADF_EVENT_RESTARTING;
            *dev_id = accel_tb[i]->accelId;
            return CPA_TRUE;
        }
        if (msg_type == ADF_PF2VF_MSGTYPE_FATAL_ERROR)
        {
            *event = ADF_EVENT_ERROR;
            *dev_id = accel_tb[i]->accelId;
            return CPA_TRUE;
        }
        if (msg_type == ADF_PF2VF_MSGTYPE_RESTARTED)
        {
            *event = ADF_EVENT_RESTARTED;
            *dev_id = accel_tb[i]->accelId;
            return CPA_TRUE;
        }
    }
    return CPA_FALSE;
}

CpaBoolean adf_io_pollProxyEvent(Cpa32U *dev_id, enum adf_event *event)
{
    struct qatmgr_transport *t_mgr = NULL;

    t_mgr = get_transport_mgr();
    return t_mgr->adf_io_poll_proxy_event(dev_id, event);
}
