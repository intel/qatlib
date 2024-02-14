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

/*  reopen_vfio_dev uses open_vfio_dev to check if the VF has been re-attached
 *  and to re-open the vfio dev. When qatlib sends RESTARTING_COMPLETE msg
 *  to kernel, then it closes the vfio device, otherwise vfio-pci may
 *  block kernel RAS recovery flow as the device appears in use.
 *  Once the vfio device is  re-opened, register dev to usdm and re-init
 *  the adf_pfvf_dev_data.
 */
STATIC int reopen_vfio_dev(vfio_dev_info_t *vfio_dev, int accelId, int pciDevId)
{
    CpaStatus status = CPA_STATUS_FAIL;
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

    ICP_STRLCPY(device_id, rsp.device_id, sizeof(device_id));

    /* Get vfio device file name */
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_VFIO_FILE))
        goto exit;

    ICP_STRLCPY(vfio_file, rsp.vfio_file.name, sizeof(vfio_file));
    group_fd = rsp.vfio_file.fd;

    if (open_vfio_dev(vfio_file, device_id, group_fd, pciDevId, vfio_dev))
    {
        ADF_DEBUG("Open vfio file %s failed!\n", vfio_file);
        goto exit;
    }

    vfio_container_fd = vfio_dev->vfio_container_fd;
    if (qaeRegisterDevice(vfio_container_fd))
    {
        close(vfio_dev->vfio_group_fd);
        goto exit;
    }

    adf_vf2pf_check_compat_version(&(vfio_dev->pfvf));
    adf_vf2pf_notify_init(&vfio_dev->pfvf);
    status = CPA_STATUS_SUCCESS;

exit:
    return status;
}

CpaStatus adf_io_userProcessToStart(char const *const name_in,
                                    size_t name_tml_len,
                                    char *name,
                                    size_t name_len)
{
    struct qatmgr_msg_req req = {0};
    struct qatmgr_msg_rsp rsp = {0};
    int ret;

    ret = qatmgr_open();
    if (ret)
        return CPA_STATUS_FAIL;

    ICP_CHECK_FOR_NULL_PARAM(name_in);
    ICP_CHECK_FOR_NULL_PARAM(name);

    ICP_STRLCPY(req.name, name_in, sizeof(req.name));

    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_SECTION_GET))
    {
        goto error;
    }

    if (strnlen(rsp.name, sizeof(rsp.name)) >= name_len)
    {
        goto error;
    }

    ICP_STRLCPY(name, rsp.name, name_len);

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

    ICP_STRLCPY(currentProcess, name, QATMGR_MAX_STRLEN);

    return CPA_STATUS_SUCCESS;
}

void adf_io_userProcessStop(void)
{
    struct qatmgr_msg_req req = {0};
    struct qatmgr_msg_rsp rsp = {0};

    assert(sizeof(req.name) == sizeof(currentProcess));
    ICP_STRLCPY(req.name, currentProcess, sizeof(req.name));

    qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_SECTION_PUT);

    memset(currentProcess, 0, QATMGR_MAX_STRLEN);

    qatmgr_close();

    return;
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

/*  pollProxyEvent function plays an important role during RAS reset/
 *  recovery flow. It should be called by an application thread.
 *  RAS recovery flow require that the SAL layer handles three key events:
 *  FATAL_ERROR, RESTARTING and RESTARTED.
 *
 *  When kernel detects some fatal error (like HB failed), it sends a
 *  FATAL_ERROR event. Qatlib handles FATAL_ERROR by cleaning the ring pair,
 *  stopping polling the response ring, and changing instance status to error.
 *
 *  qatlib handles RESTARTING by cleaning the transport layer, changing
 *  instance status to restarting and sending RESTARTING_COMPLETE msg
 *  to kernel. This triggers the kernel to disable sriov, reset PF, then
 *  re-enable sriov. During this period, VF/vfio dev disappears and the
 *  communication between kernel and qatlib is cut off.
 *  This could last for a few seconds.
 *  reopen_vfio_dev checks if the comunication path can be restored.
 *  As the RESTARTED message may not be received from the PF due to this
 *  loss of communication, this function simulates receipt of this event
 *  based on the path being restored.
 */
CpaBoolean adf_io_pollProxyEvent(Cpa32U *dev_id, enum adf_event *event)
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
        /*  If device is in restarting state, check whether
         *  VF re-attached and reopen vfio dev
         */
        if (icp_adf_isDevInRestarting(accel_tb[i]))
        {
            /*  If reopen_vfio_dev failed, means VF is not
             *  re-attached yet, then keep polling.
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
