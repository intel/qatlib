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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "cpa.h"
#include "icp_platform.h"
#include "adf_user.h"
#include "adf_kernel_types.h"
#include "adf_user_cfg.h"
#include "adf_pfvf_vf_msg.h"
#include "adf_io_cfg.h"
#include "vfio_lib.h"
#include "qat_mgr.h"
#include "qat_log.h"
#include "qae_mem.h"

#define STATIC static

void adf_io_free_bundle(struct adf_io_user_bundle *bundle)
{
    struct qatmgr_transport *t_mgr = NULL;

    t_mgr = get_transport_mgr();

    t_mgr->adf_free_bundle(bundle);
}

void adf_vfio_free_bundle(struct adf_io_user_bundle *bundle)
{
    if (bundle)
        ICP_FREE(bundle);
}

struct adf_io_user_bundle *adf_io_get_bundle_from_accelid(int accelid,
                                                          int bundle_nr)
{
    struct adf_io_user_bundle *bundle = NULL;

    bundle = ICP_ZALLOC_GEN(sizeof(*bundle));
    if (!bundle)
    {
        ADF_ERROR("failed to allocate bundle structure\n");
        return NULL;
    }
    bundle->number = bundle_nr;

    return bundle;
}

int adf_io_populate_bundle(icp_accel_dev_t *accel_dev,
                           struct adf_io_user_bundle *bundle)
{
    struct qatmgr_transport *t_mgr = NULL;
    int ret = -1;

    t_mgr = get_transport_mgr();

    ret = t_mgr->adf_populate_bundle(accel_dev, bundle);

    return ret;
}

int adf_vfio_populate_bundle(icp_accel_dev_t *accel_dev,
                             struct adf_io_user_bundle *bundle)
{
    vfio_dev_info_t *vfio_dev;
    uintptr_t addr;

    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(accel_dev, -EINVAL);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(bundle, -EINVAL);

    vfio_dev = accel_dev->ioPriv;
    if (!vfio_dev)
        return -EINVAL;

    if (vfio_dev->pcs.bar[0].ptr == NULL || vfio_dev->pcs.bar[0].size == 0)
        return -EINVAL;

    addr = (uintptr_t)vfio_dev->pcs.bar[0].ptr + (8192 * bundle->number);
    bundle->ptr = (void *)addr;

    return 0;
}

STATIC int adf_populate_accel_dev(int dev_id,
                                  icp_accel_dev_t *accel_dev,
                                  struct qatmgr_transport *t_mgr)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    int device_name_len;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    memset(accel_dev, '\0', sizeof(*accel_dev));

    /* Get device information */
    req.device_num = dev_id;
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_INFO))
        return -EIO;

    accel_dev->accelId = rsp.device_info.device_num;
    accel_dev->maxNumBanks = rsp.device_info.max_banks;
    accel_dev->accelCapabilitiesMask = rsp.device_info.capability_mask;
    accel_dev->cipherCapabilitiesMask = 0U;
    accel_dev->hashCapabilitiesMask = 0U;
    accel_dev->asymCapabilitiesMask = 0U;
    accel_dev->dcExtendedFeatures = rsp.device_info.extended_capabilities;
    if (rsp.device_info.fw_caps.is_fw_caps)
    {
        accel_dev->fw_caps.comp_algos = rsp.device_info.fw_caps.comp_algos;
        accel_dev->fw_caps.cksum_algos = rsp.device_info.fw_caps.cksum_algos;
        accel_dev->fw_caps.deflate_caps = rsp.device_info.fw_caps.deflate_caps;
        accel_dev->fw_caps.lz4_caps = rsp.device_info.fw_caps.lz4_caps;
        accel_dev->fw_caps.lz4s_caps = rsp.device_info.fw_caps.lz4s_caps;
        accel_dev->fw_caps.is_fw_caps = 1;
    }

    accel_dev->services = rsp.device_info.services;
    accel_dev->numa_node = rsp.device_info.node_id;
    accel_dev->deviceType = rsp.device_info.device_type;
    accel_dev->arb_mask = rsp.device_info.arb_mask;
    accel_dev->maxNumRingsPerBank = rsp.device_info.max_rings_per_bank;
    accel_dev->pciDevId = rsp.device_info.device_pci_id;
    accel_dev->isVf = CPA_TRUE;
    accel_dev->ringMode = rsp.device_info.ring_mode;

    /* Below two are not supported for now */
    accel_dev->sku = 0;
    accel_dev->deviceMemAvail = 0;

    device_name_len = strnlen(rsp.device_info.device_name,
                              sizeof(rsp.device_info.device_name));
    if (device_name_len < sizeof(accel_dev->deviceName))
    {
        snprintf(accel_dev->deviceName,
                 sizeof(accel_dev->deviceName),
                 "%.*s",
                 (int)sizeof(accel_dev->deviceName) - 1,
                 rsp.device_info.device_name);
    }
    else {
        return -EINVAL;
    }

    return 0;
}

int adf_io_accel_dev_exist(int dev_id)
{
    if (adf_io_cfgGetBusAddress(dev_id) == ADF_IO_OPERATION_FAIL_U16)
        return 0;
    else
        return 1;
}

static int vfio_container_fd = 0;

int get_vfio_fd(void)
{
    return vfio_container_fd;
}

int adf_io_create_accel(icp_accel_dev_t **accel_dev, int dev_id)
{
    struct qatmgr_transport *t_mgr = NULL;
    int status = -1;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    t_mgr = get_transport_mgr();

    *accel_dev = ICP_ZALLOC_GEN(sizeof(**accel_dev));
    if (!*accel_dev)
        return -ENOMEM;

    status = t_mgr->adf_create_accel(*accel_dev, dev_id, t_mgr);
    if (status < 0)
    {
        ICP_FREE(*accel_dev);
        *accel_dev = NULL;
    }

    return status;
}

int adf_vfio_create_accel(icp_accel_dev_t *accel_dev,
                          int dev_id,
                          struct qatmgr_transport *t_mgr)
{
    int status = -1;
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    char vfio_file[QATMGR_MAX_STRLEN];
    char device_id[QATMGR_MAX_STRLEN];
    int ret;
    int group_fd;
    int pci_did;

    vfio_dev_info_t *vfio_dev;

    vfio_dev = ICP_ZALLOC_GEN(sizeof(*vfio_dev));
    if (!vfio_dev)
    {
        return -ENOMEM;
    }

    if (adf_populate_accel_dev(dev_id, accel_dev, t_mgr))
        goto accel_fail;

    accel_dev->ioPriv = vfio_dev;

    /* Get device identifier */
    req.device_num = dev_id;
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_ID))
        goto accel_fail;

    snprintf(device_id, sizeof(device_id), "%s", rsp.device_id);

    /* Get vfio device file name */
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_VFIO_FILE))
        goto accel_fail;

    if (sizeof(vfio_file) <=
        strnlen(rsp.vfio_file.name, sizeof(rsp.vfio_file.name)))
    {
        goto accel_fail;
    }

    snprintf(vfio_file,
             sizeof(vfio_file),
             "%.*s",
             (int)(sizeof(vfio_file) - 1),
             rsp.vfio_file.name);
    group_fd = rsp.vfio_file.fd;

    pci_did = accel_dev->pciDevId;
    ret = open_vfio_dev(vfio_file, device_id, group_fd, pci_did, vfio_dev);
    if (ret)
    {
        ADF_ERROR("Open vfio file %s failed!\n", vfio_file);
        goto accel_fail;
    }

    vfio_container_fd = vfio_dev->vfio_container_fd;

    ret = qaeRegisterDevice(vfio_container_fd);
    if (ret)
    {
        close(vfio_dev->vfio_group_fd);
        goto accel_fail;
    }

    adf_vf2pf_notify_init(&vfio_dev->pfvf);

    return 0;

accel_fail:
    ICP_FREE(vfio_dev);
    return status;
}

int adf_io_reinit_accel(icp_accel_dev_t **accel_dev, int dev_id)
{
    struct qatmgr_transport *t_mgr = NULL;
    int status = -1;

    if (!accel_dev)
        return -ENOMEM;

    if (!*accel_dev)
        return -ENOMEM;

    t_mgr = get_transport_mgr();

    status = t_mgr->adf_reinit_accel(*accel_dev, dev_id, t_mgr);
    if (status < 0)
    {
        ICP_FREE(*accel_dev);
        *accel_dev = NULL;
    }

    return status;
}

int adf_vfio_reinit_accel(icp_accel_dev_t *accel_dev,
                          int dev_id,
                          struct qatmgr_transport *t_mgr)
{
    void *pSalHandle = NULL;
    void *pQatStats = NULL;
    void *banks = NULL;
    vfio_dev_info_t *vfio_dev = NULL;

    if (!accel_dev->ioPriv)
        return -ENOMEM;

    pSalHandle = accel_dev->pSalHandle;
    pQatStats = accel_dev->pQatStats;
    banks = accel_dev->banks;
    vfio_dev = (vfio_dev_info_t *)accel_dev->ioPriv;

    if (adf_populate_accel_dev(dev_id, accel_dev, t_mgr))
        goto accel_fail;

    accel_dev->pSalHandle = pSalHandle;
    accel_dev->pQatStats = pQatStats;
    accel_dev->banks = banks;
    accel_dev->ioPriv = vfio_dev;

    return 0;

accel_fail:
    qaeUnregisterDevice(vfio_dev->vfio_container_fd);
    close_vfio_dev(vfio_dev);
    ICP_FREE(vfio_dev);
    return -1;
}

void adf_io_destroy_accel(icp_accel_dev_t *accel_dev)
{
    struct qatmgr_transport *t_mgr = NULL;

    ICP_CHECK_FOR_NULL_PARAM_VOID(accel_dev);

    t_mgr = get_transport_mgr();

    t_mgr->adf_destroy_accel(accel_dev);
}

void adf_vfio_destroy_accel(icp_accel_dev_t *accel_dev)
{
    vfio_dev_info_t *vfio_dev;

    if (!accel_dev->ioPriv)
        goto free_accel;

    vfio_dev = accel_dev->ioPriv;

    adf_vf2pf_notify_shutdown(&vfio_dev->pfvf);

    qaeUnregisterDevice(vfio_dev->vfio_container_fd);
    close_vfio_dev(vfio_dev);

    ICP_FREE(vfio_dev);

free_accel:
    ICP_FREE(accel_dev);
}

/*  For vfio device, after handling the RESTARTING event, qatlib needs to
 *  send RESTARTING_COMPLETE msg to kernel. The kernel checks if all VFs
 *  which map to the same recovering PF have completed RAS flows.
 *  After sending RESTARTING_COMPLETE msg, qatlib should close vfio
 *  dev immediately. Once the kernel receives the RESTARTING_COMPLETE, it
 *  disables sriov and VF/vfio devices disappear.
 */
void adf_io_vf2pf_notify_restarting_complete(icp_accel_dev_t *accel_dev)
{
    vfio_dev_info_t *vfio_dev = NULL;

    ICP_CHECK_FOR_NULL_PARAM_VOID(accel_dev);
    if (!accel_dev->ioPriv)
        return;

    vfio_dev = accel_dev->ioPriv;
    adf_vf2pf_notify_restarting_complete(&vfio_dev->pfvf);
    qaeUnregisterDevice(vfio_dev->vfio_container_fd);
    close_vfio_dev(accel_dev->ioPriv);
    /*  This function is triggered by the RESTARTING event
     *  detected by pollProxyEvent.
     *  If the time interval to the next pollProxyEvent is too short
     *  the VF devices may still be active, that would be misinterpreted
     *  that the reset is already complete.
     *  To prevent this add a sleep time here.
     *  This helps qatlib to make sure that next pollProxyEvent call
     *  happens after the kernel has disabled sriov.
     */
    sleep(1);
}

