/******************************************************************************
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

#include <errno.h>
#include <string.h>

#include "adf_pfvf_vf_msg.h"
#include "icp_platform.h"
#include "qat_log.h"

#define VF2PF_MAYBE_AVAILABLE -1
#define VF2PF_AVAILABLE 1
#define VF2PF_NOT_AVAILABLE 0

/* At the beginning we assume PF driver does not support PFVF.
 * If first init notification will be ACKed, VF2PF support will be marked as
 * available. Any further error in communication will disabled it again */
static int vf2pf_available = VF2PF_MAYBE_AVAILABLE;

STATIC
void adf_set_vf2pf_available(int available)
{
    /* VF2PF error at first attempt of communication, assuming PF driver has no
     * PFVF support */
    if (vf2pf_available == VF2PF_MAYBE_AVAILABLE &&
        available == VF2PF_NOT_AVAILABLE)
    {
        qat_log(LOG_LEVEL_INFO, "PF has not support for PFVF\n");
    }
    else if (vf2pf_available == VF2PF_AVAILABLE &&
             available == VF2PF_NOT_AVAILABLE)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Error in PF2VF communication, disabling PFVF\n");
    }

    vf2pf_available = available;
}

int adf_vf2pf_available()
{
    if (vf2pf_available == VF2PF_NOT_AVAILABLE)
    {
        qat_log(
            LOG_LEVEL_INFO,
            "VF2PF communication attempt, with no PFVF support on PF side\n");
        return 0;
    }

    return 1;
}
int adf_vf2pf_notify_init(struct adf_pfvf_dev_data *dev)
{
    struct pfvf_message msg = {.type = ADF_VF2PF_MSGTYPE_INIT};

    ICP_CHECK_FOR_NULL_PARAM(dev);

    if (!adf_vf2pf_available())
        return -EIO;

    if (adf_send_vf2pf_msg(dev, msg))
    {
        qat_log(LOG_LEVEL_INFO, "Failed to send Init event to PF\n");
        adf_set_vf2pf_available(VF2PF_NOT_AVAILABLE);
        return -EFAULT;
    }
    dev->pfvf_initialized = 1;
    return 0;
}

void adf_vf2pf_notify_shutdown(struct adf_pfvf_dev_data *dev)
{
    ICP_CHECK_FOR_NULL_PARAM_VOID(dev);
    struct pfvf_message msg = {.type = ADF_VF2PF_MSGTYPE_SHUTDOWN};

    if (!adf_vf2pf_available())
        return;

    if (dev->pfvf_initialized)
    {
        if (adf_send_vf2pf_msg(dev, msg))
        {
            qat_log(LOG_LEVEL_ERROR, "Failed to send Shutdown event to PF\n");
            adf_set_vf2pf_available(VF2PF_NOT_AVAILABLE);
        }
        else
            dev->pfvf_initialized = 0;
    }
}

int adf_vf2pf_check_compat_version(struct adf_pfvf_dev_data *dev)
{
    int ret;
    struct pfvf_compat_message resp;
    struct pfvf_compat_message compat_req = {
        .type = ADF_VF2PF_MSGTYPE_COMPAT_VER_REQ,
        .version = ADF_PFVF_COMPAT_THIS_VERSION,
    };
    struct pfvf_message req;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    if (!adf_vf2pf_available())
        return -EIO;

    /* memcpy between pfvf_compat_message and pfvf_message to prevent
     * strict-aliasing warnings */
    memcpy(&req, &compat_req, sizeof(req));

    ret = adf_send_vf2pf_req(dev, req, (struct pfvf_message *)&resp);
    if (ret)
    {
        qat_log(LOG_LEVEL_INFO,
                "Failed to send Compatibility Version Request\n");
        adf_set_vf2pf_available(VF2PF_NOT_AVAILABLE);
        return ret;
    }

    if (resp.type != ADF_PF2VF_MSGTYPE_VERSION_RESP)
    {
        qat_log(LOG_LEVEL_ERROR,
                "PFVF expecting Version Response, received msg type %u\n",
                resp.type);
        return -EFAULT;
    }

    if (resp.compat != ADF_PF2VF_VF_COMPATIBLE)
    {
        qat_log(LOG_LEVEL_ERROR,
                "VF is not compatible with PF, due to the reason %d\n",
                resp.compat);
        return -EFAULT;
    }

    dev->compat_version = resp.version;
    return 0;
}

int adf_vf2pf_get_ring_to_svc(struct adf_pfvf_dev_data *dev)
{
    struct ring_to_svc_map_v1 rts_map_msg = {
        {0},
    };

    uint16_t len = sizeof(rts_map_msg);

    ICP_CHECK_FOR_NULL_PARAM(dev);
    if (!adf_vf2pf_available())
        return -EIO;

    if (dev->compat_version < ADF_PFVF_COMPAT_RING_TO_SVC_MAP)
        /* Use already set default mappings */
        return -EFAULT;

    if (adf_send_vf2pf_blkmsg_req(dev,
                                  ADF_VF2PF_BLKMSG_REQ_RING_SVC_MAP,
                                  (uint8_t *)&rts_map_msg,
                                  &len))
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to get block message response\n");
        adf_set_vf2pf_available(VF2PF_NOT_AVAILABLE);
        return -EFAULT;
    }

    if (len < sizeof(struct ring_to_svc_map_v1))
    {
        qat_log(LOG_LEVEL_ERROR,
                "RING_TO_SVC message truncated to %d bytes\n",
                len);
        return -EFAULT;
    }

    /* Only v1 at present */
    dev->ring_to_svc_map = rts_map_msg.map;
    return 0;
}

int adf_vf2pf_get_capabilities(struct adf_pfvf_dev_data *dev)
{
    struct capabilities_v3 cap_msg = {
        {0},
    };
    uint16_t len = sizeof(cap_msg);
    int ret = 0;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    if (!adf_vf2pf_available())
        return -EIO;

    if (dev->compat_version < ADF_PFVF_COMPAT_CAPABILITIES)
    {
        /* The PF is too old to support the extended capabilities */
        return -EFAULT;
    }

    if (adf_send_vf2pf_blkmsg_req(
            dev, ADF_VF2PF_BLKMSG_REQ_CAP_SUMMARY, (uint8_t *)&cap_msg, &len))
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to get CAP_SUMMARY response\n");
        adf_set_vf2pf_available(VF2PF_NOT_AVAILABLE);
        return -EFAULT;
    }

    switch (cap_msg.hdr.version)
    {
        default:
        /* Newer version received, fallthrough to handle the know parts */
        case ADF_PFVF_CAPABILITIES_V3_VERSION:
            if (len >= sizeof(struct capabilities_v3))
            {
                dev->frequency = cap_msg.frequency;
            }
            else
            {
                qat_log(LOG_LEVEL_ERROR, "Could not get frequency\n");
                ret = -EFAULT;
            }
        case ADF_PFVF_CAPABILITIES_V2_VERSION:
            if (len >= sizeof(struct capabilities_v2))
            {
                dev->capabilities = cap_msg.capabilities;
            }
            else
            {
                qat_log(LOG_LEVEL_ERROR, "Could not get capabilities\n");
                ret = -EFAULT;
            }
        case ADF_PFVF_CAPABILITIES_V1_VERSION:
            if (len >= sizeof(struct capabilities_v1))
            {
                dev->ext_dc_caps = cap_msg.ext_dc_caps;
            }
            else
            {
                qat_log(LOG_LEVEL_ERROR,
                        "CAPABILITIES message truncated to %d bytes\n",
                        len);
                ret = -EFAULT;
            }
    }

    return ret;
}

int adf_check_pf2vf_notification(struct adf_pfvf_dev_data *dev)
{
    struct pfvf_message msg;
    ICP_CHECK_FOR_NULL_PARAM(dev);
    msg = adf_recv_pf2vf_msg(dev);

    return msg.type;
}
