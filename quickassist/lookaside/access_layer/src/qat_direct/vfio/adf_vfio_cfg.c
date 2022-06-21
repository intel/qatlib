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
#include <string.h>
#include <stdint.h>
#include "adf_kernel_types.h"

#include "adf_io_cfg.h"
#include "cpa.h"
#include "icp_accel_devices.h"
#include "icp_platform.h"
#include "qat_mgr.h"
#include "qat_log.h"

#define MAX_DEVS_STATIC_CFG 256

CpaStatus adf_io_getNumDevices(unsigned int *num_devices)
{
    struct qatmgr_msg_req req = {0};
    struct qatmgr_msg_rsp rsp = {0};
    int ret;

    ICP_CHECK_FOR_NULL_PARAM(num_devices);

    *num_devices = ADF_MAX_DEVICES;

    ret = qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_NUM_DEVICES);
    if (ret)
    {
        *num_devices = 0;
        return CPA_STATUS_FAIL;
    }

    if (rsp.num_devices <= ADF_MAX_DEVICES)
        *num_devices = rsp.num_devices;

    return CPA_STATUS_SUCCESS;
}

static CpaStatus cfg_getGeneralValue(const Cpa32U accelId,
                                     const char *pParamName,
                                     char *pParamValue,
                                     struct qatmgr_msg_rsp *rsp)
{
    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (!ICP_STRNCMP_CONST(pParamName, "Device_Max_Banks"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.max_banks);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Device_Capabilities_Mask"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "0x%x",
                 rsp->device_info.capability_mask);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Device_DcExtendedFeatures"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "0x%x",
                 rsp->device_info.extended_capabilities);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "ServicesEnabled"))
    {
        if (rsp->device_info.services & SERV_TYPE_DC)
        {
            if (SERV_TYPE_CY == (rsp->device_info.services & SERV_TYPE_CY))
                sprintf(pParamValue, "dc;cy");
            else if (rsp->device_info.services & SERV_TYPE_SYM)
                sprintf(pParamValue, "dc;sym");
            else if (rsp->device_info.services & SERV_TYPE_ASYM)
                sprintf(pParamValue, "dc;asym");
            else
                sprintf(pParamValue, "dc");
        }
        else
        {
            if (SERV_TYPE_CY == (rsp->device_info.services & SERV_TYPE_CY))
                sprintf(pParamValue, "cy");
            else if (rsp->device_info.services & SERV_TYPE_SYM)
                sprintf(pParamValue, "sym");
            else if (rsp->device_info.services & SERV_TYPE_ASYM)
                sprintf(pParamValue, "asym");
            else
                *pParamValue = 0;
        }
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "statsGeneral"))
    {
        sprintf(pParamValue, "1");
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Device_PkgId"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.pkg_id);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Device_NodeId"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.node_id);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "HW_RevId"))
    {
        sprintf(pParamValue, "N/A");
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Firmware_UofVer"))
    {
        sprintf(pParamValue, "N/A");
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Firmware_MmpVer"))
    {
        sprintf(pParamValue, "N/A");
        return CPA_STATUS_SUCCESS;
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

static CpaStatus cfg_getDcInstanceValue(const Cpa32U accelId,
                                        const char *pParamName,
                                        char *pParamValue,
                                        struct qatmgr_msg_rsp *rsp)
{
    const char *name;

    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    /* Skip past the Dc<n> part of the parameter name */
    name = pParamName + 2;
    while (*name >= '0' && *name <= '9')
        name++;

    if (!ICP_STRNCMP_CONST(name, "BankNumber"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.dc.bank_number);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "IsPolled"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.dc.is_polled);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "CoreAffinity"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.dc.core_affinity);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "NumConcurrentRequests"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.dc.num_concurrent_requests);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingTx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.dc.ring_tx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingRx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.dc.ring_rx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "Name"))
    {
        if (snprintf(pParamValue,
                     ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                     "%.256s",
                     rsp->name) > ADF_CFG_MAX_VAL_LEN_IN_BYTES)
        {
            ADF_ERROR("Config parameter %s (\"%s\") truncated\n",
                      pParamName,
                      pParamValue);
            return CPA_STATUS_FAIL;
        }
        return CPA_STATUS_SUCCESS;
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

static CpaStatus cfg_getCyInstanceValue(const Cpa32U accelId,
                                        const char *pParamName,
                                        char *pParamValue,
                                        struct qatmgr_msg_rsp *rsp)
{
    const char *name;

    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    /* Skip past the Cy<n> part of the parameter name */
    name = pParamName + 2;
    while (*name >= '0' && *name <= '9')
        name++;

    if (!ICP_STRNCMP_CONST(name, "BankNumber"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.bank_number);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "BankNumberAsym"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.asym.bank_number);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "BankNumberSym"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.bank_number);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "IsPolled"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.is_polled);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "CoreAffinity"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.core_affinity);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "NumConcurrentAsymRequests"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.asym.num_concurrent_requests);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "NumConcurrentSymRequests"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.num_concurrent_requests);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingSymTx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.ring_tx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingAsymTx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.asym.ring_tx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingSymRx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.ring_rx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingAsymRx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.asym.ring_rx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "Name"))
    {
        if (snprintf(pParamValue,
                     ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                     "%.256s",
                     rsp->name) > ADF_CFG_MAX_VAL_LEN_IN_BYTES)
        {
            ADF_ERROR("Config parameter %s (\"%s\") truncated\n",
                      pParamName,
                      pParamValue);
            return CPA_STATUS_FAIL;
        }
        return CPA_STATUS_SUCCESS;
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

static CpaStatus cfg_getNumInstances(const char *pParamName,
                                     char *pParamValue,
                                     struct qatmgr_msg_rsp *rsp)
{
    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    if (!ICP_STRNCMP_CONST(pParamName, "NumberCyInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->section_info.num_cy_instances);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "NumberDcInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->section_info.num_dc_instances);
        return CPA_STATUS_SUCCESS;
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

CpaStatus adf_io_cfgGetParamValue(icp_accel_dev_t *accel_dev,
                                  const char *pSection,
                                  const char *pParamName,
                                  char *pParamValue)
{
    struct qatmgr_msg_req req = {0};
    enum serv_type type;
    unsigned serv_num;
    Cpa16U msg_type;
    /* Cache previous responses */
    static __thread Cpa32U c_accelId = UINT32_MAX;
    static __thread enum serv_type c_serv_type;
    static __thread Cpa16U c_serv_num = UINT16_MAX;
    static __thread struct qatmgr_msg_rsp rsp = {0};

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_FOR_NULL_PARAM(pSection);
    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);

    if (ICP_STRNCMP_CONST(pSection, "GENERAL") == 0)
    {
        /*
         *  All general section paramaters are handled in
         *  QATMGR_MSGTYPE_DEVICE_INFO message
         */
        if (accel_dev->accelId != c_accelId ||
            rsp.hdr.type != QATMGR_MSGTYPE_DEVICE_INFO)
        {
            req.device_num = accel_dev->accelId;
            if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_INFO))
            {
                ADF_ERROR("Failed to get DEVICE_INFO response from qatmgr\n");
                c_accelId = UINT32_MAX;
                return CPA_STATUS_FAIL;
            }
        }
        c_accelId = accel_dev->accelId;
        return cfg_getGeneralValue(
            accel_dev->accelId, pParamName, pParamValue, &rsp);
    }

    if (!ICP_STRNCMP_CONST_NO_NULL(pParamName, "Dc") ||
        !ICP_STRNCMP_CONST_NO_NULL(pParamName, "Cy"))
    {
        if (sscanf(pParamName, "Dc%u", &serv_num) == 1)
            type = SERV_TYPE_DC;
        else if (sscanf(pParamName, "Cy%u", &serv_num) == 1)
            type = SERV_TYPE_CY;
        else
        {
            ADF_ERROR("Unknown config parameter %s\n", pParamName);
            return CPA_STATUS_FAIL;
        }

        if (strstr(pParamName, "Name"))
            msg_type = QATMGR_MSGTYPE_INSTANCE_NAME;
        else
            msg_type = QATMGR_MSGTYPE_INSTANCE_INFO;

        if (msg_type != rsp.hdr.type || type != c_serv_type ||
            serv_num != c_serv_num || accel_dev->accelId != c_accelId)
        {
            req.inst.type = type;
            req.inst.num = serv_num;
            req.inst.device_num = accel_dev->accelId;
            if (qatmgr_query(&req, &rsp, msg_type))
            {
                ADF_ERROR("Failed to get INSTANCE_INFO response from qatmgr\n");
                c_accelId = UINT32_MAX;
                return CPA_STATUS_FAIL;
            }
            c_serv_type = type;
            c_serv_num = serv_num;
            c_accelId = accel_dev->accelId;
        }
        if (type == SERV_TYPE_DC)
            return cfg_getDcInstanceValue(
                accel_dev->accelId, pParamName, pParamValue, &rsp);
        else
            return cfg_getCyInstanceValue(
                accel_dev->accelId, pParamName, pParamValue, &rsp);
    }

    if (!ICP_STRNCMP_CONST_NO_NULL(pParamName, "Number"))
    {
        if (rsp.hdr.type != QATMGR_MSGTYPE_SECTION_INFO)
        {
            if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_SECTION_INFO))
            {
                ADF_ERROR("Failed to get SECTION_INFO response from qatmgr\n");
                rsp.hdr.type = 0;
                return CPA_STATUS_FAIL;
            }
        }
        return cfg_getNumInstances(pParamName, pParamValue, &rsp);
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

Cpa32S adf_io_cfgGetDomainAddress(Cpa16U packageId)
{
    struct qatmgr_msg_req req = {0};
    struct qatmgr_msg_rsp rsp = {0};
    unsigned node, b, d, f;

    req.device_num = packageId;
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_ID))
    {
        ADF_ERROR("Failed to get DEVICE_INFO response from qatmgr\n");
        return ADF_IO_OPERATION_FAIL_CPA32S;
    }

    if (sscanf(rsp.device_id, "%x:%x:%x.%x", &node, &b, &d, &f) != 4)
    {
        ADF_ERROR("Failed to parse BDF from \"%s\"\n", rsp.device_id);
    }

    return node;
}

Cpa16U adf_io_cfgGetBusAddress(Cpa16U packageId)
{
    struct qatmgr_msg_req req = {0};
    struct qatmgr_msg_rsp rsp = {0};
    unsigned n, b, d, f;
    unsigned bdf = 0;

    req.device_num = packageId;
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_ID))
    {
        ADF_ERROR("Failed to get DEVICE_INFO response from qatmgr\n");
        return ADF_IO_OPERATION_FAIL_CPA16U;
    }

    if (sscanf(rsp.device_id, "%x:%x:%x.%x", &n, &b, &d, &f) != 4)
    {
        ADF_ERROR("Failed to parse BDF from \"%s\"\n", rsp.device_id);
    }
    else
    {
        bdf = (f & 0x7) + ((d & 0x1F) << 3) + ((b & 0xFF) << 8);
    }

    return bdf;
}

CpaStatus adf_io_reset_device(Cpa32U accelId)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaBoolean adf_io_isDeviceAvailable(void)
{
    return qat_mgr_is_dev_available();
}
