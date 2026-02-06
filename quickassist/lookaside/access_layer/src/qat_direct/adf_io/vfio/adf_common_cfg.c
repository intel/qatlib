/*****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <linux/vfio.h>

#include "adf_kernel_types.h"

#include "adf_io_cfg.h"
#include "cpa.h"
#include "icp_accel_devices.h"
#include "icp_platform.h"
#include "qat_mgr.h"
#include "qat_log.h"
#include "adf_vfio_pf.h"

#define HEARTBEAT_DIR "/sys/kernel/debug/qat_%s_%s/heartbeat/"
#define STATIC static

#define HB_STATUS_FILE HEARTBEAT_DIR "status"
#define HB_SIM_FILE HEARTBEAT_DIR "inject_error"
#define HB_ALIVE "0"
#define HB_SIM_FAIL "1\n"

CpaStatus adf_io_getNumDevices(unsigned int *num_devices)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
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

STATIC CpaStatus cfg_getValueFromDeviceInfo(const Cpa32U accelId,
                                            const char *pParamName,
                                            char *pParamValue,
                                            struct qatmgr_msg_rsp *rsp)
{
    char temp_str[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = { '\0' };
    int len = 0;

    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    bool dc_enabled = rsp->device_info.services & SERV_TYPE_DC;
    bool decomp_enabled = rsp->device_info.services & SERV_TYPE_DECOMP;
    bool sym_enabled = rsp->device_info.services & SERV_TYPE_SYM;
    bool asym_enabled = rsp->device_info.services & SERV_TYPE_ASYM;
    bool cy_enabled =
        (SERV_TYPE_CY == (rsp->device_info.services & SERV_TYPE_CY));

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
        if (dc_enabled)
            len += snprintf(temp_str + len, sizeof(temp_str) - len, "dc");

        if (decomp_enabled)
            len += snprintf(temp_str + len,
                            sizeof(temp_str) - len,
                            "%sdecomp",
                            len ? ";" : "");

        if (!dc_enabled && !decomp_enabled && cy_enabled)
        {
            len += snprintf(
                temp_str + len, sizeof(temp_str) - len, "%scy", len ? ";" : "");
        }
        else
        {
            if (sym_enabled)
                len += snprintf(temp_str + len,
                                sizeof(temp_str) - len,
                                "%ssym",
                                len ? ";" : "");

            if (asym_enabled)
                len += snprintf(temp_str + len,
                                sizeof(temp_str) - len,
                                "%sasym",
                                len ? ";" : "");
        }

        snprintf(pParamValue, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%s", temp_str);

        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "statsGeneral"))
    {
        snprintf(pParamValue, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "1");
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
        snprintf(pParamValue, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "N/A");
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Firmware_UofVer"))
    {
        snprintf(pParamValue, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "N/A");
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "Firmware_MmpVer"))
    {
        snprintf(pParamValue, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "N/A");
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "NumberCyInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.num_cy_instances);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "NumberSymInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.num_sym_instances);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "NumberAsymInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.num_asym_instances);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "NumberDcInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.num_dc_instances);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(pParamName, "NumberDecompInstances"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->device_info.num_decomp_instances);
        return CPA_STATUS_SUCCESS;
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

STATIC CpaStatus cfg_getDcDecompInstanceValue(const Cpa32U accelId,
                                              const char *pParamName,
                                              char *pParamValue,
                                              struct qatmgr_msg_rsp *rsp,
                                              enum serv_type type)
{
    const char *name;
    struct ring_info instance_info = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);
    ICP_CHECK_FOR_NULL_PARAM(rsp);

    /* pParamName can be either Dc<instance_number><param_name> or
     * Decomp<instance_number><param_name>.
     * For example, configuration param for BankNumber for Dc service
     * with instance number zero will be Dc0BankNumber and for Decomp
     * will be Decomp0BankNumber.
     * First 2 characters will be skipped for Dc service and 6 characters
     * will be skipped for Decomp service to get the config param names.
     */
    if (type == SERV_TYPE_DC)
    {
        name = pParamName + strlen("Dc");
        instance_info = rsp->instance_info.dc;
    }
    else
    {
        name = pParamName + strlen("Decomp");
        instance_info = rsp->instance_info.decomp;
    }
    while (*name >= '0' && *name <= '9')
        name++;

    if (!ICP_STRNCMP_CONST(name, "BankNumber"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 instance_info.bank_number);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "IsPolled"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 instance_info.is_polled);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "CoreAffinity"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 instance_info.core_affinity);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "NumConcurrentRequests"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 instance_info.num_concurrent_requests);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingTx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 instance_info.ring_tx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "RingRx"))
    {
        snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 instance_info.ring_rx);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "Name"))
    {
        if (CPA_INST_NAME_SIZE <= strnlen(rsp->name, sizeof(rsp->name)))
        {
            ADF_ERROR("Failed to copy config parameter %s (\"%s\")\n",
                      pParamName,
                      pParamValue);
            return CPA_STATUS_FAIL;
        }
        snprintf(pParamValue,
                 CPA_INST_NAME_SIZE,
                 "%.*s",
                 CPA_INST_NAME_SIZE - 1,
                 rsp->name);
        return CPA_STATUS_SUCCESS;
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

STATIC CpaStatus cfg_getCyInstanceValue(const Cpa32U accelId,
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
                 rsp->instance_info.is_polled);
        return CPA_STATUS_SUCCESS;
    }

    if (!ICP_STRNCMP_CONST(name, "CoreAffinity"))
    {
        /* In the CY case, which has both ASYM and SYM services,
	 * the core affinity will be the same for both.
	 * Therefore though the second condition
	 * below overwrites the pParamValue set in the first,
	 * the result will be correct.
	 */
	if (rsp->device_info.services & SERV_TYPE_ASYM)
	{
            snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.asym.core_affinity);
	}
	if (rsp->device_info.services & SERV_TYPE_SYM)
	{
	    snprintf(pParamValue,
                 ADF_CFG_MAX_VAL_LEN_IN_BYTES,
                 "%u",
                 rsp->instance_info.cy.sym.core_affinity);
	}
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
        if (CPA_INST_NAME_SIZE <= strnlen(rsp->name, sizeof(rsp->name)))
        {
            ADF_ERROR("Failed to copy config parameter %s (\"%s\")\n",
                      pParamName,
                      pParamValue);
            return CPA_STATUS_FAIL;
        }
        snprintf(pParamValue,
                 CPA_INST_NAME_SIZE,
                 "%.*s",
                 CPA_INST_NAME_SIZE - 1,
                 rsp->name);
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
    struct qatmgr_msg_req req = { 0 };
    enum serv_type type;
    unsigned serv_num;
    Cpa16U msg_type;
    /* Cache previous responses */
    static __thread Cpa32U c_accelId = UINT32_MAX;
    static __thread enum serv_type c_serv_type;
    static __thread Cpa16U c_serv_num = UINT16_MAX;
    static __thread struct qatmgr_msg_rsp rsp = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_FOR_NULL_PARAM(pSection);
    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);

    // NOTE: this should improve performance due to cashing also number of
    // instances
    if (ICP_STRNCMP_CONST(pSection, "GENERAL") == 0 ||
        !ICP_STRNCMP_CONST_NO_NULL(pParamName, "Number"))
    {
        /*
         *  All general section parameters and number of instances
         *  are handled in QATMGR_MSGTYPE_DEVICE_INFO message
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
        return cfg_getValueFromDeviceInfo(
            accel_dev->accelId, pParamName, pParamValue, &rsp);
    }

    if (!ICP_STRNCMP_CONST_NO_NULL(pParamName, "Dc") ||
        !ICP_STRNCMP_CONST_NO_NULL(pParamName, "Cy") ||
        !ICP_STRNCMP_CONST_NO_NULL(pParamName, "Decomp"))
    {
        if (sscanf(pParamName, "Dc%u", &serv_num) == 1)
            type = SERV_TYPE_DC;
        else if (sscanf(pParamName, "Decomp%u", &serv_num) == 1)
            type = SERV_TYPE_DECOMP;
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
        if (type == SERV_TYPE_DC || type == SERV_TYPE_DECOMP)
            return cfg_getDcDecompInstanceValue(
                accel_dev->accelId, pParamName, pParamValue, &rsp, type);
        else
            return cfg_getCyInstanceValue(
                accel_dev->accelId, pParamName, pParamValue, &rsp);
    }

    ADF_ERROR("Unsupported config parameter %s\n", pParamName);
    return CPA_STATUS_FAIL;
}

Cpa32S adf_io_cfgGetDomainAddress(Cpa16U accelId)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    unsigned node, b, d, f;

    req.device_num = accelId;
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

Cpa16U adf_io_cfgGetBusAddress(Cpa16U accelId)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    unsigned n, b, d, f;
    unsigned bdf = ADF_IO_OPERATION_FAIL_U16;

    req.device_num = accelId;
    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_DEVICE_ID))
    {
        ADF_ERROR("Failed to get DEVICE_INFO response from qatmgr\n");
        return ADF_IO_OPERATION_FAIL_U16;
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
/*
 * icp_adf_cfgCheckUserSection
 * check if user process section exists in device cfg
 */
int adf_io_cfgCheckUserSection(int dev_id, uint8_t *pSectionPresent)
{
    *pSectionPresent = 1;
    return 0;
}

CpaBoolean adf_io_isDeviceAvailable(void)
{
    struct qatmgr_transport *t_mgr = NULL;

    t_mgr = get_transport_mgr();
    return t_mgr->qat_mgr_is_dev_available();
}

Cpa16U adf_io_getNumPfs(void)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };

    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_NUM_PF_DEVS))
    {
        ADF_ERROR("Failed to get NUM_PF_DEVS response from qatmgr\n");
        return ADF_IO_OPERATION_FAIL_U16;
    }

    return rsp.num_devices;
}

CpaStatus adf_io_getPfInfo(icp_accel_pf_info_t *pPfInfo)
{
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };
    Cpa16U pf_number, i;
    icp_accel_pf_info_t *p;

    ICP_CHECK_FOR_NULL_PARAM(pPfInfo);

    pf_number = adf_io_getNumPfs();
    if (pf_number == ADF_IO_OPERATION_FAIL_U16)
    {
        ADF_ERROR("No PFs found, assuming running inside VM!\n");
        return CPA_STATUS_RESOURCE;
    }

    for (i = 0; i < pf_number; i++)
    {
        req.device_num = i;
        p = pPfInfo + i;
        if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_PF_DEV_INFO))
        {
            ADF_ERROR("Failed to get PF_DEV_INFO response from qatmgr\n");
            return CPA_STATUS_FAIL;
        }

        memcpy(p, &rsp.pf_info, sizeof(rsp.pf_info));
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus adf_io_getHeartBeatStatus(Cpa32U packageId)
{
    char devName[ADF_CFG_MAX_STR_LEN] = { '\0' };
    char *buff = NULL;
    char device_id[DEVICE_NAME_SIZE] = { '\0' };
    size_t lineSize = 0;
    FILE *fp = NULL;
    CpaStatus ret_status = CPA_STATUS_SUCCESS;
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };

    if (packageId == VM_PACKAGE_ID_NONE)
    {
        ADF_ERROR("This API is not supported on a VM");
        return CPA_STATUS_UNSUPPORTED;
    }

    req.device_num = packageId;

    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_PF_DEV_INFO))
    {
        ADF_ERROR("Failed to get PF_DEV_INFO response from qatmgr\n");
        return CPA_STATUS_FAIL;
    }

    snprintf(device_id,
             sizeof(device_id),
             "%04x:%02x:%02x.%01x",
             rsp.pf_info.domain,
             BDF_BUS(rsp.pf_info.bdf),
             BDF_DEV(rsp.pf_info.bdf),
             BDF_FUN(rsp.pf_info.bdf));

    /* Open /sys/kernel/debug/<qat_device>/heartbeat/status */
    if (snprintf(devName,
                 ADF_CFG_MAX_STR_LEN,
                 HB_STATUS_FILE,
                 rsp.pf_info.device_gen,
                 device_id) < 0)
    {
        ADF_ERROR("Failed to build device path %s\n", devName);
        return CPA_STATUS_FAIL;
    }

    fp = fopen(devName, "r");
    if (NULL == fp)
    {
        ADF_ERROR("No heartbeat directory found, "
                  "you may need to update your QAT kernel driver\n");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (getline(&buff, &lineSize, fp) <= 0)
    {
        ret_status = CPA_STATUS_FAIL;
        goto cleanup;
    }
    if (ICP_STRNCMP_CONST_NO_NULL(buff, HB_ALIVE))
        ret_status = CPA_STATUS_FAIL;

cleanup:
    free(buff);
    fclose(fp);

    return ret_status;
}

#ifdef ICP_HB_FAIL_SIM
CpaStatus adf_io_heartbeatSimulateFailure(Cpa32U packageId)
{
    char devName[ADF_CFG_MAX_STR_LEN] = { 0 };
    char device_id[DEVICE_NAME_SIZE];
    int fp = 0;
    struct qatmgr_msg_req req = { 0 };
    struct qatmgr_msg_rsp rsp = { 0 };

    if (packageId == VM_PACKAGE_ID_NONE)
    {
        ADF_ERROR("This API is not supported on a VM");
        return CPA_STATUS_UNSUPPORTED;
    }

    req.device_num = packageId;

    if (qatmgr_query(&req, &rsp, QATMGR_MSGTYPE_PF_DEV_INFO))
    {
        ADF_ERROR("Failed to get PF_DEV_INFO response from qatmgr\n");
        return CPA_STATUS_FAIL;
    }

    snprintf(device_id,
             sizeof(device_id),
             "%04x:%02x:%02x.%01x",
             rsp.pf_info.domain,
             BDF_BUS(rsp.pf_info.bdf),
             BDF_DEV(rsp.pf_info.bdf),
             BDF_FUN(rsp.pf_info.bdf));

    /* Open /sys/kernel/debug/<qat_device>/heartbeat/inject_error */
    if (snprintf(devName,
                 ADF_CFG_MAX_STR_LEN,
                 HB_SIM_FILE,
                 rsp.pf_info.device_gen,
                 device_id) < 0)
    {
        ADF_ERROR("Failed to build device path %s\n", devName);
        return CPA_STATUS_FAIL;
    }

    fp = open(devName, O_WRONLY);
    if (0 > fp)
    {
        ADF_ERROR("No heartbeat directory found, "
                  "you may need to update your QAT kernel driver\n");
        return CPA_STATUS_UNSUPPORTED;
    }

    if (write(fp, HB_SIM_FAIL, strlen(HB_SIM_FAIL)) < 0)
    {
        close(fp);
        ADF_ERROR("Failed to inject error\n");
        return CPA_STATUS_FAIL;
    }
    close(fp);
    return CPA_STATUS_SUCCESS;
}
#endif
