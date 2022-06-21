/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2022 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
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
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file sal_compression.c
 *
 * @ingroup SalCtrl
 *
 * @description
 *    This file contains the sal implementation for compression.
 *
 *****************************************************************************/

/* QAT-API includes */
#include "cpa.h"
#include "cpa_dc.h"

/* Osal includes */
#include "Osal.h"

/* ADF includes */
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_cfg.h"
#include "icp_adf_accel_mgr.h"
#include "icp_adf_poll.h"
#include "icp_adf_debug.h"
#include "icp_qat_hw.h"

/* SAL includes */
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_common.h"
#include "lac_mem_pools.h"
#include "sal_statistics.h"
#include "lac_list.h"
#include "icp_sal_poll.h"
#include "sal_types_compression.h"
#include "dc_session.h"
#include "dc_datapath.h"
#include "dc_stats.h"
#include "lac_sal.h"
#include "lac_sal_ctrl.h"
#include "sal_string_parse.h"
#include "sal_service_state.h"
#include "lac_buffer_desc.h"
#include "icp_qat_fw_comp.h"
#include "icp_qat_hw_20_comp_defs.h"
#include "icp_sal_versions.h"

#ifndef ICP_DC_ONLY
#include "dc_chain.h"
#define CHAINING_CAPABILITY_MASK 0x1FFF0000
#endif

#define MAX_BANK_NUM 1024

/* Type to access extended features bit fields */
typedef struct dc_extended_features_s
{
    unsigned is_cnv : 1; /* Bit<0> */
    unsigned padding : 7;
    unsigned is_cnvnr : 1; /* Bit<8> */
    unsigned padding1 : 7;
    unsigned is_chain_compress_then_hash : 1;                  /* Bit<16> */
    unsigned is_chain_compress_then_encrypt : 1;               /* Bit<17> */
    unsigned is_chain_compress_then_hash_encrypt : 1;          /* Bit<18> */
    unsigned is_chain_compress_then_encrypt_hash : 1;          /* Bit<19> */
    unsigned is_chain_compress_then_aead : 1;                  /* Bit<20> */
    unsigned is_chain_hash_then_compress : 1;                  /* Bit<21> */
    unsigned is_chain_hash_verify_then_decompress : 1;         /* Bit<22> */
    unsigned is_chain_decrypt_then_decompress : 1;             /* Bit<23> */
    unsigned is_chain_hash_verify_decrypt_then_decompress : 1; /* Bit<24> */
    unsigned is_chain_decrypt_hash_verify_then_decompress : 1; /* Bit<25> */
    unsigned is_chain_aead_then_decompress : 1;                /* Bit<26> */
    unsigned is_chain_decompress_then_hash_verify : 1;         /* Bit<27> */
    unsigned is_chain_compress_then_aead_then_hash : 1;        /* Bit<28> */
    unsigned reserved : 3;
} dc_extd_ftrs_t;

/*
 * Prints statistics for a compresion instance
 */
STATIC int SalCtrl_CompresionDebug(void *private_data,
                                   char *data,
                                   int size,
                                   int offset)
{
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)private_data;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcStats dcStats = {0};
    Cpa32S len = 0;

    status = cpaDcGetStats(pCompressionService, &dcStats);
    if (status != CPA_STATUS_SUCCESS)
    {
        LAC_LOG_ERROR("cpaDcGetStats returned error\n");
        return (-1);
    }

    /* Engine Info */
    if (NULL != pCompressionService->debug_file)
    {
        len += snprintf(data + len,
                        size - len,
                        SEPARATOR BORDER
                        " Statistics for Instance %24s | \n" SEPARATOR,
                        pCompressionService->debug_file->name);
    }

    /* Perform Info */
    len += snprintf(
        data + len,
        size - len,
        BORDER " DC comp Requests:               %16llu " BORDER "\n" BORDER
               " DC comp Request Errors:         %16llu " BORDER "\n" BORDER
               " DC comp Completed:              %16llu " BORDER "\n" BORDER
               " DC comp Completed Errors:       %16llu " BORDER "\n" SEPARATOR,
        (long long unsigned int)dcStats.numCompRequests,
        (long long unsigned int)dcStats.numCompRequestsErrors,
        (long long unsigned int)dcStats.numCompCompleted,
        (long long unsigned int)dcStats.numCompCompletedErrors);

    /* Perform Info */
    len += snprintf(
        data + len,
        size - len,
        BORDER " DC decomp Requests:             %16llu " BORDER "\n" BORDER
               " DC decomp Request Errors:       %16llu " BORDER "\n" BORDER
               " DC decomp Completed:            %16llu " BORDER "\n" BORDER
               " DC decomp Completed Errors:     %16llu " BORDER "\n" SEPARATOR,
        (long long unsigned int)dcStats.numDecompRequests,
        (long long unsigned int)dcStats.numDecompRequestsErrors,
        (long long unsigned int)dcStats.numDecompCompleted,
        (long long unsigned int)dcStats.numDecompCompletedErrors);
    return 0;
}

STATIC void SalCtrl_Init_Compression_Levels_gen2(
    sal_compression_device_data_t *comp_device_data)
{
    int level = 0;

    for (level = CPA_DC_L1; level <= CPA_DC_L12; level++)
    {
        switch (level)
        {
            case CPA_DC_L1:
            case CPA_DC_L2:
            case CPA_DC_L3:
            case CPA_DC_L4:
                comp_device_data->uniqueCompressionLevels[level] = CPA_TRUE;
                break;
            default:
                comp_device_data->uniqueCompressionLevels[level] = CPA_FALSE;
                break;
        }
    }
    comp_device_data->numCompressionLevels = DC_NUM_COMPRESSION_LEVELS;
}

/* Initialise device specific information needed by compression service */
STATIC CpaStatus
SalCtrl_CompressionInit_CompData(icp_accel_dev_t *device,
                                 sal_compression_service_t *pCompService)
{
    int level = 0;

    pCompService->comp_device_data.uniqueCompressionLevels[0] = CPA_FALSE;
    switch (device->deviceType)
    {
        case DEVICE_DH895XCC:
        case DEVICE_DH895XCCVF:
            pCompService->numInterBuffs =
                DC_QAT_MAX_NUM_INTER_BUFFERS_6COMP_SLICES;
            pCompService->comp_device_data.minOutputBuffSize =
                DC_DEST_BUFFER_STA_MIN_SIZE;
            pCompService->comp_device_data.minOutputBuffSizeDynamic =
                pCompService->comp_device_data.minOutputBuffSize;
            pCompService->comp_device_data.oddByteDecompNobFinal = CPA_TRUE;
            pCompService->comp_device_data.oddByteDecompInterim = CPA_FALSE;
            pCompService->comp_device_data.translatorOverflow = CPA_FALSE;
            pCompService->comp_device_data.useDevRam =
                ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            pCompService->comp_device_data.enableDmm = CPA_FALSE;
            pCompService->comp_device_data.inflateContextSize =
                DC_INFLATE_CONTEXT_SIZE;
            pCompService->comp_device_data.highestHwCompressionDepth =
                ICP_QAT_HW_COMPRESSION_DEPTH_16;
            pCompService->comp_device_data.windowSizeMask =
                (1 << DC_4K_WINDOW_SIZE | 1 << DC_8K_WINDOW_SIZE |
                 1 << DC_16K_WINDOW_SIZE | 1 << DC_32K_WINDOW_SIZE);
            SalCtrl_Init_Compression_Levels_gen2(
                &pCompService->comp_device_data);
            break;
        case DEVICE_C3XXX:
        case DEVICE_C3XXXVF:
        case DEVICE_200XX:
        case DEVICE_200XXVF:
            pCompService->numInterBuffs =
                DC_QAT_MAX_NUM_INTER_BUFFERS_6COMP_SLICES;
            pCompService->comp_device_data.oddByteDecompNobFinal = CPA_FALSE;
            pCompService->comp_device_data.oddByteDecompInterim = CPA_TRUE;
            pCompService->comp_device_data.translatorOverflow = CPA_FALSE;
            pCompService->comp_device_data.useDevRam =
                ICP_QAT_FW_COMP_DISABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            pCompService->comp_device_data.inflateContextSize =
                DC_INFLATE_EH_CONTEXT_SIZE;
            pCompService->comp_device_data.highestHwCompressionDepth =
                ICP_QAT_HW_COMPRESSION_DEPTH_16;
            pCompService->comp_device_data.windowSizeMask =
                (1 << DC_4K_WINDOW_SIZE | 1 << DC_8K_WINDOW_SIZE |
                 1 << DC_16K_WINDOW_SIZE | 1 << DC_32K_WINDOW_SIZE);
            pCompService->comp_device_data.minOutputBuffSize =
                DC_DEST_BUFFER_STA_MIN_SIZE;
            pCompService->comp_device_data.minOutputBuffSizeDynamic =
                pCompService->comp_device_data.minOutputBuffSize;
            pCompService->comp_device_data.enableDmm = CPA_TRUE;
            SalCtrl_Init_Compression_Levels_gen2(
                &pCompService->comp_device_data);
            break;
        case DEVICE_C62X:
        case DEVICE_C62XVF:
            pCompService->numInterBuffs =
                DC_QAT_MAX_NUM_INTER_BUFFERS_10COMP_SLICES;
            pCompService->comp_device_data.oddByteDecompNobFinal = CPA_FALSE;
            pCompService->comp_device_data.oddByteDecompInterim = CPA_TRUE;
            pCompService->comp_device_data.translatorOverflow = CPA_FALSE;
            pCompService->comp_device_data.useDevRam =
                ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            pCompService->comp_device_data.inflateContextSize =
                DC_INFLATE_EH_CONTEXT_SIZE;
            pCompService->comp_device_data.highestHwCompressionDepth =
                ICP_QAT_HW_COMPRESSION_DEPTH_16;
            pCompService->comp_device_data.windowSizeMask =
                (1 << DC_4K_WINDOW_SIZE | 1 << DC_8K_WINDOW_SIZE |
                 1 << DC_16K_WINDOW_SIZE | 1 << DC_32K_WINDOW_SIZE);
            pCompService->comp_device_data.minOutputBuffSize =
                DC_DEST_BUFFER_STA_MIN_SIZE;
            pCompService->comp_device_data.minOutputBuffSizeDynamic =
                pCompService->comp_device_data.minOutputBuffSize;
            pCompService->comp_device_data.enableDmm = CPA_TRUE;
            SalCtrl_Init_Compression_Levels_gen2(
                &pCompService->comp_device_data);
            break;
        case DEVICE_D15XX:
        case DEVICE_D15XXVF:
            pCompService->numInterBuffs =
                DC_QAT_MAX_NUM_INTER_BUFFERS_10COMP_SLICES;
            pCompService->comp_device_data.minOutputBuffSize =
                DC_DEST_BUFFER_STA_MIN_SIZE;
            pCompService->comp_device_data.minOutputBuffSizeDynamic =
                pCompService->comp_device_data.minOutputBuffSize;
            pCompService->comp_device_data.oddByteDecompNobFinal = CPA_FALSE;
            pCompService->comp_device_data.oddByteDecompInterim = CPA_TRUE;
            pCompService->comp_device_data.translatorOverflow = CPA_FALSE;
            pCompService->comp_device_data.useDevRam =
                ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            pCompService->comp_device_data.enableDmm = CPA_TRUE;
            pCompService->comp_device_data.inflateContextSize =
                DC_INFLATE_EH_CONTEXT_SIZE;
            pCompService->comp_device_data.highestHwCompressionDepth =
                ICP_QAT_HW_COMPRESSION_DEPTH_16;
            pCompService->comp_device_data.windowSizeMask =
                (1 << DC_4K_WINDOW_SIZE | 1 << DC_8K_WINDOW_SIZE |
                 1 << DC_16K_WINDOW_SIZE | 1 << DC_32K_WINDOW_SIZE);
            SalCtrl_Init_Compression_Levels_gen2(
                &pCompService->comp_device_data);
            break;
        case DEVICE_4XXX:
        case DEVICE_4XXXVF:
            if ((device->accelCapabilitiesMask &
                 ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY) ||
                (device->accelCapabilitiesMask &
                 ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY64))
            {
                pCompService->generic_service_info.integrityCrcCheck = CPA_TRUE;
            }
            pCompService->numInterBuffs =
                DC_QAT_MAX_NUM_INTER_BUFFERS_6COMP_SLICES;
            pCompService->comp_device_data.minOutputBuffSize =
                DC_DEST_BUFFER_STA_MIN_SIZE_GEN4;
            pCompService->comp_device_data.minOutputBuffSizeDynamic =
                DC_DEST_BUFFER_DYN_MIN_SIZE_GEN4;
            pCompService->comp_device_data.oddByteDecompNobFinal = CPA_TRUE;
            pCompService->comp_device_data.oddByteDecompInterim = CPA_FALSE;
            pCompService->comp_device_data.translatorOverflow = CPA_TRUE;
            pCompService->comp_device_data.useDevRam =
                ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            pCompService->comp_device_data.enableDmm = CPA_TRUE;
            pCompService->comp_device_data.inflateContextSize =
                DC_INFLATE_CONTEXT_SIZE;
            pCompService->comp_device_data.lz4DecompContextSize =
                DC_LZ4_DECOMP_CONTEXT_SIZE;
            pCompService->comp_device_data.highestHwCompressionDepth =
                ICP_QAT_HW_COMP_20_SEARCH_DEPTH_LEVEL_9;
            pCompService->comp_device_data.windowSizeMask =
                (1 << DC_4K_WINDOW_SIZE | 1 << DC_8K_WINDOW_SIZE |
                 1 << DC_16K_WINDOW_SIZE | 1 << DC_32K_WINDOW_SIZE);
            for (level = CPA_DC_L1; level <= CPA_DC_L12; level++)
            {
                switch (level)
                {
                    case CPA_DC_L1:
                    case CPA_DC_L6:
                    case CPA_DC_L9:
                        pCompService->comp_device_data
                            .uniqueCompressionLevels[level] = CPA_TRUE;
                        break;
                    default:
                        pCompService->comp_device_data
                            .uniqueCompressionLevels[level] = CPA_FALSE;
                        break;
                }
            }
            pCompService->comp_device_data.numCompressionLevels =
                DC_NUM_COMPRESSION_LEVELS;
            break;
        case DEVICE_C4XXX:
        case DEVICE_C4XXXVF:
            switch (device->sku)
            {
                case DEV_SKU_1:
                case DEV_SKU_VF: /* Default to max buf for VF */
                    pCompService->numInterBuffs =
                        DC_QAT_MAX_NUM_INTER_BUFFERS_12COMP_SLICES;
                    break;
                case DEV_SKU_2:
                    pCompService->numInterBuffs =
                        DC_QAT_MAX_NUM_INTER_BUFFERS_8COMP_SLICES;
                    break;
                case DEV_SKU_3:
                    pCompService->numInterBuffs =
                        DC_QAT_MAX_NUM_INTER_BUFFERS_4COMP_SLICES;
                    break;
                default:
                    LAC_LOG_ERROR1("Unknown sku type! - %d\n", device->sku);
                    return CPA_STATUS_FAIL;
            }

            pCompService->generic_service_info.integrityCrcCheck = CPA_TRUE;
            pCompService->comp_device_data.minOutputBuffSize =
                DC_DEST_BUFFER_MIN_SIZE;
            pCompService->comp_device_data.oddByteDecompNobFinal = CPA_TRUE;
            pCompService->comp_device_data.oddByteDecompInterim = CPA_TRUE;
            pCompService->comp_device_data.translatorOverflow = CPA_TRUE;
            if (pCompService->generic_service_info.capabilitiesMask &
                ICP_ACCEL_CAPABILITIES_INLINE)
            {
                pCompService->comp_device_data.useDevRam =
                    ICP_QAT_FW_COMP_DISABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            }
            else
            {
                pCompService->comp_device_data.useDevRam =
                    ICP_QAT_FW_COMP_ENABLE_SECURE_RAM_USED_AS_INTMD_BUF;
            }
            pCompService->comp_device_data.enableDmm = CPA_TRUE;
            pCompService->comp_device_data.inflateContextSize =
                DC_INFLATE_EH_CONTEXT_SIZE;
            pCompService->comp_device_data.highestHwCompressionDepth =
                ICP_QAT_HW_COMPRESSION_DEPTH_128;
            pCompService->comp_device_data.windowSizeMask =
                (1 << DC_16K_WINDOW_SIZE | 1 << DC_32K_WINDOW_SIZE);
            for (level = 0; level < DC_NUM_COMPRESSION_LEVELS; level++)
            {
                switch (level)
                {
                    case CPA_DC_L1:
                    case CPA_DC_L2:
                    case CPA_DC_L3:
                    case CPA_DC_L4:
                    case CPA_DC_L5:
                        pCompService->comp_device_data
                            .uniqueCompressionLevels[level] = CPA_TRUE;
                        break;
                    default:
                        pCompService->comp_device_data
                            .uniqueCompressionLevels[level] = CPA_FALSE;
                        break;
                }
            }
            pCompService->comp_device_data.numCompressionLevels =
                DC_NUM_COMPRESSION_LEVELS;
            break;
        default:
            LAC_LOG_ERROR1("Unknown device type! - %d\n", device->deviceType);
            return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus SalCtrl_DcCheckRespInstance(sal_service_t *service)
{
    sal_compression_service_t *dc_handle = (sal_compression_service_t *)service;
    icp_comms_trans_handle trans_hndTable[DC_NUM_RX_RINGS];

    trans_hndTable[0] = dc_handle->trans_handle_compression_rx;
    return icp_adf_check_RespInstance(trans_hndTable, DC_NUM_RX_RINGS);
}

STATIC CpaStatus SalCtr_DcInstInit(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string2[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char *section = DYN_SEC;
    Cpa32S strSize = 0;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCompressionService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }


    /* Get Config Info: Accel Num, bank Num, packageID,
                            coreAffinity, nodeAffinity and response mode */

    pCompressionService->acceleratorNum = 0;

    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_RING_BANK_NUM,
                          temp_string);
    LAC_CHECK_STATUS(status);
    status =
        icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }
    pCompressionService->bankNum =
        (Cpa16U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

    if (pCompressionService->bankNum > MAX_BANK_NUM)
    {
        return CPA_STATUS_FAIL;
    }

    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_POLL_MODE,
                          temp_string);
    LAC_CHECK_STATUS(status);
    status =
        icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }
    pCompressionService->isPolled =
        (Cpa8U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

#ifdef KERNEL_SPACE
    /* Kernel instances do not support epoll mode */
    if (SAL_RESP_EPOLL_CFG_FILE == pCompressionService->isPolled)
    {
        LAC_LOG_ERROR_PARAMS(
            "IsPolled %u is not supported for kernel instance %s",
            pCompressionService->isPolled,
            temp_string);
        return CPA_STATUS_FAIL;
    }
#endif
#ifndef KERNEL_SPACE
    /* User instances only support poll and epoll mode */
    if (SAL_RESP_POLL_CFG_FILE != pCompressionService->isPolled &&
        SAL_RESP_EPOLL_CFG_FILE != pCompressionService->isPolled)
    {
        LAC_LOG_ERROR_PARAMS("IsPolled %u is not supported for "
                             "user instance %s",
                             pCompressionService->isPolled,
                             temp_string);
        return CPA_STATUS_FAIL;
    }
#endif

    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_DEV_PKG_ID, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              ADF_DEV_PKG_ID);
        return status;
    }
    pCompressionService->pkgID =
        (Cpa16U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

    status = icp_adf_cfgGetParamValue(
        device, LAC_CFG_SECTION_GENERAL, ADF_DEV_NODE_ID, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              ADF_DEV_NODE_ID);
        return status;
    }
    pCompressionService->nodeAffinity =
        (Cpa32U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

    /* In case of interrupt instance, use the bank affinity set by adf_ctl
     * Otherwise, use the instance affinity for backwards compatibility */
    if (SAL_RESP_POLL_CFG_FILE != pCompressionService->isPolled)
    {
        /* Next need to read the [AcceleratorX] section of the config file */
        status = Sal_StringParsing(SAL_CFG_ACCEL_SEC,
                                   pCompressionService->acceleratorNum,
                                   "",
                                   temp_string2);
        LAC_CHECK_STATUS(status);

        status = Sal_StringParsing(SAL_CFG_ETRMGR_BANK,
                                   pCompressionService->bankNum,
                                   SAL_CFG_ETRMGR_CORE_AFFINITY,
                                   temp_string);
        LAC_CHECK_STATUS(status);
    }
    else
    {
        strSize = snprintf(temp_string2, sizeof(temp_string2), "%s", section);
        LAC_CHECK_PARAM_RANGE(strSize, 1, sizeof(temp_string2));

        status = Sal_StringParsing(
            SAL_CFG_DC,
            pCompressionService->generic_service_info.instance,
            SAL_CFG_ETRMGR_CORE_AFFINITY,
            temp_string);
        LAC_CHECK_STATUS(status);
    }

    status = icp_adf_cfgGetParamValue(
        device, temp_string2, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }
    pCompressionService->coreAffinity =
        (Cpa32U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);

    return status;
}

STATIC void SalCtrl_DcDebugCleanup(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;

    if (CPA_TRUE == pStatsCollection->bStatsEnabled)
    {
        /* Clean stats */
        if (NULL != pCompressionService->debug_file)
        {
            LAC_OS_FREE(pCompressionService->debug_file->name);
            LAC_OS_FREE(pCompressionService->debug_file);
            pCompressionService->debug_file = NULL;
        }
    }
}

STATIC void SalCtrl_DcDebugShutdown(icp_accel_dev_t *device,
                                    sal_service_t *service)
{
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    SalCtrl_DcDebugCleanup(device, service);
    pCompressionService->generic_service_info.stats = NULL;
}

STATIC void SalCtrl_DcDebugRestarting(icp_accel_dev_t *device,
                                      sal_service_t *service)
{
    SalCtrl_DcDebugCleanup(device, service);
}

STATIC CpaStatus SalCtrl_DcDebugInit(icp_accel_dev_t *device,
                                     sal_service_t *service)
{
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char *instance_name = NULL;
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char *section = DYN_SEC;

    /* Instance may not in the DYN section */
    if (CPA_FALSE == pCompressionService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    if (CPA_TRUE == pStatsCollection->bStatsEnabled)
    {
        /* Get instance name for stats */
        status = LAC_OS_MALLOC(&instance_name, ADF_CFG_MAX_VAL_LEN_IN_BYTES);
        LAC_CHECK_STATUS(status);

        status = Sal_StringParsing(
            SAL_CFG_DC,
            pCompressionService->generic_service_info.instance,
            SAL_CFG_NAME,
            temp_string);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_OS_FREE(instance_name);
            return status;
        }
        status =
            icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                                  temp_string);
            LAC_OS_FREE(instance_name);
            return status;
        }
        snprintf(
            instance_name, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%s", adfGetParam);

        status = LAC_OS_MALLOC(&pCompressionService->debug_file,
                               sizeof(debug_file_info_t));
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_OS_FREE(instance_name);
            return status;
        }
        osalMemSet(
            pCompressionService->debug_file, 0, sizeof(debug_file_info_t));
        pCompressionService->debug_file->name = instance_name;
        pCompressionService->debug_file->seq_read = SalCtrl_CompresionDebug;
        pCompressionService->debug_file->private_data = pCompressionService;
        pCompressionService->debug_file->parent =
            pCompressionService->generic_service_info.debug_parent_dir;
    }
    pCompressionService->generic_service_info.stats = pStatsCollection;

    return status;
}

STATIC CpaStatus
SalCtrl_GetDcConcurrentReqNum(char *string1,
                              char *section,
                              char *string2,
                              sal_compression_service_t *pCompressionService,
                              Cpa32U *pNumDcConcurrentReq,
                              icp_accel_dev_t *device)
{
    char adfGetParam[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    Cpa32U numDcConcurrentReq = 0;

    /* get num concurrent requests from config file */
    status =
        Sal_StringParsing(string1,
                          pCompressionService->generic_service_info.instance,
                          string2,
                          temp_string);
    LAC_CHECK_STATUS(status);
    status =
        icp_adf_cfgGetParamValue(device, section, temp_string, adfGetParam);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_STRING_ERROR1("Failed to get %s from configuration file",
                              temp_string);
        return status;
    }

    numDcConcurrentReq =
        (Cpa32U)Sal_Strtoul(adfGetParam, NULL, SAL_CFG_BASE_DEC);
    if (CPA_STATUS_FAIL == validateConcurrRequest(numDcConcurrentReq))
    {
        LAC_LOG_ERROR("Invalid NumConcurrentDcRequests, valid "
                      "values {64, 128, 256, 512, .. 32768, 65536}");
        return CPA_STATUS_FAIL;
    }

    *pNumDcConcurrentReq = numDcConcurrentReq;

    return status;
}

CpaStatus SalCtrl_CompressionInit(icp_accel_dev_t *device,
                                  sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numCompConcurrentReq = 0;
    char compMemPool[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;
    icp_resp_deliv_method rx_resp_type = ICP_RESP_TYPE_IRQ;
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    Cpa32U msgSize = 0;
    char *section = DYN_SEC;
#ifndef ICP_DC_ONLY
    sal_dc_chain_service_t *pChainService = NULL;
#endif

    SAL_SERVICE_GOOD_FOR_INIT(pCompressionService);

    pCompressionService->generic_service_info.state =
        SAL_SERVICE_STATE_INITIALIZING;

    if (CPA_FALSE == pCompressionService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    if (pStatsCollection == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    /* Get Config Info: Accel Num, bank Num, packageID,
                                coreAffinity, nodeAffinity and response mode */

    pCompressionService->acceleratorNum = 0;
    pCompressionService->compression_mem_pool = LAC_MEM_POOL_INIT_POOL_ID;
    pCompressionService->trans_handle_compression_tx = NULL;
    pCompressionService->trans_handle_compression_rx = NULL;
    pCompressionService->debug_file = NULL;


    /* Initialise device specific compression data */
    SalCtrl_CompressionInit_CompData(device, pCompressionService);

    status = SalCtr_DcInstInit(device, service);
    LAC_CHECK_STATUS(status);

    if (SAL_RESP_POLL_CFG_FILE == pCompressionService->isPolled)
    {
        rx_resp_type = ICP_RESP_TYPE_POLL;
    }

    if (SalCtrl_GetDcConcurrentReqNum(SAL_CFG_DC,
                                      section,
                                      SAL_CFG_RING_DC_SIZE,
                                      pCompressionService,
                                      &numCompConcurrentReq,
                                      device))
    {
        LAC_LOG_ERROR("Failed to get ConcurrentReqNum\n");
        return CPA_STATUS_FAIL;
    }

    /* ADF does not allow us to completely fill the ring for batch requests */
    pCompressionService->maxNumCompConcurrentReq =
        (numCompConcurrentReq - SAL_BATCH_SUBMIT_FREE_SPACE);

    /* 1. Create transport handles */
    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_RING_DC_TX,
                          temp_string);
    LAC_CHECK_STATUS(status);

    msgSize = LAC_QAT_DC_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transCreateHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCompressionService->acceleratorNum,
        pCompressionService->bankNum,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_DC),
        NULL,
        ICP_RESP_TYPE_NONE,
        numCompConcurrentReq,
        msgSize,
        (icp_comms_trans_handle *)&(
            pCompressionService->trans_handle_compression_tx));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to create DC TX handle");
        goto cleanup;
    }

    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_RING_DC_RX,
                          temp_string);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to parse DcRringRx string");
        goto cleanup;
    }

    msgSize = LAC_QAT_DC_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transCreateHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCompressionService->acceleratorNum,
        pCompressionService->bankNum,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_NONE),
        (icp_trans_callback)dcCompression_ProcessCallback,
        rx_resp_type,
        numCompConcurrentReq,
        msgSize,
        (icp_comms_trans_handle *)&(
            pCompressionService->trans_handle_compression_rx));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to create DC RX handle");
        goto cleanup;
    }

    /* 2. Allocates memory pools */
    status =
        Sal_StringParsing(SAL_CFG_COMP,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_MEMPOOL,
                          compMemPool);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to parse Comp_MemPool string\n");
        goto cleanup;
    }

    status = Lac_MemPoolCreate(&pCompressionService->compression_mem_pool,
                               compMemPool,
                               (numCompConcurrentReq + 1),
                               sizeof(dc_compression_cookie_t),
                               LAC_64BYTE_ALIGNMENT,
                               CPA_FALSE,
                               pCompressionService->nodeAffinity);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to create dc memory pool\n");
        goto cleanup;
    }

    /* Init compression statistics */
    status = dcStatsInit(pCompressionService);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to initialize compression statistics\n");
        goto cleanup;
    }

    status = SalCtrl_DcDebugInit(device, service);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to initialize compression debugfs\n");
        goto cleanup;
    }

    pCompressionService->pDcChainService = NULL;

#ifndef ICP_DC_ONLY
#ifndef KERNEL_SPACE
    /* Only init Chaining service if loaded FW supports chaining */
    if ((CHAINING_CAPABILITY_MASK & device->dcExtendedFeatures))
    {
        status = LAC_OS_MALLOC(&pChainService, sizeof(sal_dc_chain_service_t));
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to allocate chain service\n");
            goto cleanup;
        }
        LAC_OS_BZERO(pChainService, sizeof(sal_dc_chain_service_t));
        status = dcChainServiceInit(pCompressionService, pChainService);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to init chain service\n");
            goto cleanup;
        }
    }
#endif
#endif

    pCompressionService->generic_service_info.state =
        SAL_SERVICE_STATE_INITIALIZED;

    return status;

cleanup:
    if (pCompressionService->trans_handle_compression_tx)
    {
        icp_adf_transReleaseHandle(
            pCompressionService->trans_handle_compression_tx);
    }

    if (pCompressionService->trans_handle_compression_rx)
    {
        icp_adf_transReleaseHandle(
            pCompressionService->trans_handle_compression_rx);
    }

    if (LAC_MEM_POOL_INIT_POOL_ID != pCompressionService->compression_mem_pool)
    {
        Lac_MemPoolDestroy(pCompressionService->compression_mem_pool);
    }

    SalCtrl_DcDebugShutdown(device, service);

#ifndef ICP_DC_ONLY
    if (NULL != pChainService)
    {
        LAC_OS_FREE(pChainService);
    }
#endif
    return status;
}

CpaStatus SalCtrl_CompressionStart(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;

    if (SAL_SERVICE_STATE_INITIALIZED !=
        pCompressionService->generic_service_info.state)
    {
        LAC_LOG_ERROR("Not in the correct state to call start\n");
        return CPA_STATUS_FAIL;
    }
    /**************************************************************/
    /* Obtain Extended Features. I.e. Compress And Verify  */
    /**************************************************************/
    pCompressionService->generic_service_info.dcExtendedFeatures =
        device->dcExtendedFeatures;
    pCompressionService->generic_service_info.state = SAL_SERVICE_STATE_RUNNING;

    return status;
}

CpaStatus SalCtrl_CompressionStop(icp_accel_dev_t *device,
                                  sal_service_t *service)
{
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;

    if (SAL_SERVICE_STATE_RUNNING !=
        pCompressionService->generic_service_info.state)
    {
        LAC_LOG_ERROR("Not in the correct state to call stop");
        return CPA_STATUS_FAIL;
    }

    pCompressionService->generic_service_info.state =
        SAL_SERVICE_STATE_SHUTTING_DOWN;
    return CPA_STATUS_SUCCESS;
}

CpaStatus SalCtrl_CompressionShutdown(icp_accel_dev_t *device,
                                      sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;

    if ((SAL_SERVICE_STATE_INITIALIZED !=
         pCompressionService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_SHUTTING_DOWN !=
         pCompressionService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_RESTARTING !=
         pCompressionService->generic_service_info.state))
    {
        LAC_LOG_ERROR("Not in the correct state to call shutdown");
        return CPA_STATUS_FAIL;
    }


    Lac_MemPoolDestroy(pCompressionService->compression_mem_pool);

    status = icp_adf_transReleaseHandle(
        pCompressionService->trans_handle_compression_tx);
    LAC_CHECK_STATUS(status);

    status = icp_adf_transReleaseHandle(
        pCompressionService->trans_handle_compression_rx);
    LAC_CHECK_STATUS(status);

    if (CPA_TRUE == pStatsCollection->bDcStatsEnabled)
    {
        if (NULL != pCompressionService->debug_file)
        {
            /* Clean stats */
            LAC_OS_FREE(pCompressionService->debug_file->name);
            LAC_OS_FREE(pCompressionService->debug_file);
            pCompressionService->debug_file = NULL;
        }
    }
    pCompressionService->generic_service_info.stats = NULL;
    dcStatsFree(pCompressionService);
#ifndef ICP_DC_ONLY
    if (NULL != pCompressionService->pDcChainService)
    {
        dcChainServiceShutdown(pCompressionService,
                               pCompressionService->pDcChainService);
        LAC_OS_FREE(pCompressionService->pDcChainService);
    }
#endif
    SalCtrl_DcDebugShutdown(device, service);

    pCompressionService->generic_service_info.state =
        SAL_SERVICE_STATE_SHUTDOWN;
    return status;
}

CpaStatus SalCtrl_CompressionRestarting(icp_accel_dev_t *device,
                                        sal_service_t *service)
{
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;

    if ((SAL_SERVICE_STATE_RUNNING !=
         pCompressionService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_ERROR !=
         pCompressionService->generic_service_info.state))

    {
        LAC_LOG_ERROR("Not in the correct state to call restarting\n");
        return CPA_STATUS_FAIL;
    }


    status = icp_adf_transResetHandle(
        pCompressionService->trans_handle_compression_tx);
    LAC_CHECK_STATUS(status);

    status = icp_adf_transResetHandle(
        pCompressionService->trans_handle_compression_rx);
    LAC_CHECK_STATUS(status);

    if (CPA_TRUE == pStatsCollection->bDcStatsEnabled)
    {
        /* Free debug file */
        LAC_OS_FREE(pCompressionService->debug_file->name);
        LAC_OS_FREE(pCompressionService->debug_file);
        pCompressionService->debug_file = NULL;
    }
#ifndef ICP_DC_ONLY
    if (NULL != pCompressionService->pDcChainService)
    {
        dcChainServiceShutdown(pCompressionService,
                               pCompressionService->pDcChainService);
        LAC_OS_FREE(pCompressionService->pDcChainService);
    }
#endif
    SalCtrl_DcDebugRestarting(device, service);

    pCompressionService->generic_service_info.state =
        SAL_SERVICE_STATE_RESTARTING;
    dcStatsReset(pCompressionService);
    return CPA_STATUS_SUCCESS;
}

CpaStatus SalCtrl_CompressionRestarted(icp_accel_dev_t *device,
                                       sal_service_t *service)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U numCompConcurrentReq = 0;
    char temp_string[SAL_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    sal_statistics_collection_t *pStatsCollection =
        (sal_statistics_collection_t *)device->pQatStats;
    icp_resp_deliv_method rx_resp_type = ICP_RESP_TYPE_IRQ;
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    Cpa32U msgSize = 0;
    char *section = DYN_SEC;
#ifndef ICP_DC_ONLY
    sal_dc_chain_service_t *pChainService = NULL;
#endif

    SAL_SERVICE_GOOD_FOR_RESTARTED(pCompressionService);

    if (CPA_FALSE == pCompressionService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    if (pStatsCollection == NULL)
    {
        status = CPA_STATUS_FAIL;
        goto cleanup;
    }

    /* Get Config Info: Accel Num, bank Num, packageID,
                                coreAffinity, nodeAffinity and response mode */

    pCompressionService->acceleratorNum = 0;
    pCompressionService->debug_file = NULL;


    /* Initialise device specific compression data */
    SalCtrl_CompressionInit_CompData(device, pCompressionService);

    status = SalCtr_DcInstInit(device, service);
    LAC_CHECK_STATUS(status);

    if (SAL_RESP_POLL_CFG_FILE == pCompressionService->isPolled)
    {
        rx_resp_type = ICP_RESP_TYPE_POLL;
    }

    if (SalCtrl_GetDcConcurrentReqNum(SAL_CFG_DC,
                                      section,
                                      SAL_CFG_RING_DC_SIZE,
                                      pCompressionService,
                                      &numCompConcurrentReq,
                                      device))
    {
        LAC_LOG_ERROR("Failed to get ConcurrentReqNum\n");
        status = CPA_STATUS_FAIL;
        goto cleanup;
    }

    /* ADF does not allow us to completely fill the ring for batch requests */
    pCompressionService->maxNumCompConcurrentReq =
        (numCompConcurrentReq - SAL_BATCH_SUBMIT_FREE_SPACE);

    /* 1. Create transport handles */
    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_RING_DC_TX,
                          temp_string);
    LAC_CHECK_STATUS(status);

    msgSize = LAC_QAT_DC_REQ_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transReinitHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCompressionService->acceleratorNum,
        pCompressionService->bankNum,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_DC),
        NULL,
        ICP_RESP_TYPE_NONE,
        numCompConcurrentReq,
        msgSize,
        (icp_comms_trans_handle *)&(
            pCompressionService->trans_handle_compression_tx));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to create DC TX handle");
        goto cleanup;
    }

    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_RING_DC_RX,
                          temp_string);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to parse DcRringRx string");
        goto cleanup;
    }

    msgSize = LAC_QAT_DC_RESP_SZ_LW * LAC_LONG_WORD_IN_BYTES;
    status = icp_adf_transReinitHandle(
        device,
        ICP_TRANS_TYPE_ETR,
        section,
        pCompressionService->acceleratorNum,
        pCompressionService->bankNum,
        temp_string,
        lac_getRingType(SAL_RING_TYPE_NONE),
        (icp_trans_callback)dcCompression_ProcessCallback,
        rx_resp_type,
        numCompConcurrentReq,
        msgSize,
        (icp_comms_trans_handle *)&(
            pCompressionService->trans_handle_compression_rx));
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to create DC RX handle");
        goto cleanup;
    }

    status = SalCtrl_DcDebugInit(device, service);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Failed to initialize compression debugfs\n");
        goto cleanup;
    }

    pCompressionService->pDcChainService = NULL;

#ifndef ICP_DC_ONLY
#ifndef KERNEL_SPACE
    /* Only init Chaining service if loaded FW supports chaining */
    if ((CHAINING_CAPABILITY_MASK & device->dcExtendedFeatures))
    {
        status = LAC_OS_MALLOC(&pChainService, sizeof(sal_dc_chain_service_t));
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to allocate chain service\n");
            goto cleanup;
        }
        LAC_OS_BZERO(pChainService, sizeof(sal_dc_chain_service_t));
        status = dcChainServiceInit(pCompressionService, pChainService);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Failed to init chain service\n");
            goto cleanup;
        }
    }
#endif
#endif

    pCompressionService->generic_service_info.dcExtendedFeatures =
        device->dcExtendedFeatures;
    pCompressionService->generic_service_info.state = SAL_SERVICE_STATE_RUNNING;

    return status;

cleanup:
    if (pCompressionService->trans_handle_compression_tx)
    {
        icp_adf_transReleaseHandle(
            pCompressionService->trans_handle_compression_tx);
    }

    if (pCompressionService->trans_handle_compression_rx)
    {
        icp_adf_transReleaseHandle(
            pCompressionService->trans_handle_compression_rx);
    }

    if (LAC_MEM_POOL_INIT_POOL_ID != pCompressionService->compression_mem_pool)
    {
        Lac_MemPoolDestroy(pCompressionService->compression_mem_pool);
    }

#ifndef ICP_DC_ONLY
    if (NULL != pChainService)
    {
        LAC_OS_FREE(pChainService);
    }
#endif
    return status;
}

CpaStatus SalCtrl_CompressionError(icp_accel_dev_t *device,
                                   sal_service_t *service)
{
    sal_compression_service_t *pCompressionService =
        (sal_compression_service_t *)service;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if ((SAL_SERVICE_STATE_RUNNING !=
         pCompressionService->generic_service_info.state) &&
        (SAL_SERVICE_STATE_ERROR !=
         pCompressionService->generic_service_info.state))
    {
        LAC_LOG_ERROR("Not in the correct state to call ERROR");
        return CPA_STATUS_FAIL;
    }

    /* There is no need to add a judgment condition like in
     * SalCtrl_CryptoError() function as the compression
     * service doesn't support dummy response */
    status = SalCtrl_DcCheckRespInstance(service);

    /* The polling functions would be prevented to poll due to
     * SAL_RUNNING_CHECK check which may cause missing retrieving in-flight
     * responses. Hence the error status is only set after there are no
     * remained responses on the response ring. */
    if (CPA_STATUS_SUCCESS == status)
    {
        pCompressionService->generic_service_info.state =
            SAL_SERVICE_STATE_ERROR;
    }
    return status;
}

CpaStatus cpaDcGetStatusText(const CpaInstanceHandle dcInstance,
                             const CpaStatus errStatus,
                             Cpa8S *pStatusText)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pStatusText);
#endif

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, %d, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             errStatus,
             (LAC_ARCH_UINT)pStatusText);
#endif

    switch (errStatus)
    {
        case CPA_STATUS_SUCCESS:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_SUCCESS);
            break;
        case CPA_STATUS_FAIL:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_FAIL);
            break;
        case CPA_STATUS_RETRY:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_RETRY);
            break;
        case CPA_STATUS_RESOURCE:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_RESOURCE);
            break;
        case CPA_STATUS_INVALID_PARAM:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_INVALID_PARAM);
            break;
        case CPA_STATUS_FATAL:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_FATAL);
            break;
        case CPA_STATUS_UNSUPPORTED:
            LAC_COPY_STRING(pStatusText, CPA_STATUS_STR_UNSUPPORTED);
            break;
        default:
            status = CPA_STATUS_INVALID_PARAM;
            break;
    }

    return status;
}

CpaStatus cpaDcGetNumIntermediateBuffers(CpaInstanceHandle dcInstance,
                                         Cpa16U *pNumBuffers)
{
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pNumBuffers);
#endif

    pService = (sal_compression_service_t *)insHandle;
    *pNumBuffers = pService->numInterBuffs;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)insHandle,
             (LAC_ARCH_UINT)pNumBuffers,
             *pNumBuffers);
#endif
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcStartInstance(CpaInstanceHandle instanceHandle,
                             Cpa16U numBuffers,
                             CpaBufferList **pIntermediateBufferPtrsArray)
{
    icp_qat_addr_width_t *pInterBuffPtrsArray = NULL;
    icp_qat_addr_width_t pArrayBufferListDescPhyAddr = 0;
    icp_qat_addr_width_t bufListDescPhyAddr;
    icp_qat_addr_width_t bufListAlignedPhyAddr;
    CpaFlatBuffer *pClientCurrFlatBuffer = NULL;
    icp_buffer_list_desc_t *pBufferListDesc = NULL;
    icp_flat_buffer_desc_t *pCurrFlatBufDesc = NULL;
/* Structure initializer is supported by C99, but it is
 * not supported by some former Intel compilers.
 */
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(disable : 188)
#endif
    CpaInstanceInfo2 info = {0};
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(enable)
#endif
    icp_accel_dev_t *dev = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_compression_service_t *pService = NULL;
    CpaInstanceHandle insHandle = NULL;
    Cpa16U bufferIndex = 0;
    Cpa32U numFlatBuffers = 0;
    Cpa64U clientListSize = 0;
    CpaBufferList *pClientCurrentIntermediateBuffer = NULL;

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    Cpa32U bufferIndex2 = 0;
    CpaBufferList **pTempIntermediateBufferPtrsArray;
    Cpa64U lastClientListSize = 0;
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = instanceHandle;
    }
    LAC_CHECK_NULL_PARAM(insHandle);

    status = cpaDcInstanceGetInfo2(insHandle, &info);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not get instance info\n");
        return status;
    }

    dev = icp_adf_getAccelDevByAccelId(info.physInstId.packageId);
    if (NULL == dev)
    {
        LAC_LOG_ERROR("Can not find device for the instance\n");
        return CPA_STATUS_FAIL;
    }

    if (NULL == pIntermediateBufferPtrsArray)
    {
        /* Increment dev ref counter and return - DRAM is not used */
        icp_adf_qaDevGet(dev);
        return CPA_STATUS_SUCCESS;
    }

    if (0 == numBuffers)
    {
        /* Increment dev ref counter and return - DRAM is not used */
        icp_adf_qaDevGet(dev);
        return CPA_STATUS_SUCCESS;
    }

    pService = (sal_compression_service_t *)insHandle;

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);

    if ((numBuffers > 0) && (NULL == pIntermediateBufferPtrsArray))
    {
        LAC_LOG_ERROR("Invalid Intermediate Buffers Array pointer\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Check number of intermediate buffers allocated by user */
    if ((pService->numInterBuffs != numBuffers))
    {
        LAC_LOG_ERROR("Invalid number of buffers\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    pTempIntermediateBufferPtrsArray = pIntermediateBufferPtrsArray;
    for (bufferIndex = 0; bufferIndex < numBuffers; bufferIndex++)
    {
        if (NULL == *pTempIntermediateBufferPtrsArray)
        {
            LAC_LOG_ERROR(
                "Intermediate Buffer - Invalid Buffer List pointer\n");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (NULL == (*pTempIntermediateBufferPtrsArray)->pBuffers)
        {
            LAC_LOG_ERROR("Intermediate Buffer - Invalid Flat Buffer "
                          "descriptor pointer\n");
            return CPA_STATUS_INVALID_PARAM;
        }

        if (NULL == (*pTempIntermediateBufferPtrsArray)->pPrivateMetaData)
        {
            LAC_LOG_ERROR("Intermediate Buffer - Invalid Private MetaData "
                          "descriptor pointer\n");
            return CPA_STATUS_INVALID_PARAM;
        }

        clientListSize = 0;
        for (bufferIndex2 = 0;
             bufferIndex2 < (*pTempIntermediateBufferPtrsArray)->numBuffers;
             bufferIndex2++)
        {

            if ((0 != (*pTempIntermediateBufferPtrsArray)
                          ->pBuffers[bufferIndex2]
                          .dataLenInBytes) &&
                NULL == (*pTempIntermediateBufferPtrsArray)
                            ->pBuffers[bufferIndex2]
                            .pData)
            {
                LAC_LOG_ERROR(
                    "Intermediate Buffer - Invalid Flat Buffer pointer\n");
                return CPA_STATUS_INVALID_PARAM;
            }

            clientListSize += (*pTempIntermediateBufferPtrsArray)
                                  ->pBuffers[bufferIndex2]
                                  .dataLenInBytes;
        }

        if (bufferIndex != 0)
        {
            if (lastClientListSize != clientListSize)
            {
                LAC_LOG_ERROR("SGLs have to be of the same size\n");
                return CPA_STATUS_INVALID_PARAM;
            }
        }
        else
        {
            lastClientListSize = clientListSize;
        }
        pTempIntermediateBufferPtrsArray++;
    }

    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
#endif

    /* Allocate array of physical pointers to icp_buffer_list_desc_t */
    status = LAC_OS_CAMALLOC(&pInterBuffPtrsArray,
                             (numBuffers * sizeof(icp_qat_addr_width_t)),
                             LAC_64BYTE_ALIGNMENT,
                             pService->nodeAffinity);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not allocate Intermediate Buffers array\n");
        return status;
    }

    /* Get physical address of the intermediate buffer pointers array */
    pArrayBufferListDescPhyAddr = LAC_MEM_CAST_PTR_TO_UINT64(
        LAC_OS_VIRT_TO_PHYS_INTERNAL(pInterBuffPtrsArray));

    pService->pInterBuffPtrsArray = pInterBuffPtrsArray;
    pService->pInterBuffPtrsArrayPhyAddr = pArrayBufferListDescPhyAddr;

    /* Get the full size of the buffer list */
    /* Assumption: all the SGLs allocated by the user have the same size */
    clientListSize = 0;
    for (bufferIndex = 0;
         (Cpa32U)bufferIndex < (*pIntermediateBufferPtrsArray)->numBuffers;
         bufferIndex++)
    {
        clientListSize += ((*pIntermediateBufferPtrsArray)
                               ->pBuffers[bufferIndex]
                               .dataLenInBytes);
    }
    pService->minInterBuffSizeInBytes = clientListSize;

    for (bufferIndex = 0; bufferIndex < numBuffers; bufferIndex++)
    {

        /* Get pointer to the client Intermediate Buffer List (CpaBufferList) */
        pClientCurrentIntermediateBuffer = *pIntermediateBufferPtrsArray;

        /* Get number of flat buffers in the buffer list */
        numFlatBuffers = pClientCurrentIntermediateBuffer->numBuffers;

        /* Get pointer to the client array of CpaFlatBuffers */
        pClientCurrFlatBuffer = pClientCurrentIntermediateBuffer->pBuffers;

        /* Calculate Physical address of current private SGL */
        bufListDescPhyAddr = LAC_OS_VIRT_TO_PHYS_EXTERNAL(
            (*pService), pClientCurrentIntermediateBuffer->pPrivateMetaData);
        if (bufListDescPhyAddr == 0)
        {
            LAC_LOG_ERROR(
                "Unable to get the physical address of the metadata\n");
            return CPA_STATUS_FAIL;
        }

        /* Align SGL physical address */
        bufListAlignedPhyAddr = LAC_ALIGN_POW2_ROUNDUP(
            bufListDescPhyAddr, ICP_DESCRIPTOR_ALIGNMENT_BYTES);

        /* Set physical address of the Intermediate Buffer SGL in the SGLs array
         */
        *pInterBuffPtrsArray =
            LAC_MEM_CAST_PTR_TO_UINT64(bufListAlignedPhyAddr);

        /* Calculate (virtual) offset to the buffer list descriptor */
        pBufferListDesc =
            (icp_buffer_list_desc_t *)((LAC_ARCH_UINT)
                                           pClientCurrentIntermediateBuffer
                                               ->pPrivateMetaData +
                                       (LAC_ARCH_UINT)(bufListAlignedPhyAddr -
                                                       bufListDescPhyAddr));

        /* Set number of flat buffers in the physical Buffer List descriptor */
        pBufferListDesc->numBuffers = numFlatBuffers;

        /* Go past the Buffer List descriptor to the list of buffer descriptors
         */
        pCurrFlatBufDesc =
            (icp_flat_buffer_desc_t *)((pBufferListDesc->phyBuffers));

        /* Loop for each flat buffer in the SGL */
        while (0 != numFlatBuffers)
        {
            /* Set length of the current flat buffer */
            pCurrFlatBufDesc->dataLenInBytes =
                pClientCurrFlatBuffer->dataLenInBytes;

            /* Set physical address of the flat buffer */
            pCurrFlatBufDesc->phyBuffer =
                LAC_MEM_CAST_PTR_TO_UINT64(LAC_OS_VIRT_TO_PHYS_EXTERNAL(
                    (*pService), pClientCurrFlatBuffer->pData));

            if (pCurrFlatBufDesc->phyBuffer == 0)
            {
                LAC_LOG_ERROR("Unable to get the physical address of the flat"
                              " buffer\n");
                return CPA_STATUS_FAIL;
            }

            pCurrFlatBufDesc++;
            pClientCurrFlatBuffer++;
            numFlatBuffers--;
        }
        pIntermediateBufferPtrsArray++;
        pInterBuffPtrsArray++;
    }

    pService->generic_service_info.isInstanceStarted = CPA_TRUE;

    /* Increment dev ref counter */
    icp_adf_qaDevGet(dev);
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcStopInstance(CpaInstanceHandle instanceHandle)
{
    CpaInstanceHandle insHandle = NULL;
/* Structure initializer is supported by C99, but it is
 * not supported by some former Intel compilers.
 */
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(disable : 188)
#endif
    CpaInstanceInfo2 info = {0};
#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER < 1300)
#pragma warning(enable)
#endif
    icp_accel_dev_t *dev = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_compression_service_t *pService = NULL;

#ifdef ICP_TRACE
    LAC_LOG1("Called with params (0x%lx)\n", (LAC_ARCH_UINT)instanceHandle);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = instanceHandle;
    }

    LAC_CHECK_NULL_PARAM(insHandle);
    pService = (sal_compression_service_t *)insHandle;

    /* Free Intermediate Buffer Pointers Array */
    if (pService->pInterBuffPtrsArray != NULL)
    {
        LAC_OS_CAFREE(pService->pInterBuffPtrsArray);
        pService->pInterBuffPtrsArray = 0;
    }

    pService->pInterBuffPtrsArrayPhyAddr = 0;

    status = cpaDcInstanceGetInfo2(insHandle, &info);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR("Can not get instance info\n");
        return status;
    }
    dev = icp_adf_getAccelDevByAccelId(info.physInstId.packageId);
    if (NULL == dev)
    {
        LAC_LOG_ERROR("Can not find device for the instance\n");
        return CPA_STATUS_FAIL;
    }

    pService->generic_service_info.isInstanceStarted = CPA_FALSE;

    /* Decrement dev ref counter */
    icp_adf_qaDevPut(dev);
    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcGetNumInstances(Cpa16U *pNumInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0;
    Cpa16U num = 0;
    Cpa16U i = 0;

    LAC_CHECK_NULL_PARAM(pNumInstances);

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (NULL == pAdfInsts)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }
    num_accel_dev = 0;

    /* Get ADF to return accel_devs with dc enabled */
    status = icp_adf_getAllAccelDevByCapabilities(
        ICP_ACCEL_CAPABILITIES_COMPRESSION, pAdfInsts, &num_accel_dev);
    if (CPA_STATUS_SUCCESS == status)
    {
        for (i = 0; i < num_accel_dev; i++)
        {
            dev_addr = (icp_accel_dev_t *)pAdfInsts[i];
            if (NULL != dev_addr)
            {
                base_addr = dev_addr->pSalHandle;
                if (NULL != base_addr)
                {
                    list_temp = base_addr->compression_services;
                    while (NULL != list_temp)
                    {
                        num++;
                        list_temp = SalList_next(list_temp);
                    }
                }
            }
        }

        *pNumInstances = num;
    }

    osalMemFree(pAdfInsts);

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx[%d])\n",
             (LAC_ARCH_UINT)pNumInstances,
             *pNumInstances);
#endif
    return status;
}

CpaStatus cpaDcGetInstances(Cpa16U numInstances, CpaInstanceHandle *dcInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    icp_accel_dev_t **pAdfInsts = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U num_accel_dev = 0;
    Cpa16U index = 0;
    Cpa16U i = 0;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (%d, 0x%lx)\n",
             numInstances,
             (LAC_ARCH_UINT)dcInstances);
#endif

    LAC_CHECK_NULL_PARAM(dcInstances);
    if (0 == numInstances)
    {
        LAC_INVALID_PARAM_LOG("numInstances is 0");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Get the number of accel_dev in the system */
    status = icp_adf_getNumInstances(&num_accel_dev);
    LAC_CHECK_STATUS(status);

    /* Allocate memory to store addr of accel_devs */
    pAdfInsts = osalMemAlloc(num_accel_dev * sizeof(icp_accel_dev_t *));
    if (pAdfInsts == NULL)
    {
        LAC_LOG_ERROR("Failed to allocate dev instance memory");
        return CPA_STATUS_RESOURCE;
    }

    num_accel_dev = 0;
    /* Get ADF to return accel_devs with dc enabled */
    status = icp_adf_getAllAccelDevByCapabilities(
        ICP_ACCEL_CAPABILITIES_COMPRESSION, pAdfInsts, &num_accel_dev);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* First check the number of instances in the system */
        for (i = 0; i < num_accel_dev; i++)
        {
            dev_addr = (icp_accel_dev_t *)pAdfInsts[i];
            if (NULL != dev_addr)
            {
                base_addr = dev_addr->pSalHandle;
                if (NULL != base_addr)
                {
                    list_temp = base_addr->compression_services;
                    while (NULL != list_temp)
                    {
                        if (index > (numInstances - 1))
                        {
                            break;
                        }

                        dcInstances[index] = SalList_getObject(list_temp);
                        list_temp = SalList_next(list_temp);
                        index++;
                    }
                }
            }
        }

        if (numInstances > index)
        {
            LAC_LOG_ERROR1("Only %d dc instances available", index);
            status = CPA_STATUS_RESOURCE;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        index = 0;
        for (i = 0; i < num_accel_dev; i++)
        {
            dev_addr = (icp_accel_dev_t *)pAdfInsts[i];
            /* Note dev_addr cannot be NULL here as numInstances=0
               is not valid and if dev_addr=NULL then index=0 (which
               is less than numInstances and status is set to _RESOURCE
               above */
            base_addr = dev_addr->pSalHandle;
            if (NULL != base_addr)
            {
                list_temp = base_addr->compression_services;
                while (NULL != list_temp)
                {
                    if (index > (numInstances - 1))
                    {
                        break;
                    }

                    dcInstances[index] = SalList_getObject(list_temp);
                    list_temp = SalList_next(list_temp);
                    index++;
                }
            }
        }
    }

    osalMemFree(pAdfInsts);

    return status;
}

CpaStatus cpaDcInstanceGetInfo2(const CpaInstanceHandle instanceHandle,
                                CpaInstanceInfo2 *pInstanceInfo2)
{
    sal_compression_service_t *pCompressionService = NULL;
    CpaInstanceHandle insHandle = NULL;
    icp_accel_dev_t *dev = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char keyStr[ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {0};
    char valStr[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
    char *section = DYN_SEC;
    Cpa32S strSize = 0;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pInstanceInfo2);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = instanceHandle;
    }

    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_NULL_PARAM(pInstanceInfo2);

    LAC_OS_BZERO(pInstanceInfo2, sizeof(CpaInstanceInfo2));
    pInstanceInfo2->accelerationServiceType = CPA_ACC_SVC_TYPE_DATA_COMPRESSION;

    snprintf((char *)pInstanceInfo2->vendorName,
             CPA_INST_VENDOR_NAME_SIZE,
             "%s",
             SAL_INFO2_VENDOR_NAME);
    pInstanceInfo2->vendorName[CPA_INST_VENDOR_NAME_SIZE - 1] = '\0';

    snprintf((char *)pInstanceInfo2->swVersion,
             CPA_INST_SW_VERSION_SIZE,
             "Version %d.%d",
             SAL_INFO2_DRIVER_SW_VERSION_MAJ_NUMBER,
             SAL_INFO2_DRIVER_SW_VERSION_MIN_NUMBER);
    pInstanceInfo2->swVersion[CPA_INST_SW_VERSION_SIZE - 1] = '\0';

    /* Note we can safely read the contents of the compression service instance
       here because icp_adf_getAccelDevByCapabilities() only returns devs
       that have started */
    pCompressionService = (sal_compression_service_t *)insHandle;
    pInstanceInfo2->physInstId.packageId = pCompressionService->pkgID;
    pInstanceInfo2->physInstId.acceleratorId =
        pCompressionService->acceleratorNum;
    pInstanceInfo2->physInstId.executionEngineId = 0;
    pInstanceInfo2->physInstId.busAddress =
        icp_adf_getBusAddress(pInstanceInfo2->physInstId.packageId);

    /* set coreAffinity to zero before use */
    LAC_OS_BZERO(pInstanceInfo2->coreAffinity,
                 sizeof(pInstanceInfo2->coreAffinity));
    CPA_BITMAP_BIT_SET(pInstanceInfo2->coreAffinity,
                       pCompressionService->coreAffinity);

    pInstanceInfo2->nodeAffinity = pCompressionService->nodeAffinity;

    if (CPA_TRUE == pCompressionService->generic_service_info.isInstanceStarted)
    {
        pInstanceInfo2->operState = CPA_OPER_STATE_UP;
    }
    else
    {
        pInstanceInfo2->operState = CPA_OPER_STATE_DOWN;
    }

    pInstanceInfo2->requiresPhysicallyContiguousMemory = CPA_TRUE;

    if (SAL_RESP_POLL_CFG_FILE == pCompressionService->isPolled ||
        SAL_RESP_EPOLL_CFG_FILE == pCompressionService->isPolled)
    {
        pInstanceInfo2->isPolled = CPA_TRUE;
    }
    else
    {
        pInstanceInfo2->isPolled = CPA_FALSE;
    }

    pInstanceInfo2->isOffloaded = CPA_TRUE;
    /* Get the instance name and part name from the config file */
    dev = icp_adf_getAccelDevByAccelId(pCompressionService->pkgID);
    if (NULL == dev)
    {
        LAC_LOG_ERROR("Can not find device for the instance\n");
        LAC_OS_BZERO(pInstanceInfo2, sizeof(CpaInstanceInfo2));
        return CPA_STATUS_FAIL;
    }
    snprintf((char *)pInstanceInfo2->partName,
             CPA_INST_PART_NAME_SIZE,
             SAL_INFO2_PART_NAME,
             dev->deviceName);
    pInstanceInfo2->partName[CPA_INST_PART_NAME_SIZE - 1] = '\0';

    if (CPA_FALSE == pCompressionService->generic_service_info.is_dyn)
    {
        section = icpGetProcessName();
    }

    status =
        Sal_StringParsing(SAL_CFG_DC,
                          pCompressionService->generic_service_info.instance,
                          SAL_CFG_NAME,
                          keyStr);
    LAC_CHECK_STATUS(status);
    status = icp_adf_cfgGetParamValue(dev, section, keyStr, valStr);
    LAC_CHECK_STATUS(status);

    strSize = snprintf(
        (char *)pInstanceInfo2->instName, CPA_INST_NAME_SIZE, "%s", valStr);
    LAC_CHECK_PARAM_RANGE(strSize, 1, CPA_INST_NAME_SIZE);

    strSize = snprintf((char *)pInstanceInfo2->instID,
                       CPA_INST_ID_SIZE,
                       "%s_%s",
                       section,
                       valStr);
    LAC_CHECK_PARAM_RANGE(strSize, 1, CPA_INST_ID_SIZE);

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcQueryCapabilities(
    CpaInstanceHandle dcInstance,
    CpaDcInstanceCapabilities *pInstanceCapabilities)
{
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;
    Cpa32U capabilitiesMask = 0;
    dc_extd_ftrs_t *pExtendedFtrs = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pInstanceCapabilities);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
        if (NULL == insHandle)
        {
            LAC_LOG_ERROR("Can not get the instance\n");
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_NULL_PARAM(pInstanceCapabilities);
#endif

    osalMemSet(pInstanceCapabilities, 0, sizeof(CpaDcInstanceCapabilities));

    capabilitiesMask = pService->generic_service_info.capabilitiesMask;

    /* Set compression capabilities */
    if (pService->generic_service_info.capabilitiesMask &
        ICP_ACCEL_CAPABILITIES_LZ4_COMPRESSION)
    {
        pInstanceCapabilities->statelessLZ4Compression = CPA_TRUE;
        pInstanceCapabilities->statelessLZ4Decompression = CPA_TRUE;
        pInstanceCapabilities->statefulLZ4Decompression = CPA_TRUE;
        pInstanceCapabilities->checksumXXHash32 = CPA_TRUE;
    }
    if (pService->generic_service_info.capabilitiesMask &
        ICP_ACCEL_CAPABILITIES_LZ4S_COMPRESSION)
    {
        pInstanceCapabilities->statelessLZ4SCompression = CPA_TRUE;
        pInstanceCapabilities->checksumXXHash32 = CPA_TRUE;
    }

    if (capabilitiesMask & ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY)
    {
        pInstanceCapabilities->integrityCrcs = CPA_TRUE;
    }

    if (capabilitiesMask & ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY64)
    {
        pInstanceCapabilities->integrityCrcs64b = CPA_TRUE;
    }

    pInstanceCapabilities->endOfLastBlock = CPA_TRUE;

    pInstanceCapabilities->statefulDeflateCompression = CPA_FALSE;
    pInstanceCapabilities->statefulDeflateDecompression = CPA_FALSE;
    pInstanceCapabilities->statelessDeflateCompression = CPA_TRUE;
    pInstanceCapabilities->statelessDeflateDecompression = CPA_TRUE;
    pInstanceCapabilities->checksumCRC32 = CPA_TRUE;
    pInstanceCapabilities->checksumAdler32 = CPA_TRUE;
#ifndef ICP_DC_DYN_NOT_SUPPORTED
    pInstanceCapabilities->dynamicHuffman = CPA_TRUE;
#else
    pInstanceCapabilities->dynamicHuffman = CPA_FALSE;
#endif
    pInstanceCapabilities->precompiledHuffman = CPA_FALSE;
    pInstanceCapabilities->dynamicHuffmanBufferReq = CPA_TRUE;
    pInstanceCapabilities->autoSelectBestHuffmanTree = CPA_TRUE;

    pInstanceCapabilities->validWindowSizeMaskCompression =
        pService->comp_device_data.windowSizeMask;
    pInstanceCapabilities->validWindowSizeMaskDecompression =
        pService->comp_device_data.windowSizeMask;
    pExtendedFtrs =
        (dc_extd_ftrs_t *)&(((sal_service_t *)insHandle)->dcExtendedFeatures);
    pInstanceCapabilities->batchAndPack = CPA_FALSE;
    pInstanceCapabilities->compressAndVerify =
        (CpaBoolean)pExtendedFtrs->is_cnv;
    pInstanceCapabilities->compressAndVerifyStrict = CPA_TRUE;
    pInstanceCapabilities->compressAndVerifyAndRecover =
        (CpaBoolean)pExtendedFtrs->is_cnvnr;

    /* Set chaining capabilities */
#ifndef ICP_DC_ONLY
    if (pExtendedFtrs->is_chain_compress_then_hash)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_COMPRESS_THEN_HASH);
    }
    if (pExtendedFtrs->is_chain_compress_then_encrypt)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT);
    }
    if (pExtendedFtrs->is_chain_compress_then_hash_encrypt)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_COMPRESS_THEN_HASH_ENCRYPT);
    }
    if (pExtendedFtrs->is_chain_compress_then_encrypt_hash)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT_HASH);
    }
    if (pExtendedFtrs->is_chain_compress_then_aead)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_COMPRESS_THEN_AEAD);
    }
    if (pExtendedFtrs->is_chain_hash_then_compress)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_HASH_THEN_COMPRESS);
    }
    if (pExtendedFtrs->is_chain_hash_verify_then_decompress)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_HASH_VERIFY_THEN_DECOMPRESS);
    }
    if (pExtendedFtrs->is_chain_decrypt_then_decompress)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_DECRYPT_THEN_DECOMPRESS);
    }
    if (pExtendedFtrs->is_chain_hash_verify_decrypt_then_decompress)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_HASH_VERIFY_DECRYPT_THEN_DECOMPRESS);
    }
    if (pExtendedFtrs->is_chain_decrypt_hash_verify_then_decompress)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_DECRYPT_HASH_VERIFY_THEN_DECOMPRESS);
    }
    if (pExtendedFtrs->is_chain_aead_then_decompress)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS);
    }
    if (pExtendedFtrs->is_chain_decompress_then_hash_verify)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_DECOMPRESS_THEN_HASH_VERIFY);
    }
    if (pExtendedFtrs->is_chain_compress_then_aead_then_hash)
    {
        CPA_BITMAP_BIT_SET(pInstanceCapabilities->dcChainCapInfo,
                           CPA_DC_CHAIN_COMPRESS_THEN_AEAD_THEN_HASH);
    }
#endif

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcSetAddressTranslation(const CpaInstanceHandle instanceHandle,
                                     CpaVirtualToPhysical virtual2Physical)
{
    sal_service_t *pService = NULL;
    CpaInstanceHandle insHandle = NULL;

#ifdef ICP_TRACE
    LAC_LOG2("Called with params (0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)virtual2Physical);
#endif

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = instanceHandle;
    }

/* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_NULL_PARAM(virtual2Physical);
#endif

    pService = (sal_service_t *)insHandle;

    pService->virt2PhysClient = virtual2Physical;

    return CPA_STATUS_SUCCESS;
}

/**
 ******************************************************************************
 * @ingroup cpaDcCommon
 * Data compression specific polling function which polls a DC instance.
 *****************************************************************************/

CpaStatus icp_sal_DcPollInstance(CpaInstanceHandle instanceHandle_in,
                                 Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_compression_service_t *dc_handle = NULL;
    sal_service_t *gen_handle = NULL;
    icp_comms_trans_handle trans_hndTable[DC_NUM_RX_RINGS];

    if (CPA_INSTANCE_HANDLE_SINGLE == instanceHandle_in)
    {
        dc_handle = (sal_compression_service_t *)dcGetFirstHandle();
    }
    else
    {
        dc_handle = (sal_compression_service_t *)instanceHandle_in;
    }

    LAC_CHECK_NULL_PARAM(dc_handle);
    SAL_RUNNING_CHECK(dc_handle);

    gen_handle = &(dc_handle->generic_service_info);
    if (SAL_SERVICE_TYPE_COMPRESSION != gen_handle->type)
    {
        LAC_LOG_ERROR("The instance handle is the wrong type");
        return CPA_STATUS_FAIL;
    }

    /*
     * From the instanceHandle we must get the trans_handle and send
     * down to adf for polling.
     * Populate our trans handle table with the appropriate handles.
     */
    trans_hndTable[0] = dc_handle->trans_handle_compression_rx;

    /* Call adf to do the polling. */
    status =
        icp_adf_pollInstance(trans_hndTable, DC_NUM_RX_RINGS, response_quota);
    return status;
}

/**
 ******************************************************************************
 * @ingroup cpaDcCommon
 *****************************************************************************/
CpaStatus cpaDcInstanceSetNotificationCb(
    const CpaInstanceHandle instanceHandle,
    const CpaDcInstanceNotificationCbFunc pInstanceNotificationCb,
    void *pCallbackTag)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_service_t *gen_handle = instanceHandle;

#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pInstanceNotificationCb,
             (LAC_ARCH_UINT)pCallbackTag);
#endif

    LAC_CHECK_NULL_PARAM(gen_handle);
    gen_handle->notification_cb = pInstanceNotificationCb;
    gen_handle->cb_tag = pCallbackTag;
    return status;
}

CpaInstanceHandle dcGetFirstHandle(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    static icp_accel_dev_t *adfInsts[ADF_MAX_DEVICES] = {0};
    CpaInstanceHandle dcInst = NULL;
    icp_accel_dev_t *dev_addr = NULL;
    sal_t *base_addr = NULL;
    sal_list_t *list_temp = NULL;
    Cpa16U i, num_dc = 0;

    /* Only need 1 dev with compression enabled - so check all devices */
    status = icp_adf_getAllAccelDevByCapabilities(
        ICP_ACCEL_CAPABILITIES_COMPRESSION, adfInsts, &num_dc);
    if ((0 == num_dc) || (CPA_STATUS_SUCCESS != status))
    {
        LAC_LOG("No compression devices enabled in the system\n");
        return dcInst;
    }

    for (i = 0; i < num_dc; i++)
    {
        dev_addr = (icp_accel_dev_t *)adfInsts[i];
        if (NULL != dev_addr)
        {
            base_addr = dev_addr->pSalHandle;
            if (NULL != base_addr)
            {
                list_temp = base_addr->compression_services;
                if (NULL != list_temp)
                {
                    dcInst = SalList_getObject(list_temp);
                    break;
                }
            }
        }
    }
    return dcInst;
}

CpaStatus icp_sal_DcGetFileDescriptor(CpaInstanceHandle instanceHandle, int *fd)
{
    sal_compression_service_t *dc_handle = NULL;
    sal_service_t *gen_handle = NULL;
    int dc_fd = -1;
    int ret = 0;

    dc_handle = (sal_compression_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(dc_handle);
    SAL_RUNNING_CHECK(dc_handle);

    gen_handle = &(dc_handle->generic_service_info);
    if (SAL_SERVICE_TYPE_COMPRESSION != gen_handle->type)
    {
        LAC_LOG_ERROR("The instance handle is the wrong type");
        return CPA_STATUS_FAIL;
    }

    if (SAL_RESP_EPOLL_CFG_FILE != dc_handle->isPolled)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    ret = icp_adf_transGetFdForHandle(dc_handle->trans_handle_compression_rx,
                                      &dc_fd);
    if (ret != CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_FAIL;
    }
    else
    {
        *fd = dc_fd;
        return CPA_STATUS_SUCCESS;
    }
}

CpaStatus icp_sal_DcPutFileDescriptor(CpaInstanceHandle instanceHandle, int fd)
{
    sal_compression_service_t *dc_handle = NULL;
    sal_service_t *gen_handle = NULL;

    dc_handle = (sal_compression_service_t *)instanceHandle;

    LAC_CHECK_NULL_PARAM(dc_handle);
    SAL_RUNNING_CHECK(dc_handle);

    gen_handle = &(dc_handle->generic_service_info);
    if (SAL_SERVICE_TYPE_COMPRESSION != gen_handle->type)
    {
        LAC_LOG_ERROR("The instance handle is the wrong type");
        return CPA_STATUS_FAIL;
    }

    if (SAL_RESP_EPOLL_CFG_FILE != dc_handle->isPolled)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    return CPA_STATUS_SUCCESS;
}
