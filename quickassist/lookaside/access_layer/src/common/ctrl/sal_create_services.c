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
 * @file sal_create_services.c
 *
 * @defgroup SalCtrl Service Access Layer Controller
 *
 * @ingroup SalCtrl
 *
 * @description
 *      This file contains the main function to create a specific service.
 *
 *****************************************************************************/

#include "cpa.h"
#include "lac_log.h"
#include "lac_mem.h"
#include "lac_mem_pools.h"
#include "Osal.h"
#include "lac_list.h"
#include "icp_adf_transport.h"
#include "icp_accel_devices.h"
#include "icp_adf_debug.h"

#include "icp_qat_fw_la.h"
#include "lac_sym_qat.h"
#include "sal_types_compression.h"
#include "lac_sal_types_crypto.h"

#include "icp_adf_init.h"

#include "lac_sal.h"
#include "lac_sal_ctrl.h"

CpaStatus SalCtrl_ServiceCreate(sal_service_type_t serviceType,
                                Cpa32U instance,
                                sal_service_t **ppInst)
{
#ifndef ICP_DC_ONLY
    sal_crypto_service_t *pCrypto_service = NULL;
#endif
    sal_compression_service_t *pCompression_service = NULL;

    switch ((sal_service_type_t)serviceType)
    {
#ifndef ICP_DC_ONLY
        case SAL_SERVICE_TYPE_CRYPTO_ASYM:
        case SAL_SERVICE_TYPE_CRYPTO_SYM:
        case SAL_SERVICE_TYPE_CRYPTO:
        {
            pCrypto_service = osalMemAlloc(sizeof(sal_crypto_service_t));
            if (NULL == pCrypto_service)
            {
                LAC_LOG_ERROR("Failed to allocate crypto service memory");
                *(ppInst) = NULL;
                return CPA_STATUS_RESOURCE;
            }

            /* Zero memory */
            osalMemSet(pCrypto_service, 0, sizeof(sal_crypto_service_t));

            pCrypto_service->generic_service_info.type =
                (sal_service_type_t)serviceType;
            pCrypto_service->generic_service_info.state =
                SAL_SERVICE_STATE_UNINITIALIZED;
            pCrypto_service->generic_service_info.instance = instance;

            pCrypto_service->generic_service_info.init = SalCtrl_CryptoInit;
            pCrypto_service->generic_service_info.start = SalCtrl_CryptoStart;
            pCrypto_service->generic_service_info.stop = SalCtrl_CryptoStop;
            pCrypto_service->generic_service_info.shutdown =
                SalCtrl_CryptoShutdown;
            pCrypto_service->generic_service_info.error = SalCtrl_CryptoError;
            pCrypto_service->generic_service_info.restarting =
                SalCtrl_CryptoRestarting;
            pCrypto_service->generic_service_info.restarted =
                SalCtrl_CryptoRestarted;

            *(ppInst) = &(pCrypto_service->generic_service_info);

            return CPA_STATUS_SUCCESS;
        }
#endif
        case SAL_SERVICE_TYPE_COMPRESSION:
        {
            pCompression_service =
                osalMemAlloc(sizeof(sal_compression_service_t));
            if (NULL == pCompression_service)
            {
                LAC_LOG_ERROR("Failed to allocate compression service memory");
                *(ppInst) = NULL;
                return CPA_STATUS_RESOURCE;
            }

            /* Zero memory */
            osalMemSet(
                pCompression_service, 0, sizeof(sal_compression_service_t));

            pCompression_service->generic_service_info.type =
                (sal_service_type_t)serviceType;
            pCompression_service->generic_service_info.state =
                SAL_SERVICE_STATE_UNINITIALIZED;
            pCompression_service->generic_service_info.instance = instance;

            pCompression_service->generic_service_info.init =
                SalCtrl_CompressionInit;
            pCompression_service->generic_service_info.start =
                SalCtrl_CompressionStart;
            pCompression_service->generic_service_info.stop =
                SalCtrl_CompressionStop;
            pCompression_service->generic_service_info.shutdown =
                SalCtrl_CompressionShutdown;
            pCompression_service->generic_service_info.error =
                SalCtrl_CompressionError;
            pCompression_service->generic_service_info.restarting =
                SalCtrl_CompressionRestarting;
            pCompression_service->generic_service_info.restarted =
                SalCtrl_CompressionRestarted;

            *(ppInst) = &(pCompression_service->generic_service_info);
            return CPA_STATUS_SUCCESS;
        }

        default:
        {
            LAC_LOG_ERROR("Not a valid service type");
            (*ppInst) = NULL;
            return CPA_STATUS_FAIL;
        }
    }
}
