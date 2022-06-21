/******************************************************************************
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
 *****************************************************************************/

/**
 ******************************************************************************
 * @file  cpa_hkdf_sample_user.c
 *
 *****************************************************************************/
#include "cpa.h"
#include "icp_sal_user.h"
#include "cpa_sample_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
extern CpaStatus hkdfSample(void);

int gDebugParam = 1;

int main(int argc, const char **argv)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (argc > 1)
    {
        gDebugParam = atoi(argv[1]);
    }

    /*    status = sampleDeviceStart("SSL", CFG_ALL_DEVICES,
                                 NUM_PROCESSES_DEFAULT,
                                 NUM_INSTANCES_DEFAULT,
                                 NUM_SYM_CONCURRENT_REQUESTS_DEFAULT,
                                 NUM_ASYM_CONCURRENT_REQUESTS_DEFAULT,
                                 LIMIT_DEVICE_ACCESS_DEFAULT);
        if(CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to start device(s)\n");
            return (int) status;
        }
    */
    PRINT_DBG("Starting HKDF sample code ...\n");

    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialize memory driver\n");
        return (int)status;
    }

    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)status;
    }

    status = hkdfSample();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("\nHKDF sample code failed\n");
    }
    else
    {
        PRINT_DBG("\nHKDF sample code finished\n");
    }

    icp_sal_userStop();
    qaeMemDestroy();
    /*

        if(CPA_STATUS_SUCCESS != sampleDeviceStop(CFG_ALL_DEVICES))
        {
            PRINT_ERR("Failed to stop device(s)\n");
        }
    */
    return (int)status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
