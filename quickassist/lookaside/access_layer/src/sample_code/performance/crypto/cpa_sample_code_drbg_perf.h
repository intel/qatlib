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
 ***************************************************************************
 * @file cpa_sample_code_drbg_perf.h
 *
 * @defgroup sampleDrbgFunctional
 *
 * @ingroup sampleCode
 *
 * @description
 *     Deterministic Random Bit Generation Performance Sample Code functions.
 *
 ***************************************************************************/
#ifndef CPA_SAMPLE_CODE_DRBG_PERF_H
#define CPA_SAMPLE_CODE_DRBG_PERF_H
#include "cpa.h"
#include "cpa_sample_code_crypto_utils.h"
#include "cpa_cy_drbg.h"
#include "cpa_cy_nrbg.h"
#include "cpa_cy_im.h"
#include "icp_sal_drbg_impl.h"

#define DRBG_MAX_THREAD 256
#define DRBG_MAX_SESSION_PERTHREAD 256

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      DRBGSetup Data.
 * @description
 *      This structure contains data relating to setting up a DRBG test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct drbg_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* derivation function required or not */
    CpaBoolean dFReq;
    /* security strength */
    Cpa32U secStrength;
    /* predication Resistance Required */
    CpaBoolean predictionResistanceRequired;
    /* length in bytes */
    Cpa32U lengthInBytes;
    /* number of loops to be used*/
    Cpa32U numLoops;
    Cpa32U numSessions;
} drbg_test_params_t;

// void nrbgRegisterDrbgImplFunctions(CpaBoolean dFReq);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupDrbgTest
 *
 * @description
 *      setup a test to run an DRBG test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupDrbgTest(CpaBoolean dFReq,
                        Cpa32U secStrength,
                        CpaBoolean predictionResistanceRequired,
                        Cpa32U lengthInBytes,
                        Cpa32U numSessions,
                        Cpa32U numLoops);

#endif
