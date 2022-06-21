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
 * @file qat_compression_cnv_utils.h
 *
 * @defgroup compression
 *
 * @ingroup compression
 *
 * @description
 * Functions types and macros to determine CnV-E environment
 * Helper functions and macros to set the CnV flag in API
 *
 *
 ***************************************************************************/
#ifndef QAT_COMPRESSION_CNV_UTILS_H_
#define QAT_COMPRESSION_CNV_UTILS_H_
#ifdef USER_SPACE
#include <assert.h>
#endif
#include "cpa_dc.h"
#include "cpa_dc_dp.h"

#define STRICT_BASE_OFFSET 16
#define LOOSE_BASE_OFFSET 0
#define STRICT_BIT_CNV (0x1 << (STRICT_BASE_OFFSET))
#define STRICT_BIT_CNVNR (0x1 << (STRICT_BASE_OFFSET + 1))
#define STRICT_BIT_CONDITIONAL_CNVNR (0x1 << (STRICT_BASE_OFFSET + 2))
#define LOOSE_BIT_CNV (0x1 << (LOOSE_BASE_OFFSET))
#define LOOSE_BIT_CNVNR (0x1 << (LOOSE_BASE_OFFSET + 1))
#define LOOSE_BIT_CONDITIONAL_CNVNR (0x1 << (LOOSE_BASE_OFFSET + 2))

/* Common macro definition for the API versions */
#ifndef DC_API_VERSION_AT_LEAST
#define DC_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_DC_API_VERSION_NUM_MAJOR > major ||                                   \
     (CPA_DC_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_DC_API_VERSION_NUM_MINOR >= minor))
#endif

/* Request Flag to set the CNV services accordingly */
/* Some of the request might not be valid for the mode but have been provided
 * to setup negative tests. The flag can contain request for both Strict
 * and Loose mode so that user does not have to query mode and set flags
 * accordingly.
 */
/* STRICT_NO_CNV : No CnV operation requested in strict mode */
#define STRICT_NO_CNV 0

/* STRICT_CNV_WITHOUT_RECOVERY : Perform CnV without Recovery in Strict mode.
 *  The recovery is explicitly turned off so that the verification failures
 *  are reported by the compression API.
 */
#define STRICT_CNV_WITHOUT_RECOVERY                                            \
    ((STRICT_BIT_CNV & ~STRICT_BIT_CNVNR) & ~STRICT_BIT_CONDITIONAL_CNVNR)

/* STRICT_CNV_WITH_RECOVERY : Perform CnV with Recovery in strict mode.
 * Recovery is turned on WITHOUT checking the capability. This can be used
 * in negative tests.
 */
#define STRICT_CNV_WITH_RECOVERY                                               \
    ((STRICT_BIT_CNV | STRICT_BIT_CNVNR) & ~STRICT_BIT_CONDITIONAL_CNVNR)

/* STRICT_CNV_CONDITIONAL_RECOVERY: Perform CnV with recovery if supported
 * in strict mode. The recovery is turned on only if the capability reports
 * that the recovery is supported else recovery is turned off.
 */
#define STRICT_CNV_CONDITIONAL_RECOVERY                                        \
    ((STRICT_BIT_CNV | STRICT_BIT_CNVNR) | STRICT_BIT_CONDITIONAL_CNVNR)

/* LOOSE_NO_CNV : No CnV operation requested in LOOSE mode */
#define LOOSE_NO_CNV 0

/* LOOSE_CNV_WITHOUT_RECOVERY : Perform CnV without Recovery in LOOSE mode.
 *  The recovery is explicitly turned off so that the verification failures
 *  are reported by the compression API.
 */
#define LOOSE_CNV_WITHOUT_RECOVERY                                             \
    ((LOOSE_BIT_CNV & ~LOOSE_BIT_CNVNR) & ~LOOSE_BIT_CONDITIONAL_CNVNR)

/* LOOSE_CNV_WITHOUT_RECOVERY : Perform CnV with Recovery in LOOSE mode.
 * Recovery is turned on without checking the capability. This can be used
 * in negative tests.
 */
#define LOOSE_CNV_WITH_RECOVERY                                                \
    ((LOOSE_BIT_CNV | LOOSE_BIT_CNVNR) & ~LOOSE_BIT_CONDITIONAL_CNVNR)

/* LOOSE_CNV_CONDITIONAL_RECOVERY: Perform CnV with recovery if supported
 * in LOOSE mode. The recovery is turned on only if the capability reports
 * that the recovery is supported else recovery is turned off.
 */
#define LOOSE_CNV_CONDITIONAL_RECOVERY                                         \
    ((LOOSE_BIT_CNV | LOOSE_BIT_CNVNR) | LOOSE_BIT_CONDITIONAL_CNVNR)

#define CNV_FLAG_DEFAULT (STRICT_CNV_CONDITIONAL_RECOVERY | LOOSE_NO_CNV)

/* CNV mode capabilities is present in DC API version 2.1 and higher */
#if DC_API_VERSION_AT_LEAST(2, 1)
#define CNV_MODE_STRICT(cap) (cap)->compressAndVerifyStrict
#else
#define CNV_MODE_STRICT(cap) CPA_FALSE
#endif

/* CNV with Recovery mode capability is present in DC API version 2.2
 * and higher. This macro helps in getting cnv recovery data member in
 * various data structures depending on the DC API version.
 */
#if DC_API_VERSION_AT_LEAST(2, 2)
#define DCDP_CNV(x) (x)->compressAndVerify
#define SET_DCDP_CNV(x, v) (DCDP_CNV(x) = (v))
#define CNV_RECOVERY(x) (x)->compressAndVerifyAndRecover
#define SET_CNV_RECOVERY(x, v) (CNV_RECOVERY(x) = v)
#define GET_CNV_RECOVERY_COUNTERS(x) (x)->numCompCnvErrorsRecovered
#else
#define DCDP_CNV(x) (x)->reserved1
#define SET_DCDP_CNV(x, v)
#define CNV_RECOVERY(x) CPA_FALSE
#define SET_CNV_RECOVERY(x, v)
#define GET_CNV_RECOVERY_COUNTERS(x) 0
#endif

#define INIT_OPDATA_DEFAULT(x)                                                 \
    INIT_OPDATA_FLAGS(x, CPA_DC_FLUSH_NONE, CNV_FLAG_DEFAULT)

#define INIT_OPDATA_FLAGS(x, flush, cnvFlag)                                   \
    do                                                                         \
    {                                                                          \
        (x)->flushFlag = flush;                                                \
        (x)->inputSkipData.skipMode = CPA_DC_SKIP_DISABLED;                    \
        (x)->outputSkipData.skipMode = CPA_DC_SKIP_DISABLED;                   \
        setCnVFlags(cnvFlag, x);                                               \
    } while (0)

#define SET_DC_DP_CNV_PARAMS_DEFAULT(x) setDcDpCnVFlags(CNV_FLAG_DEFAULT, x)

static CpaStatus setCnVFlags(Cpa32U, CpaDcOpData *const)
    __attribute__((unused));
static CpaStatus setDcDpCnVFlags(Cpa32U req, CpaDcDpOpData *const opData)
    __attribute__((unused));
static const char *getCnVOpModeStr(const CpaDcOpData *const)
    __attribute__((unused));
static const char *getDpCnVOpModeStr(const CpaDcDpOpData *const)
    __attribute__((unused));
static CpaBoolean isCnVModeStrict(void) __attribute__((unused));

static const char *getCnVModeStr(const CpaBoolean cnv,
                                 const CpaBoolean cnvRecovery);
static CpaStatus setCnVFlags(Cpa32U req, CpaDcOpData *const opData);
static CpaStatus EvaluateCnVFlag(const CpaDcInstanceCapabilities *const cap,
                                 CpaBoolean *cnv,
                                 CpaBoolean *cnvr,
                                 Cpa32U cnvReqFlag);
static CpaStatus getDcCapabilities(CpaDcInstanceCapabilities *capabilities);

static CpaBoolean isCnVModeStrict(void)
{
    CpaDcInstanceCapabilities cap = {0};
    if (getDcCapabilities(&cap) != CPA_STATUS_SUCCESS)
    {
        return CPA_FALSE;
    }
    return CNV_MODE_STRICT(&cap);
}

static const char *getCnVOpModeStr(const CpaDcOpData *const opData)
{
    return getCnVModeStr(opData->compressAndVerify, CNV_RECOVERY(opData));
}

static const char *getDpCnVOpModeStr(const CpaDcDpOpData *const opData)
{
    return getCnVModeStr(DCDP_CNV(opData), CNV_RECOVERY(opData));
}

static const char *getCnVModeStr(const CpaBoolean cnv,
                                 const CpaBoolean cnvRecovery)
{
    static const char *cmpOnly = "Compression Only";
    static const char *cmpWithVer = "Compression with Verification";
    static const char *cmpWithVerAndRec =
        "Compression with Verification and Recovery";

    if (cnv == CPA_TRUE)
    {
        if (cnvRecovery == CPA_TRUE)
        {
            return cmpWithVerAndRec;
        }
        return cmpWithVer;
    }

    return cmpOnly;
}

static CpaStatus setDcDpCnVFlags(Cpa32U req, CpaDcDpOpData *const opData)
{
    CpaDcInstanceCapabilities cap = {0};
    CpaDcInstanceCapabilities *ptr = &cap;
    CpaBoolean cnv = CPA_FALSE;
    CpaBoolean cnvr = CPA_FALSE;
    CpaStatus status;

    if (getDcCapabilities(&cap) != CPA_STATUS_SUCCESS)
    {
        ptr = NULL;
    }

    status = EvaluateCnVFlag(ptr, &cnv, &cnvr, req);

    SET_DCDP_CNV(opData, cnv);
    SET_CNV_RECOVERY(opData, cnvr);

    return status;
}

static CpaStatus setCnVFlags(Cpa32U req, CpaDcOpData *const opData)
{
    CpaDcInstanceCapabilities cap = {0};
    CpaDcInstanceCapabilities *ptr = &cap;
    CpaBoolean cnv = CPA_FALSE;
    CpaBoolean cnvr = CPA_FALSE;
    CpaStatus status;

    if (getDcCapabilities(&cap) != CPA_STATUS_SUCCESS)
    {
        ptr = NULL;
    }

    status = EvaluateCnVFlag(ptr, &cnv, &cnvr, req);

    opData->compressAndVerify = cnv;
    SET_CNV_RECOVERY(opData, cnvr);

    return status;
}

static CpaStatus EvaluateCnVFlag(const CpaDcInstanceCapabilities *const cap,
                                 CpaBoolean *cnv,
                                 CpaBoolean *cnvr,
                                 Cpa32U cnvReqFlag)
{
    CpaBoolean fwCnVRecoveryCapable = CPA_FALSE;
    /* Let the mode be loose by default for compatibility reasons.
     * for example: firmware that does not support strict/loose modes.
     */
    CpaBoolean cnvModeStrict = CPA_FALSE;
    CpaBoolean cnvOpFlag = CPA_FALSE;
    CpaBoolean cnvnrOpFlag = CPA_FALSE;

    /* When capabilities are known, fill in the queried values */
    if (cap != NULL)
    {
        fwCnVRecoveryCapable = CNV_RECOVERY(cap);
        cnvModeStrict = CNV_MODE_STRICT(cap);
    }

    if (cnvModeStrict == CPA_FALSE)
    {
        /* Set CNV Flag if Requested */
        cnvOpFlag = cnvReqFlag & LOOSE_BIT_CNV ? CPA_TRUE : CPA_FALSE;
        /* Set CnVnR Flag if Requested */
        cnvnrOpFlag = cnvReqFlag & LOOSE_BIT_CNVNR ? CPA_TRUE : CPA_FALSE;
        /* If CnVnR is requested on the condition that recovery should be done
         * only if fw supports it, update the cnvnr op flag according to the
         * firmware capability to do CnVnR.
         */
        if (cnvnrOpFlag == CPA_TRUE && cnvReqFlag & LOOSE_BIT_CONDITIONAL_CNVNR)
        {
            cnvnrOpFlag = fwCnVRecoveryCapable;
        }
    }
    else
    {
        cnvOpFlag = cnvReqFlag & STRICT_BIT_CNV ? CPA_TRUE : CPA_FALSE;
        cnvnrOpFlag = cnvReqFlag & STRICT_BIT_CNVNR ? CPA_TRUE : CPA_FALSE;
        if (cnvnrOpFlag == CPA_TRUE &&
            cnvReqFlag & STRICT_BIT_CONDITIONAL_CNVNR)
        {
            cnvnrOpFlag = fwCnVRecoveryCapable;
        }
    }

    *cnv = cnvOpFlag;
    *cnvr = cnvnrOpFlag;

    return CPA_STATUS_SUCCESS;
}

static CpaStatus getDcCapabilities(CpaDcInstanceCapabilities *capabilities)
{
    CpaStatus status;
    CpaInstanceHandle instHandle;
    Cpa16U numInstances = 0;

    /* Get the number of instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
        return CPA_STATUS_FAIL;

    if (numInstances == 0)
        return CPA_STATUS_FAIL;

    status = cpaDcGetInstances(1, &instHandle);
    if (status != CPA_STATUS_SUCCESS)
        return CPA_STATUS_FAIL;

    status = cpaDcQueryCapabilities(instHandle, capabilities);
    if (CPA_STATUS_SUCCESS != status)
        return CPA_STATUS_FAIL;

    return CPA_STATUS_SUCCESS;
}
#endif /* QAT_COMPRESSION_CNV_UTILS_H_ */
