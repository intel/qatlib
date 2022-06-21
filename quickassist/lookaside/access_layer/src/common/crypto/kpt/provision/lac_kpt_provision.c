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
/**
 *****************************************************************************
 * @file lac_kpt2_provision.c
 *
 * @ingroup LacKpt
 *
 * This file implements kpt key provision functions.
 *
 *****************************************************************************/
/*
*******************************************************************************
* Include public/global header file
*******************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_kpt.h"

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query kpt issue key certificate from qat driver
***************************************************************************/
CpaStatus cpaCyKptQueryIssuingKeys(const CpaInstanceHandle instanceHandle_in,
                                   CpaFlatBuffer *pPublicX509IssueCert,
                                   CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query kpt device credential from qat device
***************************************************************************/
CpaStatus cpaCyKptQueryDeviceCredentials(
    const CpaInstanceHandle instanceHandle,
    CpaCyKptValidationKey *pDevCredential,
    CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
***************************************************************************
* @ingroup LacKptProvision
*      Kpt load key to qat device
***************************************************************************/
CpaStatus cpaCyKptLoadKey(CpaInstanceHandle instanceHandle,
                          CpaCyKptLoadKey *pSWK,
                          CpaCyKptHandle *keyHandle,
                          CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
***************************************************************************
* @ingroup LacKptProvision
*      kpt delete key from qat device
***************************************************************************/
CpaStatus cpaCyKptDeleteKey(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle keyHandle,
                            CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}
