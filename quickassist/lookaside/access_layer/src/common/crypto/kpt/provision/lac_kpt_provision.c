/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *****************************************************************************
 * @file lac_kpt_provision.c
 *
 * @ingroup LacKptProvision
 *
 * This file implements KPT provision service APIs.
 *
 *****************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/
#include "cpa.h"
#include "cpa_cy_kpt.h"

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query KPT issue key certificate from QAT driver
***************************************************************************/
CpaStatus cpaCyKptQueryIssuingKeys(const CpaInstanceHandle instanceHandle,
                                   CpaFlatBuffer *pPublicX509IssueCert,
                                   CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query KPT device credential from QAT device
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
*      Load KPT key into QAT device
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
*      Delete KPT key from QAT device
***************************************************************************/
CpaStatus cpaCyKptDeleteKey(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle keyHandle,
                            CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}
