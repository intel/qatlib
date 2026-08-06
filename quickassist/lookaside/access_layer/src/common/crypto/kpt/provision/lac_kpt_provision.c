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

/*
****************************************************************************
* Include private header files
****************************************************************************
*/
/* SAL includes  */
#include "lac_common.h"
#include "lac_pke_utils.h"
#include "lac_sal_types_crypto.h"
#include "sal_service_state.h"
#include "lac_kpt_pro_qat_comms.h"

#ifndef QAT_KPT_DEBUG_KEY
/* Product issue key cert */
static Cpa8U kpt_product_issue_key_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFqjCCBBKgAwIBAgIUShQDHrdYk/549dCw5Yxa/lGj/oEwDQYJKoZIhvcNAQEM\n"
    "BQAwgYsxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEg\n"
    "Q2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSUwIwYDVQQLDBxLUFQg\n"
    "Um9vdCBDZXJ0IFNpZ25pbmcgUlNBIDNLMRYwFAYDVQQDDA13d3cuaW50ZWwuY29t\n"
    "MB4XDTE4MDUwODIwMzY0MVoXDTM1MTIzMTIzNTk1OVowgYQxCzAJBgNVBAYMAlVT\n"
    "MQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUlu\n"
    "dGVsIENvcnBvcmF0aW9uMR4wHAYDVQQLDBVLUFQgSXNzdWluZyBDQSBSU0EgM0sx\n"
    "FjAUBgNVBAMMDXd3dy5pbnRlbC5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw\n"
    "ggGKAoIBgQDJi5vrTU64iwydSGJ/oBSALae9hC1Aa/j1zEbhFqPZcXooN2jOxMBa\n"
    "Py6ZITFTriUJqnHWXrxF6XQN4Wvr3rI242ASW5M41k5hKWvX3dpeyuMwL99Bn75J\n"
    "b2m15IeKzbjwaYS7i5L6+n5z9tw3nBM7rT+hlB+DPlPH7u9QBoupPFU302sumVx0\n"
    "qFobBrOLj5igFsTgZ7zNpRPqzFjIRAxYeXgtQdVu4tsFOZzU1nicKn2vP3/AGNN9\n"
    "yz8pj4bLYNTKB6oeVsGlR7FuAZSyt0QDTDq0R2YE22Gvk/rpjkqn8JERZt/WHjhf\n"
    "g2qA74FVaEx0kawt1uX0Pa51Z9M4n2ifZdpGDhTJLQbLR3AXwjNo7WrvWllRjSqs\n"
    "rQ8vNjB6+lkZPqEeS1mbFAoY4WgUrgcaNTOk5Ik/h2z/CuTPnNDm7wZy11eEJS7Q\n"
    "uujc9wQ67t1gC88pFSscj4Qtk8bM7ekvxTLjsI6J6psY6MrFp0u7/ZDHVolTdaZF\n"
    "mPR3hNMOYw0CAwEAAaOCAQkwggEFMB8GA1UdIwQYMBaAFGb6TO43nCxUdtkwRtfx\n"
    "gHsGehDYMB0GA1UdDgQWBBR5Ocgnv1EGEZAUQiBa7nmHPUBi1jAPBgNVHRMBAf8E\n"
    "BTADAQH/MA4GA1UdDwEB/wQEAwIBhjBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUH\n"
    "MAKGPGh0dHA6Ly90c2NpLmludGVsLmNvbS9jb250ZW50L0tQVC9jZXJ0cy9LUFRf\n"
    "Um9vdENBX1JTQTNLLmNlcjBIBgNVHR8EQTA/MD2gO6A5hjdodHRwOi8vdHNjaS5p\n"
    "bnRlbC5jb20vY29udGVudC9LUFQvY3Jscy9LUFRfQ0FfUlNBM0suY3JsMA0GCSqG\n"
    "SIb3DQEBDAUAA4IBgQBn0KeRuZ7qVaIMDR87k4SBoDSbXKg8m6/om+W9xxeBEwQk\n"
    "rY9zsfoIdrNvgd6yfu8swRkof0pIHRlZWOBY6V+R3hlrcmWowPk1NoKLRvNz2LOj\n"
    "vchxHVcfLiiIYQbiksU9OacfLxvBCLXkYLuk5ITlh5E+eMsyIF09X/GVCghSzYor\n"
    "TgzFWqx15I8KHVoMwbPchIVfVipr/hMo8jcdo3ZUAUhuNPebORBk86nRyBEvMbtK\n"
    "IfTLVXUFVPGfahbmrihOqwZTsEQFyNnkK7fH1uUFvvOeX3Bq5f/AJbcbwacO2h8p\n"
    "U3sq1tyTNepAdM7jIn9OG4dBDvTc18NTFmPOXvogdq9Q69rKlmljJVEC1mr4eK4h\n"
    "YZ0LJuACGbuos3+TXrjEblcZUkD5i6HZ1EFnlhmGnovDZu7NG21/AsM+W/bFaOn9\n"
    "i7xJjsXzcH7tdbsYvd3QqaX+y/V9uFGFR1MRp0ISFKREReCM7NyOb4KPsRkmoJy7\n"
    "cXNwD4aT+CChYBleEY4=\n"
    "-----END CERTIFICATE-----";

#else
/* Development issue key cert */
static Cpa8U kpt_debug_issue_key_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFqjCCBBKgAwIBAgIUQ9DKepJGJw/JT7gF/cRLPQ9AixcwDQYJKoZIhvcNAQEM\n"
    "BQAwgYsxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEg\n"
    "Q2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSUwIwYDVQQLDBxLUFQg\n"
    "Um9vdCBDZXJ0IFNpZ25pbmcgUlNBIDNLMRYwFAYDVQQDDA13d3cuaW50ZWwuY29t\n"
    "MB4XDTE4MDMyNzIyMDIzOVoXDTM1MTIzMTIzNTk1OVowgYQxCzAJBgNVBAYMAlVT\n"
    "MQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUlu\n"
    "dGVsIENvcnBvcmF0aW9uMR4wHAYDVQQLDBVLUFQgSXNzdWluZyBDQSBSU0EgM0sx\n"
    "FjAUBgNVBAMMDXd3dy5pbnRlbC5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw\n"
    "ggGKAoIBgQDDKEjvzCqxgoKtzzpXyuwo/2nRQ6hM16tamsYTBhZ3LtDDElz+BFZY\n"
    "jk9lvdwjUAB+kZ5T43BXiKQ8YI8sg4uRFpw1ybZmZJXAoGBcJVvCF9Gz47ky8nqH\n"
    "ObLxz1C6S4/fmfV65qPRwEe11cIXfoRzkMJ4yhm8b9CTk85yK6WstR67U/qPc9u2\n"
    "1tqFKmaXUCzVnhRdob2VsEHh0pMGE4kdBpyAUBIJQprcEyDNHpqNjfdlvgdW8XBV\n"
    "65lbXWsFf+1nRlLFzqjUvB8Ur7qCJgdXwWFI8rVG6SA0v4w8+SfTg9ECEhrhJZ9N\n"
    "cZiBB8JD3UhzlNKhP/WbRo2H737wibSVS4CDRBUA7EygaqUGI7+SgDEkNnwbw+ql\n"
    "EJB92kwAqUJbAiDkD/rYT+rjasIaOynvLsZiYb2i9bBhBjf2mwmlW3KZwHCKH4TA\n"
    "xUT8Z36ZUHwCH/ZvJydM9tWcqr97gNijA+YLyfaxij8l3AX0DTUHV3j4Iq3oYAHZ\n"
    "TouXivYUAyMCAwEAAaOCAQkwggEFMB8GA1UdIwQYMBaAFHbZE5uoByMmdrdZM58A\n"
    "DyPgbXTlMB0GA1UdDgQWBBTGJqNtTohCujN9gOTT5kXQ7QZgXzAPBgNVHRMBAf8E\n"
    "BTADAQH/MA4GA1UdDwEB/wQEAwIBhjBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUH\n"
    "MAKGPGh0dHA6Ly90c2NpLmludGVsLmNvbS9jb250ZW50L0tQVC9jZXJ0cy9LUFRf\n"
    "Um9vdENBX1JTQTNLLmNlcjBIBgNVHR8EQTA/MD2gO6A5hjdodHRwOi8vdHNjaS5p\n"
    "bnRlbC5jb20vY29udGVudC9LUFQvY3Jscy9LUFRfQ0FfUlNBM0suY3JsMA0GCSqG\n"
    "SIb3DQEBDAUAA4IBgQCMko3YW38uKBA+FmkWsjZviiz2xPtpXYzsomce8kz8oDm3\n"
    "ial8ikAnzYrogpNm8ivb3tZ1QgT/KQZpta4Ru7dwJNVxPsI2bcQdYZs9moxX+KRG\n"
    "6tbSCf/MlL8ezPyVBkoZ4jlv0pFR3bL1yA7dKNTLWgUq5Wg5T1WqMyXoacpCE+EB\n"
    "ommAbBhj+o2rcyIgPiDpORQbsuRZVLBcEInouTz3bjvbIKx2BH0iLJ5CrK7GeKNK\n"
    "9Omob3H2bm21fNmE6ep1WKCD/vPzbfo1VWUaI8Zi9bzwpPPaEuVuGjEngYp1w5ka\n"
    "Uh1Ym/1BkxHHT1pptxRzH1TUweKHyOqgbs8hDUvy1r7oWcy1aphXzzNxK0BoC2F7\n"
    "QWBXuD6/lOZSjA/puFXraFqabCQWfPhsmsiSY9yB6in7Xa43+gT/RgVjfnM2NX81\n"
    "P75/33wVlYREn+d7QFYpY6MaXs6A7/Cdi1dS7pkENOO3gJVn21q2RdlxkJEGGlzN\n"
    "7mag/PceIuYRuARjuYc=\n"
    "-----END CERTIFICATE-----";
#endif

#ifdef ICP_PARAM_CHECK
/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Query KPT issue key certificate parameters check
 ***************************************************************************/
STATIC
CpaStatus LacQueryKptIssueKeyCertParamCheck(
    const CpaInstanceHandle instanceHandle,
    CpaFlatBuffer *pCert,
    CpaCyKptKeyManagementStatus *pStatus)
{
    LAC_CHECK_NULL_PARAM(pCert);
    LAC_CHECK_NULL_PARAM(pStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(pCert, CHECK_NONE, 0);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Query KPT device credential parameters check
 ***************************************************************************/
STATIC
CpaStatus LacQueryKptDeviceCredentialParamCheck(
    const CpaInstanceHandle instanceHandle,
    CpaCyKptValidationKey *pDevCredential,
    CpaCyKptKeyManagementStatus *pStatus)
{
    LAC_CHECK_NULL_PARAM(pDevCredential);
    LAC_CHECK_NULL_PARAM(pStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pDevCredential->publicKey.modulusN), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pDevCredential->publicKey.publicExponentE), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pDevCredential->publicKey.modulusN),
                                CHECK_GREATER_EQUALS,
                                KPT_DEV_IPUB_N_SIZE_IN_BYTE);
    LAC_CHECK_FLAT_BUFFER_PARAM(&(pDevCredential->publicKey.publicExponentE),
                                CHECK_GREATER_EQUALS,
                                KPT_DEV_IPUB_E_SIZE_IN_BYTE);

    return CPA_STATUS_SUCCESS;
}

/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Load KPT key parameters check
 ***************************************************************************/
STATIC
CpaStatus LacKptLoadKeyParamCheck(const CpaInstanceHandle instanceHandle,
                                  CpaCyKptLoadKey *pSWK,
                                  CpaCyKptHandle *keyHandle,
                                  CpaCyKptKeyManagementStatus *pStatus)
{
    LAC_CHECK_NULL_PARAM(pSWK);
    LAC_CHECK_NULL_PARAM(keyHandle);
    LAC_CHECK_NULL_PARAM(pStatus);

    LAC_CHECK_FLAT_BUFFER_PARAM(&(pSWK->eSWK), CHECK_NONE, 0);
    LAC_CHECK_FLAT_BUFFER_PARAM(
        &(pSWK->eSWK), CHECK_GREATER_EQUALS, KPT_LOAD_SWK_SIZE_IN_BYTE);

    return CPA_STATUS_SUCCESS;
}
#endif

/**
 ***************************************************************************
 * @ingroup LacKptProvision
 *      Read hard-coding X.509 KPT issue key certificate
 ***************************************************************************/
STATIC
CpaStatus LacReadKptIssueKeyCert(CpaFlatBuffer *pCert)
{

#ifndef QAT_KPT_DEBUG_KEY
    if (pCert->dataLenInBytes < sizeof(kpt_product_issue_key_cert))
        return CPA_STATUS_INVALID_PARAM;

    osalMemCopy(pCert->pData,
                kpt_product_issue_key_cert,
                sizeof(kpt_product_issue_key_cert));
    pCert->dataLenInBytes = sizeof(kpt_product_issue_key_cert);
#else
    if (pCert->dataLenInBytes < sizeof(kpt_debug_issue_key_cert))
        return CPA_STATUS_INVALID_PARAM;

    osalMemCopy(pCert->pData,
                kpt_debug_issue_key_cert,
                sizeof(kpt_debug_issue_key_cert));
    pCert->dataLenInBytes = sizeof(kpt_debug_issue_key_cert);
#endif

    return CPA_STATUS_SUCCESS;
}

/**
***************************************************************************
* @ingroup LacKptProvision
*      Query KPT issue key certificate from QAT driver
***************************************************************************/
CpaStatus cpaCyKptQueryIssuingKeys(const CpaInstanceHandle instanceHandle,
                                   CpaFlatBuffer *pPublicX509IssueCert,
                                   CpaCyKptKeyManagementStatus *pKptStatus)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_KPT_INSTANCE_HANDLE(instanceHandle);
#endif
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    status = LacQueryKptIssueKeyCertParamCheck(
        instanceHandle, pPublicX509IssueCert, pKptStatus);
    LAC_CHECK_STATUS(status);
#endif

    *pKptStatus = CPA_CY_KPT_FAILED;
    SAL_CHECK_INSTANCE_CRYPTO_CAPABILITY(instanceHandle, kpt);

    status = LacReadKptIssueKeyCert(pPublicX509IssueCert);
    if (CPA_STATUS_SUCCESS == status)
    {
        *pKptStatus = CPA_CY_KPT_SUCCESS;
    }

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pPublicX509IssueCert,
             (LAC_ARCH_UINT)pKptStatus,
             *pKptStatus);
#endif
    return status;
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
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_KPT_INSTANCE_HANDLE(instanceHandle);
#endif
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    status = LacQueryKptDeviceCredentialParamCheck(
        instanceHandle, pDevCredential, pKptStatus);
    LAC_CHECK_STATUS(status);
#endif

    *pKptStatus = CPA_CY_KPT_FAILED;
    SAL_CHECK_INSTANCE_CRYPTO_CAPABILITY(instanceHandle, kpt);

    status = LacKpt_Pro_SendRequest(instanceHandle,
                                    KPT_PRO_QUERY_DEV_CREDENTIAL_CMD,
                                    0,
                                    NULL,
                                    pDevCredential,
                                    pKptStatus);
    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR1("Failed to send device credential query request, "
                       "error code: %d\n",
                       status);
        return status;
    }

    if (CPA_STATUS_SUCCESS != *pKptStatus)
    {
        LAC_LOG_ERROR1("Failed to query device credential, error code: %d \n",
                       *pKptStatus);
    }

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pDevCredential,
             (LAC_ARCH_UINT)pKptStatus,
             *pKptStatus);
#endif
    return CPA_STATUS_SUCCESS;
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
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_KPT_INSTANCE_HANDLE(instanceHandle);
#endif
    SAL_RUNNING_CHECK(instanceHandle);
#ifdef ICP_PARAM_CHECK
    status =
        LacKptLoadKeyParamCheck(instanceHandle, pSWK, keyHandle, pKptStatus);
    LAC_CHECK_STATUS(status);
#endif

    *pKptStatus = CPA_CY_KPT_FAILED;
    SAL_CHECK_INSTANCE_CRYPTO_CAPABILITY(instanceHandle, kpt);

    status = LacKpt_Pro_SendRequest(instanceHandle,
                                    KPT_PRO_LOAD_SWK_CMD,
                                    keyHandle,
                                    &(pSWK->eSWK),
                                    NULL,
                                    pKptStatus);

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR1("Failed to send key loading request, error code: %d\n",
                       status);
        return status;
    }

    if (CPA_STATUS_SUCCESS != *pKptStatus)
    {

        LAC_LOG_ERROR1("Failed to load key to device, error code: %d\n",
                       *pKptStatus);
    }

#ifdef ICP_TRACE
    LAC_LOG6("Called with params (0x%lx, 0x%lx, 0x%lx[%llu], 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)pSWK,
             (LAC_ARCH_UINT)keyHandle,
             *keyHandle,
             (LAC_ARCH_UINT)pKptStatus,
             *pKptStatus);
#endif
    return CPA_STATUS_SUCCESS;
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
    CpaStatus status = CPA_STATUS_SUCCESS;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_KPT_INSTANCE_HANDLE(instanceHandle);
    LAC_CHECK_NULL_PARAM(pKptStatus);
#endif
    SAL_RUNNING_CHECK(instanceHandle);

    *pKptStatus = CPA_CY_KPT_FAILED;
    SAL_CHECK_INSTANCE_CRYPTO_CAPABILITY(instanceHandle, kpt);

    status = LacKpt_Pro_SendRequest(instanceHandle,
                                    KPT_PRO_DEL_SWK_CMD,
                                    &keyHandle,
                                    NULL,
                                    NULL,
                                    pKptStatus);

    if (CPA_STATUS_SUCCESS != status)
    {
        LAC_LOG_ERROR1("Failed to send key deletion request, error code: %d\n",
                       status);
        return status;
    }

    if (CPA_STATUS_SUCCESS != *pKptStatus)
    {

        LAC_LOG_ERROR1("Failed to delete key from device, error code: %d \n",
                       *pKptStatus);
    }

#ifdef ICP_TRACE
    LAC_LOG4("Called with params (0x%lx, 0x%lx, 0x%lx[%d])\n",
             (LAC_ARCH_UINT)instanceHandle,
             (LAC_ARCH_UINT)&keyHandle,
             (LAC_ARCH_UINT)pKptStatus,
             *pKptStatus);
#endif
    return CPA_STATUS_SUCCESS;
}
